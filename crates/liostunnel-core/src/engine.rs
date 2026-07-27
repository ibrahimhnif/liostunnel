//! Ties the accepted TCP flows off the packet stack to the active tunnel
//! protocol. Spec §7.6.
//!
//! Deliberately thin: `StackCore` (Task 13) owns the TCP state machine,
//! `SmoltcpStack` (Task 14) owns the poll loop and wakeups, and the protocol
//! implementations (Tasks 6-7) own the tunnel itself. This module's only job
//! is to join them without dropping anything on the floor.
//!
//! See `StackCore::poll_delay`'s rustdoc for the contract this file exists to
//! satisfy: every per-flow task must drop its `LocalStream` on every exit
//! path — success, error, early return, cancellation, panic — because that
//! drop is the only signal the stack gets that the tunnel side has finished.
//! `proxy_one`'s doc comment below explains why the structure here makes that
//! true by construction rather than something to remember on each branch.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::TunnelError;
use crate::net::{ShutdownHandle, StackHandles, TcpFlow};
use crate::protocols::Protocol;
use crate::stats::{ConnectionState, ConnectionStats};

/// Shared, lock-free counters. Cheap enough to update on every flow.
#[derive(Default)]
pub struct EngineCounters {
    pub flows_opened: AtomicU64,
    pub flows_failed: AtomicU64,
    pub dns_queries: AtomicU64,
}

#[derive(Clone)]
pub struct StatsHandle(Arc<EngineCounters>);

impl StatsHandle {
    pub fn load(&self) -> ConnectionStats {
        ConnectionStats {
            state: ConnectionState::Connected,
            flows_failed: self.0.flows_failed.load(Ordering::Relaxed),
            dns_queries: self.0.dns_queries.load(Ordering::Relaxed),
            active_flows: 0,
            ..Default::default()
        }
    }
}

/// Ties the packet stack to the active protocol. Spec §7.6.
pub struct Engine {
    protocol: Arc<dyn Protocol>,
    handles: StackHandles,
    counters: Arc<EngineCounters>,
}

impl Engine {
    pub fn new(protocol: Arc<dyn Protocol>, handles: StackHandles) -> Self {
        Self {
            protocol,
            handles,
            counters: Arc::new(EngineCounters::default()),
        }
    }

    pub fn stats_handle(&self) -> StatsHandle {
        StatsHandle(self.counters.clone())
    }

    pub fn shutdown_handle(&self) -> ShutdownHandle {
        self.handles.shutdown.clone()
    }

    /// Drives the engine until the packet stack closes `tcp_accept` — which
    /// happens when the stack thread exits, including in reaction to a
    /// `ShutdownHandle::shutdown()` call on the handle shared with it.
    ///
    /// Written as a `select!` over a single branch, rather than a plain
    /// `while let Some(flow) = ... .recv().await` loop, so that Task 18's
    /// `udp_inbound` arm (DNS resolution) slots in beside this one instead of
    /// forcing this loop to be restructured.
    pub async fn run(mut self) -> Result<(), TunnelError> {
        loop {
            tokio::select! {
                flow = self.handles.tcp_accept.recv() => {
                    match flow {
                        Some(flow) => self.spawn_flow(flow),
                        None => break,
                    }
                }
            }
        }
        tracing::info!("stack closed; engine stopping");
        Ok(())
    }

    /// Spawns one flow's proxy task.
    ///
    /// The task takes ownership of the `TcpFlow` — and so of its
    /// `LocalStream` — outright. Nothing outside the spawned future ever
    /// holds a handle to it: not `self`, not a collection, nothing. That is
    /// what lets `proxy_one` guarantee the stream drops on every exit path
    /// instead of relying on every path remembering to drop it.
    fn spawn_flow(&self, flow: TcpFlow) {
        let protocol = self.protocol.clone();
        let counters = self.counters.clone();
        tokio::spawn(async move { proxy_one(flow, protocol, counters).await });
    }
}

/// One proxied connection. A failure here is contained to this flow: the
/// `LocalStream` is dropped, which makes the stack emit RST, and the engine
/// carries on. Spec §11.
///
/// `stream` is owned by this function's local frame and never moved into
/// anything longer-lived than it — not into `remote`, not returned, not
/// stashed in a shared collection. `copy_bidirectional` below borrows it
/// (`&mut stream`) rather than taking it, so ownership never leaves this
/// stack frame either. That is what makes the drop unconditional by
/// construction:
///
/// * the early `return` on a failed `open_tcp_stream` drops `stream` as the
///   function unwinds its scope;
/// * a clean or errored `copy_bidirectional` drops it at the end of the
///   `match`;
/// * a panic anywhere in between drops it as the frame unwinds;
/// * this task's `JoinHandle` being aborted (or the whole runtime shutting
///   down) drops it too — an aborted async fn is dropped like any other
///   value, and dropping the compiler-generated future drops every local
///   still live in it, `stream` included.
///
/// There is no path through this function that returns, panics, or is
/// cancelled while still holding `stream` somewhere it would outlive the
/// call.
async fn proxy_one(flow: TcpFlow, protocol: Arc<dyn Protocol>, counters: Arc<EngineCounters>) {
    let TcpFlow {
        src,
        dst,
        mut stream,
    } = flow;

    let mut remote = match protocol.open_tcp_stream(dst).await {
        Ok(r) => {
            counters.flows_opened.fetch_add(1, Ordering::Relaxed);
            r
        }
        Err(e) => {
            counters.flows_failed.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%src, %dst, %e, "cannot open tunnel stream; resetting flow");
            return; // dropping `stream` resets the local connection
        }
    };

    match tokio::io::copy_bidirectional(&mut stream, &mut remote).await {
        Ok((up, down)) => tracing::debug!(%src, %dst, up, down, "flow finished"),
        Err(e) => tracing::debug!(%src, %dst, %e, "flow ended with an error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Wakeup;
    use crate::net::local_stream::local_stream_pair;
    use crate::protocols::TunnelStream;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Duration;

    /// Records the destinations asked for and returns a duplex pipe whose far
    /// end the test can drive — standing in for the SSH channel.
    struct MockProtocol {
        opened: Mutex<Vec<SocketAddr>>,
        far_end: Mutex<Option<tokio::io::DuplexStream>>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl Protocol for MockProtocol {
        async fn connect(
            &mut self,
            _p: &crate::config::profile::ServerProfile,
            _s: &dyn crate::config::secret::SecretStore,
        ) -> Result<(), TunnelError> {
            Ok(())
        }

        async fn open_tcp_stream(
            &self,
            dest: SocketAddr,
        ) -> Result<Box<dyn TunnelStream>, TunnelError> {
            self.opened.lock().unwrap().push(dest);
            if self.fail {
                return Err(TunnelError::Protocol("refused".into()));
            }
            let (near, far) = tokio::io::duplex(8192);
            *self.far_end.lock().unwrap() = Some(far);
            Ok(Box::new(near))
        }

        async fn send_udp(&self, _d: SocketAddr, _b: &[u8]) -> Result<(), TunnelError> {
            Err(TunnelError::Unsupported("udp"))
        }
        async fn disconnect(&mut self) -> Result<(), TunnelError> {
            Ok(())
        }
        fn stats(&self) -> ConnectionStats {
            ConnectionStats::default()
        }
    }

    fn mock(fail: bool) -> Arc<MockProtocol> {
        Arc::new(MockProtocol {
            opened: Mutex::new(Vec::new()),
            far_end: Mutex::new(None),
            fail,
        })
    }

    /// A `ShutdownHandle` with no wakeup, for tests that never fire it. See
    /// `ShutdownHandle::with_wakeup`'s doc for why there is no `Default` to
    /// reach for here.
    fn inert_shutdown() -> ShutdownHandle {
        ShutdownHandle::with_wakeup(Wakeup::default())
    }

    #[tokio::test]
    async fn a_flow_opens_a_tunnel_stream_to_its_real_destination() {
        let proto = mock(false);
        let (tcp_tx, tcp_accept) = tokio::sync::mpsc::channel(4);
        let (_udp_in_tx, udp_inbound) = tokio::sync::mpsc::channel(4);
        let (udp_outbound, _udp_out_rx) = tokio::sync::mpsc::channel(4);

        let engine = Engine::new(
            proto.clone(),
            StackHandles {
                tcp_accept,
                udp_inbound,
                udp_outbound,
                shutdown: inert_shutdown(),
            },
        );
        let handle = tokio::spawn(engine.run());

        // The peer half stands in for the packet stack; holding it open keeps
        // the flow alive long enough to observe the engine's reaction.
        let (stream, peer) = local_stream_pair(8, Wakeup::default());
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        tcp_tx
            .send(TcpFlow {
                src: "10.90.0.2:51234".parse().unwrap(),
                dst,
                stream,
            })
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(proto.opened.lock().unwrap().as_slice(), &[dst]);

        // Drop the peer half deliberately now that the observation is done,
        // rather than leaving it dangling unused.
        drop(peer);
        drop(tcp_tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn a_refused_destination_increments_the_counter_and_leaves_the_engine_running() {
        // Spec §11: per-flow failures stay per-flow.
        let proto = mock(true);
        let (tcp_tx, tcp_accept) = tokio::sync::mpsc::channel(4);
        let (_a, udp_inbound) = tokio::sync::mpsc::channel(4);
        let (udp_outbound, _b) = tokio::sync::mpsc::channel(4);

        let engine = Engine::new(
            proto.clone(),
            StackHandles {
                tcp_accept,
                udp_inbound,
                udp_outbound,
                shutdown: inert_shutdown(),
            },
        );
        let stats = engine.stats_handle();
        let handle = tokio::spawn(engine.run());

        for port in [443u16, 8443] {
            let (s, _p) = local_stream_pair(8, Wakeup::default());
            tcp_tx
                .send(TcpFlow {
                    src: "10.90.0.2:51234".parse().unwrap(),
                    dst: format!("93.184.216.34:{port}").parse().unwrap(),
                    stream: s,
                })
                .await
                .unwrap();
        }

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            stats.load().flows_failed,
            2,
            "both failures must be counted"
        );
        assert_eq!(
            proto.opened.lock().unwrap().len(),
            2,
            "engine kept accepting"
        );

        drop(tcp_tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    /// The property `StackCore::poll_delay`'s contract depends on, proven
    /// directly rather than just asserted: when the protocol call fails, the
    /// engine must drop the flow's `LocalStream` — not merely count the
    /// failure — because that drop is the only thing that makes
    /// `from_stream.is_closed()` (what `observe_flow_states` polls) true.
    /// Without the drop this test fails by timing out, because
    /// `peer.from_stream` would never see its senders go away.
    #[tokio::test]
    async fn a_failed_protocol_call_drops_the_local_stream_so_the_stack_can_reclaim_the_flow() {
        let proto = mock(true);
        let (tcp_tx, tcp_accept) = tokio::sync::mpsc::channel(4);
        let (_a, udp_inbound) = tokio::sync::mpsc::channel(4);
        let (udp_outbound, _b) = tokio::sync::mpsc::channel(4);

        let engine = Engine::new(
            proto,
            StackHandles {
                tcp_accept,
                udp_inbound,
                udp_outbound,
                shutdown: inert_shutdown(),
            },
        );
        let handle = tokio::spawn(engine.run());

        let (stream, peer) = local_stream_pair(8, Wakeup::default());
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        tcp_tx
            .send(TcpFlow {
                src: "10.90.0.2:51234".parse().unwrap(),
                dst,
                stream,
            })
            .await
            .unwrap();

        let observed_close = tokio::time::timeout(Duration::from_secs(2), async {
            while !peer.from_stream.is_closed() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            observed_close.is_ok(),
            "the stack's `from_stream.is_closed()` check must see the flow's \
             LocalStream drop after a failed open_tcp_stream, or the flow leaks \
             forever (Task 13 removed the idle timeout on established flows)"
        );

        drop(tcp_tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    /// Covers the exit path a unit test can't otherwise reach: the per-flow
    /// task being cancelled out from under it (an aborted `JoinHandle`, or a
    /// runtime shutting down) rather than returning or erroring on its own.
    /// Rust drops every live local when a future is dropped, so this must
    /// hold structurally — but "must hold structurally" is a claim, and this
    /// is the test that would fail if a future refactor moved `stream`
    /// somewhere that survives the task (e.g. into a struct field polled by
    /// something else).
    #[tokio::test]
    async fn aborting_a_flows_task_still_drops_its_local_stream() {
        let proto = mock(false);
        let (stream, peer) = local_stream_pair(8, Wakeup::default());
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let flow = TcpFlow {
            src: "10.90.0.2:51234".parse().unwrap(),
            dst,
            stream,
        };

        // `copy_bidirectional` never returns here: nothing drives either end
        // of `peer` or the mock's far end, so the task sits parked mid-copy —
        // exactly the state a real flow would be in when the runtime tears
        // down or something aborts it.
        let handle = tokio::spawn(proxy_one(flow, proto, Arc::new(EngineCounters::default())));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !handle.is_finished(),
            "the task should still be parked in copy_bidirectional"
        );

        handle.abort();
        let _ = handle.await;

        let observed_close = tokio::time::timeout(Duration::from_secs(2), async {
            while !peer.from_stream.is_closed() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            observed_close.is_ok(),
            "aborting the flow's task must still drop its LocalStream"
        );
    }
}

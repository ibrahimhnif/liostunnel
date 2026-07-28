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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::sync::mpsc;

use crate::dns::Resolver;
use crate::error::TunnelError;
use crate::net::{Datagram, ShutdownHandle, StackHandles, TcpFlow};
use crate::protocols::Protocol;
use crate::stats::{ConnectionState, ConnectionStats};

/// Shared, lock-free counters. Cheap enough to update on every flow.
#[derive(Default)]
pub struct EngineCounters {
    pub flows_opened: AtomicU64,
    pub flows_failed: AtomicU64,
    pub dns_queries: AtomicU64,
    /// Currently in-flight proxied flows -- incremented when a flow's task is
    /// spawned, decremented (via `ActiveFlowGuard`) when it ends by any
    /// means, so `StatsHandle::load` reports the real concurrent count
    /// rather than a hardcoded `0`.
    active_flows: AtomicU64,
    /// Set once `Engine::run` returns, by any means -- the stack closing both
    /// channels on request, on its own (a stack-thread panic or
    /// `Poller::wait` giving up, `poll.rs`'s `AfterWait::GiveUp`), or the
    /// engine's own task being cancelled/aborted out from under it. See
    /// `StatsHandle::load`'s doc: this is what stops it from asserting
    /// `Connected` forever after the engine has, in fact, stopped.
    stopped: AtomicBool,
}

/// Decrements `active_flows` when a flow's task ends, by any means --
/// success, error, or cancellation -- the same drop-guarantee `proxy_one`'s
/// own doc explains for `LocalStream`: nothing here needs to remember to
/// decrement on every branch, because unwinding the frame drops this guard
/// unconditionally.
struct ActiveFlowGuard(Arc<EngineCounters>);

impl Drop for ActiveFlowGuard {
    fn drop(&mut self) {
        self.0.active_flows.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Sets `EngineCounters::stopped` on *every* exit from `Engine::run` -- clean
/// completion, a panic unwinding through it, or this task's own `JoinHandle`
/// being aborted from outside. The last of those is exactly why this has to
/// be a `Drop` guard rather than a line at the end of the function body:
/// aborting a task drops its in-progress future without running any more of
/// its code, but dropping that future still drops every local still live in
/// it -- the same structural guarantee `proxy_one`'s own doc explains for
/// `LocalStream` further down this file.
struct StoppedOnDrop(Arc<EngineCounters>);

impl Drop for StoppedOnDrop {
    fn drop(&mut self) {
        self.0.stopped.store(true, Ordering::Release);
    }
}

#[derive(Clone)]
pub struct StatsHandle(Arc<EngineCounters>, Arc<dyn Protocol>);

impl StatsHandle {
    /// `state` is never hardcoded to `Connected`: before this fix it was,
    /// regardless of whether `Engine::run` had already returned -- so a dead
    /// packet engine (stack thread crashed, `Poller::wait` gave up, the
    /// engine's own task panicked or was aborted) was reported as
    /// `Connected` forever, with `connect.rs`'s three-line summary the only
    /// thing an operator could have used to notice, and only after the
    /// process itself finally exited. Reporting `Disconnected` once the
    /// engine has stopped is a state the process can actually vouch for;
    /// asserting `Connected` unconditionally is not.
    pub fn load(&self) -> ConnectionStats {
        let state = if self.0.stopped.load(Ordering::Acquire) {
            ConnectionState::Disconnected
        } else {
            ConnectionState::Connected
        };
        // Bytes are counted by the protocol, not here: the engine hands a
        // flow to `Protocol::open_stream` and never sees the payload again.
        // Before this, `load` filled them from `..Default::default()`, so
        // every consumer read a permanent zero while `SshTunnel` was counting
        // them correctly the whole time — two counter sets, and the one
        // anybody could reach was the one without the bytes.
        //
        // Caught by the Phase 1a verification: a packet capture showed a full
        // HTTP transaction crossing the TUN device while the reported
        // counters stayed flat. Spec §8.2 already ruled that a counter nobody
        // populates must not be reported as a measurement; this makes the
        // ones we do report true rather than dropping them.
        let proto = self.1.stats();
        ConnectionStats {
            state,
            bytes_up: proto.bytes_up,
            bytes_down: proto.bytes_down,
            flows_failed: self.0.flows_failed.load(Ordering::Relaxed),
            dns_queries: self.0.dns_queries.load(Ordering::Relaxed),
            active_flows: u32::try_from(self.0.active_flows.load(Ordering::Relaxed))
                .unwrap_or(u32::MAX),
            ..Default::default()
        }
    }
}

/// Ties the packet stack to the active protocol. Spec §7.6.
pub struct Engine {
    protocol: Arc<dyn Protocol>,
    resolver: Arc<dyn Resolver>,
    handles: StackHandles,
    counters: Arc<EngineCounters>,
}

impl Engine {
    pub fn new(
        protocol: Arc<dyn Protocol>,
        resolver: Arc<dyn Resolver>,
        handles: StackHandles,
    ) -> Self {
        Self {
            protocol,
            resolver,
            handles,
            counters: Arc::new(EngineCounters::default()),
        }
    }

    pub fn stats_handle(&self) -> StatsHandle {
        StatsHandle(self.counters.clone(), self.protocol.clone())
    }

    pub fn shutdown_handle(&self) -> ShutdownHandle {
        self.handles.shutdown.clone()
    }

    /// Drives the engine until the packet stack closes both `tcp_accept` and
    /// `udp_inbound` — which happens when the stack thread exits, including
    /// in reaction to a `ShutdownHandle::shutdown()` call on the handle
    /// shared with it.
    ///
    /// Each channel is tracked with its own "still open" flag and disabled
    /// (via `select!`'s `if` precondition) the moment it reports closed,
    /// rather than the whole loop breaking on the first channel to close.
    /// That distinction matters: `tokio::select!` polls whichever ready
    /// branches exist and picks among them arbitrarily, so on the shutdown
    /// path — where the stack thread drops both channels' senders in the same
    /// instant — it is entirely possible for `udp_inbound` to report closed
    /// on a poll where `tcp_accept` still has flows buffered and unread.
    /// Breaking the loop unconditionally on either arm's `None` would discard
    /// those flows silently. Tracking each channel independently means a
    /// closed one simply stops being polled, and the loop only ends once
    /// *both* are closed and drained — never losing a flow or a query queued
    /// ahead of the other channel's shutdown.
    pub async fn run(mut self) -> Result<(), TunnelError> {
        // See `StoppedOnDrop`'s own doc: covers every way this function can
        // stop running, not just the loop below ending normally.
        let _stopped_guard = StoppedOnDrop(self.counters.clone());
        let mut tcp_open = true;
        let mut udp_open = true;
        while tcp_open || udp_open {
            tokio::select! {
                flow = self.handles.tcp_accept.recv(), if tcp_open => {
                    match flow {
                        Some(flow) => self.spawn_flow(flow),
                        None => tcp_open = false,
                    }
                }
                dg = self.handles.udp_inbound.recv(), if udp_open => {
                    match dg {
                        Some(dg) => self.spawn_dns_query(dg),
                        None => udp_open = false,
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
        counters.active_flows.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            // Guarantees the decrement on every exit path `proxy_one` itself
            // guarantees for `LocalStream` -- success, error, or this whole
            // task being aborted -- for the same structural reason: dropping
            // the compiler-generated future drops every local still live in
            // it, this guard included.
            let _active = ActiveFlowGuard(counters.clone());
            proxy_one(flow, protocol, counters).await
        });
    }

    /// Spawns one DNS query's resolution. As with `spawn_flow`, the datagram
    /// is owned outright by the spawned future; nothing outside it retains
    /// the query payload.
    fn spawn_dns_query(&self, dg: Datagram) {
        let resolver = self.resolver.clone();
        let out = self.handles.udp_outbound.clone();
        let counters = self.counters.clone();
        tokio::spawn(async move { resolve_one(dg, resolver, out, counters).await });
    }
}

/// One DNS query, carried through the tunnel by `resolver`.
///
/// A failed query drops silently on the wire rather than synthesising a
/// bogus reply: the client's own resolver retries on a timeout, and
/// answering wrongly is worse than not answering at all. Spec §11.
///
/// Never logs the query or the answer — only the outcome. A DNS query names
/// exactly what a user is browsing, and is as sensitive as the traffic
/// itself.
async fn resolve_one(
    dg: Datagram,
    resolver: Arc<dyn Resolver>,
    out: mpsc::Sender<Datagram>,
    counters: Arc<EngineCounters>,
) {
    counters.dns_queries.fetch_add(1, Ordering::Relaxed);
    match resolver.query(&dg.payload).await {
        Ok(answer) => {
            // The reply comes *from* the resolver's address, back to the
            // application that asked: src/dst swap relative to the query.
            let reply = Datagram {
                src: dg.dst,
                dst: dg.src,
                payload: answer,
            };
            if out.send(reply).await.is_err() {
                tracing::debug!("stack closed before the DNS reply could be delivered");
            }
        }
        // `warn!`, not `debug!`: this is the only place a query that ran out
        // every configured resolver (or, per the review's item 3, a query
        // that starved behind a full channel budget until its own timeout)
        // becomes visible at all. At the previous `debug!` level it never
        // reached an operator's default-configured log output, so a
        // starved-DNS failure mode looked identical to "nothing happened."
        // The query name/answer themselves are still never logged -- only
        // the outcome, per this function's own contract above.
        Err(e) => tracing::warn!(%e, "DNS query failed; the client will retry"),
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
    use crate::dns::UnimplementedResolver;
    use crate::net::Wakeup;
    use crate::net::local_stream::local_stream_pair;
    use crate::protocols::TunnelStream;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Duration;

    /// Records the destinations asked for and returns a duplex pipe whose far
    /// end the test can drive — standing in for the SSH channel.
    ///
    /// `far_end` holds every far end ever produced (one per `open_tcp_stream`
    /// call), not just the most recent -- a test driving more than one
    /// concurrent flow through the same mock (see
    /// `active_flows_rises_and_falls_with_real_concurrent_flows`) needs each
    /// one to survive independently; overwriting a single slot would drop an
    /// earlier flow's far end the moment a second flow opened, ending its
    /// `copy_bidirectional` early for a reason that has nothing to do with
    /// what that test is actually exercising.
    struct MockProtocol {
        opened: Mutex<Vec<SocketAddr>>,
        far_end: Mutex<Vec<tokio::io::DuplexStream>>,
        fail: bool,
        /// Bytes the protocol claims to have carried. Only the protocol
        /// counts these -- the engine never sees a flow's payload -- so this
        /// is what `StatsHandle::load` has to reach for.
        bytes_up: AtomicU64,
        bytes_down: AtomicU64,
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
            self.far_end.lock().unwrap().push(far);
            Ok(Box::new(near))
        }

        async fn send_udp(&self, _d: SocketAddr, _b: &[u8]) -> Result<(), TunnelError> {
            Err(TunnelError::Unsupported("udp"))
        }
        async fn disconnect(&mut self) -> Result<(), TunnelError> {
            Ok(())
        }
        fn stats(&self) -> ConnectionStats {
            ConnectionStats {
                bytes_up: self.bytes_up.load(Ordering::Relaxed),
                bytes_down: self.bytes_down.load(Ordering::Relaxed),
                ..Default::default()
            }
        }
    }

    fn mock(fail: bool) -> Arc<MockProtocol> {
        Arc::new(MockProtocol {
            opened: Mutex::new(Vec::new()),
            far_end: Mutex::new(Vec::new()),
            fail,
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
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
            Arc::new(UnimplementedResolver),
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
            Arc::new(UnimplementedResolver),
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
            Arc::new(UnimplementedResolver),
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

    /// Answers with a fixed payload, or fails if none was configured —
    /// standing in for a real Task 19/20 backend. Records nothing about the
    /// query beyond raw bytes a test itself chose to send.
    struct MockResolver {
        answer: Mutex<Option<Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl Resolver for MockResolver {
        async fn query(&self, _query: &[u8]) -> Result<Vec<u8>, TunnelError> {
            match self.answer.lock().unwrap().clone() {
                Some(a) => Ok(a),
                None => Err(TunnelError::Dns("mock: no answer configured".into())),
            }
        }
    }

    #[tokio::test]
    async fn a_successful_dns_query_reaches_udp_outbound_with_swapped_endpoints() {
        let resolver = Arc::new(MockResolver {
            answer: Mutex::new(Some(b"\xAB\xCDanswer".to_vec())),
        });
        let (tcp_tx, tcp_accept) = tokio::sync::mpsc::channel(4);
        let (udp_in_tx, udp_inbound) = tokio::sync::mpsc::channel(4);
        let (udp_outbound, mut udp_out_rx) = tokio::sync::mpsc::channel(4);

        let engine = Engine::new(
            mock(false),
            resolver,
            StackHandles {
                tcp_accept,
                udp_inbound,
                udp_outbound,
                shutdown: inert_shutdown(),
            },
        );
        let stats = engine.stats_handle();
        let handle = tokio::spawn(engine.run());

        let query_src: SocketAddr = "10.90.0.2:51234".parse().unwrap();
        let query_dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
        udp_in_tx
            .send(Datagram {
                src: query_src,
                dst: query_dst,
                payload: b"\xAB\xCDquery".to_vec(),
            })
            .await
            .unwrap();

        let reply = tokio::time::timeout(Duration::from_secs(2), udp_out_rx.recv())
            .await
            .expect("a reply must be produced")
            .expect("the channel must stay open");

        assert_eq!(
            reply.src, query_dst,
            "the reply must come from the resolver's own address"
        );
        assert_eq!(
            reply.dst, query_src,
            "the reply must go back to the querying application"
        );
        assert_eq!(reply.payload, b"\xAB\xCDanswer".to_vec());
        assert_eq!(stats.load().dns_queries, 1);

        drop(udp_in_tx);
        drop(tcp_tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn a_failed_dns_query_drops_silently_without_reaching_udp_outbound() {
        // Spec: a failed resolution must drop on the wire, not synthesise a
        // bogus reply — the client's own resolver retries, and answering
        // wrongly is worse than not answering.
        let resolver = Arc::new(MockResolver {
            answer: Mutex::new(None),
        });
        let (tcp_tx, tcp_accept) = tokio::sync::mpsc::channel(4);
        let (udp_in_tx, udp_inbound) = tokio::sync::mpsc::channel(4);
        let (udp_outbound, mut udp_out_rx) = tokio::sync::mpsc::channel(4);

        let engine = Engine::new(
            mock(false),
            resolver,
            StackHandles {
                tcp_accept,
                udp_inbound,
                udp_outbound,
                shutdown: inert_shutdown(),
            },
        );
        let stats = engine.stats_handle();
        let handle = tokio::spawn(engine.run());

        udp_in_tx
            .send(Datagram {
                src: "10.90.0.2:51234".parse().unwrap(),
                dst: "1.1.1.1:53".parse().unwrap(),
                payload: b"\xAB\xCDquery".to_vec(),
            })
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            udp_out_rx.try_recv().is_err(),
            "a failed query must never produce an outbound datagram"
        );
        assert_eq!(stats.load().dns_queries, 1, "the attempt is still counted");

        drop(udp_in_tx);
        drop(tcp_tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    /// Regression test for the shutdown race in `run`'s `select!` loop. The
    /// stack thread drops `tcp_tx` and `udp_in_tx` at the same instant, so a
    /// loop that unconditionally breaks when *either* arm reports closed can
    /// end while the other channel still has buffered, unprocessed items.
    ///
    /// Dropping `udp_in_tx` with nothing ever sent on it, then pre-loading
    /// many flows onto `tcp_accept` before the engine ever starts, forces
    /// that exact race deterministically: on the very first `select!` poll,
    /// the udp arm is immediately ready with `None` while the tcp arm is
    /// immediately ready with `Some`, and `tokio::select!` picks among
    /// simultaneously-ready branches arbitrarily. A `None => break` on the
    /// udp arm would end the loop right there with every flow lost; a
    /// correct loop must keep draining `tcp_accept` until it, too, is
    /// genuinely exhausted.
    #[tokio::test]
    async fn a_closed_udp_inbound_does_not_starve_buffered_tcp_flows() {
        const N: usize = 30;
        let proto = mock(false);
        let (tcp_tx, tcp_accept) = tokio::sync::mpsc::channel(N + 1);
        let (udp_in_tx, udp_inbound) = tokio::sync::mpsc::channel(4);
        let (udp_outbound, _udp_out_rx) = tokio::sync::mpsc::channel(4);
        drop(udp_in_tx);

        let mut peers = Vec::with_capacity(N);
        for i in 0..N {
            let (stream, peer) = local_stream_pair(8, Wakeup::default());
            peers.push(peer);
            tcp_tx
                .send(TcpFlow {
                    src: "10.90.0.2:51234".parse().unwrap(),
                    dst: format!("93.184.216.34:{}", 10_000 + i).parse().unwrap(),
                    stream,
                })
                .await
                .unwrap();
        }
        drop(tcp_tx);

        let engine = Engine::new(
            proto.clone(),
            Arc::new(UnimplementedResolver),
            StackHandles {
                tcp_accept,
                udp_inbound,
                udp_outbound,
                shutdown: inert_shutdown(),
            },
        );
        tokio::time::timeout(Duration::from_secs(2), engine.run())
            .await
            .expect("the engine must drain both closed channels and exit, not hang")
            .unwrap();

        // The spawned per-flow tasks race the assertion below; give them a
        // beat to reach `open_tcp_stream`.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            proto.opened.lock().unwrap().len(),
            N,
            "every flow buffered ahead of udp_inbound's close must still be processed"
        );
    }

    // --- Review item 1: `StatsHandle::load` must not assert `Connected`
    // unconditionally, and `connect.rs` must be able to notice the engine
    // dying on its own. -----------------------------------------------------

    #[tokio::test]
    async fn stats_report_connected_while_the_engine_is_still_running() {
        let (_tcp_tx, tcp_accept) = tokio::sync::mpsc::channel(4);
        let (_udp_tx, udp_inbound) = tokio::sync::mpsc::channel(4);
        let (udp_outbound, _udp_out_rx) = tokio::sync::mpsc::channel(4);

        let engine = Engine::new(
            mock(false),
            Arc::new(UnimplementedResolver),
            StackHandles {
                tcp_accept,
                udp_inbound,
                udp_outbound,
                shutdown: inert_shutdown(),
            },
        );
        let stats = engine.stats_handle();
        let handle = tokio::spawn(engine.run());

        assert_eq!(
            stats.load().state,
            crate::stats::ConnectionState::Connected,
            "a live engine must report Connected"
        );

        drop(_tcp_tx);
        drop(_udp_tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    /// The Item-1 regression test: before this fix, `StatsHandle::load`
    /// hardcoded `ConnectionState::Connected` no matter what, so a caller
    /// polling stats after the engine had already stopped (stack thread
    /// died, `run`'s loop drained both closed channels and returned) still
    /// read a tunnel that looked perfectly healthy. Reporting a state the
    /// process cannot vouch for is worse than reporting `Disconnected`.
    #[tokio::test]
    async fn stats_report_disconnected_once_the_engine_has_stopped() {
        let (tcp_tx, tcp_accept) = tokio::sync::mpsc::channel(4);
        let (udp_in_tx, udp_inbound) = tokio::sync::mpsc::channel(4);
        let (udp_outbound, _udp_out_rx) = tokio::sync::mpsc::channel(4);

        let engine = Engine::new(
            mock(false),
            Arc::new(UnimplementedResolver),
            StackHandles {
                tcp_accept,
                udp_inbound,
                udp_outbound,
                shutdown: inert_shutdown(),
            },
        );
        let stats = engine.stats_handle();
        let handle = tokio::spawn(engine.run());

        // Simulates the stack thread dying: both channels close, which is
        // exactly how `Engine::run` returns `Ok(())` on its own per the
        // review's item 1 (`AfterWait::GiveUp`, `engine_gone`, or any other
        // stack-thread exit -- none of which involve this process ever
        // calling `shutdown()`).
        drop(tcp_tx);
        drop(udp_in_tx);

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("the engine must actually stop")
            .expect("the task must not have panicked")
            .unwrap();

        assert_eq!(
            stats.load().state,
            crate::stats::ConnectionState::Disconnected,
            "a stopped engine must never still report Connected"
        );
    }

    /// Same property, proven for the abort path too: `connect.rs`'s cleanup
    /// calls `engine_task.abort()` unconditionally, and `StoppedOnDrop`'s own
    /// doc claims this still sets `stopped` because dropping an aborted
    /// task's future drops every local still live in it. This is the test
    /// that would fail if a future refactor moved the guard somewhere that
    /// doesn't get dropped on that path.
    #[tokio::test]
    async fn stats_report_disconnected_after_the_engines_task_is_aborted() {
        let (_tcp_tx, tcp_accept) = tokio::sync::mpsc::channel(4);
        let (_udp_tx, udp_inbound) = tokio::sync::mpsc::channel(4);
        let (udp_outbound, _udp_out_rx) = tokio::sync::mpsc::channel(4);

        let engine = Engine::new(
            mock(false),
            Arc::new(UnimplementedResolver),
            StackHandles {
                tcp_accept,
                udp_inbound,
                udp_outbound,
                shutdown: inert_shutdown(),
            },
        );
        let stats = engine.stats_handle();
        let handle = tokio::spawn(engine.run());

        // Never sent to and never dropped: `run` sits parked in `select!`
        // indefinitely, exactly like a real, healthy, idle engine -- so the
        // only way this task ever stops is the abort below.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(stats.load().state, crate::stats::ConnectionState::Connected);

        handle.abort();
        let _ = handle.await;

        assert_eq!(
            stats.load().state,
            crate::stats::ConnectionState::Disconnected,
            "aborting the engine's task must still be observable as stopped"
        );
    }

    /// Bytes the protocol counted must reach whoever holds the `StatsHandle`.
    ///
    /// They are counted in the protocol -- the engine hands a flow off and
    /// never sees its payload -- and `load` used to fill them from
    /// `..Default::default()`, so every consumer read a permanent zero while
    /// `SshTunnel` counted correctly the whole time. Two counter sets, and
    /// the reachable one had no bytes in it.
    ///
    /// Found by the Phase 1a verification, not by this suite: a packet
    /// capture showed a complete HTTP transaction crossing the TUN device
    /// while the reported counters stayed flat. Nothing here would have
    /// noticed, because every mock reported zero and zero was what we
    /// asserted.
    #[tokio::test]
    async fn reported_stats_include_the_bytes_the_protocol_counted() {
        let proto = mock(false);
        let (_tcp_tx, tcp_accept) = tokio::sync::mpsc::channel(4);
        let (_udp_in_tx, udp_inbound) = tokio::sync::mpsc::channel(4);
        let (udp_outbound, _udp_out_rx) = tokio::sync::mpsc::channel(4);
        let engine = Engine::new(
            proto.clone(),
            Arc::new(MockResolver {
                answer: Mutex::new(None),
            }),
            StackHandles {
                tcp_accept,
                udp_inbound,
                udp_outbound,
                shutdown: inert_shutdown(),
            },
        );
        let stats = engine.stats_handle();

        assert_eq!(stats.load().bytes_up, 0, "nothing carried yet");

        proto.bytes_up.store(4096, Ordering::Relaxed);
        proto.bytes_down.store(8192, Ordering::Relaxed);

        let s = stats.load();
        assert_eq!(
            s.bytes_up, 4096,
            "bytes the protocol counted must be reported"
        );
        assert_eq!(
            s.bytes_down, 8192,
            "bytes the protocol counted must be reported"
        );
    }

    /// `active_flows` must reflect real concurrency, not the hardcoded `0`
    /// the review flagged alongside `state`: it rises while a flow is being
    /// proxied and falls back once every in-flight flow has actually ended.
    #[tokio::test]
    async fn active_flows_rises_and_falls_with_real_concurrent_flows() {
        let proto = mock(false);
        let (tcp_tx, tcp_accept) = tokio::sync::mpsc::channel(4);
        let (_udp_tx, udp_inbound) = tokio::sync::mpsc::channel(4);
        let (udp_outbound, _udp_out_rx) = tokio::sync::mpsc::channel(4);

        let engine = Engine::new(
            proto.clone(),
            Arc::new(UnimplementedResolver),
            StackHandles {
                tcp_accept,
                udp_inbound,
                udp_outbound,
                shutdown: inert_shutdown(),
            },
        );
        let stats = engine.stats_handle();
        let handle = tokio::spawn(engine.run());

        // Two flows held open by their peer half, standing in for the packet
        // stack keeping a real connection alive.
        let (stream_a, peer_a) = local_stream_pair(8, Wakeup::default());
        let (stream_b, peer_b) = local_stream_pair(8, Wakeup::default());
        for (i, stream) in [stream_a, stream_b].into_iter().enumerate() {
            tcp_tx
                .send(TcpFlow {
                    src: "10.90.0.2:51234".parse().unwrap(),
                    dst: format!("93.184.216.34:{}", 40_000 + i).parse().unwrap(),
                    stream,
                })
                .await
                .unwrap();
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            stats.load().active_flows,
            2,
            "both still-open flows must count as active"
        );

        // `copy_bidirectional` only finishes once *both* directions of a
        // flow see EOF: dropping the peer ends the device -> tunnel
        // direction (application traffic), and dropping the mock's far ends
        // ends the tunnel -> device direction (the "remote" side) -- both
        // are needed, or a flow's task (and its `ActiveFlowGuard`) would sit
        // parked forever on whichever direction is still open.
        drop(peer_a);
        drop(peer_b);
        proto.far_end.lock().unwrap().clear();

        tokio::time::timeout(Duration::from_secs(2), async {
            while stats.load().active_flows != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("active_flows must fall back to 0 once every flow actually ends");

        drop(tcp_tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }
}

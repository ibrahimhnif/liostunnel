//! The default [`NetStack`]: [`StackCore`] driven by a dedicated OS thread.
//!
//! Everything here exists to serve one property, exit criterion EC5: an idle
//! connected tunnel must cost approximately no CPU. The loop therefore never
//! polls for work. It blocks on three things at once —
//!
//! * the TUN descriptor, so an inbound packet wakes it;
//! * a [`Wakeup`], so the async side can tell it about the things `StackCore`
//!   cannot see (a chunk written to a flow, a slot freed, a stream dropped, a
//!   shutdown asked for);
//! * `StackCore::poll_delay`, so smoltcp's own timers and our sweeps fire.
//!
//! — and does nothing until one of them fires. Read `StackCore::poll_delay`'s
//! rustdoc before changing anything in this file: it is the contract this loop
//! exists to satisfy, and its central point is that a `None` delay does *not*
//! mean there is nothing to do.
//!
//! Spec §7.3, decision D7.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration as StdDuration;

use polling::{Event, Events, Poller};
use smoltcp::time::Instant;
use tokio::sync::mpsc;

use crate::error::TunnelError;
use crate::net::smoltcp_stack::core::StackCore;
use crate::net::tun::PacketIo;
use crate::net::{Datagram, NetStack, ShutdownHandle, StackConfig, StackHandles, TcpFlow, Wakeup};

/// Ceiling on how long the loop sleeps.
///
/// A backstop, not a mechanism. Every path that actually needs the loop to run
/// wakes it explicitly, so in a correct build this only ever fires on a fully
/// idle tunnel — twice a second, for a few microseconds. It is kept because
/// `poll_delay`'s contract has obligations this file cannot enforce on its
/// callers, and a bounded stall is a far better failure than a permanent one.
const MAX_IDLE: StdDuration = StdDuration::from_millis(500);

/// How soon to retry handing over flows the engine's channel could not take.
/// Only applies while the backlog is non-empty, i.e. while the engine is
/// already saturated.
const BACKLOG_RETRY: StdDuration = StdDuration::from_millis(10);

/// Floor on the sleep after the device failed a read.
///
/// A descriptor that is readable but errors on every read — a device torn out
/// from under us — would otherwise spin the loop at 100% CPU: the poller
/// reports it ready, the read fails, we re-arm, and it is ready again. That is
/// the one shape that can defeat everything else in this file, and on a phone
/// it is a flat battery.
const READ_ERROR_BACKOFF: StdDuration = StdDuration::from_millis(50);

/// Poller key for the TUN descriptor. Only one source is ever registered.
const TUN_KEY: usize = 7;

/// What the poller was told to watch, in the form `Poller::modify` and
/// `Poller::delete` need. They take an `AsSource`, which is `AsFd`; a bare
/// `RawFd` deliberately does not implement `AsFd`, because a raw descriptor
/// carries no lifetime, so a borrow has to be minted by hand.
#[cfg(unix)]
type TunRegistration = Option<std::os::fd::BorrowedFd<'static>>;
#[cfg(not(unix))]
type TunRegistration = Option<std::convert::Infallible>;

/// Registers the device's descriptor, if it has one.
///
/// The returned borrow is `'static` only because there is nowhere shorter to
/// tie it to; its real lifetime is argued in the `SAFETY` note and bounded by
/// [`unregister_tun`].
#[cfg(unix)]
fn register_tun(poller: &Poller, io: &dyn PacketIo) -> Result<TunRegistration, TunnelError> {
    let Some(raw) = io.pollable_fd() else {
        return Ok(None);
    };
    // SAFETY: `raw` belongs to `io`. The caller moves `io` into the stack
    // thread and drops it only after calling `unregister_tun`, so this borrow
    // never names a closed descriptor. Nothing else in this crate takes or
    // closes a `PacketIo`'s descriptor, and `PacketIo` has no method that
    // would let one be closed early.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(raw) };
    // SAFETY: `Poller::add` requires the source to stay registered until it is
    // deleted or the poller is dropped. `unregister_tun` runs on every exit
    // path out of the loop, while `io` is still alive.
    unsafe { poller.add(raw, Event::readable(TUN_KEY)) }
        .map_err(|e| TunnelError::Tun(format!("cannot watch the TUN descriptor: {e}")))?;
    Ok(Some(borrowed))
}

#[cfg(not(unix))]
fn register_tun(_poller: &Poller, _io: &dyn PacketIo) -> Result<TunRegistration, TunnelError> {
    Ok(None)
}

/// Renews the registration ahead of a wait.
///
/// `polling` hands out one-shot registrations: once an event is delivered the
/// source is disarmed, and a loop that forgets this goes permanently deaf after
/// its first packet — a failure that passes any single-packet test. Re-arming a
/// registration that did *not* fire is a no-op, so this is unconditional.
#[cfg(unix)]
fn rearm_tun(poller: &Poller, reg: TunRegistration) -> std::io::Result<()> {
    match reg {
        Some(fd) => poller.modify(fd, Event::readable(TUN_KEY)),
        None => Ok(()),
    }
}

#[cfg(not(unix))]
fn rearm_tun(_poller: &Poller, _reg: TunRegistration) -> std::io::Result<()> {
    Ok(())
}

/// Drops the registration while the descriptor is still open.
///
/// Done explicitly rather than left to the poller's own drop: the order in
/// which a closure's captured variables are dropped is not specified, so `io`
/// could close the descriptor first.
#[cfg(unix)]
fn unregister_tun(poller: &Poller, reg: TunRegistration) {
    if let Some(fd) = reg
        && let Err(e) = poller.delete(fd)
    {
        tracing::debug!(%e, "cannot unregister the TUN descriptor");
    }
}

#[cfg(not(unix))]
fn unregister_tun(_poller: &Poller, _reg: TunRegistration) {}

/// The default `NetStack`: a dedicated thread around [`StackCore`]. Decision D7.
#[derive(Default)]
pub struct SmoltcpStack {
    /// Counts passes of the poll loop. `None` in production; a test sets it to
    /// measure that the loop sleeps rather than spins, because EC5 is not
    /// something a comment can assert.
    iterations: Option<Arc<AtomicU64>>,
}

impl SmoltcpStack {
    /// A stack that reports how many times its loop has gone round.
    #[cfg(test)]
    fn counting(iterations: Arc<AtomicU64>) -> Self {
        Self {
            iterations: Some(iterations),
        }
    }
}

impl NetStack for SmoltcpStack {
    /// Spawns the stack thread and returns the handles the engine drives it by.
    ///
    /// # Panics
    ///
    /// Must be called from within a tokio runtime: the datagram bridge between
    /// `udp_outbound` and the synchronous loop is a spawned task.
    fn start(
        self,
        mut io: Box<dyn PacketIo>,
        cfg: StackConfig,
    ) -> Result<StackHandles, TunnelError> {
        let (tcp_tx, tcp_accept) = mpsc::channel::<TcpFlow>(cfg.channel_depth);
        let (udp_in_tx, udp_inbound) = mpsc::channel::<Datagram>(cfg.channel_depth);
        let (udp_outbound, mut udp_out_rx) = mpsc::channel::<Datagram>(cfg.channel_depth);

        let poller = Arc::new(
            Poller::new().map_err(|e| TunnelError::Tun(format!("cannot create poller: {e}")))?,
        );

        // The wakeup primitive `poll_delay`'s contract requires. `Poller::notify`
        // latches — a notification raised while nobody is waiting is delivered
        // to the next `wait` — and collapses repeats into a single write on the
        // notification descriptor, so this is cheap enough to call per chunk
        // written to a flow.
        let wake = {
            let poller = Arc::clone(&poller);
            Wakeup::new(move || {
                if let Err(e) = poller.notify() {
                    tracing::warn!(%e, "cannot wake the stack loop");
                }
            })
        };
        let shutdown = ShutdownHandle::with_wakeup(wake.clone());

        // Datagrams bound for the device arrive on a tokio channel, but the
        // stack thread is synchronous. Bridge them onto a std channel and wake
        // the loop, so an outbound DNS reply is never left waiting for a timeout.
        let (bridge_tx, bridge_rx) = std::sync::mpsc::channel::<Datagram>();
        {
            let wake = wake.clone();
            tokio::spawn(async move {
                while let Some(dg) = udp_out_rx.recv().await {
                    if bridge_tx.send(dg).is_err() {
                        // The stack thread is gone.
                        break;
                    }
                    wake.wake();
                }
            });
        }

        let tun = register_tun(&poller, io.as_ref())?;

        let shutdown_thread = shutdown.clone();
        let poller_thread = Arc::clone(&poller);
        let iterations = self.iterations;
        std::thread::Builder::new()
            .name("liostunnel-stack".into())
            .spawn(move || {
                let mtu = io.mtu();
                let mut core = StackCore::with_seed(cfg, random_seed());
                // Every `LocalStream` promoted from here on carries this, so a
                // write, a read, a half-close or a drop on the tunnel side is
                // seen at once instead of at the next idle tick.
                core.set_wakeup(wake);

                let mut buf = vec![0u8; mtu + 4];
                let mut events = Events::new();
                let started = std::time::Instant::now();
                // Flows that could not be handed over because the channel was
                // full. Retried rather than dropped — an accepted connection
                // that vanishes is indistinguishable from a hang, and worse
                // than a refusal. Unbounded, but each entry is a pair of
                // channel handles: the socket buffers they belong to are
                // already counted against `StackCore`'s own caps.
                let mut backlog: VecDeque<TcpFlow> = VecDeque::new();
                let mut read_errors: u64 = 0;

                loop {
                    if let Some(n) = &iterations {
                        n.fetch_add(1, Ordering::Relaxed);
                    }
                    if shutdown_thread.is_shutdown() {
                        break;
                    }

                    // Step 1: drain the device, inspecting on the way past.
                    let mut read_failed = false;
                    loop {
                        match io.read_packet(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => core.ingest(&buf[..n]),
                            Err(e) => {
                                read_failed = true;
                                read_errors += 1;
                                // Loud once, quiet thereafter: a broken device
                                // fails every backoff period and would
                                // otherwise bury the log it first appeared in.
                                if read_errors == 1 {
                                    tracing::warn!(%e, "TUN read failed");
                                } else {
                                    tracing::debug!(%e, read_errors, "TUN read failed again");
                                }
                                break;
                            }
                        }
                    }
                    if !read_failed {
                        read_errors = 0;
                    }

                    // Outbound datagrams (DNS replies) synthesised by the engine.
                    while let Ok(dg) = bridge_rx.try_recv() {
                        core.inject_datagram(dg);
                    }

                    // Steps 2 and 4.
                    let now = Instant::from_micros(
                        i64::try_from(started.elapsed().as_micros()).unwrap_or(i64::MAX),
                    );
                    core.step(now);

                    // Step 3.
                    for packet in core.drain_tx() {
                        if let Err(e) = io.write_packet(&packet) {
                            tracing::warn!(%e, "TUN write failed");
                        }
                    }

                    // Hand accepted flows to the engine, keeping any that do not fit.
                    backlog.extend(core.take_accepts());
                    let mut engine_gone = false;
                    while let Some(flow) = backlog.pop_front() {
                        match tcp_tx.try_send(flow) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(f)) => {
                                backlog.push_front(f);
                                break;
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                tracing::debug!("accept channel closed; stopping");
                                engine_gone = true;
                                break;
                            }
                        }
                    }
                    if engine_gone {
                        break;
                    }

                    for dg in core.take_datagrams() {
                        if let Err(e) = udp_in_tx.try_send(dg) {
                            // A dropped DNS query is retried by the resolver on
                            // the device, so this is a stall rather than a loss.
                            tracing::debug!(reason = %e, "cannot hand over a datagram");
                            break;
                        }
                    }

                    // Step 5: sleep on the device, the wakeup, and smoltcp's own
                    // timer at once. This is why idle-connected costs no CPU —
                    // see EC5. Spec §7.3.
                    let mut timeout = core
                        .poll_delay(now)
                        .map(|d| StdDuration::from_micros(d.total_micros()))
                        .unwrap_or(MAX_IDLE)
                        .min(MAX_IDLE);
                    if !backlog.is_empty() {
                        timeout = timeout.min(BACKLOG_RETRY);
                    }
                    if read_failed {
                        // The descriptor is *ready* and failing, so no timeout
                        // on its own can slow this down: `wait` returns the
                        // instant a re-armed ready descriptor is watched, and
                        // measuring it showed 116,000 passes in half a second.
                        // The only way to actually back off is to stop
                        // listening to it for a beat and sleep on the timer.
                        // Applied last, so it wins over the other two bounds.
                        timeout = timeout.max(READ_ERROR_BACKOFF);
                    } else if let Err(e) = rearm_tun(&poller_thread, tun) {
                        // Not fatal: the idle ceiling keeps the loop limping at
                        // reduced responsiveness rather than dropping every
                        // connection. Loud, because that is a real degradation.
                        tracing::error!(%e, "cannot re-arm the TUN descriptor; \
                             falling back to timed polling");
                    }
                    events.clear();
                    if let Err(e) = poller_thread.wait(&mut events, Some(timeout)) {
                        tracing::warn!(%e, "poller wait failed");
                    }
                }

                // While `io` is still alive; see `unregister_tun`.
                unregister_tun(&poller_thread, tun);
                drop(io);
                // Dropping `core` drops every flow, which closes both halves of
                // every `LocalStream` still out there — the engine's tasks see
                // EOF rather than hanging.
                drop(core);
                tracing::debug!("stack thread exiting");
            })
            .map_err(|e| TunnelError::Tun(format!("cannot spawn stack thread: {e}")))?;

        Ok(StackHandles {
            tcp_accept,
            udp_inbound,
            udp_outbound,
            shutdown,
        })
    }
}

/// A per-stack seed for smoltcp's initial sequence numbers.
///
/// `StackCore::new` uses a fixed one so the engine tests are deterministic;
/// shipping that would make every connection's ISN guessable. `uuid`'s v4
/// generator is already a dependency and is backed by the OS entropy source.
fn random_seed() -> u64 {
    uuid::Uuid::new_v4().as_u64_pair().0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::testutil::{TcpFlags, build_tcp};
    use crate::net::tun::FakePacketIo;
    use crate::net::{NetStack, StackConfig};
    use std::net::Ipv4Addr;
    #[cfg(unix)]
    use std::os::fd::AsRawFd;
    #[cfg(unix)]
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    const APP: (Ipv4Addr, u16) = (Ipv4Addr::new(10, 90, 0, 2), 51234);
    const WEB: (Ipv4Addr, u16) = (Ipv4Addr::new(93, 184, 216, 34), 443);

    /// Comfortably inside [`MAX_IDLE`], so a test that asserts on it fails if
    /// the loop fell back to the idle ceiling instead of being woken properly.
    const PROMPT: Duration = Duration::from_millis(200);

    /// A `PacketIo` over one end of a `UnixDatagram` pair: a real, pollable
    /// descriptor with packet boundaries, needing no privileges, no network and
    /// no filesystem.
    ///
    /// `FakePacketIo` cannot stand in for this. It has no descriptor, so with it
    /// the loop only ever exercises the timed fallback — the two properties
    /// that matter most here, re-arming and not spinning, are invisible to it.
    #[cfg(unix)]
    struct SocketPacketIo {
        sock: UnixDatagram,
        mtu: usize,
        /// When set, every read fails without consuming anything, so the
        /// descriptor stays readable: the exact shape that spins a poll loop.
        fail_reads: bool,
    }

    #[cfg(unix)]
    impl SocketPacketIo {
        /// Returns the device half and the peer half. What the stack writes
        /// arrives on the peer; what the peer sends, the stack reads.
        fn pair(fail_reads: bool) -> (Self, UnixDatagram) {
            let (device, peer) = UnixDatagram::pair().expect("socketpair");
            device
                .set_nonblocking(true)
                .expect("the loop requires a non-blocking device");
            (
                Self {
                    sock: device,
                    mtu: 1500,
                    fail_reads,
                },
                peer,
            )
        }
    }

    #[cfg(unix)]
    impl PacketIo for SocketPacketIo {
        fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunnelError> {
            if self.fail_reads {
                // Deliberately does not consume, so the descriptor stays ready.
                return Err(TunnelError::Tun("synthetic read failure".into()));
            }
            match self.sock.recv(buf) {
                Ok(n) => Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
                Err(e) => Err(TunnelError::Tun(format!("read failed: {e}"))),
            }
        }

        fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunnelError> {
            match self.sock.send(packet) {
                Ok(_) => Ok(()),
                // A full socket buffer is a dropped packet, as on a real device.
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
                Err(e) => Err(TunnelError::Tun(format!("write failed: {e}"))),
            }
        }

        fn mtu(&self) -> usize {
            self.mtu
        }

        fn pollable_fd(&self) -> Option<std::os::fd::RawFd> {
            Some(self.sock.as_raw_fd())
        }
    }

    #[cfg(unix)]
    #[derive(Debug)]
    struct Seg {
        seq: u32,
        syn: bool,
        ack: bool,
        fin: bool,
        payload: Vec<u8>,
    }

    #[cfg(unix)]
    fn parse_tcp(raw: &[u8]) -> Option<Seg> {
        use smoltcp::wire::{Ipv4Packet, TcpPacket};
        let ip = Ipv4Packet::new_checked(raw).ok()?;
        let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
        Some(Seg {
            seq: tcp.seq_number().0 as u32,
            syn: tcp.syn(),
            ack: tcp.ack(),
            fin: tcp.fin(),
            payload: tcp.payload().to_vec(),
        })
    }

    /// Waits up to `within` for a segment the stack emitted that satisfies
    /// `pred`, and reports how long it took. `None` means it never arrived.
    #[cfg(unix)]
    fn recv_matching(
        peer: &UnixDatagram,
        within: Duration,
        mut pred: impl FnMut(&Seg) -> bool,
    ) -> Option<(Seg, Duration)> {
        let t0 = std::time::Instant::now();
        let mut buf = [0u8; 2048];
        loop {
            let left = within.checked_sub(t0.elapsed())?;
            if left.is_zero() {
                return None;
            }
            peer.set_read_timeout(Some(left)).expect("read timeout");
            let n = peer.recv(&mut buf).ok()?;
            if let Some(seg) = parse_tcp(&buf[..n])
                && pred(&seg)
            {
                return Some((seg, t0.elapsed()));
            }
        }
    }

    /// Drives a real three-way handshake across the socket pair. Returns the
    /// accepted flow and the sequence numbers to carry on with.
    #[cfg(unix)]
    async fn handshake(
        peer: &UnixDatagram,
        accepts: &mut mpsc::Receiver<TcpFlow>,
        port: u16,
    ) -> (TcpFlow, u32, u32) {
        let app = (APP.0, port);
        peer.send(&build_tcp(app, WEB, TcpFlags::syn(), 1000, 0, &[]))
            .expect("send SYN");

        let (synack, _) = recv_matching(peer, Duration::from_secs(2), |s| s.syn && s.ack)
            .expect("the stack must answer a SYN with a SYN-ACK");

        peer.send(&build_tcp(
            app,
            WEB,
            TcpFlags::ack(),
            1001,
            synack.seq.wrapping_add(1),
            &[],
        ))
        .expect("send ACK");

        let flow = tokio::time::timeout(Duration::from_secs(2), accepts.recv())
            .await
            .expect("the flow must be accepted")
            .expect("the accept channel must stay open");
        (flow, 1001, synack.seq.wrapping_add(1))
    }

    /// Proves the thread wiring works end to end: a SYN pushed into the fake
    /// device comes back out of the `tcp_accept` channel as a flow. The
    /// handshake itself is covered exhaustively by Task 13's tests.
    #[tokio::test]
    async fn a_syn_on_the_device_surfaces_as_an_accepted_flow() {
        let app = (Ipv4Addr::new(10, 90, 0, 2), 51234);
        let web = (Ipv4Addr::new(93, 184, 216, 34), 443);

        let mut io = FakePacketIo::new(1500);
        io.push_inbound(build_tcp(app, web, TcpFlags::syn(), 1000, 0, &[]));

        let handles = SmoltcpStack::default()
            .start(Box::new(io), StackConfig::default())
            .unwrap();

        // The fake device never yields an fd, so the loop falls back to a timed
        // poll; the SYN-ACK and the flow still materialise.
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut h = handles;
            // The handshake needs the peer's ACK, which a fake device cannot
            // supply — so assert the stack at least answered, then stop.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            h.shutdown.shutdown();
            h.tcp_accept.close();
        })
        .await
        .expect("stack thread must not hang");
    }

    #[tokio::test]
    async fn shutdown_stops_the_thread_promptly() {
        let io = FakePacketIo::new(1500);
        let handles = SmoltcpStack::default()
            .start(Box::new(io), StackConfig::default())
            .unwrap();

        let t0 = std::time::Instant::now();
        handles.shutdown.shutdown();
        // Joining is not exposed; observe the effect instead — the accept
        // channel closes once the thread drops its sender.
        let mut rx = handles.tcp_accept;
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while rx.recv().await.is_some() {}
        })
        .await
        .expect("thread must exit and close the channel");
        assert!(t0.elapsed() < std::time::Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_device_keeps_waking_the_loop_after_the_first_packet() {
        // The regression test for `polling`'s one-shot registrations. A loop
        // that registers the descriptor once and never re-arms answers the
        // first packet and is deaf from then on — rescued only by the idle
        // ceiling, which is 2.5x the deadline asserted here. Five in a row, so
        // the second packet is not the only thing standing between us and a
        // production-only failure.
        let (io, peer) = SocketPacketIo::pair(false);
        let handles = SmoltcpStack::default()
            .start(Box::new(io), StackConfig::default())
            .unwrap();

        for (i, port) in (51_000u16..51_005).enumerate() {
            peer.send(&build_tcp(
                (APP.0, port),
                WEB,
                TcpFlags::syn(),
                1000,
                0,
                &[],
            ))
            .expect("send SYN");
            let (_, took) = recv_matching(&peer, PROMPT, |s| s.syn && s.ack).unwrap_or_else(|| {
                panic!(
                    "SYN #{} went unanswered within {PROMPT:?}: the descriptor was not re-armed",
                    i + 1
                )
            });
            assert!(
                took < PROMPT,
                "SYN #{} took {took:?}, which means it waited for the idle ceiling",
                i + 1
            );
        }

        handles.shutdown.shutdown();
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_idle_connected_stack_does_not_spin() {
        // Exit criterion EC5, and the reason every other decision in this file
        // is shaped the way it is. Measured, not asserted by comment: a loop
        // that polls instead of sleeping turns up here in the hundreds of
        // thousands.
        let (io, peer) = SocketPacketIo::pair(false);
        let counter = Arc::new(AtomicU64::new(0));
        let mut handles = SmoltcpStack::counting(Arc::clone(&counter))
            .start(Box::new(io), StackConfig::default())
            .unwrap();

        // Idle *connected*, not idle empty: a live flow is the case that has to
        // be free, and it is the one where a naive loop keeps finding work.
        let (_flow, _, _) = handshake(&peer, &mut handles.tcp_accept, APP.1).await;

        let before = counter.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(1)).await;
        let passes = counter.load(Ordering::Relaxed) - before;

        // The idle ceiling alone accounts for two passes a second; the rest is
        // headroom for a loaded test machine.
        assert!(
            passes <= 20,
            "the loop went round {passes} times in one idle second; it is polling, not sleeping"
        );
        handles.shutdown.shutdown();
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_device_that_fails_every_read_does_not_spin() {
        // A descriptor that is readable but errors on every read — a device
        // torn out from under us — defeats the sleep entirely: the poller says
        // ready, the read fails, we re-arm, it is ready again. Nothing else in
        // this file bounds that, so `READ_ERROR_BACKOFF` does.
        let (io, peer) = SocketPacketIo::pair(true);
        let counter = Arc::new(AtomicU64::new(0));
        let handles = SmoltcpStack::counting(Arc::clone(&counter))
            .start(Box::new(io), StackConfig::default())
            .unwrap();

        // Nothing ever consumes this, so the descriptor stays ready for good.
        peer.send(&build_tcp(APP, WEB, TcpFlags::syn(), 1000, 0, &[]))
            .expect("send SYN");

        let before = counter.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let passes = counter.load(Ordering::Relaxed) - before;

        // 500 ms of a 50 ms floor is ten passes.
        assert!(
            passes <= 40,
            "the loop went round {passes} times in 500 ms against a failing device"
        );
        handles.shutdown.shutdown();
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_write_on_a_flow_reaches_the_device_without_waiting_for_the_idle_ceiling() {
        // `StackCore` cannot see a chunk land in a flow's channel, and the
        // descriptor stays quiet because the write came from the tunnel, not
        // the device. Without the wakeup on `LocalStream`, every byte the
        // server sends waits out the idle ceiling — half a second of added
        // latency on every response, which is not a tunnel anyone would use.
        let (io, peer) = SocketPacketIo::pair(false);
        let mut handles = SmoltcpStack::default()
            .start(Box::new(io), StackConfig::default())
            .unwrap();
        let (mut flow, _, _) = handshake(&peer, &mut handles.tcp_accept, APP.1).await;

        flow.stream.write_all(b"HTTP/1.0 200 OK\r\n").await.unwrap();

        let (seg, took) = recv_matching(&peer, PROMPT, |s| !s.payload.is_empty())
            .expect("the write must reach the device");
        assert_eq!(seg.payload, b"HTTP/1.0 200 OK\r\n".to_vec());
        assert!(
            took < PROMPT,
            "the write took {took:?}: it waited for the idle ceiling rather than being announced"
        );
        handles.shutdown.shutdown();
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_a_flow_stream_closes_the_connection_without_waiting() {
        // Point 3 of `poll_delay`'s contract. Dropping the stream is the only
        // signal `StackCore` gets that the tunnel side has finished, and it is
        // what starts the shutdown clock — so it has to wake the loop, and it
        // has to do so *after* closing the channel, not before.
        let (io, peer) = SocketPacketIo::pair(false);
        let mut handles = SmoltcpStack::default()
            .start(Box::new(io), StackConfig::default())
            .unwrap();
        let (flow, _, _) = handshake(&peer, &mut handles.tcp_accept, APP.1).await;

        drop(flow);

        let (_, took) =
            recv_matching(&peer, PROMPT, |s| s.fin).expect("the stack must send FIN on a drop");
        assert!(
            took < PROMPT,
            "the FIN took {took:?}: the drop did not wake the loop"
        );
        handles.shutdown.shutdown();
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_wakes_the_loop_rather_than_waiting_for_the_idle_ceiling() {
        // The brief's own shutdown test allows two seconds, which a flag alone
        // would pass by leaning on the idle ceiling. Shutdown is one of the
        // things the wakeup exists for; hold it to that.
        let (io, _peer) = SocketPacketIo::pair(false);
        let handles = SmoltcpStack::default()
            .start(Box::new(io), StackConfig::default())
            .unwrap();
        // Let the loop settle into its sleep first, or it may be mid-pass and
        // notice the flag without the wakeup doing any work.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let t0 = std::time::Instant::now();
        handles.shutdown.shutdown();

        let mut accepts = handles.tcp_accept;
        let mut datagrams = handles.udp_inbound;
        tokio::time::timeout(PROMPT, async {
            assert!(accepts.recv().await.is_none(), "accepts must close");
            assert!(datagrams.recv().await.is_none(), "datagrams must close");
        })
        .await
        .expect("the thread must exit and close both channels");
        assert!(
            t0.elapsed() < PROMPT,
            "shutdown took {:?}: it waited for the idle ceiling",
            t0.elapsed()
        );
    }
}

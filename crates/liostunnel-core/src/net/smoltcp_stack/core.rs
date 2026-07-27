use std::collections::HashMap;
use std::net::SocketAddr;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::{TryRecvError, TrySendError};

use crate::net::local_stream::{StreamPeer, local_stream_pair};
use crate::net::nat_table::NatTable;
use crate::net::smoltcp_stack::device::QueuedDevice;
use crate::net::smoltcp_stack::inspect::{Inspected, inspect};
use crate::net::{Datagram, StackConfig, TcpFlow, Wakeup};

/// How much is moved between a smoltcp socket and its channel per step.
const CHUNK: usize = 8 * 1024;

/// How long an injected listener may take to complete its handshake.
///
/// This bounds two stalls by two different mechanisms, because smoltcp only
/// covers one of them:
/// * `SynReceived` — smoltcp's own socket timeout, which works here because the
///   socket has a remote tuple and so is dispatched.
/// * `Listen` — `sweep_stale_listeners`, because smoltcp cannot help: a
///   listening socket has no remote tuple, so `poll_at` is `Ingress` for ever
///   and the timer is never evaluated. smoltcp's own `test_listen_timeout`
///   asserts exactly that.
///
/// It applies *only until promotion*. The handshake it bounds is answered
/// locally, on the near side of a TUN device on this machine, so it costs no
/// network round trip at all; 30 s matches Linux's SYN-ACK retry budget and is
/// already enormously generous.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a flow whose *local* side has finished may wait on its peer.
///
/// smoltcp has no FIN_WAIT_2 timer, so `FinWait1`, `FinWait2`, `Closing` and
/// `LastAck` would otherwise stall indefinitely. Matches Linux's
/// `tcp_fin_timeout`, which governs exactly those states.
///
/// Deliberately **not** applied to `CloseWait` on its own account. There the
/// local application owns the close, and here that application is our own tunnel
/// task — still alive, still holding the channel, quite possibly still waiting
/// on a slow origin. Linux places no timer on CLOSE_WAIT for the same reason.
///
/// What bounds a `CloseWait` flow is the tunnel side going away, observed in
/// `observe_flow_states` as `from_stream.is_closed() && socket.may_send()`.
/// `pump_outbound`'s own disconnection check is **not** sufficient on its own,
/// and saying otherwise here is what hid a permanent leak for a whole review
/// cycle: that check is held back while a chunk is parked in `pending_out`, so
/// a half-closed flow with undeliverable bytes and no tunnel side left reached
/// none of the three mechanisms. The orphan clock above is what covers it.
///
/// Measured from the later of "entered the state" and "last moved a byte", so a
/// peer that is still draining data is never cut off mid-transfer.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);

/// The most listeners that may be injected but not yet promoted at once.
///
/// Each costs two `tcp_buffer_bytes` buffers, so at the 64 KiB default this
/// bounds half-open connections at about 32 MiB. An application opening more
/// than this many at once is a connection storm or a port scan, not a browser.
const MAX_PENDING_LISTENERS: usize = 256;

/// The synchronous heart of the packet engine. Owns the smoltcp interface,
/// every socket, and the queue-backed device.
///
/// Deliberately contains no threads, no file descriptors, and no async: the
/// wrapper in Task 14 supplies all three. That separation is what makes the
/// engine testable without privileges. Spec §7.3.
pub struct StackCore {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: QueuedDevice,
    nat: NatTable,
    /// Listeners injected but not yet accepted: the flow each belongs to, and
    /// when it was injected. The timestamp is what lets a listener whose SYN
    /// smoltcp never matched be torn down; see `promote_accepted`.
    pending: HashMap<SocketHandle, Pending>,
    flows: HashMap<SocketHandle, Flow>,
    accepts: Vec<TcpFlow>,
    datagrams: Vec<Datagram>,
    cfg: StackConfig,
    udp_dropped: u64,
    /// SYNs refused because `MAX_PENDING_LISTENERS` was already reached.
    syn_dropped: u64,
    /// Packets `inspect` could not classify at all.
    malformed_dropped: u64,
    /// Bytes still queued towards an application when its flow was retired.
    bytes_discarded: u64,
    /// The clock the last `step` ran at. `ingest` has no clock of its own, so
    /// this is what an injected listener is timestamped with.
    last_step: Instant,
    /// Handed to every `LocalStream` this stack creates, so the driving loop
    /// hears about the things `poll_delay` cannot report. See its contract.
    wake: Wakeup,
}

struct Pending {
    src: SocketAddr,
    dst: SocketAddr,
    injected_at: Instant,
}

struct Flow {
    src: SocketAddr,
    dst: SocketAddr,
    /// Bytes read out of the smoltcp socket, towards the tunnel.
    ///
    /// Held as an `Option` rather than a bare `StreamPeer` so the application's
    /// FIN can be surfaced *without* tearing the whole flow down: dropping this
    /// sender is the only EOF signal `LocalStream` has, and a half-closed
    /// connection still needs the other half to carry the response back.
    to_stream: Option<mpsc::Sender<Vec<u8>>>,
    /// Bytes to write into the smoltcp socket, from the tunnel.
    from_stream: mpsc::Receiver<Vec<u8>>,
    /// A chunk the socket's send buffer could not take in full.
    pending_out: Option<(Vec<u8>, usize)>,
    /// When this flow last moved a byte in either direction.
    last_activity: Instant,
    /// When the flow was first *observed* to be waiting on its peer with
    /// nothing more the local side can do. `None` while it is healthy or while
    /// the close is still ours to make.
    ///
    /// Stamped by `observe_flow_states`, which runs after `Interface::poll` —
    /// the poll is where a socket's state actually changes, so stamping any
    /// earlier records the state the socket was in *before* this step's work and
    /// leaves the deadline invisible to the `poll_delay` computed at the end of
    /// it.
    winding_down_since: Option<Instant>,
}

impl Flow {
    /// The instant this flow must be given up on, if it is winding down.
    ///
    /// Taken from the *later* of "entered the state" and "last moved a byte":
    /// a peer that is still draining data keeps refreshing the second, so a
    /// legitimate transfer is never cut short.
    fn shutdown_deadline(&self) -> Option<Instant> {
        let since = self.winding_down_since?;
        Some(since.max(self.last_activity) + SHUTDOWN_TIMEOUT)
    }
}

/// States in which the *local* side has finished and only the peer can make
/// progress. A FIN_WAIT_2-style deadline belongs here and nowhere else.
///
/// Written as an exhaustive `match` rather than a `matches!` so that a new
/// smoltcp state forces a decision here instead of silently defaulting to "no
/// deadline" — a hand-maintained list of states quietly developing a hole is
/// precisely how the `CloseWait` leak happened.
fn awaits_peer(state: tcp::State) -> bool {
    match state {
        // Our FIN is sent; only the peer can move things along.
        tcp::State::FinWait1 | tcp::State::FinWait2 | tcp::State::Closing | tcp::State::LastAck => {
            true
        }
        // The close is still ours to make. Bounded by the tunnel side going
        // away (the orphan clock in `observe_flow_states`), never by a timer.
        tcp::State::CloseWait => false,
        // Healthy.
        tcp::State::Established => false,
        // smoltcp runs its own 2MSL timer here and reaches `Closed` unaided.
        tcp::State::TimeWait => false,
        // `reap_closed` takes this one.
        tcp::State::Closed => false,
        // Not states a promoted flow is ever in: a socket only becomes a `Flow`
        // once it has left `Listen`/`SynReceived`, and this stack never dials
        // out, so `SynSent` is unreachable.
        //
        // If one of these ever becomes reachable — an outbound `connect()` is
        // added, or `promote_accepted`'s filter loosens — the flow would fall
        // through BOTH writers of `winding_down_since` and leak silently,
        // exactly as `CloseWait` did. Fail loudly in debug rather than repeat
        // this file's most expensive bug a fifth time.
        state @ (tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived) => {
            debug_assert!(false, "unreachable for a promoted flow: {state:?}");
            false
        }
    }
}

fn to_socket_addr(ep: IpEndpoint) -> Option<SocketAddr> {
    match ep.addr {
        IpAddress::Ipv4(v4) => Some(SocketAddr::from((v4, ep.port))),
        IpAddress::Ipv6(v6) => Some(SocketAddr::from((v6, ep.port))),
    }
}

/// The seed `StackCore::new` uses. Fixed, so tests are deterministic; the
/// driving loop calls [`StackCore::with_seed`] with a random one instead, which
/// is what keeps initial sequence numbers unguessable in production.
pub const TEST_SEED: u64 = 0x5eed_1105;

impl StackCore {
    pub fn new(cfg: StackConfig) -> Self {
        Self::with_seed(cfg, TEST_SEED)
    }

    /// As [`StackCore::new`], with the seed smoltcp derives initial sequence
    /// numbers from supplied by the caller.
    pub fn with_seed(cfg: StackConfig, seed: u64) -> Self {
        let mut device = QueuedDevice::new(cfg.mtu);

        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed;

        // `IpCidr::new` panics on a prefix wider than the address family allows,
        // and `StackConfig` is a plain struct any caller can build by hand.
        let prefix = cfg.netmask_prefix.min(32);
        if prefix != cfg.netmask_prefix {
            tracing::warn!(
                requested = cfg.netmask_prefix,
                "netmask prefix out of range for IPv4; clamping to /32"
            );
        }

        let mut iface = Interface::new(config, &mut device, Instant::from_micros(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(cfg.address), prefix))
                .expect("interface address list has room for one entry");
        });
        // Accept packets addressed to anything, not just our own address —
        // without this, traffic bound for the wider internet is discarded.
        iface.set_any_ip(true);

        Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
            nat: NatTable::default(),
            pending: HashMap::new(),
            flows: HashMap::new(),
            accepts: Vec::new(),
            datagrams: Vec::new(),
            cfg,
            udp_dropped: 0,
            syn_dropped: 0,
            malformed_dropped: 0,
            bytes_discarded: 0,
            last_step: Instant::from_micros(0),
            wake: Wakeup::default(),
        }
    }

    /// Installs the handle every `LocalStream` from here on will use to wake the
    /// driving loop.
    ///
    /// Left unset, it is a no-op — which is right for the synchronous tests in
    /// this file, which call `step` by hand and have no loop to wake, and wrong
    /// for anything with a loop. `SmoltcpStack::start` sets it before the first
    /// `step`, so every flow it ever promotes carries one.
    pub fn set_wakeup(&mut self, wake: Wakeup) {
        self.wake = wake;
    }

    /// Queues a datagram for delivery to the device. Reply synthesis lands in
    /// Task 18; until then the datagram is counted and discarded.
    pub fn inject_datagram(&mut self, _dg: Datagram) {
        self.udp_dropped += 1;
    }

    /// Step 1 of the loop: classify a packet, arm a listener if it opens a new
    /// flow, then queue it for `Interface::poll`. Spec §7.4.
    pub fn ingest(&mut self, packet: &[u8]) {
        match inspect(packet) {
            Inspected::TcpSyn { src, dst } => {
                if self.nat.is_armed(&src, &dst) {
                    // A retransmit: the listener for this 4-tuple already exists.
                    self.device.push_rx(packet.to_vec());
                    return;
                }
                if self.pending.len() >= MAX_PENDING_LISTENERS {
                    // Dropped, not queued. Queuing it would reach smoltcp with no
                    // matching socket, which answers RST — turning a transient
                    // burst into a hard "connection refused". A dropped SYN is
                    // retransmitted by the application's own stack, which is the
                    // standard way for it to back off.
                    self.syn_dropped += 1;
                    tracing::warn!(%src, %dst, "pending listener cap reached; dropping SYN");
                    return;
                }
                if self.nat.arm(src, dst) {
                    self.inject_listener(src, dst);
                }
                self.device.push_rx(packet.to_vec());
            }
            Inspected::TcpOther { .. } => {
                self.device.push_rx(packet.to_vec());
            }
            // UDP bypasses smoltcp entirely. Spec §7.5.
            Inspected::Udp { src, dst, payload } => {
                if dst.port() == 53 {
                    self.datagrams.push(Datagram { src, dst, payload });
                } else {
                    self.udp_dropped += 1;
                    tracing::debug!(%dst, "dropping non-DNS UDP; SSH cannot forward it");
                }
            }
            Inspected::Ignored => {
                // Malformed, truncated, or a protocol Phase 0 does not carry.
                // Counted rather than silently binned, same as non-DNS UDP.
                self.malformed_dropped += 1;
            }
        }
    }

    fn inject_listener(&mut self, src: SocketAddr, dst: SocketAddr) {
        let rx = tcp::SocketBuffer::new(vec![0u8; self.cfg.tcp_buffer_bytes]);
        let tx = tcp::SocketBuffer::new(vec![0u8; self.cfg.tcp_buffer_bytes]);
        let mut socket = tcp::Socket::new(rx, tx);

        let endpoint = IpListenEndpoint {
            addr: Some(match dst {
                SocketAddr::V4(v4) => IpAddress::Ipv4(*v4.ip()),
                SocketAddr::V6(v6) => IpAddress::Ipv6(*v6.ip()),
            }),
            port: dst.port(),
        };
        if let Err(e) = socket.listen(endpoint) {
            tracing::warn!(%dst, ?e, "cannot listen for flow");
            self.nat.disarm(&src, &dst);
            return;
        }
        // Bounds `SynReceived` only. Cleared the instant the flow is promoted:
        // smoltcp's socket timeout is a plain idle timer, not a "give up if
        // nothing useful is happening" timer, so leaving it armed on an
        // established socket resets healthy but quiet connections.
        socket.set_timeout(Some(HANDSHAKE_TIMEOUT));

        let handle = self.sockets.add(socket);
        self.pending.insert(
            handle,
            Pending {
                src,
                dst,
                injected_at: self.last_step,
            },
        );
    }

    /// Steps 2 and 4 of the loop: run smoltcp, promote accepted listeners, and
    /// move bytes between sockets and channels.
    ///
    /// The two halves of the pump sit on **opposite sides** of `Interface::poll`
    /// and that is not incidental. `send_slice` only copies into a socket's
    /// transmit buffer; the single place a packet is actually handed to the
    /// device is `poll`. Feeding outbound bytes in afterwards would leave them
    /// stranded until some later `step`, so a response would never be emitted by
    /// the same call that fed it. Inbound is the mirror image: the bytes to
    /// drain only exist once `poll` has processed the receive queue.
    pub fn step(&mut self, now: Instant) {
        self.last_step = now;
        // Acts on deadlines stamped by the previous step's observation pass, and
        // runs before the poll so the RST it queues is actually emitted.
        self.abort_expired_flows(now);
        self.pump_outbound(now);
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.sweep_stale_listeners(now);
        self.promote_accepted(now);
        self.pump_inbound(now);
        // Stamping runs *after* every mutator in this step — the poll above and
        // both pumps can all change a socket's state — so a deadline created
        // during this step is live for the `poll_delay` computed at the end of
        // it. Observing state any earlier records what the socket looked like
        // before the step did its work, and a loop sleeping on `poll_delay`
        // parks with the flow still open.
        self.observe_flow_states(now);
        self.reap_closed();
    }

    /// Releases listeners that will never handshake.
    ///
    /// A listener whose SYN smoltcp never matched — a delayed duplicate for a
    /// 4-tuple that is already established, or one returned to `Listen` by an
    /// RST — sits there for ever. smoltcp cannot rescue it: a listening socket
    /// has no remote tuple, so its `poll_at` is `Ingress` and the socket timeout
    /// is never evaluated. Left alone it pins its `NatTable` entry armed and
    /// that 4-tuple can never be retried.
    ///
    /// The predicate here must stay in step with `next_sweep_deadline`, or a
    /// deadline can come due with nothing to do and spin the caller's loop.
    fn sweep_stale_listeners(&mut self, now: Instant) {
        let stale: Vec<SocketHandle> = self
            .pending
            .iter()
            .filter(|(h, p)| {
                self.sockets.get::<tcp::Socket>(**h).state() == tcp::State::Listen
                    && now >= p.injected_at + HANDSHAKE_TIMEOUT
            })
            .map(|(h, _)| *h)
            .collect();

        for handle in stale {
            let p = self.pending.remove(&handle).expect("key came from the map");
            self.nat.disarm(&p.src, &p.dst);
            self.sockets.remove(handle);
            tracing::debug!(src = %p.src, dst = %p.dst, "listener expired before any handshake");
        }
    }

    /// Records, for each flow, whether it is now waiting on its peer with
    /// nothing more the local side can do — and therefore whether a shutdown
    /// deadline applies.
    ///
    /// Must run after every mutator in `step`; see the comment there. Splitting
    /// this from `abort_expired_flows` is the whole point: observation has to
    /// happen where the state changes, action has to happen where the resulting
    /// packet can still be emitted, and those are different places.
    fn observe_flow_states(&mut self, now: Instant) {
        for (handle, flow) in self.flows.iter_mut() {
            let socket = self.sockets.get::<tcp::Socket>(*handle);
            let state = socket.state();

            // The tunnel side is gone, yet the socket can still transmit — so
            // nothing is ever going to arrive that would close it, and
            // `pump_outbound`'s own check is deliberately held back while it is
            // still holding bytes worth delivering. Start the clock.
            //
            // Gated on `may_send()` rather than a hand-written state list.
            // `may_send()` is exactly `Established | CloseWait` (smoltcp
            // src/socket/tcp.rs:1162). Deriving it from smoltcp rather than
            // restating a list is what stops the drift that previously left
            // `CloseWait` with no deadline at all.
            //
            // These two writers are NOT a complete partition of `tcp::State`,
            // and it would be dangerous to read them as one. Four mechanisms
            // together cover a live flow:
            //   - `awaits_peer`  -> FinWait1, FinWait2, Closing, LastAck
            //   - `may_send()`   -> Established, CloseWait
            //   - `reap_closed`  -> Closed (runs in this same `step`, just below)
            //   - smoltcp itself -> TimeWait, via its 10s `Timer::Close`, which
            //     also publishes `poll_at` so the caller's sleep stays bounded
            // Listen/SynSent/SynReceived are unreachable for a promoted flow;
            // `awaits_peer` asserts that rather than assuming it.
            let orphaned = flow.from_stream.is_closed() && socket.may_send();

            if awaits_peer(state) || orphaned {
                flow.winding_down_since.get_or_insert(now);
            } else {
                // Healthy, or a state smoltcp resolves on its own.
                flow.winding_down_since = None;
            }
        }
    }

    /// Aborts flows that have sat past their shutdown deadline.
    fn abort_expired_flows(&mut self, now: Instant) {
        let stale: Vec<SocketHandle> = self
            .flows
            .iter()
            .filter(|(_, f)| f.shutdown_deadline().is_some_and(|at| now >= at))
            .map(|(h, _)| *h)
            .collect();

        for handle in stale {
            // `abort` moves the socket to `Closed` with an RST queued. The poll
            // that follows emits it and `reap_closed` then retires the flow, so
            // the application's own stack learns to let go too.
            self.sockets.get_mut::<tcp::Socket>(handle).abort();
            if let Some(f) = self.flows.get(&handle) {
                tracing::debug!(src = %f.src, dst = %f.dst, "flow exceeded its shutdown deadline");
            }
        }
    }

    fn promote_accepted(&mut self, now: Instant) {
        let ready: Vec<SocketHandle> = self
            .pending
            .keys()
            .copied()
            .filter(|h| {
                let s = self.sockets.get::<tcp::Socket>(*h);
                s.state() != tcp::State::Listen && s.state() != tcp::State::SynReceived
            })
            .collect();

        for handle in ready {
            let Pending { src, dst, .. } =
                self.pending.remove(&handle).expect("key came from the map");
            self.nat.disarm(&src, &dst);

            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            if !socket.is_active() {
                // The listener timed out or was reset before establishing.
                self.sockets.remove(handle);
                continue;
            }

            // The handshake deadline has done its job. smoltcp's socket timeout
            // is a plain idle timer — its own `test_established_timeout` shows an
            // established socket with an *empty* transmit buffer scheduling a
            // `poll_at` for it — so leaving it armed would reset any connection
            // whose application simply had nothing to say for a while.
            //
            // Nothing replaces it on `Established`, and that is deliberate — but
            // note it is *not* backstopped by smoltcp either: its retransmit
            // timer never gives up, having no retry cap, with the RTO merely
            // clamping at 60 s and repeating for ever. What reclaims a genuinely
            // dead flow is `pump_outbound` noticing the tunnel side has gone,
            // which then puts the socket into a state `abort_expired_flows`
            // does bound.
            socket.set_timeout(None);

            // Prefer the addresses smoltcp actually negotiated.
            let real_src = socket
                .remote_endpoint()
                .and_then(to_socket_addr)
                .unwrap_or(src);
            let real_dst = socket
                .local_endpoint()
                .and_then(to_socket_addr)
                .unwrap_or(dst);

            let (stream, peer) = local_stream_pair(self.cfg.channel_depth, self.wake.clone());
            let StreamPeer {
                to_stream,
                from_stream,
            } = peer;
            self.flows.insert(
                handle,
                Flow {
                    src: real_src,
                    dst: real_dst,
                    to_stream: Some(to_stream),
                    from_stream,
                    pending_out: None,
                    last_activity: now,
                    winding_down_since: None,
                },
            );
            self.accepts.push(TcpFlow {
                src: real_src,
                dst: real_dst,
                stream,
            });
            tracing::debug!(src = %real_src, dst = %real_dst, "flow accepted");
        }
    }

    /// Tunnel → application. Runs *before* `Interface::poll` so the same poll
    /// that ingests the receive queue also emits whatever this buffered.
    fn pump_outbound(&mut self, now: Instant) {
        for (handle, flow) in self.flows.iter_mut() {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);

            // (a) finish any chunk the send buffer could not take last time.
            if let Some((chunk, off)) = flow.pending_out.take() {
                if socket.can_send() {
                    match socket.send_slice(&chunk[off..]) {
                        Ok(n) if off + n < chunk.len() => {
                            flow.last_activity = now;
                            flow.pending_out = Some((chunk, off + n));
                        }
                        Ok(_) => flow.last_activity = now,
                        Err(_) => flow.pending_out = Some((chunk, off)),
                    }
                } else {
                    flow.pending_out = Some((chunk, off));
                }
            }

            // (b) whatever else the tunnel side has queued up.
            while flow.pending_out.is_none() && socket.can_send() {
                match flow.from_stream.try_recv() {
                    Ok(chunk) => match socket.send_slice(&chunk) {
                        Ok(n) if n < chunk.len() => {
                            flow.last_activity = now;
                            flow.pending_out = Some((chunk, n));
                        }
                        Ok(_) => flow.last_activity = now,
                        Err(_) => break,
                    },
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        // The engine finished with this flow: send FIN. This runs
                        // before the poll, so the FIN goes out in the same pass.
                        socket.close();
                        break;
                    }
                }
            }

            // (c) unconditional disconnection check. Both loops above are gated
            // on `can_send`, and `pump_inbound`'s equivalent is gated on
            // `can_recv`. With the transmit buffer full and nothing arriving —
            // a peer that has stopped acknowledging, say — neither body ever
            // runs, so the tunnel side going away would go unnoticed for ever.
            // With no idle timeout on `Established`, that flow would be
            // immortal: buffers, a channel pair, and perpetual retransmits.
            //
            // `is_closed` reports that every sender is gone without consuming
            // anything, so it is safe to look before deciding to drain.
            if flow.from_stream.is_closed() && flow.pending_out.is_none() {
                match flow.from_stream.try_recv() {
                    // Still buffered bytes worth trying to hand over. Park one
                    // chunk where branch (a) will retry it.
                    Ok(chunk) => flow.pending_out = Some((chunk, 0)),
                    // Closed and drained: everything the tunnel had to say has
                    // been said.
                    Err(_) => socket.close(),
                }
            }
        }
    }

    /// Application → tunnel. Runs *after* `Interface::poll`, which is what put
    /// the bytes into the socket's receive buffer in the first place.
    fn pump_inbound(&mut self, now: Instant) {
        for (handle, flow) in self.flows.iter_mut() {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);

            let Some(to_stream) = flow.to_stream.take() else {
                continue;
            };
            let mut peer_gone = false;

            // Stopping when the channel is full is exactly the backpressure
            // path: smoltcp's receive buffer fills and the advertised window
            // shrinks. Spec §7.2.
            while socket.can_recv() {
                match to_stream.try_reserve() {
                    Ok(permit) => {
                        // `recv` hands out the receive buffer directly, so this
                        // allocates exactly the bytes there are rather than a
                        // full CHUNK to move however few arrived.
                        match socket.recv(|data| {
                            let n = data.len().min(CHUNK);
                            (n, data[..n].to_vec())
                        }) {
                            Ok(chunk) if chunk.is_empty() => break,
                            Ok(chunk) => {
                                flow.last_activity = now;
                                permit.send(chunk);
                            }
                            Err(_) => break,
                        }
                    }
                    Err(TrySendError::Full(())) => break,
                    Err(TrySendError::Closed(())) => {
                        // Only reachable when the send buffer was full enough
                        // that `pump_outbound` never got to see the matching
                        // `Disconnected`; normally the close is already done
                        // before the poll.
                        socket.close();
                        peer_gone = true;
                        break;
                    }
                }
            }

            // `may_recv` stays true while the receive buffer still holds data,
            // so this only fires once the application's FIN *and* everything it
            // sent before it have been handed over. Dropping the sender is the
            // only EOF `LocalStream` understands; keeping it alive here hangs
            // every reader, because a CloseWait socket never reaches `Closed`
            // on its own and so is never reaped.
            if !peer_gone && socket.may_recv() {
                flow.to_stream = Some(to_stream);
            }
        }
    }

    fn reap_closed(&mut self) {
        let dead: Vec<SocketHandle> = self
            .flows
            .keys()
            .copied()
            .filter(|h| {
                let s = self.sockets.get::<tcp::Socket>(*h);
                s.state() == tcp::State::Closed
            })
            .collect();

        for handle in dead {
            self.retire_flow(handle);
        }
    }

    /// The single place a `Flow` is dropped. Dropping it drops both channel
    /// ends, which the `LocalStream` sees as EOF on read and a broken pipe on
    /// write — a clean close for whichever side is still using it.
    fn retire_flow(&mut self, handle: SocketHandle) {
        if let Some(mut f) = self.flows.remove(&handle) {
            // Anything still queued towards the application is about to vanish.
            // Count it rather than lose it silently.
            let mut lost = f.pending_out.as_ref().map_or(0, |(c, off)| c.len() - off);
            while let Ok(chunk) = f.from_stream.try_recv() {
                lost += chunk.len();
            }
            // Plus whatever smoltcp accepted but never got acknowledged; on an
            // abort that goes out as an RST rather than as data.
            lost += self.sockets.get::<tcp::Socket>(handle).send_queue();
            if lost > 0 {
                self.bytes_discarded += lost as u64;
                tracing::debug!(src = %f.src, dst = %f.dst, lost, "retiring flow with unsent bytes");
            }
            tracing::debug!(src = %f.src, dst = %f.dst, "flow closed");
        }
        self.sockets.remove(handle);
    }

    /// Step 3 of the loop.
    pub fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.device.drain_tx()
    }

    /// Step 5's timeout. `None` means "nothing is pending *that this stack knows
    /// about*; sleep until a packet or an external wakeup arrives".
    ///
    /// This is the value the driving loop sleeps on, so it accounts for our own
    /// sweeps as well as smoltcp's timers. smoltcp answers `Ingress` — which
    /// collapses to `None` — for every listening socket, so a `SocketSet` full of
    /// listeners would otherwise never wake the loop and the sweeps in
    /// `sweep_stale_listeners`/`abort_expired_flows` would never run.
    ///
    /// # Contract for the driving loop — read this before writing one
    ///
    /// **`None` does not mean "nothing will ever need doing."** This stack is
    /// synchronous and holds no waker, no channel handle you can select on, and
    /// no file descriptor: it cannot observe that a `LocalStream`'s peer became
    /// readable or was dropped. A flow in `CloseWait` awaiting a slow response
    /// reports `None` both before *and* after the tunnel side drops its stream.
    /// A loop that blocks on this value alone will sleep through that forever.
    ///
    /// A correct driver must therefore:
    ///
    /// 1. Block on its own wakeup primitive **and** this timeout together —
    ///    whichever fires first — never on this timeout alone.
    /// 2. Signal that primitive from the tunnel task on **every** exit path,
    ///    including errors and cancellation, not just the success path.
    /// 3. Drop the `LocalStream` when the tunnel task finishes. That drop is
    ///    what `observe_flow_states` detects (via `from_stream.is_closed()`)
    ///    to start the shutdown clock; without it the flow is never reclaimed.
    ///
    /// No wakeup handle is exposed from here deliberately: the driver owns the
    /// loop and the blocking primitive, so it should pick one (`Condvar`,
    /// `mpsc::recv_timeout`, a `polling` registration) rather than have this
    /// stack impose an unrelated one. That does mean points 2 and 3 are an
    /// obligation this type cannot enforce — hence stating them here.
    ///
    /// Note `poll_delay` is commonly `Some(0)` immediately after a `step`
    /// (`pump_inbound` frees receive buffer, so smoltcp owes a window update).
    /// The precise claim is: once quiescent, `None`.
    pub fn poll_delay(&mut self, now: Instant) -> Option<Duration> {
        let smoltcp = self.iface.poll_delay(now, &self.sockets);
        let sweep = self.next_sweep_deadline().map(|at| {
            // `Instant - Instant` takes the absolute value in smoltcp, so an
            // overdue deadline has to be handled explicitly.
            if at > now { at - now } else { Duration::ZERO }
        });

        match (smoltcp, sweep) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, None) => a,
            (None, b) => b,
        }
    }

    /// When the next sweep has work to do. Must agree with the predicates in
    /// `sweep_stale_listeners` and `abort_expired_flows`: a deadline that comes due
    /// without the matching sweep removing anything would spin the caller's loop.
    fn next_sweep_deadline(&self) -> Option<Instant> {
        let listeners = self
            .pending
            .iter()
            .filter(|(h, _)| self.sockets.get::<tcp::Socket>(**h).state() == tcp::State::Listen)
            .map(|(_, p)| p.injected_at + HANDSHAKE_TIMEOUT);
        let winding_down = self.flows.values().filter_map(Flow::shutdown_deadline);
        listeners.chain(winding_down).min()
    }

    pub fn take_accepts(&mut self) -> Vec<TcpFlow> {
        std::mem::take(&mut self.accepts)
    }

    pub fn take_datagrams(&mut self) -> Vec<Datagram> {
        std::mem::take(&mut self.datagrams)
    }

    pub fn udp_dropped(&self) -> u64 {
        self.udp_dropped
    }

    /// SYNs refused because too many listeners were already awaiting a
    /// handshake. A non-zero value means an application is opening connections
    /// faster than they complete.
    pub fn syn_dropped(&self) -> u64 {
        self.syn_dropped
    }

    /// Packets `inspect` could not classify.
    pub fn malformed_dropped(&self) -> u64 {
        self.malformed_dropped
    }

    /// Bytes queued towards an application whose flow was retired first.
    ///
    /// An **upper bound**, not an exact count: the socket's own transmit queue
    /// is included, and smoltcp exposes no way to tell bytes still unsent from
    /// bytes already on the wire awaiting an ACK. A flow retired holding
    /// segments the peer had in fact received will over-report by that much.
    pub fn bytes_discarded(&self) -> u64 {
        self.bytes_discarded
    }

    pub fn active_flows(&self) -> usize {
        self.flows.len()
    }

    /// Listeners injected but not yet promoted, bounded by
    /// `MAX_PENDING_LISTENERS`.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn armed_len(&self) -> usize {
        self.nat.armed_len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::testutil::{TcpFlags, build_tcp, build_udp};
    use smoltcp::wire::{Ipv4Packet, TcpPacket};
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const APP: (Ipv4Addr, u16) = (Ipv4Addr::new(10, 90, 0, 2), 51234);
    const APP2: (Ipv4Addr, u16) = (Ipv4Addr::new(10, 90, 0, 2), 51235);
    const WEB: (Ipv4Addr, u16) = (Ipv4Addr::new(93, 184, 216, 34), 443);

    fn sa(t: (Ipv4Addr, u16)) -> SocketAddr {
        SocketAddr::from(t)
    }

    /// Advances the deterministic clock so retransmit timers behave.
    struct Clock(u64);
    impl Clock {
        fn tick(&mut self) -> Instant {
            self.0 += 10_000;
            Instant::from_micros(self.0 as i64)
        }
    }

    /// Returns (seq, ack, flags_syn, flags_ack, payload) of the last TCP packet
    /// the stack emitted, if any.
    fn last_tcp(core: &mut StackCore) -> Option<(u32, u32, bool, bool, bool, Vec<u8>)> {
        let tx = core.drain_tx();
        let raw = tx.last()?.clone();
        let ip = Ipv4Packet::new_checked(&raw[..]).ok()?;
        let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
        Some((
            tcp.seq_number().0 as u32,
            tcp.ack_number().0 as u32,
            tcp.syn(),
            tcp.ack(),
            tcp.fin(),
            tcp.payload().to_vec(),
        ))
    }

    /// Drives a full three-way handshake and returns the accepted flow plus the
    /// sequence numbers to continue with.
    fn handshake(
        core: &mut StackCore,
        clock: &mut Clock,
        app: (Ipv4Addr, u16),
        web: (Ipv4Addr, u16),
        client_isn: u32,
    ) -> (TcpFlow, u32, u32) {
        core.ingest(&build_tcp(app, web, TcpFlags::syn(), client_isn, 0, &[]));
        core.step(clock.tick());

        let (server_isn, ack, syn, is_ack, _, _) = last_tcp(core).expect("stack must answer a SYN");
        assert!(syn && is_ack, "expected SYN-ACK");
        assert_eq!(ack, client_isn + 1);

        core.ingest(&build_tcp(
            app,
            web,
            TcpFlags::ack(),
            client_isn + 1,
            server_isn + 1,
            &[],
        ));
        core.step(clock.tick());

        let mut flows = core.take_accepts();
        assert_eq!(flows.len(), 1, "exactly one flow should be accepted");
        (flows.remove(0), client_isn + 1, server_isn + 1)
    }

    #[tokio::test]
    async fn a_syn_produces_a_flow_carrying_the_real_destination() {
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);

        let (flow, _, _) = handshake(&mut core, &mut clock, APP, WEB, 1000);

        assert_eq!(flow.dst, sa(WEB), "dst must be the app's real destination");
        assert_eq!(flow.src, sa(APP));
        assert_eq!(core.active_flows(), 1);
    }

    #[tokio::test]
    async fn application_bytes_arrive_on_the_flow_stream() {
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);
        let (mut flow, cseq, sseq) = handshake(&mut core, &mut clock, APP, WEB, 1000);

        core.ingest(&build_tcp(
            APP,
            WEB,
            TcpFlags::ack(),
            cseq,
            sseq,
            b"GET / HTTP/1.0\r\n",
        ));
        core.step(clock.tick());

        let mut buf = vec![0u8; 16];
        flow.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"GET / HTTP/1.0\r\n");
    }

    #[tokio::test]
    async fn bytes_written_to_the_flow_reach_the_device_as_tcp_payload() {
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);
        let (mut flow, _, _) = handshake(&mut core, &mut clock, APP, WEB, 1000);

        flow.stream.write_all(b"HTTP/1.0 200 OK\r\n").await.unwrap();
        // Give the channel a moment, then let the stack pick it up.
        tokio::task::yield_now().await;
        core.step(clock.tick());

        let (_, _, _, _, _, payload) = last_tcp(&mut core).expect("stack must emit data");
        assert_eq!(payload, b"HTTP/1.0 200 OK\r\n".to_vec());
    }

    #[tokio::test]
    async fn a_fin_from_the_application_closes_the_flow_stream() {
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);
        let (mut flow, cseq, sseq) = handshake(&mut core, &mut clock, APP, WEB, 1000);

        core.ingest(&build_tcp(APP, WEB, TcpFlags::fin_ack(), cseq, sseq, &[]));
        core.step(clock.tick());
        core.step(clock.tick());

        let mut rest = Vec::new();
        flow.stream.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "FIN must surface as clean EOF");
    }

    #[tokio::test]
    async fn two_concurrent_connections_to_one_destination_both_get_flows() {
        // The regression test for keying the NatTable on the 4-tuple.
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);

        core.ingest(&build_tcp(APP, WEB, TcpFlags::syn(), 1000, 0, &[]));
        core.ingest(&build_tcp(APP2, WEB, TcpFlags::syn(), 2000, 0, &[]));
        core.step(clock.tick());

        // Both handshakes must be answered.
        let tx = core.drain_tx();
        let synacks = tx
            .iter()
            .filter(|raw| {
                Ipv4Packet::new_checked(&raw[..])
                    .ok()
                    .and_then(|ip| TcpPacket::new_checked(ip.payload()).ok().map(|t| t.syn()))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(synacks, 2, "each distinct flow needs its own listener");
    }

    /// Returns every RST the stack has emitted since the last drain.
    fn rsts(core: &mut StackCore) -> usize {
        core.drain_tx()
            .iter()
            .filter(|raw| {
                Ipv4Packet::new_checked(&raw[..])
                    .ok()
                    .and_then(|ip| TcpPacket::new_checked(ip.payload()).ok().map(|t| t.rst()))
                    .unwrap_or(false)
            })
            .count()
    }

    fn secs(n: u64) -> Instant {
        Instant::from_micros((n * 1_000_000) as i64)
    }

    #[tokio::test]
    async fn an_idle_established_connection_is_never_reset() {
        // The regression test for the handshake deadline leaking into
        // `Established`. smoltcp's socket timeout is a plain idle timer: its own
        // `test_established_timeout` shows `poll_at == PollAt::Time(..)` for an
        // established socket with an *empty* transmit buffer. Left armed after
        // promotion it unilaterally RSTs any quiet SSH session, HTTP keep-alive,
        // WebSocket or database connection.
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);
        let (_flow, _, _) = handshake(&mut core, &mut clock, APP, WEB, 1000);
        assert_eq!(core.active_flows(), 1);
        core.drain_tx();

        // Five minutes of an application with nothing to say.
        for at in [5, 31, 60, 120, 300] {
            core.step(secs(at));
            assert_eq!(
                core.active_flows(),
                1,
                "an idle established flow must survive {at}s"
            );
        }
        assert_eq!(
            rsts(&mut core),
            0,
            "the stack must never reset a healthy flow"
        );
    }

    #[tokio::test]
    async fn a_half_closed_flow_whose_peer_never_finishes_is_reaped() {
        // Once the handshake deadline no longer governs established sockets,
        // nothing in smoltcp bounds `CloseWait`/`FinWait2`/`LastAck` — it has no
        // FIN_WAIT_2 timer of its own. Without our own sweep a stuck half-close
        // leaks a socket, its buffers and a channel pair for ever.
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);
        let (flow, cseq, sseq) = handshake(&mut core, &mut clock, APP, WEB, 1000);

        core.ingest(&build_tcp(APP, WEB, TcpFlags::fin_ack(), cseq, sseq, &[]));
        core.step(clock.tick());
        // The tunnel side finishes too, so the stack sends its own FIN — but the
        // application never acknowledges it.
        drop(flow);
        core.step(clock.tick());
        assert_eq!(core.active_flows(), 1, "still legitimately winding down");

        core.step(secs(600));
        assert_eq!(core.active_flows(), 0, "a stuck half-close must not leak");
    }

    #[test]
    fn poll_delay_is_bounded_while_a_listener_sweep_is_pending() {
        // Task 14 sleeps on `poll_delay`. A `SocketSet` holding only listeners
        // makes smoltcp answer `None` ("sleep until a packet arrives"), so
        // nothing would ever wake the loop to run the sweep.
        let mut core = StackCore::new(StackConfig::default());
        core.ingest(&build_tcp(APP, WEB, TcpFlags::syn(), 1000, 0, &[]));
        let now = Instant::from_micros(0);

        assert_eq!(
            core.iface.poll_delay(now, &core.sockets),
            None,
            "smoltcp alone would sleep for ever on a listening socket"
        );
        assert_eq!(
            core.poll_delay(now),
            Some(HANDSHAKE_TIMEOUT),
            "a pending sweep must bound the sleep"
        );
    }

    /// Every flow's stamp must agree with the socket state as it stands at the
    /// *end* of a step. `observe_flow_states` runs after every mutator precisely
    /// so this holds; observing any earlier records a state the step has since
    /// moved on from, and the stamp goes stale in one direction or the other.
    fn assert_stamps_match_state(core: &StackCore) {
        for (handle, flow) in core.flows.iter() {
            let socket = core.sockets.get::<tcp::Socket>(*handle);
            let needs =
                awaits_peer(socket.state()) || (flow.from_stream.is_closed() && socket.may_send());
            assert_eq!(
                needs,
                flow.winding_down_since.is_some(),
                "stamp disagrees with the final state {:?} of {:?}",
                socket.state(),
                handle
            );
        }
    }

    #[tokio::test]
    async fn a_flow_that_starts_closing_bounds_the_very_next_sleep() {
        // The socket goes `CloseWait` -> `LastAck` part-way through the last
        // step here, when `pump_outbound` notices the tunnel side has gone, and
        // the deadline that creates must be live by the time `poll_delay` is
        // computed at the end of that same step.
        //
        // NOTE: this asserts the *outcome*, not the ordering. Measured by A/B,
        // it still passes with observation moved back before the poll, because
        // the orphan clock (`is_closed() && may_send()`) covers `CloseWait` too
        // and so stamps at either position. The test that actually discriminates
        // the ordering is `a_stamp_is_never_left_stale_by_a_transition_inside_the_poll`.
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);
        let (flow, cseq, sseq) = handshake(&mut core, &mut clock, APP, WEB, 1000);

        core.ingest(&build_tcp(APP, WEB, TcpFlags::fin_ack(), cseq, sseq, &[]));
        core.step(clock.tick());
        drop(flow);

        let now = clock.tick();
        core.step(now);

        let handle = *core.flows.keys().next().expect("the flow must still exist");
        assert_eq!(
            core.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::LastAck,
            "precondition: the close must have happened during that step"
        );
        // Asserted on our own deadline rather than only on `poll_delay`:
        // smoltcp still has a FIN-retransmit timer running here, which would
        // mask a missing sweep deadline and let this pass for the wrong reason.
        assert!(
            core.next_sweep_deadline().is_some(),
            "the shutdown deadline must be live by the end of the step that created it"
        );
        assert_stamps_match_state(&core);

        let delay = core.poll_delay(now);
        assert!(delay.is_some());
        assert!(delay.unwrap() <= SHUTDOWN_TIMEOUT);
    }

    #[tokio::test]
    async fn a_stamp_is_never_left_stale_by_a_transition_inside_the_poll() {
        // This is the ordering regression test. `FinWait2` -> `TimeWait` happens
        // entirely inside `iface.poll`, and it flips a flow from "needs a
        // deadline" to "smoltcp resolves this unaided" — so it is one of the few
        // transitions the orphan clock does *not* also cover, which is exactly
        // what makes it discriminating.
        //
        // A/B measured: fails with observation moved back to the start of the
        // step (the placement this whole class of bug came from), passes with it
        // in the shipped position. It does *not* catch observation placed
        // between the poll and `pump_inbound`; nothing can, *given today's
        // `LocalStream`* — the only state change `pump_inbound` makes is a
        // `close()` that requires the `LocalStream` to be gone, which the orphan
        // clock has already stamped. That rests on `LocalStream` owning both
        // channel ends with no split API, so its read half cannot be dropped
        // independently. Nothing pins that invariant; if `LocalStream` ever
        // gains a half-shutdown, revisit this. Defensive today, not load-bearing.
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);
        let (flow, cseq, sseq) = handshake(&mut core, &mut clock, APP, WEB, 1000);

        // We close first, so the socket is in FinWait1.
        drop(flow);
        core.step(clock.tick());
        let handle = *core.flows.keys().next().expect("the flow must still exist");

        // The application acknowledges our FIN and sends its own, taking the
        // socket FinWait1 -> FinWait2 -> TimeWait inside a single poll.
        core.ingest(&build_tcp(APP, WEB, TcpFlags::ack(), cseq, sseq + 1, &[]));
        core.ingest(&build_tcp(
            APP,
            WEB,
            TcpFlags::fin_ack(),
            cseq,
            sseq + 1,
            &[],
        ));
        core.step(clock.tick());

        assert_eq!(
            core.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::TimeWait,
            "precondition: the poll must have reached TimeWait"
        );
        assert_stamps_match_state(&core);
    }

    #[tokio::test]
    async fn a_slow_response_after_a_half_close_is_not_reset() {
        // `CloseWait` means the *local* side owns the close, and here the local
        // side is our own tunnel task, still alive and still holding the
        // channel. Linux puts no timer on CLOSE_WAIT for exactly that reason.
        // An origin that takes 90 s for the first byte is slow, not broken.
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);
        let (mut flow, cseq, sseq) = handshake(&mut core, &mut clock, APP, WEB, 1000);

        core.ingest(&build_tcp(
            APP,
            WEB,
            TcpFlags::fin_ack(),
            cseq,
            sseq,
            b"GET / HTTP/1.0\r\n",
        ));
        core.step(clock.tick());
        core.drain_tx();

        // The Task 14 obligation, pinned. Let the stack settle first — after
        // `pump_inbound` frees receive buffer, smoltcp still owes a window
        // update, so it asks to be run again immediately.
        let mut now = clock.tick();
        let mut settle = 0;
        while core.poll_delay(now) == Some(Duration::ZERO) {
            core.step(now);
            core.drain_tx();
            settle += 1;
            assert!(settle < 16, "the stack never went quiescent");
            now = clock.tick();
        }

        // Once quiescent, a `CloseWait` flow waiting on a slow origin has
        // nothing for smoltcp to schedule and — correctly — no sweep deadline of
        // its own, so the loop has nothing whatever to sleep on and parks. That
        // is the right design, but it means the tunnel task MUST notify the loop
        // on every exit path, including error and cancellation paths, or this
        // flow is never progressed and never reclaimed.
        assert_eq!(
            core.poll_delay(now),
            None,
            "a half-closed flow awaiting a slow origin gives the loop nothing to wake on"
        );

        for at in [30, 59, 61, 90] {
            core.step(secs(at));
            assert_eq!(
                core.active_flows(),
                1,
                "a half-closed flow awaiting a slow response must survive {at}s"
            );
        }
        assert_eq!(rsts(&mut core), 0, "a slow response must not be reset");

        // And the response still gets delivered.
        flow.stream.write_all(b"HTTP/1.0 200 OK\r\n").await.unwrap();
        tokio::task::yield_now().await;
        core.step(secs(91));

        let (_, _, _, _, _, payload) =
            last_tcp(&mut core).expect("the late response must still be delivered");
        assert_eq!(payload, b"HTTP/1.0 200 OK\r\n".to_vec());
    }

    #[tokio::test]
    async fn a_half_closed_flow_with_parked_bytes_is_reclaimed_when_the_tunnel_goes() {
        // The leak this pass exists to fix, and a regression against an earlier
        // pass: taking `CloseWait` off the shutdown clock left it covered by
        // nothing at all. `awaits_peer` excludes it by design; the orphan clock
        // used to require `Established`; and `pump_outbound`'s disconnection
        // check is held back while a chunk is parked in `pending_out`. A
        // half-closed flow with undeliverable bytes and no tunnel side left
        // reached none of the three and lived for ever.
        let cfg = StackConfig {
            tcp_buffer_bytes: 4096,
            ..StackConfig::default()
        };
        let mut core = StackCore::new(cfg);
        let mut clock = Clock(0);
        let (mut flow, cseq, sseq) = handshake(&mut core, &mut clock, APP, WEB, 1000);

        // The application half-closes...
        core.ingest(&build_tcp(APP, WEB, TcpFlags::fin_ack(), cseq, sseq, &[]));
        core.step(clock.tick());

        // ...the tunnel writes more than the transmit buffer can take, and
        // nothing is ever acknowledged, so a chunk ends up parked...
        for _ in 0..8 {
            let _ = flow.stream.write_all(&[0u8; 2048]).await;
            tokio::task::yield_now().await;
            core.step(clock.tick());
            core.drain_tx();
        }

        let handle = *core.flows.keys().next().expect("the flow must still exist");
        assert_eq!(
            core.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::CloseWait,
            "precondition: the socket must be half-closed"
        );

        // ...and then the tunnel task goes away. Branch (c) parks one chunk in
        // `pending_out` on the next step and is gated off from then on, which is
        // exactly the hole: `CloseWait` reaches no other mechanism.
        drop(flow);
        core.step(clock.tick());
        core.drain_tx();
        assert_eq!(
            core.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::CloseWait,
            "precondition: still half-closed, branch (c) cannot close it"
        );
        assert!(
            core.flows[&handle].pending_out.is_some(),
            "precondition: a chunk must be parked, which is what gates branch (c)"
        );

        let start = clock.tick();
        let mut now = start;
        let mut steps = 0;
        loop {
            core.step(now);
            core.drain_tx();
            steps += 1;
            assert!(steps < 200, "the half-closed flow was never reclaimed");
            if core.active_flows() == 0 {
                break;
            }
            let delay = core
                .poll_delay(now)
                .expect("a half-closed flow with no tunnel side must bound the sleep");
            now += delay;
        }
        assert!(
            now <= start + SHUTDOWN_TIMEOUT + SHUTDOWN_TIMEOUT,
            "reclamation must be bounded, took {}s",
            (now - start).secs()
        );
    }

    #[tokio::test]
    async fn a_dropped_stream_is_noticed_even_when_the_socket_cannot_send() {
        // `pump_outbound`'s `try_recv` sits inside `while ... && can_send()`, and
        // `pump_inbound`'s `try_reserve` inside `while can_recv()`. With the
        // transmit buffer full and nothing arriving, neither body ever runs, so
        // without an unconditional check the stack would not even *begin* to
        // close — it would sit in `Established` until something else gave up.
        let cfg = StackConfig {
            tcp_buffer_bytes: 4096,
            ..StackConfig::default()
        };
        let mut core = StackCore::new(cfg);
        let mut clock = Clock(0);
        let (mut flow, _, _) = handshake(&mut core, &mut clock, APP, WEB, 1000);

        // Exactly fills the transmit buffer and leaves the channel empty.
        // Nothing is ever acknowledged, so `can_send()` stays false from here.
        flow.stream.write_all(&[0u8; 4096]).await.unwrap();
        tokio::task::yield_now().await;
        core.step(clock.tick());
        core.drain_tx();

        let handle = *core.flows.keys().next().expect("the flow must still exist");
        assert!(
            !core.sockets.get::<tcp::Socket>(handle).can_send(),
            "precondition: the transmit buffer must be full"
        );

        drop(flow);
        core.step(clock.tick());

        assert_ne!(
            core.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Established,
            "the stack must start closing as soon as the tunnel side is gone, \
             not wait out a deadline"
        );
    }

    #[tokio::test]
    async fn a_dropped_stream_with_a_full_transmit_buffer_is_still_reclaimed() {
        // Both places that would notice the tunnel side vanishing sit inside
        // loops gated on `can_send`/`can_recv`. With the transmit buffer full
        // and nothing arriving, neither body ever runs — and with no idle
        // timeout on `Established`, nothing else would ever reclaim the flow.
        let cfg = StackConfig {
            tcp_buffer_bytes: 4096,
            ..StackConfig::default()
        };
        let mut core = StackCore::new(cfg);
        let mut clock = Clock(0);
        let (mut flow, _, _) = handshake(&mut core, &mut clock, APP, WEB, 1000);

        // Nothing is ever acknowledged, so the transmit buffer fills and stays
        // full: `can_send()` is false from here on.
        for _ in 0..8 {
            let _ = flow.stream.write_all(&[0u8; 2048]).await;
            tokio::task::yield_now().await;
            core.step(clock.tick());
            core.drain_tx();
        }
        drop(flow);

        // Drive the real loop shape, not direct `step` calls: proving the sweep
        // works is not the same as proving the loop ever reaches it.
        let start = clock.tick();
        let mut now = start;
        let mut steps = 0;
        loop {
            core.step(now);
            core.drain_tx();
            steps += 1;
            assert!(steps < 200, "the flow was never reclaimed");
            if core.active_flows() == 0 {
                break;
            }
            // While the flow is still alive the loop must always have something
            // bounded to sleep on, or it parks and never reaches the reclaim.
            let delay = core
                .poll_delay(now)
                .expect("a flow with no tunnel side left must bound the sleep");
            now += delay;
        }
        assert!(
            now <= start + SHUTDOWN_TIMEOUT + SHUTDOWN_TIMEOUT,
            "reclamation must be bounded, took {}s",
            (now - start).secs()
        );
    }

    #[tokio::test]
    async fn a_poll_delay_driven_loop_converges_with_a_closing_flow() {
        // The sibling of the listener convergence test below, covering the half
        // of `next_sweep_deadline` that actually had the stamping bug.
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);
        let (flow, _, _) = handshake(&mut core, &mut clock, APP, WEB, 1000);
        // The stack sends its FIN; the application never acknowledges it.
        drop(flow);

        let mut now = clock.tick();
        let mut steps = 0;
        loop {
            core.step(now);
            core.drain_tx();
            steps += 1;
            assert!(steps < 1000, "the loop is spinning rather than converging");
            match core.poll_delay(now) {
                Some(delay) => now += delay,
                None => break,
            }
        }

        assert_eq!(core.active_flows(), 0, "the flow must have been reclaimed");
    }

    #[test]
    fn a_poll_delay_driven_loop_converges_rather_than_spinning() {
        // Feeding sweep deadlines into `poll_delay` is only safe while every
        // deadline that comes due actually removes something. If one did not,
        // Task 14's loop would sit at a zero delay for ever. Drive the real
        // loop shape and prove it settles.
        let mut core = StackCore::new(StackConfig::default());
        core.ingest(&build_tcp(APP, WEB, TcpFlags::syn(), 1000, 0, &[]));
        let rst = TcpFlags {
            rst: true,
            ..Default::default()
        };
        core.ingest(&build_tcp(APP, WEB, rst, 1001, 0, &[]));

        let mut now = Instant::from_micros(0);
        let mut steps = 0;
        loop {
            core.step(now);
            core.drain_tx();
            steps += 1;
            assert!(steps < 1000, "the loop is spinning rather than converging");
            match core.poll_delay(now) {
                Some(delay) => now += delay,
                None => break,
            }
        }

        assert_eq!(core.armed_len(), 0, "the sweep must have run");
        assert_eq!(core.pending_len(), 0);
    }

    #[tokio::test]
    async fn an_aborted_connection_attempt_releases_its_four_tuple() {
        // smoltcp returns a listen-derived socket to `Listen` on RST rather than
        // to `Closed` (src/socket/tcp.rs:1826, `self.tuple = None;
        // self.set_state(State::Listen)`). Promotion therefore never sees it, and
        // with no remote tuple its `poll_at` is `Ingress`, so the socket timeout
        // never fires either. Only the listener sweep can release the 4-tuple.
        let mut core = StackCore::new(StackConfig::default());
        core.ingest(&build_tcp(APP, WEB, TcpFlags::syn(), 1000, 0, &[]));
        core.step(secs(0));

        let rst = TcpFlags {
            rst: true,
            ..Default::default()
        };
        core.ingest(&build_tcp(APP, WEB, rst, 1001, 0, &[]));
        core.step(secs(1));
        assert_eq!(
            core.armed_len(),
            1,
            "an RST puts the socket back in Listen, still armed"
        );

        core.step(secs(120));
        assert_eq!(core.armed_len(), 0, "the listener sweep releases it");
        assert_eq!(core.pending_len(), 0);
    }

    #[tokio::test]
    async fn a_swept_four_tuple_can_complete_a_fresh_handshake() {
        // Releasing the NAT entry is only half the point; the 4-tuple has to
        // actually work again afterwards.
        let mut core = StackCore::new(StackConfig::default());
        core.ingest(&build_tcp(APP, WEB, TcpFlags::syn(), 1000, 0, &[]));
        core.step(secs(1));
        assert_eq!(core.armed_len(), 1);

        // No ACK ever arrives; the handshake deadline expires.
        core.step(secs(120));
        assert_eq!(
            core.armed_len(),
            0,
            "an abandoned handshake releases its 4-tuple"
        );
        assert_eq!(core.pending_len(), 0);
        core.drain_tx();

        let mut clock = Clock(200_000_000);
        let (flow, _, _) = handshake(&mut core, &mut clock, APP, WEB, 5000);
        assert_eq!(flow.dst, sa(WEB), "the same 4-tuple must be usable again");
        assert_eq!(core.active_flows(), 1);
    }

    #[test]
    fn a_syn_flood_cannot_exhaust_memory() {
        // 1000 SYNs from distinct source ports before a single `step`. Without a
        // cap that is 1000 sockets' worth of buffers, ~131 MB at the defaults.
        let mut core = StackCore::new(StackConfig::default());
        for port in 0..1000u16 {
            core.ingest(&build_tcp(
                (APP.0, 10_000 + port),
                WEB,
                TcpFlags::syn(),
                1000,
                0,
                &[],
            ));
        }

        assert_eq!(core.pending_len(), MAX_PENDING_LISTENERS);
        assert_eq!(core.armed_len(), MAX_PENDING_LISTENERS);
        assert_eq!(
            core.syn_dropped(),
            1000 - MAX_PENDING_LISTENERS as u64,
            "SYNs past the cap must be dropped and counted"
        );
    }

    #[test]
    fn a_listener_that_cannot_be_created_is_disarmed_at_once() {
        // smoltcp cannot listen on port 0, so this exercises the failure branch
        // in `inject_listener`.
        let mut core = StackCore::new(StackConfig::default());
        core.ingest(&build_tcp(APP, (WEB.0, 0), TcpFlags::syn(), 1000, 0, &[]));

        assert_eq!(
            core.armed_len(),
            0,
            "a listener that cannot exist must not stay armed"
        );
        assert_eq!(core.pending_len(), 0);
    }

    #[test]
    fn a_syn_retransmit_does_not_inject_a_second_listener() {
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);

        let syn = build_tcp(APP, WEB, TcpFlags::syn(), 1000, 0, &[]);
        core.ingest(&syn);
        core.ingest(&syn);
        core.step(clock.tick());

        assert_eq!(core.armed_len(), 1, "a retransmit is the same flow");
    }

    #[tokio::test]
    async fn a_listener_that_never_sees_a_handshake_is_reaped_and_disarmed() {
        // A delayed duplicate SYN for a 4-tuple that is already established
        // arms the NAT and injects a listener, but smoltcp hands the segment to
        // the established socket, so the new listener sits in `Listen` for
        // ever. smoltcp's own socket timeout cannot expire it (a listening
        // socket has no remote tuple), and a permanently armed entry means this
        // 4-tuple could never be used again.
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);
        let syn = build_tcp(APP, WEB, TcpFlags::syn(), 1000, 0, &[]);

        let (_flow, _, _) = handshake(&mut core, &mut clock, APP, WEB, 1000);
        assert_eq!(core.armed_len(), 0, "promotion must disarm");

        core.ingest(&syn);
        core.step(clock.tick());
        assert_eq!(core.armed_len(), 1, "the duplicate armed a fresh listener");

        // Well past the idle timeout.
        core.step(Instant::from_micros(120_000_000));
        assert_eq!(
            core.armed_len(),
            0,
            "a listener that never handshakes must release its 4-tuple"
        );
    }

    #[test]
    fn a_dns_datagram_is_surfaced_rather_than_dropped() {
        let mut core = StackCore::new(StackConfig::default());
        let dns = (Ipv4Addr::new(1, 1, 1, 1), 53);
        core.ingest(&build_udp(APP, dns, b"\xAB\xCDquery"));

        let dgs = core.take_datagrams();
        assert_eq!(dgs.len(), 1);
        assert_eq!(dgs[0].dst, sa(dns));
        assert_eq!(dgs[0].payload, b"\xAB\xCDquery".to_vec());
        assert_eq!(core.udp_dropped(), 0);
    }

    #[test]
    fn non_dns_udp_is_dropped_and_counted_never_silently() {
        // Spec §7.5.
        let mut core = StackCore::new(StackConfig::default());
        let quic = (Ipv4Addr::new(93, 184, 216, 34), 443);
        core.ingest(&build_udp(APP, quic, b"quic-ish"));

        assert!(core.take_datagrams().is_empty());
        assert_eq!(core.udp_dropped(), 1, "drops must be visible in stats");
    }

    #[test]
    fn a_malformed_packet_does_not_disturb_the_stack() {
        let mut core = StackCore::new(StackConfig::default());
        core.ingest(&[0xFF, 0x01, 0x02]);
        core.ingest(&[]);
        core.step(Instant::from_micros(0));
        assert_eq!(core.active_flows(), 0);
        assert_eq!(core.udp_dropped(), 0);
    }
}

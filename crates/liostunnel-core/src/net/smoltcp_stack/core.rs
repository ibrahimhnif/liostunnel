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
use crate::net::{Datagram, StackConfig, TcpFlow};

/// How much is moved between a smoltcp socket and its channel per step.
const CHUNK: usize = 8 * 1024;

/// How long a socket may sit half-open before the engine gives up on it.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// The clock the last `step` ran at. `ingest` has no clock of its own, so
    /// this is what an injected listener is timestamped with.
    last_step: Instant,
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
}

fn to_socket_addr(ep: IpEndpoint) -> Option<SocketAddr> {
    match ep.addr {
        IpAddress::Ipv4(v4) => Some(SocketAddr::from((v4, ep.port))),
        IpAddress::Ipv6(v6) => Some(SocketAddr::from((v6, ep.port))),
    }
}

impl StackCore {
    pub fn new(cfg: StackConfig) -> Self {
        let mut device = QueuedDevice::new(cfg.mtu);

        let mut config = Config::new(HardwareAddress::Ip);
        // Fixed so tests are deterministic; the wrapper in Task 14 randomises it.
        config.random_seed = 0x5eed_1105;

        let mut iface = Interface::new(config, &mut device, Instant::from_micros(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(
                    IpAddress::Ipv4(cfg.address),
                    cfg.netmask_prefix,
                ))
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
            last_step: Instant::from_micros(0),
        }
    }

    /// Step 1 of the loop: classify a packet, arm a listener if it opens a new
    /// flow, then queue it for `Interface::poll`. Spec §7.4.
    pub fn ingest(&mut self, packet: &[u8]) {
        match inspect(packet) {
            Inspected::TcpSyn { src, dst } => {
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
            Inspected::Ignored => {}
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
        // A flow whose peer never completes the handshake should not hold a
        // socket for ever.
        socket.set_timeout(Some(IDLE_TIMEOUT));

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
        self.pump_outbound();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.promote_accepted(now);
        self.pump_inbound();
        self.reap_closed();
    }

    fn promote_accepted(&mut self, now: Instant) {
        // A listener whose SYN smoltcp never matched — a delayed duplicate for
        // a 4-tuple that is already established, say — sits in `Listen` for
        // ever, and smoltcp's own socket timeout cannot rescue it: a listening
        // socket has no remote tuple, so its `poll_at` is `Ingress` and the
        // timer never runs. Left alone it pins its `NatTable` entry armed, and
        // that 4-tuple can then never be retried.
        let stale: Vec<SocketHandle> = self
            .pending
            .iter()
            .filter(|(h, p)| {
                self.sockets.get::<tcp::Socket>(**h).state() == tcp::State::Listen
                    && now >= p.injected_at + IDLE_TIMEOUT
            })
            .map(|(h, _)| *h)
            .collect();

        for handle in stale {
            let p = self.pending.remove(&handle).expect("key came from the map");
            self.nat.disarm(&p.src, &p.dst);
            self.sockets.remove(handle);
            tracing::debug!(src = %p.src, dst = %p.dst, "listener expired before any handshake");
        }

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

            let socket = self.sockets.get::<tcp::Socket>(handle);
            if !socket.is_active() {
                // The listener timed out or was reset before establishing.
                self.sockets.remove(handle);
                continue;
            }

            // Prefer the addresses smoltcp actually negotiated.
            let real_src = socket
                .remote_endpoint()
                .and_then(to_socket_addr)
                .unwrap_or(src);
            let real_dst = socket
                .local_endpoint()
                .and_then(to_socket_addr)
                .unwrap_or(dst);

            let (stream, peer) = local_stream_pair(self.cfg.channel_depth);
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
    fn pump_outbound(&mut self) {
        for (handle, flow) in self.flows.iter_mut() {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);

            // (a) finish any chunk the send buffer could not take last time.
            if let Some((chunk, off)) = flow.pending_out.take() {
                if socket.can_send() {
                    match socket.send_slice(&chunk[off..]) {
                        Ok(n) if off + n < chunk.len() => {
                            flow.pending_out = Some((chunk, off + n));
                        }
                        Ok(_) => {}
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
                        Ok(n) if n < chunk.len() => flow.pending_out = Some((chunk, n)),
                        Ok(_) => {}
                        Err(_) => break,
                    },
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        // The engine finished with this flow: send FIN.
                        socket.close();
                        break;
                    }
                }
            }
        }
    }

    /// Application → tunnel. Runs *after* `Interface::poll`, which is what put
    /// the bytes into the socket's receive buffer in the first place.
    fn pump_inbound(&mut self) {
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
                        let mut buf = vec![0u8; CHUNK];
                        match socket.recv_slice(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                buf.truncate(n);
                                permit.send(buf);
                            }
                        }
                    }
                    Err(TrySendError::Full(())) => break,
                    Err(TrySendError::Closed(())) => {
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
            // Dropping the Flow drops both channel ends, which the LocalStream
            // sees as EOF on read and a broken pipe on write — a clean close
            // for whichever side is still using it.
            if let Some(f) = self.flows.remove(&handle) {
                tracing::debug!(src = %f.src, dst = %f.dst, "flow closed");
            }
            self.sockets.remove(handle);
        }
    }

    /// Step 3 of the loop.
    pub fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.device.drain_tx()
    }

    /// Step 5's timeout. `None` means "nothing is pending; sleep until a packet
    /// or a wakeup arrives".
    pub fn poll_delay(&mut self, now: Instant) -> Option<Duration> {
        self.iface.poll_delay(now, &self.sockets)
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

    pub fn active_flows(&self) -> usize {
        self.flows.len()
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

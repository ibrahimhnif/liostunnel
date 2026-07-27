use std::collections::VecDeque;
use std::net::Ipv4Addr;

use crate::error::TunnelError;

/// macOS utun frames every packet with a four-byte big-endian address family.
/// Linux `/dev/net/tun` opened with IFF_NO_PI does not. Decision D2 —
/// this is the only place in the codebase that knows the difference.
pub const AF_INET_BE: [u8; 4] = [0, 0, 0, 2];
pub const AF_INET6_BE: [u8; 4] = [0, 0, 0, 30];

pub fn af_prefix_for(packet: &[u8]) -> Result<[u8; 4], TunnelError> {
    match packet.first().map(|b| b >> 4) {
        Some(4) => Ok(AF_INET_BE),
        Some(6) => Ok(AF_INET6_BE),
        Some(v) => Err(TunnelError::Tun(format!("unknown IP version {v}"))),
        None => Err(TunnelError::Tun("empty packet".into())),
    }
}

pub fn strip_af_prefix(framed: &[u8]) -> Result<&[u8], TunnelError> {
    if framed.len() < 4 {
        return Err(TunnelError::Tun(format!(
            "packet of {} bytes is shorter than the utun address-family prefix",
            framed.len()
        )));
    }
    Ok(&framed[4..])
}

/// Reads and writes **bare IP packets**. Implementations hide any platform framing.
pub trait PacketIo: Send {
    /// Returns 0 when nothing is currently available.
    ///
    /// Implementations must not block: the driving loop calls this until it
    /// answers 0 and then sleeps on [`PacketIo::pollable_fd`], so a blocking
    /// read here would park the loop somewhere it cannot be woken.
    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunnelError>;
    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunnelError>;
    fn mtu(&self) -> usize;

    /// The descriptor to wait on, when the implementation has one.
    /// `None` means the caller must fall back to a timed poll — only the
    /// in-memory test double does this.
    #[cfg(unix)]
    fn pollable_fd(&self) -> Option<std::os::fd::RawFd> {
        None
    }
}

#[derive(Clone, Debug)]
pub struct TunConfig {
    pub name: Option<String>,
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: None,
            address: Ipv4Addr::new(10, 90, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1500,
        }
    }
}

/// In-memory `PacketIo` used by every stack test, so the poll loop is testable
/// without a device or elevated privileges. Spec §12.
pub struct FakePacketIo {
    inbound: VecDeque<Vec<u8>>,
    outbound: Vec<Vec<u8>>,
    mtu: usize,
}

impl FakePacketIo {
    pub fn new(mtu: usize) -> Self {
        Self {
            inbound: VecDeque::new(),
            outbound: Vec::new(),
            mtu,
        }
    }

    /// Queue a packet as though an application on the device had sent it.
    pub fn push_inbound(&mut self, packet: Vec<u8>) {
        self.inbound.push_back(packet);
    }

    /// Take everything the stack has written back towards the device.
    pub fn take_outbound(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outbound)
    }

    pub fn outbound_len(&self) -> usize {
        self.outbound.len()
    }
}

impl PacketIo for FakePacketIo {
    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunnelError> {
        match self.inbound.pop_front() {
            None => Ok(0),
            Some(p) => {
                if p.len() > buf.len() {
                    return Err(TunnelError::Tun(format!(
                        "packet of {} bytes exceeds the {}-byte read buffer",
                        p.len(),
                        buf.len()
                    )));
                }
                buf[..p.len()].copy_from_slice(&p);
                Ok(p.len())
            }
        }
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunnelError> {
        self.outbound.push(packet.to_vec());
        Ok(())
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}

/// The macOS utun address-family framing, and the two buffers it needs.
///
/// Split out from [`TunDevice`] for one reason: the buffers *are* the subtlety
/// here, and opening a real device needs root, so this is the only way the
/// invariant below can have a test at all.
///
/// **Read and write must not share a buffer.** A shared one works right up
/// until the first write, which truncates it to that packet's framed length —
/// 48 bytes for a SYN-ACK. Every subsequent `recv` is then handed 48 bytes
/// instead of `mtu + 4`, and on a `SOCK_DGRAM` utun descriptor the excess is
/// discarded *silently* rather than erroring. So reads keep succeeding and
/// every inbound packet after the first outbound one arrives truncated, with
/// no error anywhere to explain it.
pub(crate) struct UtunFraming {
    /// Sized for one full framed packet, and never resized.
    read: Vec<u8>,
    /// Rebuilt from scratch on every write. Never handed to a read.
    write: Vec<u8>,
}

impl UtunFraming {
    pub(crate) fn new(mtu: usize) -> Self {
        Self {
            read: vec![0u8; mtu + 4],
            write: Vec::with_capacity(mtu + 4),
        }
    }

    /// The buffer to hand to the device's `recv`. Always the full length.
    pub(crate) fn read_buf(&mut self) -> &mut [u8] {
        &mut self.read
    }

    /// Strips the address-family prefix off the `n` bytes just read into
    /// [`Self::read_buf`], copying the bare IP packet into `out`.
    pub(crate) fn finish_read(&self, n: usize, out: &mut [u8]) -> Result<usize, TunnelError> {
        let ip = strip_af_prefix(&self.read[..n])?;
        if ip.len() > out.len() {
            return Err(TunnelError::Tun(format!(
                "packet of {} bytes exceeds the {}-byte read buffer",
                ip.len(),
                out.len()
            )));
        }
        out[..ip.len()].copy_from_slice(ip);
        Ok(ip.len())
    }

    /// The framed bytes to hand to the device's `send`.
    pub(crate) fn frame_for_write(&mut self, packet: &[u8]) -> Result<&[u8], TunnelError> {
        self.write.clear();
        self.write.extend_from_slice(&af_prefix_for(packet)?);
        self.write.extend_from_slice(packet);
        Ok(&self.write)
    }
}

/// The real TUN device. macOS framing is applied here and nowhere else.
pub struct TunDevice {
    inner: tun_rs::SyncDevice,
    mtu: usize,
    /// True on macOS, where utun prepends the address family.
    framed: bool,
    framing: UtunFraming,
}

impl TunDevice {
    pub fn open(cfg: TunConfig) -> Result<Self, TunnelError> {
        let mut builder = tun_rs::DeviceBuilder::new()
            .ipv4(cfg.address, cfg.netmask, None)
            .mtu(cfg.mtu);
        if let Some(name) = &cfg.name {
            builder = builder.name(name);
        }
        let inner = builder
            .build_sync()
            .map_err(|e| TunnelError::Tun(format!("cannot create TUN interface: {e}")))?;

        // tun-rs opens the device blocking. The driving loop reads until the
        // device says 0 and only then sleeps on the descriptor, so a blocking
        // read would park it inside `recv` — deaf to the shutdown flag, to the
        // wakeup, and to every smoltcp timer. It is also what makes the
        // `WouldBlock` arm in `read_packet` reachable at all.
        inner.set_nonblocking(true).map_err(|e| {
            TunnelError::Tun(format!("cannot set the TUN device non-blocking: {e}"))
        })?;

        Ok(Self {
            inner,
            mtu: cfg.mtu as usize,
            framed: cfg!(target_os = "macos"),
            framing: UtunFraming::new(cfg.mtu as usize),
        })
    }

    pub fn name(&self) -> Result<String, TunnelError> {
        self.inner
            .name()
            .map_err(|e| TunnelError::Tun(format!("cannot read interface name: {e}")))
    }
}

#[cfg(unix)]
impl std::os::fd::AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inner.as_raw_fd()
    }
}

impl PacketIo for TunDevice {
    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunnelError> {
        if !self.framed {
            return match self.inner.recv(buf) {
                Ok(n) => Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
                Err(e) => Err(TunnelError::Tun(format!("read failed: {e}"))),
            };
        }
        let n = match self.inner.recv(self.framing.read_buf()) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(0),
            Err(e) => return Err(TunnelError::Tun(format!("read failed: {e}"))),
        };
        self.framing.finish_read(n, buf)
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunnelError> {
        let out = if self.framed {
            self.framing.frame_for_write(packet)?
        } else {
            packet
        };
        self.inner
            .send(out)
            .map(|_| ())
            .map_err(|e| TunnelError::Tun(format!("write failed: {e}")))
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    #[cfg(unix)]
    fn pollable_fd(&self) -> Option<std::os::fd::RawFd> {
        use std::os::fd::AsRawFd;
        Some(self.as_raw_fd())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal well-formed IPv4 header — enough for version sniffing.
    fn ipv4() -> Vec<u8> {
        let mut v = vec![0u8; 20];
        v[0] = 0x45;
        v
    }

    fn ipv6() -> Vec<u8> {
        let mut v = vec![0u8; 40];
        v[0] = 0x60;
        v
    }

    #[test]
    fn af_prefix_is_chosen_from_the_ip_version() {
        assert_eq!(af_prefix_for(&ipv4()).unwrap(), [0, 0, 0, 2]);
        assert_eq!(af_prefix_for(&ipv6()).unwrap(), [0, 0, 0, 30]);
    }

    #[test]
    fn af_prefix_rejects_a_packet_that_is_neither_v4_nor_v6() {
        let mut junk = vec![0u8; 20];
        junk[0] = 0x35;
        assert!(af_prefix_for(&junk).is_err());
    }

    #[test]
    fn af_prefix_rejects_an_empty_packet() {
        assert!(af_prefix_for(&[]).is_err());
    }

    #[test]
    fn stripping_removes_exactly_four_bytes() {
        let mut framed = vec![0, 0, 0, 2];
        framed.extend_from_slice(&ipv4());
        assert_eq!(strip_af_prefix(&framed).unwrap(), &ipv4()[..]);
    }

    #[test]
    fn stripping_rejects_a_runt() {
        assert!(strip_af_prefix(&[0, 0, 0]).is_err());
    }

    #[test]
    fn prefix_then_strip_is_the_identity() {
        let pkt = ipv6();
        let mut framed = af_prefix_for(&pkt).unwrap().to_vec();
        framed.extend_from_slice(&pkt);
        assert_eq!(strip_af_prefix(&framed).unwrap(), &pkt[..]);
    }

    #[test]
    fn the_fake_device_round_trips_bare_ip_packets() {
        let mut io = FakePacketIo::new(1500);
        io.push_inbound(ipv4());

        let mut buf = [0u8; 2048];
        let n = io.read_packet(&mut buf).unwrap();
        assert_eq!(&buf[..n], &ipv4()[..]);

        io.write_packet(&ipv6()).unwrap();
        assert_eq!(io.take_outbound(), vec![ipv6()]);
    }

    #[test]
    fn a_write_never_shrinks_the_buffer_the_next_read_uses() {
        // Read and write shared one `scratch` buffer until this pass. The first
        // framed write truncated it to that packet's length, so every later
        // `recv` was handed a fraction of the MTU.
        let mut framing = UtunFraming::new(1500);
        assert_eq!(framing.read_buf().len(), 1504);

        let mut synack = vec![0u8; 44];
        synack[0] = 0x45;
        assert_eq!(framing.frame_for_write(&synack).unwrap().len(), 48);

        assert_eq!(
            framing.read_buf().len(),
            1504,
            "a write must not resize the buffer reads are handed"
        );
    }

    #[test]
    fn a_full_mtu_packet_still_reads_whole_after_a_write() {
        // The behavioural half: not just "the buffer is the right length" but
        // "a full-MTU packet survives a read that follows a write". With the
        // shared buffer this lost 1456 of 1500 bytes, and a `SOCK_DGRAM` utun
        // descriptor discards the excess silently — no error, no log, just a
        // corrupt packet handed to `StackCore::ingest`.
        const MTU: usize = 1500;
        let mut framing = UtunFraming::new(MTU);

        let mut synack = vec![0u8; 44];
        synack[0] = 0x45;
        framing.frame_for_write(&synack).unwrap();

        let mut inbound = vec![0u8; MTU];
        inbound[0] = 0x45;
        inbound[MTU - 1] = 0xEE; // the tail the truncation used to eat
        let mut delivered = AF_INET_BE.to_vec();
        delivered.extend_from_slice(&inbound);

        let read_buf = framing.read_buf();
        assert!(
            read_buf.len() >= delivered.len(),
            "the read buffer holds only {} bytes, so the device would truncate",
            read_buf.len()
        );
        read_buf[..delivered.len()].copy_from_slice(&delivered);

        let mut out = vec![0u8; MTU];
        let n = framing.finish_read(delivered.len(), &mut out).unwrap();
        assert_eq!(n, MTU, "the whole packet must survive the round trip");
        assert_eq!(out[..n], inbound[..]);
    }

    #[test]
    fn a_packet_too_large_for_the_callers_buffer_is_an_error_not_a_panic() {
        let mut framing = UtunFraming::new(1500);
        let mut delivered = AF_INET_BE.to_vec();
        delivered.extend_from_slice(&[0x45u8; 100]);
        framing.read_buf()[..delivered.len()].copy_from_slice(&delivered);

        let mut out = [0u8; 64];
        assert!(framing.finish_read(delivered.len(), &mut out).is_err());
    }

    #[test]
    fn the_fake_device_reports_zero_when_drained() {
        let mut io = FakePacketIo::new(1500);
        let mut buf = [0u8; 64];
        assert_eq!(io.read_packet(&mut buf).unwrap(), 0);
    }
}

use std::collections::VecDeque;
use std::net::Ipv4Addr;

use crate::error::TunnelError;

/// Reads and writes bare IP packets on every platform.
///
/// The macOS utun address-family header is handled inside `tun-rs`, which
/// constructs its `Tun` with `ignore_packet_information: true` — `recv`
/// returns `len - 4` with the head read into a scratch buffer, and `send`
/// prepends it. This crate deliberately knows nothing about that framing;
/// duplicating it here is what broke macOS entirely.
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

/// The real TUN device.
///
/// **The utun address-family header is `tun-rs`'s job, not ours.** On macOS
/// its `Tun` is constructed with `ignore_packet_information: true`, so `recv`
/// reads the four-byte head into a scratch buffer and returns `len - PIL` —
/// a bare IP packet — while `send` prepends the header itself.
///
/// This type used to apply that framing a *second* time on macOS. The extra
/// strip ate the first four bytes of every IP header, smoltcp discarded the
/// result without a word, and the tunnel carried nothing: packets reached the
/// interface, the stack thread stayed alive, and every counter read zero.
/// Phase 0 never caught it because all of its traffic-carrying exit criteria
/// ran in a Linux container, where `tun-rs` adds no header and the second
/// framing was correctly skipped.
pub struct TunDevice {
    inner: tun_rs::SyncDevice,
    mtu: usize,
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
        // Bare IP on every platform: tun-rs has already removed the utun
        // address-family header on macOS, and Linux never had one.
        match self.inner.recv(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(TunnelError::Tun(format!("read failed: {e}"))),
        }
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunnelError> {
        // Bare IP goes in: tun-rs prepends the utun address-family header on
        // macOS. Adding one here too produced a double header the kernel
        // rejected.
        self.inner
            .send(packet)
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
    fn a_packet_too_large_for_the_callers_buffer_is_an_error_not_a_panic() {
        let mut io = FakePacketIo::new(1500);
        io.push_inbound(vec![0x45u8; 200]);
        let mut out = [0u8; 64];
        assert!(io.read_packet(&mut out).is_err());
    }

    /// A packet handed to `write_packet` must reach the device unchanged.
    ///
    /// This crate adds no framing of its own. It used to add the macOS utun
    /// address-family header, which `tun-rs` already adds — the resulting
    /// double header was rejected, and the matching double strip on read ate
    /// the first four bytes of every inbound IP header, so macOS carried no
    /// traffic at all while every counter read zero.
    #[test]
    fn nothing_is_prepended_to_an_outgoing_packet() {
        let mut io = FakePacketIo::new(1500);
        io.write_packet(&ipv4()).unwrap();
        let out = io.take_outbound();
        assert_eq!(out, vec![ipv4()], "the packet must go out byte-identical");
        assert_ne!(
            &out[0][..4],
            &[0, 0, 0, 2],
            "an address-family header here means it is being applied twice"
        );
    }

    #[test]
    fn the_fake_device_reports_zero_when_drained() {
        let mut io = FakePacketIo::new(1500);
        let mut buf = [0u8; 64];
        assert_eq!(io.read_packet(&mut buf).unwrap(), 0);
    }
}

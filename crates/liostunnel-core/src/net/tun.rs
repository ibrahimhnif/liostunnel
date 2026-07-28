use std::collections::VecDeque;
use std::net::Ipv4Addr;

use crate::error::TunnelError;

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
            // Stated, not inherited. macOS correctness rests on tun-rs
            // stripping the utun address-family header itself; it does that by
            // default today, but a default is not a contract. Saying so here
            // means a change upstream breaks the build's intent visibly
            // instead of silently returning framed packets.
            .packet_information(false)
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
        // Bare IP on every platform: tun-rs removes the utun address-family
        // header on macOS, and Linux never had one.
        let n = match self.inner.recv(buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(0),
            Err(e) => return Err(TunnelError::Tun(format!("read failed: {e}"))),
        };

        // A framed packet begins with the address family (`\0\0\0\x02`), so
        // its first nibble is 0 rather than 4 or 6. Rejecting that here is the
        // difference between a loud error and the failure this whole layer was
        // rewritten for: double-framing made every packet unparseable, smoltcp
        // dropped it into `malformed_dropped` — the one `Inspected` arm that
        // logs nothing, read by nobody — and macOS carried no traffic at all
        // while every counter read zero and no line appeared anywhere.
        if n > 0 && !matches!(buf[0] >> 4, 4 | 6) {
            return Err(TunnelError::Tun(format!(
                "read a packet whose first nibble is {} — not IPv4 or IPv6. \
                 The device is delivering framed packets; tun-rs is expected \
                 to strip the utun address-family header itself",
                buf[0] >> 4
            )));
        }
        Ok(n)
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

    /// The framing guard rejects what a double-framed device would deliver.
    ///
    /// This is deliberately a unit test of the *classification*, not of
    /// `TunDevice` — opening a real device needs root. It exists because the
    /// test that previously carried this name exercised `FakePacketIo`, whose
    /// `write_packet` is a passthrough that structurally cannot prepend
    /// anything: restoring the double-framing bug left it green, wearing the
    /// defect's name.
    #[test]
    fn a_framed_packet_is_not_mistaken_for_bare_ip() {
        // What a utun device delivers when nobody strips the header.
        let mut framed = vec![0u8, 0, 0, 2];
        framed.extend_from_slice(&ipv4());
        assert!(
            !matches!(framed[0] >> 4, 4 | 6),
            "an address-family header must not read as an IP version"
        );
        // And what it delivers when somebody does.
        assert!(matches!(ipv4()[0] >> 4, 4 | 6));
        assert!(matches!(ipv6()[0] >> 4, 4 | 6));
    }

    #[test]
    fn the_fake_device_reports_zero_when_drained() {
        let mut io = FakePacketIo::new(1500);
        let mut buf = [0u8; 64];
        assert_eq!(io.read_packet(&mut buf).unwrap(), 0);
    }
}

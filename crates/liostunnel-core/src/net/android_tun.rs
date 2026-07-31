//! [`PacketIo`] over a descriptor somebody else configured.
//!
//! # Why this is not `#[cfg(target_os = "android")]`
//!
//! Nothing in here is Android-specific: it is `read(2)`, `write(2)` and
//! `fcntl(2)` on a descriptor. Gating it to Android would put the whole thing
//! beyond the reach of `cargo test` on a development machine and beyond CI,
//! for no benefit — and this phase already has an untestable surface it cannot
//! avoid (the JNI bridge in `platform::android`). Keeping this compiled
//! everywhere is what lets the byte-level behaviour be tested against a
//! `pipe(2)` on the machine the code is written on.
//!
//! On Android the descriptor comes from `VpnService.establish()` via
//! `ParcelFileDescriptor.detachFd()`, already carrying its address, routes and
//! MTU. There is no device to create and nothing to configure, which is why
//! `TunDevice` has no Android counterpart.

use crate::error::TunnelError;
use crate::net::tun::PacketIo;
use std::os::fd::RawFd;

/// A tunnel interface this process did not create.
///
/// Owns `fd` and closes it on drop: `detachFd()` gives up the Java-side
/// descriptor, so nothing else will.
pub struct AndroidTun {
    fd: RawFd,
    mtu: usize,
}

impl AndroidTun {
    /// Takes ownership of `fd` and puts it in non-blocking mode.
    ///
    /// The driving loop reads until the device reports 0 and only then sleeps
    /// on the descriptor, so a blocking descriptor would park it inside
    /// `read` — deaf to the shutdown flag, the wakeup, and every smoltcp
    /// timer. It is also what makes the `WouldBlock` arm of [`read_packet`]
    /// reachable at all.
    ///
    /// [`read_packet`]: PacketIo::read_packet
    pub fn new(fd: RawFd, mtu: usize) -> Result<Self, TunnelError> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(TunnelError::Tun(format!(
                "cannot read descriptor flags: {}",
                std::io::Error::last_os_error()
            )));
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(TunnelError::Tun(format!(
                "cannot set the tunnel descriptor non-blocking: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self { fd, mtu })
    }
}

impl PacketIo for AndroidTun {
    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunnelError> {
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            return match e.kind() {
                // The contract is 0, not an error. Returning an error here
                // kills the driving loop on its very first idle poll, which
                // presents as a tunnel that connects and instantly dies.
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => Ok(0),
                _ => Err(TunnelError::Tun(format!("read failed: {e}"))),
            };
        }
        let n = n as usize;

        // `VpnService` delivers bare IP, with no address-family header -- the
        // framing that silently ate four bytes of every packet on macOS until
        // it was found. Checking costs one nibble and turns the same class of
        // mistake into a loud error rather than a tunnel that carries nothing
        // while every counter reads zero.
        if n > 0 && !matches!(buf[0] >> 4, 4 | 6) {
            return Err(TunnelError::Tun(format!(
                "read a packet whose first nibble is {} — not IPv4 or IPv6. \
                 The descriptor is delivering framed packets; VpnService is \
                 expected to deliver bare IP",
                buf[0] >> 4
            )));
        }
        Ok(n)
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunnelError> {
        let n = unsafe { libc::write(self.fd, packet.as_ptr().cast(), packet.len()) };
        if n < 0 {
            return Err(TunnelError::Tun(format!(
                "write failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        // A tun descriptor is packet-oriented: it writes a whole packet or
        // none. A short write means the kernel took part of an IP packet,
        // which is not something to paper over by looping.
        if (n as usize) != packet.len() {
            return Err(TunnelError::Tun(format!(
                "short write: {n} of {} bytes",
                packet.len()
            )));
        }
        Ok(())
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    #[cfg(unix)]
    fn pollable_fd(&self) -> Option<RawFd> {
        Some(self.fd)
    }
}

impl Drop for AndroidTun {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A four-byte IPv4 header stub: version nibble 4, so the guard in
    /// `read_packet` accepts it. Contents beyond the first nibble are not
    /// inspected by this layer.
    const IPV4ISH: &[u8] = &[0x45, 0x00, 0x00, 0x14];

    fn pipe_pair() -> (AndroidTun, AndroidTun) {
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe(2) failed");
        (
            AndroidTun::new(fds[0], 1500).expect("read end"),
            AndroidTun::new(fds[1], 1500).expect("write end"),
        )
    }

    /// An idle descriptor reports "nothing available", not a failure.
    ///
    /// This is the assertion that fails if the `WouldBlock` arm is removed,
    /// and the failure it protects against is not subtle: the driving loop
    /// polls until it reads 0, so an error on the first idle poll stops the
    /// tunnel immediately after it appears to connect.
    #[test]
    fn an_idle_descriptor_reads_zero_rather_than_erroring() {
        let (mut rx, _tx) = pipe_pair();
        let mut buf = [0u8; 2048];
        assert_eq!(rx.read_packet(&mut buf).expect("idle read"), 0);
    }

    #[test]
    fn a_written_packet_is_read_back_intact() {
        let (mut rx, mut tx) = pipe_pair();
        tx.write_packet(IPV4ISH).expect("write");
        let mut buf = [0u8; 2048];
        assert_eq!(rx.read_packet(&mut buf).expect("read"), IPV4ISH.len());
        assert_eq!(&buf[..IPV4ISH.len()], IPV4ISH);
    }

    /// Framed packets are rejected loudly.
    ///
    /// A leading address-family header makes the first nibble 0. On macOS the
    /// equivalent mistake was invisible: smoltcp discarded every packet and
    /// the tunnel carried nothing while reporting no error at all.
    #[test]
    fn a_packet_that_is_not_ip_is_an_error_not_a_silent_drop() {
        let (mut rx, mut tx) = pipe_pair();
        tx.write_packet(&[0x00, 0x00, 0x00, 0x02]).expect("write");
        let mut buf = [0u8; 2048];
        let err = rx.read_packet(&mut buf).expect_err("should reject");
        assert!(
            format!("{err}").contains("not IPv4 or IPv6"),
            "unexpected error: {err}"
        );
    }

    /// `new` reports a bad descriptor instead of producing a tun that fails
    /// on every later read.
    #[test]
    fn a_descriptor_that_is_not_open_is_refused_at_construction() {
        // `expect_err` would need `AndroidTun: Debug`, and deriving it on a
        // type that owns a descriptor invites logging the descriptor.
        let Err(err) = AndroidTun::new(-1, 1500) else {
            panic!("a closed descriptor should be refused");
        };
        assert!(
            format!("{err}").contains("cannot read descriptor flags"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn the_descriptor_is_offered_for_polling() {
        let (rx, _tx) = pipe_pair();
        assert_eq!(rx.pollable_fd(), Some(rx.fd));
        assert_eq!(rx.mtu(), 1500);
    }
}

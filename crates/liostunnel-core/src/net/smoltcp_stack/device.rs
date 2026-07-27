use std::collections::VecDeque;

use smoltcp::phy::{Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

/// A `smoltcp::phy::Device` backed by two queues rather than a file descriptor.
///
/// This indirection is what makes the whole engine testable without a TUN
/// device (spec §12) and is also what makes SYN-triggered listener injection
/// possible at all: packets must be inspectable *before* `Interface::poll`
/// runs, and the `SocketSet` cannot be mutated from inside `Device::receive`.
/// Spec §7.4.
pub struct QueuedDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl QueuedDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        }
    }

    pub fn push_rx(&mut self, packet: Vec<u8>) {
        self.rx.push_back(packet);
    }

    pub fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.tx.drain(..).collect()
    }

    /// Queues a fully-formed packet for the device, bypassing smoltcp
    /// entirely. Used for synthesised DNS replies, which never touch a
    /// smoltcp socket. Spec §7.5.
    pub fn push_tx(&mut self, packet: Vec<u8>) {
        self.tx.push_back(packet);
    }

    pub fn rx_len(&self) -> usize {
        self.rx.len()
    }
}

pub struct QueuedRxToken(Vec<u8>);

impl smoltcp::phy::RxToken for QueuedRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

pub struct QueuedTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl smoltcp::phy::TxToken for QueuedTxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl Device for QueuedDevice {
    type RxToken<'a>
        = QueuedRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = QueuedTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _t: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((QueuedRxToken(packet), QueuedTxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _t: Instant) -> Option<Self::TxToken<'_>> {
        Some(QueuedTxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        // A TUN device carries no Ethernet frame, and nothing between us and the
        // application corrupts bytes — but leave IP/TCP checksums on so malformed
        // packets from a misbehaving app are rejected rather than proxied.
        let mut cks = ChecksumCapabilities::default();
        cks.ipv4 = Checksum::Both;
        cks.tcp = Checksum::Both;
        cks.udp = Checksum::Both;
        caps.checksum = cks;
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::{Device, RxToken, TxToken};
    use smoltcp::time::Instant;

    #[test]
    fn a_drained_device_yields_nothing_to_receive() {
        let mut d = QueuedDevice::new(1500);
        assert!(d.receive(Instant::from_micros(0)).is_none());
    }

    #[test]
    fn queued_packets_are_handed_to_smoltcp_in_order() {
        let mut d = QueuedDevice::new(1500);
        d.push_rx(vec![1, 2, 3]);
        d.push_rx(vec![4, 5]);

        let (rx, _tx) = d.receive(Instant::from_micros(0)).unwrap();
        assert_eq!(rx.consume(|b| b.to_vec()), vec![1, 2, 3]);

        let (rx, _tx) = d.receive(Instant::from_micros(0)).unwrap();
        assert_eq!(rx.consume(|b| b.to_vec()), vec![4, 5]);

        assert!(d.receive(Instant::from_micros(0)).is_none());
    }

    #[test]
    fn transmitted_packets_land_in_the_tx_queue() {
        let mut d = QueuedDevice::new(1500);
        let tx = d.transmit(Instant::from_micros(0)).unwrap();
        tx.consume(4, |buf| buf.copy_from_slice(&[9, 9, 9, 9]));

        assert_eq!(d.drain_tx(), vec![vec![9, 9, 9, 9]]);
        assert!(d.drain_tx().is_empty(), "draining must consume");
    }

    #[test]
    fn a_pushed_packet_reaches_drain_tx_ahead_of_smoltcps_own_transmits() {
        let mut d = QueuedDevice::new(1500);
        d.push_tx(vec![1, 2, 3]);
        let tx = d.transmit(Instant::from_micros(0)).unwrap();
        tx.consume(2, |buf| buf.copy_from_slice(&[9, 9]));

        assert_eq!(d.drain_tx(), vec![vec![1, 2, 3], vec![9, 9]]);
    }

    #[test]
    fn capabilities_report_the_ip_medium_and_configured_mtu() {
        let d = QueuedDevice::new(1400);
        let caps = d.capabilities();
        assert_eq!(caps.max_transmission_unit, 1400);
        assert_eq!(caps.medium, smoltcp::phy::Medium::Ip);
    }
}

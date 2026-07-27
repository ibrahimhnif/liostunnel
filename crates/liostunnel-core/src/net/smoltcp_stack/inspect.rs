use std::net::SocketAddr;

use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket, UdpPacket};

/// What a packet drained off the TUN device turns out to be. Spec §7.4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inspected {
    /// A connection attempt to an endpoint we may not be listening on yet.
    TcpSyn { src: SocketAddr, dst: SocketAddr },
    /// Any other TCP segment — smoltcp already has state for it.
    TcpOther { src: SocketAddr, dst: SocketAddr },
    Udp {
        src: SocketAddr,
        dst: SocketAddr,
        payload: Vec<u8>,
    },
    /// Malformed, truncated, or a protocol Phase 0 does not carry.
    Ignored,
}

/// Classifies a bare IPv4 packet. Never panics and never mutates — a malformed
/// packet from a misbehaving application must not be able to stop the engine.
pub fn inspect(packet: &[u8]) -> Inspected {
    let Ok(ip) = Ipv4Packet::new_checked(packet) else {
        return Inspected::Ignored;
    };
    if !ip.verify_checksum() {
        return Inspected::Ignored;
    }

    let src_ip = ip.src_addr();
    let dst_ip = ip.dst_addr();
    let (sa, da) = (IpAddress::Ipv4(src_ip), IpAddress::Ipv4(dst_ip));

    match ip.next_header() {
        IpProtocol::Tcp => {
            let Ok(tcp) = TcpPacket::new_checked(ip.payload()) else {
                return Inspected::Ignored;
            };
            if !tcp.verify_checksum(&sa, &da) {
                return Inspected::Ignored;
            }
            let src = SocketAddr::from((src_ip, tcp.src_port()));
            let dst = SocketAddr::from((dst_ip, tcp.dst_port()));
            // A SYN without ACK is a fresh connection attempt; a SYN-ACK belongs
            // to a handshake smoltcp is already driving.
            if tcp.syn() && !tcp.ack() {
                Inspected::TcpSyn { src, dst }
            } else {
                Inspected::TcpOther { src, dst }
            }
        }
        IpProtocol::Udp => {
            let Ok(udp) = UdpPacket::new_checked(ip.payload()) else {
                return Inspected::Ignored;
            };
            if !udp.verify_checksum(&sa, &da) {
                return Inspected::Ignored;
            }
            Inspected::Udp {
                src: SocketAddr::from((src_ip, udp.src_port())),
                dst: SocketAddr::from((dst_ip, udp.dst_port())),
                payload: udp.payload().to_vec(),
            }
        }
        _ => Inspected::Ignored,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::testutil::{TcpFlags, build_tcp, build_udp};
    use std::net::{Ipv4Addr, SocketAddr};

    const APP: (Ipv4Addr, u16) = (Ipv4Addr::new(10, 90, 0, 2), 51234);
    const WEB: (Ipv4Addr, u16) = (Ipv4Addr::new(93, 184, 216, 34), 443);

    fn sa(t: (Ipv4Addr, u16)) -> SocketAddr {
        SocketAddr::from(t)
    }

    #[test]
    fn a_bare_syn_is_recognised_as_a_new_connection() {
        let pkt = build_tcp(APP, WEB, TcpFlags::syn(), 1000, 0, &[]);
        assert_eq!(
            inspect(&pkt),
            Inspected::TcpSyn {
                src: sa(APP),
                dst: sa(WEB)
            }
        );
    }

    #[test]
    fn a_syn_ack_is_not_a_new_connection() {
        let mut flags = TcpFlags::syn();
        flags.ack = true;
        let pkt = build_tcp(WEB, APP, flags, 5000, 1001, &[]);
        assert_eq!(
            inspect(&pkt),
            Inspected::TcpOther {
                src: sa(WEB),
                dst: sa(APP)
            }
        );
    }

    #[test]
    fn an_established_data_segment_is_tcp_other() {
        let pkt = build_tcp(APP, WEB, TcpFlags::ack(), 1001, 5001, b"GET /");
        assert_eq!(
            inspect(&pkt),
            Inspected::TcpOther {
                src: sa(APP),
                dst: sa(WEB)
            }
        );
    }

    #[test]
    fn a_udp_datagram_carries_its_payload_out() {
        let dns = (Ipv4Addr::new(1, 1, 1, 1), 53);
        let pkt = build_udp(APP, dns, b"\xAB\xCD query");
        assert_eq!(
            inspect(&pkt),
            Inspected::Udp {
                src: sa(APP),
                dst: sa(dns),
                payload: b"\xAB\xCD query".to_vec()
            }
        );
    }

    #[test]
    fn icmp_and_other_protocols_are_ignored() {
        let mut pkt = build_udp(APP, WEB, b"x");
        // Rewrite the protocol field to ICMP.
        pkt[9] = 1;
        assert_eq!(inspect(&pkt), Inspected::Ignored);
    }

    #[test]
    fn a_truncated_packet_is_ignored_rather_than_panicking() {
        let pkt = build_tcp(APP, WEB, TcpFlags::syn(), 1, 0, &[]);
        assert_eq!(inspect(&pkt[..10]), Inspected::Ignored);
        assert_eq!(inspect(&[]), Inspected::Ignored);
    }

    #[test]
    fn a_packet_with_a_corrupt_checksum_is_ignored() {
        let mut pkt = build_tcp(APP, WEB, TcpFlags::syn(), 1000, 0, &[]);
        pkt[36] ^= 0xFF; // flip a byte inside the TCP checksum field
        assert_eq!(inspect(&pkt), Inspected::Ignored);
    }
}

//! DNS interception and UDP reply synthesis. Spec §7.5, §9.1. Decision D3.
//!
//! The PRD descopes UDP for the SSH protocol (§11) but also requires DNS leak
//! protection (EC4). Both hold only because DNS is handled specially: a
//! UDP:53 datagram is intercepted at the packet layer
//! (`StackCore::ingest`), the query is carried through the tunnel by a
//! [`Resolver`], and the reply is synthesised straight back into a raw
//! UDP/IP packet by [`build_udp_packet`] — no `UdpSocket`, no socket
//! lifecycle smoltcp needs to know about at all.
//!
//! The two concrete resolvers land in later tasks: `over_tcp` (RFC 7766,
//! Task 19) and `over_https` (DoH, Task 20). This module only defines the
//! trait they implement, plus interception and synthesis, both of which are
//! exercised end-to-end without either backend existing yet.

pub mod over_https;
pub mod over_tcp;

use std::net::SocketAddr;

use async_trait::async_trait;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, UdpPacket};

use crate::error::TunnelError;

/// Resolves a DNS query by carrying it through the tunnel. Decision D3.
///
/// Takes and returns raw DNS wire-format bytes only. Nothing in this trait,
/// or in anything that calls it, parses or logs the query name or the
/// answer — a DNS query names exactly what a user is browsing, and is as
/// sensitive as the traffic itself. Log query counts and outcomes, never
/// names or payload bytes.
#[async_trait]
pub trait Resolver: Send + Sync {
    async fn query(&self, query: &[u8]) -> Result<Vec<u8>, TunnelError>;
}

/// A resolver that always fails. Used wherever no real backend is wired in
/// yet (Tasks 19/20 add `over_tcp`/`over_https`); a query against it drops
/// silently on the wire exactly like any other failed resolution, per the
/// module's own rule that answering wrongly is worse than not answering.
pub struct UnimplementedResolver;

#[async_trait]
impl Resolver for UnimplementedResolver {
    async fn query(&self, _query: &[u8]) -> Result<Vec<u8>, TunnelError> {
        Err(TunnelError::Dns(
            "no DNS resolver backend is wired in yet".into(),
        ))
    }
}

/// The transaction id, used to match a reply to its query.
pub fn dns_query_id(payload: &[u8]) -> Option<u16> {
    if payload.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([payload[0], payload[1]]))
}

/// Builds a complete IPv4 + UDP packet carrying `payload`. Checksums must be
/// right or the host's own network stack silently discards the reply — no
/// error, no log, just a DNS timeout that looks exactly like a hang.
pub fn build_udp_packet(
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, TunnelError> {
    let (s4, d4) = match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => (s, d),
        _ => {
            return Err(TunnelError::Dns(
                "Phase 0 synthesises IPv4 datagrams only".into(),
            ));
        }
    };

    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut buf = vec![0u8; total];

    {
        let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_total_len(total as u16);
        ip.set_ident(0);
        ip.set_dont_frag(true);
        ip.set_more_frags(false);
        ip.set_frag_offset(0);
        ip.set_hop_limit(64);
        ip.set_next_header(IpProtocol::Udp);
        ip.set_src_addr(*s4.ip());
        ip.set_dst_addr(*d4.ip());
    }
    {
        let mut udp = UdpPacket::new_unchecked(&mut buf[20..]);
        udp.set_src_port(s4.port());
        udp.set_dst_port(d4.port());
        udp.set_len(udp_len as u16);
        udp.payload_mut().copy_from_slice(payload);
        udp.fill_checksum(&IpAddress::Ipv4(*s4.ip()), &IpAddress::Ipv4(*d4.ip()));
    }
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip.fill_checksum();
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{IpAddress, Ipv4Packet, UdpPacket};
    use std::net::SocketAddr;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_synthesised_reply_is_a_well_formed_checksummed_udp_packet() {
        let from = sa("1.1.1.1:53");
        let to = sa("10.90.0.2:51234");
        let raw = build_udp_packet(from, to, b"\xAB\xCD answer").unwrap();

        let ip = Ipv4Packet::new_checked(&raw[..]).expect("valid IPv4");
        assert!(ip.verify_checksum(), "IP checksum must be correct");
        assert_eq!(ip.src_addr().to_string(), "1.1.1.1");
        assert_eq!(ip.dst_addr().to_string(), "10.90.0.2");

        let udp = UdpPacket::new_checked(ip.payload()).expect("valid UDP");
        assert!(
            udp.verify_checksum(
                &IpAddress::Ipv4(ip.src_addr()),
                &IpAddress::Ipv4(ip.dst_addr())
            ),
            "UDP checksum must be correct or the host stack discards the reply"
        );
        // `verify_checksum` alone does not catch a checksum that was never
        // computed at all: RFC 768 makes an all-zero UDP checksum mean "no
        // checksum was computed," and smoltcp's own `verify_checksum` treats
        // that as trivially valid (see `udp.rs`'s `if self.checksum() == 0 {
        // return true; }`). Our buffer starts zero-filled, so a build that
        // silently forgot to call `fill_checksum` would still pass the
        // assertion above. Pin the field itself non-zero so that regression
        // is caught here rather than by a host silently accepting an
        // unverified packet.
        assert_ne!(
            udp.checksum(),
            0,
            "the UDP checksum must actually be computed, not left at the \
             RFC 768 no-checksum sentinel"
        );
        assert_eq!(udp.src_port(), 53);
        assert_eq!(udp.dst_port(), 51234);
        assert_eq!(udp.payload(), b"\xAB\xCD answer");
    }

    #[test]
    fn the_query_id_is_the_first_two_bytes_big_endian() {
        assert_eq!(dns_query_id(&[0xAB, 0xCD, 0x01, 0x00]), Some(0xABCD));
        assert_eq!(dns_query_id(&[0x00, 0x01]), Some(1));
    }

    #[test]
    fn a_runt_payload_has_no_query_id() {
        assert_eq!(dns_query_id(&[0xAB]), None);
        assert_eq!(dns_query_id(&[]), None);
    }

    #[test]
    fn mixing_address_families_is_rejected_rather_than_producing_garbage() {
        let v6 = sa("[2001:db8::1]:53");
        let v4 = sa("10.90.0.2:51234");
        assert!(build_udp_packet(v6, v4, b"x").is_err());
    }

    #[tokio::test]
    async fn the_unimplemented_resolver_fails_every_query() {
        // The stand-in used wherever Task 19/20's real backends are not
        // wired in yet. Must fail, never fabricate an answer.
        let r = UnimplementedResolver;
        assert!(r.query(b"\x00\x01query").await.is_err());
    }
}

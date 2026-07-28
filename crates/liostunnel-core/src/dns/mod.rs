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

#[cfg(feature = "doh")]
pub mod over_https;
pub mod over_tcp;
#[cfg(all(test, feature = "doh"))]
pub(crate) mod testutil;

use std::net::SocketAddr;

use async_trait::async_trait;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, UdpPacket};

use crate::error::TunnelError;

/// The largest payload [`build_udp_packet`] can carry: the IP total-length
/// field is itself a `u16`, so the whole datagram — 20-byte IP header +
/// 8-byte UDP header + payload — can never exceed `u16::MAX`. This is also
/// the standard maximum UDP-over-IPv4 payload (65,507 bytes), not an
/// arbitrary cap.
///
/// A DNS-over-TCP answer (RFC 1035's two-byte length prefix, Task 19) can
/// legally be up to 65,535 bytes — comfortably past this limit — so this is
/// a real, reachable path once that resolver lands, not a defensive-only
/// bound.
///
/// This says nothing about the tunnel's actual MTU (`StackConfig::mtu`,
/// default 1500): nothing here fragments the synthesised packet, and
/// `dont_frag(true)` is set unconditionally below, so a legal answer under
/// this cap but over the MTU still produces a frame the TUN device may
/// refuse or the OS may drop — the same "looks like a hang" failure mode as
/// a bad checksum, just for a different reason. `build_udp_packet` itself
/// still has no way to know the configured MTU without a signature change
/// that would ripple through `testutil::build_udp` and every other caller
/// that doesn't care about MTU truncation at all (the inbound-query test
/// packets built via `testutil::build_udp`, for instance). Review item 4
/// resolves the MTU/answer-size mismatch one call site up instead:
/// `StackCore::inject_datagram` (the *only* caller synthesising outbound DNS
/// *answers*, and the only one with `StackConfig::mtu` in scope) now checks
/// the answer against the MTU itself and, when it doesn't fit, hands
/// [`truncate_dns_reply`]'s output to this function instead of the real
/// (oversized) answer — a truncated reply with the TC bit set (RFC 1035
/// §4.1.1), so the client's own resolver retries over TCP rather than the
/// hostname simply never resolving.
pub const MAX_UDP_PAYLOAD: usize = u16::MAX as usize - 20 - 8;

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

/// The DNS header's fixed 12-byte layout (RFC 1035 §4.1.1). Only the offsets
/// this module actually touches are named.
const DNS_HEADER_LEN: usize = 12;
/// Byte 2: `QR(1) Opcode(4) AA(1) TC(1) RD(1)`. `0x02` is the TC bit.
const DNS_FLAGS_BYTE: usize = 2;
const DNS_TC_BIT: u8 = 0x02;

/// Truncates an oversized DNS *answer* (not a query) down to just its
/// 12-byte header, with the TC (truncated) bit set and every record count
/// zeroed to match — RFC 1035 §4.1.1's mechanism for telling the client
/// "retry over TCP" instead of silently failing to deliver an answer the
/// device cannot carry as a single UDP/IP datagram. Review item 4.
///
/// `answer` is expected to already be a real, valid (merely oversized) DNS
/// message from the upstream resolver — its ID and flags (QR, Opcode, AA,
/// RD, RA, RCODE) are copied through unmodified, since the resolver already
/// set them correctly; only TC and the four counts change. This function
/// never fabricates a header from scratch.
///
/// Deliberately does *not* attempt to retain the question section. Doing so
/// correctly means walking the QNAME label encoding — length-prefixed labels
/// terminated by a zero byte, with edge cases (a length byte that runs past
/// the buffer, a compression pointer, a QDCOUNT that lies) that amount to
/// real DNS message parsing, not a fixed-offset field access like the TC bit
/// itself. A bug there would risk corrupting or panicking on the one packet
/// this function exists to make *safer* to emit — the header-only, RFC-legal
/// truncated reply below is unconditionally well-formed, is never wrong to
/// send, and does not require parsing anything.
pub fn truncate_dns_reply(answer: &[u8]) -> Vec<u8> {
    // A message too short to even have a full header cannot be answered
    // meaningfully either way; pad with zeroed bytes rather than index out of
    // bounds. This was never going to resolve anything regardless of the
    // path taken -- the goal here is only "never panic," not "recover a
    // sensible ID out of a malformed answer."
    let mut header = if answer.len() >= DNS_HEADER_LEN {
        answer[..DNS_HEADER_LEN].to_vec()
    } else {
        let mut h = answer.to_vec();
        h.resize(DNS_HEADER_LEN, 0);
        h
    };

    header[DNS_FLAGS_BYTE] |= DNS_TC_BIT;
    // QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT: all zeroed. Nothing follows the
    // header in a truncated-to-just-the-header reply, so claiming otherwise
    // (e.g. a QDCOUNT of 1 with no question section actually present) would
    // itself be a malformed message.
    header[4..DNS_HEADER_LEN].fill(0);
    header
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

    // Reject outright rather than truncate: `20 + 8 + payload.len()` cast
    // down to `u16` for `set_total_len`/`set_len` would otherwise wrap
    // silently for a payload at or beyond this bound, leaving those fields
    // smaller than the buffer they describe — which is exactly what made
    // `payload_mut()` panic (`slice index starts at 8 but ends at 0`) on an
    // oversized answer. A dropped oversized answer is correct behaviour
    // (the client's own resolver retries); a panic here takes down the
    // single stack thread that owns every active flow for the session.
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(TunnelError::Dns(
            "DNS answer is too large to synthesise into a single UDP/IP packet".into(),
        ));
    }

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
    fn the_largest_payload_that_fits_a_u16_ip_total_length_still_succeeds() {
        // The boundary itself, not just comfortably inside it: an off-by-one
        // in the guard (`>=` where it should be `>`, or vice versa) would
        // only show up right at this edge.
        let from = sa("1.1.1.1:53");
        let to = sa("10.90.0.2:51234");
        let payload = vec![0xAAu8; MAX_UDP_PAYLOAD];

        let raw = build_udp_packet(from, to, &payload).expect("the boundary size must succeed");

        let ip = Ipv4Packet::new_checked(&raw[..]).expect("valid IPv4");
        assert!(ip.verify_checksum());
        assert_eq!(ip.total_len() as usize, 20 + 8 + MAX_UDP_PAYLOAD);

        let udp = UdpPacket::new_checked(ip.payload()).expect("valid UDP");
        assert!(udp.verify_checksum(
            &IpAddress::Ipv4(ip.src_addr()),
            &IpAddress::Ipv4(ip.dst_addr())
        ));
        assert_eq!(udp.payload().len(), MAX_UDP_PAYLOAD);
    }

    #[test]
    fn one_byte_past_the_boundary_is_rejected_rather_than_panicking() {
        // Without this guard, this exact size (28 + payload.len() == 65536)
        // wraps `set_total_len`'s `u16` cast to 0 -- the packet is still
        // built and returned as `Ok`, but with a corrupted IP header rather
        // than a matching one. Silent corruption, not a panic; the guard
        // must catch it just as surely as the larger, louder failure below.
        let from = sa("1.1.1.1:53");
        let to = sa("10.90.0.2:51234");
        let payload = vec![0xAAu8; MAX_UDP_PAYLOAD + 1];

        let err = build_udp_packet(from, to, &payload)
            .expect_err("one byte past the boundary must be rejected, not silently corrupted");
        assert!(matches!(err, TunnelError::Dns(_)));
    }

    #[test]
    fn a_payload_that_would_wrap_the_udp_length_field_is_rejected_not_panicked() {
        // The exact reproduction of the reported defect: at `payload.len() ==
        // 65528`, `8 + payload.len()` wraps `set_len`'s `u16` cast to 0, and
        // `payload_mut()` — which slices `8..len()` — panics inside smoltcp
        // rather than this function ever returning. Reproduced directly
        // against the pre-fix code (guard temporarily removed):
        //
        //   thread '...' panicked at .../smoltcp-0.13.1/src/wire/udp.rs:215:18:
        //   slice index starts at 8 but ends at 0
        //
        // That panic unwinds the single dedicated stack thread that owns
        // every active flow for the session (see `poll.rs`), which the
        // engine's own shutdown-race fix (this same task) reads as an
        // ordinary clean close -- so one oversized DNS answer would silently
        // end the whole tunnel with nothing in the logs to explain why.
        let from = sa("1.1.1.1:53");
        let to = sa("10.90.0.2:51234");
        let payload = vec![0xAAu8; 65528];

        let err = build_udp_packet(from, to, &payload)
            .expect_err("a payload this large must be rejected, not panic the stack thread");
        assert!(matches!(err, TunnelError::Dns(_)));
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

    // --- Review item 4: `truncate_dns_reply` -----------------------------

    /// A realistic (if fictitious past byte 12) DNS answer header: id
    /// 0xABCD, standard query response flags (`0x81 0x80` = QR + RD + RA,
    /// RCODE NOERROR), one question, one answer.
    fn sample_header() -> Vec<u8> {
        vec![
            0xAB, 0xCD, // ID
            0x81, 0x80, // flags: QR=1 RD=1 RA=1, RCODE=0
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x01, // ANCOUNT=1
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ]
    }

    #[test]
    fn an_oversized_answer_is_truncated_to_exactly_a_12_byte_header() {
        let mut answer = sample_header();
        answer.extend(vec![0x41u8; 4000]); // the oversized rest of the message

        let truncated = truncate_dns_reply(&answer);
        assert_eq!(
            truncated.len(),
            12,
            "a truncated-to-header reply must be exactly 12 bytes"
        );
    }

    #[test]
    fn the_transaction_id_survives_truncation() {
        let mut answer = sample_header();
        answer.extend(vec![0x41u8; 4000]);

        let truncated = truncate_dns_reply(&answer);
        assert_eq!(
            &truncated[..2],
            &[0xAB, 0xCD],
            "the client matches replies to queries by transaction id; it must be unchanged"
        );
    }

    #[test]
    fn the_tc_bit_is_set_without_disturbing_the_other_flag_bits() {
        let mut answer = sample_header();
        answer.extend(vec![0x41u8; 4000]);

        let truncated = truncate_dns_reply(&answer);
        assert_eq!(
            truncated[2], 0x83,
            "0x81 (QR|RD) with TC (0x02) added must be 0x83"
        );
        assert_eq!(truncated[3], 0x80, "RA/RCODE byte must be untouched");
    }

    #[test]
    fn every_record_count_is_zeroed_since_nothing_follows_the_header() {
        let mut answer = sample_header();
        answer.extend(vec![0x41u8; 4000]);

        let truncated = truncate_dns_reply(&answer);
        assert_eq!(
            &truncated[4..12],
            &[0, 0, 0, 0, 0, 0, 0, 0],
            "QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT must all read 0 -- nothing past \
             the header is actually present"
        );
    }

    #[test]
    fn a_message_shorter_than_a_full_header_is_padded_not_panicked() {
        // Never realistically produced by a real resolver, but a function
        // that must never panic the shared stack thread (see
        // `build_udp_packet`'s own regression tests for why that stakes are
        // this high) must handle it anyway.
        let truncated = truncate_dns_reply(&[0xAB, 0xCD]);
        assert_eq!(truncated.len(), 12);
        assert_eq!(&truncated[..2], &[0xAB, 0xCD]);
        assert_eq!(truncated[2] & DNS_TC_BIT, DNS_TC_BIT);
    }

    #[test]
    fn an_empty_message_is_also_padded_not_panicked() {
        let truncated = truncate_dns_reply(&[]);
        assert_eq!(truncated.len(), 12);
        assert_eq!(truncated[2] & DNS_TC_BIT, DNS_TC_BIT);
    }

    #[test]
    fn the_truncated_reply_still_builds_into_a_valid_udp_packet() {
        // End-to-end within this module: the truncated bytes must still be a
        // legal `build_udp_packet` payload, since that is exactly how
        // `StackCore::inject_datagram` uses this function's output.
        let mut answer = sample_header();
        answer.extend(vec![0x41u8; 4000]);
        let truncated = truncate_dns_reply(&answer);

        let raw = build_udp_packet(sa("1.1.1.1:53"), sa("10.90.0.2:51234"), &truncated).unwrap();
        let ip = Ipv4Packet::new_checked(&raw[..]).expect("valid IPv4");
        assert!(ip.verify_checksum());
        let udp = UdpPacket::new_checked(ip.payload()).expect("valid UDP");
        assert_eq!(udp.payload().len(), 12);
    }
}

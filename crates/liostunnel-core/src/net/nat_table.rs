use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

/// Tracks which connection attempts currently have a smoltcp listener armed,
/// plus DNS queries awaiting a reply.
///
/// Under SYN-triggered listener injection (spec §7.4) this holds **no address
/// translations** — it only becomes a rewrite table if the destination-rewriting
/// NAT fallback is ever adopted.
///
/// Keyed on the `(src, dst)` 4-tuple rather than the destination alone: a
/// smoltcp listener accepts exactly one connection, so six concurrent sockets
/// to one host need six listeners, while a SYN retransmit needs none.
#[derive(Default, Debug)]
pub struct NatTable {
    armed: HashSet<(SocketAddr, SocketAddr)>,
    dns_inflight: HashMap<(SocketAddr, u16), ()>,
}

impl NatTable {
    /// Returns true if this flow had no listener yet, meaning the caller must
    /// inject one bound to `dst`.
    pub fn arm(&mut self, src: SocketAddr, dst: SocketAddr) -> bool {
        self.armed.insert((src, dst))
    }

    pub fn is_armed(&self, src: &SocketAddr, dst: &SocketAddr) -> bool {
        self.armed.contains(&(*src, *dst))
    }

    pub fn disarm(&mut self, src: &SocketAddr, dst: &SocketAddr) {
        self.armed.remove(&(*src, *dst));
    }

    pub fn armed_len(&self) -> usize {
        self.armed.len()
    }

    pub fn record_dns(&mut self, src: SocketAddr, query_id: u16) {
        self.dns_inflight.insert((src, query_id), ());
    }

    /// Claims an in-flight query. Returns false for a duplicate or unknown reply.
    pub fn take_dns(&mut self, src: SocketAddr, query_id: u16) -> bool {
        self.dns_inflight.remove(&(src, query_id)).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn ep(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn arming_a_flow_reports_whether_a_listener_is_needed() {
        let mut t = NatTable::default();
        let (a, w) = (ep("10.90.0.2:51234"), ep("93.184.216.34:443"));
        assert!(t.arm(a, w), "first SYN needs a listener");
        assert!(!t.arm(a, w), "a SYN retransmit for the same flow does not");
        assert_eq!(t.armed_len(), 1);
    }

    #[test]
    fn concurrent_connections_to_one_destination_each_get_a_listener() {
        let mut t = NatTable::default();
        let w = ep("93.184.216.34:443");
        // What a browser actually does.
        assert!(t.arm(ep("10.90.0.2:51234"), w));
        assert!(t.arm(ep("10.90.0.2:51235"), w));
        assert!(t.arm(ep("10.90.0.2:51236"), w));
        assert_eq!(t.armed_len(), 3);
    }

    #[test]
    fn disarming_lets_the_same_flow_be_armed_again() {
        let mut t = NatTable::default();
        let (a, w) = (ep("10.90.0.2:51234"), ep("1.2.3.4:80"));
        t.arm(a, w);
        t.disarm(&a, &w);
        assert!(!t.is_armed(&a, &w));
        assert!(t.arm(a, w));
    }

    #[test]
    fn flows_are_tracked_per_destination_port() {
        let mut t = NatTable::default();
        let a = ep("10.90.0.2:51234");
        t.arm(a, ep("1.2.3.4:80"));
        assert!(!t.is_armed(&a, &ep("1.2.3.4:443")));
    }

    #[test]
    fn a_dns_query_can_be_recorded_and_claimed_exactly_once() {
        let mut t = NatTable::default();
        t.record_dns(ep("10.90.0.2:51234"), 0xABCD);
        assert!(t.take_dns(ep("10.90.0.2:51234"), 0xABCD));
        assert!(
            !t.take_dns(ep("10.90.0.2:51234"), 0xABCD),
            "replays must not match"
        );
    }

    #[test]
    fn an_unrecorded_dns_response_is_not_claimed() {
        let mut t = NatTable::default();
        assert!(!t.take_dns(ep("10.90.0.2:51234"), 0x0001));
    }
}

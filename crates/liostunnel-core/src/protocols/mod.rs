pub mod counting;
pub mod shadowsocks;
pub mod ss_uri;
pub mod ssh;

use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::profile::ServerProfile;
use crate::config::secret::SecretStore;
use crate::error::TunnelError;
use crate::stats::ConnectionStats;

/// A logical byte stream carried by the tunnel. PRD §5.1.
pub trait TunnelStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> TunnelStream for T {}

/// Picks the first IPv4 candidate from a resolved address list, in order.
///
/// The `default`-mode route pin this address feeds (via a protocol's own
/// `peer_addr`) is built by IPv4-only commands -- `route::linux`/`route::macos`
/// hardcode a `/32` and expect a v4 gateway -- so handing them a v6 address
/// produces a malformed route command that fails `RouteGuard::apply` partway
/// through applying (review item 2). A dual-stack host's resolved address list
/// often has the AAAA record first, so picking blindly (`.next()`, the pre-fix
/// behaviour) rather than filtering for v4 is itself the bug this closes.
///
/// Errors clearly, rather than silently building a malformed command, when
/// the host resolves to IPv6 addresses only -- Phase 0 has no IPv6 support
/// anywhere else in the stack either (the TUN device, `StackConfig`, and the
/// route commands are all IPv4-only), so this is a real, honest limitation
/// to surface at connect time, not a bug to paper over.
///
/// Lives here rather than in `protocols::ssh`, where it was written: it is
/// not SSH policy, it is the packet stack's and the route layer's IPv4-only
/// constraint, and `ShadowsocksTunnel::connect` now resolves through it too
/// (fix wave 1, finding 1). One implementation so the two protocols cannot
/// disagree about what "the server's address" means.
pub fn pick_ipv4(addrs: impl IntoIterator<Item = SocketAddr>) -> Result<SocketAddr, TunnelError> {
    let mut saw_any = false;
    for addr in addrs {
        saw_any = true;
        if addr.is_ipv4() {
            return Ok(addr);
        }
    }
    if saw_any {
        Err(TunnelError::Protocol(
            "host resolved only to IPv6 addresses; Phase 0's route pinning and packet stack are \
             IPv4-only"
                .into(),
        ))
    } else {
        Err(TunnelError::Protocol(
            "host resolved to no addresses".into(),
        ))
    }
}

/// PRD §5.1. The packet engine calls this and never learns which protocol it has.
#[async_trait]
pub trait Protocol: Send + Sync {
    async fn connect(
        &mut self,
        profile: &ServerProfile,
        store: &dyn SecretStore,
    ) -> Result<(), TunnelError>;

    async fn open_tcp_stream(&self, dest: SocketAddr)
    -> Result<Box<dyn TunnelStream>, TunnelError>;

    /// Opens a stream reserved for DNS resolution rather than ordinary
    /// proxied application traffic.
    ///
    /// Review item 3: `over_tcp::TcpResolver` and `over_https::DohResolver`
    /// both used to call `open_tcp_stream` for this too, so a DNS query and a
    /// long-lived bulk flow (a browser tab, routinely one of dozens held open
    /// at once) drew from the exact same channel budget. `tokio::sync::Semaphore`
    /// is FIFO-fair, so a DNS query queued behind a busy tunnel's worth of
    /// held-open flows can queue past its own timeout and fail -- DNS starved
    /// by ordinary traffic, invisibly, on every busy connection.
    ///
    /// The default implementation just calls `open_tcp_stream` -- correct for
    /// any `Protocol` impl (real or a test mock) with no reason to
    /// distinguish the two, and exactly what every implementor did before
    /// this method existed. `SshTunnel` overrides it to draw from a small,
    /// separate, reserved channel allowance instead — see its own doc.
    async fn open_dns_stream(
        &self,
        dest: SocketAddr,
    ) -> Result<Box<dyn TunnelStream>, TunnelError> {
        self.open_tcp_stream(dest).await
    }

    async fn send_udp(&self, dest: SocketAddr, data: &[u8]) -> Result<(), TunnelError>;

    async fn disconnect(&mut self) -> Result<(), TunnelError>;

    fn stats(&self) -> ConnectionStats;
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Review item 2: `pick_ipv4` --------------------------------------
    //
    // Moved here verbatim with the function itself (fix wave 1, finding 1),
    // which both protocols now resolve through rather than only SSH.
    //
    // Pure, no network, no handle -- this is the one piece of the fix that
    // does not need a live session to verify. The property under test:
    // whatever a protocol's `connect` resolves to, and whatever its
    // `peer_addr` reports afterward for the route pin, must be an IPv4
    // address (the route commands are IPv4-only), chosen deterministically
    // rather than by whatever order `lookup_host` happened to return.

    fn v4(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn v6(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_v4_address_is_chosen_when_the_list_is_v6_first_then_v4() {
        // The exact dual-stack shape the review names: `lookup_host` often
        // surfaces the AAAA record first. A `.next()`-style pick (the
        // pre-fix behaviour) would have taken the v6 address here.
        let picked = pick_ipv4([v6("[2001:db8::1]:22"), v4("198.51.100.7:22")]).unwrap();
        assert_eq!(picked, v4("198.51.100.7:22"));
    }

    #[test]
    fn a_v4_address_is_chosen_when_it_already_comes_first() {
        let picked = pick_ipv4([v4("198.51.100.7:22"), v6("[2001:db8::1]:22")]).unwrap();
        assert_eq!(picked, v4("198.51.100.7:22"));
    }

    #[test]
    fn the_first_v4_wins_among_several_a_records() {
        let picked = pick_ipv4([
            v6("[2001:db8::1]:22"),
            v4("198.51.100.7:22"),
            v4("198.51.100.8:22"),
        ])
        .unwrap();
        assert_eq!(
            picked,
            v4("198.51.100.7:22"),
            "must be deterministic, not merely 'some' v4 address"
        );
    }

    #[test]
    fn an_ipv6_only_resolution_is_a_clear_error_not_a_malformed_route_later() {
        let err = pick_ipv4([v6("[2001:db8::1]:22"), v6("[2001:db8::2]:22")]).unwrap_err();
        match err {
            TunnelError::Protocol(reason) => {
                assert!(
                    reason.contains("IPv4"),
                    "error should explain the IPv4-only constraint: {reason}"
                );
            }
            other => panic!("expected TunnelError::Protocol, got {other:?}"),
        }
    }

    #[test]
    fn no_addresses_at_all_is_also_a_clear_error() {
        assert!(pick_ipv4(std::iter::empty()).is_err());
    }
}

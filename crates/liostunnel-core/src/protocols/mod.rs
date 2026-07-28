pub mod counting;
pub mod shadowsocks;
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

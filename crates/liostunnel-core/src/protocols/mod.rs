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

    async fn send_udp(&self, dest: SocketAddr, data: &[u8]) -> Result<(), TunnelError>;

    async fn disconnect(&mut self) -> Result<(), TunnelError>;

    fn stats(&self) -> ConnectionStats;
}

//! A `Protocol` that opens ordinary sockets, for tests that want to reach the
//! real network without an SSH server in the way.

use std::net::SocketAddr;

use async_trait::async_trait;

use crate::config::profile::ServerProfile;
use crate::config::secret::SecretStore;
use crate::error::TunnelError;
use crate::protocols::{Protocol, TunnelStream};
use crate::stats::ConnectionStats;

pub struct DirectProtocol;

#[async_trait]
impl Protocol for DirectProtocol {
    async fn connect(
        &mut self,
        _p: &ServerProfile,
        _s: &dyn SecretStore,
    ) -> Result<(), TunnelError> {
        Ok(())
    }

    async fn open_tcp_stream(
        &self,
        dest: SocketAddr,
    ) -> Result<Box<dyn TunnelStream>, TunnelError> {
        let s = tokio::net::TcpStream::connect(dest)
            .await
            .map_err(|e| TunnelError::Protocol(format!("cannot connect to {dest}: {e}")))?;
        Ok(Box::new(s))
    }

    async fn send_udp(&self, _d: SocketAddr, _b: &[u8]) -> Result<(), TunnelError> {
        Err(TunnelError::Unsupported("udp"))
    }
    async fn disconnect(&mut self) -> Result<(), TunnelError> {
        Ok(())
    }
    fn stats(&self) -> ConnectionStats {
        ConnectionStats::default()
    }
}

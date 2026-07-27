pub mod local_stream;
pub mod smoltcp_stack;
pub mod tun;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::mpsc;

use crate::error::TunnelError;
use crate::net::local_stream::LocalStream;
use crate::net::tun::PacketIo;

/// A TCP connection initiated by an application on the device.
pub struct TcpFlow {
    pub src: SocketAddr,
    /// The application's real destination, not the TUN's own address.
    pub dst: SocketAddr,
    pub stream: LocalStream,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Datagram {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct StackConfig {
    pub address: Ipv4Addr,
    pub netmask_prefix: u8,
    pub mtu: usize,
    pub tcp_buffer_bytes: usize,
    /// Bounded so a slow tunnel applies backpressure through the TCP window
    /// rather than growing an unbounded queue. Spec §7.2.
    pub channel_depth: usize,
}

impl Default for StackConfig {
    fn default() -> Self {
        Self {
            address: Ipv4Addr::new(10, 90, 0, 1),
            netmask_prefix: 24,
            mtu: 1500,
            tcp_buffer_bytes: 64 * 1024,
            channel_depth: 64,
        }
    }
}

#[derive(Clone, Default)]
pub struct ShutdownHandle(Arc<AtomicBool>);

impl ShutdownHandle {
    pub fn shutdown(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
    pub fn is_shutdown(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

pub struct StackHandles {
    pub tcp_accept: mpsc::Receiver<TcpFlow>,
    pub udp_inbound: mpsc::Receiver<Datagram>,
    pub udp_outbound: mpsc::Sender<Datagram>,
    pub shutdown: ShutdownHandle,
}

/// Decision D7. The engine consumes only this, so swapping in
/// `netstack-smoltcp` means writing one more implementation.
pub trait NetStack: Send + 'static {
    fn start(self, io: Box<dyn PacketIo>, cfg: StackConfig) -> Result<StackHandles, TunnelError>;
}

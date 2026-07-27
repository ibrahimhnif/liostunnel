pub mod local_stream;
pub mod nat_table;
pub mod smoltcp_stack;
#[cfg(test)]
pub(crate) mod testutil;
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

/// Wakes the synchronous stack loop from asynchronous code.
///
/// `StackCore::poll_delay` spells out why this has to exist and why the stack
/// cannot own it: the loop blocks on a descriptor and a timer, and neither of
/// those notices a tokio channel gaining an item, freeing a slot, or losing its
/// last sender. Anything on the async side that changes what the loop would do
/// next has to say so, and this is how.
///
/// The default is a no-op, for the synchronous tests that drive
/// `StackCore::step` by hand and have no loop to wake.
#[derive(Clone, Default)]
pub struct Wakeup(Option<Arc<dyn Fn() + Send + Sync>>);

impl Wakeup {
    pub fn new(wake: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Some(Arc::new(wake)))
    }

    /// Cheap enough to call per write: the only implementation in the tree
    /// collapses repeats into a single write on the notification descriptor.
    pub fn wake(&self) {
        if let Some(f) = &self.0 {
            f();
        }
    }
}

impl std::fmt::Debug for Wakeup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Wakeup").field(&self.0.is_some()).finish()
    }
}

#[derive(Clone, Default)]
pub struct ShutdownHandle {
    flag: Arc<AtomicBool>,
    /// So a shutdown is acted on at once rather than whenever the loop next
    /// happens to surface. Without it the only bound is the loop's idle
    /// ceiling, which is a backstop, not a mechanism.
    wake: Wakeup,
}

impl ShutdownHandle {
    pub fn with_wakeup(wake: Wakeup) -> Self {
        Self {
            flag: Arc::default(),
            wake,
        }
    }

    pub fn shutdown(&self) {
        // Release/Acquire rather than Relaxed: the loop must see everything
        // that happened before the caller decided to stop, not just the flag.
        self.flag.store(true, Ordering::Release);
        self.wake.wake();
    }

    pub fn is_shutdown(&self) -> bool {
        self.flag.load(Ordering::Acquire)
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

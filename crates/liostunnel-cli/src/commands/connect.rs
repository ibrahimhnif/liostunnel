use std::net::Ipv4Addr;
use std::sync::Arc;

use liostunnel_core::TunnelError;
use liostunnel_core::config::profile::ServerProfile;
use liostunnel_core::config::secret::FileSecretStore;
use liostunnel_core::engine::Engine;
use liostunnel_core::net::smoltcp_stack::poll::SmoltcpStack;
use liostunnel_core::net::tun::{TunConfig, TunDevice};
use liostunnel_core::net::{NetStack, ShutdownHandle, StackConfig};
use liostunnel_core::protocols::Protocol;
use liostunnel_core::protocols::ssh::{HostKeyPolicy, SshTunnel};
use liostunnel_core::route::{RouteGuard, RouteMode, RoutePlan, platform_manager};

pub struct ConnectOpts {
    pub route_mode: RouteMode,
    pub tun_address: Ipv4Addr,
}

/// Tells the stack thread to stop if this scope is torn down before the
/// engine takes over that responsibility itself.
///
/// Between `SmoltcpStack::start` returning and the engine actually running,
/// there are several fallible steps (gateway detection, DNS resolution for
/// the server's own address, route installation) that have nothing to do
/// with the stack thread, but whose failure must still stop it -- otherwise
/// a `--route-mode default` run (unsupported until Task 21 and therefore
/// guaranteed to error here today) leaks the background thread and the open
/// TUN device for the life of the process. `ShutdownHandle::shutdown` is
/// idempotent (it only sets a flag and wakes the loop), so it is harmless
/// for this to fire again later on the engine's own shutdown path -- this
/// guard only needs to cover the gap before that path exists.
struct StackShutdownOnDrop(ShutdownHandle);

impl Drop for StackShutdownOnDrop {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

/// Brings up a tunnel: SSH first, then the TUN device and packet stack, and
/// only then the routing table. Spec §7, decision D6.
///
/// The ordering is deliberate and load-bearing: a failed SSH handshake must
/// never leave routes pointing at an interface with nothing behind it, so
/// every fallible step before route installation runs first, and nothing
/// before `RouteGuard::apply` touches the routing table at all.
pub async fn run(
    profile: &ServerProfile,
    user: String,
    opts: ConnectOpts,
    policy: HostKeyPolicy,
) -> Result<(), TunnelError> {
    // 1. Establish the tunnel before touching the routing table, so a failed
    //    connection never leaves the machine with routes pointing at a dead
    //    interface.
    let mut ssh = SshTunnel::new(user, policy);
    ssh.connect(profile, &FileSecretStore).await?;
    let protocol: Arc<dyn Protocol> = Arc::new(ssh);

    // 2. Create the TUN device.
    let tun = TunDevice::open(TunConfig {
        address: opts.tun_address,
        ..TunConfig::default()
    })?;
    let interface = tun.name()?;
    tracing::info!(%interface, address = %opts.tun_address, "TUN interface up");

    // 3. Start the packet stack.
    let handles = SmoltcpStack::default().start(
        Box::new(tun),
        StackConfig {
            address: opts.tun_address,
            ..StackConfig::default()
        },
    )?;
    // See `StackShutdownOnDrop`'s doc: covers every early return between here
    // and the engine existing, including a panic unwinding through this scope.
    let _stack_guard = StackShutdownOnDrop(handles.shutdown.clone());

    // 4. Install routes. The guard reverts them on drop (including on a
    //    panic), which is why a failure here -- gateway detection, DNS
    //    resolution for the server's own address, or the route commands
    //    themselves -- can be propagated with a plain `?` without leaving
    //    routes behind.
    let manager = platform_manager();
    let gateway = manager.detect_gateway()?;
    let server_ip = tokio::net::lookup_host((profile.host.as_str(), profile.port))
        .await
        .map_err(|e| TunnelError::Route(format!("cannot resolve {}: {e}", profile.host)))?
        .next()
        .ok_or_else(|| TunnelError::Route(format!("no address for {}", profile.host)))?
        .ip();

    let mut guard = RouteGuard::apply(
        manager,
        RoutePlan {
            interface,
            mode: opts.route_mode,
            server_ip,
            original_gateway: gateway,
            dns_servers: profile.dns.servers.clone(),
        },
    )?;

    // 5. Run until interrupted.
    let engine = Engine::new(protocol, handles);
    let shutdown = engine.shutdown_handle();
    let stats = engine.stats_handle();
    let engine_task = tokio::spawn(engine.run());

    println!("connected — press Ctrl-C to stop");
    // Deliberately not `tokio::signal::ctrl_c().await?;` here. An early `?`
    // on that line would return before the three cleanup lines below ever
    // run; `guard`'s `Drop` would still revert the routes on that path, but
    // nothing would tell the stack thread to stop -- `ShutdownHandle::shutdown`
    // is a plain method call, not something any `Drop` impl reaches for on
    // its own. Holding the `Result` instead of propagating it immediately
    // means shutdown/revert/abort run on *every* path out of this `await`,
    // success or error alike -- exactly what `StackCore::poll_delay`'s
    // contract (point 2) requires: the tunnel side must signal on every exit
    // path, not just the happy one.
    let ctrl_c = tokio::signal::ctrl_c().await;
    println!("\nshutting down");

    shutdown.shutdown();
    guard.revert_now();
    engine_task.abort();

    let s = stats.load();
    println!(
        "flows failed: {}, dns queries: {}",
        s.flows_failed, s.dns_queries
    );

    ctrl_c?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use liostunnel_core::net::Wakeup;

    /// The property `StackShutdownOnDrop` exists to guarantee: tearing down
    /// the scope it lives in -- by any means, not just a clean return --
    /// must signal the stack's shutdown flag. This is the one part of the
    /// fix that doesn't need root or a real TUN device to verify.
    #[test]
    fn stack_shutdown_guard_signals_shutdown_on_drop() {
        let handle = ShutdownHandle::with_wakeup(Wakeup::default());
        assert!(!handle.is_shutdown());
        {
            let _guard = StackShutdownOnDrop(handle.clone());
        }
        assert!(
            handle.is_shutdown(),
            "dropping the guard must signal the stack thread to stop"
        );
    }
}

use std::net::Ipv4Addr;
use std::sync::Arc;

use liostunnel_core::TunnelError;
use liostunnel_core::config::profile::{DnsMode, ServerProfile};
use liostunnel_core::config::secret::FileSecretStore;
use liostunnel_core::dns::Resolver;
use liostunnel_core::dns::over_https::DohResolver;
use liostunnel_core::dns::over_tcp::TcpResolver;
use liostunnel_core::engine::Engine;
use liostunnel_core::net::smoltcp_stack::poll::SmoltcpStack;
use liostunnel_core::net::tun::{TunConfig, TunDevice};
use liostunnel_core::net::{NetStack, ShutdownHandle, StackConfig};
use liostunnel_core::protocols::Protocol;
use liostunnel_core::protocols::ssh::{HostKeyPolicy, SshTunnel};
use liostunnel_core::route::{
    RouteGuard, RouteMode, RoutePlan, platform_manager, reject_full_default_prefixes,
};

pub struct ConnectOpts {
    pub route_mode: RouteMode,
    pub tun_address: Ipv4Addr,
}

/// Maps the CLI's `--route-mode`/`--cidr`/`--capture-dns` strings to a
/// [`RouteMode`], purely -- no process spawn, no TUN device, no filesystem
/// access, so it can (and does, see `tests` below) run without root or a
/// stack thread ever existing.
///
/// Deliberately called from `main.rs` *before* `run` above does anything
/// with side effects (SSH connect, `TunDevice::open`, `SmoltcpStack::start`):
/// an obviously-invalid `--cidr` -- including the full-default-prefix case
/// `reject_full_default_prefixes` rejects -- should fail before any of that
/// runs, not after a TUN interface has already flickered into existence and
/// back out. `RouteGuard::apply` (via `RouteManager::apply_commands`/
/// `revert_commands`) calls `reject_full_default_prefixes` again
/// unconditionally at route-installation time; that is not redundant dead
/// code, it is defense in depth for the route layer's own callers, of which
/// this CLI is only one.
pub fn parse_route_mode(
    route_mode: &str,
    cidrs: &[String],
    capture_dns: bool,
) -> Result<RouteMode, TunnelError> {
    match route_mode {
        "test" => {
            let parsed = cidrs
                .iter()
                .map(|c| {
                    c.parse::<ipnet::IpNet>()
                        .map_err(|e| TunnelError::config("--cidr", e.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if parsed.is_empty() {
                return Err(TunnelError::config(
                    "--cidr",
                    "test route mode needs at least one prefix",
                ));
            }
            reject_full_default_prefixes(&parsed)?;
            Ok(RouteMode::Test {
                cidrs: parsed,
                capture_dns,
            })
        }
        "default" => Ok(RouteMode::Default),
        other => Err(TunnelError::config(
            "--route-mode",
            format!("expected `test` or `default`, got `{other}`"),
        )),
    }
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

    let plan = RoutePlan {
        interface,
        mode: opts.route_mode,
        server_ip,
        original_gateway: gateway,
        dns_servers: profile.dns.servers.clone(),
    };

    // Third cleanup path: a state file that survives `kill -9`, which neither
    // `RouteGuard`'s `Drop` nor a signal handler can. Recover anything a
    // previous crashed run left behind *before* installing anything new.
    let state_path = crate::profile_io::home().join("applied_routes.json");
    liostunnel_core::route::state::recover_if_stale(&state_path)?;

    // Record before applying: a crash between these two lines leaves a state
    // file describing routes that were never installed, and reverting those
    // is harmless. The reverse order would lose them entirely -- do not
    // "optimize" this by moving the save after `RouteGuard::apply`.
    liostunnel_core::route::state::AppliedState {
        interface: plan.interface.clone(),
        revert: manager.revert_commands(&plan)?,
        pid: std::process::id(),
    }
    .save(&state_path)?;

    let mut guard = RouteGuard::apply(manager, plan)?;

    // 5. Run until interrupted.
    // Select the real resolver backend from `profile.dns.mode`: DNS-over-TCP
    // (RFC 7766, Task 19, the zero-dependency default) or DNS-over-HTTPS
    // (RFC 8484, Task 20, opt-in per profile). `ServerProfile::validate`
    // already rejected `Https` mode without a `dns.https` block, so the
    // `ok_or_else` below is a defence-in-depth check, not the primary guard.
    let resolver: Arc<dyn Resolver> = match profile.dns.mode {
        DnsMode::Tcp => Arc::new(TcpResolver::new(
            protocol.clone(),
            profile.dns.servers.clone(),
        )),
        DnsMode::Https => {
            let doh = profile.dns.https.clone().ok_or_else(|| {
                TunnelError::config("dns.https", "required when dns.mode is `https`")
            })?;
            Arc::new(DohResolver::new(
                protocol.clone(),
                profile.dns.servers.clone(),
                doh,
            ))
        }
    };
    let engine = Engine::new(protocol, resolver, handles);
    let shutdown = engine.shutdown_handle();
    let stats = engine.stats_handle();
    let engine_task = tokio::spawn(engine.run());

    println!("connected — press Ctrl-C to stop");
    // Deliberately not `tokio::signal::ctrl_c().await?;` here. An early `?`
    // on that line would return before the four cleanup lines below ever
    // run; `guard`'s `Drop` would still revert the routes on that path, but
    // nothing would tell the stack thread to stop -- `ShutdownHandle::shutdown`
    // is a plain method call, not something any `Drop` impl reaches for on
    // its own. Holding the `Result` instead of propagating it immediately
    // means shutdown/revert/abort run on *every* path out of this `await`,
    // success or error alike -- exactly what `StackCore::poll_delay`'s
    // contract (point 2) requires: the tunnel side must signal on every exit
    // path, not just the happy one.
    //
    // The second cleanup path: covers a graceful stop request (Ctrl-C or
    // `kill -TERM`), as opposed to `RouteGuard`'s `Drop` (path one, covers
    // normal return and unwinding panics) and the state file (path three,
    // survives `kill -9`, which delivers no signal at all).
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(TunnelError::Transport)?;

    let ctrl_c = tokio::select! {
        r = tokio::signal::ctrl_c() => r,
        _ = sigterm.recv() => Ok(()),
    };
    println!("\nshutting down");

    shutdown.shutdown();
    guard.revert_now();
    // A clean shutdown reverted the routes above, so the state file describing
    // them would be stale as soon as this process exits; clear it now so the
    // next start does not mistake a normal exit for a crash to recover from.
    liostunnel_core::route::state::AppliedState::clear(&state_path);
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

    // `parse_route_mode` regression coverage. All hermetic: no TUN, no
    // routes, no root -- it is a pure string/`Vec<String>` -> `RouteMode`
    // mapping, exercised directly rather than only through
    // `Cli::try_parse_from` (which stops at clap's own parsing and never
    // reaches this logic at all).

    #[test]
    fn an_unknown_route_mode_is_a_clear_config_error() {
        let e = parse_route_mode("bogus", &["10.0.0.0/24".into()], false).unwrap_err();
        match e {
            TunnelError::Config { field, reason } => {
                assert_eq!(field, "--route-mode");
                assert!(
                    reason.contains("bogus"),
                    "error should name the bad value: {reason}"
                );
            }
            other => panic!("expected TunnelError::Config, got {other:?}"),
        }
    }

    #[test]
    fn test_mode_with_no_cidr_is_rejected() {
        let e = parse_route_mode("test", &[], false).unwrap_err();
        match e {
            TunnelError::Config { field, reason } => {
                assert_eq!(field, "--cidr");
                assert!(reason.contains("at least one prefix"), "{reason}");
            }
            other => panic!("expected TunnelError::Config, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_cidr_string_names_the_bad_value_and_the_flag() {
        let e = parse_route_mode("test", &["not-a-cidr".into()], false).unwrap_err();
        match e {
            TunnelError::Config { field, .. } => assert_eq!(field, "--cidr"),
            other => panic!("expected TunnelError::Config, got {other:?}"),
        }
    }

    #[test]
    fn a_valid_test_invocation_maps_to_the_expected_route_mode() {
        let mode = parse_route_mode(
            "test",
            &["93.184.216.0/24".into(), "198.51.100.0/24".into()],
            true,
        )
        .unwrap();
        match mode {
            RouteMode::Test { cidrs, capture_dns } => {
                assert_eq!(
                    cidrs,
                    vec![
                        "93.184.216.0/24".parse().unwrap(),
                        "198.51.100.0/24".parse().unwrap(),
                    ]
                );
                assert!(capture_dns);
            }
            other => panic!("expected RouteMode::Test, got {other:?}"),
        }
    }

    #[test]
    fn default_route_mode_string_maps_to_route_mode_default() {
        assert!(matches!(
            parse_route_mode("default", &[], false).unwrap(),
            RouteMode::Default
        ));
    }

    #[test]
    fn a_full_default_prefix_is_rejected_before_anything_with_side_effects_runs() {
        // The property this whole fix pass is about: this call is pure (no
        // TUN device, no stack thread, no process spawned), so a `/0` being
        // caught here -- rather than only later inside `RouteGuard::apply`
        // -- means an operator never sees an interface flicker into
        // existence for an argument this obviously wrong.
        let e = parse_route_mode("test", &["0.0.0.0/0".into()], false).unwrap_err();
        match e {
            TunnelError::Config { field, reason } => {
                assert_eq!(field, "route.test.cidrs");
                assert!(reason.contains("full-default"), "{reason}");
            }
            other => panic!("expected TunnelError::Config, got {other:?}"),
        }
    }
}

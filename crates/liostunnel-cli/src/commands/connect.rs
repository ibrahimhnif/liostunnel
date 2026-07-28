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
    // The exact address the SSH session actually connected to -- not a
    // second, independent `lookup_host` call. Review item 2: a dual-stack or
    // multi-A-record host could previously make this resolution disagree
    // with the one `SshTunnel::connect` performed internally, either handing
    // the (IPv4-only) route commands below a v6 address or pinning the wrong
    // peer entirely. `SshTunnel::peer_addr` is `Some` here in every real
    // case -- `connect` above already returned `Ok`, and `connect`'s own Err
    // arm is the only place that leaves it `None` -- but a clean error still
    // beats a `panic!`/`unwrap!` if that invariant is ever violated by a
    // future refactor.
    let server_ip = ssh
        .peer_addr()
        .ok_or_else(|| {
            TunnelError::Route(
                "ssh session reports no resolved peer address after connecting".into(),
            )
        })?
        .ip();
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
    //    panic), which is why a failure here -- gateway detection, or the
    //    route commands themselves -- can be propagated with a plain `?`
    //    without leaving routes behind. `server_ip` was already resolved in
    //    step 1, from the SSH connection itself, not re-resolved here.
    let manager = platform_manager();
    let gateway = manager.detect_gateway()?;
    let ipv6_available = manager.ipv6_available();

    let plan = RoutePlan {
        interface,
        mode: opts.route_mode,
        server_ip,
        original_gateway: gateway,
        dns_servers: profile.dns.servers.clone(),
        ipv6_available,
    };

    // Gap 2: be loud about IPv6 rather than let an operator discover it only
    // when their v6 connectivity silently stops working. `None` in `test`
    // mode, which never claimed to capture "everything" in the first place.
    if let Some(notice) = ipv6_notice(&plan.mode, plan.ipv6_available) {
        eprintln!("  !!  {notice}");
    }

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
    let mut engine_task = tokio::spawn(engine.run());

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

    // Review item 1: the engine's own task is a third arm here, not just the
    // two signals. `Engine::run` (`engine.rs`) returns `Ok(())` whenever the
    // packet stack closes both its channels -- which happens on a
    // stack-thread panic, `Poller::wait` giving up after repeated failures
    // (`poll.rs`'s `AfterWait::GiveUp`), or any other unrequested stack
    // exit, none of which involve this process ever calling `shutdown()`
    // itself. Before this fix, that left the process sitting in
    // `ctrl_c().await` forever with the routes (in `default` mode, both `/1`
    // halves and the server pin) still installed and no packet engine behind
    // them -- a total, silent network blackout, with `StatsHandle::load`
    // still reporting `Connected` the whole time.
    let stop = tokio::select! {
        r = tokio::signal::ctrl_c() => Stop::Signal(r),
        _ = sigterm.recv() => Stop::Signal(Ok(())),
        res = &mut engine_task => Stop::EngineExited(res),
    };

    // `None` on the signal path (the ordinary, expected way to stop); `Some`
    // is the exact condition that must turn into a loud log line and a
    // non-zero exit further down.
    let engine_failure = match &stop {
        Stop::EngineExited(res) => {
            let detail = describe_engine_exit(res);
            tracing::error!(
                reason = %detail,
                "tunnel stopped on its own, not by operator request; reverting routes and \
                 exiting non-zero"
            );
            Some(detail)
        }
        Stop::Signal(_) => None,
    };

    println!("\nshutting down");

    shutdown.shutdown();
    guard.revert_now();
    // A clean shutdown reverted the routes above, so the state file describing
    // them would be stale as soon as this process exits; clear it now so the
    // next start does not mistake a normal exit for a crash to recover from.
    liostunnel_core::route::state::AppliedState::clear(&state_path);
    // A no-op if `stop` is already `EngineExited` (the task has already
    // finished); still required on the signal path, where the engine is very
    // much still running.
    engine_task.abort();

    let s = stats.load();
    println!(
        "flows failed: {}, dns queries: {}",
        s.flows_failed, s.dns_queries
    );

    if let Some(detail) = engine_failure {
        return Err(TunnelError::Protocol(format!(
            "tunnel engine stopped unexpectedly: {detail}"
        )));
    }

    match stop {
        Stop::Signal(r) => r.map_err(TunnelError::Transport)?,
        Stop::EngineExited(_) => unreachable!("handled and returned above"),
    }
    Ok(())
}

/// Why `run`'s final `select!` has a third arm, alongside Ctrl-C and
/// `SIGTERM` -- see the comment at its call site for the failure mode this
/// closes.
enum Stop {
    Signal(std::io::Result<()>),
    EngineExited(Result<Result<(), TunnelError>, tokio::task::JoinError>),
}

/// What to tell the operator about IPv6 handling in `default` mode -- Gap 2's
/// "be deliberate and loud" requirement: an operator who needs working IPv6
/// must not discover its absence only when their connectivity silently
/// breaks. Pure -- a match on already-computed values, no I/O -- so every
/// branch is covered by a test with no TUN device, no routes, and no root,
/// matching this module's own testing convention (see `describe_engine_exit`
/// just below).
///
/// `None` in `test` mode: that mode only ever routes the CIDRs the operator
/// explicitly listed and never claims to capture "everything", so there is
/// nothing new to warn about there -- IPv6 was already outside its scope.
fn ipv6_notice(mode: &RouteMode, ipv6_available: bool) -> Option<String> {
    match mode {
        RouteMode::Default if ipv6_available => Some(
            "IPv6 traffic is being captured and DROPPED, not tunnelled. Phase 0's packet \
             engine only parses IPv4 (net/smoltcp_stack/inspect.rs), so the IPv6 \
             split-default this mode installs (::/1 + 8000::/1) routes v6 traffic into the \
             TUN device only to blackhole it there. This is deliberate -- failing closed \
             beats leaking in cleartext -- but if you need working IPv6 connectivity, this \
             tool does not provide it yet."
                .to_string(),
        ),
        RouteMode::Default => Some(
            "This host has no working IPv6 stack, so `default` mode is not installing any \
             IPv6 routes; there is no IPv6 traffic to misdirect, so there is nothing to \
             blackhole."
                .to_string(),
        ),
        RouteMode::Test { .. } => None,
    }
}

/// Describes why the engine's task ended, for the log line and non-zero
/// exit `run` produces when the tunnel dies on its own. Factored out as a
/// pure function -- no I/O, no process state -- so every shape this can take
/// is covered by a test that needs no TUN device, no routes, and no root.
fn describe_engine_exit(res: &Result<Result<(), TunnelError>, tokio::task::JoinError>) -> String {
    match res {
        Ok(Ok(())) => "the packet engine stopped on its own -- the packet stack closed both of \
                       its channels without this process ever asking it to. The tunnel is no \
                       longer forwarding any traffic."
            .to_string(),
        Ok(Err(e)) => format!("the packet engine returned an error: {e}"),
        Err(e) if e.is_panic() => format!("the packet engine's task panicked: {e}"),
        Err(e) => format!("the packet engine's task ended unexpectedly: {e}"),
    }
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

    // --- Review item 1: `describe_engine_exit` ---------------------------
    //
    // Pure, so every shape `engine_task`'s outcome can take is covered
    // without a TUN device, routes, or root -- exactly the property this
    // whole fix pass is about (per the module's own testing convention
    // above). This is the message an operator actually sees (via
    // `tracing::error!` at the call site, and again via `main.rs`'s own
    // `eprintln!("error: {e}")` once it becomes this function's `Err`).

    #[test]
    fn a_clean_engine_return_is_described_as_stopping_on_its_own() {
        let msg = describe_engine_exit(&Ok(Ok(())));
        assert!(
            msg.contains("stopped on its own"),
            "must say the engine ended without being asked to: {msg}"
        );
    }

    #[test]
    fn an_engine_error_return_names_the_underlying_error() {
        let res = Ok(Err(TunnelError::Protocol("stack thread gave up".into())));
        let msg = describe_engine_exit(&res);
        assert!(
            msg.contains("stack thread gave up"),
            "must surface the actual error, not just say something failed: {msg}"
        );
    }

    #[tokio::test]
    async fn a_panicking_engine_task_is_described_as_a_panic() {
        // A real `JoinError`, not a hand-built stand-in: spawning a task
        // that panics and awaiting its handle is the only way to get one
        // whose `is_panic()` is genuinely true.
        let handle = tokio::spawn(async { panic!("simulated stack-thread panic") });
        let join_err = handle.await.expect_err("a panicking task must join as Err");
        assert!(
            join_err.is_panic(),
            "test setup must actually produce a panic"
        );

        let msg = describe_engine_exit(&Err(join_err));
        assert!(
            msg.contains("panicked"),
            "a panicking task must be described as a panic, not a generic failure: {msg}"
        );
    }

    #[tokio::test]
    async fn an_aborted_engine_task_is_described_without_claiming_it_panicked() {
        let handle = tokio::spawn(std::future::pending::<()>());
        handle.abort();
        let join_err = handle.await.expect_err("an aborted task must join as Err");
        assert!(
            join_err.is_cancelled(),
            "test setup must actually produce a cancellation"
        );

        let msg = describe_engine_exit(&Err(join_err));
        assert!(
            !msg.contains("panicked"),
            "a cancelled task must not be described as a panic: {msg}"
        );
    }

    // --- Gap 2: `ipv6_notice` ------------------------------------------------
    //
    // Pure, so every branch is covered without a TUN device, routes, or
    // root -- this is the message an operator actually sees (via `eprintln!`
    // at the call site in `run`) before their v6 traffic silently starts
    // getting dropped instead of leaking.

    #[test]
    fn default_mode_with_ipv6_warns_that_v6_is_dropped_not_tunnelled() {
        let msg = ipv6_notice(&RouteMode::Default, true).expect("must warn in this case");
        assert!(msg.contains("DROPPED"), "{msg}");
        assert!(msg.contains("::/1") && msg.contains("8000::/1"), "{msg}");
    }

    #[test]
    fn default_mode_without_ipv6_explains_nothing_was_installed() {
        let msg = ipv6_notice(&RouteMode::Default, false).expect("must warn in this case too");
        assert!(msg.to_lowercase().contains("no working ipv6"), "{msg}");
    }

    #[test]
    fn test_mode_gets_no_ipv6_notice() {
        let mode = RouteMode::Test {
            cidrs: vec!["93.184.216.0/24".parse().unwrap()],
            capture_dns: false,
        };
        assert!(ipv6_notice(&mode, true).is_none());
        assert!(ipv6_notice(&mode, false).is_none());
    }
}

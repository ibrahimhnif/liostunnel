use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use liostunnel_core::TunnelError;
use liostunnel_core::config::profile::{DnsMode, ServerProfile};
use liostunnel_core::config::secret::{Redacted, SecretRef};
use liostunnel_core::dns::Resolver;
use liostunnel_core::dns::over_https::DohResolver;
use liostunnel_core::dns::over_tcp::TcpResolver;
use liostunnel_core::engine::{Engine, StatsHandle};
use liostunnel_core::net::smoltcp_stack::poll::SmoltcpStack;
use liostunnel_core::net::tun::{TunConfig, TunDevice};
use liostunnel_core::net::{NetStack, ShutdownHandle, StackConfig};
use liostunnel_core::protocols::Protocol;
use liostunnel_core::protocols::ssh::{HostKeyPolicy, SshTunnel};
use liostunnel_core::route::{
    RouteGuard, RouteMode, RoutePlan, platform_manager, reject_full_default_prefixes,
};
use liostunnel_ffi::dto::protocol::{ConnectParams, StatsSnapshot};

use crate::auth::{self, AuthError};

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// Deliberately carries nothing. serde_json's Display quotes keys and
    /// enum tags from the offending input, and that input is a profile.
    #[error("profile is not valid")]
    BadProfile,
    #[error("{0}")]
    BadRouteMode(String),
    #[error("tun address is not a valid IPv4 address")]
    BadTunAddress,
    #[error("env-var secrets are not available through the helper")]
    EnvSecretNotAllowed,
    #[error("{0}")]
    SecretNotPermitted(AuthError),
    #[error("{0}")]
    Tunnel(#[from] liostunnel_core::TunnelError),
}

/// A connect request that has passed every check decidable without privilege.
///
/// Holding one of these is the evidence that `authorize_params` ran and
/// approved: `start` takes this rather than raw `ConnectParams`, so there is
/// no way to reach the privileged path without going through the gate.
pub struct Authorized {
    pub profile: ServerProfile,
    pub user: String,
    pub route_mode: RouteMode,
    pub tun_address: Ipv4Addr,
    /// Every secret this profile needs, already read under the gate.
    ///
    /// The connect path is handed these rather than the paths they came
    /// from. Checking a path and letting something else re-open it later is
    /// check-then-use, and the gap here is not a race to be won by luck: a
    /// DNS lookup and an SSH handshake against a server the caller chose sit
    /// between the two, so the caller decides how long the window stays open.
    pub secrets: ResolvedSecrets,
}

/// Secrets read from the descriptors the gate authorized.
///
/// Serves `SshTunnel::connect` from memory so it never re-opens a path. The
/// alternative — handing it `FileSecretStore` and the profile — opens each
/// file a second time and checks only its mode, not its owner, which lets a
/// caller swap their own file for a symlink to one root can read but they
/// cannot. That is the exact escalation the gate exists to stop.
#[derive(Default)]
pub struct ResolvedSecrets(Vec<(SecretRef, Redacted<String>)>);

impl liostunnel_core::config::secret::SecretStore for ResolvedSecrets {
    fn resolve(&self, r: &SecretRef) -> Result<Redacted<String>, TunnelError> {
        self.0
            .iter()
            .find(|(k, _)| k == r)
            .map(|(_, v)| Redacted::new(v.expose().clone()))
            .ok_or_else(|| {
                // Unreachable unless a ref appears at connect time that
                // `secret_refs()` did not report at authorization time. Fail
                // closed rather than fall back to reading it: an unresolved
                // ref is one the gate never saw.
                TunnelError::config("secret", "not resolved under the authorization gate")
            })
    }
}

/// Hand-written rather than derived. A derived impl would render the whole
/// profile — including the paths and variable names its `SecretRef`s point
/// at — into anything that formats this with `{:?}`, and the helper's log is
/// the most sensitive one in the system. Names what it is, not what it holds.
impl std::fmt::Debug for Authorized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorized")
            .field("host", &self.profile.host)
            .field("port", &self.profile.port)
            .field("tun_address", &self.tun_address)
            .finish_non_exhaustive()
    }
}

/// Where the daemon keeps its own root-owned files.
///
/// All derived from the socket path, so a test instance is isolated from a
/// real one and nothing lands in any user's home. The helper is root: its
/// route-recovery record and its host-key store are its own, not the calling
/// user's.
#[derive(Clone, Debug)]
pub struct HelperPaths {
    pub applied_routes: PathBuf,
    pub known_hosts: PathBuf,
}

impl HelperPaths {
    pub fn beside_socket(socket: &Path) -> Self {
        let sibling = |suffix: &str| {
            let mut s = socket.as_os_str().to_os_string();
            s.push(suffix);
            PathBuf::from(s)
        };
        Self {
            applied_routes: sibling(".routes.json"),
            known_hosts: sibling(".known_hosts"),
        }
    }
}

/// Tells the stack thread to stop if this scope is torn down before the
/// engine takes over that responsibility.
///
/// Between `SmoltcpStack::start` returning and the engine existing there are
/// several fallible steps — gateway detection, route installation — whose
/// failure has nothing to do with the stack thread but must still stop it,
/// or the background thread and the open TUN device leak for the life of the
/// process. `shutdown` only sets a flag and wakes the loop, so firing again
/// later on the engine's own path is harmless.
struct StackShutdownOnDrop(ShutdownHandle);

impl Drop for StackShutdownOnDrop {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

pub struct Tunnel {
    shutdown: ShutdownHandle,
    stats: StatsHandle,
    guard: Option<RouteGuard>,
    state_path: PathBuf,
    engine_task: tokio::task::JoinHandle<Result<(), TunnelError>>,
}

impl Tunnel {
    /// Brings up the tunnel: SSH, then the TUN device and packet stack, and
    /// only then the routing table.
    ///
    /// The ordering is Phase 0's and is load-bearing — see
    /// `liostunnel-cli/src/commands/connect.rs`, which this mirrors rather
    /// than re-derives. Taking `Authorized` rather than `ConnectParams` makes
    /// "the gate ran first" a type-level fact instead of a convention.
    pub async fn start(auth: Authorized, paths: &HelperPaths) -> Result<Self, StartError> {
        // 1. SSH before routes, so a failed handshake never leaves the machine
        //    with routes pointing at an interface with nothing behind it.
        //
        //    Host keys are verified against a root-owned store of the
        //    daemon's own, never AcceptAny: the helper dials whatever host a
        //    profile names, and accepting any key would turn it into a
        //    machine-in-the-middle oracle for every profile it is given.
        let policy = HostKeyPolicy::Verify {
            known_hosts: paths.known_hosts.clone(),
        };
        // Everything needed to diagnose a rejected login, and nothing that
        // would put a credential in a root-owned log that persists and gets
        // backed up. `RUST_LOG=liostunnel_helper=debug` turns it on.
        describe_connect_attempt(&auth.user, &auth.profile);

        let mut ssh = SshTunnel::new(auth.user, policy);
        // The secrets, not the paths. See `ResolvedSecrets`.
        ssh.connect(&auth.profile, &auth.secrets).await?;

        // The address the SSH session actually reached, not a second
        // independent lookup — a multi-A-record host could otherwise have the
        // route pin a different peer than the one carrying the traffic.
        let server_ip = ssh
            .peer_addr()
            .ok_or_else(|| {
                TunnelError::Route("ssh session reports no peer address after connecting".into())
            })?
            .ip();
        let protocol: Arc<dyn Protocol> = Arc::new(ssh);

        // 2. TUN device.
        let tun = TunDevice::open(TunConfig {
            address: auth.tun_address,
            ..TunConfig::default()
        })?;
        let interface = tun.name()?;
        tracing::info!(%interface, address = %auth.tun_address, "TUN interface up");

        // 3. Packet stack, guarded from here until the engine owns it.
        let handles = SmoltcpStack::default().start(
            Box::new(tun),
            StackConfig {
                address: auth.tun_address,
                ..StackConfig::default()
            },
        )?;
        let stack_guard = StackShutdownOnDrop(handles.shutdown.clone());

        // 4. Routes last.
        let manager = platform_manager();
        let gateway = manager.detect_gateway()?;
        let plan = RoutePlan {
            interface,
            mode: auth.route_mode,
            server_ip,
            original_gateway: gateway,
            dns_servers: auth.profile.dns.servers.clone(),
            ipv6_available: manager.ipv6_available(),
        };

        // Record before applying. A crash between these two lines leaves a
        // record of routes that were never installed, and reverting those is
        // harmless; the reverse order loses them entirely. Do not "optimise"
        // this by moving the save after apply.
        liostunnel_core::route::state::AppliedState {
            interface: plan.interface.clone(),
            revert: manager.revert_commands(&plan)?,
            pid: std::process::id(),
        }
        .save(&paths.applied_routes)?;

        let guard = RouteGuard::apply(manager, plan)?;

        // 5. Engine.
        let resolver: Arc<dyn Resolver> = match auth.profile.dns.mode {
            DnsMode::Tcp => Arc::new(TcpResolver::new(
                protocol.clone(),
                auth.profile.dns.servers.clone(),
            )),
            DnsMode::Https => {
                let doh = auth.profile.dns.https.clone().ok_or_else(|| {
                    TunnelError::config("dns.https", "required when dns.mode is `https`")
                })?;
                Arc::new(DohResolver::new(
                    protocol.clone(),
                    auth.profile.dns.servers.clone(),
                    doh,
                ))
            }
        };
        let engine = Engine::new(protocol, resolver, handles);
        let shutdown = engine.shutdown_handle();
        let stats = engine.stats_handle();
        let engine_task = tokio::spawn(engine.run());

        // The engine owns the stack's lifetime from here, and `Tunnel`'s own
        // Drop calls the same shutdown. Letting this guard fire on the way
        // out of `start` would stop the stack we just handed over.
        std::mem::forget(stack_guard);

        Ok(Self {
            shutdown,
            stats,
            guard: Some(guard),
            state_path: paths.applied_routes.clone(),
            engine_task,
        })
    }

    pub fn stats(&self) -> StatsSnapshot {
        let s = self.stats.load();
        StatsSnapshot {
            bytes_up: s.bytes_up,
            bytes_down: s.bytes_down,
            active_flows: s.active_flows,
            flows_failed: s.flows_failed,
            dns_queries: s.dns_queries,
        }
    }

    /// True once the engine has exited on its own — a stack-thread panic, or
    /// the poller giving up — rather than being asked to stop.
    ///
    /// Phase 0 shipped the bug this exists to catch: a process sitting
    /// waiting forever with routes installed and no packet engine behind
    /// them, a silent network blackout while stats still read Connected.
    pub fn has_stopped(&self) -> bool {
        self.engine_task.is_finished()
    }

    /// Shuts down, reverts routes, clears the state file, aborts the engine.
    /// Consuming `self` runs `Drop`, where those four live, so there is
    /// exactly one teardown path rather than two that can drift.
    pub fn stop(self) {}
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // ROUTES FIRST, then the stack. The CLI does the reverse and it is
        // wrong on macOS: shutting the stack down destroys the utun device,
        // and `route delete -net CIDR -interface utunN` then fails with
        // "bad address: utunN" because there is no such interface any more.
        // Measured — the revert failed 23ms after "stack closed" on every
        // single disconnect, and cleanup only happened as a side effect of
        // macOS reclaiming an interface's routes when it disappears.
        //
        // Reverting first is also better behaviour on its own terms: it
        // restores ordinary routing while the tunnel is still up, instead of
        // leaving routes pointing at a device that is already gone.
        if let Some(mut g) = self.guard.take() {
            g.revert_now();
        }
        // `shutdown` is a plain method call, not something any Drop reaches
        // for on its own, so it has to be explicit here.
        self.shutdown.shutdown();
        // The routes are gone, so a record of them is stale the moment this
        // process exits; clear it, or the next start mistakes a clean stop
        // for a crash to recover from.
        liostunnel_core::route::state::AppliedState::clear(&self.state_path);
        self.engine_task.abort();
    }
}

impl Tunnel {
    /// Everything that must be checked *before* any privileged action.
    ///
    /// Split out from `start` deliberately: it is pure, so the escalation
    /// guard is testable without root, a TUN device, or a routing table.
    pub fn authorize_params(
        params: &ConnectParams,
        caller_uid: u32,
    ) -> Result<Authorized, StartError> {
        // Note the discarded error: serde_json's Display quotes keys and enum
        // tags from the input, and the input is a profile.
        let profile: ServerProfile =
            serde_json::from_str(&params.profile_json).map_err(|_| StartError::BadProfile)?;

        let route_mode = parse_route_mode(&params.route_mode, &params.cidrs, params.capture_dns)?;

        let tun_address: Ipv4Addr = params
            .tun_address
            .parse()
            .map_err(|_| StartError::BadTunAddress)?;

        // THE ESCALATION GATE. The helper runs as root and could read any of
        // these; this is what stops the caller borrowing that power.
        //
        // Each secret is read HERE, from the descriptor that was checked, and
        // carried forward. Nothing downstream re-opens a path.
        let mut resolved = Vec::new();
        for r in profile.auth.secret_refs() {
            match r {
                SecretRef::File { path } => {
                    let body = auth::read_secret_owned_by(path, caller_uid)
                        .map_err(StartError::SecretNotPermitted)?;
                    resolved.push((r.clone(), Redacted::new(body)));
                }
                // Refused outright rather than checked. SecretRef::Env
                // resolves against the *process* environment, and this
                // process is root — so an env ref can only ever name
                // something that was never the caller's, and the value would
                // leave as a credential to a server they chose. There is no
                // ownership test that makes it safe, because the caller
                // cannot put anything into the helper's environment. Env
                // secrets only make sense where the process IS the user,
                // which is the CLI, not the daemon.
                SecretRef::Env { .. } => return Err(StartError::EnvSecretNotAllowed),
            }
        }

        Ok(Authorized {
            profile,
            user: params.user.clone(),
            route_mode,
            tun_address,
            secrets: ResolvedSecrets(resolved),
        })
    }
}

/// Logs what a connection attempt is about to use.
///
/// Reports the *shape* of the credential — where it lives, its size, its
/// permissions, and whether it has trailing whitespace — never its value.
/// That is enough to identify every cause of a rejected login this code can
/// produce, and it keeps the rule the whole design rests on: the helper's log
/// is the most sensitive one on the machine, and a password written there
/// outlives the debugging session that wanted it.
///
/// The trailing-whitespace check earns its place. `FileSecretStore` strips at
/// most ONE trailing line ending, so a file ending in `\n\n`, a space, or a
/// CRLF pair sends a credential that differs from the one the user believes
/// they stored — and the server's only reply is a flat rejection.
/// The final byte, without reading the file.
///
/// The caller names this path, so `std::fs::read` here was a caller-chosen
/// allocation inside a root daemon — an 8 GB file would OOM it mid-tunnel.
fn last_byte_of(path: &Path) -> Option<u8> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    f.seek(SeekFrom::End(-1)).ok()?;
    let mut b = [0u8; 1];
    f.read_exact(&mut b).ok()?;
    Some(b[0])
}

fn describe_connect_attempt(user: &str, profile: &ServerProfile) {
    // Nothing below is built unless the level is actually on. `tracing`'s
    // macro gates emission, not the construction of its arguments, so the
    // work happened on every connect regardless.
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    for r in profile.auth.secret_refs() {
        let detail = match r {
            SecretRef::Env { var } => format!("env:{var} (the helper refuses these)"),
            SecretRef::File { path } => match std::fs::metadata(path) {
                Err(e) => format!("file:{} — CANNOT STAT: {e}", path.display()),
                Ok(m) => {
                    // Only the final byte is inspected, and only to classify
                    // it as whitespace or not.
                    let trailing = last_byte_of(path)
                        .map(|b| match b {
                            b'\n' => "ends with LF (one is stripped, more are not)",
                            b'\r' => "ends with CR — likely a CRLF file",
                            b' ' | b'\t' => "ENDS WITH A SPACE OR TAB — not stripped",
                            _ => "no trailing whitespace",
                        })
                        .unwrap_or("empty file");
                    format!(
                        "file:{} — {} bytes, mode {:o}, owner uid {}, {}",
                        path.display(),
                        m.len(),
                        m.permissions().mode() & 0o777,
                        m.uid(),
                        trailing
                    )
                }
            },
        };
        tracing::debug!(
            ssh_user = %user,
            host = %profile.host,
            port = profile.port,
            auth = ?std::mem::discriminant(&profile.auth),
            secret = %detail,
            "connect attempt"
        );
    }
}

/// Maps the wire's route-mode strings to a [`RouteMode`], purely.
///
/// Mirrors `liostunnel-cli`'s `parse_route_mode`. Duplicated rather than
/// shared because the CLI is a binary crate the helper must not depend on,
/// and the plan forbids modifying it. The checks it performs — especially
/// `reject_full_default_prefixes` — live in core, so the rule itself is not
/// duplicated, only the string mapping.
fn parse_route_mode(
    route_mode: &str,
    cidrs: &[String],
    capture_dns: bool,
) -> Result<RouteMode, StartError> {
    match route_mode {
        "test" => {
            let parsed = cidrs
                .iter()
                .map(|c| {
                    c.parse::<ipnet::IpNet>()
                        .map_err(|_| StartError::BadRouteMode(format!("cidr is not valid: {c}")))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if parsed.is_empty() {
                return Err(StartError::BadRouteMode(
                    "test route mode needs at least one prefix".into(),
                ));
            }
            reject_full_default_prefixes(&parsed)?;
            // `reject_full_default_prefixes` only rejects /0. The classic
            // split-default pair `0.0.0.0/1` + `128.0.0.0/1` walks past it and
            // covers the whole address space — and `test` mode installs NO
            // server pin through the original gateway, unlike `default` mode.
            // The SSH session's own packets then route into the tunnel that
            // carries them: total connectivity loss, reachable from the
            // unprivileged socket, persisting until an explicit disconnect.
            if let Some(bad) = parsed.iter().find(|c| c.prefix_len() <= 1) {
                return Err(StartError::BadRouteMode(format!(
                    "{bad} is too broad for test mode, which installs no route \
                     to the server itself; use default mode to capture everything"
                )));
            }
            Ok(RouteMode::Test {
                cidrs: parsed,
                capture_dns,
            })
        }
        "default" => Ok(RouteMode::Default),
        other => Err(StartError::BadRouteMode(format!(
            "expected `test` or `default`, got `{other}`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use liostunnel_ffi::dto::protocol::ConnectParams;

    fn me() -> u32 {
        unsafe { libc::getuid() }
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("lios-sess-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A 0600 file owned by this process, standing in for a private key.
    fn owned_secret(dir: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("key");
        std::fs::write(&p, b"not really a key").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    }

    fn params_with_file_secret(path: &std::path::Path) -> ConnectParams {
        ConnectParams {
            profile_json: format!(
                r#"{{"id":"00000000-0000-0000-0000-000000000000","name":"t",
                    "protocol":"ssh","host":"127.0.0.1","port":22,
                    "auth":{{"type":"password","password":{{"source":"file","path":"{}"}}}},
                    "dns":["1.1.1.1"],"split_tunnel":{{"type":"all_traffic"}},
                    "kill_switch":false}}"#,
                path.display()
            ),
            user: "someone".into(),
            route_mode: "test".into(),
            cidrs: vec!["93.184.216.0/24".into()],
            capture_dns: false,
            tun_address: "10.90.0.1".into(),
        }
    }

    fn params_with_env_secret(var: &str) -> ConnectParams {
        ConnectParams {
            profile_json: format!(
                r#"{{"id":"00000000-0000-0000-0000-000000000000","name":"t",
                    "protocol":"ssh","host":"127.0.0.1","port":22,
                    "auth":{{"type":"password","password":{{"source":"env","var":"{var}"}}}},
                    "dns":["1.1.1.1"],"split_tunnel":{{"type":"all_traffic"}},
                    "kill_switch":false}}"#
            ),
            user: "someone".into(),
            route_mode: "test".into(),
            cidrs: vec!["93.184.216.0/24".into()],
            capture_dns: false,
            tun_address: "10.90.0.1".into(),
        }
    }

    #[test]
    fn a_secret_the_caller_does_not_own_is_refused() {
        // THE ESCALATION, at the layer that matters: refused before a TUN
        // device exists, before a route is installed, and before any file is
        // read.
        //
        // The discriminator is a mismatched uid argument, not a root-owned
        // system file. /etc/shadow is absent on macOS, "ours" in a root
        // container, and mode 0640 on Debian — every one of which makes the
        // test vacuous exactly where it must not be. Task 3 learned this the
        // expensive way.
        let d = scratch("foreign-secret");
        let p = owned_secret(&d);
        let err = Tunnel::authorize_params(&params_with_file_secret(&p), me().wrapping_add(1))
            .expect_err("a secret the caller does not own must be refused");
        assert!(
            matches!(err, StartError::SecretNotPermitted(_)),
            "got {err:?}"
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_secret_the_caller_owns_is_permitted() {
        let d = scratch("own-secret");
        let p = owned_secret(&d);
        Tunnel::authorize_params(&params_with_file_secret(&p), me())
            .expect("our own 0600 file must be accepted");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn an_env_var_secret_is_refused_outright() {
        // SecretRef::Env resolves against the *process* environment, and this
        // process is root. A caller naming an env var would be reaching into
        // root's environment for something that was never theirs, and the
        // result would leave as an SSH password to a server they chose.
        //
        // There is no ownership check that makes this safe, because the
        // caller cannot put anything into the helper's environment in the
        // first place. Env secrets are a CLI affordance — they only make
        // sense when the process IS the user — so the daemon refuses them.
        let err = Tunnel::authorize_params(&params_with_env_secret("SSH_AUTH_SOCK"), me())
            .expect_err("an env-var secret must be refused by the daemon");
        assert!(
            matches!(err, StartError::EnvSecretNotAllowed),
            "got {err:?}"
        );
    }

    #[test]
    fn a_profile_that_does_not_parse_is_refused_without_echoing_it() {
        // The marker sits where serde_json actually echoes — an unknown enum
        // tag. Put it in a value and the test passes against an
        // implementation that leaks, proving nothing (Task 5's lesson).
        let mut p = params_with_file_secret(std::path::Path::new("/tmp/whatever"));
        p.profile_json = r#"{"protocol":"SECRET-VALUE-HERE","host":"h","port":22}"#.into();
        let err = Tunnel::authorize_params(&p, me()).expect_err("must not parse");
        let text = format!("{err}");
        assert!(
            !text.contains("SECRET-VALUE-HERE"),
            "error echoed input: {text}"
        );
        let debug = format!("{err:?}");
        assert!(
            !debug.contains("SECRET-VALUE-HERE"),
            "Debug echoed input: {debug}"
        );
    }

    #[test]
    fn an_unknown_route_mode_is_refused() {
        let d = scratch("bad-mode");
        let p = owned_secret(&d);
        let mut params = params_with_file_secret(&p);
        params.route_mode = "wide-open".into();
        assert!(Tunnel::authorize_params(&params, me()).is_err());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn test_mode_without_any_cidr_is_refused() {
        // Otherwise `test` mode installs nothing and the tunnel silently
        // carries no traffic at all.
        let d = scratch("no-cidr");
        let p = owned_secret(&d);
        let mut params = params_with_file_secret(&p);
        params.cidrs = vec![];
        assert!(Tunnel::authorize_params(&params, me()).is_err());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_split_default_pair_in_test_mode_is_refused() {
        // reject_full_default_prefixes only rejects /0, so this pair walked
        // past it — and test mode installs NO route to the server through the
        // original gateway, unlike default mode. The SSH session's own packets
        // would route into the tunnel carrying them: total connectivity loss,
        // reachable from the unprivileged socket.
        let d = scratch("split-default");
        let p = owned_secret(&d);
        let mut params = params_with_file_secret(&p);
        params.cidrs = vec!["0.0.0.0/1".into(), "128.0.0.0/1".into()];
        assert!(matches!(
            Tunnel::authorize_params(&params, me()),
            Err(StartError::BadRouteMode(_))
        ));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_single_half_of_the_default_route_is_refused_too() {
        // One /1 is half the internet and still has no server pin behind it.
        let d = scratch("one-half");
        let p = owned_secret(&d);
        let mut params = params_with_file_secret(&p);
        params.cidrs = vec!["0.0.0.0/1".into()];
        assert!(Tunnel::authorize_params(&params, me()).is_err());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn an_ordinary_prefix_is_still_accepted() {
        // The guard must not swallow legitimate use.
        let d = scratch("ordinary");
        let p = owned_secret(&d);
        let mut params = params_with_file_secret(&p);
        params.cidrs = vec!["10.0.0.0/8".into(), "93.184.216.34/32".into()];
        assert!(Tunnel::authorize_params(&params, me()).is_ok());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_full_default_prefix_in_test_mode_is_refused() {
        // Phase 0's route layer refuses 0.0.0.0/0 as a `test` CIDR because it
        // would silently become a default route without the split-default
        // machinery that makes one reversible. The helper must not offer a
        // way around that check.
        let d = scratch("full-default");
        let p = owned_secret(&d);
        let mut params = params_with_file_secret(&p);
        params.cidrs = vec!["0.0.0.0/0".into()];
        assert!(Tunnel::authorize_params(&params, me()).is_err());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_malformed_tun_address_is_refused() {
        let d = scratch("bad-tun");
        let p = owned_secret(&d);
        let mut params = params_with_file_secret(&p);
        params.tun_address = "not-an-address".into();
        assert!(Tunnel::authorize_params(&params, me()).is_err());
        std::fs::remove_dir_all(&d).ok();
    }
}

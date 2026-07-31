//! Starting and stopping the packet engine inside the app process.
//!
//! # How this differs from the desktop path
//!
//! `liostunnel-helper` assembles the same pieces in `session.rs`, but as root
//! in a separate process, and with two steps that have no Android
//! counterpart: it creates the TUN device itself, and it installs routes.
//! Here the descriptor arrives already configured from
//! `VpnService.establish()`, and `VpnService.Builder` owns the routing table.
//! What is left — protocol, stack, resolver, engine — is identical.
//!
//! # Lifetime
//!
//! The engine runs on a tokio runtime owned by this module, on threads owned
//! by the process rather than by the Dart isolate. That is what lets the
//! tunnel survive the app being swiped away: the Activity and its Flutter
//! engine are destroyed, the foreground service keeps the process alive, and
//! these threads never notice.

use crate::config::profile::{DnsMode, ProtocolKind, ServerProfile};
use crate::config::secret::{Redacted, SecretRef, SecretStore};
use crate::dns::Resolver;
use crate::dns::over_https::DohResolver;
use crate::dns::over_tcp::TcpResolver;
use crate::engine::{Engine, StatsHandle};
use crate::error::TunnelError;
use crate::net::android_tun::AndroidTun;
use crate::net::smoltcp_stack::poll::SmoltcpStack;
use crate::net::{NetStack, ShutdownHandle, StackConfig};
use crate::protocols::Protocol;
use crate::protocols::shadowsocks::ShadowsocksTunnel;
use crate::protocols::ssh::{HostKeyPolicy, SshTunnel};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

/// The tunnel interface's address, and the single source of truth for it.
///
/// `VpnService.Builder.addAddress` in Kotlin and [`StackConfig::address`] here
/// must name the same address, or the stack answers on one the descriptor
/// never carries and the tunnel silently carries nothing. Rather than write
/// the literal twice, Kotlin reads it from
/// [`Java_com_liostunnel_app_LiosVpnService_nativeTunAddress`].
///
/// [`Java_com_liostunnel_app_LiosVpnService_nativeTunAddress`]: super::Java_com_liostunnel_app_LiosVpnService_nativeTunAddress
pub const TUN_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 90, 0, 1);

/// Matches `Builder.setMtu`, for the same reason as [`TUN_ADDRESS`].
pub const TUN_MTU: usize = 1500;

/// Secrets resolved by the app and handed over with the profile.
///
/// The Android counterpart of the helper's `ResolvedSecrets`: values, never
/// paths. An app sandbox has no root-owned secret files to read, and the UI
/// already holds what the user typed.
pub struct AndroidSecrets(Vec<(SecretRef, Redacted<String>)>);

impl AndroidSecrets {
    pub fn new(pairs: Vec<(SecretRef, String)>) -> Self {
        Self(
            pairs
                .into_iter()
                .map(|(r, v)| (r, Redacted::new(v)))
                .collect(),
        )
    }
}

impl SecretStore for AndroidSecrets {
    fn resolve(&self, r: &SecretRef) -> Result<Redacted<String>, TunnelError> {
        self.0
            .iter()
            .find(|(k, _)| k == r)
            .map(|(_, v)| Redacted::new(v.expose().clone()))
            .ok_or_else(|| TunnelError::config("secret", "was not supplied to the tunnel"))
    }
}

/// Everything needed to start, staged by the app before the service runs.
pub struct StartRequest {
    pub profile: ServerProfile,
    pub user: String,
    pub secrets: AndroidSecrets,
}

/// What the UI is shown.
///
/// Deliberately not `ConnectionState`: this carries a failure reason, and the
/// UI needs to distinguish "never started" from "tried and failed".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineState {
    Idle,
    Connecting,
    Connected,
    Failed(String),
}

struct Running {
    shutdown: ShutdownHandle,
    stats: StatsHandle,
    runtime: tokio::runtime::Runtime,
}

static PENDING: Mutex<Option<StartRequest>> = Mutex::new(None);
static RUNNING: Mutex<Option<Running>> = Mutex::new(None);
static STATE: Mutex<Option<EngineState>> = Mutex::new(None);

fn set_state(s: EngineState) {
    *STATE.lock().expect("state lock") = Some(s);
}

/// The current engine state, for the UI to poll over FFI.
pub fn state() -> EngineState {
    STATE
        .lock()
        .expect("state lock")
        .clone()
        .unwrap_or(EngineState::Idle)
}

/// Byte and flow counters, or zeros when nothing is running.
pub fn stats() -> (u64, u64, u64, u64, u64) {
    let guard = RUNNING.lock().expect("running lock");
    let Some(r) = guard.as_ref() else {
        return (0, 0, 0, 0, 0);
    };
    let s = r.stats.load();
    (
        s.bytes_up,
        s.bytes_down,
        s.active_flows.into(),
        s.flows_failed,
        s.dns_queries,
    )
}

/// Stages a profile for the next `nativeStart`.
///
/// Called from Dart over FFI **before** the service is asked to start, which
/// is what keeps the credential out of the `Intent` that starts it.
pub fn stage(request: StartRequest) {
    *PENDING.lock().expect("pending lock") = Some(request);
    set_state(EngineState::Idle);
}

/// Builds the engine on `fd` and runs it until [`stop`].
///
/// Returns immediately; the engine runs on its own runtime threads.
pub fn start(fd: std::os::fd::RawFd) {
    let Some(request) = PENDING.lock().expect("pending lock").take() else {
        // Nothing staged. The descriptor is still ours to close, or it leaks
        // for the life of the process.
        super::log(
            super::ANDROID_LOG_ERROR,
            "start: no profile staged; closing the descriptor",
        );
        unsafe { libc::close(fd) };
        set_state(EngineState::Failed("no profile was staged".into()));
        return;
    };

    let tun = match AndroidTun::new(fd, TUN_MTU) {
        Ok(t) => t,
        Err(e) => {
            super::log(super::ANDROID_LOG_ERROR, &format!("start: {e}"));
            set_state(EngineState::Failed(e.to_string()));
            return;
        }
    };

    set_state(EngineState::Connecting);

    // Its own runtime, on its own threads. Nothing here belongs to the Dart
    // isolate, so tearing the Flutter engine down does not touch it.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("lios-engine")
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            super::log(super::ANDROID_LOG_ERROR, &format!("start: runtime: {e}"));
            set_state(EngineState::Failed(format!("cannot start runtime: {e}")));
            return;
        }
    };

    match runtime.block_on(assemble(request, tun)) {
        Ok((shutdown, stats, task)) => {
            runtime.spawn(task);
            *RUNNING.lock().expect("running lock") = Some(Running {
                shutdown,
                stats,
                runtime,
            });
            set_state(EngineState::Connected);
            super::log(super::ANDROID_LOG_INFO, "start: engine running");
        }
        Err(e) => {
            // The message is the protocol's own. Profile content never
            // reaches it -- `shadowsocks.rs` and `ssh.rs` both enforce that
            // in their own error paths, and this only forwards.
            super::log(super::ANDROID_LOG_ERROR, &format!("start failed: {e}"));
            set_state(EngineState::Failed(e.to_string()));
        }
    }
}

/// Connects the protocol, starts the stack, and builds the engine.
async fn assemble(
    request: StartRequest,
    tun: AndroidTun,
) -> Result<
    (
        ShutdownHandle,
        StatsHandle,
        impl std::future::Future<Output = ()> + Send + 'static,
    ),
    TunnelError,
> {
    let StartRequest {
        profile,
        user,
        secrets,
    } = request;

    let protocol: Arc<dyn Protocol> = match profile.protocol {
        ProtocolKind::Ssh => {
            // Host keys are verified, never AcceptAny. The app's own store,
            // in its sandbox -- there is no root-owned known_hosts here, and
            // accepting any key would make the tunnel a
            // machine-in-the-middle oracle for every profile it is given.
            let policy = HostKeyPolicy::Verify {
                known_hosts: known_hosts_path(),
            };
            let mut ssh = SshTunnel::new(user, policy);
            ssh.connect(&profile, &secrets).await?;
            Arc::new(ssh)
        }
        ProtocolKind::Shadowsocks => {
            let mut ss = ShadowsocksTunnel::new();
            ss.connect(&profile, &secrets).await?;
            Arc::new(ss)
        }
        other => {
            return Err(TunnelError::Unsupported(match other {
                ProtocolKind::WireGuard => "wireguard",
                _ => "this protocol",
            }));
        }
    };

    let handles = SmoltcpStack::default().start(
        Box::new(tun),
        StackConfig {
            address: TUN_ADDRESS,
            mtu: TUN_MTU,
            ..StackConfig::default()
        },
    )?;

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
    Ok((shutdown, stats, async move {
        // `run` returning an error means the engine stopped on its own --
        // a stack-thread panic, or the poller giving up -- rather than
        // being asked to. Phase 0 shipped the bug of a tunnel sitting
        // there with no engine behind it while stats still read
        // Connected, so this records the state instead of discarding it.
        match engine.run().await {
            Ok(()) => set_state(EngineState::Idle),
            Err(e) => {
                super::log(super::ANDROID_LOG_ERROR, &format!("engine stopped: {e}"));
                set_state(EngineState::Failed(e.to_string()));
            }
        }
    }))
}

/// Where SSH host keys are remembered.
///
/// Inside the app's own data directory: an Android app has no `$HOME`, and
/// this is the only location it is guaranteed to be able to write.
fn known_hosts_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/data/data/com.liostunnel.app/files/known_hosts")
}

/// Stops the engine and releases the descriptor.
pub fn stop() {
    let taken = RUNNING.lock().expect("running lock").take();
    if let Some(r) = taken {
        r.shutdown.shutdown();
        // Dropping the runtime joins its threads, so the stack -- and with it
        // the `AndroidTun` that owns the descriptor -- is fully torn down
        // before this returns. Kotlin closes its ParcelFileDescriptor next,
        // and it must not do that while a thread is still reading.
        drop(r.runtime);
    }
    set_state(EngineState::Idle);
    super::log(super::ANDROID_LOG_INFO, "stop: engine stopped");
}

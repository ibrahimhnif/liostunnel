use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use russh::client::{self, AuthResult};
use russh::keys::known_hosts::{
    check_known_hosts_path, known_host_keys_path, learn_known_hosts_path,
};
use russh::keys::ssh_key::PublicKey;

use crate::config::profile::{AuthMethod, ProtocolKind, ServerProfile};
use crate::config::secret::SecretStore;
use crate::error::TunnelError;
use crate::protocols::{Protocol, TunnelStream};
use crate::stats::{ConnectionState, ConnectionStats};

/// Spec §8. `AcceptAny` is reachable only via `--insecure-accept-any-hostkey`.
#[derive(Clone, Debug)]
pub enum HostKeyPolicy {
    Verify { known_hosts: PathBuf },
    AcceptAny,
}

/// Conservative: OpenSSH's default limits are higher, but a burst of flows
/// from the packet engine should queue rather than fail. Spec §8.
const MAX_CONCURRENT_CHANNELS: usize = 64;

pub struct SshTunnel {
    user: String,
    policy: HostKeyPolicy,
    handle: Option<client::Handle<ClientHandler>>,
    state: ConnectionState,
    counters: Arc<Counters>,
    channel_limit: Arc<tokio::sync::Semaphore>,
}

#[derive(Default)]
struct Counters {
    bytes_up: Arc<AtomicU64>,
    bytes_down: Arc<AtomicU64>,
    active_flows: Arc<AtomicU64>,
    flows_failed: AtomicU64,
}

impl SshTunnel {
    pub fn new(user: String, policy: HostKeyPolicy) -> Self {
        Self {
            user,
            policy,
            handle: None,
            state: ConnectionState::Disconnected,
            counters: Arc::new(Counters::default()),
            channel_limit: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CHANNELS)),
        }
    }
}

struct ClientHandler {
    host: String,
    port: u16,
    policy: HostKeyPolicy,
}

/// Required by `client::Handler::Error: From<russh::Error>` — russh's default
/// trait-method bodies (all the ones we don't override) convert their internal
/// errors through this. Never carries payload bytes, only russh's own message.
impl From<russh::Error> for TunnelError {
    fn from(e: russh::Error) -> Self {
        TunnelError::Protocol(e.to_string())
    }
}

impl client::Handler for ClientHandler {
    type Error = TunnelError;

    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, TunnelError> {
        match &self.policy {
            HostKeyPolicy::AcceptAny => {
                tracing::warn!(
                    host = %self.host, port = self.port,
                    "host key verification DISABLED; this connection is vulnerable to \
                     machine-in-the-middle interception"
                );
                Ok(true)
            }
            HostKeyPolicy::Verify { known_hosts } => {
                if let Some(parent) = known_hosts.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        TunnelError::HostKey(format!("cannot create known_hosts directory: {e}"))
                    })?;
                }

                // `check_known_hosts_path` is tri-state in a way that is easy
                // to misread: `Ok(false)` means *either* "no entry for this
                // host at all" (genuine first contact — TOFU applies) *or*
                // "entries exist for this host, but none share the presented
                // key's algorithm" (an on-path attacker who offers an
                // algorithm we haven't recorded yet would land here too, and
                // is exactly as dangerous as a same-algorithm mismatch). We
                // must tell those apart ourselves before trusting anything.
                let existing =
                    known_host_keys_path(&self.host, self.port, known_hosts).map_err(|e| {
                        TunnelError::HostKey(format!("cannot read {}: {e}", known_hosts.display()))
                    })?;

                // `known_host_keys_path` swallows *every* `File::open` error
                // (not just "missing") into `Ok(vec![])`
                // (russh-0.62.4 src/keys/known_hosts.rs:70-74), so an empty
                // `existing` is ambiguous: it means "no entry for this host"
                // whether the file doesn't exist yet, exists and is readable
                // but has nothing for this host, or exists and can't be read
                // at all (EACCES, EIO, a dangling symlink...). Only the last
                // of those is unsafe to treat as first contact — and telling
                // it apart from the first two means actually attempting to
                // open the file ourselves, not just checking whether the
                // path exists: a multi-profile app routinely has a
                // `known_hosts` that already exists (with entries for other
                // hosts) by the time it TOFUs a brand-new host, and that must
                // keep working.
                let unreadable_known_hosts = match std::fs::File::open(known_hosts) {
                    // Opened fine (and immediately dropped — we're only
                    // probing readability, not parsing): an empty `existing`
                    // is trustworthy.
                    Ok(_) => None,
                    // Doesn't exist yet: also trustworthy — genuine first
                    // contact, nothing to fail to read.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    // Exists but couldn't be opened for some other reason:
                    // we cannot verify it has no entry for this host.
                    Err(e) => Some(e),
                };

                match check_known_hosts_path(&self.host, self.port, key, known_hosts) {
                    // Known and matching.
                    Ok(true) => Ok(true),
                    // Entries exist for this host, but none uses the
                    // presented key's algorithm. Never auto-accept, never
                    // learn — this is the "attacker offers an algorithm we
                    // haven't recorded yet" case, not a first contact.
                    Ok(false) if !existing.is_empty() => Err(TunnelError::HostKey(format!(
                        "host key for {}:{} uses an algorithm not recorded in {} \
                         ({} entries already recorded for this host); refusing to \
                         trust it automatically",
                        self.host,
                        self.port,
                        known_hosts.display(),
                        existing.len()
                    ))),
                    // No recorded entry for this host, and we can trust that:
                    // genuine first contact. Trust on first use, then record
                    // it — this leaves any other hosts already recorded in
                    // the same file untouched.
                    Ok(false) if unreadable_known_hosts.is_none() => {
                        tracing::warn!(
                            host = %self.host, port = self.port,
                            fingerprint = %key.fingerprint(Default::default()),
                            "unknown host key; trusting on first use and recording it"
                        );
                        learn_known_hosts_path(&self.host, self.port, key, known_hosts).map_err(
                            |e| TunnelError::HostKey(format!("cannot record host key: {e}")),
                        )?;
                        Ok(true)
                    }
                    // The file exists but couldn't be opened for reading, so
                    // an empty entry list here cannot be trusted as "no entry
                    // for this host." Fail closed rather than risk treating
                    // an unreadable file as first contact.
                    Ok(false) => Err(TunnelError::HostKey(format!(
                        "cannot verify {} has no entry for {}:{}: {}; refusing to \
                         treat this as first contact",
                        known_hosts.display(),
                        self.host,
                        self.port,
                        unreadable_known_hosts.expect("guarded by is_none() above"),
                    ))),
                    // Known, but a same-algorithm key differs — the classic
                    // MITM case. Never auto-accept.
                    Err(russh::keys::Error::KeyChanged { line }) => {
                        Err(TunnelError::HostKey(format!(
                            "host key for {}:{} does not match the key recorded at {}:{line}",
                            self.host,
                            self.port,
                            known_hosts.display()
                        )))
                    }
                    // Anything else (e.g. the file is unreadable, or a
                    // recorded line is corrupt) fails closed too, but is not
                    // reported as a confirmed key change — it might just be a
                    // damaged file, not an attack.
                    Err(e) => Err(TunnelError::HostKey(format!(
                        "cannot verify host key for {}:{} against {}: {e}",
                        self.host,
                        self.port,
                        known_hosts.display()
                    ))),
                }
            }
        }
    }
}

#[async_trait]
impl Protocol for SshTunnel {
    async fn connect(
        &mut self,
        profile: &ServerProfile,
        store: &dyn SecretStore,
    ) -> Result<(), TunnelError> {
        // Spec §9.3: the other kinds parse but cannot run in this build.
        match profile.protocol {
            ProtocolKind::Ssh => {}
            ProtocolKind::WireGuard => return Err(TunnelError::Unsupported("wireguard")),
            ProtocolKind::Shadowsocks => return Err(TunnelError::Unsupported("shadowsocks")),
        }

        self.state = ConnectionState::Connecting;

        // Every error exit from here on must leave `state == Failed`, never
        // stuck at `Connecting` — a caller polling `stats()` needs a state
        // that eventually settles. Centralised here rather than repeated at
        // each fallible step below.
        match self.connect_inner(profile, store).await {
            Ok(handle) => {
                self.handle = Some(handle);
                self.state = ConnectionState::Connected;
                tracing::info!(host = %profile.host, port = profile.port, "ssh session established");
                Ok(())
            }
            Err(e) => {
                // No reconnect caller exists yet in Phase 0, but a failed
                // `connect` on an already-`Connected` tunnel must not leave a
                // stale, still-authenticated session (with keepalives still
                // running) behind a `Failed` state.
                self.handle = None;
                self.state = ConnectionState::Failed;
                Err(e)
            }
        }
    }

    async fn open_tcp_stream(
        &self,
        dest: SocketAddr,
    ) -> Result<Box<dyn TunnelStream>, TunnelError> {
        self.open_tcp_stream_named(&dest.ip().to_string(), dest.port(), dest)
            .await
    }

    async fn send_udp(&self, _dest: SocketAddr, _data: &[u8]) -> Result<(), TunnelError> {
        // Spec §8 / PRD §11: SSH has no UDP forwarding. DNS is handled by the
        // resolver over a TCP channel instead.
        Err(TunnelError::Unsupported("UDP over SSH"))
    }

    async fn disconnect(&mut self) -> Result<(), TunnelError> {
        // The handle is taken either way, so the session cannot be reused
        // even if the disconnect message itself fails to send — the state
        // must reflect that regardless of the result we return.
        let result = if let Some(h) = self.handle.take() {
            h.disconnect(russh::Disconnect::ByApplication, "", "en")
                .await
                .map_err(|e| TunnelError::Protocol(e.to_string()))
        } else {
            Ok(())
        };
        self.state = ConnectionState::Disconnected;
        result
    }

    fn stats(&self) -> ConnectionStats {
        ConnectionStats {
            state: self.state,
            bytes_up: self.counters.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.counters.bytes_down.load(Ordering::Relaxed),
            // `ConnectionStats::active_flows` is a `u32` (Task 1's shape);
            // `MAX_CONCURRENT_CHANNELS` bounds the real value far below
            // `u32::MAX`, so this only ever saturates in a bug, never in
            // normal operation.
            active_flows: u32::try_from(self.counters.active_flows.load(Ordering::Relaxed))
                .unwrap_or(u32::MAX),
            flows_failed: self.counters.flows_failed.load(Ordering::Relaxed),
            ..Default::default()
        }
    }
}

impl SshTunnel {
    /// `direct-tcpip` takes a *host string*, so a destination reached by name
    /// (a DoH endpoint, or a compose alias in tests) can be requested directly
    /// without resolving it locally. `origin` is reported to the server as the
    /// originator and is otherwise unused.
    pub async fn open_tcp_stream_named(
        &self,
        host: &str,
        port: u16,
        origin: SocketAddr,
    ) -> Result<Box<dyn TunnelStream>, TunnelError> {
        let handle = self
            .handle
            .as_ref()
            .ok_or_else(|| TunnelError::Protocol("ssh session is not connected".into()))?;

        // Bound concurrent channels so a burst of flows cannot exhaust the
        // server's channel limit. Spec §8.
        let permit = self
            .channel_limit
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| TunnelError::Protocol("channel limiter closed".into()))?;

        let channel = handle
            .channel_open_direct_tcpip(
                host.to_string(),
                u32::from(port),
                origin.ip().to_string(),
                u32::from(origin.port()),
            )
            .await
            .inspect_err(|_| {
                self.counters.flows_failed.fetch_add(1, Ordering::Relaxed);
            })
            .map_err(|e| {
                TunnelError::Protocol(format!("cannot open channel to {host}:{port}: {e}"))
            })?;

        let stream = crate::protocols::counting::CountingStream::new(
            channel.into_stream(),
            self.counters.bytes_up.clone(),
            self.counters.bytes_down.clone(),
            self.counters.active_flows.clone(),
            Some(permit),
        );

        Ok(Box::new(stream))
    }
}

impl SshTunnel {
    /// The fallible body of `connect`, factored out so every error exit —
    /// secret resolution, transport, auth, key decode, unsupported methods —
    /// funnels through one `Failed`-state transition in the caller instead of
    /// each call site having to remember to set it.
    async fn connect_inner(
        &self,
        profile: &ServerProfile,
        store: &dyn SecretStore,
    ) -> Result<client::Handle<ClientHandler>, TunnelError> {
        let config = Arc::new(client::Config {
            // Detects a dead session directly rather than via a stalled flow. Spec §8.
            keepalive_interval: Some(std::time::Duration::from_secs(15)),
            keepalive_max: 3,
            ..Default::default()
        });

        let handler = ClientHandler {
            host: profile.host.clone(),
            port: profile.port,
            policy: self.policy.clone(),
        };

        let mut handle =
            client::connect(config, (profile.host.as_str(), profile.port), handler).await?;

        let result = match &profile.auth {
            AuthMethod::Password { password } => {
                let pw = store.resolve(password)?;
                handle
                    .authenticate_password(&self.user, pw.expose().clone())
                    .await
                    .map_err(|e| TunnelError::Auth(e.to_string()))?
            }
            AuthMethod::PrivateKey {
                private_key,
                passphrase,
            } => {
                let pem = store.resolve(private_key)?;
                let key = match passphrase {
                    Some(p) => {
                        let pass = store.resolve(p)?;
                        russh::keys::decode_secret_key(pem.expose(), Some(pass.expose()))
                    }
                    None => russh::keys::decode_secret_key(pem.expose(), None),
                }
                .map_err(|e| TunnelError::Auth(format!("cannot decode private key: {e}")))?;

                handle
                    .authenticate_publickey(
                        &self.user,
                        russh::keys::PrivateKeyWithHashAlg::new(
                            Arc::new(key),
                            Some(russh::keys::HashAlg::Sha256),
                        ),
                    )
                    .await
                    .map_err(|e| TunnelError::Auth(e.to_string()))?
            }
            AuthMethod::PresharedKey { .. } => {
                return Err(TunnelError::Unsupported("preshared-key authentication"));
            }
        };

        match result {
            AuthResult::Success => {}
            AuthResult::Failure {
                remaining_methods, ..
            } => {
                return Err(TunnelError::Auth(format!(
                    "server rejected credentials; it still offers: {remaining_methods:?}"
                )));
            }
        }

        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    //! Unit-level coverage for `check_server_key` — no Docker, no socket, no
    //! subprocess, runs in every default `cargo test`. `ssh_integration.rs`
    //! covers the same policy end-to-end against a real server, but that
    //! suite is `#[ignore]`d and easy to skip; this suite is the one that
    //! always runs.
    //!
    //! `check_server_key` only ever needs `PublicKey` values, and public keys
    //! are not secret, so these use real, valid, checked-in key blobs rather
    //! than shelling out to `ssh-keygen` at test time: a subprocess made the
    //! *default* `cargo test` depend on openssh-client being on `PATH` (it
    //! previously wasn't — only the `#[ignore]`d suite needed external
    //! tooling), and `Command::status()` inherits stdout/stderr, so every
    //! default run interleaved "Generating public/private key pair" banners
    //! and ASCII randomart into otherwise-pristine test output.
    use russh::client::Handler as _;

    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("lios-ssh-unit-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A real, valid ed25519 public key. Source: russh 0.62.4's own
    /// `src/keys/mod.rs` `test_fingerprint` fixture — already proven valid by
    /// that crate's own test suite.
    const ED25519_KEY_A: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAILagOJFgwaMNhBWQINinKOXmqS4Gh5NgxgriXwdOoINJ";
    /// A second, distinct real ed25519 public key. Source: russh 0.62.4's
    /// `src/keys/mod.rs` module-level doc example.
    const ED25519_KEY_B: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";
    /// A real ECDSA (NIST P-256) public key — a different algorithm from the
    /// two above. Source: russh 0.62.4's `src/keys/mod.rs`
    /// `test_parse_p256_public_key` fixture.
    const ECDSA_P256_KEY: &str = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMxBTpMIGvo7CnordO7wP0QQRqpBwUjOLl4eMhfucfE1sjTYyK5wmTl1UqoSDS1PtRVTBdl+0+9pquFb46U7fwg=";

    fn key(base64: &str) -> PublicKey {
        russh::keys::parse_public_key_base64(base64).unwrap()
    }

    fn handler(host: &str, port: u16, known_hosts: PathBuf) -> ClientHandler {
        ClientHandler {
            host: host.to_string(),
            port,
            policy: HostKeyPolicy::Verify { known_hosts },
        }
    }

    #[tokio::test]
    async fn an_unknown_host_is_trusted_on_first_use_and_recorded() {
        let dir = scratch("unknown");
        let known = dir.join("known_hosts");
        let k = key(ED25519_KEY_A);

        let mut h = handler("example.test", 2222, known.clone());
        let accepted = h.check_server_key(&k).await.unwrap();
        assert!(accepted);

        let recorded = std::fs::read_to_string(&known).unwrap();
        assert!(
            recorded.contains("2222"),
            "port must be recorded: {recorded}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_learned_key_is_re_validated_and_accepted_on_a_second_call() {
        let dir = scratch("relearn");
        let known = dir.join("known_hosts");
        let k = key(ED25519_KEY_A);

        let mut h = handler("example.test", 2222, known);
        assert!(
            h.check_server_key(&k).await.unwrap(),
            "first call should learn it"
        );
        assert!(
            h.check_server_key(&k).await.unwrap(),
            "second call should hit the known-and-matching path, not re-learn"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_recorded_key_that_still_matches_is_accepted() {
        let dir = scratch("matching");
        let known = dir.join("known_hosts");
        let k = key(ED25519_KEY_A);
        learn_known_hosts_path("example.test", 2222, &k, &known).unwrap();

        let mut h = handler("example.test", 2222, known);
        assert!(h.check_server_key(&k).await.unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_same_algorithm_key_change_is_rejected_and_never_learned() {
        let dir = scratch("keychanged");
        let known = dir.join("known_hosts");
        let original = key(ED25519_KEY_A);
        let attacker = key(ED25519_KEY_B);
        learn_known_hosts_path("example.test", 2222, &original, &known).unwrap();
        let before = std::fs::read_to_string(&known).unwrap();

        let mut h = handler("example.test", 2222, known.clone());
        let err = h.check_server_key(&attacker).await.unwrap_err();
        assert!(matches!(err, TunnelError::HostKey(_)), "got {err:?}");

        let after = std::fs::read_to_string(&known).unwrap();
        assert_eq!(
            before, after,
            "a rejected key must never be written to known_hosts"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The Critical-1 regression test: a host with a recorded key of one
    /// algorithm must reject a *different* algorithm's key too, not treat it
    /// as an unknown host. `check_known_hosts_path` returns `Ok(false)` for
    /// this case exactly as it does for a genuinely new host — telling those
    /// two apart is the whole fix.
    #[tokio::test]
    async fn a_different_algorithm_key_for_a_known_host_is_rejected_and_never_learned() {
        let dir = scratch("diffalgo");
        let known = dir.join("known_hosts");
        let recorded = key(ED25519_KEY_A);
        let attacker = key(ECDSA_P256_KEY);
        learn_known_hosts_path("example.test", 2222, &recorded, &known).unwrap();
        let before = std::fs::read_to_string(&known).unwrap();

        let mut h = handler("example.test", 2222, known.clone());
        let err = h.check_server_key(&attacker).await.unwrap_err();
        assert!(
            matches!(err, TunnelError::HostKey(_)),
            "a host with a recorded ed25519 key must reject an unrecorded ecdsa key, got {err:?}"
        );

        let after = std::fs::read_to_string(&known).unwrap();
        assert_eq!(
            before, after,
            "a rejected different-algorithm key must never be learned"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The multi-profile regression test: this app's whole premise is saved
    /// profiles for multiple servers, so a `known_hosts` that already has a
    /// real, readable entry for host A must not block TOFU for a brand-new
    /// host B — that would make trust-on-first-use work for exactly one host
    /// ever. Asserting A's entry survives byte-identically is what
    /// distinguishes "learned B correctly" from "rewrote the file."
    #[tokio::test]
    async fn a_known_hosts_file_with_an_entry_for_another_host_still_tofus_a_new_host() {
        let dir = scratch("multi-host");
        let known = dir.join("known_hosts");
        let host_a_key = key(ED25519_KEY_A);
        learn_known_hosts_path("host-a.test", 22, &host_a_key, &known).unwrap();
        let before = std::fs::read_to_string(&known).unwrap();

        let host_b_key = key(ED25519_KEY_B);
        let mut h = handler("host-b.test", 2222, known.clone());
        let accepted = h.check_server_key(&host_b_key).await.unwrap();
        assert!(
            accepted,
            "a new host in an established file must still TOFU"
        );

        let after = std::fs::read_to_string(&known).unwrap();
        assert!(
            after.starts_with(&before),
            "host A's entry must survive byte-identically, not just be present: \
             before={before:?} after={after:?}"
        );
        assert!(
            after.contains("2222"),
            "host B's entry must have been appended: {after}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Minor-2 regression: `known_host_keys_path` swallows *every*
    /// `File::open` failure into `Ok(vec![])`, not just "file missing," so a
    /// `known_hosts` that exists but genuinely cannot be opened for reading
    /// must not be treated as first contact.
    ///
    /// Made unopenable with a self-referential symlink (`ELOOP`) rather than
    /// a permission bit (e.g. chmod 000): root — and some sandboxes — simply
    /// ignore permission bits, which would make this test's outcome depend on
    /// which user runs it. A filesystem-loop error is a structural condition,
    /// not a permission check, so it fails to open the same way regardless of
    /// privilege level.
    #[tokio::test]
    async fn an_unreadable_known_hosts_file_is_never_treated_as_first_contact() {
        let dir = scratch("unreadable");
        let known = dir.join("known_hosts");
        std::os::unix::fs::symlink("known_hosts", &known).unwrap();

        let mut h = handler("example.test", 2222, known.clone());
        let err = h.check_server_key(&key(ED25519_KEY_A)).await.unwrap_err();
        assert!(matches!(err, TunnelError::HostKey(_)), "got {err:?}");
        // `learn_known_hosts_path` also opens with `.read(true)`, so it would
        // incidentally fail on this same broken symlink even without the
        // readability check — asserting on the message (not just the error
        // variant) proves the *check* rejected it, not a downstream write
        // failure it happened to share a root cause with.
        assert!(
            err.to_string()
                .contains("refusing to treat this as first contact"),
            "expected the readability check's own message, got: {err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn accept_any_still_accepts_a_never_before_seen_key() {
        let mut h = ClientHandler {
            host: "example.test".into(),
            port: 22,
            policy: HostKeyPolicy::AcceptAny,
        };
        assert!(h.check_server_key(&key(ED25519_KEY_B)).await.unwrap());
    }
}

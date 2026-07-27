use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

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

pub struct SshTunnel {
    user: String,
    policy: HostKeyPolicy,
    handle: Option<client::Handle<ClientHandler>>,
    state: ConnectionState,
    counters: Arc<Counters>,
}

#[derive(Default)]
struct Counters {
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    active_flows: AtomicU32,
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
                let known_hosts_exists = known_hosts.try_exists().map_err(|e| {
                    TunnelError::HostKey(format!(
                        "cannot check whether {} exists: {e}",
                        known_hosts.display()
                    ))
                })?;
                let existing =
                    known_host_keys_path(&self.host, self.port, known_hosts).map_err(|e| {
                        TunnelError::HostKey(format!("cannot read {}: {e}", known_hosts.display()))
                    })?;

                match check_known_hosts_path(&self.host, self.port, key, known_hosts) {
                    // Known and matching.
                    Ok(true) => Ok(true),
                    // No recorded entry whatsoever for this host, and the
                    // file itself doesn't even exist yet: genuine first
                    // contact. Trust on first use, then record it.
                    Ok(false) if !known_hosts_exists && existing.is_empty() => {
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
                    // The file exists, but we found no usable entry for this
                    // host in it. `known_host_keys_path` swallows *every*
                    // `File::open` failure (not just "missing") into
                    // `Ok(vec![])` (russh-0.62.4 src/keys/known_hosts.rs:70-74),
                    // so an existing-but-unreadable file (e.g. mode 0222)
                    // would otherwise look identical to "no entry for this
                    // host." We cannot tell those apart from here, so a file
                    // that exists and comes back empty fails closed instead
                    // of risking being treated as first contact.
                    Ok(false) if existing.is_empty() => Err(TunnelError::HostKey(format!(
                        "{} exists but no host key for {}:{} could be read from it; \
                         refusing to treat this as first contact",
                        known_hosts.display(),
                        self.host,
                        self.port
                    ))),
                    // Entries exist for this host, but none uses the
                    // presented key's algorithm. Never auto-accept, never
                    // learn — this is the "attacker offers an algorithm we
                    // haven't recorded yet" case, not a first contact.
                    Ok(false) => Err(TunnelError::HostKey(format!(
                        "host key for {}:{} uses an algorithm not recorded in {} \
                         ({} entries already recorded for this host); refusing to \
                         trust it automatically",
                        self.host,
                        self.port,
                        known_hosts.display(),
                        existing.len()
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
        _dest: SocketAddr,
    ) -> Result<Box<dyn TunnelStream>, TunnelError> {
        Err(TunnelError::Unsupported(
            "open_tcp_stream (arrives in Task 7)",
        ))
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
            active_flows: self.counters.active_flows.load(Ordering::Relaxed),
            flows_failed: self.counters.flows_failed.load(Ordering::Relaxed),
            ..Default::default()
        }
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

    /// Minor-2 regression: `known_host_keys_path` swallows *every*
    /// `File::open` failure into `Ok(vec![])`, not just "file missing," so an
    /// existing file that happens to have no entry for this host must not be
    /// silently treated as first contact.
    #[tokio::test]
    async fn an_existing_known_hosts_file_with_no_entry_for_the_host_is_never_first_contact() {
        let dir = scratch("existing-no-entry");
        let known = dir.join("known_hosts");
        std::fs::write(&known, b"# entries for other hosts would go here\n").unwrap();

        let mut h = handler("example.test", 2222, known.clone());
        let err = h.check_server_key(&key(ED25519_KEY_A)).await.unwrap_err();
        assert!(matches!(err, TunnelError::HostKey(_)), "got {err:?}");

        let after = std::fs::read_to_string(&known).unwrap();
        assert_eq!(
            after, "# entries for other hosts would go here\n",
            "nothing must be learned when the file already existed but couldn't prove absence"
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

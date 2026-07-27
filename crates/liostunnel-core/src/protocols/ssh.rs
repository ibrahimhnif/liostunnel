use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use russh::client::{self, AuthResult};
use russh::keys::known_hosts::{check_known_hosts_path, learn_known_hosts_path};
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
    active_flows: AtomicU64,
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
                    host = %self.host,
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
                match check_known_hosts_path(&self.host, self.port, key, known_hosts) {
                    // Known and matching.
                    Ok(true) => Ok(true),
                    // Unknown host: trust on first use, then record it.
                    Ok(false) => {
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
                    // Known but different — the dangerous case. Never auto-accept.
                    Err(e) => Err(TunnelError::HostKey(format!(
                        "host key for {}:{} does not match {}: {e}",
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

        let mut handle = client::connect(config, (profile.host.as_str(), profile.port), handler)
            .await
            .inspect_err(|_| self.state = ConnectionState::Failed)?;

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
                self.state = ConnectionState::Failed;
                return Err(TunnelError::Auth(format!(
                    "server rejected credentials; it still offers: {remaining_methods:?}"
                )));
            }
        }

        self.handle = Some(handle);
        self.state = ConnectionState::Connected;
        tracing::info!(host = %profile.host, port = profile.port, "ssh session established");
        Ok(())
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
        if let Some(h) = self.handle.take() {
            h.disconnect(russh::Disconnect::ByApplication, "", "en")
                .await
                .map_err(|e| TunnelError::Protocol(e.to_string()))?;
        }
        self.state = ConnectionState::Disconnected;
        Ok(())
    }

    fn stats(&self) -> ConnectionStats {
        ConnectionStats {
            state: self.state,
            bytes_up: self.counters.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.counters.bytes_down.load(Ordering::Relaxed),
            active_flows: self.counters.active_flows.load(Ordering::Relaxed) as u32,
            flows_failed: self.counters.flows_failed.load(Ordering::Relaxed),
            ..Default::default()
        }
    }
}

//! Shadowsocks over TCP. Spec §6.
//!
//! Deliberately thin. `ProxyClientStream` already satisfies `TunnelStream`'s
//! bounds, so a proxied flow is one `connect` call and a `Box` — there is no
//! channel budget, no multiplexing and no host key, because Shadowsocks has
//! none of those. Anything more here would be inventing structure the
//! protocol does not have.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use shadowsocks::ProxyClientStream;
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;

use crate::config::profile::{AuthMethod, ServerProfile};
use crate::config::secret::{SecretRef, SecretStore};
use crate::error::TunnelError;
use crate::protocols::counting::CountingStream;
use crate::protocols::{Protocol, TunnelStream};
use crate::stats::{ConnectionState, ConnectionStats};

/// Ciphers this build offers.
///
/// Stream ciphers are excluded on purpose: they are broken, the crate gates
/// them behind a feature we do not enable, and offering one we would have to
/// warn about is worse than not offering it.
const OFFERED: &[&str] = &[
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

#[derive(Default)]
struct Counters {
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    active: Arc<AtomicU64>,
    failed: AtomicU64,
}

pub struct ShadowsocksTunnel {
    server: Option<ServerConfig>,
    context: Option<Arc<Context>>,
    state: ConnectionState,
    counters: Counters,
}

impl Default for ShadowsocksTunnel {
    fn default() -> Self {
        Self::new()
    }
}

impl ShadowsocksTunnel {
    pub fn new() -> Self {
        Self {
            server: None,
            context: None,
            state: ConnectionState::Disconnected,
            counters: Counters::default(),
        }
    }

    fn cipher(name: &str) -> Result<CipherKind, TunnelError> {
        if !OFFERED.contains(&name) {
            return Err(TunnelError::config(
                "auth.method",
                format!(
                    "`{name}` is not a cipher this build offers; one of: {}",
                    OFFERED.join(", ")
                ),
            ));
        }
        // The crate owns the mapping. We only decide what to offer.
        CipherKind::from_str(name).map_err(|_| {
            TunnelError::config("auth.method", format!("`{name}` is not a known cipher"))
        })
    }
}

#[async_trait]
impl Protocol for ShadowsocksTunnel {
    async fn connect(
        &mut self,
        profile: &ServerProfile,
        store: &dyn SecretStore,
    ) -> Result<(), TunnelError> {
        // Explicit annotation so `SecretRef` is a real reference in
        // non-test code, not just an inferred type -- otherwise the import
        // is unused outside `#[cfg(test)]` (nothing else here spells the
        // name), which `cargo clippy --all-targets -D warnings` catches on
        // the plain `lib` target even though the `lib (test)` target uses it
        // freely via the test module's `use super::*`.
        let (method, password_ref): (&String, &SecretRef) = match &profile.auth {
            AuthMethod::Shadowsocks { method, password } => (method, password),
            _ => {
                return Err(TunnelError::config(
                    "auth",
                    "a shadowsocks profile needs shadowsocks credentials",
                ));
            }
        };

        let cipher = Self::cipher(method)?;
        let password = store.resolve(password_ref)?;

        // `expose` is the only place the password is read, and it goes
        // straight into ServerConfig. It is never formatted, logged or put in
        // an error.
        let cfg = ServerConfig::new(
            (profile.host.clone(), profile.port),
            password.expose().clone(),
            cipher,
        )
        .map_err(|_| {
            TunnelError::config("auth", "the server rejected this cipher/password pair")
        })?;

        self.context = Some(Context::new_shared(ServerType::Local));
        self.server = Some(cfg);
        self.state = ConnectionState::Connected;
        Ok(())
    }

    async fn open_tcp_stream(
        &self,
        dest: SocketAddr,
    ) -> Result<Box<dyn TunnelStream>, TunnelError> {
        let (cfg, ctx) = match (&self.server, &self.context) {
            (Some(c), Some(x)) => (c, x.clone()),
            _ => return Err(TunnelError::Protocol("not connected".into())),
        };
        let stream = ProxyClientStream::connect(ctx, cfg, Address::SocketAddress(dest))
            .await
            .map_err(|e| {
                self.counters.failed.fetch_add(1, Ordering::Relaxed);
                TunnelError::Protocol(format!("cannot open a relayed stream: {e}"))
            })?;
        Ok(Box::new(CountingStream::new(
            stream,
            self.counters.up.clone(),
            self.counters.down.clone(),
            self.counters.active.clone(),
            None,
        )))
    }

    async fn send_udp(&self, _dest: SocketAddr, _data: &[u8]) -> Result<(), TunnelError> {
        // Shadowsocks relays UDP natively; wiring it needs a return path on
        // this trait, which does not exist yet. Spec §2 — its own slice.
        Err(TunnelError::Unsupported("shadowsocks udp"))
    }

    async fn disconnect(&mut self) -> Result<(), TunnelError> {
        self.server = None;
        self.context = None;
        self.state = ConnectionState::Disconnected;
        Ok(())
    }

    fn stats(&self) -> ConnectionStats {
        ConnectionStats {
            state: self.state,
            bytes_up: self.counters.up.load(Ordering::Relaxed),
            bytes_down: self.counters.down.load(Ordering::Relaxed),
            active_flows: u32::try_from(self.counters.active.load(Ordering::Relaxed))
                .unwrap_or(u32::MAX),
            flows_failed: self.counters.failed.load(Ordering::Relaxed),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::secret::{Redacted, SecretStore};

    struct FixedSecret(&'static str);
    impl SecretStore for FixedSecret {
        fn resolve(&self, _r: &SecretRef) -> Result<Redacted<String>, TunnelError> {
            Ok(Redacted::new(self.0.to_string()))
        }
    }

    fn profile(method: &str) -> ServerProfile {
        serde_json::from_str(&format!(
            r#"{{"id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"SS",
                "protocol":"shadowsocks","host":"198.51.100.7","port":8388,
                "auth":{{"type":"shadowsocks","method":"{method}",
                        "password":{{"source":"file","path":"/tmp/k"}}}},
                "dns":["1.1.1.1"],"split_tunnel":{{"type":"all_traffic"}},
                "kill_switch":false}}"#
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn an_unknown_cipher_is_refused_by_name() {
        // Mapping cipher names ourselves would be custom crypto config;
        // CipherKind::from_str is the crate's job. What we own is refusing
        // an unknown one clearly rather than defaulting to something.
        let mut t = ShadowsocksTunnel::new();
        let err = t
            .connect(&profile("rot13"), &FixedSecret("pw"))
            .await
            .expect_err("an unknown cipher must be refused");
        assert!(format!("{err}").contains("rot13"), "name it: {err}");
    }

    #[tokio::test]
    async fn a_stream_cipher_is_refused_even_though_the_name_is_real() {
        // rc4-md5 parses as a CipherKind but the aead-cipher feature does not
        // build it, and it is broken regardless. Refusing by name is clearer
        // than a runtime failure from the crate.
        let mut t = ShadowsocksTunnel::new();
        assert!(
            t.connect(&profile("rc4-md5"), &FixedSecret("pw"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_non_shadowsocks_profile_is_refused() {
        // The factory dispatches on profile.protocol, but nothing stops a
        // profile whose protocol says shadowsocks and whose auth says ssh.
        let mut p = profile("aes-256-gcm");
        p.auth = AuthMethod::Password {
            password: SecretRef::File {
                path: "/tmp/k".into(),
            },
        };
        let mut t = ShadowsocksTunnel::new();
        assert!(t.connect(&p, &FixedSecret("pw")).await.is_err());
    }

    #[tokio::test]
    async fn an_error_never_carries_the_password() {
        let mut t = ShadowsocksTunnel::new();
        let err = t
            .connect(&profile("rot13"), &FixedSecret("hunter2-SECRET"))
            .await
            .unwrap_err();
        assert!(!format!("{err}").contains("hunter2-SECRET"), "{err}");
        assert!(!format!("{err:?}").contains("hunter2-SECRET"));
    }

    #[test]
    fn stats_start_at_zero_and_report_disconnected() {
        let t = ShadowsocksTunnel::new();
        let s = t.stats();
        assert_eq!(s.state, ConnectionState::Disconnected);
        assert_eq!(s.bytes_up, 0);
    }
}

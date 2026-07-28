//! Shadowsocks over TCP. Spec §6.
//!
//! Deliberately thin. `ProxyClientStream` already satisfies `TunnelStream`'s
//! bounds, so a proxied flow is one `connect` call and a `Box` — there is no
//! multiplexing and no host key, because Shadowsocks has none of those.
//! Anything more here would be inventing structure the protocol does not
//! have.
//!
//! It does carry a flow budget, though, and for a blunter reason than SSH's:
//! every Shadowsocks flow is a *fresh socket*, and `engine.rs` spawns one task
//! per flow with no cap of its own, so the semaphores below are the only
//! backpressure between a burst of connections and the process fd limit.

use std::fmt;
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

use crate::config::profile::{AuthMethod, ProtocolKind, ServerProfile};
use crate::config::secret::{Redacted, SecretRef, SecretStore};
use crate::error::TunnelError;
use crate::protocols::counting::CountingStream;
use crate::protocols::{Protocol, TunnelStream};
use crate::stats::{ConnectionState, ConnectionStats};

/// Ciphers this build offers.
///
/// This list is not documentation: it is the advice printed to a user who
/// typed a cipher name wrong, and they will copy an entry from it verbatim.
/// So every entry must be a name this build can actually construct --
/// `every_offered_cipher_is_one_this_build_can_actually_construct` enforces
/// exactly that.
///
/// Stream ciphers are excluded on purpose: they are broken, the crate gates
/// them behind a feature we do not enable, and offering one we would have to
/// warn about is worse than not offering it.
///
/// AEAD-2022 (`2022-blake3-*`) is excluded for a blunter reason: this build
/// cannot build it. Its `CipherKind::from_str` arms are gated on the crypto
/// crate's `v2` feature, reachable only through
/// `shadowsocks/aead-cipher-2022`, which this build does not enable. Offering
/// those three names told a user with a typo to switch to a cipher that then
/// failed with "not a known cipher" -- advice that cannot work is worse than
/// no advice.
const OFFERED: &[&str] = &["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"];

/// Concurrent ordinary proxied flows. The same figure `SshTunnel` uses
/// (`ssh::MAX_CONCURRENT_CHANNELS`), for a different reason: there the cap
/// protects the server's channel limit, here it protects *this process's* file
/// descriptors, because each Shadowsocks flow is its own socket. A burst from
/// the packet engine should queue rather than fail.
///
/// This bounds ordinary flows only, not DNS -- see [`MAX_CONCURRENT_DNS_FLOWS`]
/// and `Protocol::open_dns_stream`'s doc for why DNS gets its own separate,
/// reserved allowance rather than sharing this one.
const MAX_CONCURRENT_FLOWS: usize = 64;

/// A small, separate flow budget reserved for DNS queries so a busy tunnel's
/// worth of ordinary proxied flows (routinely dozens of held-open browser
/// connections, all counted against [`MAX_CONCURRENT_FLOWS`]) cannot starve
/// DNS resolution out of existence. `tokio::sync::Semaphore` is FIFO-fair, so
/// a DNS query queued behind a full general allowance would queue past its own
/// 5s timeout (`over_tcp::DEFAULT_TIMEOUT`) and fail — invisibly, since
/// nothing distinguishes "starved" from "the resolver is down". Mirrors
/// `ssh::MAX_CONCURRENT_DNS_CHANNELS`, and matters here specifically because
/// `open_dns_stream` relays over the same transport as everything else.
const MAX_CONCURRENT_DNS_FLOWS: usize = 8;

#[derive(Default)]
struct Counters {
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    active: Arc<AtomicU64>,
    failed: AtomicU64,
}

pub struct ShadowsocksTunnel {
    /// Wrapped in [`Redacted`] because `ServerConfig` is `#[derive(Debug)]`
    /// over a plaintext `password: String` *and* a cleartext `enc_key:
    /// Box<[u8]>`, and this field is held for the tunnel's whole lifetime. A
    /// bare `ServerConfig` here meant any `Debug` surface that ever reached it
    /// -- a derived `Debug` on this struct, a `tracing::debug!(?self)`, a
    /// panic message -- printed the password and the derived key in the
    /// clear, which is exactly what `Redacted` exists to prevent
    /// (`config/secret.rs`). The wrapper makes every read of it explicit at
    /// the call site (`.expose()`), of which there is one.
    server: Option<Redacted<ServerConfig>>,
    context: Option<Arc<Context>>,
    state: ConnectionState,
    counters: Counters,
    flow_limit: Arc<tokio::sync::Semaphore>,
    dns_flow_limit: Arc<tokio::sync::Semaphore>,
}

/// Hand-written, not derived, on purpose: a `#[derive(Debug)]` here would
/// print `server` in full, and `ServerConfig`'s own derived `Debug` renders
/// the password and the derived key as plaintext. Writing it out by hand also
/// means a later `#[derive(Debug)]` cannot be added silently -- it would
/// conflict with this impl and fail to compile.
impl fmt::Debug for ShadowsocksTunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowsocksTunnel")
            .field("state", &self.state)
            // `Option<Redacted<_>>` renders as `Some(<redacted>)`: the fact
            // that a server is configured is not secret, its contents are.
            .field("server", &self.server)
            .field("context", &self.context.is_some())
            .finish()
    }
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
            flow_limit: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_FLOWS)),
            dns_flow_limit: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_DNS_FLOWS)),
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

    /// The fallible body of [`Protocol::connect`], factored out so that every
    /// error exit -- wrong protocol, wrong credential kind, unknown cipher,
    /// unresolvable secret, key derivation -- funnels through one
    /// `Failed`-state transition in the caller instead of each call site
    /// having to remember to clear the previous session. `SshTunnel` splits
    /// `connect`/`connect_inner` for the same reason.
    ///
    /// Takes no `&self` precisely so it *cannot* leave `self` half-updated on
    /// the way out: the caller assigns the retained state only once, from the
    /// `Ok` arm.
    fn prepare(
        profile: &ServerProfile,
        store: &dyn SecretStore,
    ) -> Result<(Redacted<ServerConfig>, Arc<Context>), TunnelError> {
        // `SshTunnel::connect` has refused a profile of the wrong kind since
        // Phase 0; without the same guard here a profile saying
        // `"protocol": "ssh"` with shadowsocks credentials was accepted and
        // quietly relayed over shadowsocks.
        match profile.protocol {
            ProtocolKind::Shadowsocks => {}
            other => {
                return Err(TunnelError::config(
                    "protocol",
                    format!("a shadowsocks tunnel cannot carry a {other:?} profile"),
                ));
            }
        }

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

        // `expose` is the only place the password is read. The bare `String`
        // it produces is consumed by `ServerConfig::new` on the same
        // expression and the result is wrapped in `Redacted` immediately, so
        // no plaintext copy outlives this function. It is never formatted,
        // logged or put in an error.
        let cfg = ServerConfig::new(
            (profile.host.clone(), profile.port),
            password.expose().clone(),
            cipher,
        )
        // Deliberately discards the underlying error: `ServerConfigError`'s
        // variants quote the offending key material. Nothing has been sent to
        // any server at this point -- this is local key derivation from the
        // configured cipher and password, and nothing else.
        //
        // Unreachable for every cipher in `OFFERED` as this build is
        // configured: key derivation for the AEAD ciphers is
        // `openssl_bytes_to_key`, which is infallible. The only fallible path
        // is AEAD-2022's base64 key decoding, which needs the
        // `aead-cipher-2022` feature this build does not enable. Kept because
        // the crate's signature is fallible and that can change under us.
        .map_err(|_| {
            TunnelError::config(
                "auth",
                "cannot derive an encryption key from this cipher and password",
            )
        })?;

        Ok((Redacted::new(cfg), Context::new_shared(ServerType::Local)))
    }

    /// How long the probe waits. A server that cannot answer a DNS query in
    /// this long is not one worth installing routes for.
    const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

    /// Proves the credentials work, because the protocol will not.
    ///
    /// Shadowsocks has no handshake: a server given the wrong key accepts
    /// the TCP connection and drops it silently. Without this, `connect`
    /// returning `Ok` would mean "a socket opened" -- the UI would report
    /// Connected, routes would be installed, and nothing would carry.
    ///
    /// One DNS query over a relayed stream, using the profile's own
    /// resolver. If bytes come back, the cipher and password are right AND
    /// the server relays traffic.
    ///
    /// Drawn from the reserved DNS flow allowance (`dns_flow_limit`), not
    /// the general one (`open_tcp_stream`/`flow_limit`): this genuinely is a
    /// DNS query, and reconnecting a tunnel that already has a busy
    /// session's worth of ordinary flows holding the general permits would
    /// otherwise queue the probe behind them and risk it timing out for a
    /// reason that has nothing to do with whether the credentials work --
    /// precisely the starvation `MAX_CONCURRENT_DNS_FLOWS` exists to prevent
    /// for ordinary DNS traffic.
    ///
    /// This is not authentication in the SSH sense. It proves the server
    /// relays for these credentials; it does not identify the server.
    /// Shadowsocks offers no server identity at all.
    async fn probe(&self, dns: SocketAddr) -> Result<(), TunnelError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // A minimal A query for "." -- the smallest well-formed thing a
        // resolver will answer. RFC 7766 framing: two-byte length prefix.
        let query: [u8; 17] = [
            0x00, 0x0f, // length
            0xAB, 0xCD, // id
            0x01, 0x00, // standard query, recursion desired
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // root name
            0x00, 0x01, // A
        ];

        let fut = async {
            let mut s = self.open_dns_stream(dns).await?;
            s.write_all(&query).await?;
            let mut len = [0u8; 2];
            s.read_exact(&mut len).await.map_err(|_| {
                TunnelError::Auth(
                    "the server accepted the connection but returned nothing; \
                     the cipher or password is probably wrong"
                        .into(),
                )
            })?;
            Ok::<(), TunnelError>(())
        };

        match tokio::time::timeout(Self::PROBE_TIMEOUT, fut).await {
            Ok(r) => r,
            Err(_) => Err(TunnelError::Auth(
                "the server did not answer a probe query in time".into(),
            )),
        }
    }
}

#[async_trait]
impl Protocol for ShadowsocksTunnel {
    async fn connect(
        &mut self,
        profile: &ServerProfile,
        store: &dyn SecretStore,
    ) -> Result<(), TunnelError> {
        self.state = ConnectionState::Connecting;

        match Self::prepare(profile, store) {
            Ok((server, context)) => {
                self.server = Some(server);
                self.context = Some(context);

                // The profile's first DNS server, asked over the tunnel
                // just built. See `probe`'s doc for why this one round trip
                // is load-bearing: Shadowsocks has no handshake, so without
                // it `Ok` here would mean nothing more than "a socket
                // opened".
                let probed = match profile.dns.servers.first() {
                    Some(dns) => self.probe(SocketAddr::new(*dns, 53)).await,
                    None => Err(TunnelError::config("dns.servers", "must not be empty")),
                };
                if let Err(e) = probed {
                    // Same failure-state contract as the `Err` arm below: a
                    // tunnel whose credentials fail the probe must not be
                    // left `Connected`, or half-built with a server config
                    // that was never actually proven to work, either.
                    self.server = None;
                    self.context = None;
                    self.state = ConnectionState::Failed;
                    return Err(e);
                }

                self.state = ConnectionState::Connected;
                Ok(())
            }
            // The failure-state contract, mirroring `SshTunnel::connect`:
            // every error exit leaves this tunnel with nothing retained and
            // `state == Failed`. Before this, an error simply returned without
            // touching `self`, so reconnecting a live tunnel with a profile
            // whose password file had been deleted left `state == Connected`,
            // the *previous* server's config and password in `self.server`,
            // and every subsequent flow still relaying to a server the profile
            // no longer names -- while `stats()` reported a healthy
            // connection. Note this deliberately also covers the wrong-kind
            // guards, which is stricter than `SshTunnel` (it checks
            // `profile.protocol` before entering `Connecting`): a stale
            // session must not survive a reconnect that is refused for *any*
            // reason.
            Err(e) => {
                self.server = None;
                self.context = None;
                self.state = ConnectionState::Failed;
                Err(e)
            }
        }
    }

    async fn open_tcp_stream(
        &self,
        dest: SocketAddr,
    ) -> Result<Box<dyn TunnelStream>, TunnelError> {
        self.open_flow(dest, &self.flow_limit).await
    }

    /// Drawn from the reserved DNS allowance ([`MAX_CONCURRENT_DNS_FLOWS`])
    /// rather than the general one -- see `Protocol::open_dns_stream`'s doc
    /// for why the two must not share a pool. Overriding matters more here
    /// than it does for SSH: the default implementation delegates to
    /// `open_tcp_stream`, which now takes a general permit, so without this
    /// override DNS would compete with bulk traffic for the same 64.
    async fn open_dns_stream(
        &self,
        dest: SocketAddr,
    ) -> Result<Box<dyn TunnelStream>, TunnelError> {
        self.open_flow(dest, &self.dns_flow_limit).await
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

impl ShadowsocksTunnel {
    /// The shared body of `open_tcp_stream`/`open_dns_stream`: identical in
    /// every respect except *which* semaphore gates it, which is the entire
    /// point -- a bulk proxied flow and a DNS query must never be able to
    /// block each other out of existence by competing for the same permits.
    /// Same split, and the same reasoning, as `SshTunnel::open_channel`.
    async fn open_flow(
        &self,
        dest: SocketAddr,
        limit: &Arc<tokio::sync::Semaphore>,
    ) -> Result<Box<dyn TunnelStream>, TunnelError> {
        let (cfg, ctx) = match (&self.server, &self.context) {
            (Some(c), Some(x)) => (c.expose(), x.clone()),
            _ => return Err(TunnelError::Protocol("not connected".into())),
        };

        // Bound concurrent flows so a burst cannot exhaust this process's file
        // descriptors: each flow below opens a socket of its own, and nothing
        // upstream of here caps them. The permit is held by the returned
        // `CountingStream` and released when the flow is dropped.
        let permit = limit
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| TunnelError::Protocol("flow limiter closed".into()))?;

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
            Some(permit),
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::config::profile::ProtocolKind;
    use crate::config::secret::{Redacted, SecretStore};

    /// A password distinctive enough that finding it anywhere in rendered
    /// output is unambiguous.
    const PW: &str = "hunter2-SECRET";

    struct FixedSecret(&'static str);
    impl SecretStore for FixedSecret {
        fn resolve(&self, _r: &SecretRef) -> Result<Redacted<String>, TunnelError> {
            Ok(Redacted::new(self.0.to_string()))
        }
    }

    fn profile_at(method: &str, host: &str, port: u16) -> ServerProfile {
        serde_json::from_str(&format!(
            r#"{{"id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"SS",
                "protocol":"shadowsocks","host":"{host}","port":{port},
                "auth":{{"type":"shadowsocks","method":"{method}",
                        "password":{{"source":"file","path":"/tmp/k"}}}},
                "dns":["1.1.1.1"],"split_tunnel":{{"type":"all_traffic"}},
                "kill_switch":false}}"#
        ))
        .unwrap()
    }

    fn profile(method: &str) -> ServerProfile {
        profile_at(method, "198.51.100.7", 8388)
    }

    /// Some destination to ask the tunnel for. Which one is irrelevant to
    /// every test here: `ProxyClientStream::connect` dials the *server*
    /// (`profile.host:port`) and only encodes this address in the request
    /// header, so it is the server address a test has to control.
    fn dest() -> SocketAddr {
        "203.0.113.9:443".parse().unwrap()
    }

    /// A loopback port that was bound and immediately released. Connecting to
    /// it is refused instantly, deterministically and without leaving the
    /// machine, which is what a test needs when it must observe a *real*
    /// connect error rather than a black hole.
    async fn a_closed_loopback_port() -> SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        addr
    }

    /// A tunnel already `Connected`, pointed at a server address that refuses
    /// instantly -- built by calling `prepare` directly and assigning state
    /// by hand instead of going through `connect`. `connect`'s probe (Task
    /// 3) dials this same address before reporting success, and a server
    /// that refuses every connection refuses the probe's connection too, so
    /// a real `connect` call against one can never reach `Connected` in the
    /// first place. What the tests using this helper exercise -- the
    /// failure-state contract on reconnect, the no-leak invariants on flow
    /// errors, the flow semaphores -- all sit downstream of `Connected`, not
    /// the probe, so building the state directly is the accurate setup for
    /// them and leaves the resolved password retained, same as before.
    async fn connected_to_a_refusing_server() -> (ShadowsocksTunnel, SocketAddr) {
        let server = a_closed_loopback_port().await;
        let (server_cfg, context) = ShadowsocksTunnel::prepare(
            &profile_at(
                "chacha20-ietf-poly1305",
                &server.ip().to_string(),
                server.port(),
            ),
            &FixedSecret(PW),
        )
        .expect("an offered cipher must prepare");
        let mut t = ShadowsocksTunnel::new();
        t.server = Some(server_cfg);
        t.context = Some(context);
        t.state = ConnectionState::Connected;
        (t, server)
    }

    /// The plaintext the tunnel is holding right now. Tests use this to prove
    /// the secret is genuinely in play *before* asserting it does not appear
    /// anywhere -- an assertion about a string that was never constructed is
    /// exactly the defect finding 3 names.
    fn server_password(t: &ShadowsocksTunnel) -> &str {
        t.server.as_ref().expect("connected").expose().password()
    }

    /// `Box<dyn TunnelStream>` is not `Debug`, so `unwrap_err` is unavailable
    /// on a flow result. Same meaning, and it names what went wrong when a
    /// flow unexpectedly succeeds.
    fn flow_error(r: Result<Box<dyn TunnelStream>, TunnelError>, why: &str) -> TunnelError {
        match r {
            Ok(_) => panic!("this flow was expected to fail: {why}"),
            Err(e) => e,
        }
    }

    /// Finding 1. `OFFERED` is not documentation, it is the advice printed to
    /// a user who typed a cipher name wrong -- they will copy one of these
    /// verbatim. Every entry must therefore be a name this build can actually
    /// construct. Three AEAD-2022 names failed this: their
    /// `CipherKind::from_str` arms are `#[cfg(feature = "v2")]`, reachable
    /// only through `shadowsocks/aead-cipher-2022`, which this build does not
    /// enable and must keep not enabling.
    #[test]
    fn every_offered_cipher_is_one_this_build_can_actually_construct() {
        assert!(!OFFERED.is_empty(), "an empty list would pass vacuously");
        for name in OFFERED {
            assert!(
                CipherKind::from_str(name).is_ok(),
                "`{name}` is offered as advice but this build cannot construct it"
            );
            assert!(
                ShadowsocksTunnel::cipher(name).is_ok(),
                "`{name}` is offered but our own gate rejects it"
            );
        }
    }

    /// Finding 2. The allow-list branch and the crate's own `from_str`
    /// fallback both interpolate the offending name, so asserting only on the
    /// name would still pass with the allow-list deleted outright. The
    /// distinguishing text -- "this build offers", plus the list of what does
    /// work -- is produced by the allow-list branch and nothing else.
    #[tokio::test]
    async fn an_unknown_cipher_is_refused_by_our_allow_list_not_by_the_crate() {
        let mut t = ShadowsocksTunnel::new();
        let err = t
            .connect(&profile("rot13"), &FixedSecret("pw"))
            .await
            .expect_err("an unknown cipher must be refused");
        let msg = format!("{err}");
        assert!(msg.contains("rot13"), "name the offending cipher: {msg}");
        assert!(
            msg.contains("this build offers"),
            "the allow-list, not the crate's fallback, must be what refused it: {msg}"
        );
        assert!(
            msg.contains("chacha20-ietf-poly1305"),
            "and it must suggest something that actually works: {msg}"
        );
    }

    #[tokio::test]
    async fn a_stream_cipher_is_refused_by_name_before_the_crate_sees_it() {
        // rc4-md5 does not parse here at all: `CipherKind::from_str`'s arm for
        // it is `#[cfg(feature = "v1-stream")]`, a feature this build does not
        // enable. Refusing it by name up front is still what we want, because
        // the user gets the list of ciphers that do work instead of a bare
        // "not a known cipher" -- so assert on the allow-list's own message,
        // not merely that something failed.
        assert!(
            CipherKind::from_str("rc4-md5").is_err(),
            "this build must not be able to build a stream cipher either"
        );
        let mut t = ShadowsocksTunnel::new();
        let err = t
            .connect(&profile("rc4-md5"), &FixedSecret("pw"))
            .await
            .expect_err("a stream cipher must be refused");
        assert!(
            format!("{err}").contains("this build offers"),
            "the allow-list must refuse it by name, not the crate: {err}"
        );
    }

    #[tokio::test]
    async fn a_profile_with_non_shadowsocks_credentials_is_refused() {
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

    /// Finding 6. The opposite direction of the test above, and the one that
    /// was missing: `profile.protocol` was never looked at, so a profile
    /// saying `"protocol": "ssh"` with shadowsocks credentials was accepted
    /// and quietly relayed over shadowsocks. `SshTunnel::connect` has refused
    /// the mirror image of this since Phase 0.
    #[tokio::test]
    async fn a_profile_whose_protocol_is_not_shadowsocks_is_refused() {
        let mut p = profile("aes-256-gcm");
        p.protocol = ProtocolKind::Ssh;
        let mut t = ShadowsocksTunnel::new();
        let err = t
            .connect(&p, &FixedSecret("pw"))
            .await
            .expect_err("a shadowsocks tunnel must not carry an ssh profile");
        let msg = format!("{err}");
        assert!(msg.contains("protocol"), "name the offending field: {msg}");
        assert!(msg.contains("Ssh"), "name the offending kind: {msg}");
    }

    /// Finding 5. Every error exit from `connect` used to return without
    /// touching `self`, so a failed reconnect on a live tunnel left
    /// `state == Connected` and the *previous* server's config in place --
    /// every subsequent flow kept relaying to a server the profile no longer
    /// names, while `stats()` reported a healthy connection.
    #[tokio::test]
    async fn a_failed_reconnect_never_keeps_relaying_through_the_previous_server() {
        let (mut t, _server) = connected_to_a_refusing_server().await;
        assert_eq!(t.stats().state, ConnectionState::Connected);
        // The tunnel really is relaying to that server right now: the flow
        // fails at the server's refusal, not at a missing config.
        let live = flow_error(
            t.open_tcp_stream(dest()).await,
            "the server address is a closed port",
        );
        assert!(
            format!("{live}").contains("cannot open a relayed stream"),
            "precondition: the tunnel must be dialling the old server, got: {live}"
        );

        t.connect(&profile("rot13"), &FixedSecret("pw"))
            .await
            .expect_err("a bad cipher must fail the reconnect");

        assert_eq!(
            t.stats().state,
            ConnectionState::Failed,
            "a failed connect must settle on Failed, not report the old session as healthy"
        );
        let err = flow_error(
            t.open_tcp_stream(dest()).await,
            "the tunnel must no longer be connected",
        );
        assert!(
            format!("{err}").contains("not connected"),
            "the previous server's config must be gone, not still relaying: {err}"
        );
    }

    /// Finding 3. The previous version of this test connected with a *bad
    /// cipher*, so `connect` returned at `Self::cipher(method)?` before
    /// `store.resolve` ever ran: it asserted that a string which had never
    /// been constructed did not appear anywhere. These are the paths on which
    /// the plaintext genuinely exists -- inside `connect`, where it is handed
    /// to `ServerConfig::new`, and for the whole life of the tunnel
    /// afterwards, where `open_tcp_stream` builds errors while holding it.
    #[tokio::test]
    async fn an_error_never_carries_the_password() {
        let (t, _server) = connected_to_a_refusing_server().await;
        // The secret really is in play: it reached `ServerConfig::new` and is
        // retained. Without this the rest of the test would again be
        // asserting about a string that was never constructed.
        assert_eq!(
            server_password(&t),
            PW,
            "precondition: the plaintext must actually be retained"
        );

        let err = flow_error(t.open_tcp_stream(dest()).await, "a closed port refuses");
        assert!(!format!("{err}").contains(PW), "Display leaks it: {err}");
        assert!(!format!("{err:?}").contains(PW), "Debug leaks it: {err:?}");
    }

    // There was a second test here using 192.0.2.1 (TEST-NET-1) as the
    // unreachable server. It is gone: TEST-NET-1 black-holes the SYN rather
    // than refusing it on at least this machine, so the test spent 2s
    // reaching its timeout arm and executed no assertions at all -- green,
    // named after a behaviour, proving nothing. That is the exact shape this
    // module's other tests exist to avoid. The refused-loopback test above
    // covers the same leak site with assertions that always run.

    /// Finding 4. The plaintext password and the derived key used to sit in a
    /// `#[derive(Debug)]` type held on the struct for the tunnel's whole
    /// lifetime, so a `tracing::debug!(?self)` or a derived `Debug` on
    /// `ShadowsocksTunnel` would have shipped both to a log.
    #[tokio::test]
    async fn no_debug_surface_of_a_live_tunnel_prints_the_password() {
        let (t, _server) = connected_to_a_refusing_server().await;
        assert_eq!(server_password(&t), PW, "precondition: it is really there");

        // Both surfaces: the retained field itself, and the whole struct --
        // the latter being what a `tracing::debug!(?self)` would print.
        for rendered in [format!("{:?}", t.server), format!("{t:?}")] {
            assert!(
                !rendered.contains(PW),
                "a Debug surface leaks the password: {rendered}"
            );
            assert!(
                !rendered.contains("enc_key"),
                "a Debug surface leaks the derived key material: {rendered}"
            );
        }
        // And the struct's Debug is still worth having.
        assert!(
            format!("{t:?}").contains("Connected"),
            "the state must still be visible: {t:?}"
        );
    }

    /// Finding 7. Each shadowsocks flow is a fresh socket, and `engine.rs`
    /// spawns one task per flow with no cap of its own, so this tunnel's own
    /// semaphore is the only backpressure in the system -- without it a burst
    /// walks straight into the process fd limit. And because
    /// `open_dns_stream` here (correctly) relays over the same transport as
    /// everything else, DNS must draw on a separate, reserved allowance or a
    /// busy tunnel's worth of held-open flows starves resolution out of
    /// existence: `tokio::sync::Semaphore` is FIFO-fair, so a DNS query
    /// queued behind them queues past its own timeout. That is the exact
    /// shape `protocols/mod.rs` documents and `SshTunnel` already implements.
    ///
    /// One test, both halves: with no bound at all the general flow would
    /// reach the connect and be refused inside the 250ms window instead of
    /// queueing; with DNS sharing the general pool the DNS flow would queue
    /// behind the hog and never return.
    #[tokio::test]
    async fn a_dns_flow_is_never_starved_by_a_full_general_flow_allowance() {
        let (t, _server) = connected_to_a_refusing_server().await;

        // Every general-purpose permit taken, as a burst of held-open flows
        // would take them.
        let _hog = t
            .flow_limit
            .clone()
            .acquire_many_owned(u32::try_from(MAX_CONCURRENT_FLOWS).unwrap())
            .await
            .unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(250), t.open_tcp_stream(dest()))
                .await
                .is_err(),
            "a general flow must queue for a permit rather than open unbounded"
        );

        let dns = tokio::time::timeout(Duration::from_secs(2), t.open_dns_stream(dest()))
            .await
            .expect("a dns flow must not queue behind the general allowance");
        let err = flow_error(dns, "the server address is a closed port");
        assert!(
            format!("{err}").contains("cannot open a relayed stream"),
            "the dns flow must have reached the connect, not failed some other way: {err}"
        );
    }

    #[test]
    fn stats_start_at_zero_and_report_disconnected() {
        let t = ShadowsocksTunnel::new();
        let s = t.stats();
        assert_eq!(s.state, ConnectionState::Disconnected);
        assert_eq!(s.bytes_up, 0);
    }

    /// A loopback listener that accepts a connection and then answers
    /// nothing, standing in for a Shadowsocks server given the wrong key:
    /// the spec's own behaviour is to accept the TCP connection and
    /// silently discard it, never refusing it outright. Held open with a
    /// long sleep rather than dropped -- dropping would surface as a clean
    /// EOF, not the genuine, silent hang this simulates -- matching
    /// `dns::over_tcp`'s `HostileDnsProtocol::hold_open`. The test that uses
    /// this drops its own runtime long before the sleep fires.
    async fn a_server_that_accepts_and_answers_nothing() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((_sock, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });
        addr
    }

    /// Task 3 (`task-3-brief.md`), Step 1: the failing test this task
    /// exists to fix. Before the probe, `connect` built a `ServerConfig` and
    /// never spoke to anything, so a connection to a server that accepts
    /// and never answers -- exactly what happens when the password is wrong
    /// -- reported `Ok`.
    ///
    /// The brief's own version of this test pointed `host` at 192.0.2.1
    /// (TEST-NET-1, RFC 5737) to get an address nothing can reach. Dropped
    /// in favour of the listener above: TEST-NET-1 is black-holed by some
    /// network stacks and refused outright by others, so a test built on it
    /// would depend on the machine it runs on rather than on the probe --
    /// the exact "reaches a timeout arm and asserts nothing reliable" shape
    /// this module's other tests already avoid (see the removed 192.0.2.1
    /// flow test above). A listener that genuinely accepts and stays silent
    /// is deterministic on every machine and is what the bug looks like.
    #[tokio::test]
    async fn connect_fails_when_the_server_does_not_answer() {
        let server = a_server_that_accepts_and_answers_nothing().await;
        let p = profile_at("aes-256-gcm", &server.ip().to_string(), server.port());
        let mut t = ShadowsocksTunnel::new();
        let err = t
            .connect(&p, &FixedSecret("pw"))
            .await
            .expect_err("a server that never answers is not a connection");
        assert!(
            matches!(err, TunnelError::Auth(_) | TunnelError::Transport(_)),
            "got {err:?}"
        );
        assert_eq!(
            t.stats().state,
            ConnectionState::Failed,
            "a failed probe must not leave the tunnel looking Connected"
        );
    }
}

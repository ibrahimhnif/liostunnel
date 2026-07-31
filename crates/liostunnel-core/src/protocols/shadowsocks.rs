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

use crate::config::profile::{
    AuthMethod, DnsConfig, DnsMode, DohConfig, ProtocolKind, ServerProfile,
};
use crate::config::secret::{Redacted, SecretRef, SecretStore};
use crate::error::TunnelError;
use crate::protocols::counting::CountingStream;
use crate::protocols::{Protocol, TunnelStream, pick_ipv4};
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
/// The connect options every relayed flow is opened with.
///
/// # Why a hook rather than a call site
///
/// On Android the tunnel's own connection to the Shadowsocks server must be
/// excluded from the tunnel's routing, or it is routed into itself. Unlike
/// SSH -- one long-lived socket, protected once -- this crate opens **one
/// socket per flow**, bounded only by [`MAX_CONCURRENT_FLOWS`], and it owns
/// their creation. There is no call site of ours to protect them at.
///
/// `set_vpn_socket_protect` is the crate's answer: it hands us every socket
/// it opens, before connecting. A socket that escapes it does not fail
/// loudly -- it routes into the tunnel and that one flow hangs, which
/// presents as an intermittent stall under load after the happy path has
/// already passed.
///
/// # Everywhere else this is the previous behaviour, exactly
///
/// Off Android this returns `ConnectOpts::default()`, which is what
/// `ProxyClientStream::connect` used implicitly before. Desktop conduct is
/// unchanged by construction rather than by inspection.
fn connect_opts() -> shadowsocks::net::ConnectOpts {
    #[allow(unused_mut)]
    let mut opts = shadowsocks::net::ConnectOpts::default();
    #[cfg(target_os = "android")]
    opts.set_vpn_socket_protect(|fd| crate::platform::android::protect_fd(fd));
    opts
}

const OFFERED: &[&str] = &["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"];

/// The offered cipher names, for callers that must agree with this list
/// rather than keep a copy of it -- the editor's dropdown, and the check the
/// app runs before saving a profile. A second copy is how a UI comes to offer
/// a cipher the core refuses.
pub fn offered_ciphers() -> &'static [&'static str] {
    OFFERED
}

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

/// Where a `DnsMode::Tcp` resolver is contacted (RFC 7766). The DoH port
/// deliberately is not spelled here: it lives on the resolver that uses it
/// (`dns::over_https::HTTPS_PORT`), so the probe and the resolver cannot
/// drift apart.
const DNS_PORT: u16 = 53;

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
    peer: Option<SocketAddr>,
    state: ConnectionState,
    counters: Counters,
    flow_limit: Arc<tokio::sync::Semaphore>,
    dns_flow_limit: Arc<tokio::sync::Semaphore>,
    /// How long [`Self::probe`] waits. Always [`Self::PROBE_TIMEOUT`] in
    /// production; a field rather than using the constant directly so a test
    /// can shrink it (`with_probe_timeout`, `#[cfg(test)]`) and observe the
    /// timeout path on the real clock in milliseconds instead of needing
    /// `#[tokio::test(start_paused = true)]` -- which races a real socket's
    /// I/O against the paused clock's auto-advance and can report a timeout
    /// before the round trip in the reactor ever completes. See
    /// `connect_fails_when_the_server_does_not_answer`'s doc.
    probe_timeout: std::time::Duration,
    /// How long one flow's connect to the server may take.
    /// Always [`Self::FLOW_CONNECT_TIMEOUT`] in production; a field for the
    /// same reason `probe_timeout` is one.
    flow_connect_timeout: std::time::Duration,
    /// How long one flow may wait for a permit before it is refused.
    /// Always [`Self::FLOW_PERMIT_TIMEOUT`] in production.
    flow_permit_timeout: std::time::Duration,
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
            peer: None,
            state: ConnectionState::Disconnected,
            counters: Counters::default(),
            flow_limit: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_FLOWS)),
            dns_flow_limit: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_DNS_FLOWS)),
            probe_timeout: Self::PROBE_TIMEOUT,
            flow_connect_timeout: Self::FLOW_CONNECT_TIMEOUT,
            flow_permit_timeout: Self::FLOW_PERMIT_TIMEOUT,
        }
    }

    /// The concrete address the last successful `connect` resolved and
    /// relayed through. `None` before the first successful connect and after
    /// a failed one, exactly like `SshTunnel::peer_addr`.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// Neither error below quotes `name` (fix wave 1, finding 4). It is
    /// caller-supplied profile content, and this `Display` reaches the
    /// root-owned helper log via `tracing::warn!(error = %e, "connect failed")`
    /// and the wire via `dispatch::connect_failed` — the same rule
    /// `authorize_params` follows when it discards serde's message. The
    /// actionable half is the field name, which `TunnelError::Config` carries,
    /// and the list of ciphers that do work; the string the user typed is
    /// already in front of them, in their own profile.
    fn cipher(name: &str) -> Result<CipherKind, TunnelError> {
        if !OFFERED.contains(&name) {
            return Err(TunnelError::config(
                "auth.method",
                format!(
                    "not a cipher this build offers; use one of: {}",
                    OFFERED.join(", ")
                ),
            ));
        }
        // The crate owns the mapping. We only decide what to offer.
        CipherKind::from_str(name)
            .map_err(|_| TunnelError::config("auth.method", "not a known cipher"))
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
    ///
    /// Async since fix wave 1, finding 1: `profile.host` is resolved here,
    /// exactly once, and the concrete [`SocketAddr`] is what both
    /// `ServerConfig` and [`Self::peer_addr`] are built from. See the
    /// resolution site below for what that buys.
    async fn prepare(
        profile: &ServerProfile,
        store: &dyn SecretStore,
    ) -> Result<(Redacted<ServerConfig>, Arc<Context>, SocketAddr), TunnelError> {
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

        // ONE resolution, here, and a concrete address from here on.
        //
        // `ServerConfig::new((host, port), ..)` goes through
        // `From<(I, u16)> for ServerAddr`, which *always* yields
        // `ServerAddr::DomainName` -- and the crate's own
        // `TcpStream::connect_server_with_opts` sends that variant through
        // `lookup_then_connect!`, one OS-resolver lookup per flow, every
        // flow. Two ways that ends badly in `default` route mode: a multi-A
        // host has flows land on addresses the route layer never pinned (and
        // the engine's attempt to relay those opens another flow, which
        // resolves again, until the flow semaphore is exhausted); and every
        // lookup goes to the profile's resolvers, which `default` mode has
        // just pointed *into the tunnel*, so resolving the server's own name
        // needs a relayed flow that needs the server's name resolved. It
        // works only while the OS DNS cache holds the pre-route answer, and
        // at TTL expiry the machine has no default route of its own left.
        //
        // Resolved after the local config checks above so a typo'd cipher
        // still costs no lookup, and through the shared `pick_ipv4` for the
        // same reason `SshTunnel` does: the route pin this address feeds is
        // IPv4-only. The error deliberately carries the io error alone --
        // interpolating `profile.host` would echo caller-supplied profile
        // content into a root-owned log.
        let addr = pick_ipv4(
            tokio::net::lookup_host((profile.host.as_str(), profile.port))
                .await
                .map_err(TunnelError::Transport)?,
        )?;

        // `expose` is the only place the password is read. The bare `String`
        // it produces is consumed by `ServerConfig::new` on the same
        // expression and the result is wrapped in `Redacted` immediately, so
        // no plaintext copy outlives this function. It is never formatted,
        // logged or put in an error.
        //
        // `addr` is a `SocketAddr`, so `From<SocketAddr> for ServerAddr`
        // gives `ServerAddr::SocketAddr` and the crate connects to it
        // directly, without a lookup, for the life of the tunnel.
        let cfg = ServerConfig::new(addr, password.expose().clone(), cipher)
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

        Ok((
            Redacted::new(cfg),
            Context::new_shared(ServerType::Local),
            addr,
        ))
    }

    /// How long the probe waits, in production. A server that cannot answer
    /// a DNS query in this long is not one worth installing routes for.
    /// `self.probe_timeout` is what `probe` actually reads; this is only its
    /// default, so tests can shrink it without changing that default -- see
    /// `probe_timeout`'s field doc.
    const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

    /// Test-only seam for `probe_timeout`: shrinks it from the 8s production
    /// default so a test can exercise the timeout path on the real clock, in
    /// milliseconds, without `#[tokio::test(start_paused = true)]` -- which
    /// races a real socket's I/O against the paused clock's own auto-advance
    /// and can report a timeout before the round trip in the reactor ever
    /// completes. `#[cfg(test)]` so it cannot become a second production
    /// timeout that drifts from `PROBE_TIMEOUT`.
    #[cfg(test)]
    fn with_probe_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.probe_timeout = timeout;
        self
    }

    /// How long one flow's connect to the server may take before it is
    /// abandoned.
    ///
    /// Nothing else bounds it. `ProxyClientStream::connect` reads
    /// `ServerConfig::timeout()`, which `ServerConfig::new` leaves `None`
    /// (shadowsocks-1.24.0, `src/config.rs`), and with no timeout the connect
    /// waits the OS SYN retransmission limit -- about 75 seconds on macOS and
    /// 130 on Linux -- while holding a permit out of
    /// [`MAX_CONCURRENT_FLOWS`]. A blocked or dead server is the expected
    /// failure mode for this product, so that is the ordinary case, not an
    /// exotic one.
    ///
    /// Ten seconds is generous for a TCP handshake to a server the profile
    /// already resolved once, and comfortably under `SshTunnel`'s own ~45s
    /// (`keepalive_interval` 15s x `keepalive_max` 3).
    const FLOW_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    /// How long one flow waits for a permit before it is refused.
    ///
    /// Queueing is the point of the semaphores; queueing without end is not.
    /// `acquire_owned()` has no timeout of its own, so a burst that filled the
    /// allowance left every later flow parked forever: `proxy_one` never
    /// returned, the local half of the flow was never reset, and the
    /// application saw a stall rather than an error it could report.
    ///
    /// Longer than [`Self::FLOW_CONNECT_TIMEOUT`] on purpose: a flow queued
    /// behind one that is about to give up must still get its turn rather
    /// than be refused a moment before the permit comes free.
    const FLOW_PERMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

    /// Test-only seam for the two bounds above, for the same reason
    /// `with_probe_timeout` exists: so a test can watch them fire on the real
    /// clock in milliseconds.
    #[cfg(test)]
    fn with_flow_timeouts(
        mut self,
        connect: std::time::Duration,
        permit: std::time::Duration,
    ) -> Self {
        self.flow_connect_timeout = connect;
        self.flow_permit_timeout = permit;
        self
    }

    /// Proves the credentials work, because the protocol will not.
    ///
    /// Shadowsocks has no handshake: a server given the wrong key accepts
    /// the TCP connection and drops it silently. Without this, `connect`
    /// returning `Ok` would mean "a socket opened" -- the UI would report
    /// Connected, routes would be installed, and nothing would carry.
    ///
    /// One round trip over a relayed stream to the profile's own resolver,
    /// spoken the way that resolver is spoken to (`probe_over_dns` /
    /// `probe_over_tls`). If bytes come back, the cipher and password are
    /// right AND the server relays traffic.
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
    ///
    /// Follows `profile.dns.mode`, and must: a DoH profile's resolver is
    /// contacted on 443 (`dns/over_https.rs`) and need not
    /// serve plain DNS on 53 at all, so probing 53 unconditionally stalled a
    /// DoH profile with *correct* credentials for the whole timeout and then
    /// reported an auth failure.
    async fn probe(&self, dns: &DnsConfig) -> Result<(), TunnelError> {
        match tokio::time::timeout(self.probe_timeout, self.probe_once(dns)).await {
            Ok(r) => r,
            Err(_) => Err(Self::probe_timed_out()),
        }
    }

    /// What a probe that ran out of time means.
    ///
    /// Deliberately not `Auth`, and the message names both causes, because
    /// from here they are genuinely indistinguishable.
    ///
    /// The integration suite established which one is actually common: given
    /// a wrong password OR a wrong cipher, a real ss-libev server does not
    /// close the connection -- it accepts the bytes and silently discards
    /// them, which is the behaviour the whole probe exists to work around.
    /// So a bad credential against a real server arrives HERE, as a timeout,
    /// not at `probe_over_dns`'s `read_exact` arm. The loopback fixtures
    /// reach that arm only because they hang up.
    ///
    /// Calling it `Auth` would still be wrong: an exit that cannot reach the
    /// configured resolver produces exactly this too, and telling that user
    /// their password is wrong sends them to change the one thing that was
    /// never at fault. So the message carries both, in the order of
    /// likelihood a real server implies.
    ///
    /// `Config`, and not `Transport`, since fix wave 3, finding 3.
    /// `dispatch::connect_failed` maps every error that is neither `Auth` nor
    /// `Config` to `ErrorKind::Internal`, which the app renders as "The
    /// helper hit an internal error. Check its log." Given what the
    /// integration suite established, that made the single most common user
    /// error in this protocol read as a helper bug. `Config` maps to
    /// `BadRequest` through the arm `dispatch.rs` added this phase for
    /// exactly this reasoning -- a profile the user can fix, not a helper
    /// fault -- and `auth` is the field to look at. Nothing about the shape
    /// of the message changes, and no new `ErrorKind` is needed.
    fn probe_timed_out() -> TunnelError {
        TunnelError::config(
            "auth",
            "nothing came back through the tunnel in time: the cipher or password may be \
             wrong (a Shadowsocks server given either accepts the connection and discards \
             it silently), or the exit cannot reach the resolver this profile names",
        )
    }

    /// Every resolver the profile names, in order, until one answers.
    ///
    /// Iterating rather than taking `servers.first()` since fix wave 3,
    /// finding 4. `TcpResolver::query` (`dns/over_tcp.rs`) and
    /// `DohResolver::query` (`dns/over_https.rs`) both try every entry, so a
    /// probe that tried only the first refused profiles that would resolve
    /// perfectly once connected -- and `import_ss_uri` gives every imported
    /// link a *pair* (`api/config.rs`), precisely because an exit may not be
    /// able to reach one of them.
    ///
    /// The budget is shared out rather than spent per resolver: `probe`'s
    /// ceiling covers the whole loop, so the worst case a user waits is
    /// unchanged. Without a per-resolver share a first entry that swallows
    /// the query consumes everything and the loop is decorative -- exactly
    /// the failure it exists to fix, one step in.
    async fn probe_once(&self, dns: &DnsConfig) -> Result<(), TunnelError> {
        // Guarded by `ServerProfile::validate`, so this is a belt-and-braces
        // arm rather than a reachable one -- but `connect` does not call
        // `validate`, and the alternative here is dividing by zero below.
        let n = u32::try_from(dns.servers.len()).unwrap_or(u32::MAX);
        if n == 0 {
            return Err(TunnelError::config("dns.servers", "must not be empty"));
        }
        let each = self.probe_timeout / n;

        let mut last = None;
        for &server in &dns.servers {
            let attempt = async {
                match dns.mode {
                    DnsMode::Tcp => self.probe_over_dns(SocketAddr::new(server, DNS_PORT)).await,
                    DnsMode::Https => self.probe_over_tls(server, dns.https.as_ref()).await,
                }
            };
            match tokio::time::timeout(each, attempt).await {
                Ok(Ok(())) => return Ok(()),
                // A malformed `dns.https` block or an unparseable SNI is the
                // same for every entry in the list, and knowable without a
                // byte on the wire. Trying the next resolver would spend the
                // budget re-deciding it and then report a timeout instead of
                // the field that is actually wrong.
                Ok(Err(e @ TunnelError::Config { .. })) => return Err(e),
                Ok(Err(e)) => last = Some(e),
                Err(_) => last = Some(Self::probe_timed_out()),
            }
        }
        Err(last.unwrap_or_else(Self::probe_timed_out))
    }

    /// `DnsMode::Tcp`: one RFC 7766-framed query to a resolver's port 53. Two
    /// bytes back is the whole proof -- they arrived through an AEAD tag
    /// check, so a wrong-key server cannot have produced them.
    ///
    /// Called once per entry in `dns.servers` (see `probe_once`), not once
    /// for `servers[0]`.
    async fn probe_over_dns(&self, dns: SocketAddr) -> Result<(), TunnelError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // A minimal A query for "." -- the smallest well-formed thing a
        // resolver will answer. RFC 7766 §8 framing: two-byte length prefix.
        // RFC 1035 §4.1.2: a question is QNAME, QTYPE(2), QCLASS(2), and all
        // three are required. This declared 15 bytes and sent header(12) +
        // root label(1) + QTYPE(2) -- one field short, and unparseable. It
        // looked like it worked only because most resolvers answer FORMERR
        // and two bytes of FORMERR read the same as two bytes of answer; a
        // resolver that drops a malformed message instead answered nothing,
        // and a correct password was reported as an auth failure.
        let query: [u8; 19] = [
            0x00, 0x11, // length: 17 bytes follow
            0xAB, 0xCD, // id
            0x01, 0x00, // standard query, recursion desired
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // root name
            0x00, 0x01, // QTYPE  = A
            0x00, 0x01, // QCLASS = IN
        ];

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
        Ok(())
    }

    /// `DnsMode::Https`: relay to a resolver's port 443 and complete a TLS
    /// handshake against the configured SNI, the same one `DohResolver` will
    /// perform for every real query -- same `tls_config`, same roots, same
    /// port, deliberately shared rather than re-derived here.
    ///
    /// A completed handshake is the same proof a DNS answer is: the
    /// certificate, and every record carrying it, came back *through the
    /// cipher*, which a wrong-key server cannot produce.
    ///
    /// `DohResolver` itself is not reused: it takes an `Arc<dyn Protocol>`,
    /// and this runs inside `connect(&mut self)` where no such handle to
    /// `self` exists or could be made without restructuring ownership around
    /// a probe. The six lines below are the handshake and nothing else.
    #[cfg(feature = "doh")]
    async fn probe_over_tls(
        &self,
        server: std::net::IpAddr,
        doh: Option<&DohConfig>,
    ) -> Result<(), TunnelError> {
        use crate::dns::over_https::{HTTPS_PORT, tls_config};

        // Knowable before a byte is sent: without an SNI there is no
        // handshake to attempt, so this must not cost the probe timeout
        // first. `ServerProfile::validate` refuses it too, but `connect`
        // does not call `validate`.
        let Some(doh) = doh else {
            return Err(TunnelError::config(
                "dns.https",
                "required when dns.mode is `https`",
            ));
        };
        // Fix wave 2, finding 1: `doh.sni` does not appear in this message.
        // `authorize_params` never calls `ServerProfile::validate`, so this
        // is reachable with no network at all -- an unprivileged caller
        // sends a `dns.https.sni` that fails to parse as a server name, and
        // this `Display` reaches the same two sinks `cipher`'s doc names:
        // the root-owned helper log (`tracing::warn!(error = %e, "connect
        // failed")`) and the wire (`dispatch::connect_failed`). Because the
        // helper logs with plain-text `tracing_subscriber::fmt()`, an SNI
        // containing a newline would forge lines in that log. The field
        // name already says which value is wrong; the string itself is
        // already in the caller's own profile.
        let name = rustls::pki_types::ServerName::try_from(doh.sni.clone()).map_err(|e| {
            TunnelError::config("dns.https.sni", format!("is not a valid server name: {e}"))
        })?;

        let stream = self
            .open_dns_stream(SocketAddr::new(server, HTTPS_PORT))
            .await?;
        tokio_rustls::TlsConnector::from(tls_config())
            .connect(name, stream)
            .await
            // A rustls/IO error, never key material: the far end's
            // certificate and alerts are all this can quote.
            //
            // The two failure shapes here mean opposite things about the
            // credentials, and must not collapse into one message. A wrong
            // key fails the AEAD tag check on the relay request itself --
            // before the server has read a plaintext byte -- and the socket
            // drops with nothing rustls ever saw, which surfaces as a bare
            // `ConnectionReset`/`UnexpectedEof` and `e.get_ref()` carrying no
            // `rustls::Error`. Once a byte *has* reached rustls at all, it
            // only exists because the relay decrypted it correctly under
            // this cipher and password -- the credentials are already
            // proven -- so a `rustls::Error` here (a malformed message, or a
            // fatal alert refusing the configured SNI, RFC 8446 §6) is the
            // resolver's own answer, not a verdict on the key. That is
            // exactly the failure `DohResolver::query_one` reports as `Dns`
            // for the identical resolver (`dns/over_https.rs`), so the probe
            // must agree with it rather than misreport the same event as a
            // wrong password.
            .map_err(|e| {
                if e.get_ref()
                    .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                    .is_some()
                {
                    // Fix wave 2, finding 1, the sibling leak: this used to
                    // quote `doh.sni` too. Naming the resolver and the
                    // rustls error is the actionable half; the SNI is
                    // caller-supplied profile content the caller already has.
                    TunnelError::Dns(format!(
                        "TLS handshake with the resolver {server} failed: {e}"
                    ))
                } else {
                    TunnelError::Auth(format!(
                        "the server accepted the connection but no TLS handshake with the \
                         resolver completed through it ({e}); the cipher or password is \
                         probably wrong"
                    ))
                }
            })?;
        Ok(())
    }

    /// Without `doh` there is no rustls in this build to handshake with,
    /// and nothing can resolve for such a profile anyway (`dns::over_https`
    /// is compiled out) -- so say that, rather than probe port 53 for a
    /// resolver that was never asked to serve it.
    #[cfg(not(feature = "doh"))]
    async fn probe_over_tls(
        &self,
        _server: std::net::IpAddr,
        _doh: Option<&DohConfig>,
    ) -> Result<(), TunnelError> {
        Err(TunnelError::Unsupported("dns-over-https"))
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

        match Self::prepare(profile, store).await {
            Ok((server, context, peer)) => {
                self.server = Some(server);
                self.context = Some(context);
                self.peer = Some(peer);

                // The profile's own resolver, asked over the tunnel just
                // built, in whichever way the profile says that resolver is
                // spoken to. See `probe`'s doc for why this one round trip
                // is load-bearing: Shadowsocks has no handshake, so without
                // it `Ok` here would mean nothing more than "a socket
                // opened".
                if let Err(e) = self.probe(&profile.dns).await {
                    // Same failure-state contract as the `Err` arm below: a
                    // tunnel whose credentials fail the probe must not be
                    // left `Connected`, or half-built with a server config
                    // that was never actually proven to work, either. `peer`
                    // goes with them: a route pin aimed at a server this
                    // tunnel never proved it can relay through is worse than
                    // no pin at all.
                    self.server = None;
                    self.context = None;
                    self.peer = None;
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
                self.peer = None;
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
        self.peer = None;
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
        //
        // Bounded in time as well as in count. `acquire_owned()` waits
        // forever, so once the allowance was full every later flow parked
        // here indefinitely: `engine.rs`'s `proxy_one` never returned, the
        // local half of the flow was never reset, and the application saw a
        // stall rather than an error. The caller has to be told.
        let permit =
            match tokio::time::timeout(self.flow_permit_timeout, limit.clone().acquire_owned())
                .await
            {
                Ok(Ok(p)) => p,
                Ok(Err(_)) => return Err(TunnelError::Protocol("flow limiter closed".into())),
                Err(_) => {
                    self.counters.failed.fetch_add(1, Ordering::Relaxed);
                    return Err(TunnelError::Transport(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "no flow budget came free in time; the tunnel is saturated",
                    )));
                }
            };

        // The connect is bounded here rather than through
        // `ServerConfig::set_timeout` -- which `ProxyClientStream::connect_with_opts`
        // would honour -- for one reason: the crate's own timeout error is
        // `format!("connect {} timeout", svr_cfg.addr())`, and `addr` is the
        // address this profile's `host` resolved to. That string reaches the
        // root-owned helper log (`tracing::warn!(error = %e, ...)`) and the
        // wire (`dispatch::connect_failed`), and echoing caller-supplied
        // profile content into either is the rule `cipher` and
        // `probe_over_tls` already follow. Ours names the timeout and
        // nothing else.
        let opts = connect_opts();
        let connect =
            ProxyClientStream::connect_with_opts(ctx, cfg, Address::SocketAddress(dest), &opts);
        let stream = match tokio::time::timeout(self.flow_connect_timeout, connect).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                self.counters.failed.fetch_add(1, Ordering::Relaxed);
                return Err(TunnelError::Protocol(format!(
                    "cannot open a relayed stream: {e}"
                )));
            }
            Err(_) => {
                self.counters.failed.fetch_add(1, Ordering::Relaxed);
                return Err(TunnelError::Transport(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "the server did not accept a connection in time",
                )));
            }
        };
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

    /// The same profile with `dns.mode == https`, so the probe has to look at
    /// the mode rather than assuming port 53. `resolver` is the DoH server's
    /// IP literal -- never a name, per `over_https`'s bootstrap argument.
    ///
    /// Gated on `doh`: every call site is itself `#[cfg(feature = "doh")]`,
    /// and an ungated helper used only from those sites is dead code under
    /// `--no-default-features` -- `cargo test -p liostunnel-core
    /// --no-default-features --no-run` failed on exactly that under this
    /// repo's `-D warnings`.
    #[cfg(feature = "doh")]
    fn doh_profile_at(host: &str, port: u16, resolver: &str) -> ServerProfile {
        serde_json::from_str(&format!(
            r#"{{"id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"SS",
                "protocol":"shadowsocks","host":"{host}","port":{port},
                "auth":{{"type":"shadowsocks","method":"aes-256-gcm",
                        "password":{{"source":"file","path":"/tmp/k"}}}},
                "dns":{{"mode":"https","servers":["{resolver}"],
                        "https":{{"sni":"cloudflare-dns.com","path":"/dns-query"}}}},
                "split_tunnel":{{"type":"all_traffic"}},
                "kill_switch":false}}"#
        ))
        .unwrap()
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

    /// Everything that has to stay alive for [`a_black_hole`] to keep
    /// swallowing SYNs: the listener itself, and the connections that filled
    /// its accept queue. Dropping this makes the address refuse again.
    struct BlackHole {
        _listener: tokio::net::TcpListener,
        _queued: Vec<tokio::task::JoinHandle<std::io::Result<tokio::net::TcpStream>>>,
    }

    /// A loopback address whose TCP connect never completes.
    ///
    /// A listener with a backlog of one that nothing ever accepts from: once
    /// the kernel's accept queue is full it *drops* further SYNs instead of
    /// refusing them, so a connect to it sits in SYN retransmission until the
    /// caller gives up. macOS and Linux both behave this way, and none of it
    /// leaves the loopback interface -- which is the whole point. This module
    /// already deleted one test built on TEST-NET-1 (192.0.2.1) because that
    /// address is black-holed by some network stacks and refused outright by
    /// others, so the test proved a property of the machine rather than of
    /// the code.
    ///
    /// This is what a blocked or dead Shadowsocks server looks like from
    /// here, and it is the expected failure mode for this product: the
    /// server is exactly the thing a censor drops packets to.
    async fn a_black_hole() -> (SocketAddr, BlackHole) {
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = sock.listen(1).unwrap();
        let addr = listener.local_addr().unwrap();

        // Deliberately not awaited: the ones past the queue's capacity never
        // complete, which is the state being built. Holding the handles keeps
        // the ones that *did* complete from being dropped and freeing a slot.
        let queued = (0..16)
            .map(|_| tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await }))
            .collect();
        tokio::time::sleep(Duration::from_millis(200)).await;
        (
            addr,
            BlackHole {
                _listener: listener,
                _queued: queued,
            },
        )
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
        connected_to(a_closed_loopback_port().await).await
    }

    /// The same, pointed at whatever server address the caller has arranged.
    async fn connected_to(server: SocketAddr) -> (ShadowsocksTunnel, SocketAddr) {
        let (server_cfg, context, peer) = ShadowsocksTunnel::prepare(
            &profile_at(
                "chacha20-ietf-poly1305",
                &server.ip().to_string(),
                server.port(),
            ),
            &FixedSecret(PW),
        )
        .await
        .expect("an offered cipher must prepare");
        let mut t = ShadowsocksTunnel::new();
        t.server = Some(server_cfg);
        t.context = Some(context);
        t.peer = Some(peer);
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
    /// fallback both used to interpolate the offending name, so asserting only
    /// on the name would still pass with the allow-list deleted outright. The
    /// distinguishing text -- "this build offers", plus the list of what does
    /// work -- is produced by the allow-list branch and nothing else.
    ///
    /// Fix wave 1, finding 4: the name itself is no longer echoed, and this
    /// asserts that too. `auth.method` is caller-supplied profile content, and
    /// this message reaches the root-owned helper log
    /// (`tracing::warn!(error = %e, "connect failed")`) and the wire
    /// (`dispatch::connect_failed`). Naming the field and listing what does
    /// work is the actionable half; quoting the string back is not.
    #[tokio::test]
    async fn an_unknown_cipher_is_refused_by_our_allow_list_not_by_the_crate() {
        let mut t = ShadowsocksTunnel::new();
        let err = t
            .connect(&profile("rot13"), &FixedSecret("pw"))
            .await
            .expect_err("an unknown cipher must be refused");
        let msg = format!("{err}");
        assert!(
            !msg.contains("rot13"),
            "the message must not echo caller-supplied profile content: {msg}"
        );
        assert!(
            msg.contains("auth.method"),
            "it must still say which field is wrong: {msg}"
        );
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
    async fn a_stream_cipher_is_refused_by_our_allow_list_before_the_crate_sees_it() {
        // rc4-md5 does not parse here at all: `CipherKind::from_str`'s arm for
        // it is `#[cfg(feature = "v1-stream")]`, a feature this build does not
        // enable. Refusing it up front is still what we want, because the user
        // gets the list of ciphers that do work instead of a bare "not a known
        // cipher" -- so assert on the allow-list's own message, not merely
        // that something failed.
        assert!(
            CipherKind::from_str("rc4-md5").is_err(),
            "this build must not be able to build a stream cipher either"
        );
        let mut t = ShadowsocksTunnel::new();
        let err = t
            .connect(&profile("rc4-md5"), &FixedSecret("pw"))
            .await
            .expect_err("a stream cipher must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("this build offers"),
            "the allow-list must refuse it, not the crate: {msg}"
        );
        // Fix wave 1, finding 4, on the other error path a caller can steer.
        assert!(
            !msg.contains("rc4-md5"),
            "the message must not echo caller-supplied profile content: {msg}"
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

    /// Fix wave 3, finding 2. `ProxyClientStream::connect` takes its connect
    /// timeout from `ServerConfig::timeout()`, which `ServerConfig::new`
    /// initialises to `None` and `prepare` never set -- so a flow to a server
    /// whose SYNs are dropped waited the OS retransmission limit (~75s on
    /// macOS, ~130s on Linux) *while holding a flow permit*.
    ///
    /// That is not an exotic failure, it is the expected one: the server is
    /// precisely what a blocking network drops packets to. Sixty-four such
    /// flows take every permit in [`MAX_CONCURRENT_FLOWS`], and since
    /// `acquire_owned` had no bound either, every flow after them -- and,
    /// after eight, every DNS query -- blocked indefinitely. `proxy_one`
    /// never returned, so the local flow was never reset and applications
    /// hung instead of erroring, while `stats()` still said `Connected` and
    /// `flows_failed` never moved. In `default` route mode that is the whole
    /// machine.
    ///
    /// `SshTunnel` has never had this: `keepalive_interval: 15s` with
    /// `keepalive_max: 3` tears its session down in about 45 seconds.
    ///
    /// The outer `timeout` here is what makes the failure a *failure* rather
    /// than a hung test: without the fix this call does not return at all.
    #[tokio::test]
    async fn a_flow_to_a_black_hole_fails_instead_of_hanging_on_to_its_permit() {
        let (server, _hole) = a_black_hole().await;
        let (t, _) = connected_to(server).await;
        let t = t.with_flow_timeouts(Duration::from_millis(300), Duration::from_millis(300));

        let flow = tokio::time::timeout(Duration::from_secs(3), t.open_tcp_stream(dest()))
            .await
            .expect("a flow to a server that never answers must fail, not hang");
        let err = flow_error(flow, "the server address swallows SYNs");
        assert!(
            matches!(err, TunnelError::Transport(e) if e.kind() == std::io::ErrorKind::TimedOut),
            "a connect that ran out of time is a transport timeout"
        );

        // The half that turns one dead flow into a dead machine. A permit
        // held by a connect nobody bounded is a permit no other flow, and
        // after eight no DNS query, can ever have.
        assert_eq!(
            t.flow_limit.available_permits(),
            MAX_CONCURRENT_FLOWS,
            "the permit must go back when the connect is abandoned"
        );
        assert_eq!(
            t.stats().flows_failed,
            1,
            "a flow that timed out is a failed flow; reporting zero is how this \
             stayed invisible"
        );
    }

    /// Fix wave 3, finding 2, the other unbounded wait. Even with a bounded
    /// connect, `acquire_owned()` itself had no timeout: a caller queued
    /// behind a full allowance waited forever, so the engine's per-flow task
    /// never returned and the application's own socket was never reset. The
    /// caller has to be told, so that it can fail the flow and let the
    /// application see an error rather than a stall.
    ///
    /// Distinct from `a_dns_flow_is_never_starved_by_a_full_general_flow_allowance`,
    /// which pins that a flow *does* queue rather than opening unbounded.
    /// Queueing is right; queueing without end is not.
    #[tokio::test]
    async fn a_flow_that_never_gets_a_permit_gives_up_rather_than_waiting_forever() {
        let (t, _server) = connected_to_a_refusing_server().await;
        let t = t.with_flow_timeouts(Duration::from_millis(300), Duration::from_millis(300));

        let _hog = t
            .flow_limit
            .clone()
            .acquire_many_owned(u32::try_from(MAX_CONCURRENT_FLOWS).unwrap())
            .await
            .unwrap();

        let flow = tokio::time::timeout(Duration::from_secs(3), t.open_tcp_stream(dest()))
            .await
            .expect("a flow that cannot get a permit must give up, not wait forever");
        let err = flow_error(flow, "every permit is taken");
        assert!(
            format!("{err}").contains("no flow budget"),
            "the caller must be told the tunnel is saturated: {err}"
        );
        assert_eq!(
            t.stats().flows_failed,
            1,
            "a flow refused for want of budget is a failed flow"
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

    // --- A real Shadowsocks server on loopback ---------------------------
    //
    // Everything above this line can be tested against a bare TCP socket,
    // because everything above this line fails before a byte is decrypted.
    // The probe cannot: the only way to tell "the probe correctly rejects
    // bad credentials" from "the probe rejects everything" is to point it at
    // a server that really does relay for the credentials it was given.
    //
    // `ProxyServerStream::from_stream` is exported unconditionally
    // (`relay/tcprelay/proxy_stream/mod.rs`) and is not gated on
    // `aead-cipher-2022`, so this stands up under the feature set this build
    // pins.

    /// What the loopback server below observed on one connection: the
    /// destination the client asked it to relay to (from the Shadowsocks
    /// request header) and the plaintext bytes that followed.
    struct Probed {
        dest: Address,
        payload: Vec<u8>,
    }

    /// Hand-written so a failing assertion names the destination and prints
    /// the bytes as hex -- a derived `Debug` over `Vec<u8>` renders decimal,
    /// which is unreadable against an RFC's field layout.
    impl fmt::Debug for Probed {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{} bytes to {}: {:02x?}",
                self.payload.len(),
                self.dest,
                self.payload
            )
        }
    }

    /// Everything the peer sent, gathered until it goes quiet, rather than
    /// read to a length the peer itself declared. Reading exactly the framed
    /// length would make any later assertion *about* that framing vacuously
    /// true -- the bug in the probe's query was a length field that agreed
    /// with a body missing a field.
    async fn drain_briefly<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        while let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(150), s.read(&mut buf)).await
        {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        got
    }

    /// The probe's own resolver, in the only role that matters here: decide
    /// whether this is a question it can answer. Returns the question's
    /// QTYPE and QCLASS, or why the message is not a well-formed question.
    ///
    /// A real parser, deliberately: asserting that the probe's literal
    /// equals a copy of the probe's literal proves nothing about whether the
    /// bytes are a DNS message. RFC 1035 §4.1.2 -- a question is QNAME
    /// (length-prefixed labels, terminated by a zero length) followed by
    /// QTYPE(2) and QCLASS(2); RFC 7766 §8 -- over TCP the message is
    /// preceded by its own two-byte length.
    fn parse_dns_question(framed: &[u8]) -> Result<(u16, u16), String> {
        if framed.len() < 2 {
            return Err(format!(
                "{} bytes is not even an RFC 7766 length prefix",
                framed.len()
            ));
        }
        let declared = usize::from(u16::from_be_bytes([framed[0], framed[1]]));
        let msg = &framed[2..];
        if declared != msg.len() {
            return Err(format!(
                "the length prefix declares {declared} bytes but {} follow",
                msg.len()
            ));
        }
        if msg.len() < 12 {
            return Err(format!("{} bytes is short of a 12-byte header", msg.len()));
        }
        let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
        if qdcount != 1 {
            return Err(format!("QDCOUNT is {qdcount}, not 1"));
        }
        // Walk the QNAME's length-prefixed labels to the root label.
        let mut i = 12;
        loop {
            let label = usize::from(
                *msg.get(i)
                    .ok_or_else(|| "the QNAME runs past the end of the message".to_string())?,
            );
            if label >= 64 {
                return Err(format!("`{label}` is not a plain label length"));
            }
            i += 1 + label;
            if label == 0 {
                break;
            }
        }
        let rest = msg.len().saturating_sub(i);
        if rest != 4 {
            return Err(format!(
                "the question carries {rest} bytes after the QNAME; QTYPE(2) + QCLASS(2) is 4"
            ));
        }
        Ok((
            u16::from_be_bytes([msg[i], msg[i + 1]]),
            u16::from_be_bytes([msg[i + 2], msg[i + 3]]),
        ))
    }

    /// A real Shadowsocks server on loopback, keyed with `method`/`password`,
    /// standing in for the profile's exit. It decrypts one connection, reads
    /// the request header, and answers *only* a well-formed DNS question.
    ///
    /// Answering selectively is the point, not decoration: a server that
    /// echoed anything back would let the probe pass with a query no
    /// resolver would answer, which is exactly how the malformed query
    /// (missing QCLASS) survived. Refusing to answer models the resolver
    /// that drops a malformed message rather than returning FORMERR.
    ///
    /// Keyed *differently* from the client, it models the bug this task is
    /// named after: `handshake` below fails in the AEAD tag check without
    /// the server ever reading a plaintext byte, and the socket drops.
    async fn a_shadowsocks_server_keyed_with(
        method: &str,
        password: &str,
    ) -> (SocketAddr, tokio::sync::oneshot::Receiver<Probed>) {
        use shadowsocks::relay::tcprelay::ProxyServerStream;
        use tokio::io::AsyncWriteExt;

        let cipher = CipherKind::from_str(method).expect("the test's own cipher must build");
        // The address is irrelevant to the wire protocol -- only the cipher
        // and password feed key derivation -- but `ServerConfig` wants one.
        let cfg = ServerConfig::new(("127.0.0.1".to_string(), 1), password.to_string(), cipher)
            .expect("the test's own key must derive");
        let key = cfg.key().to_vec();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let ctx = Context::new_shared(ServerType::Server);
            let mut s = ProxyServerStream::from_stream(ctx, sock, cipher, &key);
            // A wrong key dies here, in the tag check over the request
            // header: the server never reads a plaintext byte. Returning
            // drops the socket, which the client sees as EOF -- the
            // silent-discard behaviour the spec describes.
            let Ok(dest) = s.handshake().await else {
                return;
            };
            let payload = drain_briefly(&mut s).await;
            let answerable = parse_dns_question(&payload).is_ok();
            let _ = tx.send(Probed {
                dest,
                payload: payload.clone(),
            });
            if !answerable {
                return;
            }
            // Any bytes back through the cipher prove the relay works,
            // which is all the probe reads for. The answer's own shape is
            // beside the point.
            let _ = s.write_all(&payload).await;
            let _ = s.flush().await;
            // Held open rather than dropped: a drop would surface at the
            // client as an EOF, the *other* outcome the probe distinguishes.
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });
        (addr, rx)
    }

    /// A real Shadowsocks server that relays for these credentials but
    /// answers only when the client asked it to reach `answers_for`.
    /// Anything else it accepts and then holds open in silence -- a resolver
    /// the *exit* cannot reach, which is not the same thing as a wrong
    /// credential and is the case `probe_once` has to survive by moving on to
    /// the next entry in `dns.servers`.
    ///
    /// Serves connections in a loop, not one: the whole point is that the
    /// probe comes back for the second resolver. Returns the destinations it
    /// was asked for, in order, so a test can assert *which* resolvers were
    /// tried rather than only that the connect succeeded.
    async fn a_shadowsocks_server_that_answers_only_for(
        method: &str,
        password: &str,
        answers_for: SocketAddr,
    ) -> (SocketAddr, Arc<std::sync::Mutex<Vec<SocketAddr>>>) {
        use shadowsocks::relay::tcprelay::ProxyServerStream;
        use tokio::io::AsyncWriteExt;

        let cipher = CipherKind::from_str(method).expect("the test's own cipher must build");
        let cfg = ServerConfig::new(("127.0.0.1".to_string(), 1), password.to_string(), cipher)
            .expect("the test's own key must derive");
        let key = cfg.key().to_vec();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let asked: Arc<std::sync::Mutex<Vec<SocketAddr>>> = Arc::default();
        let recorded = asked.clone();

        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let key = key.clone();
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let ctx = Context::new_shared(ServerType::Server);
                    let mut s = ProxyServerStream::from_stream(ctx, sock, cipher, &key);
                    let Ok(dest) = s.handshake().await else {
                        return;
                    };
                    let Address::SocketAddress(dest) = dest else {
                        return;
                    };
                    recorded.lock().unwrap().push(dest);
                    let payload = drain_briefly(&mut s).await;
                    if dest != answers_for {
                        // Accepted, decrypted, and then nothing -- an exit
                        // that cannot reach this resolver. Held open rather
                        // than dropped, because a drop is a clean EOF and
                        // that is the *other* outcome the probe distinguishes.
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        return;
                    }
                    let _ = s.write_all(&payload).await;
                    let _ = s.flush().await;
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                });
            }
        });
        (addr, asked)
    }

    /// Fix wave 3, finding 4. `probe_once` read `dns.servers.first()` and
    /// nothing else, so one resolver the exit cannot reach failed the whole
    /// connect -- while `TcpResolver::query` (`dns/over_tcp.rs`) and
    /// `DohResolver::query` (`dns/over_https.rs`) both iterate every entry, so
    /// a profile that would resolve perfectly at runtime could not be
    /// connected at all.
    ///
    /// Not hypothetical. `import_ss_uri` gives every imported link
    /// `["1.1.1.1", "1.0.0.1"]` (`api/config.rs`), and the editor's own help
    /// text says "Many tunnel providers block outbound port 53" -- an exit
    /// that blocks or blackholes the first of a pair is the case the second
    /// exists for.
    ///
    /// Asserts *which* resolvers were asked, in order, not merely that the
    /// connect succeeded: a probe that skipped straight to the last entry
    /// would satisfy "it connected" while quietly ignoring the user's
    /// preference.
    #[tokio::test]
    async fn the_probe_tries_every_resolver_not_just_the_first() {
        let answering: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let (server, asked) =
            a_shadowsocks_server_that_answers_only_for("aes-256-gcm", PW, answering).await;
        let mut p = profile_at("aes-256-gcm", &server.ip().to_string(), server.port());
        p.dns.servers = vec![
            "203.0.113.1".parse().unwrap(),
            answering.ip(),
            "192.0.2.1".parse().unwrap(),
        ];

        let mut t = ShadowsocksTunnel::new().with_probe_timeout(Duration::from_secs(3));
        t.connect(&p, &FixedSecret(PW))
            .await
            .expect("the second resolver answers, so this profile connects");

        assert_eq!(
            *asked.lock().unwrap(),
            vec!["203.0.113.1:53".parse().unwrap(), answering],
            "every resolver up to the one that answered must have been tried, \
             in the order the profile lists them, and none after it"
        );
    }

    /// Fix wave 3, finding 4, the ceiling. Iterating is only useful if each
    /// resolver actually gets a turn: a first entry that swallows the query
    /// must not consume the whole budget, or the loop is decorative. The
    /// budget is shared out, so the ceiling on `connect` is unchanged.
    #[tokio::test]
    async fn one_silent_resolver_does_not_spend_the_whole_probe_budget() {
        let (server, _asked) = a_shadowsocks_server_that_answers_only_for(
            "aes-256-gcm",
            PW,
            "9.9.9.9:53".parse().unwrap(),
        )
        .await;
        let mut p = profile_at("aes-256-gcm", &server.ip().to_string(), server.port());
        // Two that never answer, then the one that does.
        p.dns.servers = vec![
            "203.0.113.1".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            "9.9.9.9".parse().unwrap(),
        ];

        let mut t = ShadowsocksTunnel::new().with_probe_timeout(Duration::from_secs(3));
        let started = std::time::Instant::now();
        t.connect(&p, &FixedSecret(PW))
            .await
            .expect("the third resolver answers");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the whole loop must fit inside the one ceiling `probe` already \
             enforces, not take it per resolver: {:?}",
            started.elapsed()
        );
    }

    async fn what_the_server_saw(rx: tokio::sync::oneshot::Receiver<Probed>) -> Probed {
        tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .expect("the probe must have opened a relayed stream")
            .expect("the server must have decrypted the request header")
    }

    /// Finding 2. Nothing in the repo asserted that `connect` can return
    /// `Ok` at all: every call site in this module expected an error, and
    /// `ShadowsocksTunnel` is referenced nowhere else in the workspace. A
    /// probe that rejected *everything* -- including one whose query no
    /// resolver would answer -- left the suite entirely green, and the suite
    /// could not tell that from a probe that correctly rejects bad
    /// credentials.
    #[tokio::test]
    async fn connect_succeeds_against_a_server_that_relays_for_these_credentials() {
        let (server, probed) = a_shadowsocks_server_keyed_with("aes-256-gcm", PW).await;
        let p = profile_at("aes-256-gcm", &server.ip().to_string(), server.port());

        let mut t = ShadowsocksTunnel::new();
        t.connect(&p, &FixedSecret(PW))
            .await
            .expect("a server that relays for these credentials is a connection");

        assert_eq!(
            t.stats().state,
            ConnectionState::Connected,
            "a probe the server answered must settle on Connected"
        );
        let seen = what_the_server_saw(probed).await;
        assert_eq!(
            parse_dns_question(&seen.payload).map(|(t, _)| t),
            Ok(1),
            "precondition: the server answered because the question parsed"
        );
    }

    /// Fix wave 1, finding 1. `ServerConfig::new((host, port), ..)` takes
    /// `From<(I, u16)> for ServerAddr`, which *always* yields
    /// `ServerAddr::DomainName` (`shadowsocks-1.24.0/src/config.rs:1174`) --
    /// and the crate's own `TcpStream::connect_server_with_opts`
    /// (`src/net/tcp.rs:49`) sends that variant through `lookup_then_connect!`,
    /// i.e. one OS-resolver lookup *per flow, every flow*.
    ///
    /// Two ways that ends badly, both in `default` route mode: a multi-A host
    /// has flows land on addresses the route layer never pinned, and every
    /// lookup goes to the profile's resolvers, which `default` mode has just
    /// pointed *into the tunnel* -- so resolving the server's own name needs a
    /// relayed flow that needs the server's name resolved. It survives only as
    /// long as the OS DNS cache holds the pre-route answer.
    ///
    /// A *name* is used here, not a literal, because the name is the whole
    /// finding: the address the config ends up holding must be the one
    /// `connect` resolved once, not the string it was given.
    #[tokio::test]
    async fn the_server_config_is_built_from_one_resolved_address_not_a_name() {
        let (server, _probed) = a_shadowsocks_server_keyed_with("aes-256-gcm", PW).await;
        let p = profile_at("aes-256-gcm", "localhost", server.port());

        let mut t = ShadowsocksTunnel::new();
        t.connect(&p, &FixedSecret(PW))
            .await
            .expect("the loopback server relays for these credentials");

        match t.server.as_ref().expect("connected").expose().addr() {
            shadowsocks::config::ServerAddr::SocketAddr(a) => assert_eq!(
                *a, server,
                "the config must hold the address `connect` actually resolved"
            ),
            other => panic!(
                "the crate re-resolves this on every single flow \
                 (net/tcp.rs's lookup_then_connect!): {other:?}"
            ),
        }
    }

    /// Fix wave 1, finding 1. The address the route layer pins must be the
    /// one the session actually reached, and `Protocol` cannot say -- so this
    /// type has to, exactly as `SshTunnel::peer_addr` already does. Without
    /// it the helper had to look the host up a second time, independently,
    /// and a multi-A host lets the two answers disagree.
    #[tokio::test]
    async fn a_connected_tunnel_reports_the_address_it_actually_reached() {
        let (server, _probed) = a_shadowsocks_server_keyed_with("aes-256-gcm", PW).await;
        let p = profile_at("aes-256-gcm", "localhost", server.port());

        let mut t = ShadowsocksTunnel::new();
        assert_eq!(
            t.peer_addr(),
            None,
            "nothing has been reached before connect"
        );
        t.connect(&p, &FixedSecret(PW))
            .await
            .expect("the loopback server relays for these credentials");
        assert_eq!(
            t.peer_addr(),
            Some(server),
            "the reported peer must be the resolved v4 address of `localhost`"
        );
    }

    /// Fix wave 1, finding 1. `pick_ipv4` is not SSH policy, it is the packet
    /// stack's and the route layer's IPv4-only constraint, and resolving here
    /// is what puts a concrete address in front of the crate. A v6-only host
    /// must therefore be refused with that constraint named -- before a
    /// socket, not after a relayed flow fails for some unrelated-looking
    /// reason.
    #[tokio::test]
    async fn an_ipv6_only_host_is_refused_by_the_ipv4_only_constraint() {
        let p = profile_at("aes-256-gcm", "::1", 8388);
        let mut t = ShadowsocksTunnel::new();
        let err = t
            .connect(&p, &FixedSecret(PW))
            .await
            .expect_err("the route pin and packet stack are IPv4-only");
        assert!(
            format!("{err}").contains("IPv4-only"),
            "the IPv4-only constraint must be what refused it: {err}"
        );
        assert_eq!(t.stats().state, ConnectionState::Failed);
        assert!(
            t.peer_addr().is_none(),
            "a failed connect reached nothing, so it must report no peer"
        );
    }

    /// Finding 2, the other half, and the bug this task is named after: a
    /// server keyed differently cannot produce a readable byte -- every
    /// chunk goes through an AEAD tag check -- so `connect` must refuse.
    /// Nothing in the suite exercised a wrong password at all.
    #[tokio::test]
    async fn connect_fails_when_the_password_is_wrong() {
        let (server, _probed) =
            a_shadowsocks_server_keyed_with("aes-256-gcm", "the-servers-actual-password").await;
        let p = profile_at("aes-256-gcm", &server.ip().to_string(), server.port());

        let mut t = ShadowsocksTunnel::new();
        let err = t
            .connect(&p, &FixedSecret(PW))
            .await
            .expect_err("a server that cannot decrypt for us is not a connection");

        assert!(matches!(err, TunnelError::Auth(_)), "got {err:?}");
        assert!(
            !format!("{err:?}").contains(PW),
            "it leaks the password: {err:?}"
        );
        assert_eq!(t.stats().state, ConnectionState::Failed);
        // Finding 4 (re-review). `open_tcp_stream`'s "not connected" also
        // fires when only one of the two fields is cleared -- `open_flow`
        // matches `(Some, Some)` and falls to the same error arm for every
        // other combination -- so the assertion below is the only thing that
        // actually distinguishes "both cleared" from "half-built with a
        // server config the probe just disproved".
        //
        // Fix wave 2, finding 3: `t.peer.is_none()` joins the other two.
        // Nothing here asserted on `peer` before, so the `self.peer = None`
        // line in the probe-failure branch could be deleted outright and
        // this whole suite stayed green -- a route pin aimed at a server
        // this tunnel never proved it can relay through is worse than no
        // pin at all, and that regression was invisible.
        assert!(
            t.server.is_none() && t.context.is_none() && t.peer.is_none(),
            "a probe-refused connect must retain neither field, nor the peer it never proved"
        );
        let flow = flow_error(
            t.open_tcp_stream(dest()).await,
            "the tunnel must not have retained a config the probe disproved",
        );
        assert!(
            format!("{flow}").contains("not connected"),
            "nothing may be retained from a connect the probe refused: {flow}"
        );
    }

    /// Finding 1. The probe's query declared a 15-byte message that was
    /// header(12) + root label(1) + QTYPE(2) -- one field short, because a
    /// question is QNAME + QTYPE + QCLASS. It appeared to work only because
    /// most resolvers answer FORMERR and the probe accepts any two bytes; a
    /// resolver that drops a malformed message instead answers nothing, and
    /// a *correct* password is then reported as an auth failure.
    ///
    /// Decoded from what the probe actually put on the wire, not compared
    /// against a copy of the literal that produced it.
    #[tokio::test]
    async fn the_probe_asks_a_question_a_resolver_can_parse() {
        let (server, probed) = a_shadowsocks_server_keyed_with("aes-256-gcm", PW).await;
        let p = profile_at("aes-256-gcm", &server.ip().to_string(), server.port());

        let mut t = ShadowsocksTunnel::new();
        let _ = t.connect(&p, &FixedSecret(PW)).await;

        let seen = what_the_server_saw(probed).await;
        let (qtype, qclass) = parse_dns_question(&seen.payload).unwrap_or_else(|why| {
            panic!("the probe sent {seen:?}, which is not a question: {why}")
        });
        assert_eq!(qtype, 1, "QTYPE must be A");
        assert_eq!(qclass, 1, "QCLASS must be IN -- the field that was missing");
    }

    /// Finding 3. The probe hardcoded `servers[0]:53` and never looked at
    /// `profile.dns.mode`. In `DnsMode::Https` the resolver is contacted at
    /// `servers[0]:443` (`dns/over_https.rs`) and need not serve plain DNS
    /// on 53 at all -- so a DoH profile with *correct* credentials stalled
    /// for the whole probe timeout and was then reported as an auth failure.
    ///
    /// The proof the probe wants from a DoH resolver is a completed TLS
    /// handshake: bytes came back through the cipher, which is the same
    /// proof a DNS answer gives. Nothing here speaks TLS, so the probe
    /// fails -- what this asserts is *where it went and what it said*.
    #[cfg(feature = "doh")]
    #[tokio::test]
    async fn a_doh_profile_is_probed_at_the_resolvers_https_port_not_53() {
        let (server, probed) = a_shadowsocks_server_keyed_with("aes-256-gcm", PW).await;
        let p = doh_profile_at(&server.ip().to_string(), server.port(), "127.0.0.1");

        let mut t = ShadowsocksTunnel::new();
        let _ = t.connect(&p, &FixedSecret(PW)).await;

        let seen = what_the_server_saw(probed).await;
        let dest = match seen.dest {
            Address::SocketAddress(a) => a,
            ref other => panic!("the probe named a destination by name: {other}"),
        };
        assert_eq!(
            dest.port(),
            443,
            "a DoH resolver is contacted at 443; port 53 need not answer at all"
        );
        assert_eq!(
            seen.payload.first(),
            Some(&0x16),
            "the probe must open a TLS handshake (record type 0x16), not send a DNS query: {seen:?}"
        );
    }

    /// Finding 3's config hole: `dns.mode == https` with no `dns.https`
    /// block. `ServerProfile::validate` refuses that, but `connect` does not
    /// call it, and a probe that cannot know which SNI to use must say so
    /// rather than stall for the whole timeout first.
    #[cfg(feature = "doh")]
    #[tokio::test]
    async fn a_https_profile_with_no_doh_block_is_a_config_error_not_a_stall() {
        let (server, _probed) = a_shadowsocks_server_keyed_with("aes-256-gcm", PW).await;
        let mut p = doh_profile_at(&server.ip().to_string(), server.port(), "127.0.0.1");
        p.dns.https = None;

        let mut t = ShadowsocksTunnel::new();
        let err = tokio::time::timeout(Duration::from_secs(2), t.connect(&p, &FixedSecret(PW)))
            .await
            .expect("a missing DoH block is knowable up front, without waiting out the probe")
            .expect_err("a https profile with no DoH block cannot be probed");

        assert!(matches!(err, TunnelError::Config { .. }), "got {err:?}");
        assert!(
            format!("{err}").contains("dns.https"),
            "name the offending field: {err}"
        );
        assert_eq!(t.stats().state, ConnectionState::Failed);
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
    ///
    /// Finding 6 (original review): `start_paused`. Reverted by finding 2 of
    /// the re-review, below -- kept here only as the historical note that
    /// motivated it, since the replacement doc explains why it had to go.
    ///
    /// Finding 2 (re-review). `#[tokio::test(start_paused = true)]` does not
    /// mix with a real loopback socket: the paused clock auto-advances to
    /// the probe's deadline whenever the runtime finds nothing else runnable,
    /// and a task parked on real I/O -- `read_exact` waiting on the reactor,
    /// here -- looks exactly like that to the scheduler even though the
    /// round trip is still in flight. So the auto-advance can win the race
    /// and report `TimedOut` before the connection the fixture actually
    /// holds open ever gets polled again -- which means the same test
    /// passed identically against a server that answered instantly, because
    /// paused time never gave the real round trip a chance to finish either
    /// way. Confirmed by swapping in `a_shadowsocks_server_keyed_with` (a
    /// server that answers) with `start_paused` still in place: `expect_err`
    /// below still didn't fail (see the report for the transcript).
    ///
    /// Fixed by running on the real clock (no `start_paused`) with a short
    /// timeout injected just for this test (`with_probe_timeout`), rather
    /// than the 8s production default -- so the test is back to costing
    /// milliseconds, but now because the fixture genuinely never answers
    /// within that window, not because a virtual clock raced ahead of it.
    #[tokio::test]
    async fn connect_fails_when_the_server_does_not_answer() {
        let server = a_server_that_accepts_and_answers_nothing().await;
        let p = profile_at("aes-256-gcm", &server.ip().to_string(), server.port());
        let mut t = ShadowsocksTunnel::new().with_probe_timeout(Duration::from_millis(200));
        let err = t
            .connect(&p, &FixedSecret("pw"))
            .await
            .expect_err("a server that never answers is not a connection");
        // Finding 4. A probe that ran out of time says nothing about the
        // password: an exit that cannot reach the configured resolver, or a
        // network that stalls for eight seconds, produces exactly this. The
        // user must not be told their credentials are wrong.
        //
        // Fix wave 3, finding 3. It must not be reported as a *helper* fault
        // either, and `Transport` was. `dispatch::connect_failed` maps every
        // non-`Auth` error except `Config` to `ErrorKind::Internal`, which the
        // app renders as "The helper hit an internal error. Check its log." --
        // and the integration suite established that a real ss-libev server
        // given a wrong password or cipher does not hang up, it accepts and
        // silently discards, so a bad credential arrives HERE. The single most
        // common user error in this protocol read as a helper bug. `Config`
        // maps to `BadRequest`: a profile the user can fix, in their own file,
        // which is what this is.
        assert!(
            matches!(&err, TunnelError::Config { field, .. } if field == "auth"),
            "a probe that ran out of time is the user's profile to fix, not a \
             helper fault, and the field is the credential: got {err:?}"
        );
        assert!(
            !format!("{err}").contains("authentication"),
            "a transport stall must not be reported as an auth failure: {err}"
        );
        assert!(
            format!("{err}").contains("cipher or password"),
            "and it must still name both causes, in the order a real server \
             implies: {err}"
        );
        assert_eq!(
            t.stats().state,
            ConnectionState::Failed,
            "a failed probe must not leave the tunnel looking Connected"
        );
        // Finding 5 (original review), and finding 4 of the re-review: half
        // the contract is `Failed`, the other half is that nothing is
        // retained -- both fields, not just one, mirroring the
        // failed-reconnect test.
        //
        // Fix wave 2, finding 3: `t.peer.is_none()` joins the other two, for
        // the same reason as the sibling assertion in
        // `connect_fails_when_the_password_is_wrong` above.
        assert!(
            t.server.is_none() && t.context.is_none() && t.peer.is_none(),
            "a timed-out probe must retain neither field, nor the peer it never proved"
        );
        let flow = flow_error(
            t.open_tcp_stream(dest()).await,
            "the tunnel must no longer be connected",
        );
        assert!(
            format!("{flow}").contains("not connected"),
            "the config the probe disproved must be gone, not still relaying: {flow}"
        );
    }

    /// A real Shadowsocks server, keyed *correctly*, whose downstream
    /// "resolver" is not a resolver at all: after decrypting the relay
    /// request it writes `reply` back verbatim and holds the connection
    /// open, rather than checking the payload against `parse_dns_question`
    /// (`a_shadowsocks_server_keyed_with`'s job) or performing any TLS of
    /// its own. Bytes only reach `reply`'s sender because the relay
    /// decrypted the client's request correctly -- so whatever the client
    /// makes of `reply` next says nothing about whether the credentials
    /// were right; they already were.
    ///
    /// Gated on `doh`: its only call site is `#[cfg(feature = "doh")]`
    /// (finding 1's test needs real TLS to reach the branch it exercises),
    /// so ungated it is dead code under `--no-default-features` -- the same
    /// shape finding 3 fixed for `doh_profile_at`.
    #[cfg(feature = "doh")]
    async fn a_shadowsocks_server_that_relays_then_answers_with(
        method: &str,
        password: &str,
        reply: &'static [u8],
    ) -> SocketAddr {
        use shadowsocks::relay::tcprelay::ProxyServerStream;
        use tokio::io::AsyncWriteExt;

        let cipher = CipherKind::from_str(method).expect("the test's own cipher must build");
        let cfg = ServerConfig::new(("127.0.0.1".to_string(), 1), password.to_string(), cipher)
            .expect("the test's own key must derive");
        let key = cfg.key().to_vec();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let ctx = Context::new_shared(ServerType::Server);
            let mut s = ProxyServerStream::from_stream(ctx, sock, cipher, &key);
            let Ok(_dest) = s.handshake().await else {
                return;
            };
            let _ = drain_briefly(&mut s).await;
            let _ = s.write_all(reply).await;
            let _ = s.flush().await;
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });
        addr
    }

    /// Finding 1 (re-review). By the time `TlsConnector::connect` sees a
    /// byte, the credentials have already been proven: those bytes only
    /// exist because the relay decrypted the client's request under the
    /// configured cipher and password. A fatal TLS alert (RFC 8446 §6,
    /// `handshake_failure`) is exactly what a real resolver sends when it
    /// refuses the configured SNI -- the same shape `DohResolver` itself
    /// would see from the identical resolver. Reporting that as "the cipher
    /// or password is probably wrong" disagrees with the resolver about
    /// what its own refusal means and sends the user to change the one
    /// thing that was never at fault.
    #[cfg(feature = "doh")]
    #[tokio::test]
    async fn a_tls_failure_after_the_relay_proves_credentials_is_reported_as_dns_not_auth() {
        let alert: &[u8] = &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        let server =
            a_shadowsocks_server_that_relays_then_answers_with("aes-256-gcm", PW, alert).await;
        let p = doh_profile_at(&server.ip().to_string(), server.port(), "127.0.0.1");

        let mut t = ShadowsocksTunnel::new();
        let err = t
            .connect(&p, &FixedSecret(PW))
            .await
            .expect_err("a resolver that refuses the handshake is not a connection");

        assert!(
            matches!(err, TunnelError::Dns(_)),
            "a proven relay's own TLS failure must not be reported as a wrong password: {err:?}"
        );
        let msg = format!("{err}");
        assert!(msg.contains("127.0.0.1"), "name the resolver: {msg}");
        // Fix wave 2, finding 1. This used to assert `msg.contains("cloudflare-dns.com")`
        // -- pinning the leak in place, since `doh.sni` is caller-supplied
        // profile content that reaches the same two sinks `cipher`'s doc
        // names (the root-owned helper log and the wire). Asserting on the
        // rustls failure text instead keeps the test discriminating: it can
        // still fail if the `Dns` arm stops naming what actually went wrong,
        // it just no longer requires the SNI to do it.
        assert!(
            msg.contains("HandshakeFailure"),
            "name the rustls failure that actually occurred: {msg}"
        );
        assert!(
            !msg.contains("cloudflare-dns.com"),
            "dns.https.sni is caller-supplied profile content and must not be echoed: {msg}"
        );
    }

    /// Finding 1 (re-review), the case that must still be `Auth`: a wrong
    /// key fails the AEAD tag check on the relay request itself, before the
    /// server ever reads a plaintext byte -- so no TLS bytes travel at all,
    /// and `TlsConnector::connect` sees a bare connection drop with no
    /// rustls payload behind it. That is the one shape left for "the
    /// cipher or password is probably wrong" to mean.
    #[cfg(feature = "doh")]
    #[tokio::test]
    async fn a_https_probe_still_reports_auth_when_no_tls_bytes_come_back() {
        let (server, _probed) =
            a_shadowsocks_server_keyed_with("aes-256-gcm", "the-servers-actual-password").await;
        let p = doh_profile_at(&server.ip().to_string(), server.port(), "127.0.0.1");

        let mut t = ShadowsocksTunnel::new();
        let err = t
            .connect(&p, &FixedSecret(PW))
            .await
            .expect_err("a server that cannot decrypt for us is not a connection");

        assert!(matches!(err, TunnelError::Auth(_)), "got {err:?}");
    }
}

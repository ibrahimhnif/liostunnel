# LiosTunnel Phase 1b Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Shadowsocks over TCP as a second tunnel protocol, verified against a real server.

**Architecture:** A new `ShadowsocksTunnel` implements the existing `Protocol` trait beside `SshTunnel`. The engine, smoltcp stack, helper socket layer and UI are untouched — `open_tcp_stream` becomes `ProxyClientStream::connect`. The helper gains a factory keyed on `profile.protocol`, which is where anything SSH-shaped in the trait becomes visible.

**Tech Stack:** Rust 2024 / 1.93, `shadowsocks` 1.24 (`--no-default-features --features aead-cipher`), `flutter_rust_bridge` 2.12.0, Docker fixtures.

**Spec:** [`../specs/2026-07-28-liostunnel-phase1b-shadowsocks-design.md`](../specs/2026-07-28-liostunnel-phase1b-shadowsocks-design.md)

## Global Constraints

Every task's requirements implicitly include this section.

- **Rust edition 2024, `rust-version = "1.93"`.**
- **`shadowsocks` is pinned to `1.24` with `default-features = false, features = ["aead-cipher"]`.** Stream ciphers stay off: they are broken, and offering a cipher we would have to warn about is worse than not offering it.
- **No custom crypto** (PRD §2). Cipher selection is `CipherKind::from_str`; we never map names ourselves.
- **No error message, log line, or protocol field may carry secret material.** A Shadowsocks password is key material and an `ss://` URI contains it — a parse error must never echo either.
- **A Shadowsocks password is a `SecretRef`**, so the Phase 1a ownership gate covers it unchanged. Do not add a second rule for a second protocol.
- **TDD, strictly.** Failing test first, confirmed failing for the *expected* reason, then implement. Report RED and GREEN transcripts.
- **A test that passes must be shown failing against the defect it names.** This project has produced at least thirteen tests that were green while the thing they named was broken — one whose fixture could not reach the branch it claimed to test, one that asserted a feature existed while it was absent from the screen. Every A/B is run and its transcript pasted.
- `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, and `flutter analyze` must pass before every commit.
- **Dart changes require `./testing/build-ffi-for-tests.sh` before `flutter test`** — the app links Rust statically, but `flutter test` opens a dylib by path.
- Conventional commit prefixes. **Write commit messages to a file and use `git commit -F`** — backticks inside `-m` are command substitution and will execute. This has happened once in this project and ran a `route delete`.

## Verified API reference

Confirmed by compiling against the crate on 2026-07-28, not from documentation.

```rust
// shadowsocks 1.24, default-features = false, features = ["aead-cipher"]
use shadowsocks::{
    config::{ServerConfig, ServerType},
    context::Context,
    crypto::CipherKind,
    relay::socks5::Address,
    ProxyClientStream,
};

ServerConfig::new((host: String, port: u16), password: String, CipherKind)
    -> Result<ServerConfig, _>
Context::new_shared(ServerType::Local) -> Arc<Context>
ProxyClientStream::connect(ctx, &ServerConfig, Address)
    -> io::Result<ProxyClientStream<shadowsocks::net::TcpStream>>

// Satisfies TunnelStream's bounds exactly:
//   pub trait TunnelStream: AsyncRead + AsyncWrite + Send + Unpin {}
// so `Box::new(stream) as Box<dyn TunnelStream>` compiles with no adapter.

// Cipher names, read from shadowsocks-crypto-0.6.2/src/kind.rs:
//   "aes-128-gcm" "aes-256-gcm" "chacha20-ietf-poly1305"
//   "2022-blake3-aes-128-gcm" "2022-blake3-aes-256-gcm"
//   "2022-blake3-chacha20-poly1305"
// CipherKind implements FromStr and lowercases its input.
```

```rust
// The trait to satisfy (crates/liostunnel-core/src/protocols/mod.rs:20).
// NOTE: open_dns_stream has a DEFAULT that delegates to open_tcp_stream.
// Shadowsocks makes no distinction, so do NOT override it.
async fn connect(&mut self, profile: &ServerProfile, store: &dyn SecretStore) -> Result<(), TunnelError>;
async fn open_tcp_stream(&self, dest: SocketAddr) -> Result<Box<dyn TunnelStream>, TunnelError>;
async fn send_udp(&self, dest: SocketAddr, data: &[u8]) -> Result<(), TunnelError>;
async fn disconnect(&mut self) -> Result<(), TunnelError>;
fn stats(&self) -> ConnectionStats;
```

```
Docker images, both pulled successfully before this plan was written:
  shadowsocks/shadowsocks-libev    AEAD, the C reference implementation
  teddysun/shadowsocks-rust        AEAD-2022
```

## File structure

| File | Responsibility |
|---|---|
| `crates/liostunnel-core/src/config/profile.rs` | `AuthMethod::Shadowsocks` variant + `secret_refs` |
| `crates/liostunnel-core/src/protocols/shadowsocks.rs` | `ShadowsocksTunnel`, the `Protocol` impl |
| `crates/liostunnel-core/src/protocols/ss_uri.rs` | `ss://` parsing, both forms |
| `crates/liostunnel-helper/src/session.rs` | the protocol factory; `HostKeyPolicy` moves into the SSH arm |
| `crates/liostunnel-ffi/src/dto/profile.rs` | `auth_kind: "shadowsocks"`, cipher field |
| `crates/liostunnel-ffi/src/api/config.rs` | `import_ss_uri` |
| `app/lib/screens/profile_editor.dart` | cipher dropdown, `ss://` paste box |
| `testing/docker/docker-compose.yml` | `ss-libev` and `ss-rust` services |
| `crates/liostunnel-core/tests/shadowsocks_integration.rs` | against both live servers |

**Milestones.** A (Tasks 1–4) is the protocol and the factory — the abstraction test. B (5–6) is the config surface. C (7–9) is verification. Only Task 9 needs root.

---

# Milestone A — the protocol

---

### Task 1: The `Shadowsocks` auth variant

**Files:**
- Modify: `crates/liostunnel-core/src/config/profile.rs`

**Interfaces:**
- Produces: `AuthMethod::Shadowsocks { method: String, password: SecretRef }`, covered by `AuthMethod::secret_refs()`.

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module in `profile.rs`:

```rust
const SS_PROFILE: &str = r#"{
    "id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"SS",
    "protocol":"shadowsocks","host":"198.51.100.7","port":8388,
    "auth":{"type":"shadowsocks","method":"aes-256-gcm",
            "password":{"source":"file","path":"/tmp/ss-key"}},
    "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},
    "kill_switch":false}"#;

#[test]
fn a_shadowsocks_profile_parses() {
    let p: ServerProfile = serde_json::from_str(SS_PROFILE).unwrap();
    assert_eq!(p.protocol, ProtocolKind::Shadowsocks);
    match &p.auth {
        AuthMethod::Shadowsocks { method, password } => {
            assert_eq!(method, "aes-256-gcm");
            assert!(matches!(password, SecretRef::File { .. }));
        }
        other => panic!("expected Shadowsocks, got {other:?}"),
    }
}

#[test]
fn a_shadowsocks_password_is_reported_as_a_secret() {
    // If secret_refs misses it, the Phase 1a ownership gate never sees the
    // password and a caller could name a file they do not own. The gate
    // iterates exactly this list.
    let p: ServerProfile = serde_json::from_str(SS_PROFILE).unwrap();
    let refs = p.auth.secret_refs();
    assert_eq!(refs.len(), 1, "the password must be enumerated");
    assert!(matches!(refs[0], SecretRef::File { .. }));
}

#[test]
fn a_shadowsocks_profile_never_serialises_its_password() {
    let p: ServerProfile = serde_json::from_str(SS_PROFILE).unwrap();
    let out = serde_json::to_string(&p).unwrap();
    assert!(out.contains("/tmp/ss-key"), "the location is kept: {out}");
    assert!(!out.contains("BEGIN"), "no key material");
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p liostunnel-core --lib config::profile`
Expected: FAIL — `no variant named Shadowsocks found for enum AuthMethod`.

- [ ] **Step 3: Add the variant**

In `AuthMethod`, after `PresharedKey`:

```rust
    /// Shadowsocks. `method` is a cipher name as Shadowsocks spells it
    /// (`aes-256-gcm`, `2022-blake3-aes-256-gcm`); it is not secret. The
    /// password IS key material, hence a `SecretRef` — which is what makes
    /// the helper's ownership gate cover it with no new code.
    Shadowsocks {
        method: String,
        password: SecretRef,
    },
```

In `secret_refs`, add the arm:

```rust
            AuthMethod::Shadowsocks { password, .. } => vec![password],
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core --lib config::profile`
Expected: PASS.

- [ ] **Step 5: A/B the secret enumeration**

Temporarily change the new `secret_refs` arm to `vec![]`. Confirm
`a_shadowsocks_password_is_reported_as_a_secret` FAILS. Restore, confirm green.
Paste both.

This one matters more than it looks: `secret_refs` is the list the escalation
gate iterates, so a variant missing from it is a variant whose secret is never
checked for ownership.

- [ ] **Step 6: Commit**

```bash
git add crates/liostunnel-core/src/config/profile.rs
git commit -F - <<'EOF'
feat: a Shadowsocks auth variant

The cipher name is not secret; the password is, so it is a SecretRef like
every other credential. That is what makes the Phase 1a ownership gate cover
it with no new code -- a second rule for a second protocol is how the two
drift.

secret_refs enumerates it, A/B verified: the gate iterates exactly that list,
so a variant missing from it is a variant whose secret is never checked.
EOF
```

---

### Task 2: `ShadowsocksTunnel`

**Files:**
- Create: `crates/liostunnel-core/src/protocols/shadowsocks.rs`
- Modify: `crates/liostunnel-core/src/protocols/mod.rs`, `crates/liostunnel-core/Cargo.toml`

**Interfaces:**
- Consumes: `AuthMethod::Shadowsocks` (Task 1), `Protocol`, `TunnelStream`.
- Produces: `ShadowsocksTunnel::new() -> Self` implementing `Protocol`.

**Do not override `open_dns_stream`.** Its default delegates to
`open_tcp_stream`, which is correct here: Shadowsocks makes no distinction, and
the reserved-channel reasoning in the trait's doc is an SSH concern about a
shared channel budget that Shadowsocks does not have.

- [ ] **Step 1: Add the dependency**

In `crates/liostunnel-core/Cargo.toml`:

```toml
shadowsocks = { version = "1.24", default-features = false, features = ["aead-cipher"] }
```

- [ ] **Step 2: Write the failing tests**

`crates/liostunnel-core/src/protocols/shadowsocks.rs`:

```rust
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
        assert!(t.connect(&profile("rc4-md5"), &FixedSecret("pw")).await.is_err());
    }

    #[tokio::test]
    async fn a_non_shadowsocks_profile_is_refused() {
        // The factory dispatches on profile.protocol, but nothing stops a
        // profile whose protocol says shadowsocks and whose auth says ssh.
        let mut p = profile("aes-256-gcm");
        p.auth = AuthMethod::Password {
            password: SecretRef::File { path: "/tmp/k".into() },
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
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p liostunnel-core --lib protocols::shadowsocks`
Expected: FAIL — `cannot find type ShadowsocksTunnel in this scope`.

- [ ] **Step 4: Implement**

Prepend to `shadowsocks.rs`:

```rust
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
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use shadowsocks::ProxyClientStream;

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
                format!("`{name}` is not a cipher this build offers; one of: {}", OFFERED.join(", ")),
            ));
        }
        // The crate owns the mapping. We only decide what to offer.
        CipherKind::from_str(name)
            .map_err(|_| TunnelError::config("auth.method", format!("`{name}` is not a known cipher")))
    }
}

#[async_trait]
impl Protocol for ShadowsocksTunnel {
    async fn connect(
        &mut self,
        profile: &ServerProfile,
        store: &dyn SecretStore,
    ) -> Result<(), TunnelError> {
        let (method, password_ref) = match &profile.auth {
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
        .map_err(|_| TunnelError::config("auth", "the server rejected this cipher/password pair"))?;

        self.context = Some(Context::new_shared(ServerType::Local));
        self.server = Some(cfg);
        self.state = ConnectionState::Connected;
        Ok(())
    }

    async fn open_tcp_stream(&self, dest: SocketAddr) -> Result<Box<dyn TunnelStream>, TunnelError> {
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
```

Add `pub mod shadowsocks;` to `protocols/mod.rs`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core --lib protocols::shadowsocks`
Expected: PASS — 5 passed.

- [ ] **Step 6: A/B the password-leak guard**

Temporarily change `Self::cipher`'s error to include the resolved password
(pass it in and interpolate it). Confirm `an_error_never_carries_the_password`
FAILS. Restore, confirm green. Paste both.

- [ ] **Step 7: Commit**

```bash
git add crates/liostunnel-core
git commit -F - <<'EOF'
feat: Shadowsocks over TCP

Thin on purpose. ProxyClientStream already satisfies TunnelStream's bounds, so
a proxied flow is one connect call and a Box -- no channel budget, no
multiplexing, no host key, because Shadowsocks has none of those. Inventing
structure the protocol does not have is how an abstraction acquires a shape.

open_dns_stream is deliberately NOT overridden. Its default delegates to
open_tcp_stream, which is right here: the reserved-channel reasoning in the
trait's doc is an SSH concern about a shared budget Shadowsocks does not have.

Ciphers are an allow-list of six AEAD names, mapped by CipherKind::from_str --
the crate owns the mapping, we only decide what to offer. Stream ciphers are
excluded: broken, gated behind a feature we do not enable, and offering one we
would have to warn about is worse than not offering it.

send_udp stays Unsupported. Shadowsocks relays UDP natively, but the trait has
no return path for a reply, so it is its own slice.
EOF
```

---

### Task 3: The connect-time probe

**Files:**
- Modify: `crates/liostunnel-core/src/protocols/shadowsocks.rs`

**Interfaces:**
- Consumes: `ShadowsocksTunnel` (Task 2).
- Produces: `connect()` that fails on bad credentials rather than succeeding.

**Why this task exists.** Shadowsocks has no handshake. Each stream is
independent, and a server given a wrong key accepts the TCP connection and
silently discards it. So Task 2's `connect` returns `Ok` for a typo'd password,
the UI shows `Connected`, routes get installed, and nothing works — the exact
class of green-over-nothing failure this project keeps finding.

- [ ] **Step 1: Write the failing test**

Append to the tests module:

```rust
    #[tokio::test]
    async fn connect_fails_when_the_server_does_not_answer() {
        // TEST-NET-1, RFC 5737 — reserved and unroutable, so the probe cannot
        // succeed. Before the probe existed, connect() returned Ok here: it
        // only built a config and never spoke to anything.
        let mut p = profile("aes-256-gcm");
        p.host = "192.0.2.1".into();
        let mut t = ShadowsocksTunnel::new();
        let err = t
            .connect(&p, &FixedSecret("pw"))
            .await
            .expect_err("a server that cannot be reached is not a connection");
        assert!(
            matches!(err, TunnelError::Auth(_) | TunnelError::Transport(_)),
            "got {err:?}"
        );
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p liostunnel-core --lib protocols::shadowsocks::tests::connect_fails_when_the_server_does_not_answer`
Expected: FAIL — `expect_err` panics on `Ok(())`, because `connect` never
contacts the server.

This failure IS the bug the task fixes. Paste it.

- [ ] **Step 3: Implement the probe**

Add to `ShadowsocksTunnel`, and call it at the end of `connect` before setting
`state`:

```rust
    /// How long the probe waits. A server that cannot answer a DNS query in
    /// this long is not one worth installing routes for.
    const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

    /// Proves the credentials work, because the protocol will not.
    ///
    /// Shadowsocks has no handshake: a server given the wrong key accepts the
    /// connection and drops it silently. Without this, `connect` returning
    /// `Ok` would mean "a socket opened" — the UI would report Connected,
    /// routes would be installed, and nothing would carry.
    ///
    /// One DNS query over a relayed stream, using the profile's own resolver.
    /// If bytes come back, the cipher and password are right AND the server
    /// relays traffic.
    ///
    /// This is not authentication in the SSH sense. It proves the server
    /// relays for these credentials; it does not identify the server.
    /// Shadowsocks offers no server identity at all.
    async fn probe(&self, dns: SocketAddr) -> Result<(), TunnelError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // A minimal A query for "." — the smallest well-formed thing a
        // resolver will answer. RFC 7766 framing: two-byte length prefix.
        let query: [u8; 17] = [
            0x00, 0x0f, // length
            0xAB, 0xCD, // id
            0x01, 0x00, // standard query, recursion desired
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // root name
            0x00, 0x01, // A
        ];

        let fut = async {
            let mut s = self.open_tcp_stream(dns).await?;
            s.write_all(&query)
                .await
                .map_err(|e| TunnelError::Transport(e))?;
            let mut len = [0u8; 2];
            s.read_exact(&mut len)
                .await
                .map_err(|_| TunnelError::Auth(
                    "the server accepted the connection but returned nothing; \
                     the cipher or password is probably wrong".into(),
                ))?;
            Ok::<(), TunnelError>(())
        };

        match tokio::time::timeout(Self::PROBE_TIMEOUT, fut).await {
            Ok(r) => r,
            Err(_) => Err(TunnelError::Auth(
                "the server did not answer a probe query in time".into(),
            )),
        }
    }
```

In `connect`, after building `self.server`/`self.context` and before setting
`state`:

```rust
        // The profile's first DNS server, over the tunnel being tested.
        let dns = profile
            .dns
            .servers
            .first()
            .ok_or_else(|| TunnelError::config("dns.servers", "at least one is required"))?;
        self.probe(SocketAddr::new(*dns, 53)).await.inspect_err(|_| {
            // Do not leave a half-built tunnel behind on failure.
            self.state = ConnectionState::Failed;
        })?;
```

Note `connect` takes `&mut self` while `probe` takes `&self`; assign
`self.server`/`self.context` first so `probe` can use them.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p liostunnel-core --lib protocols::shadowsocks`
Expected: PASS — 6 passed. The unroutable-host test takes ~8s (the timeout).

- [ ] **Step 5: A/B the probe**

Comment out the `self.probe(...)` call. Confirm
`connect_fails_when_the_server_does_not_answer` FAILS with `expect_err` on
`Ok(())`. Restore, confirm green. Paste both.

That failure is precisely what would ship without this task: a tunnel that
reports success to an address nothing can reach.

- [ ] **Step 6: Commit**

```bash
git add crates/liostunnel-core/src/protocols/shadowsocks.rs
git commit -F - <<'EOF'
fix: prove the credentials at connect, because the protocol will not

Shadowsocks has no handshake. A server given the wrong key accepts the TCP
connection and silently discards it, so connect() returning Ok would have
meant "a socket opened" -- the UI reporting Connected, routes installed, and
nothing carrying. That is the green-over-nothing failure this project keeps
finding, and here it was designed in.

connect now sends one real DNS query over a relayed stream to the profile's
own resolver. Bytes back prove the cipher and password are right AND that the
server relays traffic. Costs one round trip per connect.

Not authentication in the SSH sense: it proves the server relays for these
credentials, not who the server is. Shadowsocks offers no server identity, and
that is recorded so nobody later reads Connected as meaning more than it does.

A/B verified against an unroutable RFC 5737 address: without the probe,
connect returns Ok for a host nothing can reach.
EOF
```

---

### Task 4: The protocol factory — the abstraction test

**Files:**
- Modify: `crates/liostunnel-helper/src/session.rs`

**Interfaces:**
- Consumes: `ShadowsocksTunnel` (Tasks 2–3), `Authorized` (Phase 1a).
- Produces: `Tunnel::start` dispatching on `profile.protocol`.

**This task answers exit criterion P1b-6.** Record in your report every place
that could not be made protocol-neutral. `HostKeyPolicy` is the known one;
report anything else you hit.

- [ ] **Step 1: Write the failing test**

In `session.rs`'s tests module:

```rust
    #[test]
    fn a_wireguard_profile_is_refused_by_name() {
        // The factory must reject what it cannot build, rather than falling
        // through to SSH and producing a confusing failure much later.
        let d = scratch("wg");
        let p = owned_secret(&d);
        let mut params = params_with_file_secret(&p);
        params.profile_json = params.profile_json.replace(r#""protocol":"ssh""#, r#""protocol":"wireguard""#);
        let err = Tunnel::authorize_params(&params, me()).expect_err("wireguard is not built");
        assert!(format!("{err}").to_lowercase().contains("wireguard"), "name it: {err}");
        std::fs::remove_dir_all(&d).ok();
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p liostunnel-helper --bin liostunnel-helper session`
Expected: FAIL — `authorize_params` accepts the profile, so `expect_err` panics.

- [ ] **Step 3: Refuse unbuildable protocols in the gate**

In `authorize_params`, after the profile parses:

```rust
        // Refuse here rather than at connect: nothing privileged should
        // happen for a protocol this build cannot speak.
        if profile.protocol == ProtocolKind::WireGuard {
            return Err(StartError::BadProfile);
        }
```

Change `StartError::BadProfile` to carry a fixed reason so the message can name
the protocol without echoing the document:

```rust
    #[error("{0}")]
    BadProfile(&'static str),
```

and update its two construction sites to
`StartError::BadProfile("profile is not valid")` and
`StartError::BadProfile("wireguard is not supported in this build")`.

- [ ] **Step 4: Build the factory**

In `Tunnel::start`, replace the hardcoded `SshTunnel` construction:

```rust
        // The abstraction test. Everything protocol-specific lives inside an
        // arm; anything that had to sit outside would be an SSH-shaped hole
        // in `Protocol`, and is reported as such (spec §13, P1b-6).
        let protocol: Arc<dyn Protocol> = match auth.profile.protocol {
            ProtocolKind::Ssh => {
                // HostKeyPolicy moved in here from `start`'s body: it is
                // meaningless for a protocol with no server identity, and
                // leaving it in the shared path would be exactly the hole
                // this slice exists to find.
                let policy = HostKeyPolicy::Verify {
                    known_hosts: paths.known_hosts.clone(),
                };
                let mut ssh = SshTunnel::new(auth.user.clone(), policy);
                ssh.connect(&auth.profile, &auth.secrets).await?;
                Arc::new(ssh)
            }
            ProtocolKind::Shadowsocks => {
                let mut ss = ShadowsocksTunnel::new();
                ss.connect(&auth.profile, &auth.secrets).await?;
                Arc::new(ss)
            }
            ProtocolKind::WireGuard => {
                return Err(StartError::BadProfile("wireguard is not supported in this build"));
            }
        };
```

`server_ip` currently comes from `ssh.peer_addr()`, which is SSH-specific.
Resolve it once, before the match, from `profile.host`:

```rust
        // Needed for the route that pins the server through the original
        // gateway, and `Protocol` exposes no peer address — so it is resolved
        // here rather than asked of the protocol. REPORT THIS: it is a real
        // finding for P1b-6. SSH previously supplied it from the session it
        // had already opened, which was strictly better (one resolution, the
        // address actually in use); doing it here reintroduces the
        // dual-stack disagreement Phase 0's comment warns about.
        let server_ip = tokio::net::lookup_host((auth.profile.host.as_str(), auth.profile.port))
            .await
            .map_err(|e| TunnelError::Transport(e))?
            .next()
            .ok_or_else(|| TunnelError::Route(format!("{} resolved to nothing", auth.profile.host)))?
            .ip();
```

- [ ] **Step 5: Run the tests**

```bash
cargo test -p liostunnel-helper
docker run --rm -v "$PWD":/w -w /w -e CARGO_TARGET_DIR=/w/target-linux \
  rust:1.93-slim cargo test -p liostunnel-helper
```
Expected: PASS on both.

- [ ] **Step 6: Record the P1b-6 finding**

In your report, list every construct that could not go inside an arm. At
minimum: `HostKeyPolicy` (resolved — moved into the SSH arm) and `server_ip`
(a real hole — `Protocol` has no peer-address accessor, so resolution moved
out of the protocol and lost the guarantee that the route pins the address the
session actually used).

State plainly whether the trait needed a concession. The spec commits to
amending itself if so.

- [ ] **Step 7: Commit**

```bash
git add crates/liostunnel-helper/src/session.rs
git commit -F - <<'EOF'
feat: dispatch on the profile's protocol

The factory is the abstraction test, and it found two things.

HostKeyPolicy moved into the SSH arm. It is meaningless for a protocol with no
server identity, and leaving it in the shared path was the SSH-shaped hole this
slice existed to look for.

server_ip is a real hole. The route that pins the server through the original
gateway needs its address, and Protocol exposes no peer address -- SSH supplied
it from the session it had already opened, which was strictly better: one
resolution, of the address actually in use. Resolving it separately
reintroduces exactly the dual-stack disagreement Phase 0's own comment warns
about. Recorded rather than papered over.

WireGuard is refused in the gate rather than at connect, so nothing privileged
happens for a protocol this build cannot speak.
EOF
```

---

# Milestone B — the config surface

---

### Task 5: `ss://` parsing

**Files:**
- Create: `crates/liostunnel-core/src/protocols/ss_uri.rs`
- Modify: `crates/liostunnel-core/src/protocols/mod.rs`

**Interfaces:**
- Produces: `parse_ss_uri(uri: &str) -> Result<SsUri, TunnelError>` where
  `SsUri { host: String, port: u16, method: String, password: String, tag: Option<String> }`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
    }

    #[test]
    fn a_sip002_uri_parses() {
        let uri = format!("ss://{}@198.51.100.7:8388#Home", b64("aes-256-gcm:hunter2"));
        let p = parse_ss_uri(&uri).unwrap();
        assert_eq!(p.host, "198.51.100.7");
        assert_eq!(p.port, 8388);
        assert_eq!(p.method, "aes-256-gcm");
        assert_eq!(p.password, "hunter2");
        assert_eq!(p.tag.as_deref(), Some("Home"));
    }

    #[test]
    fn the_legacy_all_in_one_form_parses() {
        // Still in wide circulation; a client that only reads SIP002 rejects
        // half the links people actually have.
        let uri = format!("ss://{}", b64("aes-256-gcm:hunter2@198.51.100.7:8388"));
        let p = parse_ss_uri(&uri).unwrap();
        assert_eq!(p.host, "198.51.100.7");
        assert_eq!(p.port, 8388);
        assert_eq!(p.password, "hunter2");
        assert_eq!(p.tag, None);
    }

    #[test]
    fn a_password_containing_a_colon_survives() {
        // The method/password split is on the FIRST colon; passwords contain
        // colons routinely and a greedy split silently truncates them.
        let uri = format!("ss://{}@h:1#t", b64("aes-256-gcm:a:b:c"));
        assert_eq!(parse_ss_uri(&uri).unwrap().password, "a:b:c");
    }

    #[test]
    fn a_uri_without_a_tag_parses() {
        let uri = format!("ss://{}@198.51.100.7:8388", b64("aes-256-gcm:pw"));
        assert_eq!(parse_ss_uri(&uri).unwrap().tag, None);
    }

    #[test]
    fn a_uri_that_is_not_shadowsocks_is_refused() {
        assert!(parse_ss_uri("https://example.com").is_err());
    }

    #[test]
    fn a_malformed_uri_never_echoes_itself() {
        // The URI CONTAINS THE PASSWORD. This is the rule Phase 0 broke in
        // profile_io::load and Phase 1a broke again in the protocol codec.
        let uri = format!("ss://{}", b64("no-colon-here-SECRET"));
        let err = parse_ss_uri(&uri).unwrap_err();
        assert!(!format!("{err}").contains("SECRET"), "echoed: {err}");
        assert!(!format!("{err}").contains(&uri), "echoed the whole uri");
        assert!(!format!("{err:?}").contains("SECRET"));
    }

    #[test]
    fn a_port_that_is_not_a_port_is_refused() {
        let uri = format!("ss://{}@h:notaport", b64("aes-256-gcm:pw"));
        assert!(parse_ss_uri(&uri).is_err());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p liostunnel-core --lib ss_uri`
Expected: FAIL — `cannot find function parse_ss_uri`.

- [ ] **Step 3: Implement**

Add `base64 = "0.22"` to `crates/liostunnel-core/Cargo.toml`, then:

```rust
//! `ss://` links, both forms in circulation. Spec §9.
//!
//! Parsed here rather than in Dart for the same reason profiles are: the
//! format has one owner. A second parser is free to drift from the first.

use base64::Engine;

use crate::error::TunnelError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsUri {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub password: String,
    pub tag: Option<String>,
}

/// Every error is a fixed string.
///
/// The URI contains the password, so an error that quotes its input hands the
/// credential to a log. Phase 0 shipped that in `profile_io::load` and Phase
/// 1a shipped it again in the protocol codec; the test named
/// `a_malformed_uri_never_echoes_itself` is what stops a third.
fn bad(reason: &'static str) -> TunnelError {
    TunnelError::config("ss uri", reason)
}

fn decode(s: &str) -> Result<String, TunnelError> {
    // Links appear with and without padding, and in both alphabets.
    let engines = [
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
    ];
    for e in engines {
        if let Ok(v) = e.decode(s.trim_end_matches('=')) {
            if let Ok(t) = String::from_utf8(v) {
                return Ok(t);
            }
        }
    }
    Err(bad("the encoded section is not valid base64"))
}

/// Splits `method:password` on the FIRST colon. Passwords contain colons.
fn split_creds(s: &str) -> Result<(String, String), TunnelError> {
    match s.split_once(':') {
        Some((m, p)) if !m.is_empty() && !p.is_empty() => Ok((m.to_string(), p.to_string())),
        _ => Err(bad("expected method:password")),
    }
}

fn split_host_port(s: &str) -> Result<(String, u16), TunnelError> {
    let (h, p) = s.rsplit_once(':').ok_or_else(|| bad("expected host:port"))?;
    let port = p.parse().map_err(|_| bad("the port is not a number"))?;
    if h.is_empty() {
        return Err(bad("the host is empty"));
    }
    Ok((h.to_string(), port))
}

pub fn parse_ss_uri(uri: &str) -> Result<SsUri, TunnelError> {
    let rest = uri.strip_prefix("ss://").ok_or_else(|| bad("not an ss:// link"))?;

    let (body, tag) = match rest.split_once('#') {
        Some((b, t)) => (b, (!t.is_empty()).then(|| t.to_string())),
        None => (rest, None),
    };
    // Query parameters (plugin=...) are ignored; plugins are out of scope.
    let body = body.split('?').next().unwrap_or(body);

    if let Some((creds, hostport)) = body.rsplit_once('@') {
        // SIP002: base64(method:password) @ host:port
        let (method, password) = split_creds(&decode(creds)?)?;
        let (host, port) = split_host_port(hostport)?;
        Ok(SsUri { host, port, method, password, tag })
    } else {
        // Legacy: base64(method:password@host:port)
        let all = decode(body)?;
        let (creds, hostport) = all.rsplit_once('@').ok_or_else(|| bad("expected method:password@host:port"))?;
        let (method, password) = split_creds(creds)?;
        let (host, port) = split_host_port(hostport)?;
        Ok(SsUri { host, port, method, password, tag })
    }
}
```

Add `pub mod ss_uri;` to `protocols/mod.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core --lib ss_uri`
Expected: PASS — 7 passed.

- [ ] **Step 5: A/B the echo guard**

Change `bad` to take the offending input and interpolate it. Confirm
`a_malformed_uri_never_echoes_itself` FAILS with the marker visible. Restore,
confirm green. Paste both.

- [ ] **Step 6: Commit**

```bash
git add crates/liostunnel-core
git commit -F - <<'EOF'
feat: parse ss:// links, both forms

SIP002 and the older all-in-one form, because a client that reads only the
first rejects half the links people actually have.

The method/password split is on the FIRST colon: passwords contain colons
routinely, and a greedy split truncates them silently into an auth failure
nobody can explain.

Every error is a fixed string. The URI contains the password, so an error that
quotes its input hands a credential to a log -- shipped once in Phase 0's
profile_io::load and again in Phase 1a's protocol codec. A/B verified against
an echoing implementation.

Parsed in Rust for the same reason profiles are: the format has one owner.
EOF
```

---

### Task 6: The config surface — DTO, import, editor

**Files:**
- Modify: `crates/liostunnel-ffi/src/dto/profile.rs`, `crates/liostunnel-ffi/src/api/config.rs`, `app/lib/screens/profile_editor.dart`
- Test: `app/test/profile_writer_test.dart`

**Interfaces:**
- Consumes: `AuthMethod::Shadowsocks` (Task 1), `parse_ss_uri` (Task 5).
- Produces: `ProfileDto.cipher: Option<String>`; FFI `import_ss_uri(uri: String) -> Result<ProfileDto, String>`.

- [ ] **Step 1: Write the failing Rust tests**

In `dto/profile.rs`'s tests:

```rust
    const SS: &str = r#"{
        "id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"SS",
        "protocol":"shadowsocks","host":"198.51.100.7","port":8388,
        "auth":{"type":"shadowsocks","method":"aes-256-gcm",
                "password":{"source":"file","path":"/tmp/ss-key"}},
        "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},
        "kill_switch":false}"#;

    #[test]
    fn a_shadowsocks_profile_round_trips_through_the_dto() {
        let core: ServerProfile = serde_json::from_str(SS).unwrap();
        let dto = ProfileDto::from(core.clone());
        assert_eq!(dto.auth_kind, "shadowsocks");
        assert_eq!(dto.cipher.as_deref(), Some("aes-256-gcm"));
        assert_eq!(dto.auth_secret_source, "file:/tmp/ss-key");
        assert_eq!(ServerProfile::try_from(dto).unwrap(), core);
    }

    #[test]
    fn a_shadowsocks_dto_without_a_cipher_is_refused() {
        let core: ServerProfile = serde_json::from_str(SS).unwrap();
        let mut dto = ProfileDto::from(core);
        dto.cipher = None;
        assert!(ServerProfile::try_from(dto).is_err());
    }
```

In `api/config.rs`, add a tests module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ss_uri_imports_to_a_usable_profile() {
        use base64::Engine;
        let creds = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:pw");
        let dto = import_ss_uri(format!("ss://{creds}@198.51.100.7:8388#Home")).unwrap();
        assert_eq!(dto.name, "Home");
        assert_eq!(dto.host, "198.51.100.7");
        assert_eq!(dto.port, 8388);
        assert_eq!(dto.protocol, "shadowsocks");
        assert_eq!(dto.cipher.as_deref(), Some("aes-256-gcm"));
        // The password is NOT in the DTO. It comes back separately so the
        // caller can write it to a 0600 file.
        assert!(!format!("{dto:?}").contains("pw"));
    }

    #[test]
    fn an_imported_profile_needs_its_password_written_before_use() {
        // auth_secret_source is a placeholder until the caller writes the
        // password; it must not silently claim a file that does not exist.
        use base64::Engine;
        let creds = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:pw");
        let dto = import_ss_uri(format!("ss://{creds}@h:1")).unwrap();
        assert!(dto.auth_secret_source.is_empty(), "the caller supplies this");
    }

    #[test]
    fn a_bad_uri_is_refused_without_echoing_it() {
        use base64::Engine;
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("no-colon-SECRET");
        let e = import_ss_uri(format!("ss://{b}")).unwrap_err();
        assert!(!e.contains("SECRET"), "echoed: {e}");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p liostunnel_ffi`
Expected: FAIL — `no field cipher on ProfileDto`, `cannot find function import_ss_uri`.

- [ ] **Step 3: Implement the DTO changes**

Add to `ProfileDto`:

```rust
    /// The Shadowsocks cipher name. `None` for every other protocol.
    pub cipher: Option<String>,
```

In `From<ServerProfile>`, add the arm and set `cipher`:

```rust
            AuthMethod::Shadowsocks { method, password } => (
                "shadowsocks",
                describe(password),
                None,
                None,
            ),
```

carrying `method` out so `cipher` can be set; and in `TryFrom`:

```rust
            "shadowsocks" => AuthMethod::Shadowsocks {
                method: d.cipher.clone().ok_or_else(|| ProfileDtoError::at("cipher"))?,
                password: secret,
            },
```

Every other construction of `ProfileDto` in the crate needs `cipher: None`.

- [ ] **Step 4: Implement the import**

In `api/config.rs`:

```rust
/// Turns an `ss://` link into a profile the editor can show.
///
/// Returns the profile WITHOUT its password: `auth_secret_source` is left
/// empty and the caller writes the password to a `0600` file, then fills it
/// in. Returning the password inside the DTO would put a credential in a
/// value that crosses into Dart and gets rendered on screen — the one thing
/// this type exists not to do.
pub fn import_ss_uri(uri: String) -> Result<ProfileDto, String> {
    let p = liostunnel_core::protocols::ss_uri::parse_ss_uri(&uri).map_err(|e| e.to_string())?;
    Ok(ProfileDto {
        id: new_profile_id(),
        name: p.tag.unwrap_or_else(|| format!("{}:{}", p.host, p.port)),
        protocol: "shadowsocks".into(),
        host: p.host,
        port: p.port,
        auth_kind: "shadowsocks".into(),
        auth_secret_source: String::new(),
        auth_passphrase_source: None,
        peer_public_key: None,
        cipher: Some(p.method),
        dns_mode: "tcp".into(),
        dns_servers: vec!["1.1.1.1".into(), "1.0.0.1".into()],
        doh_sni: None,
        doh_path: None,
        split_tunnel: "all_traffic".into(),
        split_tunnel_apps: vec![],
        kill_switch: false,
    })
}

/// The password from an `ss://` link, so the caller can write it to a file.
///
/// Separate from `import_ss_uri` on purpose: the profile crosses into Dart and
/// is rendered, and this does not belong in it. The caller passes this
/// straight to the secret writer and never holds it in widget state.
pub fn ss_uri_password(uri: String) -> Result<String, String> {
    liostunnel_core::protocols::ss_uri::parse_ss_uri(&uri)
        .map(|p| p.password)
        .map_err(|e| e.to_string())
}
```

- [ ] **Step 5: Run the Rust tests**

Run: `cargo test -p liostunnel_ffi && cargo test -p liostunnel-core`
Expected: PASS.

- [ ] **Step 6: Regenerate and wire the editor**

```bash
flutter_rust_bridge_codegen generate
cargo fmt --all
./testing/build-ffi-for-tests.sh
```

In `profile_editor.dart`, add state:

```dart
  final _uri = TextEditingController();
  String _cipher = 'aes-256-gcm';

  static const _ciphers = [
    'aes-128-gcm',
    'aes-256-gcm',
    'chacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm',
    '2022-blake3-aes-256-gcm',
    '2022-blake3-chacha20-poly1305',
  ];
```

Add `_uri` to `dispose`'s list. In `initState`'s edit branch, carry the cipher
through like every other field the form does not own:

```dart
    _cipher = p.cipher ?? 'aes-256-gcm';
```

The import handler. **The order matters**: parse first, so a bad link writes
nothing; write the secret before the form is touched, so a failure leaves the
form as it was rather than half-filled with a password that never landed.

```dart
  Future<void> _import() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final uri = _uri.text.trim();
      // Parsed before anything is written: a malformed link must not leave a
      // secret file behind.
      final dto = await importSsUri(uri: uri);
      final password = await ssUriPassword(uri: uri);
      // Straight to a 0600 file. The password is never held in widget state
      // and never reaches the profile document.
      final ref = await widget.writer.writeSecret(dto.id, password);

      if (!mounted) return;
      setState(() {
        _name.text = dto.name;
        _host.text = dto.host;
        _port.text = dto.port.toString();
        _authKind = 'shadowsocks';
        _cipher = dto.cipher ?? 'aes-256-gcm';
        _secretMode = 'file';
        _secretPath.text = ref.substring('file:'.length);
        _dns.text = dto.dnsServers.join(', ');
        _uri.clear();   // it contains the password; do not leave it on screen
      });
    } catch (e) {
      if (mounted) setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }
```

Add `'shadowsocks'` to the auth-kind dropdown, and show the cipher dropdown and
paste box only when it is selected:

```dart
            if (_authKind == 'shadowsocks') ...[
              _text(_uri, 'Paste an ss:// link', key: 'f-uri',
                  hint: 'ss://...',
                  help: 'Filled in from the link. The password is written to a '
                      '0600 file and never stored in the profile.',
                  validator: (_) => null),
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 6),
                child: FilledButton.tonal(
                  key: const Key('import-button'),
                  onPressed: _busy ? null : _import,
                  child: const Text('Import from link'),
                ),
              ),
              DropdownButtonFormField<String>(
                key: const Key('f-cipher'),
                initialValue: _cipher,
                decoration: const InputDecoration(labelText: 'Cipher'),
                items: [
                  for (final c in _ciphers)
                    DropdownMenuItem(value: c, child: Text(c)),
                ],
                onChanged: (v) => setState(() => _cipher = v!),
              ),
            ],
```

The SSH username field is only meaningful for SSH, so wrap it:

```dart
            if (_authKind != 'shadowsocks')
              _text(_user, 'SSH username', key: 'f-user'),
```

And in `_save`'s DTO:

```dart
        cipher: _authKind == 'shadowsocks' ? _cipher : old?.cipher,
```

- [ ] **Step 7: Write the Dart test**

In `test/profile_writer_test.dart`:

```dart
  test('an ss:// link imports without putting the password in the profile',
      () async {
    final creds = base64Url.encode(utf8.encode('aes-256-gcm:hunter2'))
        .replaceAll('=', '');
    final dto = await importSsUri(uri: 'ss://$creds@198.51.100.7:8388#Home');
    expect(dto.protocol, 'shadowsocks');
    expect(dto.cipher, 'aes-256-gcm');
    expect(dto.name, 'Home');

    final dir = Directory.systemTemp.createTempSync('lios-ss');
    final w = ProfileWriter(directory: dir.path);
    final pw = await ssUriPassword(uri: 'ss://$creds@198.51.100.7:8388#Home');
    final ref = await w.writeSecret(dto.id, pw);
    final file = await w.writeProfile(
      ProfileDto(
        id: dto.id, name: dto.name, protocol: dto.protocol, host: dto.host,
        port: dto.port, authKind: dto.authKind, authSecretSource: ref,
        cipher: dto.cipher, dnsMode: dto.dnsMode, dnsServers: dto.dnsServers,
        splitTunnel: dto.splitTunnel, splitTunnelApps: dto.splitTunnelApps,
        killSwitch: dto.killSwitch,
      ),
    );
    final text = file.readAsStringSync();
    expect(text, isNot(contains('hunter2')),
        reason: 'the profile holds the path, never the password');
    expect(text, contains('aes-256-gcm'));
    dir.deleteSync(recursive: true);
  });
```

- [ ] **Step 8: Run everything**

```bash
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
cd app && flutter test && flutter analyze
```
Expected: all pass.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -F - <<'EOF'
feat: import ss:// links and edit Shadowsocks profiles

import_ss_uri returns the profile WITHOUT its password. The DTO crosses into
Dart and is rendered on screen, so a credential inside it is the one thing the
type exists not to carry; the password comes back from a separate call and
goes straight to a 0600 file by the path the editor already uses.

The editor gains a paste box, a cipher dropdown of the six offered AEAD names,
and carries cipher through on edit like every other field the form does not
offer -- the omission that silently rewrote profiles in Phase 1a.
EOF
```

---

# Milestone C — verification

---

### Task 7: The Shadowsocks fixture

**Files:**
- Modify: `testing/docker/docker-compose.yml`, `testing/docker/Makefile`
- Create: `testing/docker/ss/gen-config.sh`

- [ ] **Step 1: Generate credentials, never commit them**

`testing/docker/ss/gen-config.sh`, mirroring `sshd/gen-keys.sh`:

```bash
#!/usr/bin/env bash
# Throwaway Shadowsocks credentials for the fixture. Never committed.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p conf
[ -f conf/password ] || openssl rand -base64 24 | tr -d '\n' > conf/password
chmod 600 conf/password
echo "shadowsocks fixture password ready in $(pwd)/conf/password"
```

Add `testing/docker/ss/conf/` to `.gitignore`.

- [ ] **Step 2: Add both servers**

In `docker-compose.yml`:

```yaml
  ss-libev:
    image: shadowsocks/shadowsocks-libev
    command: >
      ss-server -s 0.0.0.0 -p 8388 -k ${SS_PASSWORD} -m aes-256-gcm -u
    ports: ["127.0.0.1:8388:8388"]
    networks: [lios]
  ss-rust:
    image: teddysun/shadowsocks-rust
    command: >
      ssserver -s 0.0.0.0:8389 -k ${SS_PASSWORD} -m 2022-blake3-aes-256-gcm
    ports: ["127.0.0.1:8389:8389"]
    networks: [lios]
```

In the `Makefile`'s `up` target, before `docker compose up`:

```make
	./ss/gen-config.sh
	SS_PASSWORD=$$(cat ss/conf/password) docker compose up -d --build
```

**AEAD-2022 requires a base64 key of exact length for its cipher.** If
`ss-rust` refuses the generated password, that is a real finding: record the
requirement and generate a conforming key rather than switching cipher to make
the error go away.

- [ ] **Step 3: Bring it up and prove both answer**

```bash
make -C testing/docker up
docker compose -f testing/docker/docker-compose.yml ps
nc -z 127.0.0.1 8388 && echo "libev listening"
nc -z 127.0.0.1 8389 && echo "rust listening"
```
Paste the output.

- [ ] **Step 4: Commit**

```bash
git add testing/docker .gitignore
git commit -F - <<'EOF'
feat: Shadowsocks fixtures, C and Rust

Two servers, because testing a shadowsocks-rust client against a
shadowsocks-rust server lets a bug shared by both sides pass -- the same shape
as a mock written to match the code it tests. libev is the C reference and is
what makes this interop; the Rust server covers AEAD-2022, which libev
predates.

Credentials are generated and gitignored, as the sshd fixture's keys are.
EOF
```

---

### Task 8: Integration tests against both servers

**Files:**
- Create: `crates/liostunnel-core/tests/shadowsocks_integration.rs`

**Interfaces:**
- Consumes: `ShadowsocksTunnel` (Tasks 2–3), the fixture (Task 7).

Mirror `tests/ssh_integration.rs`: `#[ignore]` with a reason naming the
`make -C testing/docker up` command, so a run without the fixture reports
*ignored* rather than a false pass.

- [ ] **Step 1: Write the tests**

```rust
//! Against a real Shadowsocks server. Run with:
//!   make -C testing/docker up
//!   cargo test -p liostunnel-core --test shadowsocks_integration -- --ignored

use liostunnel_core::config::secret::{Redacted, SecretRef, SecretStore};
use liostunnel_core::error::TunnelError;
use liostunnel_core::protocols::Protocol;
use liostunnel_core::protocols::shadowsocks::ShadowsocksTunnel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Pw(String);
impl SecretStore for Pw {
    fn resolve(&self, _r: &SecretRef) -> Result<Redacted<String>, TunnelError> {
        Ok(Redacted::new(self.0.clone()))
    }
}

fn password() -> String {
    std::fs::read_to_string("../../testing/docker/ss/conf/password")
        .expect("run: make -C testing/docker up")
        .trim()
        .to_string()
}

fn profile(port: u16, method: &str) -> liostunnel_core::config::profile::ServerProfile {
    serde_json::from_str(&format!(
        r#"{{"id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"fixture",
            "protocol":"shadowsocks","host":"127.0.0.1","port":{port},
            "auth":{{"type":"shadowsocks","method":"{method}",
                    "password":{{"source":"file","path":"/tmp/k"}}}},
            "dns":["1.1.1.1"],"split_tunnel":{{"type":"all_traffic"}},
            "kill_switch":false}}"#
    ))
    .unwrap()
}

#[tokio::test]
#[ignore = "needs the fixture: make -C testing/docker up"]
async fn connects_to_the_c_reference_implementation() {
    // P1b-2. A Rust client against a Rust server proves the crate agrees with
    // itself; this proves it agrees with Shadowsocks.
    let mut t = ShadowsocksTunnel::new();
    t.connect(&profile(8388, "aes-256-gcm"), &Pw(password()))
        .await
        .expect("libev must accept these credentials");
}

#[tokio::test]
#[ignore = "needs the fixture: make -C testing/docker up"]
async fn relays_a_real_http_request() {
    // P1b-1 at the protocol layer: bytes out and bytes back.
    let mut t = ShadowsocksTunnel::new();
    t.connect(&profile(8388, "aes-256-gcm"), &Pw(password())).await.unwrap();

    let target = "93.184.216.34:80".parse().unwrap();
    let mut s = t.open_tcp_stream(target).await.expect("a relayed stream");
    s.write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n").await.unwrap();
    let mut buf = vec![0u8; 128];
    let n = s.read(&mut buf).await.unwrap();
    assert!(n > 0, "the relay returned nothing");
    assert!(
        String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/"),
        "not an HTTP reply: {:?}",
        String::from_utf8_lossy(&buf[..n])
    );

    let stats = t.stats();
    assert!(stats.bytes_up > 0 && stats.bytes_down > 0, "counters must move");
}

#[tokio::test]
#[ignore = "needs the fixture: make -C testing/docker up"]
async fn a_wrong_password_fails_at_connect() {
    // P1b-3, and the reason the probe exists. Without it this returns Ok and
    // the failure surfaces much later as a tunnel that carries nothing.
    let mut t = ShadowsocksTunnel::new();
    let err = t
        .connect(&profile(8388, "aes-256-gcm"), &Pw("definitely-wrong".into()))
        .await
        .expect_err("a wrong password must fail at connect");
    assert!(matches!(err, TunnelError::Auth(_)), "got {err:?}");
}

#[tokio::test]
#[ignore = "needs the fixture: make -C testing/docker up"]
async fn connects_with_an_aead_2022_cipher() {
    let mut t = ShadowsocksTunnel::new();
    t.connect(&profile(8389, "2022-blake3-aes-256-gcm"), &Pw(password()))
        .await
        .expect("the rust server must accept AEAD-2022");
}
```

- [ ] **Step 2: Run them against the fixture**

```bash
make -C testing/docker up
cargo test -p liostunnel-core --test shadowsocks_integration -- --ignored --nocapture
```
Expected: 4 passed. Paste the output.

`relays_a_real_http_request` needs outbound internet from the container. If
that is unavailable, point it at the fixture's own nginx instead and say so —
do not delete the assertion.

- [ ] **Step 3: A/B the wrong-password test**

Comment out the probe call in `connect` (Task 3). Confirm
`a_wrong_password_fails_at_connect` FAILS. Restore, confirm green. Paste both.

This is P1b-3's evidence and the justification for Task 3 existing.

- [ ] **Step 4: Commit**

```bash
git add crates/liostunnel-core/tests/shadowsocks_integration.rs
git commit -F - <<'EOF'
test: Shadowsocks against real servers

Four tests behind #[ignore] with the fixture command in the reason, so a run
without the fixture reports ignored rather than a false pass.

Interop against the C reference implementation is the one that matters: a Rust
client against a Rust server proves the crate agrees with itself.

The wrong-password test is A/B verified against the probe being removed --
without it, connect returns Ok and the failure surfaces much later as a tunnel
that carries nothing.
EOF
```

---

### Task 9: Exit criteria

**Files:**
- Create: `docs/superpowers/phase1b-verification.md`

The only task needing root.

- [ ] **Step 1: Build a Shadowsocks profile for the verifier**

```bash
mkdir -p /tmp/lios-verify
install -m 600 testing/docker/ss/conf/password /tmp/lios-verify/ss-key
cat > /tmp/lios-verify/ss-profile.json <<EOF
{"id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"SS fixture",
 "protocol":"shadowsocks","host":"127.0.0.1","port":8388,
 "auth":{"type":"shadowsocks","method":"aes-256-gcm",
         "password":{"source":"file","path":"/tmp/lios-verify/ss-key"}},
 "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},"kill_switch":false}
EOF
```

- [ ] **Step 2: Run the Phase 1a script unchanged**

```bash
cargo build --release -p liostunnel-helper
LIOS_PROFILE=/tmp/lios-verify/ss-profile.json sudo -E ./testing/verify-phase1a.sh
```

Expected: 14 passed, 0 failed.

**If the script needs any edit to pass, that edit is a P1b-6 finding.** Record
what and why; do not quietly patch it. The script passing unchanged against a
second protocol is the evidence the abstraction held.

- [ ] **Step 3: Record P1b-1 through P1b-6**

Write `docs/superpowers/phase1b-verification.md` with, for each criterion, the
exact command and verbatim output — including anything that failed. P1b-6 gets
the list from Task 4's report: what could not be made protocol-neutral, and
whether `Protocol` needed a concession.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/phase1b-verification.md
git commit -F - <<'EOF'
docs: Phase 1b exit criteria verification

Records P1b-1 through P1b-6 with exact commands and verbatim output.

P1b-6 is the one that could not be satisfied by writing code: whether Protocol
needed an SSH-shaped concession. The answer is what the factory turned out to
need, and it is recorded whichever way it went.
EOF
```

---

## Completion checklist

| Criterion | Verified by |
|---|---|
| P1b-1 — connects and carries traffic | Task 8 step 2, Task 9 step 2 |
| P1b-2 — interoperates with libev | Task 8 step 2 |
| P1b-3 — a wrong password fails at connect | Task 3 (A/B), Task 8 step 3 |
| P1b-4 — `ss://` imports; malformed refused without echo | Task 5 (A/B), Task 6 |
| P1b-5 — the ownership gate covers SS passwords | Task 1 (A/B), Task 9 step 2 |
| P1b-6 — no SSH-shaped concession, or it is recorded | Task 4 step 6, Task 9 step 3 |

P1b-6 is the criterion this slice exists for. The others confirm Shadowsocks
works; only that one tells us whether the architecture does.

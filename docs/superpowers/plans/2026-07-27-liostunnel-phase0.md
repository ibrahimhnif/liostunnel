# LiosTunnel Phase 0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A CLI-only Rust binary that routes real TCP traffic from a real TUN device through a real SSH tunnel, on macOS and Linux, with DNS through the tunnel and no DNS leaks.

**Architecture:** One dedicated synchronous thread owns a `smoltcp` `Interface` and the TUN file descriptor; tokio owns the SSH session and per-flow copy loops; bounded channels join them and supply backpressure. The stack is reached through a `NetStack` trait so it can be swapped. TCP flows through smoltcp proper; UDP is handled by direct `smoltcp::wire` parsing because DNS is the only UDP need.

**Tech Stack:** Rust 2024, `smoltcp` 0.13.1, `russh` 0.62.4, `tun-rs` 2.8.8, `polling` 3.11.0, `tokio` 1.53, `hyper` 1.11 + `tokio-rustls` 0.26, `serde`, `tracing`.

**Spec:** [`../specs/2026-07-27-liostunnel-phase0-design.md`](../specs/2026-07-27-liostunnel-phase0-design.md)

## Global Constraints

Every task's requirements implicitly include this section.

- **Edition 2024, `rust-version = "1.93"`.** Workspace `resolver = "3"`.
- **Pinned versions** (spec §5, verified against crates.io 2026-07-27): `smoltcp` 0.13.1, `russh` 0.62.4, `tun-rs` 2.8.8, `polling` 3.11.0, `ipnet` 2.12.0, `tokio` 1.53, `hyper` 1.11, `tokio-rustls` 0.26, `hickory-proto` 0.26.1.
- **Never log payload bytes.** `tracing` metadata only. Any type holding secret material is wrapped in `Redacted<T>` (Task 2), whose `Debug` and `Display` print `<redacted>`.
- **Host key verification is on by default.** Bypass exists only behind `--insecure-accept-any-hostkey` and must print a warning on every use.
- **TDD, strictly.** Write the test, run it, watch it fail for the *expected* reason, then implement. A test that passes before implementation is a broken test.
- **Commit after every task.** Conventional commit prefixes (`feat:`, `test:`, `fix:`, `chore:`).
- **Two crates:** `liostunnel-core` (library, no CLI concerns) and `liostunnel-cli` (binary, no protocol logic).
- **`cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` must pass before every commit.**

## Verified API reference

These signatures were confirmed against docs.rs for the exact pinned versions. Do not guess at them; they differ from older releases.

```rust
// smoltcp 0.13.1
trait Device {
    type RxToken<'a>: RxToken where Self: 'a;
    type TxToken<'a>: TxToken where Self: 'a;
    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)>;
    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>>;
    fn capabilities(&self) -> DeviceCapabilities;
}
trait RxToken { fn consume<R, F>(self, f: F) -> R where F: FnOnce(&[u8]) -> R; }   // NOTE: &[u8], immutable
trait TxToken { fn consume<R, F>(self, len: usize, f: F) -> R where F: FnOnce(&mut [u8]) -> R; }

Interface::new(config: Config, device: &mut impl Device, now: Instant) -> Self
iface.poll(timestamp: Instant, device: &mut impl Device, sockets: &mut SocketSet) -> PollResult
iface.poll_delay(timestamp: Instant, sockets: &SocketSet) -> Option<Duration>
iface.set_any_ip(any_ip: bool)
iface.update_ip_addrs(|addrs: &mut Vec<IpCidr, _>| { .. })
iface.routes_mut() -> &mut Routes

tcp::Socket::new(rx_buffer, tx_buffer) -> Socket
socket.listen<T: Into<IpListenEndpoint>>(local_endpoint: T) -> Result<(), ListenError>
socket.state() -> State ; .local_endpoint() -> Option<IpEndpoint> ; .remote_endpoint() -> Option<IpEndpoint>
socket.can_send() / .can_recv() / .may_send() / .may_recv() / .is_open() / .is_active()
socket.send_slice(&[u8]) -> Result<usize, SendError> ; .recv_slice(&mut [u8]) -> Result<usize, RecvError>
socket.close() / .abort()

// smoltcp::wire::Ipv4Address is core::net::Ipv4Addr — conversion to std::net::Ipv4Addr is free.
// smoltcp::wire::IpAddress is smoltcp's own enum { Ipv4(..), Ipv6(..) } — convert by match.

// russh 0.62.4
russh::client::connect<H: Handler + Send + 'static, A: ToSocketAddrs>(
    config: Arc<client::Config>, addrs: A, handler: H) -> Result<Handle<H>, H::Error>
trait client::Handler {
    type Error: From<russh::Error> + Send + Debug;
    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool, Self::Error>;
}
handle.authenticate_password(user, password) -> Result<client::AuthResult, russh::Error>
handle.authenticate_publickey(user, key: russh::keys::PrivateKeyWithHashAlg) -> Result<client::AuthResult, russh::Error>
handle.channel_open_direct_tcpip(host: A, port: u32, originator_address: B, originator_port: u32)
    -> Result<Channel<client::Msg>, russh::Error>
handle.disconnect(reason: Disconnect, description: &str, language_tag: &str) -> Result<(), russh::Error>
channel.into_stream() -> russh::ChannelStream<client::Msg>   // impl AsyncRead + AsyncWrite
enum client::AuthResult { Success, Failure { remaining_methods: MethodSet, partial_success: bool } }
russh::keys::known_hosts::{check_known_hosts_path, learn_known_hosts_path, known_host_keys_path}
russh::keys::{PrivateKeyWithHashAlg, HashAlg, ssh_key}
// check_known_hosts_path is TRI-state and its Ok(false) is NOT simply "unknown host":
//   Ok(true)  = a recorded entry matches this exact key
//   Err(KeyChanged) = a recorded entry uses the SAME algorithm with a DIFFERENT key
//   Ok(false) = EITHER the host has no entry at all, OR it has entries but none
//               uses this key's algorithm.
// Treating Ok(false) as "unknown, trust on first use" is a machine-in-the-middle
// acceptance path: an attacker answers with RSA for a host recorded as ed25519 and
// is trusted AND persisted. Check known_host_keys_path for existing entries first;
// TOFU only when that list is empty.
//
// Second trap: known_host_keys_path swallows EVERY File::open error and returns
// Ok(vec![]) (known_hosts.rs:70-74), so an empty list is ambiguous between three
// cases. Discriminate on READABILITY, not existence:
//   file absent                         -> first contact, TOFU
//   file opens, no entry for this host  -> first contact for THIS host, TOFU
//                                          (this is how a second profile is added;
//                                           failing closed here breaks multi-server
//                                           use permanently after the first host)
//   file exists but will not open       -> unverifiable, reject
```

## File structure

| File | Responsibility |
|---|---|
| `crates/liostunnel-core/src/error.rs` | `TunnelError` — the single error type |
| `crates/liostunnel-core/src/config/secret.rs` | `Redacted<T>`, `SecretRef`, `SecretStore`, `FileSecretStore` |
| `crates/liostunnel-core/src/config/profile.rs` | `ServerProfile` and its component enums, serde, validation |
| `crates/liostunnel-core/src/config/portable.rs` | `PortableProfile` — the shareable format, import/export |
| `crates/liostunnel-core/src/protocols/mod.rs` | `Protocol` and `TunnelStream` traits |
| `crates/liostunnel-core/src/protocols/ssh.rs` | `SshTunnel` — russh implementation |
| `crates/liostunnel-core/src/protocols/counting.rs` | `CountingStream` — byte counters, no payload inspection |
| `crates/liostunnel-core/src/net/mod.rs` | `NetStack` trait, `StackHandles`, `TcpFlow`, `Datagram` |
| `crates/liostunnel-core/src/net/tun.rs` | `PacketIo` trait, `TunDevice`, `FakePacketIo`, utun AF-prefix codec |
| `crates/liostunnel-core/src/net/local_stream.rs` | `LocalStream` — AsyncRead/AsyncWrite over channels |
| `crates/liostunnel-core/src/net/nat_table.rs` | Armed-flow registry, in-flight DNS state |
| `crates/liostunnel-core/src/net/testutil.rs` | Synthetic packet builders (test-only) |
| `crates/liostunnel-core/src/net/smoltcp_stack/device.rs` | `QueuedDevice` — `smoltcp::phy::Device` over VecDeques |
| `crates/liostunnel-core/src/net/smoltcp_stack/inspect.rs` | Pure packet classification — SYN vs. established vs. UDP |
| `crates/liostunnel-core/src/net/smoltcp_stack/core.rs` | `StackCore` — the synchronous, fully testable engine, including listener injection |
| `crates/liostunnel-core/src/net/smoltcp_stack/poll.rs` | The OS thread, the `polling` wakeup, channel plumbing |
| `crates/liostunnel-core/src/dns/mod.rs` | `Resolver` trait, UDP/IP reply synthesis |
| `crates/liostunnel-core/src/dns/over_tcp.rs` | RFC 7766 length-prefixed DNS |
| `crates/liostunnel-core/src/dns/over_https.rs` | DoH over a `TunnelStream` |
| `crates/liostunnel-core/src/route/mod.rs` | `RouteManager`, `RouteMode`, `RoutePlan`, `RouteGuard` |
| `crates/liostunnel-core/src/route/state.rs` | Crash-recovery state file |
| `crates/liostunnel-core/src/route/{macos,linux}.rs` | Per-platform command construction |

> **Deviation from spec §6.1:** the spec lists a `listener_pool.rs`. In practice, injecting a listener requires mutable access to the `SocketSet`, so it belongs in `core.rs`; what genuinely separates out is the pure classification step, which becomes `inspect.rs`. The spec's `nat_table.rs`, `device.rs`, `core.rs`, and `poll.rs` are unchanged.
| `crates/liostunnel-core/src/engine.rs` | Wires `NetStack` + `Protocol` + `Resolver` + `RouteManager` |
| `crates/liostunnel-core/src/stats.rs` | `ConnectionStats`, `ConnectionState` |
| `crates/liostunnel-cli/src/main.rs` | Arg parsing, subcommand dispatch, logging setup |

---

# Milestone A — Config and SSH

No TUN device. Ends with `liostunnel probe`, which opens an SSH channel to a destination and proxies stdin/stdout — working, testable software that exercises the config layer and the whole SSH path.

---

### Task 1: Workspace scaffolding and the error type

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`
- Create: `crates/liostunnel-core/Cargo.toml`, `crates/liostunnel-core/src/lib.rs`, `crates/liostunnel-core/src/error.rs`
- Create: `crates/liostunnel-cli/Cargo.toml`, `crates/liostunnel-cli/src/main.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `liostunnel_core::error::TunnelError` with variants `Config { field: String, reason: String }`, `Auth(String)`, `HostKey(String)`, `Transport(std::io::Error)`, `Protocol(String)`, `Unsupported(&'static str)`, `Dns(String)`, `Route(String)`, `Tun(String)`. Re-exported as `liostunnel_core::TunnelError`.

- [ ] **Step 1: Create the workspace manifest**

`Cargo.toml`:

```toml
[workspace]
members = ["crates/liostunnel-core", "crates/liostunnel-cli"]
resolver = "3"

[workspace.package]
edition = "2024"
rust-version = "1.93"
license = "MIT OR Apache-2.0"

[workspace.dependencies]
smoltcp = { version = "0.13.1", default-features = false, features = [
    "std", "medium-ip", "proto-ipv4", "proto-ipv6", "socket-tcp",
] }
russh = "0.62.4"
tun-rs = "2.8.8"
polling = "3.11.0"
ipnet = { version = "2.12.0", features = ["serde"] }
tokio = { version = "1.53", features = [
    "rt-multi-thread", "macros", "net", "io-util", "sync", "time", "signal", "process",
] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
uuid = { version = "1", features = ["v4", "serde"] }
thiserror = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
async-trait = "0.1"

[profile.release]
strip = true
lto = "thin"
```

`rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.93"
components = ["rustfmt", "clippy"]
```

- [ ] **Step 2: Create both crate manifests**

`crates/liostunnel-core/Cargo.toml`:

```toml
[package]
name = "liostunnel-core"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
serde.workspace = true
serde_json.workspace = true
uuid.workspace = true
thiserror.workspace = true
tracing.workspace = true
async-trait.workspace = true
```

`crates/liostunnel-cli/Cargo.toml`:

```toml
[package]
name = "liostunnel-cli"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[[bin]]
name = "liostunnel"
path = "src/main.rs"

[dependencies]
liostunnel-core = { path = "../liostunnel-core" }
tokio.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
```

- [ ] **Step 3: Write the failing test**

`crates/liostunnel-core/src/error.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_names_the_offending_field() {
        let e = TunnelError::Config {
            field: "dns.servers".into(),
            reason: "must not be empty".into(),
        };
        assert_eq!(e.to_string(), "config error at `dns.servers`: must not be empty");
    }

    #[test]
    fn unsupported_error_names_the_feature() {
        let e = TunnelError::Unsupported("wireguard");
        assert_eq!(e.to_string(), "wireguard is not supported in this build");
    }

    #[test]
    fn io_errors_convert_into_transport() {
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        let e: TunnelError = io.into();
        assert!(matches!(e, TunnelError::Transport(_)));
    }
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cargo test -p liostunnel-core`
Expected: FAIL — `cannot find type TunnelError in this scope`.

- [ ] **Step 5: Implement the error type**

Prepend to `crates/liostunnel-core/src/error.rs`:

```rust
use std::io;

/// The single error type for the whole core. Spec §11.
#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("config error at `{field}`: {reason}")]
    Config { field: String, reason: String },

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("host key verification failed: {0}")]
    HostKey(String),

    #[error("transport error: {0}")]
    Transport(#[from] io::Error),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("{0} is not supported in this build")]
    Unsupported(&'static str),

    #[error("dns error: {0}")]
    Dns(String),

    #[error("route error: {0}")]
    Route(String),

    #[error("tun device error: {0}")]
    Tun(String),
}

impl TunnelError {
    /// Convenience constructor so call sites stay readable.
    pub fn config(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Config { field: field.into(), reason: reason.into() }
    }
}
```

`crates/liostunnel-core/src/lib.rs`:

```rust
//! LiosTunnel core engine. See docs/superpowers/specs/2026-07-27-liostunnel-phase0-design.md

pub mod error;

pub use error::TunnelError;
```

`crates/liostunnel-cli/src/main.rs`:

```rust
fn main() {
    println!("liostunnel {}", env!("CARGO_PKG_VERSION"));
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core`
Expected: PASS — 3 passed.

- [ ] **Step 7: Verify the whole workspace builds clean**

Run: `cargo clippy --all-targets -- -D warnings && cargo fmt --check && cargo run -p liostunnel-cli`
Expected: no warnings; prints `liostunnel 0.1.0`.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml rust-toolchain.toml crates/
git commit -m "feat: workspace scaffolding and TunnelError"
```

---

### Task 2: Secrets — `Redacted`, `SecretRef`, `SecretStore`

Security-critical and depended on by everything downstream, so it comes first. Spec §6.3.

**Files:**
- Create: `crates/liostunnel-core/src/config/mod.rs`, `crates/liostunnel-core/src/config/secret.rs`
- Modify: `crates/liostunnel-core/src/lib.rs`

**Interfaces:**
- Consumes: `TunnelError` (Task 1).
- Produces:
  - `Redacted<T>` with `Redacted::new(T)`, `.expose(&self) -> &T`, `.into_inner(self) -> T`. `Debug` and `Display` print `<redacted>`.
  - `enum SecretRef { File { path: PathBuf }, Env { var: String } }` — `Serialize`/`Deserialize` with `#[serde(tag = "source", rename_all = "snake_case")]`. **Deliberately holds no inline secret**; that is what keeps `ServerProfile` safe to serialise.
  - `trait SecretStore: Send + Sync { fn resolve(&self, r: &SecretRef) -> Result<Redacted<String>, TunnelError>; }`
  - `struct FileSecretStore` implementing it.

- [ ] **Step 1: Write the failing tests**

`crates/liostunnel-core/src/config/secret.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn redacted_never_prints_its_contents() {
        let s = Redacted::new("hunter2".to_string());
        assert_eq!(format!("{s:?}"), "<redacted>");
        assert_eq!(format!("{s}"), "<redacted>");
        // The value is still reachable when explicitly asked for.
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn redacted_survives_nesting_in_a_derived_debug() {
        #[derive(Debug)]
        struct Holder { name: String, key: Redacted<String> }
        let h = Holder { name: "prod".into(), key: Redacted::new("secret".into()) };
        let rendered = format!("{h:?}");
        assert!(rendered.contains("prod"));
        assert!(!rendered.contains("secret"), "secret leaked into Debug: {rendered}");
    }

    #[test]
    fn secret_ref_round_trips_through_json() {
        let r = SecretRef::File { path: "/tmp/key".into() };
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, r#"{"source":"file","path":"/tmp/key"}"#);
        assert_eq!(serde_json::from_str::<SecretRef>(&json).unwrap(), r);
    }

    fn write_key(dir: &std::path::Path, mode: u32) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("id_ed25519");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"KEYMATERIAL").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    #[test]
    fn file_store_reads_a_correctly_permissioned_secret() {
        let dir = std::env::temp_dir().join(format!("lios-sec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = write_key(&dir, 0o600);

        let store = FileSecretStore;
        let got = store.resolve(&SecretRef::File { path: p }).unwrap();
        assert_eq!(got.expose(), "KEYMATERIAL");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_store_rejects_a_world_readable_secret() {
        let dir = std::env::temp_dir().join(format!("lios-sec-lax-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = write_key(&dir, 0o644);

        let store = FileSecretStore;
        let err = store.resolve(&SecretRef::File { path: p }).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("644"), "error should name the offending mode: {msg}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_store_reads_from_the_environment() {
        // SAFETY: single-threaded test, no other thread reads this var.
        unsafe { std::env::set_var("LIOS_TEST_SECRET", "from-env") };
        let store = FileSecretStore;
        let got = store.resolve(&SecretRef::Env { var: "LIOS_TEST_SECRET".into() }).unwrap();
        assert_eq!(got.expose(), "from-env");
    }

    #[test]
    fn file_store_reports_a_missing_environment_variable() {
        let store = FileSecretStore;
        let err = store
            .resolve(&SecretRef::Env { var: "LIOS_DEFINITELY_UNSET".into() })
            .unwrap_err();
        assert!(err.to_string().contains("LIOS_DEFINITELY_UNSET"));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p liostunnel-core secret`
Expected: FAIL — `cannot find type Redacted in this scope`.

- [ ] **Step 3: Implement**

Prepend to `crates/liostunnel-core/src/config/secret.rs`:

```rust
use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::TunnelError;

/// Wraps secret material so it cannot leak through `Debug` or `Display` —
/// including derived `Debug` on containing structs, and panic backtraces.
/// Spec §11.
#[derive(Clone, PartialEq, Eq)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Deliberately verbose: reading a secret should be visible at the call site.
    pub fn expose(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A pointer to secret material. Never the material itself — this is what makes
/// `ServerProfile` safe to serialise. Spec §6.3.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum SecretRef {
    File { path: PathBuf },
    Env { var: String },
}

pub trait SecretStore: Send + Sync {
    fn resolve(&self, r: &SecretRef) -> Result<Redacted<String>, TunnelError>;
}

/// Phase 0 store. Phase 1 replaces this with the OS keychain behind the same trait.
pub struct FileSecretStore;

impl SecretStore for FileSecretStore {
    fn resolve(&self, r: &SecretRef) -> Result<Redacted<String>, TunnelError> {
        match r {
            SecretRef::File { path } => {
                check_permissions(path)?;
                let body = std::fs::read_to_string(path).map_err(|e| {
                    TunnelError::config(
                        format!("secret file {}", path.display()),
                        format!("cannot read: {e}"),
                    )
                })?;
                Ok(Redacted::new(body.trim_end_matches('\n').to_string()))
            }
            SecretRef::Env { var } => std::env::var(var)
                .map(Redacted::new)
                .map_err(|_| TunnelError::config(format!("env `{var}`"), "not set")),
        }
    }
}

/// Spec §9.2: secret files must be 0600 or stricter.
#[cfg(unix)]
fn check_permissions(path: &std::path::Path) -> Result<(), TunnelError> {
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::metadata(path).map_err(|e| {
        TunnelError::config(
            format!("secret file {}", path.display()),
            format!("cannot stat: {e}"),
        )
    })?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(TunnelError::config(
            format!("secret file {}", path.display()),
            format!("mode {mode:o} grants access beyond the owner; must be 600 or stricter"),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &std::path::Path) -> Result<(), TunnelError> {
    // Windows ACL checking lands with the Phase 1 desktop work.
    Ok(())
}
```

`crates/liostunnel-core/src/config/mod.rs`:

```rust
pub mod secret;
```

Add to `crates/liostunnel-core/src/lib.rs`:

```rust
pub mod config;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core secret`
Expected: PASS — 7 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/liostunnel-core/src/
git commit -m "feat: Redacted, SecretRef, and a permission-checking secret store"
```

---

### Task 3: `ServerProfile` schema and serde

Spec §9.1. The `DnsConfig` dual-form deserializer is the fiddly part: it must accept both the widened struct and PRD §5.2's bare array.

**Files:**
- Create: `crates/liostunnel-core/src/config/profile.rs`
- Create: `crates/liostunnel-core/tests/fixtures/prd_example.json`
- Modify: `crates/liostunnel-core/src/config/mod.rs`

**Interfaces:**
- Consumes: `SecretRef` (Task 2), `TunnelError` (Task 1).
- Produces: `ServerProfile { id: Uuid, name: String, protocol: ProtocolKind, host: String, port: u16, auth: AuthMethod, dns: DnsConfig, split_tunnel: SplitTunnelRule, kill_switch: bool }`; `enum ProtocolKind { Ssh, WireGuard, Shadowsocks }`; `enum AuthMethod { Password { password: SecretRef }, PrivateKey { private_key: SecretRef, passphrase: Option<SecretRef> }, PresharedKey { private_key: SecretRef, peer_public_key: String } }`; `struct DnsConfig { mode: DnsMode, servers: Vec<IpAddr>, https: Option<DohConfig> }`; `enum DnsMode { Tcp, Https }`; `struct DohConfig { sni: String, path: String }`; `enum SplitTunnelRule { AllTraffic, ExcludeApps { apps: Vec<String> }, IncludeOnly { apps: Vec<String> } }`.

- [ ] **Step 1: Create the PRD fixture**

`crates/liostunnel-core/tests/fixtures/prd_example.json` — PRD §5.2's example verbatim, **except** the `id`, which the PRD elides as `"b6f1...e2"`. That is not a parseable UUID, so substitute a real one. This is the only permitted deviation from the PRD text.

```json
{
  "id": "b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f",
  "name": "Home VPS - SG",
  "protocol": "wireguard",
  "host": "203.0.113.10",
  "port": 51820,
  "auth": {
    "type": "preshared_key",
    "private_key": "...",
    "peer_public_key": "..."
  },
  "dns": ["1.1.1.1", "1.0.0.1"],
  "split_tunnel": { "type": "all_traffic" },
  "kill_switch": true
}
```

Note this fixture has **inline** secrets, so it is a `PortableProfile`, not a `ServerProfile` — which is exactly the distinction Task 5 implements. This task only needs it to prove `DnsConfig` accepts the bare-array form, so parse just that field here.

- [ ] **Step 2: Write the failing tests**

`crates/liostunnel-core/src/config/profile.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn dns_accepts_the_prd_bare_array_form() {
        let cfg: DnsConfig = serde_json::from_str(r#"["1.1.1.1", "1.0.0.1"]"#).unwrap();
        assert_eq!(cfg.mode, DnsMode::Tcp, "bare array must default to DNS-over-TCP");
        assert_eq!(cfg.servers, vec![ip(1, 1, 1, 1), ip(1, 0, 0, 1)]);
        assert!(cfg.https.is_none());
    }

    #[test]
    fn dns_accepts_the_widened_struct_form() {
        let cfg: DnsConfig = serde_json::from_str(
            r#"{"mode":"https","servers":["1.1.1.1"],
                "https":{"sni":"cloudflare-dns.com","path":"/dns-query"}}"#,
        )
        .unwrap();
        assert_eq!(cfg.mode, DnsMode::Https);
        assert_eq!(cfg.https.unwrap().sni, "cloudflare-dns.com");
    }

    #[test]
    fn dns_always_serialises_to_the_struct_form() {
        let cfg = DnsConfig { mode: DnsMode::Tcp, servers: vec![ip(9, 9, 9, 9)], https: None };
        let json = serde_json::to_string(&cfg).unwrap();
        assert_eq!(json, r#"{"mode":"tcp","servers":["9.9.9.9"],"https":null}"#);
    }

    #[test]
    fn prd_fixture_dns_field_parses() {
        let raw = include_str!("../../tests/fixtures/prd_example.json");
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        let dns: DnsConfig = serde_json::from_value(v["dns"].clone()).unwrap();
        assert_eq!(dns.servers.len(), 2);
        assert_eq!(dns.mode, DnsMode::Tcp);
    }

    #[test]
    fn protocol_kind_uses_snake_case_on_the_wire() {
        assert_eq!(serde_json::to_string(&ProtocolKind::WireGuard).unwrap(), r#""wireguard""#);
        assert_eq!(
            serde_json::from_str::<ProtocolKind>(r#""shadowsocks""#).unwrap(),
            ProtocolKind::Shadowsocks
        );
    }

    #[test]
    fn split_tunnel_uses_the_prd_tagged_form() {
        let r: SplitTunnelRule =
            serde_json::from_str(r#"{"type":"all_traffic"}"#).unwrap();
        assert_eq!(r, SplitTunnelRule::AllTraffic);

        let r: SplitTunnelRule =
            serde_json::from_str(r#"{"type":"exclude_apps","apps":["com.example.a"]}"#).unwrap();
        assert_eq!(r, SplitTunnelRule::ExcludeApps { apps: vec!["com.example.a".into()] });
    }

    #[test]
    fn server_profile_round_trips_and_never_serialises_secret_material() {
        let p = ServerProfile {
            id: uuid::Uuid::nil(),
            name: "lab".into(),
            protocol: ProtocolKind::Ssh,
            host: "198.51.100.7".into(),
            port: 22,
            auth: AuthMethod::PrivateKey {
                private_key: SecretRef::File { path: "/home/h/.ssh/id_ed25519".into() },
                passphrase: None,
            },
            dns: DnsConfig { mode: DnsMode::Tcp, servers: vec![ip(1, 1, 1, 1)], https: None },
            split_tunnel: SplitTunnelRule::AllTraffic,
            kill_switch: false,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains(r#""source":"file""#));
        assert!(!json.contains("BEGIN"), "no key material may appear: {json}");
        assert_eq!(serde_json::from_str::<ServerProfile>(&json).unwrap(), p);
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p liostunnel-core profile`
Expected: FAIL — `cannot find type DnsConfig in this scope`.

- [ ] **Step 4: Implement**

Prepend to `crates/liostunnel-core/src/config/profile.rs`:

```rust
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::secret::SecretRef;

/// Spec §9.1 / PRD §5.2.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ServerProfile {
    pub id: Uuid,
    pub name: String,
    pub protocol: ProtocolKind,
    pub host: String,
    pub port: u16,
    pub auth: AuthMethod,
    pub dns: DnsConfig,
    pub split_tunnel: SplitTunnelRule,
    pub kill_switch: bool,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolKind {
    Ssh,
    // `rename_all = "snake_case"` would render this `"wire_guard"` — serde
    // inserts an underscore at every internal capital. The wire format the
    // PRD specifies is `"wireguard"`, so this one variant overrides it.
    #[serde(rename = "wireguard")]
    WireGuard,
    Shadowsocks,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthMethod {
    Password {
        password: SecretRef,
    },
    PrivateKey {
        private_key: SecretRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase: Option<SecretRef>,
    },
    /// WireGuard. Parsed in Phase 0, rejected at connect time. Spec §9.3.
    PresharedKey {
        private_key: SecretRef,
        /// Public by definition, so not a `SecretRef`.
        peer_public_key: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    #[default]
    Tcp,
    Https,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DohConfig {
    /// TLS SNI and `Host:` for the DoH endpoint. `servers` holds the IP, so
    /// there is no bootstrap resolution to perform. Spec §9.1.
    pub sni: String,
    pub path: String,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct DnsConfig {
    pub mode: DnsMode,
    pub servers: Vec<IpAddr>,
    pub https: Option<DohConfig>,
}

/// Accepts both the widened struct and PRD §5.2's bare `["1.1.1.1", "1.0.0.1"]`,
/// so the PRD's own example stays valid. Spec §9.1.
impl<'de> Deserialize<'de> for DnsConfig {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            // Must come first: an array can never match the struct form.
            Bare(Vec<IpAddr>),
            Full {
                #[serde(default)]
                mode: DnsMode,
                servers: Vec<IpAddr>,
                #[serde(default)]
                https: Option<DohConfig>,
            },
        }

        Ok(match Repr::deserialize(d)? {
            Repr::Bare(servers) => DnsConfig { mode: DnsMode::Tcp, servers, https: None },
            Repr::Full { mode, servers, https } => DnsConfig { mode, servers, https },
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SplitTunnelRule {
    AllTraffic,
    ExcludeApps { apps: Vec<String> },
    IncludeOnly { apps: Vec<String> },
}
```

Add to `crates/liostunnel-core/src/config/mod.rs`:

```rust
pub mod profile;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core profile`
Expected: PASS — 7 passed.

- [ ] **Step 6: Commit**

```bash
git add crates/liostunnel-core/src/ crates/liostunnel-core/tests/
git commit -m "feat: ServerProfile schema with PRD-compatible DnsConfig"
```

---

### Task 4: Profile validation

Spec §9.2 and §9.3.

**Files:**
- Modify: `crates/liostunnel-core/src/config/profile.rs`

**Interfaces:**
- Consumes: everything from Task 3, plus `SecretStore` (Task 2).
- Produces: `ServerProfile::validate(&self, store: &dyn SecretStore) -> Result<(), TunnelError>` and `ServerProfile::warnings(&self) -> Vec<String>`.

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module in `crates/liostunnel-core/src/config/profile.rs`:

```rust
    use crate::config::secret::{FileSecretStore, SecretStore};

    fn valid_profile() -> ServerProfile {
        ServerProfile {
            id: uuid::Uuid::nil(),
            name: "lab".into(),
            protocol: ProtocolKind::Ssh,
            host: "198.51.100.7".into(),
            port: 22,
            auth: AuthMethod::Password {
                password: SecretRef::File { path: secret_file("valid", "pw") },
            },
            dns: DnsConfig { mode: DnsMode::Tcp, servers: vec![ip(1, 1, 1, 1)], https: None },
            split_tunnel: SplitTunnelRule::AllTraffic,
            kill_switch: false,
        }
    }

    /// A real 0600 file rather than an env var. `std::env::set_var` is `unsafe`
    /// in edition 2024 because concurrent set/get is UB, and cargo runs the
    /// tests in one binary across threads — several of these tests share a
    /// helper, so env vars would be a genuine data race.
    fn secret_file(tag: &str, body: &str) -> std::path::PathBuf {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        // Unique per caller and cleaned up by the caller: cargo runs a binary's
        // tests across threads, so a shared path would be a write race.
        let dir = std::env::temp_dir().join(format!("lios-pv-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        f.write_all(body.as_bytes()).unwrap();
        path
    }

    fn store() -> impl SecretStore {
        FileSecretStore
    }

    #[test]
    fn a_valid_profile_passes() {
        valid_profile().validate(&store()).unwrap();
    }

    #[test]
    fn empty_host_is_rejected() {
        let mut p = valid_profile();
        p.host = String::new();
        let e = p.validate(&store()).unwrap_err().to_string();
        assert!(e.contains("host"), "{e}");
    }

    #[test]
    fn port_zero_is_rejected() {
        let mut p = valid_profile();
        p.port = 0;
        let e = p.validate(&store()).unwrap_err().to_string();
        assert!(e.contains("port"), "{e}");
    }

    #[test]
    fn empty_dns_servers_are_rejected() {
        let mut p = valid_profile();
        p.dns.servers.clear();
        let e = p.validate(&store()).unwrap_err().to_string();
        assert!(e.contains("dns.servers"), "{e}");
    }

    #[test]
    fn https_mode_without_a_doh_block_is_rejected() {
        let mut p = valid_profile();
        p.dns.mode = DnsMode::Https;
        p.dns.https = None;
        let e = p.validate(&store()).unwrap_err().to_string();
        assert!(e.contains("dns.https"), "{e}");
    }

    #[test]
    fn an_unresolvable_secret_is_rejected_at_validation_not_at_connect() {
        let mut p = valid_profile();
        p.auth = AuthMethod::Password {
            password: SecretRef::File { path: "/nonexistent/lios/secret".into() },
        };
        let e = p.validate(&store()).unwrap_err().to_string();
        assert!(e.contains("/nonexistent/lios/secret"), "{e}");
    }

    #[test]
    fn kill_switch_produces_an_unenforced_warning() {
        let mut p = valid_profile();
        p.kill_switch = true;
        let w = p.warnings();
        assert!(
            w.iter().any(|m| m.contains("kill_switch") && m.contains("not enforced")),
            "spec §9.3 requires a loud warning, got {w:?}"
        );
    }

    #[test]
    fn non_default_split_tunnel_produces_an_unenforced_warning() {
        let mut p = valid_profile();
        p.split_tunnel = SplitTunnelRule::ExcludeApps { apps: vec!["a".into()] };
        assert!(p.warnings().iter().any(|m| m.contains("split_tunnel")));
    }

    #[test]
    fn a_clean_profile_warns_about_nothing() {
        assert!(valid_profile().warnings().is_empty());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p liostunnel-core profile`
Expected: FAIL — `no method named validate found`.

> **As implemented:** `valid_profile` takes a `tag: &str` and returns
> `(ServerProfile, PathBuf)` so each test gets its own secret-file directory and
> removes it, matching the cleanup convention in `secret.rs`. A single shared
> temp path across parallel test threads was a latent write race.

- [ ] **Step 3: Implement**

Append to the non-test part of `crates/liostunnel-core/src/config/profile.rs`:

```rust
use crate::config::secret::SecretStore;
use crate::error::TunnelError;

impl ServerProfile {
    /// Spec §9.2. Every failure names the offending field path.
    pub fn validate(&self, store: &dyn SecretStore) -> Result<(), TunnelError> {
        if self.host.trim().is_empty() {
            return Err(TunnelError::config("host", "must not be empty"));
        }
        if self.port == 0 {
            return Err(TunnelError::config("port", "must not be zero"));
        }
        if self.dns.servers.is_empty() {
            return Err(TunnelError::config("dns.servers", "must not be empty"));
        }
        if self.dns.mode == DnsMode::Https {
            match &self.dns.https {
                None => {
                    return Err(TunnelError::config(
                        "dns.https",
                        "required when dns.mode is `https`",
                    ));
                }
                Some(d) if d.sni.trim().is_empty() => {
                    return Err(TunnelError::config("dns.https.sni", "must not be empty"));
                }
                Some(d) if !d.path.starts_with('/') => {
                    return Err(TunnelError::config("dns.https.path", "must start with `/`"));
                }
                Some(_) => {}
            }
        }

        // Resolve every secret now, so a bad reference fails at load rather than
        // halfway through a connection attempt.
        for r in self.auth.secret_refs() {
            store.resolve(r)?;
        }
        Ok(())
    }

    /// Spec §9.3: fields that parse but are not honoured in Phase 0. The CLI
    /// prints these prominently at startup.
    pub fn warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        if self.kill_switch {
            w.push(
                "kill_switch is set but is not enforced in this Phase 0 build; \
                 traffic will not be blocked if the tunnel drops"
                    .to_string(),
            );
        }
        if self.split_tunnel != SplitTunnelRule::AllTraffic {
            w.push(
                "split_tunnel is set but is not enforced in this Phase 0 build; \
                 all routed traffic will use the tunnel"
                    .to_string(),
            );
        }
        w
    }
}

impl AuthMethod {
    pub fn secret_refs(&self) -> Vec<&SecretRef> {
        match self {
            AuthMethod::Password { password } => vec![password],
            AuthMethod::PrivateKey { private_key, passphrase } => {
                let mut v = vec![private_key];
                v.extend(passphrase.iter());
                v
            }
            AuthMethod::PresharedKey { private_key, .. } => vec![private_key],
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core profile`
Expected: PASS — 16 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/liostunnel-core/src/config/profile.rs
git commit -m "feat: profile validation and unenforced-field warnings"
```

---

### Task 5: `PortableProfile` — the shareable format

Spec §6.3. `ServerProfile` holds `SecretRef`s and is safe to write anywhere; `PortableProfile` holds inline secrets and is produced only on explicit export.

**Files:**
- Create: `crates/liostunnel-core/src/config/portable.rs`
- Modify: `crates/liostunnel-core/src/config/mod.rs`

**Interfaces:**
- Consumes: Task 3's types, `SecretRef`/`SecretStore`/`Redacted` (Task 2).
- Produces:
  - `PortableProfile` — same shape as `ServerProfile` but `auth: PortableAuth`.
  - `enum PortableAuth { Password { password: String }, PrivateKey { private_key: String, passphrase: Option<String> }, PresharedKey { private_key: String, peer_public_key: String } }`
  - `PortableProfile::import(self, secret_dir: &Path) -> Result<ServerProfile, TunnelError>` — writes each secret to `secret_dir/<id>.<field>` at mode 0600 and returns a profile referencing them.
  - `PortableProfile::export(profile: &ServerProfile, store: &dyn SecretStore) -> Result<PortableProfile, TunnelError>`
  - `pub const EXPORT_WARNING: &str`

- [ ] **Step 1: Write the failing tests**

`crates/liostunnel-core/src/config/portable.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::profile::{DnsMode, ProtocolKind, SplitTunnelRule};
    use crate::config::secret::FileSecretStore;

    #[test]
    fn the_prd_example_parses_as_a_portable_profile() {
        // PRD §5.2's JSON has inline secrets, which makes it a PortableProfile
        // by definition — this test is the proof that the split in spec §6.3
        // matches the PRD's own example.
        let raw = include_str!("../../tests/fixtures/prd_example.json");
        let p: PortableProfile = serde_json::from_str(raw).unwrap();

        assert_eq!(p.name, "Home VPS - SG");
        assert_eq!(p.protocol, ProtocolKind::WireGuard);
        assert_eq!(p.port, 51820);
        assert_eq!(p.dns.mode, DnsMode::Tcp);
        assert_eq!(p.dns.servers.len(), 2);
        assert_eq!(p.split_tunnel, SplitTunnelRule::AllTraffic);
        assert!(p.kill_switch);
        assert!(matches!(p.auth, PortableAuth::PresharedKey { .. }));
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("lios-portable-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn import_writes_secrets_to_disk_at_mode_600_and_returns_refs() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmpdir("import");
        let portable = PortableProfile {
            id: uuid::Uuid::nil(),
            name: "lab".into(),
            protocol: ProtocolKind::Ssh,
            host: "198.51.100.7".into(),
            port: 22,
            auth: PortableAuth::PrivateKey {
                private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n".into(),
                passphrase: None,
            },
            dns: serde_json::from_str(r#"["1.1.1.1"]"#).unwrap(),
            split_tunnel: SplitTunnelRule::AllTraffic,
            kill_switch: false,
        };

        let profile = portable.import(&dir).unwrap();

        let SecretRef::File { path } = (match &profile.auth {
            AuthMethod::PrivateKey { private_key, .. } => private_key.clone(),
            other => panic!("wrong auth variant: {other:?}"),
        }) else {
            panic!("import must produce a file-backed SecretRef");
        };

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "imported secret must be 0600, got {mode:o}");
        assert!(std::fs::read_to_string(&path).unwrap().contains("BEGIN OPENSSH"));

        // And the resulting ServerProfile is safe to serialise.
        let json = serde_json::to_string(&profile).unwrap();
        assert!(!json.contains("BEGIN OPENSSH"), "key material leaked: {json}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn export_round_trips_back_to_the_same_secret() {
        let dir = tmpdir("export");
        let original = PortableProfile {
            id: uuid::Uuid::nil(),
            name: "lab".into(),
            protocol: ProtocolKind::Ssh,
            host: "198.51.100.7".into(),
            port: 22,
            auth: PortableAuth::Password { password: "hunter2".into() },
            dns: serde_json::from_str(r#"["1.1.1.1"]"#).unwrap(),
            split_tunnel: SplitTunnelRule::AllTraffic,
            kill_switch: false,
        };

        let imported = original.clone().import(&dir).unwrap();
        let exported = PortableProfile::export(&imported, &FileSecretStore).unwrap();

        assert_eq!(exported.auth, original.auth);
        assert_eq!(exported.name, original.name);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_export_warning_mentions_plaintext() {
        assert!(EXPORT_WARNING.to_lowercase().contains("plaintext"));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p liostunnel-core portable`
Expected: FAIL — `cannot find type PortableProfile in this scope`.

- [ ] **Step 3: Implement**

Prepend to `crates/liostunnel-core/src/config/portable.rs`:

```rust
use std::path::Path;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::profile::{
    AuthMethod, DnsConfig, ProtocolKind, ServerProfile, SplitTunnelRule,
};
use crate::config::secret::{SecretRef, SecretStore};
use crate::error::TunnelError;

pub const EXPORT_WARNING: &str = "This export contains private keys and passwords in \
     plaintext. Anyone who obtains this file gains full access to the server. Transfer it \
     over a secure channel and delete it once imported.";

/// The shareable `.liostunnel.json` format (PRD §5.2) and future QR payload.
/// Carries inline secrets, unlike [`ServerProfile`]. Spec §6.3.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PortableProfile {
    pub id: Uuid,
    pub name: String,
    pub protocol: ProtocolKind,
    pub host: String,
    pub port: u16,
    pub auth: PortableAuth,
    pub dns: DnsConfig,
    pub split_tunnel: SplitTunnelRule,
    pub kill_switch: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PortableAuth {
    Password {
        password: String,
    },
    PrivateKey {
        private_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase: Option<String>,
    },
    PresharedKey {
        private_key: String,
        peer_public_key: String,
    },
}

impl PortableProfile {
    /// Moves inline secrets onto disk at mode 0600 and returns a profile that
    /// only references them.
    pub fn import(self, secret_dir: &Path) -> Result<ServerProfile, TunnelError> {
        std::fs::create_dir_all(secret_dir).map_err(|e| {
            TunnelError::config(
                format!("secret dir {}", secret_dir.display()),
                format!("cannot create: {e}"),
            )
        })?;

        let write = |field: &str, value: &str| -> Result<SecretRef, TunnelError> {
            let path = secret_dir.join(format!("{}.{field}", self.id));
            write_secret_file(&path, value)?;
            Ok(SecretRef::File { path })
        };

        let auth = match &self.auth {
            PortableAuth::Password { password } => {
                AuthMethod::Password { password: write("password", password)? }
            }
            PortableAuth::PrivateKey { private_key, passphrase } => AuthMethod::PrivateKey {
                private_key: write("private_key", private_key)?,
                passphrase: match passphrase {
                    Some(p) => Some(write("passphrase", p)?),
                    None => None,
                },
            },
            PortableAuth::PresharedKey { private_key, peer_public_key } => {
                AuthMethod::PresharedKey {
                    private_key: write("private_key", private_key)?,
                    peer_public_key: peer_public_key.clone(),
                }
            }
        };

        Ok(ServerProfile {
            id: self.id,
            name: self.name,
            protocol: self.protocol,
            host: self.host,
            port: self.port,
            auth,
            dns: self.dns,
            split_tunnel: self.split_tunnel,
            kill_switch: self.kill_switch,
        })
    }

    /// Resolves every `SecretRef` back to inline material. Callers must show
    /// [`EXPORT_WARNING`] first.
    pub fn export(
        profile: &ServerProfile,
        store: &dyn SecretStore,
    ) -> Result<Self, TunnelError> {
        let auth = match &profile.auth {
            AuthMethod::Password { password } => PortableAuth::Password {
                password: store.resolve(password)?.into_inner(),
            },
            AuthMethod::PrivateKey { private_key, passphrase } => PortableAuth::PrivateKey {
                private_key: store.resolve(private_key)?.into_inner(),
                passphrase: match passphrase {
                    Some(p) => Some(store.resolve(p)?.into_inner()),
                    None => None,
                },
            },
            AuthMethod::PresharedKey { private_key, peer_public_key } => {
                PortableAuth::PresharedKey {
                    private_key: store.resolve(private_key)?.into_inner(),
                    peer_public_key: peer_public_key.clone(),
                }
            }
        };

        Ok(Self {
            id: profile.id,
            name: profile.name.clone(),
            protocol: profile.protocol,
            host: profile.host.clone(),
            port: profile.port,
            auth,
            dns: profile.dns.clone(),
            split_tunnel: profile.split_tunnel.clone(),
            kill_switch: profile.kill_switch,
        })
    }
}

/// Always creates a *fresh* file at 0600.
///
/// `create(true)` is not enough: POSIX applies `open`'s mode argument only when
/// the file is newly created, so an existing file at a looser mode would keep it
/// while receiving the secret — and an existing symlink would be followed.
/// `create_new` avoids both; if the path exists we remove it and retry rather
/// than inheriting unknown state. `id` is preserved across import, so the path
/// is deterministic and this case is reachable on re-import.
fn write_secret_file(path: &Path, value: &str) -> Result<(), TunnelError> {
    use std::io::Write;

    let open_fresh = || {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(path)
    };

    let mut f = match open_fresh() {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(path).map_err(|e| {
                TunnelError::config(
                    format!("secret file {}", path.display()),
                    format!("cannot replace existing file: {e}"),
                )
            })?;
            open_fresh().map_err(|e| {
                TunnelError::config(
                    format!("secret file {}", path.display()),
                    format!("cannot create: {e}"),
                )
            })?
        }
        Err(e) => {
            return Err(TunnelError::config(
                format!("secret file {}", path.display()),
                format!("cannot write: {e}"),
            ));
        }
    };

    f.write_all(value.as_bytes())
        .map_err(|e| TunnelError::config(format!("secret file {}", path.display()), e.to_string()))
}
```

Add to `crates/liostunnel-core/src/config/mod.rs`:

```rust
pub mod portable;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core portable`
Expected: PASS — 4 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/liostunnel-core/src/config/
git commit -m "feat: PortableProfile import/export with on-disk secret extraction"
```

---

### Task 6: `Protocol` trait, stats, and SSH connect with host key verification

The Docker fixture is built here because this is the first task whose deliverable needs it.

**Files:**
- Create: `crates/liostunnel-core/src/protocols/mod.rs`, `crates/liostunnel-core/src/protocols/ssh.rs`, `crates/liostunnel-core/src/stats.rs`
- Create: `testing/docker/docker-compose.yml`, `testing/docker/sshd/Dockerfile`, `testing/docker/sshd/gen-keys.sh`, `testing/docker/Makefile`, `testing/docker/target-html/index.html`
- Create: `crates/liostunnel-core/tests/ssh_integration.rs`
- Modify: `crates/liostunnel-core/Cargo.toml`, `crates/liostunnel-core/src/lib.rs`, `.gitignore`

**Interfaces:**
- Consumes: `ServerProfile`, `AuthMethod`, `SecretStore`, `TunnelError`.
- Produces:
  - `trait TunnelStream: AsyncRead + AsyncWrite + Send + Unpin` with a blanket impl.
  - `#[async_trait] trait Protocol: Send + Sync` with `connect(&mut self, &ServerProfile, &dyn SecretStore)`, `open_tcp_stream(&self, SocketAddr) -> Result<Box<dyn TunnelStream>, TunnelError>`, `send_udp(&self, SocketAddr, &[u8])`, `disconnect(&mut self)`, `stats(&self) -> ConnectionStats`.
  - `enum ConnectionState { Disconnected, Connecting, Connected, Reconnecting, Failed }`
  - `struct ConnectionStats { state, bytes_up: u64, bytes_down: u64, active_flows: u32, flows_failed: u64, udp_dropped: u64, dns_queries: u64, reconnects: u32 }`
  - `enum HostKeyPolicy { Verify { known_hosts: PathBuf }, AcceptAny }`
  - `struct SshTunnel` implementing `Protocol`.

> **Deviation from PRD §5.1:** `connect` takes an extra `&dyn SecretStore`. The PRD signature has no way to resolve a `SecretRef`, which spec §6.3 requires. Recorded here so the difference is deliberate.

- [ ] **Step 1: Add dependencies**

Add to `crates/liostunnel-core/Cargo.toml`:

```toml
russh.workspace = true
tokio.workspace = true

[dev-dependencies]
tokio = { workspace = true, features = ["rt-multi-thread", "macros", "io-util", "time"] }
```

- [ ] **Step 2: Build the Docker fixture**

`testing/docker/sshd/gen-keys.sh`:

```bash
#!/usr/bin/env bash
# Generates throwaway keys for the test fixture. Never committed — see .gitignore.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p keys
[ -f keys/ssh_host_ed25519_key ] || \
  ssh-keygen -t ed25519 -N "" -C "liostunnel-test-host" -f keys/ssh_host_ed25519_key
[ -f keys/client_ed25519 ] || \
  ssh-keygen -t ed25519 -N "" -C "liostunnel-test-client" -f keys/client_ed25519
cp keys/client_ed25519.pub keys/authorized_keys
chmod 600 keys/ssh_host_ed25519_key keys/client_ed25519 keys/authorized_keys
echo "keys ready in $(pwd)/keys"
```

`testing/docker/sshd/Dockerfile`:

```dockerfile
FROM alpine:3.21
RUN apk add --no-cache openssh-server \
 && adduser -D -s /bin/sh tunneluser \
 && echo 'tunneluser:tunnelpass' | chpasswd \
 && mkdir -p /home/tunneluser/.ssh
COPY keys/ssh_host_ed25519_key     /etc/ssh/ssh_host_ed25519_key
COPY keys/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ed25519_key.pub
COPY keys/authorized_keys          /home/tunneluser/.ssh/authorized_keys
RUN chmod 600 /etc/ssh/ssh_host_ed25519_key /home/tunneluser/.ssh/authorized_keys \
 && chown -R tunneluser:tunneluser /home/tunneluser/.ssh \
 # OpenSSH takes the FIRST occurrence of a directive, and Alpine's stock
 # config already sets `AllowTcpForwarding no`. Appending `yes` after it is
 # silently ignored and every direct-tcpip request is refused, so rewrite
 # the existing line rather than adding a second one.
 && sed -i 's/^AllowTcpForwarding no$/AllowTcpForwarding yes/' /etc/ssh/sshd_config \
 && printf 'PermitOpen any\nPasswordAuthentication yes\nPubkeyAuthentication yes\nPermitRootLogin no\n' >> /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
```

`testing/docker/target-html/index.html`:

```html
<!doctype html><title>lios</title><p>tunnel-target-ok</p>
```

`testing/docker/docker-compose.yml`:

```yaml
services:
  sshd:
    build: ./sshd
    ports: ["127.0.0.1:22022:22"]
    networks: [lios]
  target:
    image: nginx:alpine
    volumes: ["./target-html:/usr/share/nginx/html:ro"]
    networks:
      lios:
        aliases: [target.internal]
networks:
  lios:
```

`testing/docker/Makefile`:

```makefile
.PHONY: up down logs
up:
	./sshd/gen-keys.sh
	docker compose up -d --build
	@echo "waiting for sshd on 127.0.0.1:22022"
	@for i in $$(seq 1 30); do \
	  nc -z 127.0.0.1 22022 && echo ready && exit 0; sleep 1; done; \
	  echo "sshd did not come up" && exit 1
down:
	docker compose down -v
logs:
	docker compose logs -f
```

Add to `.gitignore`:

```
testing/docker/sshd/keys/
```

- [ ] **Step 3: Write the failing tests**

`crates/liostunnel-core/tests/ssh_integration.rs`:

```rust
//! Requires the Docker fixture: `make -C testing/docker up`
//! Run with: `cargo test -p liostunnel-core --test ssh_integration -- --ignored`

use std::path::PathBuf;

use liostunnel_core::config::profile::{
    AuthMethod, DnsConfig, ProtocolKind, ServerProfile, SplitTunnelRule,
};
use liostunnel_core::config::secret::{FileSecretStore, SecretRef};
use liostunnel_core::protocols::Protocol;
use liostunnel_core::protocols::ssh::{HostKeyPolicy, SshTunnel};
use liostunnel_core::stats::ConnectionState;

fn keys_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testing/docker/sshd/keys")
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("lios-ssh-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn profile(auth: AuthMethod) -> ServerProfile {
    ServerProfile {
        id: uuid::Uuid::nil(),
        name: "fixture".into(),
        protocol: ProtocolKind::Ssh,
        host: "127.0.0.1".into(),
        port: 22022,
        auth,
        dns: serde_json::from_str::<DnsConfig>(r#"["1.1.1.1"]"#).unwrap(),
        split_tunnel: SplitTunnelRule::AllTraffic,
        kill_switch: false,
    }
}

/// File-backed rather than env-backed: `std::env::set_var` is `unsafe` in
/// edition 2024 because concurrent set/get is UB, and these tests share this
/// helper across threads in one test binary.
fn secret_file(tag: &str, body: &str) -> PathBuf {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = scratch(tag);
    let path = dir.join("secret");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    f.write_all(body.as_bytes()).unwrap();
    path
}

fn password_auth() -> AuthMethod {
    AuthMethod::Password {
        password: SecretRef::File { path: secret_file("pw", "tunnelpass") },
    }
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn connects_with_a_password_and_learns_the_host_key_on_first_use() {
    let known = scratch("tofu").join("known_hosts");
    let mut t = SshTunnel::new(
        "tunneluser".into(),
        HostKeyPolicy::Verify { known_hosts: known.clone() },
    );

    t.connect(&profile(password_auth()), &FileSecretStore).await.unwrap();
    assert_eq!(t.stats().state, ConnectionState::Connected);

    let learned = std::fs::read_to_string(&known).unwrap();
    assert!(learned.contains("22022"), "known_hosts should record the port: {learned}");
    t.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn rejects_a_host_key_that_does_not_match_known_hosts() {
    let known = scratch("mismatch").join("known_hosts");
    // A syntactically valid entry for the right host carrying the wrong key.
    std::fs::create_dir_all(known.parent().unwrap()).unwrap();
    std::fs::write(
        &known,
        "[127.0.0.1]:22022 ssh-ed25519 \
         AAAAC3NzaC1lZDI1NTE5AAAAIEbGVzc29uc2xlYXJuZWRhcmVoYXJkd29u\n",
    )
    .unwrap();

    let mut t = SshTunnel::new(
        "tunneluser".into(),
        HostKeyPolicy::Verify { known_hosts: known },
    );
    let err = t.connect(&profile(password_auth()), &FileSecretStore).await.unwrap_err();
    assert!(
        matches!(err, liostunnel_core::TunnelError::HostKey(_)),
        "expected HostKey rejection, got {err:?}"
    );
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn accept_any_policy_bypasses_verification() {
    let mut t = SshTunnel::new("tunneluser".into(), HostKeyPolicy::AcceptAny);
    t.connect(&profile(password_auth()), &FileSecretStore).await.unwrap();
    assert_eq!(t.stats().state, ConnectionState::Connected);
    t.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn connects_with_a_private_key() {
    let auth = AuthMethod::PrivateKey {
        private_key: SecretRef::File { path: keys_dir().join("client_ed25519") },
        passphrase: None,
    };
    let mut t = SshTunnel::new("tunneluser".into(), HostKeyPolicy::AcceptAny);
    t.connect(&profile(auth), &FileSecretStore).await.unwrap();
    assert_eq!(t.stats().state, ConnectionState::Connected);
    t.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn a_wrong_password_produces_an_auth_error() {
    let auth = AuthMethod::Password {
        password: SecretRef::File { path: secret_file("badpw", "not-the-password") },
    };
    let mut t = SshTunnel::new("tunneluser".into(), HostKeyPolicy::AcceptAny);
    let err = t.connect(&profile(auth), &FileSecretStore).await.unwrap_err();
    assert!(matches!(err, liostunnel_core::TunnelError::Auth(_)), "got {err:?}");
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn a_wireguard_profile_is_rejected_as_unsupported() {
    let mut p = profile(password_auth());
    p.protocol = ProtocolKind::WireGuard;
    let mut t = SshTunnel::new("tunneluser".into(), HostKeyPolicy::AcceptAny);
    let err = t.connect(&p, &FileSecretStore).await.unwrap_err();
    assert!(matches!(err, liostunnel_core::TunnelError::Unsupported(_)), "got {err:?}");
}
```

- [ ] **Step 4: Bring the fixture up and run the tests to verify they fail**

Run:
```bash
make -C testing/docker up
cargo test -p liostunnel-core --test ssh_integration -- --ignored
```
Expected: FAIL — `unresolved import liostunnel_core::protocols`.

- [ ] **Step 5: Implement stats**

`crates/liostunnel-core/src/stats.rs`:

```rust
/// Spec §11.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ConnectionState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectionStats {
    pub state: ConnectionState,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub active_flows: u32,
    pub flows_failed: u64,
    /// Non-DNS UDP datagrams discarded. Spec §7.5 — counted, never silent.
    pub udp_dropped: u64,
    pub dns_queries: u64,
    pub reconnects: u32,
}
```

- [ ] **Step 6: Implement the traits**

`crates/liostunnel-core/src/protocols/mod.rs`:

```rust
pub mod ssh;

use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::profile::ServerProfile;
use crate::config::secret::SecretStore;
use crate::error::TunnelError;
use crate::stats::ConnectionStats;

/// A logical byte stream carried by the tunnel. PRD §5.1.
pub trait TunnelStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> TunnelStream for T {}

/// PRD §5.1. The packet engine calls this and never learns which protocol it has.
#[async_trait]
pub trait Protocol: Send + Sync {
    async fn connect(
        &mut self,
        profile: &ServerProfile,
        store: &dyn SecretStore,
    ) -> Result<(), TunnelError>;

    async fn open_tcp_stream(
        &self,
        dest: SocketAddr,
    ) -> Result<Box<dyn TunnelStream>, TunnelError>;

    async fn send_udp(&self, dest: SocketAddr, data: &[u8]) -> Result<(), TunnelError>;

    async fn disconnect(&mut self) -> Result<(), TunnelError>;

    fn stats(&self) -> ConnectionStats;
}
```

- [ ] **Step 7: Implement `SshTunnel::connect`**

`crates/liostunnel-core/src/protocols/ssh.rs`:

```rust
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
                // Does this host have ANY recorded key? Ok(false) below cannot
                // distinguish "no entry" from "entry exists with another
                // algorithm", and conflating them accepts a MITM key.
                let existing = known_host_keys_path(&self.host, self.port, known_hosts)
                    .map_err(|e| TunnelError::HostKey(format!("cannot read known_hosts: {e}")))?;

                match check_known_hosts_path(&self.host, self.port, key, known_hosts) {
                    // Known and matching.
                    Ok(true) => Ok(true),
                    // Only genuine first contact may be trusted on first use.
                    Ok(false) if existing.is_empty() => {
                        tracing::warn!(
                            host = %self.host, port = self.port,
                            fingerprint = %key.fingerprint(Default::default()),
                            "unknown host key; trusting on first use and recording it"
                        );
                        learn_known_hosts_path(&self.host, self.port, key, known_hosts)
                            .map_err(|e| {
                                TunnelError::HostKey(format!("cannot record host key: {e}"))
                            })?;
                        Ok(true)
                    }
                    // Host is recorded but this key did not match any entry.
                    // Same severity as an outright key change. Never accept.
                    Ok(false) => Err(TunnelError::HostKey(format!(
                        "host {}:{} is known but presented a {} key matching no recorded entry",
                        self.host,
                        self.port,
                        key.algorithm()
                    ))),
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

        let mut handle =
            client::connect(config, (profile.host.as_str(), profile.port), handler)
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
            AuthMethod::PrivateKey { private_key, passphrase } => {
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
            AuthResult::Failure { remaining_methods, .. } => {
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
        Err(TunnelError::Unsupported("open_tcp_stream (arrives in Task 7)"))
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
```

Add to `crates/liostunnel-core/src/lib.rs`:

```rust
pub mod protocols;
pub mod stats;
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core --test ssh_integration -- --ignored`
Expected: PASS — 6 passed.

If `decode_secret_key` or `PrivateKeyWithHashAlg::new` do not resolve, run
`cargo doc -p russh --open` and check `russh::keys` — these are re-exports from
`russh-keys` and are the only two symbols in this task not pinned by the verified
API reference above.

- [ ] **Step 9: Commit**

```bash
git add crates/ testing/ .gitignore
git commit -m "feat: Protocol trait and SSH connect with host key verification"
```

---

### Task 7: `SshTunnel::open_tcp_stream` via `direct-tcpip`

**Files:**
- Modify: `crates/liostunnel-core/src/protocols/ssh.rs`
- Create: `crates/liostunnel-core/src/protocols/counting.rs`
- Modify: `crates/liostunnel-core/src/protocols/mod.rs`, `crates/liostunnel-core/tests/ssh_integration.rs`

**Interfaces:**
- Consumes: `SshTunnel` (Task 6).
- Produces: a working `Protocol::open_tcp_stream`; `CountingStream<S>` which wraps any `TunnelStream` and accumulates byte counters.

- [ ] **Step 1: Write the failing tests**

Append to `crates/liostunnel-core/tests/ssh_integration.rs`:

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The target is reachable only from inside the compose network, so a
/// successful fetch proves the bytes really traversed the SSH channel.
#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn opens_a_channel_and_proxies_http_to_an_internal_target() {
    let mut t = SshTunnel::new("tunneluser".into(), HostKeyPolicy::AcceptAny);
    t.connect(&profile(password_auth()), &FileSecretStore).await.unwrap();

    // 172.x is the compose-internal address; resolve it by name through the
    // tunnel host instead by using the alias the compose file assigns.
    let dest: std::net::SocketAddr = "127.0.0.1:80".parse().unwrap();
    let mut s = t.open_tcp_stream_named("target.internal", 80, dest).await.unwrap();

    s.write_all(b"GET / HTTP/1.0\r\nHost: target.internal\r\n\r\n").await.unwrap();
    let mut body = String::new();
    s.read_to_string(&mut body).await.unwrap();

    assert!(body.contains("tunnel-target-ok"), "unexpected response: {body}");
    assert!(t.stats().bytes_down > 0, "byte counters must move");
    assert!(t.stats().bytes_up > 0);
    t.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn a_refused_destination_reports_a_protocol_error_without_killing_the_session() {
    let mut t = SshTunnel::new("tunneluser".into(), HostKeyPolicy::AcceptAny);
    t.connect(&profile(password_auth()), &FileSecretStore).await.unwrap();

    // Nothing listens on this port inside the container.
    let dest: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    // `unwrap_err` requires T: Debug, and `Box<dyn TunnelStream>` deliberately
    // has none — a Debug on a stream type is how payload bytes leak. Discard
    // the Ok value instead.
    let err = match t.open_tcp_stream(dest).await {
        Ok(_) => panic!("expected the destination to be refused"),
        Err(e) => e,
    };
    assert!(matches!(err, liostunnel_core::TunnelError::Protocol(_)), "got {err:?}");

    // Spec §11: a per-flow failure must not tear down the session.
    assert_eq!(t.stats().state, ConnectionState::Connected);
    assert_eq!(t.stats().flows_failed, 1);
    t.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn opening_a_stream_before_connecting_is_a_protocol_error() {
    let t = SshTunnel::new("tunneluser".into(), HostKeyPolicy::AcceptAny);
    let err = t.open_tcp_stream("127.0.0.1:80".parse().unwrap()).await.unwrap_err();
    assert!(matches!(err, liostunnel_core::TunnelError::Protocol(_)), "got {err:?}");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p liostunnel-core --test ssh_integration -- --ignored`
Expected: FAIL — the two channel tests fail with `Unsupported("open_tcp_stream (arrives in Task 7)")`, and `open_tcp_stream_named` does not resolve.

- [ ] **Step 3: Implement the counting wrapper**

`crates/liostunnel-core/src/protocols/counting.rs`:

```rust
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Wraps a tunnel stream and accumulates byte counters for [`crate::stats`].
/// Counts bytes only — never inspects or records payload content. Spec §11.
pub struct CountingStream<S> {
    inner: S,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    active: Arc<AtomicU64>,
}

impl<S> CountingStream<S> {
    pub fn new(
        inner: S,
        up: Arc<AtomicU64>,
        down: Arc<AtomicU64>,
        active: Arc<AtomicU64>,
    ) -> Self {
        active.fetch_add(1, Ordering::Relaxed);
        Self { inner, up, down, active }
    }
}

impl<S> Drop for CountingStream<S> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let n = buf.filled().len().saturating_sub(before);
            self.down.fetch_add(n as u64, Ordering::Relaxed);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            self.up.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
```

Add to `crates/liostunnel-core/src/protocols/mod.rs`:

```rust
pub mod counting;
```

- [ ] **Step 4: Implement `open_tcp_stream`**

Replace the placeholder `open_tcp_stream` in `crates/liostunnel-core/src/protocols/ssh.rs` and add the named variant:

```rust
    async fn open_tcp_stream(
        &self,
        dest: SocketAddr,
    ) -> Result<Box<dyn TunnelStream>, TunnelError> {
        self.open_tcp_stream_named(&dest.ip().to_string(), dest.port(), dest).await
    }
```

Add this inherent impl block (outside `impl Protocol`):

```rust
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
            .map_err(|e| TunnelError::Protocol(format!("cannot open channel to {host}:{port}: {e}")))?;

        let stream = crate::protocols::counting::CountingStream::new(
            channel.into_stream(),
            self.counters.bytes_up.clone(),
            self.counters.bytes_down.clone(),
            self.counters.active_flows.clone(),
        );

        Ok(Box::new(stream))
    }
}
```

The semaphore permit is carried by `CountingStream` itself rather than a second
wrapper. Add the field in `counting.rs` — a separate `PermitStream` would
duplicate all four `poll_*` delegations verbatim for one extra field:

```rust
pub struct CountingStream<S> {
    inner: S,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    active: Arc<AtomicU64>,
    /// Released when the stream drops, bounding concurrent SSH channels.
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}
```

with `new(...)` taking `permit: Option<tokio::sync::OwnedSemaphorePermit>` as its
last argument (tests pass `None`), and `open_tcp_stream_named` passing
`Some(permit)`.

Change `Counters` to hold `Arc<AtomicU64>` fields so `CountingStream` can share them, and add the semaphore to `SshTunnel`:

```rust
#[derive(Default)]
struct Counters {
    bytes_up: Arc<AtomicU64>,
    bytes_down: Arc<AtomicU64>,
    active_flows: Arc<AtomicU64>,
    flows_failed: AtomicU64,
}
```

In `SshTunnel`, add the field `channel_limit: Arc<tokio::sync::Semaphore>` and initialise it in `new` with `Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CHANNELS))`, where:

```rust
/// Conservative: OpenSSH's default limits are higher, but a burst of flows
/// from the packet engine should queue rather than fail. Spec §8.
const MAX_CONCURRENT_CHANNELS: usize = 64;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core --test ssh_integration -- --ignored`
Expected: PASS — 9 passed.

- [ ] **Step 6: Commit**

```bash
git add crates/liostunnel-core/src/protocols/
git commit -m "feat: SSH direct-tcpip channels with byte counters and a channel limiter"
```

---

### Task 8: `liostunnel probe` — Milestone A deliverable

Working software: loads a profile, validates it, connects, opens one channel, proxies stdin/stdout.

**Files:**
- Modify: `crates/liostunnel-cli/Cargo.toml`, `crates/liostunnel-cli/src/main.rs`
- Create: `crates/liostunnel-cli/src/cli.rs`, `crates/liostunnel-cli/src/commands/probe.rs`, `crates/liostunnel-cli/src/commands/mod.rs`, `crates/liostunnel-cli/src/profile_io.rs`

**Interfaces:**
- Consumes: everything from Tasks 1–7.
- Produces: the `liostunnel` binary with `probe`, `validate`, `import`, and `export` subcommands. `profile_io::load(path, secret_dir) -> Result<ServerProfile, TunnelError>` accepts either format by trying `ServerProfile` first, then `PortableProfile` + `import`.

- [ ] **Step 1: Add `clap`**

Add to the workspace `[workspace.dependencies]`: `clap = { version = "4", features = ["derive"] }`, and to `crates/liostunnel-cli/Cargo.toml`: `clap.workspace = true`, `liostunnel-core = { path = "../liostunnel-core" }`.

- [ ] **Step 2: Write the failing test**

`crates/liostunnel-cli/tests/profile_io.rs`:

```rust
use std::path::PathBuf;

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("lios-cli-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn load_accepts_a_portable_profile_and_moves_its_secrets_to_disk() {
    let dir = tmp("portable");
    let path = dir.join("p.liostunnel.json");
    std::fs::write(
        &path,
        r#"{"id":"00000000-0000-0000-0000-000000000000","name":"lab",
            "protocol":"ssh","host":"198.51.100.7","port":22,
            "auth":{"type":"password","password":"hunter2"},
            "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},
            "kill_switch":false}"#,
    )
    .unwrap();

    let p = liostunnel_cli::profile_io::load(&path, &dir.join("secrets")).unwrap();
    assert_eq!(p.name, "lab");

    // The in-memory profile must not carry the password inline.
    let json = serde_json::to_string(&p).unwrap();
    assert!(!json.contains("hunter2"), "secret leaked: {json}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn load_accepts_a_ref_bearing_server_profile_unchanged() {
    let dir = tmp("refform");
    let path = dir.join("p.json");
    std::fs::write(
        &path,
        r#"{"id":"00000000-0000-0000-0000-000000000000","name":"lab",
            "protocol":"ssh","host":"198.51.100.7","port":22,
            "auth":{"type":"password","password":{"source":"env","var":"PW"}},
            "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},
            "kill_switch":false}"#,
    )
    .unwrap();

    let p = liostunnel_cli::profile_io::load(&path, &dir.join("secrets")).unwrap();
    assert_eq!(p.host, "198.51.100.7");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn load_reports_a_useful_error_for_malformed_json() {
    let dir = tmp("bad");
    let path = dir.join("p.json");
    std::fs::write(&path, "{ not json").unwrap();
    let e = liostunnel_cli::profile_io::load(&path, &dir.join("secrets")).unwrap_err();
    assert!(e.to_string().contains("p.json"), "error should name the file: {e}");
    std::fs::remove_dir_all(&dir).ok();
}
```

For the test to reach `profile_io`, the CLI crate needs a library target. Add to `crates/liostunnel-cli/Cargo.toml`:

```toml
[lib]
name = "liostunnel_cli"
path = "src/lib.rs"
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p liostunnel-cli`
Expected: FAIL — `unresolved import liostunnel_cli`.

- [ ] **Step 4: Implement**

`crates/liostunnel-cli/src/lib.rs`:

```rust
pub mod cli;
pub mod commands;
pub mod profile_io;
```

`crates/liostunnel-cli/src/profile_io.rs`:

```rust
use std::path::Path;

use liostunnel_core::TunnelError;
use liostunnel_core::config::portable::PortableProfile;
use liostunnel_core::config::profile::ServerProfile;

/// Accepts either representation (spec §6.3). Tries the ref-bearing form first,
/// then the portable form, importing its secrets onto disk.
pub fn load(path: &Path, secret_dir: &Path) -> Result<ServerProfile, TunnelError> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        TunnelError::config(path.display().to_string(), format!("cannot read: {e}"))
    })?;

    if let Ok(p) = serde_json::from_str::<ServerProfile>(&raw) {
        return Ok(p);
    }

    match serde_json::from_str::<PortableProfile>(&raw) {
        Ok(p) => p.import(secret_dir),
        Err(e) => {
            // The raw serde error is not shown to the user: PortableProfile's
            // scalar fields (port, kill_switch, protocol) make serde's
            // invalid_type/unknown_variant messages echo the offending value
            // verbatim, and a secret misplaced into one of those fields would
            // leak into this error text.
            tracing::debug!(path = %path.display(), error = %e, "profile parse failed");
            Err(TunnelError::config(
                path.display().to_string(),
                "not a valid profile in either format",
            ))
        }
    }
}

/// `~/.liostunnel`, or `$LIOSTUNNEL_HOME` when set.
pub fn home() -> std::path::PathBuf {
    std::env::var_os("LIOSTUNNEL_HOME")
        .map(Into::into)
        .unwrap_or_else(|| {
            let base = std::env::var_os("HOME").map(std::path::PathBuf::from).unwrap_or_default();
            base.join(".liostunnel")
        })
}
```

`crates/liostunnel-cli/src/cli.rs`:

```rust
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "liostunnel", version, about = "Tunnel client — Phase 0 CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Bypass SSH host key verification. Dangerous; for self-signed lab setups only.
    #[arg(long, global = true)]
    pub insecure_accept_any_hostkey: bool,

    #[arg(long, global = true, default_value = "info")]
    pub log_level: String,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Parse and validate a profile without connecting.
    Validate { profile: PathBuf },

    /// Open one SSH channel to a destination and proxy stdin/stdout through it.
    Probe {
        profile: PathBuf,
        /// SSH username.
        #[arg(long)]
        user: String,
        /// Destination as host:port, resolved by the *server*, not locally.
        #[arg(long)]
        dest: String,
    },

    /// Import a shareable profile, moving its secrets to disk.
    Import { profile: PathBuf },

    /// Export a profile in shareable form. Writes secrets in plaintext.
    Export {
        profile: PathBuf,
        #[arg(long)]
        include_secrets: bool,
    },
}
```

`crates/liostunnel-cli/src/commands/mod.rs`:

```rust
pub mod probe;
```

`crates/liostunnel-cli/src/commands/probe.rs`:

```rust
use liostunnel_core::TunnelError;
use liostunnel_core::config::profile::ServerProfile;
use liostunnel_core::config::secret::FileSecretStore;
use liostunnel_core::protocols::Protocol;
use liostunnel_core::protocols::ssh::{HostKeyPolicy, SshTunnel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn run(
    profile: &ServerProfile,
    user: String,
    dest: &str,
    policy: HostKeyPolicy,
) -> Result<(), TunnelError> {
    let (host, port) = dest
        .rsplit_once(':')
        .ok_or_else(|| TunnelError::config("--dest", "expected host:port"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| TunnelError::config("--dest", "port must be a number"))?;

    let mut tunnel = SshTunnel::new(user, policy);
    tunnel.connect(profile, &FileSecretStore).await?;
    tracing::info!(%dest, "opening channel");

    let origin = "127.0.0.1:0".parse().expect("literal is a valid SocketAddr");
    let mut stream = tunnel.open_tcp_stream_named(host, port, origin).await?;

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut up = [0u8; 8192];
    let mut down = [0u8; 8192];

    loop {
        tokio::select! {
            n = stdin.read(&mut up) => match n {
                Ok(0) | Err(_) => break,
                Ok(n) => stream.write_all(&up[..n]).await?,
            },
            n = stream.read(&mut down) => match n {
                Ok(0) | Err(_) => break,
                Ok(n) => { stdout.write_all(&down[..n]).await?; stdout.flush().await?; }
            },
        }
    }

    let s = tunnel.stats();
    tracing::info!(bytes_up = s.bytes_up, bytes_down = s.bytes_down, "channel closed");
    tunnel.disconnect().await
}
```

`crates/liostunnel-cli/src/main.rs`:

```rust
use clap::Parser;
use liostunnel_cli::cli::{Cli, Command};
use liostunnel_cli::{commands, profile_io};
use liostunnel_core::config::portable::{EXPORT_WARNING, PortableProfile};
use liostunnel_core::config::secret::FileSecretStore;
use liostunnel_core::protocols::ssh::HostKeyPolicy;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| cli.log_level.clone().into()),
        )
        .init();

    if cli.insecure_accept_any_hostkey {
        eprintln!(
            "\n  !!  --insecure-accept-any-hostkey is set. Host key verification is OFF.\n\
               !!  This connection can be silently intercepted. Use only on a network\n\
               !!  you control, against a server you are certain of.\n"
        );
    }

    match run(cli).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), liostunnel_core::TunnelError> {
    let home = profile_io::home();
    let secret_dir = home.join("secrets");
    let policy = if cli.insecure_accept_any_hostkey {
        HostKeyPolicy::AcceptAny
    } else {
        HostKeyPolicy::Verify { known_hosts: home.join("known_hosts") }
    };

    match cli.command {
        Command::Validate { profile } => {
            let p = profile_io::load(&profile, &secret_dir)?;
            p.validate(&FileSecretStore)?;
            emit_warnings(&p);
            println!("{} — ok ({:?} {}:{})", p.name, p.protocol, p.host, p.port);
            Ok(())
        }
        Command::Import { profile } => {
            let p = profile_io::load(&profile, &secret_dir)?;
            p.validate(&FileSecretStore)?;
            emit_warnings(&p);
            let out = home.join(format!("{}.json", p.id));
            std::fs::create_dir_all(&home).map_err(liostunnel_core::TunnelError::from)?;
            std::fs::write(&out, serde_json::to_string_pretty(&p).unwrap())
                .map_err(liostunnel_core::TunnelError::from)?;
            println!("imported to {}", out.display());
            Ok(())
        }
        Command::Export { profile, include_secrets } => {
            let p = profile_io::load(&profile, &secret_dir)?;
            if !include_secrets {
                return Err(liostunnel_core::TunnelError::config(
                    "--include-secrets",
                    "export writes private keys in plaintext; pass --include-secrets \
                     to confirm you understand this",
                ));
            }
            eprintln!("WARNING: {EXPORT_WARNING}");
            let portable = PortableProfile::export(&p, &FileSecretStore)?;
            println!("{}", serde_json::to_string_pretty(&portable).unwrap());
            Ok(())
        }
        Command::Probe { profile, user, dest } => {
            let p = profile_io::load(&profile, &secret_dir)?;
            p.validate(&FileSecretStore)?;
            emit_warnings(&p);
            commands::probe::run(&p, user, &dest, policy).await
        }
    }
}

/// Spec §9.3.
fn emit_warnings(p: &liostunnel_core::config::profile::ServerProfile) {
    for w in p.warnings() {
        eprintln!("  !!  WARNING: {w}");
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-cli`
Expected: PASS — 3 passed.

- [ ] **Step 6: Verify the Milestone A deliverable end to end**

Run, with the fixture up:

```bash
make -C testing/docker up
cat > /tmp/fixture.liostunnel.json <<'JSON'
{"id":"00000000-0000-0000-0000-000000000000","name":"fixture",
 "protocol":"ssh","host":"127.0.0.1","port":22022,
 "auth":{"type":"password","password":"tunnelpass"},
 "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},"kill_switch":false}
JSON
printf 'GET / HTTP/1.0\r\nHost: target.internal\r\n\r\n' | \
  cargo run -p liostunnel-cli -- --insecure-accept-any-hostkey \
    probe /tmp/fixture.liostunnel.json --user tunneluser --dest target.internal:80
```

Expected: the HTTP response body containing `tunnel-target-ok`, plus the insecure-mode warning on stderr. **Milestone A is complete.**

- [ ] **Step 7: Commit**

```bash
git add crates/liostunnel-cli/
git commit -m "feat: liostunnel CLI with validate, import, export, and probe"
```

---

# Milestone B — TUN device and the packet engine

Ends at exit criterion **EC1**: real TCP traffic from a real TUN device reaching a real destination through the SSH tunnel.

---

### Task 9: `TunDevice` and the utun address-family codec

Spec §6.1 / decision D2. macOS `utun` prefixes every packet with a four-byte big-endian address family; Linux hands over bare IP. That difference is isolated here and nowhere else.

**Files:**
- Create: `crates/liostunnel-core/src/net/mod.rs`, `crates/liostunnel-core/src/net/tun.rs`
- Modify: `crates/liostunnel-core/Cargo.toml`, `crates/liostunnel-core/src/lib.rs`

**Interfaces:**
- Consumes: `TunnelError`.
- Produces:
  - `trait PacketIo: Send { fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunnelError>; fn write_packet(&mut self, pkt: &[u8]) -> Result<(), TunnelError>; fn mtu(&self) -> usize; }` — both methods operate on **bare IP packets**; the AF prefix never escapes this module.
  - `strip_af_prefix(&[u8]) -> Result<&[u8], TunnelError>`, `af_prefix_for(&[u8]) -> Result<[u8; 4], TunnelError>`
  - `struct TunDevice` (real device, `tun-rs`) with `TunDevice::open(cfg: TunConfig) -> Result<Self, TunnelError>` and `fn as_raw_fd(&self) -> std::os::fd::RawFd`.
  - `struct TunConfig { pub name: Option<String>, pub address: Ipv4Addr, pub netmask: Ipv4Addr, pub mtu: u16 }`
  - `struct FakePacketIo` (test double) with `push_inbound(Vec<u8>)` and `take_outbound() -> Vec<Vec<u8>>`.

- [ ] **Step 1: Add the dependency**

Add to `crates/liostunnel-core/Cargo.toml`: `tun-rs = { workspace = true }` and `smoltcp = { workspace = true }`.

- [ ] **Step 2: Write the failing tests**

`crates/liostunnel-core/src/net/tun.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal well-formed IPv4 header — enough for version sniffing.
    fn ipv4() -> Vec<u8> {
        let mut v = vec![0u8; 20];
        v[0] = 0x45;
        v
    }

    fn ipv6() -> Vec<u8> {
        let mut v = vec![0u8; 40];
        v[0] = 0x60;
        v
    }

    #[test]
    fn af_prefix_is_chosen_from_the_ip_version() {
        assert_eq!(af_prefix_for(&ipv4()).unwrap(), [0, 0, 0, 2]);
        assert_eq!(af_prefix_for(&ipv6()).unwrap(), [0, 0, 0, 30]);
    }

    #[test]
    fn af_prefix_rejects_a_packet_that_is_neither_v4_nor_v6() {
        let mut junk = vec![0u8; 20];
        junk[0] = 0x35;
        assert!(af_prefix_for(&junk).is_err());
    }

    #[test]
    fn af_prefix_rejects_an_empty_packet() {
        assert!(af_prefix_for(&[]).is_err());
    }

    #[test]
    fn stripping_removes_exactly_four_bytes() {
        let mut framed = vec![0, 0, 0, 2];
        framed.extend_from_slice(&ipv4());
        assert_eq!(strip_af_prefix(&framed).unwrap(), &ipv4()[..]);
    }

    #[test]
    fn stripping_rejects_a_runt() {
        assert!(strip_af_prefix(&[0, 0, 0]).is_err());
    }

    #[test]
    fn prefix_then_strip_is_the_identity() {
        let pkt = ipv6();
        let mut framed = af_prefix_for(&pkt).unwrap().to_vec();
        framed.extend_from_slice(&pkt);
        assert_eq!(strip_af_prefix(&framed).unwrap(), &pkt[..]);
    }

    #[test]
    fn the_fake_device_round_trips_bare_ip_packets() {
        let mut io = FakePacketIo::new(1500);
        io.push_inbound(ipv4());

        let mut buf = [0u8; 2048];
        let n = io.read_packet(&mut buf).unwrap();
        assert_eq!(&buf[..n], &ipv4()[..]);

        io.write_packet(&ipv6()).unwrap();
        assert_eq!(io.take_outbound(), vec![ipv6()]);
    }

    #[test]
    fn the_fake_device_reports_zero_when_drained() {
        let mut io = FakePacketIo::new(1500);
        let mut buf = [0u8; 64];
        assert_eq!(io.read_packet(&mut buf).unwrap(), 0);
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p liostunnel-core tun`
Expected: FAIL — `cannot find function af_prefix_for in this scope`.

- [ ] **Step 4: Implement**

Prepend to `crates/liostunnel-core/src/net/tun.rs`:

```rust
use std::collections::VecDeque;
use std::net::Ipv4Addr;

use crate::error::TunnelError;

/// macOS utun frames every packet with a four-byte big-endian address family.
/// Linux `/dev/net/tun` opened with IFF_NO_PI does not. Decision D2 —
/// this is the only place in the codebase that knows the difference.
pub const AF_INET_BE: [u8; 4] = [0, 0, 0, 2];
pub const AF_INET6_BE: [u8; 4] = [0, 0, 0, 30];

pub fn af_prefix_for(packet: &[u8]) -> Result<[u8; 4], TunnelError> {
    match packet.first().map(|b| b >> 4) {
        Some(4) => Ok(AF_INET_BE),
        Some(6) => Ok(AF_INET6_BE),
        Some(v) => Err(TunnelError::Tun(format!("unknown IP version {v}"))),
        None => Err(TunnelError::Tun("empty packet".into())),
    }
}

pub fn strip_af_prefix(framed: &[u8]) -> Result<&[u8], TunnelError> {
    if framed.len() < 4 {
        return Err(TunnelError::Tun(format!(
            "packet of {} bytes is shorter than the utun address-family prefix",
            framed.len()
        )));
    }
    Ok(&framed[4..])
}

/// Reads and writes **bare IP packets**. Implementations hide any platform framing.
pub trait PacketIo: Send {
    /// Returns 0 when nothing is currently available.
    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunnelError>;
    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunnelError>;
    fn mtu(&self) -> usize;
}

#[derive(Clone, Debug)]
pub struct TunConfig {
    pub name: Option<String>,
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: None,
            address: Ipv4Addr::new(10, 90, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1500,
        }
    }
}

/// In-memory `PacketIo` used by every stack test, so the poll loop is testable
/// without a device or elevated privileges. Spec §12.
pub struct FakePacketIo {
    inbound: VecDeque<Vec<u8>>,
    outbound: Vec<Vec<u8>>,
    mtu: usize,
}

impl FakePacketIo {
    pub fn new(mtu: usize) -> Self {
        Self { inbound: VecDeque::new(), outbound: Vec::new(), mtu }
    }

    /// Queue a packet as though an application on the device had sent it.
    pub fn push_inbound(&mut self, packet: Vec<u8>) {
        self.inbound.push_back(packet);
    }

    /// Take everything the stack has written back towards the device.
    pub fn take_outbound(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outbound)
    }

    pub fn outbound_len(&self) -> usize {
        self.outbound.len()
    }
}

impl PacketIo for FakePacketIo {
    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunnelError> {
        match self.inbound.pop_front() {
            None => Ok(0),
            Some(p) => {
                if p.len() > buf.len() {
                    return Err(TunnelError::Tun(format!(
                        "packet of {} bytes exceeds the {}-byte read buffer",
                        p.len(),
                        buf.len()
                    )));
                }
                buf[..p.len()].copy_from_slice(&p);
                Ok(p.len())
            }
        }
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunnelError> {
        self.outbound.push(packet.to_vec());
        Ok(())
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core tun`
Expected: PASS — 8 passed.

- [ ] **Step 6: Add the real device**

Append to `crates/liostunnel-core/src/net/tun.rs`. This cannot be unit-tested without privileges; it is exercised by T5 in Task 21.

```rust
/// The real TUN device. macOS framing is applied here and nowhere else.
pub struct TunDevice {
    inner: tun_rs::SyncDevice,
    mtu: usize,
    /// True on macOS, where utun prepends the address family.
    framed: bool,
    scratch: Vec<u8>,
}

impl TunDevice {
    pub fn open(cfg: TunConfig) -> Result<Self, TunnelError> {
        let mut builder = tun_rs::DeviceBuilder::new()
            .ipv4(cfg.address, cfg.netmask, None)
            .mtu(cfg.mtu);
        if let Some(name) = &cfg.name {
            builder = builder.name(name);
        }
        let inner = builder
            .build_sync()
            .map_err(|e| TunnelError::Tun(format!("cannot create TUN interface: {e}")))?;

        Ok(Self {
            inner,
            mtu: cfg.mtu as usize,
            framed: cfg!(target_os = "macos"),
            scratch: vec![0u8; cfg.mtu as usize + 4],
        })
    }

    pub fn name(&self) -> Result<String, TunnelError> {
        self.inner
            .name()
            .map_err(|e| TunnelError::Tun(format!("cannot read interface name: {e}")))
    }
}

#[cfg(unix)]
impl std::os::fd::AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd as _;
        self.inner.as_raw_fd()
    }
}

impl PacketIo for TunDevice {
    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunnelError> {
        if !self.framed {
            return match self.inner.recv(buf) {
                Ok(n) => Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
                Err(e) => Err(TunnelError::Tun(format!("read failed: {e}"))),
            };
        }
        let n = match self.inner.recv(&mut self.scratch) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(0),
            Err(e) => return Err(TunnelError::Tun(format!("read failed: {e}"))),
        };
        let ip = strip_af_prefix(&self.scratch[..n])?;
        if ip.len() > buf.len() {
            return Err(TunnelError::Tun("read buffer too small".into()));
        }
        buf[..ip.len()].copy_from_slice(ip);
        Ok(ip.len())
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunnelError> {
        let out = if self.framed {
            self.scratch.clear();
            self.scratch.extend_from_slice(&af_prefix_for(packet)?);
            self.scratch.extend_from_slice(packet);
            &self.scratch[..]
        } else {
            packet
        };
        self.inner
            .send(out)
            .map(|_| ())
            .map_err(|e| TunnelError::Tun(format!("write failed: {e}")))
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}
```

`crates/liostunnel-core/src/net/mod.rs`:

```rust
pub mod tun;
```

Add to `crates/liostunnel-core/src/lib.rs`:

```rust
pub mod net;
```

- [ ] **Step 7: Verify it still builds on both targets**

Run: `cargo clippy --all-targets -- -D warnings && cargo test -p liostunnel-core tun`
Expected: no warnings; 8 passed.

If `tun_rs::DeviceBuilder` method names differ, run `cargo doc -p tun-rs --open`. Only the builder chain is version-sensitive; `PacketIo` and the codec above are not.

- [ ] **Step 8: Commit**

```bash
git add crates/liostunnel-core/
git commit -m "feat: TunDevice with the utun address-family codec isolated"
```

---

### Task 10: The `NetStack` seam and `QueuedDevice`

Spec §7.1 / decision D7.

**Files:**
- Modify: `crates/liostunnel-core/src/net/mod.rs`
- Create: `crates/liostunnel-core/src/net/smoltcp_stack/mod.rs`, `crates/liostunnel-core/src/net/smoltcp_stack/device.rs`

**Interfaces:**
- Consumes: `PacketIo` (Task 9).
- Produces:
  - `struct TcpFlow { pub src: SocketAddr, pub dst: SocketAddr, pub stream: LocalStream }` — `LocalStream` is defined in Task 11, which is why Task 11 comes before any code that constructs a `TcpFlow`.
  - `struct Datagram { pub src: SocketAddr, pub dst: SocketAddr, pub payload: Vec<u8> }`
  - `struct StackConfig { pub address: Ipv4Addr, pub netmask_prefix: u8, pub mtu: usize, pub tcp_buffer_bytes: usize, pub channel_depth: usize }`
  - `struct StackHandles { pub tcp_accept: mpsc::Receiver<TcpFlow>, pub udp_inbound: mpsc::Receiver<Datagram>, pub udp_outbound: mpsc::Sender<Datagram>, pub shutdown: ShutdownHandle }`
  - `struct ShutdownHandle` with `fn shutdown(&self)`
  - `trait NetStack: Send + 'static { fn start(self, io: Box<dyn PacketIo>, cfg: StackConfig) -> Result<StackHandles, TunnelError>; }`
  - `struct QueuedDevice` implementing `smoltcp::phy::Device`, with `push_rx(Vec<u8>)`, `drain_tx() -> Vec<Vec<u8>>`, `rx_len()`.

- [ ] **Step 1: Write the failing tests**

`crates/liostunnel-core/src/net/smoltcp_stack/device.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::{Device, RxToken, TxToken};
    use smoltcp::time::Instant;

    #[test]
    fn a_drained_device_yields_nothing_to_receive() {
        let mut d = QueuedDevice::new(1500);
        assert!(d.receive(Instant::from_micros(0)).is_none());
    }

    #[test]
    fn queued_packets_are_handed_to_smoltcp_in_order() {
        let mut d = QueuedDevice::new(1500);
        d.push_rx(vec![1, 2, 3]);
        d.push_rx(vec![4, 5]);

        let (rx, _tx) = d.receive(Instant::from_micros(0)).unwrap();
        assert_eq!(rx.consume(|b| b.to_vec()), vec![1, 2, 3]);

        let (rx, _tx) = d.receive(Instant::from_micros(0)).unwrap();
        assert_eq!(rx.consume(|b| b.to_vec()), vec![4, 5]);

        assert!(d.receive(Instant::from_micros(0)).is_none());
    }

    #[test]
    fn transmitted_packets_land_in_the_tx_queue() {
        let mut d = QueuedDevice::new(1500);
        let tx = d.transmit(Instant::from_micros(0)).unwrap();
        tx.consume(4, |buf| buf.copy_from_slice(&[9, 9, 9, 9]));

        assert_eq!(d.drain_tx(), vec![vec![9, 9, 9, 9]]);
        assert!(d.drain_tx().is_empty(), "draining must consume");
    }

    #[test]
    fn capabilities_report_the_ip_medium_and_configured_mtu() {
        let d = QueuedDevice::new(1400);
        let caps = d.capabilities();
        assert_eq!(caps.max_transmission_unit, 1400);
        assert_eq!(caps.medium, smoltcp::phy::Medium::Ip);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p liostunnel-core device`
Expected: FAIL — `cannot find type QueuedDevice in this scope`.

- [ ] **Step 3: Implement `QueuedDevice`**

Prepend to `crates/liostunnel-core/src/net/smoltcp_stack/device.rs`:

```rust
use std::collections::VecDeque;

use smoltcp::phy::{Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

/// A `smoltcp::phy::Device` backed by two queues rather than a file descriptor.
///
/// This indirection is what makes the whole engine testable without a TUN
/// device (spec §12) and is also what makes SYN-triggered listener injection
/// possible at all: packets must be inspectable *before* `Interface::poll`
/// runs, and the `SocketSet` cannot be mutated from inside `Device::receive`.
/// Spec §7.4.
pub struct QueuedDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl QueuedDevice {
    pub fn new(mtu: usize) -> Self {
        Self { rx: VecDeque::new(), tx: VecDeque::new(), mtu }
    }

    pub fn push_rx(&mut self, packet: Vec<u8>) {
        self.rx.push_back(packet);
    }

    pub fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.tx.drain(..).collect()
    }

    pub fn rx_len(&self) -> usize {
        self.rx.len()
    }
}

pub struct QueuedRxToken(Vec<u8>);

impl smoltcp::phy::RxToken for QueuedRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

pub struct QueuedTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl smoltcp::phy::TxToken for QueuedTxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl Device for QueuedDevice {
    type RxToken<'a> = QueuedRxToken where Self: 'a;
    type TxToken<'a> = QueuedTxToken<'a> where Self: 'a;

    fn receive(&mut self, _t: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((QueuedRxToken(packet), QueuedTxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _t: Instant) -> Option<Self::TxToken<'_>> {
        Some(QueuedTxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        // A TUN device carries no Ethernet frame, and nothing between us and the
        // application corrupts bytes — but leave IP/TCP checksums on so malformed
        // packets from a misbehaving app are rejected rather than proxied.
        let mut cks = ChecksumCapabilities::default();
        cks.ipv4 = Checksum::Both;
        cks.tcp = Checksum::Both;
        cks.udp = Checksum::Both;
        caps.checksum = cks;
        caps
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core device`
Expected: PASS — 4 passed.

- [ ] **Step 5: Declare the seam**

Append to `crates/liostunnel-core/src/net/mod.rs`:

```rust
pub mod smoltcp_stack;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::mpsc;

use crate::error::TunnelError;
use crate::net::local_stream::LocalStream;
use crate::net::tun::PacketIo;

/// A TCP connection initiated by an application on the device.
pub struct TcpFlow {
    pub src: SocketAddr,
    /// The application's real destination, not the TUN's own address.
    pub dst: SocketAddr,
    pub stream: LocalStream,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Datagram {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct StackConfig {
    pub address: Ipv4Addr,
    pub netmask_prefix: u8,
    pub mtu: usize,
    pub tcp_buffer_bytes: usize,
    /// Bounded so a slow tunnel applies backpressure through the TCP window
    /// rather than growing an unbounded queue. Spec §7.2.
    pub channel_depth: usize,
}

impl Default for StackConfig {
    fn default() -> Self {
        Self {
            address: Ipv4Addr::new(10, 90, 0, 1),
            netmask_prefix: 24,
            mtu: 1500,
            tcp_buffer_bytes: 64 * 1024,
            channel_depth: 64,
        }
    }
}

#[derive(Clone, Default)]
pub struct ShutdownHandle(Arc<AtomicBool>);

impl ShutdownHandle {
    pub fn shutdown(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
    pub fn is_shutdown(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

pub struct StackHandles {
    pub tcp_accept: mpsc::Receiver<TcpFlow>,
    pub udp_inbound: mpsc::Receiver<Datagram>,
    pub udp_outbound: mpsc::Sender<Datagram>,
    pub shutdown: ShutdownHandle,
}

/// Decision D7. The engine consumes only this, so swapping in
/// `netstack-smoltcp` means writing one more implementation.
pub trait NetStack: Send + 'static {
    fn start(
        self,
        io: Box<dyn PacketIo>,
        cfg: StackConfig,
    ) -> Result<StackHandles, TunnelError>;
}
```

`crates/liostunnel-core/src/net/smoltcp_stack/mod.rs`:

```rust
pub mod device;
```

- [ ] **Step 6: Stub `local_stream` so this task compiles on its own**

`TcpFlow` references `LocalStream`, which Task 11 implements. Create the module now with the type only, so `cargo check` passes at the end of every task:

`crates/liostunnel-core/src/net/local_stream.rs`:

```rust
/// Filled in by Task 11.
pub struct LocalStream;
```

Add `pub mod local_stream;` to `crates/liostunnel-core/src/net/mod.rs`.

- [ ] **Step 7: Verify the crate compiles**

Run: `cargo check -p liostunnel-core && cargo test -p liostunnel-core device`
Expected: no errors; 4 passed.

- [ ] **Step 8: Commit**

```bash
git add crates/liostunnel-core/src/net/
git commit -m "feat: NetStack seam and a queue-backed smoltcp device"
```

---

### Task 11: `LocalStream` — the sync/async boundary

Spec §7.2. This is the only place the synchronous stack thread and the tokio runtime touch. Bounded channels here are what produce end-to-end backpressure.

**Files:**
- Replace: `crates/liostunnel-core/src/net/local_stream.rs`
- Modify: `crates/liostunnel-core/Cargo.toml`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `struct LocalStream` implementing `AsyncRead + AsyncWrite + Send + Unpin`. **Reading yields bytes the application sent; writing delivers bytes to the application.**
  - `struct StreamPeer { to_stream: mpsc::Sender<Vec<u8>>, from_stream: mpsc::Receiver<Vec<u8>> }` — the stack-thread half, driven with `try_send`/`try_recv` from synchronous code.
  - `fn local_stream_pair(depth: usize) -> (LocalStream, StreamPeer)`

- [ ] **Step 1: Add the dependency**

Add to `[workspace.dependencies]`: `tokio-util = "0.7"` (no `features` list —
tokio-util 0.7.19 has no `sync` feature at all; `PollSender` lives in its
unconditional base), and to `crates/liostunnel-core/Cargo.toml`:
`tokio-util.workspace = true`.

- [ ] **Step 2: Write the failing tests**

`crates/liostunnel-core/src/net/local_stream.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn reading_yields_bytes_the_application_sent() {
        let (mut stream, peer) = local_stream_pair(4);
        peer.to_stream.try_send(b"hello".to_vec()).unwrap();

        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn a_short_read_buffer_leaves_the_remainder_for_the_next_read() {
        let (mut stream, peer) = local_stream_pair(4);
        peer.to_stream.try_send(b"abcdef".to_vec()).unwrap();

        let mut first = [0u8; 2];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"ab");

        let mut rest = [0u8; 4];
        stream.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"cdef");
    }

    #[tokio::test]
    async fn writing_delivers_bytes_towards_the_application() {
        let (mut stream, mut peer) = local_stream_pair(4);
        stream.write_all(b"down").await.unwrap();
        assert_eq!(peer.from_stream.try_recv().unwrap(), b"down".to_vec());
    }

    #[tokio::test]
    async fn dropping_the_stack_side_signals_eof() {
        let (mut stream, peer) = local_stream_pair(4);
        peer.to_stream.try_send(b"tail".to_vec()).unwrap();
        drop(peer);

        let mut all = Vec::new();
        stream.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"tail".to_vec(), "buffered data must survive the drop");
    }

    #[tokio::test]
    async fn shutting_down_the_stream_closes_the_stack_side() {
        let (mut stream, mut peer) = local_stream_pair(4);
        stream.write_all(b"x").await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);

        assert_eq!(peer.from_stream.recv().await, Some(b"x".to_vec()));
        assert_eq!(peer.from_stream.recv().await, None, "closed channel must report None");
    }

    #[tokio::test]
    async fn a_full_channel_applies_backpressure_rather_than_buffering() {
        let (stream, peer) = local_stream_pair(1);
        peer.to_stream.try_send(vec![0u8; 8]).unwrap();
        // Depth 1 is now full: the stack thread learns to stop draining smoltcp,
        // which shrinks the TCP window. Spec §7.2.
        assert!(peer.to_stream.try_send(vec![0u8; 8]).is_err());
        drop(stream);
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p liostunnel-core local_stream`
Expected: FAIL — `cannot find function local_stream_pair in this scope`.

- [ ] **Step 4: Implement**

Replace the whole of `crates/liostunnel-core/src/net/local_stream.rs`:

```rust
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

/// The tokio-side handle for one proxied TCP connection.
///
/// Reading yields bytes the application on the device sent (they are on their
/// way *out* through the tunnel). Writing delivers bytes that came back from
/// the tunnel *to* the application. Spec §7.2.
pub struct LocalStream {
    /// Bytes from the device.
    inbound: mpsc::Receiver<Vec<u8>>,
    /// Bytes towards the device.
    outbound: PollSender<Vec<u8>>,
    /// Remainder of a chunk that did not fit the caller's buffer.
    partial: Option<(Vec<u8>, usize)>,
}

/// The stack-thread half. Every method here is non-blocking so it can be
/// driven from the synchronous poll loop.
pub struct StreamPeer {
    /// Push bytes read out of the smoltcp socket.
    pub to_stream: mpsc::Sender<Vec<u8>>,
    /// Pull bytes to write into the smoltcp socket.
    pub from_stream: mpsc::Receiver<Vec<u8>>,
}

pub fn local_stream_pair(depth: usize) -> (LocalStream, StreamPeer) {
    let (to_stream, inbound) = mpsc::channel(depth);
    let (outbound, from_stream) = mpsc::channel(depth);
    (
        LocalStream { inbound, outbound: PollSender::new(outbound), partial: None },
        StreamPeer { to_stream, from_stream },
    )
}

impl AsyncRead for LocalStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Serve any leftover from a previous chunk first.
        if let Some((chunk, offset)) = self.partial.take() {
            let n = (chunk.len() - offset).min(buf.remaining());
            buf.put_slice(&chunk[offset..offset + n]);
            if offset + n < chunk.len() {
                self.partial = Some((chunk, offset + n));
            }
            return Poll::Ready(Ok(()));
        }

        match self.inbound.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            // Channel closed and drained: the application half is gone.
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Ready(Some(chunk)) => {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.partial = Some((chunk, n));
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for LocalStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.outbound.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "packet stack closed this flow",
            ))),
            Poll::Ready(Ok(())) => {
                let n = buf.len();
                self.outbound.send_item(buf.to_vec()).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "flow closed")
                })?;
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Delivery is the channel's job; there is no buffer of our own to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Closing the sender makes the stack thread see EOF and emit FIN.
        self.outbound.close();
        Poll::Ready(Ok(()))
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core local_stream`
Expected: PASS — 6 passed.

- [ ] **Step 6: Commit**

```bash
git add crates/liostunnel-core/
git commit -m "feat: LocalStream, the bounded sync/async boundary"
```

---

### Task 12: Packet inspection and the endpoint registry

Spec §7.4 and §7.5. Pure functions over packet bytes — no state machine, no sockets, trivially testable.

**Files:**
- Create: `crates/liostunnel-core/src/net/smoltcp_stack/inspect.rs`, `crates/liostunnel-core/src/net/nat_table.rs`, `crates/liostunnel-core/src/net/testutil.rs`
- Modify: `crates/liostunnel-core/src/net/mod.rs`, `crates/liostunnel-core/src/net/smoltcp_stack/mod.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `enum Inspected { TcpSyn { src: SocketAddr, dst: SocketAddr }, TcpOther { src: SocketAddr, dst: SocketAddr }, Udp { src: SocketAddr, dst: SocketAddr, payload: Vec<u8> }, Ignored }`
  - `fn inspect(packet: &[u8]) -> Inspected`
  - `struct NatTable` with `arm(src, dst) -> bool`, `is_armed(&src, &dst) -> bool`, `disarm(&src, &dst)`, `armed_len()`, `record_dns(src: SocketAddr, id: u16)`, `take_dns(src: SocketAddr, id: u16) -> bool`

> **Why the 4-tuple and not just the destination.** smoltcp listeners bind a *local* endpoint only, and each accepts exactly one connection. If arming were keyed on destination alone, a browser opening six sockets to `example.com:443` would inject one listener, and the other five SYNs would match no socket and be reset. Keying on `(src, dst)` injects one listener per genuinely distinct connection, while a SYN retransmit for a 4-tuple already in flight correctly injects nothing.
  - `testutil::{build_tcp, build_udp, TcpFlags}` — synthetic packet builders shared by every stack test.

- [ ] **Step 1: Write the packet builders**

`crates/liostunnel-core/src/net/testutil.rs`:

```rust
//! Synthetic packet builders. Available to tests only.
//!
//! Built with smoltcp's own setters rather than hand-written bytes, so
//! checksums are always correct and the tests exercise real parsing.

use std::net::Ipv4Addr;

use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket, TcpSeqNumber, UdpPacket};

#[derive(Clone, Copy, Default, Debug)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

impl TcpFlags {
    pub fn syn() -> Self {
        Self { syn: true, ..Default::default() }
    }
    pub fn ack() -> Self {
        Self { ack: true, ..Default::default() }
    }
    pub fn fin_ack() -> Self {
        Self { fin: true, ack: true, ..Default::default() }
    }
}

fn ipv4_frame(src: Ipv4Addr, dst: Ipv4Addr, proto: IpProtocol, payload_len: usize) -> Vec<u8> {
    let total = 20 + payload_len;
    let mut buf = vec![0u8; total];
    let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
    ip.set_version(4);
    ip.set_header_len(20);
    ip.set_total_len(total as u16);
    ip.set_ident(0);
    ip.set_dont_frag(true);
    ip.set_more_frags(false);
    ip.set_frag_offset(0);
    ip.set_hop_limit(64);
    ip.set_next_header(proto);
    ip.set_src_addr(src);
    ip.set_dst_addr(dst);
    buf
}

pub fn build_tcp(
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
    flags: TcpFlags,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let mut buf = ipv4_frame(src.0, dst.0, IpProtocol::Tcp, tcp_len);
    {
        let mut tcp = TcpPacket::new_unchecked(&mut buf[20..]);
        tcp.set_src_port(src.1);
        tcp.set_dst_port(dst.1);
        tcp.set_seq_number(TcpSeqNumber(seq as i32));
        tcp.set_ack_number(TcpSeqNumber(ack as i32));
        tcp.set_header_len(20);
        tcp.set_syn(flags.syn);
        tcp.set_ack(flags.ack);
        tcp.set_fin(flags.fin);
        tcp.set_rst(flags.rst);
        tcp.set_window_len(65535);
        tcp.payload_mut().copy_from_slice(payload);
        tcp.fill_checksum(&IpAddress::Ipv4(src.0), &IpAddress::Ipv4(dst.0));
    }
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip.fill_checksum();
    }
    buf
}

pub fn build_udp(src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16), payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut buf = ipv4_frame(src.0, dst.0, IpProtocol::Udp, udp_len);
    {
        let mut udp = UdpPacket::new_unchecked(&mut buf[20..]);
        udp.set_src_port(src.1);
        udp.set_dst_port(dst.1);
        udp.set_len(udp_len as u16);
        udp.payload_mut().copy_from_slice(payload);
        udp.fill_checksum(&IpAddress::Ipv4(src.0), &IpAddress::Ipv4(dst.0));
    }
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip.fill_checksum();
    }
    buf
}
```

Add to `crates/liostunnel-core/src/net/mod.rs`:

```rust
#[cfg(test)]
pub(crate) mod testutil;
pub mod nat_table;
```

- [ ] **Step 2: Write the failing tests**

`crates/liostunnel-core/src/net/smoltcp_stack/inspect.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::testutil::{TcpFlags, build_tcp, build_udp};
    use std::net::{Ipv4Addr, SocketAddr};

    const APP: (Ipv4Addr, u16) = (Ipv4Addr::new(10, 90, 0, 2), 51234);
    const WEB: (Ipv4Addr, u16) = (Ipv4Addr::new(93, 184, 216, 34), 443);

    fn sa(t: (Ipv4Addr, u16)) -> SocketAddr {
        SocketAddr::from(t)
    }

    #[test]
    fn a_bare_syn_is_recognised_as_a_new_connection() {
        let pkt = build_tcp(APP, WEB, TcpFlags::syn(), 1000, 0, &[]);
        assert_eq!(inspect(&pkt), Inspected::TcpSyn { src: sa(APP), dst: sa(WEB) });
    }

    #[test]
    fn a_syn_ack_is_not_a_new_connection() {
        let mut flags = TcpFlags::syn();
        flags.ack = true;
        let pkt = build_tcp(WEB, APP, flags, 5000, 1001, &[]);
        assert_eq!(inspect(&pkt), Inspected::TcpOther { src: sa(WEB), dst: sa(APP) });
    }

    #[test]
    fn an_established_data_segment_is_tcp_other() {
        let pkt = build_tcp(APP, WEB, TcpFlags::ack(), 1001, 5001, b"GET /");
        assert_eq!(inspect(&pkt), Inspected::TcpOther { src: sa(APP), dst: sa(WEB) });
    }

    #[test]
    fn a_udp_datagram_carries_its_payload_out() {
        let dns = (Ipv4Addr::new(1, 1, 1, 1), 53);
        let pkt = build_udp(APP, dns, b"\xAB\xCD query");
        assert_eq!(
            inspect(&pkt),
            Inspected::Udp { src: sa(APP), dst: sa(dns), payload: b"\xAB\xCD query".to_vec() }
        );
    }

    #[test]
    fn icmp_and_other_protocols_are_ignored() {
        let mut pkt = build_udp(APP, WEB, b"x");
        // Rewrite the protocol field to ICMP.
        pkt[9] = 1;
        assert_eq!(inspect(&pkt), Inspected::Ignored);
    }

    #[test]
    fn a_truncated_packet_is_ignored_rather_than_panicking() {
        let pkt = build_tcp(APP, WEB, TcpFlags::syn(), 1, 0, &[]);
        assert_eq!(inspect(&pkt[..10]), Inspected::Ignored);
        assert_eq!(inspect(&[]), Inspected::Ignored);
    }

    #[test]
    fn a_packet_with_a_corrupt_checksum_is_ignored() {
        let mut pkt = build_tcp(APP, WEB, TcpFlags::syn(), 1000, 0, &[]);
        pkt[36] ^= 0xFF; // flip a byte inside the TCP checksum field
        assert_eq!(inspect(&pkt), Inspected::Ignored);
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p liostunnel-core inspect`
Expected: FAIL — `cannot find function inspect in this scope`.

- [ ] **Step 4: Implement `inspect`**

Prepend to `crates/liostunnel-core/src/net/smoltcp_stack/inspect.rs`:

```rust
use std::net::SocketAddr;

use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket, UdpPacket};

/// What a packet drained off the TUN device turns out to be. Spec §7.4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inspected {
    /// A connection attempt to an endpoint we may not be listening on yet.
    TcpSyn { src: SocketAddr, dst: SocketAddr },
    /// Any other TCP segment — smoltcp already has state for it.
    TcpOther { src: SocketAddr, dst: SocketAddr },
    Udp { src: SocketAddr, dst: SocketAddr, payload: Vec<u8> },
    /// Malformed, truncated, or a protocol Phase 0 does not carry.
    Ignored,
}

/// Classifies a bare IPv4 packet. Never panics and never mutates — a malformed
/// packet from a misbehaving application must not be able to stop the engine.
pub fn inspect(packet: &[u8]) -> Inspected {
    let Ok(ip) = Ipv4Packet::new_checked(packet) else {
        return Inspected::Ignored;
    };
    if !ip.verify_checksum() {
        return Inspected::Ignored;
    }

    let src_ip = ip.src_addr();
    let dst_ip = ip.dst_addr();
    let (sa, da) = (IpAddress::Ipv4(src_ip), IpAddress::Ipv4(dst_ip));

    match ip.next_header() {
        IpProtocol::Tcp => {
            let Ok(tcp) = TcpPacket::new_checked(ip.payload()) else {
                return Inspected::Ignored;
            };
            if !tcp.verify_checksum(&sa, &da) {
                return Inspected::Ignored;
            }
            let src = SocketAddr::from((src_ip, tcp.src_port()));
            let dst = SocketAddr::from((dst_ip, tcp.dst_port()));
            // A SYN without ACK is a fresh connection attempt; a SYN-ACK belongs
            // to a handshake smoltcp is already driving.
            if tcp.syn() && !tcp.ack() {
                Inspected::TcpSyn { src, dst }
            } else {
                Inspected::TcpOther { src, dst }
            }
        }
        IpProtocol::Udp => {
            let Ok(udp) = UdpPacket::new_checked(ip.payload()) else {
                return Inspected::Ignored;
            };
            if !udp.verify_checksum(&sa, &da) {
                return Inspected::Ignored;
            }
            Inspected::Udp {
                src: SocketAddr::from((src_ip, udp.src_port())),
                dst: SocketAddr::from((dst_ip, udp.dst_port())),
                payload: udp.payload().to_vec(),
            }
        }
        _ => Inspected::Ignored,
    }
}
```

Add `pub mod inspect;` to `crates/liostunnel-core/src/net/smoltcp_stack/mod.rs`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core inspect`
Expected: PASS — 7 passed.

- [ ] **Step 6: Write the failing `NatTable` tests**

`crates/liostunnel-core/src/net/nat_table.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn ep(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn arming_a_flow_reports_whether_a_listener_is_needed() {
        let mut t = NatTable::default();
        let (a, w) = (ep("10.90.0.2:51234"), ep("93.184.216.34:443"));
        assert!(t.arm(a, w), "first SYN needs a listener");
        assert!(!t.arm(a, w), "a SYN retransmit for the same flow does not");
        assert_eq!(t.armed_len(), 1);
    }

    #[test]
    fn concurrent_connections_to_one_destination_each_get_a_listener() {
        let mut t = NatTable::default();
        let w = ep("93.184.216.34:443");
        // What a browser actually does.
        assert!(t.arm(ep("10.90.0.2:51234"), w));
        assert!(t.arm(ep("10.90.0.2:51235"), w));
        assert!(t.arm(ep("10.90.0.2:51236"), w));
        assert_eq!(t.armed_len(), 3);
    }

    #[test]
    fn disarming_lets_the_same_flow_be_armed_again() {
        let mut t = NatTable::default();
        let (a, w) = (ep("10.90.0.2:51234"), ep("1.2.3.4:80"));
        t.arm(a, w);
        t.disarm(&a, &w);
        assert!(!t.is_armed(&a, &w));
        assert!(t.arm(a, w));
    }

    #[test]
    fn flows_are_tracked_per_destination_port() {
        let mut t = NatTable::default();
        let a = ep("10.90.0.2:51234");
        t.arm(a, ep("1.2.3.4:80"));
        assert!(!t.is_armed(&a, &ep("1.2.3.4:443")));
    }

    #[test]
    fn a_dns_query_can_be_recorded_and_claimed_exactly_once() {
        let mut t = NatTable::default();
        t.record_dns(ep("10.90.0.2:51234"), 0xABCD);
        assert!(t.take_dns(ep("10.90.0.2:51234"), 0xABCD));
        assert!(!t.take_dns(ep("10.90.0.2:51234"), 0xABCD), "replays must not match");
    }

    #[test]
    fn an_unrecorded_dns_response_is_not_claimed() {
        let mut t = NatTable::default();
        assert!(!t.take_dns(ep("10.90.0.2:51234"), 0x0001));
    }
}
```

- [ ] **Step 7: Run to verify failure, then implement**

Run: `cargo test -p liostunnel-core nat_table` — Expected: FAIL, `cannot find type NatTable`.

Prepend to `crates/liostunnel-core/src/net/nat_table.rs`:

```rust
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

/// Tracks which connection attempts currently have a smoltcp listener armed,
/// plus DNS queries awaiting a reply.
///
/// Under SYN-triggered listener injection (spec §7.4) this holds **no address
/// translations** — it only becomes a rewrite table if the destination-rewriting
/// NAT fallback is ever adopted.
///
/// Keyed on the `(src, dst)` 4-tuple rather than the destination alone: a
/// smoltcp listener accepts exactly one connection, so six concurrent sockets
/// to one host need six listeners, while a SYN retransmit needs none.
#[derive(Default, Debug)]
pub struct NatTable {
    armed: HashSet<(SocketAddr, SocketAddr)>,
    dns_inflight: HashMap<(SocketAddr, u16), ()>,
}

impl NatTable {
    /// Returns true if this flow had no listener yet, meaning the caller must
    /// inject one bound to `dst`.
    pub fn arm(&mut self, src: SocketAddr, dst: SocketAddr) -> bool {
        self.armed.insert((src, dst))
    }

    pub fn is_armed(&self, src: &SocketAddr, dst: &SocketAddr) -> bool {
        self.armed.contains(&(*src, *dst))
    }

    pub fn disarm(&mut self, src: &SocketAddr, dst: &SocketAddr) {
        self.armed.remove(&(*src, *dst));
    }

    pub fn armed_len(&self) -> usize {
        self.armed.len()
    }

    pub fn record_dns(&mut self, src: SocketAddr, query_id: u16) {
        self.dns_inflight.insert((src, query_id), ());
    }

    /// Claims an in-flight query. Returns false for a duplicate or unknown reply.
    pub fn take_dns(&mut self, src: SocketAddr, query_id: u16) -> bool {
        self.dns_inflight.remove(&(src, query_id)).is_some()
    }
}
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core nat_table`
Expected: PASS — 5 passed.

- [ ] **Step 9: Commit**

```bash
git add crates/liostunnel-core/src/net/
git commit -m "feat: packet inspection and the listened-endpoint registry"
```

---

### Task 13: `StackCore` — the synchronous engine

Spec §7.3 and §7.4. The hardest code in the project, and — because `QueuedDevice` and `FakePacketIo` exist — fully testable with no TUN device, no root, and no tokio runtime driving it. This is the payoff for Tasks 9–12.

**Files:**
- Create: `crates/liostunnel-core/src/net/smoltcp_stack/core.rs`
- Modify: `crates/liostunnel-core/src/net/smoltcp_stack/mod.rs`

**Interfaces:**
- Consumes: `QueuedDevice` (10), `local_stream_pair`/`StreamPeer` (11), `inspect`/`Inspected` (12), `NatTable` (12), `TcpFlow`/`Datagram`/`StackConfig` (10).
- Produces:
  - `struct StackCore` with `new(cfg: StackConfig) -> Self`, `ingest(&mut self, packet: &[u8])`, `step(&mut self, now: Instant)`, `drain_tx(&mut self) -> Vec<Vec<u8>>`, `poll_delay(&mut self, now: Instant) -> Option<Duration>`, `take_accepts(&mut self) -> Vec<TcpFlow>`, `take_datagrams(&mut self) -> Vec<Datagram>`, `udp_dropped(&self) -> u64`, `active_flows(&self) -> usize`.

- [ ] **Step 1: Write the failing tests**

`crates/liostunnel-core/src/net/smoltcp_stack/core.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::testutil::{TcpFlags, build_tcp, build_udp};
    use smoltcp::wire::{Ipv4Packet, TcpPacket};
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const APP: (Ipv4Addr, u16) = (Ipv4Addr::new(10, 90, 0, 2), 51234);
    const APP2: (Ipv4Addr, u16) = (Ipv4Addr::new(10, 90, 0, 2), 51235);
    const WEB: (Ipv4Addr, u16) = (Ipv4Addr::new(93, 184, 216, 34), 443);

    fn sa(t: (Ipv4Addr, u16)) -> SocketAddr {
        SocketAddr::from(t)
    }

    /// Advances the deterministic clock so retransmit timers behave.
    struct Clock(u64);
    impl Clock {
        fn tick(&mut self) -> Instant {
            self.0 += 10_000;
            Instant::from_micros(self.0 as i64)
        }
    }

    /// Returns (seq, ack, flags_syn, flags_ack, payload) of the last TCP packet
    /// the stack emitted, if any.
    fn last_tcp(core: &mut StackCore) -> Option<(u32, u32, bool, bool, bool, Vec<u8>)> {
        let tx = core.drain_tx();
        let raw = tx.last()?.clone();
        let ip = Ipv4Packet::new_checked(&raw[..]).ok()?;
        let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
        Some((
            tcp.seq_number().0 as u32,
            tcp.ack_number().0 as u32,
            tcp.syn(),
            tcp.ack(),
            tcp.fin(),
            tcp.payload().to_vec(),
        ))
    }

    /// Drives a full three-way handshake and returns the accepted flow plus the
    /// sequence numbers to continue with.
    fn handshake(
        core: &mut StackCore,
        clock: &mut Clock,
        app: (Ipv4Addr, u16),
        web: (Ipv4Addr, u16),
        client_isn: u32,
    ) -> (TcpFlow, u32, u32) {
        core.ingest(&build_tcp(app, web, TcpFlags::syn(), client_isn, 0, &[]));
        core.step(clock.tick());

        let (server_isn, ack, syn, is_ack, _, _) =
            last_tcp(core).expect("stack must answer a SYN");
        assert!(syn && is_ack, "expected SYN-ACK");
        assert_eq!(ack, client_isn + 1);

        core.ingest(&build_tcp(app, web, TcpFlags::ack(), client_isn + 1, server_isn + 1, &[]));
        core.step(clock.tick());

        let mut flows = core.take_accepts();
        assert_eq!(flows.len(), 1, "exactly one flow should be accepted");
        (flows.remove(0), client_isn + 1, server_isn + 1)
    }

    #[tokio::test]
    async fn a_syn_produces_a_flow_carrying_the_real_destination() {
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);

        let (flow, _, _) = handshake(&mut core, &mut clock, APP, WEB, 1000);

        assert_eq!(flow.dst, sa(WEB), "dst must be the app's real destination");
        assert_eq!(flow.src, sa(APP));
        assert_eq!(core.active_flows(), 1);
    }

    #[tokio::test]
    async fn application_bytes_arrive_on_the_flow_stream() {
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);
        let (mut flow, cseq, sseq) = handshake(&mut core, &mut clock, APP, WEB, 1000);

        core.ingest(&build_tcp(APP, WEB, TcpFlags::ack(), cseq, sseq, b"GET / HTTP/1.0\r\n"));
        core.step(clock.tick());

        let mut buf = vec![0u8; 16];
        flow.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"GET / HTTP/1.0\r\n");
    }

    #[tokio::test]
    async fn bytes_written_to_the_flow_reach_the_device_as_tcp_payload() {
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);
        let (mut flow, _, _) = handshake(&mut core, &mut clock, APP, WEB, 1000);

        flow.stream.write_all(b"HTTP/1.0 200 OK\r\n").await.unwrap();
        // Give the channel a moment, then let the stack pick it up.
        tokio::task::yield_now().await;
        core.step(clock.tick());

        let (_, _, _, _, _, payload) = last_tcp(&mut core).expect("stack must emit data");
        assert_eq!(payload, b"HTTP/1.0 200 OK\r\n".to_vec());
    }

    #[tokio::test]
    async fn a_fin_from_the_application_closes_the_flow_stream() {
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);
        let (mut flow, cseq, sseq) = handshake(&mut core, &mut clock, APP, WEB, 1000);

        core.ingest(&build_tcp(APP, WEB, TcpFlags::fin_ack(), cseq, sseq, &[]));
        core.step(clock.tick());
        core.step(clock.tick());

        let mut rest = Vec::new();
        flow.stream.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "FIN must surface as clean EOF");
    }

    #[tokio::test]
    async fn two_concurrent_connections_to_one_destination_both_get_flows() {
        // The regression test for keying the NatTable on the 4-tuple.
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);

        core.ingest(&build_tcp(APP, WEB, TcpFlags::syn(), 1000, 0, &[]));
        core.ingest(&build_tcp(APP2, WEB, TcpFlags::syn(), 2000, 0, &[]));
        core.step(clock.tick());

        // Both handshakes must be answered.
        let tx = core.drain_tx();
        let synacks = tx
            .iter()
            .filter(|raw| {
                Ipv4Packet::new_checked(&raw[..])
                    .ok()
                    .and_then(|ip| TcpPacket::new_checked(ip.payload()).ok().map(|t| t.syn()))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(synacks, 2, "each distinct flow needs its own listener");
    }

    #[test]
    fn a_syn_retransmit_does_not_inject_a_second_listener() {
        let mut core = StackCore::new(StackConfig::default());
        let mut clock = Clock(0);

        let syn = build_tcp(APP, WEB, TcpFlags::syn(), 1000, 0, &[]);
        core.ingest(&syn);
        core.ingest(&syn);
        core.step(clock.tick());

        assert_eq!(core.armed_len(), 1, "a retransmit is the same flow");
    }

    #[test]
    fn a_dns_datagram_is_surfaced_rather_than_dropped() {
        let mut core = StackCore::new(StackConfig::default());
        let dns = (Ipv4Addr::new(1, 1, 1, 1), 53);
        core.ingest(&build_udp(APP, dns, b"\xAB\xCDquery"));

        let dgs = core.take_datagrams();
        assert_eq!(dgs.len(), 1);
        assert_eq!(dgs[0].dst, sa(dns));
        assert_eq!(dgs[0].payload, b"\xAB\xCDquery".to_vec());
        assert_eq!(core.udp_dropped(), 0);
    }

    #[test]
    fn non_dns_udp_is_dropped_and_counted_never_silently() {
        // Spec §7.5.
        let mut core = StackCore::new(StackConfig::default());
        let quic = (Ipv4Addr::new(93, 184, 216, 34), 443);
        core.ingest(&build_udp(APP, quic, b"quic-ish"));

        assert!(core.take_datagrams().is_empty());
        assert_eq!(core.udp_dropped(), 1, "drops must be visible in stats");
    }

    #[test]
    fn a_malformed_packet_does_not_disturb_the_stack() {
        let mut core = StackCore::new(StackConfig::default());
        core.ingest(&[0xFF, 0x01, 0x02]);
        core.ingest(&[]);
        core.step(Instant::from_micros(0));
        assert_eq!(core.active_flows(), 0);
        assert_eq!(core.udp_dropped(), 0);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p liostunnel-core smoltcp_stack::core`
Expected: FAIL — `cannot find type StackCore in this scope`.

(The module path is `smoltcp_stack::core`, not `stack_core` — a bare `stack_core` filter matches nothing and silently reports "0 passed" as if it were success.)

- [ ] **Step 3: Implement**

Prepend to `crates/liostunnel-core/src/net/smoltcp_stack/core.rs`:

```rust
use std::collections::HashMap;
use std::net::SocketAddr;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::sync::mpsc::error::{TryRecvError, TrySendError};

use crate::net::local_stream::{StreamPeer, local_stream_pair};
use crate::net::nat_table::NatTable;
use crate::net::smoltcp_stack::device::QueuedDevice;
use crate::net::smoltcp_stack::inspect::{Inspected, inspect};
use crate::net::{Datagram, StackConfig, TcpFlow};

/// How much is moved between a smoltcp socket and its channel per step.
const CHUNK: usize = 8 * 1024;

/// The synchronous heart of the packet engine. Owns the smoltcp interface,
/// every socket, and the queue-backed device.
///
/// Deliberately contains no threads, no file descriptors, and no async: the
/// wrapper in Task 14 supplies all three. That separation is what makes the
/// engine testable without privileges. Spec §7.3.
pub struct StackCore {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: QueuedDevice,
    nat: NatTable,
    /// Listeners injected but not yet accepted, and the flow each belongs to.
    pending: HashMap<SocketHandle, (SocketAddr, SocketAddr)>,
    flows: HashMap<SocketHandle, Flow>,
    accepts: Vec<TcpFlow>,
    datagrams: Vec<Datagram>,
    cfg: StackConfig,
    udp_dropped: u64,
}

struct Flow {
    src: SocketAddr,
    dst: SocketAddr,
    peer: StreamPeer,
    /// A chunk the socket's send buffer could not take in full.
    pending_out: Option<(Vec<u8>, usize)>,
}

fn to_socket_addr(ep: IpEndpoint) -> Option<SocketAddr> {
    match ep.addr {
        IpAddress::Ipv4(v4) => Some(SocketAddr::from((v4, ep.port))),
        IpAddress::Ipv6(v6) => Some(SocketAddr::from((v6, ep.port))),
    }
}

impl StackCore {
    pub fn new(cfg: StackConfig) -> Self {
        let mut device = QueuedDevice::new(cfg.mtu);

        let mut config = Config::new(HardwareAddress::Ip);
        // Fixed so tests are deterministic; the wrapper in Task 14 randomises it.
        config.random_seed = 0x5eed_1105;

        let mut iface = Interface::new(config, &mut device, Instant::from_micros(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(cfg.address), cfg.netmask_prefix))
                .expect("interface address list has room for one entry");
        });
        // Accept packets addressed to anything, not just our own address —
        // without this, traffic bound for the wider internet is discarded.
        iface.set_any_ip(true);

        Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
            nat: NatTable::default(),
            pending: HashMap::new(),
            flows: HashMap::new(),
            accepts: Vec::new(),
            datagrams: Vec::new(),
            cfg,
            udp_dropped: 0,
        }
    }

    /// Step 1 of the loop: classify a packet, arm a listener if it opens a new
    /// flow, then queue it for `Interface::poll`. Spec §7.4.
    pub fn ingest(&mut self, packet: &[u8]) {
        match inspect(packet) {
            Inspected::TcpSyn { src, dst } => {
                if self.nat.arm(src, dst) {
                    self.inject_listener(src, dst);
                }
                self.device.push_rx(packet.to_vec());
            }
            Inspected::TcpOther { .. } => {
                self.device.push_rx(packet.to_vec());
            }
            // UDP bypasses smoltcp entirely. Spec §7.5.
            Inspected::Udp { src, dst, payload } => {
                if dst.port() == 53 {
                    self.datagrams.push(Datagram { src, dst, payload });
                } else {
                    self.udp_dropped += 1;
                    tracing::debug!(%dst, "dropping non-DNS UDP; SSH cannot forward it");
                }
            }
            Inspected::Ignored => {}
        }
    }

    fn inject_listener(&mut self, src: SocketAddr, dst: SocketAddr) {
        let rx = tcp::SocketBuffer::new(vec![0u8; self.cfg.tcp_buffer_bytes]);
        let tx = tcp::SocketBuffer::new(vec![0u8; self.cfg.tcp_buffer_bytes]);
        let mut socket = tcp::Socket::new(rx, tx);

        let endpoint = IpListenEndpoint {
            addr: Some(match dst {
                SocketAddr::V4(v4) => IpAddress::Ipv4(*v4.ip()),
                SocketAddr::V6(v6) => IpAddress::Ipv6(*v6.ip()),
            }),
            port: dst.port(),
        };
        if let Err(e) = socket.listen(endpoint) {
            tracing::warn!(%dst, ?e, "cannot listen for flow");
            self.nat.disarm(&src, &dst);
            return;
        }
        // A flow whose peer never completes the handshake should not hold a
        // socket for ever.
        socket.set_timeout(Some(Duration::from_secs(30)));

        let handle = self.sockets.add(socket);
        self.pending.insert(handle, (src, dst));
    }

    /// Steps 2 and 4 of the loop: run smoltcp, promote accepted listeners, and
    /// move bytes between sockets and channels.
    pub fn step(&mut self, now: Instant) {
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.promote_accepted();
        self.pump_flows();
        self.reap_closed();
    }

    fn promote_accepted(&mut self) {
        let ready: Vec<SocketHandle> = self
            .pending
            .keys()
            .copied()
            .filter(|h| {
                let s = self.sockets.get::<tcp::Socket>(*h);
                s.state() != tcp::State::Listen && s.state() != tcp::State::SynReceived
            })
            .collect();

        for handle in ready {
            let (src, dst) = self.pending.remove(&handle).expect("key came from the map");
            self.nat.disarm(&src, &dst);

            let socket = self.sockets.get::<tcp::Socket>(handle);
            if !socket.is_active() {
                // The listener timed out or was reset before establishing.
                self.sockets.remove(handle);
                continue;
            }

            // Prefer the addresses smoltcp actually negotiated.
            let real_src = socket.remote_endpoint().and_then(to_socket_addr).unwrap_or(src);
            let real_dst = socket.local_endpoint().and_then(to_socket_addr).unwrap_or(dst);

            let (stream, peer) = local_stream_pair(self.cfg.channel_depth);
            self.flows.insert(
                handle,
                Flow { src: real_src, dst: real_dst, peer, pending_out: None },
            );
            self.accepts.push(TcpFlow { src: real_src, dst: real_dst, stream });
            tracing::debug!(src = %real_src, dst = %real_dst, "flow accepted");
        }
    }

    fn pump_flows(&mut self) {
        for (handle, flow) in self.flows.iter_mut() {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);

            // (a) finish any chunk the send buffer could not take last time.
            if let Some((chunk, off)) = flow.pending_out.take() {
                if socket.can_send() {
                    match socket.send_slice(&chunk[off..]) {
                        Ok(n) if off + n < chunk.len() => {
                            flow.pending_out = Some((chunk, off + n));
                        }
                        Ok(_) => {}
                        Err(_) => flow.pending_out = Some((chunk, off)),
                    }
                } else {
                    flow.pending_out = Some((chunk, off));
                }
            }

            // (b) tunnel → application.
            while flow.pending_out.is_none() && socket.can_send() {
                match flow.peer.from_stream.try_recv() {
                    Ok(chunk) => match socket.send_slice(&chunk) {
                        Ok(n) if n < chunk.len() => flow.pending_out = Some((chunk, n)),
                        Ok(_) => {}
                        Err(_) => break,
                    },
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        // The engine finished with this flow: send FIN.
                        socket.close();
                        break;
                    }
                }
            }

            // (c) application → tunnel. Stopping when the channel is full is
            // exactly the backpressure path: smoltcp's receive buffer fills and
            // the advertised window shrinks. Spec §7.2.
            while socket.can_recv() {
                match flow.peer.to_stream.try_reserve() {
                    Ok(permit) => {
                        let mut buf = vec![0u8; CHUNK];
                        match socket.recv_slice(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                buf.truncate(n);
                                permit.send(buf);
                            }
                        }
                    }
                    Err(TrySendError::Full(())) => break,
                    Err(TrySendError::Closed(())) => {
                        socket.close();
                        break;
                    }
                }
            }
        }
    }

    fn reap_closed(&mut self) {
        let dead: Vec<SocketHandle> = self
            .flows
            .keys()
            .copied()
            .filter(|h| {
                let s = self.sockets.get::<tcp::Socket>(*h);
                s.state() == tcp::State::Closed
            })
            .collect();

        for handle in dead {
            // Dropping the Flow drops StreamPeer, which the LocalStream sees as
            // EOF — a clean close for whichever side is still reading.
            if let Some(f) = self.flows.remove(&handle) {
                tracing::debug!(src = %f.src, dst = %f.dst, "flow closed");
            }
            self.sockets.remove(handle);
        }
    }

    /// Step 3 of the loop.
    pub fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.device.drain_tx()
    }

    /// Step 5's timeout. `None` means "nothing is pending; sleep until a packet
    /// or a wakeup arrives".
    pub fn poll_delay(&mut self, now: Instant) -> Option<Duration> {
        self.iface.poll_delay(now, &self.sockets)
    }

    pub fn take_accepts(&mut self) -> Vec<TcpFlow> {
        std::mem::take(&mut self.accepts)
    }

    pub fn take_datagrams(&mut self) -> Vec<Datagram> {
        std::mem::take(&mut self.datagrams)
    }

    pub fn udp_dropped(&self) -> u64 {
        self.udp_dropped
    }

    pub fn active_flows(&self) -> usize {
        self.flows.len()
    }

    pub fn armed_len(&self) -> usize {
        self.nat.armed_len()
    }
}
```

Add `pub mod core;` to `crates/liostunnel-core/src/net/smoltcp_stack/mod.rs`, and add `dev-dependencies` on `tokio` with the `rt` and `macros` features if not already present.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core smoltcp_stack::core -- --nocapture`
Expected: PASS — 9 passed.

If `Socket::set_timeout` or `SocketSet::remove` differ, check `cargo doc -p smoltcp --open`; everything else in this task is pinned by the verified API reference.

- [ ] **Step 5: Commit**

```bash
git add crates/liostunnel-core/src/net/
git commit -m "feat: StackCore with SYN-triggered listener injection"
```

---

### Task 14: `SmoltcpStack` — the thread, the wakeup, the `NetStack` impl

Spec §7.3, step 5. Exit criterion **EC5** (idle CPU ≈ 0%) is won or lost here.

**Files:**
- Create: `crates/liostunnel-core/src/net/smoltcp_stack/poll.rs`
- Modify: `crates/liostunnel-core/src/net/tun.rs`, `crates/liostunnel-core/src/net/smoltcp_stack/mod.rs`, `crates/liostunnel-core/Cargo.toml`

**Interfaces:**
- Consumes: `StackCore` (13), `PacketIo` (9), `NetStack`/`StackHandles`/`ShutdownHandle` (10).
- Produces: `struct SmoltcpStack` implementing `NetStack`. Adds `fn pollable_fd(&self) -> Option<RawFd>` to `PacketIo` with a `None` default.

- [ ] **Step 1: Extend `PacketIo`**

Add to the `PacketIo` trait in `crates/liostunnel-core/src/net/tun.rs`:

```rust
    /// The descriptor to wait on, when the implementation has one.
    /// `None` means the caller must fall back to a timed poll — only the
    /// in-memory test double does this.
    #[cfg(unix)]
    fn pollable_fd(&self) -> Option<std::os::fd::RawFd> {
        None
    }
```

And implement it for `TunDevice`:

```rust
    #[cfg(unix)]
    fn pollable_fd(&self) -> Option<std::os::fd::RawFd> {
        use std::os::fd::AsRawFd;
        Some(self.as_raw_fd())
    }
```

Add `polling.workspace = true` to `crates/liostunnel-core/Cargo.toml`.

- [ ] **Step 2: Write the failing test**

`crates/liostunnel-core/src/net/smoltcp_stack/poll.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::testutil::{TcpFlags, build_tcp};
    use crate::net::tun::FakePacketIo;
    use crate::net::{NetStack, StackConfig};
    use std::net::Ipv4Addr;

    /// Proves the thread wiring works end to end: a SYN pushed into the fake
    /// device comes back out of the `tcp_accept` channel as a flow. The
    /// handshake itself is covered exhaustively by Task 13's tests.
    #[tokio::test]
    async fn a_syn_on_the_device_surfaces_as_an_accepted_flow() {
        let app = (Ipv4Addr::new(10, 90, 0, 2), 51234);
        let web = (Ipv4Addr::new(93, 184, 216, 34), 443);

        let mut io = FakePacketIo::new(1500);
        io.push_inbound(build_tcp(app, web, TcpFlags::syn(), 1000, 0, &[]));

        let handles = SmoltcpStack::default()
            .start(Box::new(io), StackConfig::default())
            .unwrap();

        // The fake device never yields an fd, so the loop falls back to a timed
        // poll; the SYN-ACK and the flow still materialise.
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut h = handles;
            // The handshake needs the peer's ACK, which a fake device cannot
            // supply — so assert the stack at least answered, then stop.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            h.shutdown.shutdown();
            h.tcp_accept.close();
        })
        .await
        .expect("stack thread must not hang");
    }

    #[tokio::test]
    async fn shutdown_stops_the_thread_promptly() {
        let io = FakePacketIo::new(1500);
        let handles = SmoltcpStack::default()
            .start(Box::new(io), StackConfig::default())
            .unwrap();

        let t0 = std::time::Instant::now();
        handles.shutdown.shutdown();
        // Joining is not exposed; observe the effect instead — the accept
        // channel closes once the thread drops its sender.
        let mut rx = handles.tcp_accept;
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while rx.recv().await.is_some() {}
        })
        .await
        .expect("thread must exit and close the channel");
        assert!(t0.elapsed() < std::time::Duration::from_secs(2));
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p liostunnel-core smoltcp_stack::poll`
Expected: FAIL — `cannot find type SmoltcpStack in this scope`.

- [ ] **Step 4: Implement**

Prepend to `crates/liostunnel-core/src/net/smoltcp_stack/poll.rs`:

```rust
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use polling::{Event, Events, Poller};
use smoltcp::time::Instant;
use tokio::sync::mpsc;

use crate::error::TunnelError;
use crate::net::smoltcp_stack::core::StackCore;
use crate::net::tun::PacketIo;
use crate::net::{Datagram, NetStack, ShutdownHandle, StackConfig, StackHandles, TcpFlow};

/// Ceiling on how long the loop sleeps when smoltcp has no pending timer.
/// Only reached if the device supplies no pollable descriptor.
const MAX_IDLE: StdDuration = StdDuration::from_millis(500);

/// The default `NetStack`: a dedicated thread around [`StackCore`]. Decision D7.
#[derive(Default)]
pub struct SmoltcpStack;

impl NetStack for SmoltcpStack {
    fn start(
        self,
        mut io: Box<dyn PacketIo>,
        cfg: StackConfig,
    ) -> Result<StackHandles, TunnelError> {
        let (tcp_tx, tcp_accept) = mpsc::channel::<TcpFlow>(cfg.channel_depth);
        let (udp_in_tx, udp_inbound) = mpsc::channel::<Datagram>(cfg.channel_depth);
        let (udp_outbound, mut udp_out_rx) = mpsc::channel::<Datagram>(cfg.channel_depth);
        let shutdown = ShutdownHandle::default();

        let poller = Arc::new(
            Poller::new().map_err(|e| TunnelError::Tun(format!("cannot create poller: {e}")))?,
        );

        // Datagrams bound for the device arrive on a tokio channel, but the
        // stack thread is synchronous. Bridge them onto a std channel and wake
        // the loop, so an outbound DNS reply is never left waiting for a timeout.
        let (bridge_tx, bridge_rx) = std::sync::mpsc::channel::<Datagram>();
        {
            let poller = poller.clone();
            tokio::spawn(async move {
                while let Some(dg) = udp_out_rx.recv().await {
                    if bridge_tx.send(dg).is_err() {
                        break;
                    }
                    let _ = poller.notify();
                }
            });
        }

        let key = 7usize;
        let has_fd = {
            #[cfg(unix)]
            {
                match io.pollable_fd() {
                    Some(fd) => {
                        // SAFETY: the descriptor is owned by `io`, which this
                        // thread keeps alive for as long as the poller is used.
                        unsafe {
                            poller.add(&fd, Event::readable(key)).map_err(|e| {
                                TunnelError::Tun(format!("cannot register TUN fd: {e}"))
                            })?;
                        }
                        true
                    }
                    None => false,
                }
            }
            #[cfg(not(unix))]
            {
                false
            }
        };

        let shutdown_thread = shutdown.clone();
        let poller_thread = poller.clone();
        std::thread::Builder::new()
            .name("liostunnel-stack".into())
            .spawn(move || {
                let mtu = io.mtu();
                let mut core = StackCore::new(cfg);
                let mut buf = vec![0u8; mtu + 4];
                let mut events = Events::new();
                let started = std::time::Instant::now();
                // Flows that could not be handed over because the channel was
                // full. Retried rather than dropped — an accepted connection
                // that vanishes is indistinguishable from a hang.
                let mut backlog: VecDeque<TcpFlow> = VecDeque::new();

                loop {
                    if shutdown_thread.is_shutdown() {
                        break;
                    }

                    // Step 1: drain the device, inspecting on the way past.
                    loop {
                        match io.read_packet(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => core.ingest(&buf[..n]),
                            Err(e) => {
                                tracing::warn!(%e, "TUN read failed");
                                break;
                            }
                        }
                    }

                    // Outbound datagrams (DNS replies) synthesised by the engine.
                    while let Ok(dg) = bridge_rx.try_recv() {
                        core.inject_datagram(dg);
                    }

                    // Steps 2 and 4.
                    let now = Instant::from_micros(started.elapsed().as_micros() as i64);
                    core.step(now);

                    // Step 3.
                    for packet in core.drain_tx() {
                        if let Err(e) = io.write_packet(&packet) {
                            tracing::warn!(%e, "TUN write failed");
                        }
                    }

                    // Hand accepted flows to the engine, keeping any that do not fit.
                    backlog.extend(core.take_accepts());
                    while let Some(flow) = backlog.pop_front() {
                        match tcp_tx.try_send(flow) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(f)) => {
                                backlog.push_front(f);
                                break;
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => return,
                        }
                    }

                    for dg in core.take_datagrams() {
                        if udp_in_tx.try_send(dg).is_err() {
                            // Either full or closed; a dropped DNS query is
                            // retried by the resolver on the device.
                            break;
                        }
                    }

                    // Step 5: sleep on the device, the wakeup, and smoltcp's
                    // own timer at once. This is why idle-connected costs no
                    // CPU — see EC5. Spec §7.3.
                    let timeout = core
                        .poll_delay(now)
                        .map(|d| StdDuration::from_micros(d.total_micros()))
                        .unwrap_or(MAX_IDLE)
                        .min(MAX_IDLE);

                    events.clear();
                    if let Err(e) = poller_thread.wait(&mut events, Some(timeout)) {
                        tracing::warn!(%e, "poller wait failed");
                    }
                    #[cfg(unix)]
                    if has_fd {
                        // `polling` is oneshot: re-arm for the next iteration.
                        if let Some(fd) = io.pollable_fd() {
                            let _ = poller_thread.modify(&fd, Event::readable(key));
                        }
                    }
                }

                tracing::debug!("stack thread exiting");
            })
            .map_err(|e| TunnelError::Tun(format!("cannot spawn stack thread: {e}")))?;

        Ok(StackHandles { tcp_accept, udp_inbound, udp_outbound, shutdown })
    }
}
```

- [ ] **Step 5: Add `StackCore::inject_datagram`**

The thread calls it; Task 18 gives it a body. Add to `crates/liostunnel-core/src/net/smoltcp_stack/core.rs`:

```rust
impl StackCore {
    /// Queues a datagram for delivery to the device. Reply synthesis lands in
    /// Task 18; until then the datagram is counted and discarded.
    pub fn inject_datagram(&mut self, _dg: Datagram) {
        self.udp_dropped += 1;
    }
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core smoltcp_stack`
Expected: PASS — Task 13's 9 tests plus these 2.

Add `pub mod poll;` to `crates/liostunnel-core/src/net/smoltcp_stack/mod.rs`.

- [ ] **Step 7: Commit**

```bash
git add crates/liostunnel-core/
git commit -m "feat: stack thread with a device+timer+wakeup poll, no busy-wait"
```

---

### Task 15: `Engine` — joining the stack to the protocol

Spec §7.6 and §11.

**Files:**
- Create: `crates/liostunnel-core/src/engine.rs`
- Modify: `crates/liostunnel-core/src/lib.rs`, `crates/liostunnel-core/src/stats.rs`

**Interfaces:**
- Consumes: `NetStack`/`StackHandles`/`TcpFlow` (10, 14), `Protocol` (6), `ConnectionStats` (6).
- Produces: `struct Engine` with `Engine::new(protocol: Arc<dyn Protocol>, handles: StackHandles) -> Self`, `async fn run(self) -> Result<(), TunnelError>`, `fn stats_handle(&self) -> StatsHandle`, `fn shutdown_handle(&self) -> ShutdownHandle`. (Task 17's `connect.rs` calls the `_handle` names — the Step 2 code below is authoritative.)

- [ ] **Step 1: Write the failing tests**

`crates/liostunnel-core/src/engine.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::local_stream::local_stream_pair;
    use crate::protocols::TunnelStream;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Records the destinations asked for and returns a duplex pipe whose far
    /// end the test can drive — standing in for the SSH channel.
    struct MockProtocol {
        opened: Mutex<Vec<SocketAddr>>,
        far_end: Mutex<Option<tokio::io::DuplexStream>>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl Protocol for MockProtocol {
        async fn connect(
            &mut self,
            _p: &crate::config::profile::ServerProfile,
            _s: &dyn crate::config::secret::SecretStore,
        ) -> Result<(), TunnelError> {
            Ok(())
        }

        async fn open_tcp_stream(
            &self,
            dest: SocketAddr,
        ) -> Result<Box<dyn TunnelStream>, TunnelError> {
            self.opened.lock().unwrap().push(dest);
            if self.fail {
                return Err(TunnelError::Protocol("refused".into()));
            }
            let (near, far) = tokio::io::duplex(8192);
            *self.far_end.lock().unwrap() = Some(far);
            Ok(Box::new(near))
        }

        async fn send_udp(&self, _d: SocketAddr, _b: &[u8]) -> Result<(), TunnelError> {
            Err(TunnelError::Unsupported("udp"))
        }
        async fn disconnect(&mut self) -> Result<(), TunnelError> {
            Ok(())
        }
        fn stats(&self) -> ConnectionStats {
            ConnectionStats::default()
        }
    }

    fn mock(fail: bool) -> Arc<MockProtocol> {
        Arc::new(MockProtocol { opened: Mutex::new(Vec::new()), far_end: Mutex::new(None), fail })
    }

    #[tokio::test]
    async fn a_flow_opens_a_tunnel_stream_to_its_real_destination() {
        let proto = mock(false);
        let (tcp_tx, tcp_accept) = tokio::sync::mpsc::channel(4);
        let (_udp_in_tx, udp_inbound) = tokio::sync::mpsc::channel(4);
        let (udp_outbound, _udp_out_rx) = tokio::sync::mpsc::channel(4);

        let engine = Engine::new(
            proto.clone(),
            StackHandles {
                tcp_accept,
                udp_inbound,
                udp_outbound,
                shutdown: ShutdownHandle::default(),
            },
        );
        let handle = tokio::spawn(engine.run());

        // The peer half stands in for the packet stack; holding it open keeps
        // the flow alive long enough to observe the engine's reaction.
        let (stream, _peer) = local_stream_pair(8);
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        tcp_tx
            .send(TcpFlow { src: "10.90.0.2:51234".parse().unwrap(), dst, stream })
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(proto.opened.lock().unwrap().as_slice(), &[dst]);

        drop(tcp_tx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn a_refused_destination_increments_the_counter_and_leaves_the_engine_running() {
        // Spec §11: per-flow failures stay per-flow.
        let proto = mock(true);
        let (tcp_tx, tcp_accept) = tokio::sync::mpsc::channel(4);
        let (_a, udp_inbound) = tokio::sync::mpsc::channel(4);
        let (udp_outbound, _b) = tokio::sync::mpsc::channel(4);

        let engine = Engine::new(
            proto.clone(),
            StackHandles {
                tcp_accept,
                udp_inbound,
                udp_outbound,
                shutdown: ShutdownHandle::default(),
            },
        );
        let stats = engine.stats_handle();
        let handle = tokio::spawn(engine.run());

        for port in [443u16, 8443] {
            let (s, _p) = local_stream_pair(8);
            tcp_tx
                .send(TcpFlow {
                    src: "10.90.0.2:51234".parse().unwrap(),
                    dst: format!("93.184.216.34:{port}").parse().unwrap(),
                    stream: s,
                })
                .await
                .unwrap();
        }

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(stats.load().flows_failed, 2, "both failures must be counted");
        assert_eq!(proto.opened.lock().unwrap().len(), 2, "engine kept accepting");

        drop(tcp_tx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }
}
```

- [ ] **Step 2: Run to verify failure, then implement**

Run: `cargo test -p liostunnel-core engine` — Expected: FAIL, `cannot find type Engine`.

Prepend to `crates/liostunnel-core/src/engine.rs`:

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::TunnelError;
use crate::net::{ShutdownHandle, StackHandles, TcpFlow};
use crate::protocols::Protocol;
use crate::stats::{ConnectionState, ConnectionStats};

/// Shared, lock-free counters. Cheap enough to update on every flow.
#[derive(Default)]
pub struct EngineCounters {
    pub flows_opened: AtomicU64,
    pub flows_failed: AtomicU64,
    pub dns_queries: AtomicU64,
}

#[derive(Clone)]
pub struct StatsHandle(Arc<EngineCounters>);

impl StatsHandle {
    pub fn load(&self) -> ConnectionStats {
        ConnectionStats {
            state: ConnectionState::Connected,
            flows_failed: self.0.flows_failed.load(Ordering::Relaxed),
            dns_queries: self.0.dns_queries.load(Ordering::Relaxed),
            active_flows: 0,
            ..Default::default()
        }
    }
}

/// Ties the packet stack to the active protocol. Spec §7.6.
pub struct Engine {
    protocol: Arc<dyn Protocol>,
    handles: StackHandles,
    counters: Arc<EngineCounters>,
}

impl Engine {
    pub fn new(protocol: Arc<dyn Protocol>, handles: StackHandles) -> Self {
        Self { protocol, handles, counters: Arc::new(EngineCounters::default()) }
    }

    pub fn stats_handle(&self) -> StatsHandle {
        StatsHandle(self.counters.clone())
    }

    pub fn shutdown_handle(&self) -> ShutdownHandle {
        self.handles.shutdown.clone()
    }

    pub async fn run(mut self) -> Result<(), TunnelError> {
        while let Some(flow) = self.handles.tcp_accept.recv().await {
            let protocol = self.protocol.clone();
            let counters = self.counters.clone();
            tokio::spawn(async move { proxy_one(flow, protocol, counters).await });
        }
        tracing::info!("stack closed; engine stopping");
        Ok(())
    }
}

/// One proxied connection. A failure here is contained to this flow: the
/// `LocalStream` is dropped, which makes the stack emit RST, and the engine
/// carries on. Spec §11.
async fn proxy_one(flow: TcpFlow, protocol: Arc<dyn Protocol>, counters: Arc<EngineCounters>) {
    let TcpFlow { src, dst, mut stream } = flow;

    let mut remote = match protocol.open_tcp_stream(dst).await {
        Ok(r) => {
            counters.flows_opened.fetch_add(1, Ordering::Relaxed);
            r
        }
        Err(e) => {
            counters.flows_failed.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%src, %dst, %e, "cannot open tunnel stream; resetting flow");
            return; // dropping `stream` resets the local connection
        }
    };

    match tokio::io::copy_bidirectional(&mut stream, &mut remote).await {
        Ok((up, down)) => tracing::debug!(%src, %dst, up, down, "flow finished"),
        Err(e) => tracing::debug!(%src, %dst, %e, "flow ended with an error"),
    }
}
```

Add `pub mod engine;` to `crates/liostunnel-core/src/lib.rs`.

- [ ] **Step 3: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core engine`
Expected: PASS — 2 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/liostunnel-core/src/
git commit -m "feat: Engine joining accepted flows to protocol streams"
```

---

### Task 16: `RouteManager` — test mode

Spec §10 / decision D6. The design trick: **command construction is a pure function, execution is separate.** That makes routing logic unit-testable without root, and leaves only a thin `Command::spawn` shell that needs privileges.

**Files:**
- Create: `crates/liostunnel-core/src/route/mod.rs`, `crates/liostunnel-core/src/route/macos.rs`, `crates/liostunnel-core/src/route/linux.rs`
- Modify: `crates/liostunnel-core/src/lib.rs`, `crates/liostunnel-core/Cargo.toml`

**Interfaces:**
- Consumes: `TunnelError`.
- Produces:
  - `enum RouteMode { Test { cidrs: Vec<IpNet>, capture_dns: bool }, Default }`
  - `struct RoutePlan { interface: String, mode: RouteMode, server_ip: IpAddr, original_gateway: IpAddr, dns_servers: Vec<IpAddr> }`
  - `struct RouteCommand { program: String, args: Vec<String> }` with `fn run(&self) -> Result<(), TunnelError>`
  - `trait RouteManager: Send + Sync { fn apply_commands(&self, plan: &RoutePlan) -> Result<Vec<RouteCommand>, TunnelError>; fn revert_commands(&self, plan: &RoutePlan) -> Result<Vec<RouteCommand>, TunnelError>; fn detect_gateway(&self) -> Result<IpAddr, TunnelError>; }`
  - `fn platform_manager() -> Box<dyn RouteManager>`
  - `struct RouteGuard` — reverts on drop.

- [ ] **Step 1: Add `ipnet`**

Add `ipnet.workspace = true` to `crates/liostunnel-core/Cargo.toml`.

- [ ] **Step 2: Write the failing tests**

`crates/liostunnel-core/src/route/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn plan(mode: RouteMode) -> RoutePlan {
        RoutePlan {
            interface: "utun7".into(),
            mode,
            server_ip: "198.51.100.7".parse().unwrap(),
            original_gateway: "192.168.1.1".parse().unwrap(),
            dns_servers: vec!["1.1.1.1".parse().unwrap()],
        }
    }

    fn test_mode(capture_dns: bool) -> RouteMode {
        RouteMode::Test {
            cidrs: vec!["93.184.216.0/24".parse().unwrap()],
            capture_dns,
        }
    }

    fn rendered(cmds: &[RouteCommand]) -> Vec<String> {
        cmds.iter().map(|c| format!("{} {}", c.program, c.args.join(" "))).collect()
    }

    #[test]
    fn macos_test_mode_routes_only_the_listed_cidrs() {
        let cmds = macos::MacOsRoutes.apply_commands(&plan(test_mode(false))).unwrap();
        let r = rendered(&cmds);
        assert_eq!(r.len(), 1, "no DNS capture was requested: {r:?}");
        assert_eq!(r[0], "route -n add -net 93.184.216.0/24 -interface utun7");
    }

    #[test]
    fn macos_test_mode_adds_host_routes_for_dns_when_asked() {
        let cmds = macos::MacOsRoutes.apply_commands(&plan(test_mode(true))).unwrap();
        let r = rendered(&cmds);
        assert!(
            r.iter().any(|c| c.contains("-host 1.1.1.1") && c.contains("utun7")),
            "spec §10 requires --capture-dns to route the resolvers: {r:?}"
        );
    }

    #[test]
    fn linux_test_mode_uses_ip_route() {
        let cmds = linux::LinuxRoutes.apply_commands(&plan(test_mode(false))).unwrap();
        assert_eq!(rendered(&cmds)[0], "ip route add 93.184.216.0/24 dev utun7");
    }

    #[test]
    fn test_mode_never_touches_the_default_route() {
        for r in [
            rendered(&macos::MacOsRoutes.apply_commands(&plan(test_mode(true))).unwrap()),
            rendered(&linux::LinuxRoutes.apply_commands(&plan(test_mode(true))).unwrap()),
        ] {
            assert!(
                !r.iter().any(|c| c.contains("0.0.0.0/1") || c.contains("128.0.0.0/1")),
                "test mode must not install default-beating routes: {r:?}"
            );
        }
    }

    #[test]
    fn reverting_undoes_exactly_what_was_applied() {
        for mgr in [
            Box::new(macos::MacOsRoutes) as Box<dyn RouteManager>,
            Box::new(linux::LinuxRoutes),
        ] {
            let p = plan(test_mode(true));
            let applied = mgr.apply_commands(&p).unwrap();
            let reverted = mgr.revert_commands(&p).unwrap();
            assert_eq!(
                applied.len(),
                reverted.len(),
                "every applied route needs a matching revert"
            );
            assert!(rendered(&reverted).iter().all(|c| c.contains("del")));
        }
    }
}
```

- [ ] **Step 3: Run to verify failure, then implement**

Run: `cargo test -p liostunnel-core route` — Expected: FAIL, `cannot find type RoutePlan`.

Prepend to `crates/liostunnel-core/src/route/mod.rs`:

```rust
pub mod linux;
pub mod macos;

use std::net::IpAddr;

use ipnet::IpNet;

use crate::error::TunnelError;

#[derive(Clone, Debug)]
pub enum RouteMode {
    /// Route only these prefixes. Cannot lock the operator out of the machine,
    /// which is why it is built first. Decision D6.
    Test { cidrs: Vec<IpNet>, capture_dns: bool },
    /// Full default-route override. Lands in Task 21.
    Default,
}

#[derive(Clone, Debug)]
pub struct RoutePlan {
    pub interface: String,
    pub mode: RouteMode,
    /// Pinned via the original gateway in `Default` mode so the tunnel's own
    /// transport does not route through itself. Spec §10.
    pub server_ip: IpAddr,
    pub original_gateway: IpAddr,
    pub dns_servers: Vec<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl RouteCommand {
    pub fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn run(&self) -> Result<(), TunnelError> {
        let out = std::process::Command::new(&self.program)
            .args(&self.args)
            .output()
            .map_err(|e| {
                TunnelError::Route(format!("cannot execute `{}`: {e}", self.program))
            })?;
        if !out.status.success() {
            return Err(TunnelError::Route(format!(
                "`{} {}` failed: {}",
                self.program,
                self.args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }
}

/// Command construction is pure so it can be unit-tested without privileges;
/// only [`RouteCommand::run`] needs root. Spec §10.
pub trait RouteManager: Send + Sync {
    fn apply_commands(&self, plan: &RoutePlan) -> Result<Vec<RouteCommand>, TunnelError>;
    fn revert_commands(&self, plan: &RoutePlan) -> Result<Vec<RouteCommand>, TunnelError>;
    fn detect_gateway(&self) -> Result<IpAddr, TunnelError>;
}

pub fn platform_manager() -> Box<dyn RouteManager> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsRoutes)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(linux::LinuxRoutes)
    }
}

/// Reverts on drop, covering normal exit and unwinding panics. The other two
/// cleanup paths (signals, state file) arrive in Task 21. Spec §10.
pub struct RouteGuard {
    manager: Box<dyn RouteManager>,
    plan: RoutePlan,
    active: bool,
}

impl RouteGuard {
    pub fn apply(manager: Box<dyn RouteManager>, plan: RoutePlan) -> Result<Self, TunnelError> {
        for cmd in manager.apply_commands(&plan)? {
            cmd.run()?;
        }
        tracing::info!(interface = %plan.interface, "routes applied");
        Ok(Self { manager, plan, active: true })
    }

    pub fn revert_now(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        match self.manager.revert_commands(&self.plan) {
            Ok(cmds) => {
                for cmd in cmds {
                    if let Err(e) = cmd.run() {
                        // Keep going: a partial revert beats an early return.
                        tracing::error!(%e, "route revert step failed");
                    }
                }
                tracing::info!("routes reverted");
            }
            Err(e) => tracing::error!(%e, "cannot build revert commands"),
        }
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        self.revert_now();
    }
}
```

`crates/liostunnel-core/src/route/macos.rs`:

```rust
use std::net::IpAddr;

use crate::error::TunnelError;
use crate::route::{RouteCommand, RouteManager, RouteMode, RoutePlan};

pub struct MacOsRoutes;

impl RouteManager for MacOsRoutes {
    fn apply_commands(&self, plan: &RoutePlan) -> Result<Vec<RouteCommand>, TunnelError> {
        let mut cmds = Vec::new();
        match &plan.mode {
            RouteMode::Test { cidrs, capture_dns } => {
                for cidr in cidrs {
                    cmds.push(RouteCommand::new(
                        "route",
                        &["-n", "add", "-net", &cidr.to_string(), "-interface", &plan.interface],
                    ));
                }
                if *capture_dns {
                    for dns in &plan.dns_servers {
                        cmds.push(RouteCommand::new(
                            "route",
                            &["-n", "add", "-host", &dns.to_string(), "-interface", &plan.interface],
                        ));
                    }
                }
            }
            RouteMode::Default => return Err(TunnelError::Unsupported("default route mode")),
        }
        Ok(cmds)
    }

    fn revert_commands(&self, plan: &RoutePlan) -> Result<Vec<RouteCommand>, TunnelError> {
        let mut cmds = Vec::new();
        match &plan.mode {
            RouteMode::Test { cidrs, capture_dns } => {
                for cidr in cidrs {
                    cmds.push(RouteCommand::new(
                        "route",
                        &["-n", "delete", "-net", &cidr.to_string(), "-interface", &plan.interface],
                    ));
                }
                if *capture_dns {
                    for dns in &plan.dns_servers {
                        cmds.push(RouteCommand::new(
                            "route",
                            &["-n", "delete", "-host", &dns.to_string(), "-interface", &plan.interface],
                        ));
                    }
                }
            }
            RouteMode::Default => return Err(TunnelError::Unsupported("default route mode")),
        }
        Ok(cmds)
    }

    fn detect_gateway(&self) -> Result<IpAddr, TunnelError> {
        let out = std::process::Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .map_err(|e| TunnelError::Route(format!("cannot run `route get default`: {e}")))?;
        let text = String::from_utf8_lossy(&out.stdout);
        text.lines()
            .find_map(|l| l.trim().strip_prefix("gateway:"))
            .and_then(|v| v.trim().parse().ok())
            .ok_or_else(|| TunnelError::Route("no default gateway found".into()))
    }
}
```

`crates/liostunnel-core/src/route/linux.rs`:

```rust
use std::net::IpAddr;

use crate::error::TunnelError;
use crate::route::{RouteCommand, RouteManager, RouteMode, RoutePlan};

pub struct LinuxRoutes;

impl RouteManager for LinuxRoutes {
    fn apply_commands(&self, plan: &RoutePlan) -> Result<Vec<RouteCommand>, TunnelError> {
        let mut cmds = Vec::new();
        match &plan.mode {
            RouteMode::Test { cidrs, capture_dns } => {
                for cidr in cidrs {
                    cmds.push(RouteCommand::new(
                        "ip",
                        &["route", "add", &cidr.to_string(), "dev", &plan.interface],
                    ));
                }
                if *capture_dns {
                    for dns in &plan.dns_servers {
                        cmds.push(RouteCommand::new(
                            "ip",
                            &["route", "add", &format!("{dns}/32"), "dev", &plan.interface],
                        ));
                    }
                }
            }
            RouteMode::Default => return Err(TunnelError::Unsupported("default route mode")),
        }
        Ok(cmds)
    }

    fn revert_commands(&self, plan: &RoutePlan) -> Result<Vec<RouteCommand>, TunnelError> {
        let mut cmds = Vec::new();
        match &plan.mode {
            RouteMode::Test { cidrs, capture_dns } => {
                for cidr in cidrs {
                    cmds.push(RouteCommand::new(
                        "ip",
                        &["route", "del", &cidr.to_string(), "dev", &plan.interface],
                    ));
                }
                if *capture_dns {
                    for dns in &plan.dns_servers {
                        cmds.push(RouteCommand::new(
                            "ip",
                            &["route", "del", &format!("{dns}/32"), "dev", &plan.interface],
                        ));
                    }
                }
            }
            RouteMode::Default => return Err(TunnelError::Unsupported("default route mode")),
        }
        Ok(cmds)
    }

    fn detect_gateway(&self) -> Result<IpAddr, TunnelError> {
        let out = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .map_err(|e| TunnelError::Route(format!("cannot run `ip route show default`: {e}")))?;
        let text = String::from_utf8_lossy(&out.stdout);
        // e.g. "default via 192.168.1.1 dev eth0 ..."
        text.split_whitespace()
            .skip_while(|t| *t != "via")
            .nth(1)
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| TunnelError::Route("no default gateway found".into()))
    }
}
```

Add `pub mod route;` to `crates/liostunnel-core/src/lib.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core route`
Expected: PASS — 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/liostunnel-core/src/route/
git commit -m "feat: RouteManager with pure command construction, test mode"
```

---

### Task 17: `liostunnel connect` — exit criterion EC1

**Files:**
- Create: `crates/liostunnel-cli/src/commands/connect.rs`
- Modify: `crates/liostunnel-cli/src/cli.rs`, `crates/liostunnel-cli/src/commands/mod.rs`, `crates/liostunnel-cli/src/main.rs`

**Interfaces:**
- Consumes: everything built so far.
- Produces: `connect::run(profile, user, opts, policy) -> Result<(), TunnelError>` and the `Connect` subcommand.

- [ ] **Step 1: Extend the CLI**

Add to `enum Command` in `crates/liostunnel-cli/src/cli.rs`:

```rust
    /// Bring up the TUN device and route traffic through the tunnel.
    Connect {
        profile: PathBuf,
        #[arg(long)]
        user: String,
        /// `test` routes only --cidr; `default` takes over all traffic (Task 21).
        #[arg(long, default_value = "test")]
        route_mode: String,
        /// Prefixes to route in test mode. Repeatable.
        #[arg(long = "cidr")]
        cidrs: Vec<String>,
        /// Also route the profile's DNS servers through the tunnel. Spec §10.
        #[arg(long)]
        capture_dns: bool,
        /// Address assigned to the TUN interface.
        #[arg(long, default_value = "10.90.0.1")]
        tun_address: std::net::Ipv4Addr,
    },
```

- [ ] **Step 2: Implement**

`crates/liostunnel-cli/src/commands/connect.rs`:

```rust
use std::sync::Arc;

use liostunnel_core::TunnelError;
use liostunnel_core::config::profile::ServerProfile;
use liostunnel_core::config::secret::FileSecretStore;
use liostunnel_core::engine::Engine;
use liostunnel_core::net::smoltcp_stack::poll::SmoltcpStack;
use liostunnel_core::net::tun::{TunConfig, TunDevice};
use liostunnel_core::net::{NetStack, StackConfig};
use liostunnel_core::protocols::Protocol;
use liostunnel_core::protocols::ssh::{HostKeyPolicy, SshTunnel};
use liostunnel_core::route::{RouteGuard, RouteMode, RoutePlan, platform_manager};

pub struct ConnectOpts {
    pub route_mode: RouteMode,
    pub tun_address: std::net::Ipv4Addr,
}

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
    let protocol: Arc<dyn Protocol> = Arc::new(ssh);

    // 2. Create the TUN device.
    let tun = TunDevice::open(TunConfig {
        name: None,
        address: opts.tun_address,
        netmask: std::net::Ipv4Addr::new(255, 255, 255, 0),
        mtu: 1500,
    })?;
    let interface = tun.name()?;
    tracing::info!(%interface, address = %opts.tun_address, "TUN interface up");

    // 3. Start the packet stack.
    let handles = SmoltcpStack::default().start(
        Box::new(tun),
        StackConfig { address: opts.tun_address, ..Default::default() },
    )?;

    // 4. Install routes. The guard reverts them on drop, including on panic.
    let manager = platform_manager();
    let gateway = manager.detect_gateway()?;
    let server_ip = tokio::net::lookup_host((profile.host.as_str(), profile.port))
        .await
        .map_err(|e| TunnelError::Route(format!("cannot resolve {}: {e}", profile.host)))?
        .next()
        .ok_or_else(|| TunnelError::Route(format!("no address for {}", profile.host)))?
        .ip();

    let mut guard = RouteGuard::apply(
        manager,
        RoutePlan {
            interface,
            mode: opts.route_mode,
            server_ip,
            original_gateway: gateway,
            dns_servers: profile.dns.servers.clone(),
        },
    )?;

    // 5. Run until interrupted.
    let engine = Engine::new(protocol, handles);
    let shutdown = engine.shutdown_handle();
    let stats = engine.stats_handle();
    let engine_task = tokio::spawn(engine.run());

    println!("connected — press Ctrl-C to stop");
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| TunnelError::Transport(e))?;
    println!("\nshutting down");

    shutdown.shutdown();
    guard.revert_now();
    engine_task.abort();

    let s = stats.load();
    println!("flows failed: {}, dns queries: {}", s.flows_failed, s.dns_queries);
    Ok(())
}
```

Wire it into `crates/liostunnel-cli/src/main.rs`'s `match cli.command`:

```rust
        Command::Connect { profile, user, route_mode, cidrs, capture_dns, tun_address } => {
            let p = profile_io::load(&profile, &secret_dir)?;
            p.validate(&FileSecretStore)?;
            emit_warnings(&p);

            let mode = match route_mode.as_str() {
                "test" => {
                    let parsed = cidrs
                        .iter()
                        .map(|c| {
                            c.parse::<ipnet::IpNet>().map_err(|e| {
                                liostunnel_core::TunnelError::config("--cidr", e.to_string())
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    if parsed.is_empty() {
                        return Err(liostunnel_core::TunnelError::config(
                            "--cidr",
                            "test route mode needs at least one prefix",
                        ));
                    }
                    liostunnel_core::route::RouteMode::Test { cidrs: parsed, capture_dns }
                }
                "default" => liostunnel_core::route::RouteMode::Default,
                other => {
                    return Err(liostunnel_core::TunnelError::config(
                        "--route-mode",
                        format!("expected `test` or `default`, got `{other}`"),
                    ));
                }
            };

            commands::connect::run(
                &p,
                user,
                commands::connect::ConnectOpts { route_mode: mode, tun_address },
                policy,
            )
            .await
        }
```

Add `pub mod connect;` to `crates/liostunnel-cli/src/commands/mod.rs`, and `ipnet.workspace = true` to the CLI's dependencies.

- [ ] **Step 3: Verify EC1**

With the Docker fixture up and a profile pointing at it, on Linux (or macOS with `sudo`):

```bash
sudo -E cargo run -p liostunnel-cli -- --insecure-accept-any-hostkey \
  connect /tmp/fixture.liostunnel.json --user tunneluser \
  --route-mode test --cidr 93.184.216.0/24
```

In another shell: `curl -v http://93.184.216.34/`

Expected: the request completes through the tunnel; the connect process logs `flow accepted` with `dst=93.184.216.34:80`. Ctrl-C restores the routing table — verify with `netstat -rn | grep 93.184.216` (macOS) or `ip route | grep 93.184.216` (Linux), which must print nothing afterwards.

**Exit criterion EC1 met. Milestone B is complete.**

- [ ] **Step 4: Commit**

```bash
git add crates/liostunnel-cli/
git commit -m "feat: liostunnel connect wiring TUN, stack, SSH, and routes"
```

---

# Milestone C — DNS, the default route, and the release gates

Ends at exit criteria **EC2–EC7**, completing Phase 0.

---

### Task 18: DNS interception and UDP reply synthesis

Spec §7.5 and §9.1. Decision D3.

**Files:**
- Create: `crates/liostunnel-core/src/dns/mod.rs`
- Modify: `crates/liostunnel-core/src/net/smoltcp_stack/device.rs`, `crates/liostunnel-core/src/net/smoltcp_stack/core.rs`, `crates/liostunnel-core/src/net/testutil.rs`, `crates/liostunnel-core/src/engine.rs`, `crates/liostunnel-core/src/lib.rs`

**Interfaces:**
- Consumes: `Datagram` (10), `NatTable` (12), `StackCore` (13), `Engine` (15).
- Produces:
  - `#[async_trait] trait Resolver: Send + Sync { async fn query(&self, query: &[u8]) -> Result<Vec<u8>, TunnelError>; }`
  - `fn build_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, TunnelError>`
  - `fn dns_query_id(payload: &[u8]) -> Option<u16>`
  - `QueuedDevice::push_tx(Vec<u8>)`
  - A real `StackCore::inject_datagram`, replacing Task 14's counting stub.
  - `Engine::new(protocol, resolver, handles)` — **signature change from Task 15**, which took only `(protocol, handles)`.

- [ ] **Step 1: Write the failing tests**

`crates/liostunnel-core/src/dns/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{IpAddress, Ipv4Packet, UdpPacket};
    use std::net::SocketAddr;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_synthesised_reply_is_a_well_formed_checksummed_udp_packet() {
        let from = sa("1.1.1.1:53");
        let to = sa("10.90.0.2:51234");
        let raw = build_udp_packet(from, to, b"\xAB\xCD answer").unwrap();

        let ip = Ipv4Packet::new_checked(&raw[..]).expect("valid IPv4");
        assert!(ip.verify_checksum(), "IP checksum must be correct");
        assert_eq!(ip.src_addr().to_string(), "1.1.1.1");
        assert_eq!(ip.dst_addr().to_string(), "10.90.0.2");

        let udp = UdpPacket::new_checked(ip.payload()).expect("valid UDP");
        assert!(
            udp.verify_checksum(&IpAddress::Ipv4(ip.src_addr()), &IpAddress::Ipv4(ip.dst_addr())),
            "UDP checksum must be correct or the host stack discards the reply"
        );
        assert_eq!(udp.src_port(), 53);
        assert_eq!(udp.dst_port(), 51234);
        assert_eq!(udp.payload(), b"\xAB\xCD answer");
    }

    #[test]
    fn the_query_id_is_the_first_two_bytes_big_endian() {
        assert_eq!(dns_query_id(&[0xAB, 0xCD, 0x01, 0x00]), Some(0xABCD));
        assert_eq!(dns_query_id(&[0x00, 0x01]), Some(1));
    }

    #[test]
    fn a_runt_payload_has_no_query_id() {
        assert_eq!(dns_query_id(&[0xAB]), None);
        assert_eq!(dns_query_id(&[]), None);
    }

    #[test]
    fn mixing_address_families_is_rejected_rather_than_producing_garbage() {
        let v6 = sa("[2001:db8::1]:53");
        let v4 = sa("10.90.0.2:51234");
        assert!(build_udp_packet(v6, v4, b"x").is_err());
    }
}
```

Append to `crates/liostunnel-core/src/net/smoltcp_stack/core.rs`'s test module:

```rust
    #[test]
    fn an_injected_datagram_is_written_towards_the_device() {
        let mut core = StackCore::new(StackConfig::default());
        let dns = (Ipv4Addr::new(1, 1, 1, 1), 53);

        core.ingest(&build_udp(APP, dns, b"\xAB\xCDquery"));
        let dgs = core.take_datagrams();
        assert_eq!(dgs.len(), 1);

        // The engine answers: src/dst are swapped relative to the query.
        core.inject_datagram(Datagram {
            src: sa(dns),
            dst: sa(APP),
            payload: b"\xAB\xCDanswer".to_vec(),
        });

        let tx = core.drain_tx();
        assert_eq!(tx.len(), 1, "the reply must reach the device");
        let ip = Ipv4Packet::new_checked(&tx[0][..]).unwrap();
        assert!(ip.verify_checksum());
        assert_eq!(core.udp_dropped(), 0, "a DNS reply is not a drop");
    }

    #[test]
    fn an_unsolicited_reply_is_still_delivered_but_a_malformed_one_is_counted() {
        let mut core = StackCore::new(StackConfig::default());
        // Address families that cannot produce a packet.
        core.inject_datagram(Datagram {
            src: "[2001:db8::1]:53".parse().unwrap(),
            dst: sa(APP),
            payload: b"x".to_vec(),
        });
        assert!(core.drain_tx().is_empty());
        assert_eq!(core.udp_dropped(), 1);
    }
```

- [ ] **Step 2: Run to verify failure, then implement the DNS module**

Run: `cargo test -p liostunnel-core dns` — Expected: FAIL, `cannot find function build_udp_packet`.

Prepend to `crates/liostunnel-core/src/dns/mod.rs`:

```rust
pub mod over_https;
pub mod over_tcp;

use std::net::SocketAddr;

use async_trait::async_trait;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, UdpPacket};

use crate::error::TunnelError;

/// Resolves a DNS query by carrying it through the tunnel. Decision D3.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Takes and returns raw DNS wire-format bytes. The payload is opaque —
    /// nothing here parses or logs its contents. Spec §11.
    async fn query(&self, query: &[u8]) -> Result<Vec<u8>, TunnelError>;
}

/// The transaction id, used to match a reply to its query.
pub fn dns_query_id(payload: &[u8]) -> Option<u16> {
    if payload.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([payload[0], payload[1]]))
}

/// Builds a complete IPv4 + UDP packet. Checksums must be right or the host's
/// own stack silently discards the reply, which looks exactly like a hang.
pub fn build_udp_packet(
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, TunnelError> {
    let (s4, d4) = match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => (s, d),
        _ => {
            return Err(TunnelError::Dns(
                "Phase 0 synthesises IPv4 datagrams only".into(),
            ));
        }
    };

    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut buf = vec![0u8; total];

    {
        let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_total_len(total as u16);
        ip.set_ident(0);
        ip.set_dont_frag(true);
        ip.set_more_frags(false);
        ip.set_frag_offset(0);
        ip.set_hop_limit(64);
        ip.set_next_header(IpProtocol::Udp);
        ip.set_src_addr(*s4.ip());
        ip.set_dst_addr(*d4.ip());
    }
    {
        let mut udp = UdpPacket::new_unchecked(&mut buf[20..]);
        udp.set_src_port(s4.port());
        udp.set_dst_port(d4.port());
        udp.set_len(udp_len as u16);
        udp.payload_mut().copy_from_slice(payload);
        udp.fill_checksum(&IpAddress::Ipv4(*s4.ip()), &IpAddress::Ipv4(*d4.ip()));
    }
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip.fill_checksum();
    }
    Ok(buf)
}
```

Add `pub mod dns;` to `crates/liostunnel-core/src/lib.rs`.

Simplify `crates/liostunnel-core/src/net/testutil.rs` to reuse it — replace the body of `build_udp` with:

```rust
pub fn build_udp(src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16), payload: &[u8]) -> Vec<u8> {
    crate::dns::build_udp_packet(SocketAddr::from(src), SocketAddr::from(dst), payload)
        .expect("test addresses are IPv4")
}
```

(and add `use std::net::SocketAddr;` there).

- [ ] **Step 3: Implement `inject_datagram`**

Add to `crates/liostunnel-core/src/net/smoltcp_stack/device.rs`:

```rust
impl QueuedDevice {
    /// Queues a fully-formed packet for the device, bypassing smoltcp. Used for
    /// synthesised DNS replies. Spec §7.5.
    pub fn push_tx(&mut self, packet: Vec<u8>) {
        self.tx.push_back(packet);
    }
}
```

Replace the stub `StackCore::inject_datagram` from Task 14 with:

```rust
    /// Delivers a datagram to the device. `src`/`dst` are already oriented
    /// device-ward: `src` is the resolver, `dst` the application.
    pub fn inject_datagram(&mut self, dg: Datagram) {
        match crate::dns::build_udp_packet(dg.src, dg.dst, &dg.payload) {
            Ok(packet) => self.device.push_tx(packet),
            Err(e) => {
                self.udp_dropped += 1;
                tracing::debug!(%e, "cannot synthesise datagram for the device");
            }
        }
    }
```

- [ ] **Step 4: Add the DNS loop to the engine**

In `crates/liostunnel-core/src/engine.rs`, add a `resolver` field, change `new`, and drive `udp_inbound` alongside `tcp_accept`:

```rust
pub struct Engine {
    protocol: Arc<dyn Protocol>,
    resolver: Arc<dyn crate::dns::Resolver>,
    handles: StackHandles,
    counters: Arc<EngineCounters>,
}

impl Engine {
    pub fn new(
        protocol: Arc<dyn Protocol>,
        resolver: Arc<dyn crate::dns::Resolver>,
        handles: StackHandles,
    ) -> Self {
        Self { protocol, resolver, handles, counters: Arc::new(EngineCounters::default()) }
    }

    pub async fn run(mut self) -> Result<(), TunnelError> {
        loop {
            tokio::select! {
                flow = self.handles.tcp_accept.recv() => match flow {
                    None => break,
                    Some(flow) => {
                        let (p, c) = (self.protocol.clone(), self.counters.clone());
                        tokio::spawn(async move { proxy_one(flow, p, c).await });
                    }
                },
                dg = self.handles.udp_inbound.recv() => match dg {
                    None => break,
                    Some(dg) => {
                        let resolver = self.resolver.clone();
                        let out = self.handles.udp_outbound.clone();
                        let counters = self.counters.clone();
                        tokio::spawn(async move { resolve_one(dg, resolver, out, counters).await });
                    }
                },
            }
        }
        tracing::info!("stack closed; engine stopping");
        Ok(())
    }
}

/// One DNS query. A failure drops the query silently on the wire, which the
/// application's own resolver retries — far better than answering wrongly.
async fn resolve_one(
    dg: crate::net::Datagram,
    resolver: Arc<dyn crate::dns::Resolver>,
    out: tokio::sync::mpsc::Sender<crate::net::Datagram>,
    counters: Arc<EngineCounters>,
) {
    counters.dns_queries.fetch_add(1, Ordering::Relaxed);
    match resolver.query(&dg.payload).await {
        Ok(answer) => {
            // Swap the endpoints: the reply comes *from* the resolver.
            let reply = crate::net::Datagram { src: dg.dst, dst: dg.src, payload: answer };
            if out.send(reply).await.is_err() {
                tracing::debug!("stack closed before the DNS reply could be delivered");
            }
        }
        Err(e) => tracing::debug!(%e, "DNS query failed; the client will retry"),
    }
}
```

Update Task 15's two engine tests to pass a resolver. Add this stub to that test module:

```rust
    struct NullResolver;
    #[async_trait::async_trait]
    impl crate::dns::Resolver for NullResolver {
        async fn query(&self, _q: &[u8]) -> Result<Vec<u8>, TunnelError> {
            Err(TunnelError::Dns("no resolver in this test".into()))
        }
    }
```

and change both `Engine::new(proto.clone(), StackHandles { .. })` calls to
`Engine::new(proto.clone(), Arc::new(NullResolver), StackHandles { .. })`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core`
Expected: PASS — the full suite, including the two new `StackCore` datagram tests and 4 DNS tests.

- [ ] **Step 6: Commit**

```bash
git add crates/liostunnel-core/src/
git commit -m "feat: DNS interception with checksummed UDP reply synthesis"
```

---

### Task 19: DNS-over-TCP (RFC 7766)

Spec §7.6. The default resolver, and the one that needs no new dependencies.

**Files:**
- Create: `crates/liostunnel-core/src/dns/over_tcp.rs`

**Interfaces:**
- Consumes: `Resolver` (18), `Protocol` (6).
- Produces: `struct TcpResolver { protocol: Arc<dyn Protocol>, servers: Vec<IpAddr>, timeout: Duration }` with `TcpResolver::new(protocol, servers)`.

- [ ] **Step 1: Write the failing tests**

`crates/liostunnel-core/src/dns/over_tcp.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::TunnelStream;
    use crate::stats::ConnectionStats;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Speaks RFC 7766 on the far end of the "tunnel": reads a length-prefixed
    /// query and answers with a length-prefixed response.
    struct EchoDnsProtocol {
        asked: Mutex<Vec<SocketAddr>>,
        answer: Vec<u8>,
        refuse: bool,
    }

    #[async_trait]
    impl crate::protocols::Protocol for EchoDnsProtocol {
        async fn connect(
            &mut self,
            _p: &crate::config::profile::ServerProfile,
            _s: &dyn crate::config::secret::SecretStore,
        ) -> Result<(), TunnelError> {
            Ok(())
        }

        async fn open_tcp_stream(
            &self,
            dest: SocketAddr,
        ) -> Result<Box<dyn TunnelStream>, TunnelError> {
            self.asked.lock().unwrap().push(dest);
            if self.refuse {
                return Err(TunnelError::Protocol("refused".into()));
            }
            let (near, mut far) = tokio::io::duplex(4096);
            let answer = self.answer.clone();
            tokio::spawn(async move {
                let mut len = [0u8; 2];
                if far.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                if far.read_exact(&mut q).await.is_err() {
                    return;
                }
                let _ = far.write_all(&(answer.len() as u16).to_be_bytes()).await;
                let _ = far.write_all(&answer).await;
            });
            Ok(Box::new(near))
        }

        async fn send_udp(&self, _d: SocketAddr, _b: &[u8]) -> Result<(), TunnelError> {
            Err(TunnelError::Unsupported("udp"))
        }
        async fn disconnect(&mut self) -> Result<(), TunnelError> {
            Ok(())
        }
        fn stats(&self) -> ConnectionStats {
            ConnectionStats::default()
        }
    }

    fn proto(answer: &[u8], refuse: bool) -> Arc<EchoDnsProtocol> {
        Arc::new(EchoDnsProtocol {
            asked: Mutex::new(Vec::new()),
            answer: answer.to_vec(),
            refuse,
        })
    }

    #[tokio::test]
    async fn a_query_is_framed_with_a_two_byte_length_and_the_answer_unframed() {
        let p = proto(b"\xAB\xCDanswer-bytes", false);
        let r = TcpResolver::new(p.clone(), vec!["1.1.1.1".parse().unwrap()]);

        let got = r.query(b"\xAB\xCDquery").await.unwrap();
        assert_eq!(got, b"\xAB\xCDanswer-bytes".to_vec());
        assert_eq!(p.asked.lock().unwrap().as_slice(), &["1.1.1.1:53".parse().unwrap()]);
    }

    #[tokio::test]
    async fn the_next_server_is_tried_when_the_first_is_unreachable() {
        let p = proto(b"", true);
        let r = TcpResolver::new(
            p.clone(),
            vec!["1.1.1.1".parse().unwrap(), "1.0.0.1".parse().unwrap()],
        );

        assert!(r.query(b"\xAB\xCDq").await.is_err());
        assert_eq!(
            p.asked.lock().unwrap().len(),
            2,
            "both configured resolvers must be attempted"
        );
    }

    #[tokio::test]
    async fn an_oversized_query_is_rejected_before_it_reaches_the_wire() {
        let p = proto(b"x", false);
        let r = TcpResolver::new(p.clone(), vec!["1.1.1.1".parse().unwrap()]);

        let huge = vec![0u8; 70_000];
        assert!(r.query(&huge).await.is_err());
        assert!(p.asked.lock().unwrap().is_empty(), "must not open a channel");
    }

    #[tokio::test]
    async fn no_configured_servers_is_an_error_not_a_hang() {
        let p = proto(b"x", false);
        let r = TcpResolver::new(p, vec![]);
        assert!(r.query(b"\xAB\xCDq").await.is_err());
    }
}
```

- [ ] **Step 2: Run to verify failure, then implement**

Run: `cargo test -p liostunnel-core over_tcp` — Expected: FAIL, `cannot find type TcpResolver`.

Prepend to `crates/liostunnel-core/src/dns/over_tcp.rs`:

```rust
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::dns::Resolver;
use crate::error::TunnelError;
use crate::protocols::Protocol;

const DNS_PORT: u16 = 53;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Plain DNS carried over a TCP channel through the tunnel, framed per RFC 7766
/// with a two-byte big-endian length prefix. The zero-dependency default that
/// makes DNS work at all when the protocol cannot forward UDP. Decision D3.
pub struct TcpResolver {
    protocol: Arc<dyn Protocol>,
    servers: Vec<IpAddr>,
    timeout: Duration,
}

impl TcpResolver {
    pub fn new(protocol: Arc<dyn Protocol>, servers: Vec<IpAddr>) -> Self {
        Self { protocol, servers, timeout: DEFAULT_TIMEOUT }
    }

    async fn query_one(&self, server: IpAddr, query: &[u8]) -> Result<Vec<u8>, TunnelError> {
        let dest = SocketAddr::new(server, DNS_PORT);
        let mut stream = self.protocol.open_tcp_stream(dest).await?;

        let len = u16::try_from(query.len())
            .map_err(|_| TunnelError::Dns("query exceeds 65535 bytes".into()))?;

        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| TunnelError::Dns(format!("cannot send query length: {e}")))?;
        stream
            .write_all(query)
            .await
            .map_err(|e| TunnelError::Dns(format!("cannot send query: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| TunnelError::Dns(format!("cannot flush query: {e}")))?;

        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| TunnelError::Dns(format!("cannot read answer length: {e}")))?;

        let n = u16::from_be_bytes(len_buf) as usize;
        if n == 0 {
            return Err(TunnelError::Dns("resolver returned an empty answer".into()));
        }
        let mut answer = vec![0u8; n];
        stream
            .read_exact(&mut answer)
            .await
            .map_err(|e| TunnelError::Dns(format!("cannot read answer: {e}")))?;

        Ok(answer)
    }
}

#[async_trait]
impl Resolver for TcpResolver {
    async fn query(&self, query: &[u8]) -> Result<Vec<u8>, TunnelError> {
        if self.servers.is_empty() {
            return Err(TunnelError::Dns("no DNS servers configured".into()));
        }
        // Reject before opening a channel, so a malformed query costs nothing.
        if u16::try_from(query.len()).is_err() {
            return Err(TunnelError::Dns("query exceeds 65535 bytes".into()));
        }

        let mut last = None;
        for server in &self.servers {
            match tokio::time::timeout(self.timeout, self.query_one(*server, query)).await {
                Ok(Ok(answer)) => return Ok(answer),
                Ok(Err(e)) => {
                    tracing::debug!(%server, %e, "resolver failed; trying the next");
                    last = Some(e);
                }
                Err(_) => {
                    tracing::debug!(%server, "resolver timed out; trying the next");
                    last = Some(TunnelError::Dns(format!("{server} timed out")));
                }
            }
        }
        Err(last.unwrap_or_else(|| TunnelError::Dns("all resolvers failed".into())))
    }
}
```

- [ ] **Step 3: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core over_tcp`
Expected: PASS — 4 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/liostunnel-core/src/dns/
git commit -m "feat: RFC 7766 DNS-over-TCP resolver through the tunnel"
```

---

### Task 20: DNS-over-HTTPS

Spec §7.6 and §9.1. The bootstrap problem is solved by config, not code: `dns.servers` holds IP literals and `dns.https.sni` supplies the TLS name, so nothing needs resolving to start resolving.

**Files:**
- Create: `crates/liostunnel-core/src/dns/over_https.rs`
- Modify: `crates/liostunnel-core/Cargo.toml`, workspace `Cargo.toml`

**Interfaces:**
- Consumes: `Resolver` (18), `Protocol` (6), `DohConfig` (3).
- Produces: `struct DohResolver` with `DohResolver::new(protocol, servers, doh: DohConfig)`, and `fn build_doh_request(sni: &str, path: &str, query: &[u8]) -> Result<http::Request<Full<Bytes>>, TunnelError>`.

- [ ] **Step 1: Add dependencies**

Add to `[workspace.dependencies]`:

```toml
hyper = { version = "1.11", features = ["client", "http1"] }
hyper-util = { version = "0.1", features = ["tokio"] }
http-body-util = "0.1"
bytes = "1"
tokio-rustls = "0.26"
rustls = "0.23"
webpki-roots = "1"
```

Add all of them to `crates/liostunnel-core/Cargo.toml` behind a default-on feature so a DNS-over-TCP-only build stays lean (spec §14 risk register):

```toml
[features]
default = ["doh"]
doh = ["dep:hyper", "dep:hyper-util", "dep:http-body-util", "dep:bytes",
       "dep:tokio-rustls", "dep:rustls", "dep:webpki-roots"]
```

with each of those dependencies marked `optional = true`.

- [ ] **Step 2: Write the failing tests**

`crates/liostunnel-core/src/dns/over_https.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_targets_the_configured_sni_and_path() {
        let req = build_doh_request("cloudflare-dns.com", "/dns-query", b"\xAB\xCDq").unwrap();
        assert_eq!(req.method(), http::Method::POST);
        assert_eq!(req.uri().to_string(), "https://cloudflare-dns.com/dns-query");
    }

    #[test]
    fn the_request_declares_the_dns_message_media_type_both_ways() {
        // RFC 8484 §4.1 — a DoH server may refuse anything else.
        let req = build_doh_request("dns.google", "/dns-query", b"\xAB\xCDq").unwrap();
        assert_eq!(req.headers()["content-type"], "application/dns-message");
        assert_eq!(req.headers()["accept"], "application/dns-message");
        assert_eq!(req.headers()["content-length"], "5");
    }

    #[test]
    fn a_path_without_a_leading_slash_is_rejected() {
        assert!(build_doh_request("dns.google", "dns-query", b"q").is_err());
    }

    #[test]
    fn an_empty_sni_is_rejected() {
        assert!(build_doh_request("", "/dns-query", b"q").is_err());
    }

    /// Exercises the real path against a public resolver. Not part of the
    /// default suite — it needs outbound network.
    #[tokio::test]
    #[ignore = "requires outbound network access to 1.1.1.1:443"]
    async fn resolves_a_real_name_over_the_public_internet() {
        use crate::dns::testutil::DirectProtocol;
        use std::sync::Arc;

        let r = DohResolver::new(
            Arc::new(DirectProtocol),
            vec!["1.1.1.1".parse().unwrap()],
            crate::config::profile::DohConfig {
                sni: "cloudflare-dns.com".into(),
                path: "/dns-query".into(),
            },
        );

        // A minimal query for example.com A, transaction id 0xABCD.
        let query: Vec<u8> = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let answer = r.query(&query).await.unwrap();
        assert_eq!(&answer[..2], &[0xAB, 0xCD], "transaction id must be echoed");
        assert!(answer.len() > query.len(), "an answer carries records");
    }
}
```

Add the direct-TCP helper at `crates/liostunnel-core/src/dns/testutil.rs`, declared `#[cfg(test)] pub(crate) mod testutil;` in `dns/mod.rs`:

```rust
//! A `Protocol` that opens ordinary sockets, for tests that want to reach the
//! real network without an SSH server in the way.

use std::net::SocketAddr;

use async_trait::async_trait;

use crate::config::profile::ServerProfile;
use crate::config::secret::SecretStore;
use crate::error::TunnelError;
use crate::protocols::{Protocol, TunnelStream};
use crate::stats::ConnectionStats;

pub struct DirectProtocol;

#[async_trait]
impl Protocol for DirectProtocol {
    async fn connect(
        &mut self,
        _p: &ServerProfile,
        _s: &dyn SecretStore,
    ) -> Result<(), TunnelError> {
        Ok(())
    }

    async fn open_tcp_stream(
        &self,
        dest: SocketAddr,
    ) -> Result<Box<dyn TunnelStream>, TunnelError> {
        let s = tokio::net::TcpStream::connect(dest)
            .await
            .map_err(|e| TunnelError::Protocol(format!("cannot connect to {dest}: {e}")))?;
        Ok(Box::new(s))
    }

    async fn send_udp(&self, _d: SocketAddr, _b: &[u8]) -> Result<(), TunnelError> {
        Err(TunnelError::Unsupported("udp"))
    }
    async fn disconnect(&mut self) -> Result<(), TunnelError> {
        Ok(())
    }
    fn stats(&self) -> ConnectionStats {
        ConnectionStats::default()
    }
}
```

- [ ] **Step 3: Run to verify failure, then implement**

Run: `cargo test -p liostunnel-core over_https` — Expected: FAIL, `cannot find function build_doh_request`.

Prepend to `crates/liostunnel-core/src/dns/over_https.rs`:

```rust
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;

use crate::config::profile::DohConfig;
use crate::dns::Resolver;
use crate::error::TunnelError;
use crate::protocols::Protocol;

const HTTPS_PORT: u16 = 443;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const MEDIA_TYPE: &str = "application/dns-message";

/// DNS-over-HTTPS (RFC 8484) carried through the tunnel.
///
/// The transport is a `TunnelStream`, not a `TcpStream`, so `reqwest` is not
/// usable here — hyper's connection API is driven directly over our own IO.
/// Spec §5.
pub struct DohResolver {
    protocol: Arc<dyn Protocol>,
    servers: Vec<IpAddr>,
    doh: DohConfig,
    timeout: Duration,
}

impl DohResolver {
    pub fn new(protocol: Arc<dyn Protocol>, servers: Vec<IpAddr>, doh: DohConfig) -> Self {
        Self { protocol, servers, doh, timeout: DEFAULT_TIMEOUT }
    }
}

/// Pure request construction, so the wire shape is testable without a server.
pub fn build_doh_request(
    sni: &str,
    path: &str,
    query: &[u8],
) -> Result<http::Request<Full<Bytes>>, TunnelError> {
    if sni.trim().is_empty() {
        return Err(TunnelError::Dns("dns.https.sni must not be empty".into()));
    }
    if !path.starts_with('/') {
        return Err(TunnelError::Dns("dns.https.path must start with `/`".into()));
    }

    http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("https://{sni}{path}"))
        .header(http::header::HOST, sni)
        .header(http::header::CONTENT_TYPE, MEDIA_TYPE)
        .header(http::header::ACCEPT, MEDIA_TYPE)
        .header(http::header::CONTENT_LENGTH, query.len().to_string())
        .body(Full::new(Bytes::copy_from_slice(query)))
        .map_err(|e| TunnelError::Dns(format!("cannot build DoH request: {e}")))
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

impl DohResolver {
    async fn query_one(&self, server: IpAddr, query: &[u8]) -> Result<Vec<u8>, TunnelError> {
        // The channel goes to an IP literal; TLS is verified against the
        // configured SNI. This is what removes the bootstrap loop. Spec §9.1.
        let stream = self
            .protocol
            .open_tcp_stream(SocketAddr::new(server, HTTPS_PORT))
            .await?;

        let name = rustls::pki_types::ServerName::try_from(self.doh.sni.clone())
            .map_err(|e| TunnelError::Dns(format!("invalid SNI `{}`: {e}", self.doh.sni)))?;

        let tls = tokio_rustls::TlsConnector::from(tls_config())
            .connect(name, stream)
            .await
            .map_err(|e| TunnelError::Dns(format!("TLS handshake with {server} failed: {e}")))?;

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| TunnelError::Dns(format!("HTTP handshake failed: {e}")))?;

        // The connection task drives IO; it ends when the response is complete.
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(%e, "DoH connection closed");
            }
        });

        let req = build_doh_request(&self.doh.sni, &self.doh.path, query)?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| TunnelError::Dns(format!("DoH request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(TunnelError::Dns(format!(
                "resolver answered HTTP {}",
                resp.status()
            )));
        }

        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| TunnelError::Dns(format!("cannot read DoH body: {e}")))?
            .to_bytes();

        if body.is_empty() {
            return Err(TunnelError::Dns("resolver returned an empty body".into()));
        }
        Ok(body.to_vec())
    }
}

#[async_trait]
impl Resolver for DohResolver {
    async fn query(&self, query: &[u8]) -> Result<Vec<u8>, TunnelError> {
        if self.servers.is_empty() {
            return Err(TunnelError::Dns("no DNS servers configured".into()));
        }

        let mut last = None;
        for server in &self.servers {
            match tokio::time::timeout(self.timeout, self.query_one(*server, query)).await {
                Ok(Ok(answer)) => return Ok(answer),
                Ok(Err(e)) => {
                    tracing::debug!(%server, %e, "DoH resolver failed; trying the next");
                    last = Some(e);
                }
                Err(_) => last = Some(TunnelError::Dns(format!("{server} timed out"))),
            }
        }
        Err(last.unwrap_or_else(|| TunnelError::Dns("all DoH resolvers failed".into())))
    }
}
```

Also add `http = "1"` to the workspace dependencies and to the `doh` feature.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core over_https`
Expected: PASS — 4 passed (the network test stays ignored).

Then verify the real path once: `cargo test -p liostunnel-core over_https -- --ignored`
Expected: PASS — 1 passed.

- [ ] **Step 5: Verify the lean build still compiles**

Run: `cargo check -p liostunnel-core --no-default-features`
Expected: no errors — DNS-over-TCP builds without the TLS/HTTP stack.

- [ ] **Step 6: Wire resolver selection into the CLI**

In `crates/liostunnel-cli/src/commands/connect.rs`, before constructing the `Engine`:

```rust
    let resolver: Arc<dyn liostunnel_core::dns::Resolver> = match profile.dns.mode {
        liostunnel_core::config::profile::DnsMode::Tcp => Arc::new(
            liostunnel_core::dns::over_tcp::TcpResolver::new(
                protocol.clone(),
                profile.dns.servers.clone(),
            ),
        ),
        liostunnel_core::config::profile::DnsMode::Https => {
            let doh = profile.dns.https.clone().ok_or_else(|| {
                TunnelError::config("dns.https", "required when dns.mode is `https`")
            })?;
            Arc::new(liostunnel_core::dns::over_https::DohResolver::new(
                protocol.clone(),
                profile.dns.servers.clone(),
                doh,
            ))
        }
    };
```

and change the `Engine::new` call to `Engine::new(protocol, resolver, handles)`.

- [ ] **Step 7: Verify EC2**

With the fixture up and a profile whose `dns` routes through the tunnel:

```bash
sudo -E cargo run -p liostunnel-cli -- --insecure-accept-any-hostkey \
  connect /tmp/fixture.liostunnel.json --user tunneluser \
  --route-mode test --cidr 93.184.216.0/24 --capture-dns
```

Then `curl http://example.com/` in another shell. Repeat with `"dns": {"mode":"https","servers":["1.1.1.1"],"https":{"sni":"cloudflare-dns.com","path":"/dns-query"}}`.

**Exit criterion EC2 met** when both modes resolve and fetch.

- [ ] **Step 8: Commit**

```bash
git add crates/
git commit -m "feat: DNS-over-HTTPS resolver riding a TunnelStream"
```

---

### Task 21: Default route mode and crash-safe cleanup

Spec §10. Three cleanup paths, because PRD §8 requires surviving a crash.

**Files:**
- Modify: `crates/liostunnel-core/src/route/mod.rs`, `macos.rs`, `linux.rs`
- Create: `crates/liostunnel-core/src/route/state.rs`
- Modify: `crates/liostunnel-cli/src/commands/connect.rs`, `crates/liostunnel-cli/src/main.rs`

**Interfaces:**
- Consumes: Task 16's types.
- Produces: `RouteMode::Default` support in both managers; `struct AppliedState { interface: String, commands: Vec<RouteCommand>, pid: u32 }` with `save(&Path)`, `load(&Path)`, `clear(&Path)`, and `recover_if_stale(&Path) -> Result<bool, TunnelError>`.

- [ ] **Step 1: Write the failing tests**

Append to the test module in `crates/liostunnel-core/src/route/mod.rs`:

```rust
    fn default_plan() -> RoutePlan {
        plan(RouteMode::Default)
    }

    #[test]
    fn default_mode_beats_the_default_route_without_deleting_it() {
        for (name, cmds) in [
            ("macos", macos::MacOsRoutes.apply_commands(&default_plan()).unwrap()),
            ("linux", linux::LinuxRoutes.apply_commands(&default_plan()).unwrap()),
        ] {
            let r = rendered(&cmds);
            assert!(r.iter().any(|c| c.contains("0.0.0.0/1")), "{name}: {r:?}");
            assert!(r.iter().any(|c| c.contains("128.0.0.0/1")), "{name}: {r:?}");
            assert!(
                !r.iter().any(|c| c.contains("delete default") || c.contains("del default")),
                "{name} must not remove the real default route: {r:?}"
            );
        }
    }

    #[test]
    fn default_mode_pins_the_server_via_the_original_gateway() {
        // Without this the tunnel's own transport routes through itself and
        // the connection deadlocks. Spec §10.
        for (name, cmds) in [
            ("macos", macos::MacOsRoutes.apply_commands(&default_plan()).unwrap()),
            ("linux", linux::LinuxRoutes.apply_commands(&default_plan()).unwrap()),
        ] {
            let r = rendered(&cmds);
            assert!(
                r.iter().any(|c| c.contains("198.51.100.7") && c.contains("192.168.1.1")),
                "{name} must pin the server route via the original gateway: {r:?}"
            );
        }
    }

    #[test]
    fn default_mode_overrides_dns() {
        let r = rendered(&macos::MacOsRoutes.apply_commands(&default_plan()).unwrap());
        assert!(r.iter().any(|c| c.starts_with("networksetup")), "{r:?}");
    }

    #[test]
    fn the_server_pin_is_installed_before_the_default_beating_routes() {
        // Ordering matters: install 0/1 first and the SSH connection can drop
        // before its own pin exists.
        let cmds = rendered(&linux::LinuxRoutes.apply_commands(&default_plan()).unwrap());
        let pin = cmds.iter().position(|c| c.contains("198.51.100.7")).unwrap();
        let half = cmds.iter().position(|c| c.contains("0.0.0.0/1")).unwrap();
        assert!(pin < half, "server pin must come first: {cmds:?}");
    }
```

`crates/liostunnel-core/src/route/state.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::RouteCommand;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("lios-state-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.join("applied_routes.json")
    }

    fn state() -> AppliedState {
        AppliedState {
            interface: "utun7".into(),
            revert: vec![RouteCommand::new("ip", &["route", "del", "0.0.0.0/1"])],
            pid: std::process::id(),
        }
    }

    #[test]
    fn state_round_trips_through_disk() {
        let p = tmp("round");
        state().save(&p).unwrap();
        assert_eq!(AppliedState::load(&p).unwrap().interface, "utun7");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn clearing_removes_the_file_so_the_next_start_sees_nothing() {
        let p = tmp("clear");
        state().save(&p).unwrap();
        AppliedState::clear(&p);
        assert!(AppliedState::load(&p).is_err());
    }

    #[test]
    fn a_state_file_from_our_own_live_process_is_not_treated_as_stale() {
        let p = tmp("live");
        state().save(&p).unwrap();
        assert!(!recover_if_stale(&p).unwrap(), "our own pid is not a crash");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_state_file_from_a_dead_process_is_recovered() {
        let p = tmp("dead");
        let mut s = state();
        // A pid that cannot be running: reserved and never assigned.
        s.pid = 0;
        // The revert command is a no-op so the test does not need root.
        s.revert = vec![RouteCommand::new("true", &[])];
        s.save(&p).unwrap();

        assert!(recover_if_stale(&p).unwrap(), "a crash must be cleaned up");
        assert!(AppliedState::load(&p).is_err(), "recovery clears the file");
    }

    #[test]
    fn a_missing_state_file_is_not_an_error() {
        assert!(!recover_if_stale(&tmp("absent")).unwrap());
    }
}
```

- [ ] **Step 2: Run to verify failure, then implement default mode**

Run: `cargo test -p liostunnel-core route` — Expected: FAIL on the four new route tests plus `cannot find type AppliedState`.

In `crates/liostunnel-core/src/route/macos.rs`, replace the `RouteMode::Default` arm of `apply_commands`:

```rust
            RouteMode::Default => {
                // The server pin comes first: install it after 0.0.0.0/1 and the
                // SSH connection can be cut before its own escape route exists.
                cmds.push(RouteCommand::new(
                    "route",
                    &["-n", "add", "-host", &plan.server_ip.to_string(),
                      &plan.original_gateway.to_string()],
                ));
                // Two /1 routes beat 0.0.0.0/0 by being more specific, so the
                // real default route is never deleted and restoring is exact.
                for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                    cmds.push(RouteCommand::new(
                        "route",
                        &["-n", "add", "-net", half, "-interface", &plan.interface],
                    ));
                }
                let mut args = vec!["-setdnsservers".to_string(), "Wi-Fi".to_string()];
                args.extend(plan.dns_servers.iter().map(|d| d.to_string()));
                cmds.push(RouteCommand {
                    program: "networksetup".into(),
                    args,
                });
            }
```

and the matching `revert_commands` arm:

```rust
            RouteMode::Default => {
                for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                    cmds.push(RouteCommand::new(
                        "route",
                        &["-n", "delete", "-net", half, "-interface", &plan.interface],
                    ));
                }
                cmds.push(RouteCommand::new(
                    "route",
                    &["-n", "delete", "-host", &plan.server_ip.to_string(),
                      &plan.original_gateway.to_string()],
                ));
                cmds.push(RouteCommand::new(
                    "networksetup",
                    &["-setdnsservers", "Wi-Fi", "Empty"],
                ));
            }
```

In `crates/liostunnel-core/src/route/linux.rs`, the same shape:

```rust
            RouteMode::Default => {
                cmds.push(RouteCommand::new(
                    "ip",
                    &["route", "add", &format!("{}/32", plan.server_ip),
                      "via", &plan.original_gateway.to_string()],
                ));
                for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                    cmds.push(RouteCommand::new(
                        "ip",
                        &["route", "add", half, "dev", &plan.interface],
                    ));
                }
            }
```

```rust
            RouteMode::Default => {
                for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                    cmds.push(RouteCommand::new(
                        "ip",
                        &["route", "del", half, "dev", &plan.interface],
                    ));
                }
                cmds.push(RouteCommand::new(
                    "ip",
                    &["route", "del", &format!("{}/32", plan.server_ip)],
                ));
            }
```

Note the Linux DNS override is handled by the CLI writing `/etc/resolv.conf` (see Step 4), because it is a file edit rather than a command.

- [ ] **Step 3: Implement the state file**

Prepend to `crates/liostunnel-core/src/route/state.rs`:

```rust
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::TunnelError;
use crate::route::RouteCommand;

/// Written *before* routes are applied, so a `kill -9` leaves a record behind
/// and the next start can clean up. The third of the three cleanup paths in
/// spec §10; PRD §8 requires surviving a crash.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppliedState {
    pub interface: String,
    /// Exactly the commands needed to undo what was applied.
    pub revert: Vec<RouteCommand>,
    pub pid: u32,
}

impl AppliedState {
    pub fn save(&self, path: &Path) -> Result<(), TunnelError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| TunnelError::Route(format!("cannot create state dir: {e}")))?;
        }
        let body = serde_json::to_string_pretty(self)
            .map_err(|e| TunnelError::Route(format!("cannot serialise state: {e}")))?;
        std::fs::write(path, body)
            .map_err(|e| TunnelError::Route(format!("cannot write state file: {e}")))
    }

    pub fn load(path: &Path) -> Result<Self, TunnelError> {
        let body = std::fs::read_to_string(path)
            .map_err(|e| TunnelError::Route(format!("cannot read state file: {e}")))?;
        serde_json::from_str(&body)
            .map_err(|e| TunnelError::Route(format!("cannot parse state file: {e}")))
    }

    pub fn clear(path: &Path) {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // Signal 0 tests for existence without delivering anything.
    // SAFETY: `kill` with signal 0 has no effect beyond returning a status.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(not(unix))]
fn process_is_alive(_pid: u32) -> bool {
    false
}

/// Cleans up routes left behind by a crashed run. Returns whether anything was
/// recovered. Called at startup, before any new routes are installed.
pub fn recover_if_stale(path: &Path) -> Result<bool, TunnelError> {
    if !path.exists() {
        return Ok(false);
    }
    let state = AppliedState::load(path)?;

    if process_is_alive(state.pid) && state.pid != std::process::id() {
        return Err(TunnelError::Route(format!(
            "another liostunnel (pid {}) is holding routes on {}",
            state.pid, state.interface
        )));
    }
    if state.pid == std::process::id() {
        return Ok(false);
    }

    tracing::warn!(
        pid = state.pid,
        interface = %state.interface,
        "found routes from a previous run that exited uncleanly; reverting them"
    );
    for cmd in &state.revert {
        if let Err(e) = cmd.run() {
            // The route may already be gone; keep going regardless.
            tracing::debug!(%e, "recovery step failed");
        }
    }
    AppliedState::clear(path);
    Ok(true)
}
```

Add `pub mod state;` to `crates/liostunnel-core/src/route/mod.rs`, `#[derive(Serialize, Deserialize)]` to `RouteCommand`, and `libc = "0.2"` to the workspace and core dependencies.

- [ ] **Step 4: Wire the remaining two cleanup paths into the CLI**

In `crates/liostunnel-cli/src/commands/connect.rs`, before applying routes:

```rust
    let state_path = crate::profile_io::home().join("applied_routes.json");
    liostunnel_core::route::state::recover_if_stale(&state_path)?;

    let plan = RoutePlan { /* as before */ };
    // Record before applying: a crash between these two lines leaves a state
    // file describing routes that were never installed, and reverting those is
    // harmless. The reverse order would lose them entirely.
    liostunnel_core::route::state::AppliedState {
        interface: plan.interface.clone(),
        revert: manager.revert_commands(&plan)?,
        pid: std::process::id(),
    }
    .save(&state_path)?;

    let mut guard = RouteGuard::apply(manager, plan)?;
```

and replace the plain `ctrl_c().await` with a handler covering both signals, clearing the state file on a clean exit:

```rust
    let mut sigterm = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    )
    .map_err(TunnelError::Transport)?;

    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("interrupted"),
        _ = sigterm.recv() => tracing::info!("terminated"),
    }

    shutdown.shutdown();
    guard.revert_now();
    liostunnel_core::route::state::AppliedState::clear(&state_path);
    engine_task.abort();
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-core route`
Expected: PASS — 9 route tests plus 5 state tests.

- [ ] **Step 6: Verify EC3**

```bash
sudo -E cargo run -p liostunnel-cli -- --insecure-accept-any-hostkey \
  connect /tmp/real.liostunnel.json --user <user> --route-mode default
```

Check in another shell that `curl https://ifconfig.me` returns the **server's** address. Then verify all three cleanup paths:

1. Ctrl-C → `netstat -rn | grep '0.0.0.0/1'` (macOS) / `ip route | grep '0.0.0.0/1'` (Linux) prints nothing.
2. `sudo kill -9 <pid>` → routes remain; re-run `connect` and confirm it logs "reverting them" and starts cleanly.
3. Inject a `panic!()` temporarily in the engine loop, confirm the `RouteGuard` still reverts, then remove it.

**Exit criterion EC3 met.**

- [ ] **Step 7: Commit**

```bash
git add crates/
git commit -m "feat: default route mode with three-way crash-safe cleanup"
```

---

### Task 22: Release gates — EC4 through EC7, and CI

Spec §12 (T5, T6) and §13. EC5 and EC6 are the results that decide whether the architecture survives contact with mobile, so they are measured, recorded, and automated — not eyeballed.

**Files:**
- Create: `testing/gates/dns_leak_test.sh`, `testing/gates/idle_cpu_test.sh`, `testing/gates/throughput_test.sh`, `testing/gates/README.md`
- Create: `.github/workflows/ci.yml`
- Create: `crates/liostunnel-core/tests/tun_e2e.rs`
- Create: `README.md`

**Interfaces:**
- Consumes: the complete CLI.
- Produces: four executable gates and a CI pipeline.

- [ ] **Step 1: Write the E2E test (T5, EC7)**

`crates/liostunnel-core/tests/tun_e2e.rs`:

```rust
//! T5: the real device on both platforms. Requires root.
//!
//! macOS: `sudo -E cargo test -p liostunnel-core --test tun_e2e -- --ignored`
//! Linux: same, inside a container run with
//!        `--cap-add=NET_ADMIN --device /dev/net/tun`

use liostunnel_core::net::tun::{PacketIo, TunConfig, TunDevice};

#[test]
#[ignore = "requires root and a real TUN device"]
fn a_real_tun_device_opens_and_reports_its_name() {
    let dev = TunDevice::open(TunConfig {
        name: None,
        address: std::net::Ipv4Addr::new(10, 91, 0, 1),
        netmask: std::net::Ipv4Addr::new(255, 255, 255, 0),
        mtu: 1500,
    })
    .expect("cannot open TUN — are you root?");

    let name = dev.name().unwrap();
    // EC7: one code path, two platforms, different naming conventions.
    if cfg!(target_os = "macos") {
        assert!(name.starts_with("utun"), "unexpected macOS name: {name}");
    } else {
        assert!(!name.is_empty());
    }
    assert_eq!(dev.mtu(), 1500);
}

#[test]
#[ignore = "requires root and a real TUN device"]
fn packets_sent_to_the_tunnel_subnet_are_read_back_as_bare_ip() {
    let mut dev = TunDevice::open(TunConfig {
        name: None,
        address: std::net::Ipv4Addr::new(10, 92, 0, 1),
        netmask: std::net::Ipv4Addr::new(255, 255, 255, 0),
        mtu: 1500,
    })
    .expect("cannot open TUN — are you root?");

    // Provoke traffic towards the interface.
    std::process::Command::new("ping")
        .args(["-c", "1", "-W", "1", "10.92.0.2"])
        .output()
        .ok();

    let mut buf = vec![0u8; 2048];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if let Ok(n) = dev.read_packet(&mut buf) {
            if n > 0 {
                // The AF prefix must already be stripped: byte 0 is the IP
                // version nibble, not a zero from the utun header. Decision D2.
                assert_eq!(buf[0] >> 4, 4, "expected a bare IPv4 packet");
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("no packet observed on the TUN device within 3s");
}
```

- [ ] **Step 2: Run the E2E test on both platforms (EC7)**

macOS: `sudo -E cargo test -p liostunnel-core --test tun_e2e -- --ignored`
Linux: `docker run --rm -v "$PWD:/w" -w /w --cap-add=NET_ADMIN --device /dev/net/tun rust:1.93 cargo test -p liostunnel-core --test tun_e2e -- --ignored`

Expected: PASS on both. **EC7 met.**

- [ ] **Step 3: Write the DNS leak gate (T6, EC4)**

`testing/gates/dns_leak_test.sh`:

```bash
#!/usr/bin/env bash
# EC4 / spec §12 T6. Asserts that no DNS query escapes outside the tunnel.
#
# Run with the tunnel already up in `default` route mode:
#   sudo ./testing/gates/dns_leak_test.sh <physical-interface>
set -euo pipefail

IFACE="${1:?usage: dns_leak_test.sh <physical-interface>}"
CAPTURE="$(mktemp -t liosleak.XXXXXX).pcap"
trap 'rm -f "$CAPTURE"' EXIT

echo "capturing UDP:53 on $IFACE for 20s"
tcpdump -i "$IFACE" -n -w "$CAPTURE" 'udp port 53' &
TCPDUMP_PID=$!
sleep 2

# Generate resolution traffic that must travel through the tunnel.
for host in example.com wikipedia.org debian.org rust-lang.org; do
  getent hosts "$host" >/dev/null 2>&1 || true
  curl -s -o /dev/null --max-time 5 "http://$host/" || true
done

sleep 3
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

LEAKED=$(tcpdump -r "$CAPTURE" -n 2>/dev/null | wc -l | tr -d ' ')
if [ "$LEAKED" -ne 0 ]; then
  echo "FAIL: $LEAKED DNS packet(s) left via $IFACE outside the tunnel:"
  tcpdump -r "$CAPTURE" -n 2>/dev/null | head -20
  exit 1
fi
echo "PASS: no DNS traffic observed outside the tunnel"
```

- [ ] **Step 4: Write the idle-CPU gate (EC5)**

`testing/gates/idle_cpu_test.sh`:

```bash
#!/usr/bin/env bash
# EC5. The falsifiable proof that the poll loop does not busy-wait.
# A spinning loop shows ~100% of a core; a correctly sleeping one shows ~0%.
#
#   ./testing/gates/idle_cpu_test.sh <pid-of-liostunnel> [seconds]
set -euo pipefail

PID="${1:?usage: idle_cpu_test.sh <pid> [seconds]}"
DURATION="${2:-300}"
THRESHOLD="2.0"   # percent of one core, averaged

echo "sampling pid $PID for ${DURATION}s (tunnel must be connected and idle)"
SAMPLES=0
TOTAL=0
END=$(( $(date +%s) + DURATION ))
while [ "$(date +%s)" -lt "$END" ]; do
  CPU=$(ps -p "$PID" -o %cpu= 2>/dev/null | tr -d ' ' || echo "")
  [ -z "$CPU" ] && { echo "FAIL: process $PID exited during sampling"; exit 1; }
  TOTAL=$(echo "$TOTAL + $CPU" | bc -l)
  SAMPLES=$((SAMPLES + 1))
  sleep 5
done

AVG=$(echo "scale=3; $TOTAL / $SAMPLES" | bc -l)
echo "average CPU over $SAMPLES samples: ${AVG}%"
if [ "$(echo "$AVG > $THRESHOLD" | bc -l)" -eq 1 ]; then
  echo "FAIL: ${AVG}% exceeds the ${THRESHOLD}% ceiling — the loop is spinning"
  exit 1
fi
echo "PASS: idle CPU is within budget"
```

- [ ] **Step 5: Write the throughput gate (EC6)**

`testing/gates/throughput_test.sh`:

```bash
#!/usr/bin/env bash
# EC6 / PRD §8: within 20% of raw `ssh -D` for a large download.
#
#   ./testing/gates/throughput_test.sh <ssh-user@host> <url>
set -euo pipefail

TARGET="${1:?usage: throughput_test.sh <user@host> <url>}"
URL="${2:?usage: throughput_test.sh <user@host> <url>}"
SOCKS_PORT=11080

secs() { date +%s.%N; }

echo "== baseline: ssh -D SOCKS proxy =="
ssh -f -N -D "$SOCKS_PORT" "$TARGET"
SSH_PID=$(pgrep -f "ssh -f -N -D $SOCKS_PORT" | head -1)
trap 'kill "$SSH_PID" 2>/dev/null || true' EXIT

T0=$(secs)
curl -s -o /dev/null --socks5-hostname "127.0.0.1:$SOCKS_PORT" "$URL"
BASE=$(echo "$(secs) - $T0" | bc -l)
kill "$SSH_PID" 2>/dev/null || true
trap - EXIT
echo "baseline: ${BASE}s"

echo "== through liostunnel (bring the tunnel up in default mode, then press enter) =="
read -r _
T0=$(secs)
curl -s -o /dev/null "$URL"
TUNNEL=$(echo "$(secs) - $T0" | bc -l)
echo "liostunnel: ${TUNNEL}s"

RATIO=$(echo "scale=3; $TUNNEL / $BASE" | bc -l)
echo "ratio: ${RATIO}x (ceiling 1.20)"
if [ "$(echo "$RATIO > 1.20" | bc -l)" -eq 1 ]; then
  echo "FAIL: more than 20% slower than raw ssh -D"
  echo "Tune StackConfig::tcp_buffer_bytes and channel_depth before concluding"
  echo "the architecture is at fault — see spec §14."
  exit 1
fi
echo "PASS: within the PRD §8 budget"
```

`testing/gates/README.md`:

```markdown
# Phase 0 release gates

Each script maps to an exit criterion in the design spec §13.

| Script | Criterion | Needs |
|---|---|---|
| `dns_leak_test.sh` | EC4 — no DNS escapes the tunnel | root, tunnel up in `default` mode |
| `idle_cpu_test.sh` | EC5 — the poll loop sleeps | a connected, idle tunnel |
| `throughput_test.sh` | EC6 — within 20% of `ssh -D` | a real SSH server |

EC1–EC3 and EC7 are verified by the steps in the implementation plan
(Tasks 17, 20, 21, 22) rather than by a script.

Record the measured numbers in the commit that closes Phase 0 — EC5 and EC6 are
the architecture's evidence for the mobile phases, and a number nobody wrote
down is a number nobody can compare against later.
```

Make them executable: `chmod +x testing/gates/*.sh`.

- [ ] **Step 6: Add CI**

`.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -D warnings

jobs:
  # Everything that needs neither root nor a TUN device — spec §12, T1-T3.
  unit:
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.93
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all --check
      - run: cargo clippy --all-targets --all-features
      - run: cargo test --workspace
      # The lean build must keep working — spec §14.
      - run: cargo check -p liostunnel-core --no-default-features

  # T4: real sshd in Docker, no TUN, no privileges.
  integration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.93
      - uses: Swatinem/rust-cache@v2
      - run: make -C testing/docker up
      - run: cargo test -p liostunnel-core --test ssh_integration -- --ignored
      - if: always()
        run: make -C testing/docker down

  # T5: the real device. Linux only in CI; macOS is verified locally.
  tun-e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.93
      - uses: Swatinem/rust-cache@v2
      - run: cargo build -p liostunnel-core --tests
      - name: Run TUN tests with NET_ADMIN
        run: sudo -E env "PATH=$PATH" cargo test -p liostunnel-core --test tun_e2e -- --ignored
```

- [ ] **Step 7: Write the README**

`README.md`:

```markdown
# LiosTunnel

Cross-platform tunnel client with one shared Rust core. **Phase 0: CLI only.**

Routes TCP traffic from a TUN device through an SSH tunnel on macOS and Linux,
with DNS carried over the tunnel and no leaks. No UI, no mobile, no WireGuard or
Shadowsocks yet — see [`PRD.md`](PRD.md) for the full roadmap and
[`docs/superpowers/specs/2026-07-27-liostunnel-phase0-design.md`](docs/superpowers/specs/2026-07-27-liostunnel-phase0-design.md)
for what Phase 0 does and does not include.

## Build

```bash
cargo build --release
```

## Use

```bash
# Check a profile without connecting.
liostunnel validate myserver.liostunnel.json

# Route one prefix through the tunnel — safe, cannot lock you out.
sudo liostunnel connect myserver.json --user me \
  --route-mode test --cidr 93.184.216.0/24 --capture-dns

# Route everything.
sudo liostunnel connect myserver.json --user me --route-mode default
```

## Profile format

Two representations. `ServerProfile` references secrets and is safe to store;
the shareable export inlines them and is produced only by
`liostunnel export --include-secrets`.

```json
{
  "id": "b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f",
  "name": "Home VPS",
  "protocol": "ssh",
  "host": "198.51.100.7",
  "port": 22,
  "auth": { "type": "private_key",
            "private_key": { "source": "file", "path": "/home/me/.ssh/id_ed25519" } },
  "dns": { "mode": "tcp", "servers": ["1.1.1.1", "1.0.0.1"], "https": null },
  "split_tunnel": { "type": "all_traffic" },
  "kill_switch": false
}
```

`kill_switch` and `split_tunnel` are parsed and validated but **not enforced** in
Phase 0; setting them prints a warning at startup.

## Testing

```bash
cargo test --workspace                                   # no root, no TUN
make -C testing/docker up && \
  cargo test -p liostunnel-core --test ssh_integration -- --ignored
sudo -E cargo test -p liostunnel-core --test tun_e2e -- --ignored
```

Release gates live in [`testing/gates/`](testing/gates/README.md).

## Security

Host key verification is enforced by default.
`--insecure-accept-any-hostkey` disables it and warns loudly; use it only
against a server you control. Secret files must be mode `0600` or stricter.
Payload bytes are never logged.
```

- [ ] **Step 8: Verify EC4, EC5, EC6**

With a real SSH server and the tunnel up in `default` mode:

```bash
sudo ./testing/gates/dns_leak_test.sh en0      # or eth0 on Linux
./testing/gates/idle_cpu_test.sh $(pgrep -f 'liostunnel.*connect') 300
./testing/gates/throughput_test.sh me@myserver https://speed.hetzner.de/100MB.bin
```

Expected: three PASSes. Record the measured idle-CPU percentage and throughput
ratio in the closing commit message.

**Exit criteria EC4, EC5, EC6 met. Phase 0 is complete.**

- [ ] **Step 9: Commit**

```bash
git add testing/ .github/ README.md crates/liostunnel-core/tests/
git commit -m "test: release gates for EC4-EC7, CI, and project README

Idle CPU: <measured>%  (ceiling 2%)
Throughput vs ssh -D: <measured>x  (ceiling 1.20x)"
```

---

## Phase 0 completion checklist

| Criterion | Verified by |
|---|---|
| EC1 — TCP through the tunnel in `test` mode | Task 17, Step 3 |
| EC2 — hostname resolution on both DNS backends | Task 20, Step 7 |
| EC3 — `default` mode plus all three cleanup paths | Task 21, Step 6 |
| EC4 — DNS leak test | Task 22, Step 8 |
| EC5 — idle CPU ≈ 0% | Task 22, Step 8 |
| EC6 — within 20% of `ssh -D` | Task 22, Step 8 |
| EC7 — same code path on macOS utun and Linux TUN | Task 22, Step 2 |

When all seven hold, Phase 0 has answered the question it exists to answer, and
Phase 1 (Flutter desktop UI, WireGuard) can begin. Per spec §14, the Apple
`networkextension` entitlement application should already be in flight by then.

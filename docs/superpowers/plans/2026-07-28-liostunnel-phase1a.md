# LiosTunnel Phase 1a Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Flutter desktop app that manages profiles and drives the verified Phase 0 tunnel engine through a privileged helper daemon, on macOS and Linux.

**Architecture:** Three processes. The Flutter app (user uid) links `liostunnel-ffi` via `flutter_rust_bridge` for config work only. A privileged `liostunnel-helper` daemon owns the TUN device, routes, and engine, and listens on a unix socket. They speak newline-delimited JSON, with the message types defined once in Rust and mirrored to Dart by FRB. `liostunnel-core` and `liostunnel-cli` are untouched.

**Tech Stack:** Rust 2024 / 1.93, `flutter_rust_bridge` 2.12.0, Flutter 3.41, Dart 3.11, `serde_json`, `nix` (Linux peer creds), `libc` (macOS peer creds), `provider`.

**Spec:** [`../specs/2026-07-28-liostunnel-phase1a-desktop-ui-design.md`](../specs/2026-07-28-liostunnel-phase1a-desktop-ui-design.md)

## Global Constraints

Every task's requirements implicitly include this section.

- **Rust edition 2024, `rust-version = "1.93"`.** Workspace `resolver = "3"`.
- **`liostunnel-core` and `liostunnel-cli` are not modified.** If a task appears to need a core change, stop and report it — that is a spec violation, not an implementation detail.
- **`flutter_rust_bridge` is pinned to `2.12.0`** — the latest *stable*. `2.13.0-beta.5` exists and must not be used; a prerelease codegen dependency in a privileged build chain is not acceptable.
- **No error message, log line, or protocol field may carry secret material.** Phase 0's `Redacted<T>` discipline crosses the socket unchanged.
- **The helper resolves secrets as the calling uid, never as root** (spec §7.2). This is the privilege escalation the design exists to prevent.
- **A helper started without an authorized uid refuses every connection** rather than defaulting permissive.
- **TDD, strictly.** Write the test, run it, confirm it fails for the *expected* reason, then implement. A test that passes before implementation is a broken test.
- **A test that passes must be shown failing against the defect it names.** Phase 0 shipped three tests that passed while their bug was still present. Revert the fix, confirm red, restore.
- `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, and `dart analyze` must pass before every commit.
- Conventional commit prefixes. **Write commit messages to a file and use `git commit -F`** — backticks inside a `-m` argument are command substitution and will execute.

## Verified API reference

Confirmed against docs.rs, crates.io, and by compiling locally on 2026-07-28. Do not guess at these; they were verified because Phase 0 lost cycles to exactly this class of error.

```rust
// flutter_rust_bridge: latest STABLE is 2.12.0. 2.13.0-beta.5 is a prerelease — do not use.
// Install codegen:  cargo install flutter_rust_bridge_codegen --version 2.12.0
// Generate:         flutter_rust_bridge_codegen generate

// PEER CREDENTIALS ARE PLATFORM-SPLIT. nix 0.31 has NO macOS equivalent.
// Linux — nix provides it:
nix::sys::socket::sockopt::PeerCredentials   // SO_PEERCRED, requires nix feature "socket"
// nix 0.31's full peer/cred sockopt list is exactly: PassCred, PeerCredentials, PeerPidfd.
// There is no LocalPeerCred. macOS must call libc directly.

// macOS — verified by compiling against libc 0.2 on this machine:
libc::xucred                 // size 76 bytes; field cr_uid: libc::uid_t, cr_ngroups: libc::c_short
libc::SOL_LOCAL              // = 0
libc::LOCAL_PEERCRED         // = 1
libc::getsockopt(fd: c_int, level: c_int, name: c_int,
                 val: *mut c_void, len: *mut socklen_t) -> c_int
```

```dart
// Dart unix domain sockets — verified by running the real thing on this machine:
final addr = InternetAddress('/path/to.sock', type: InternetAddressType.unix);
await ServerSocket.bind(addr, 0);     // port argument is required and ignored
await Socket.connect(addr, 0);
// Line framing that works:
socket.cast<List<int>>()
      .transform(utf8.decoder)
      .transform(const LineSplitter())
// Note: a live ServerSocket listener keeps the isolate alive; tests must
// cancel the subscription and close the server or they hang rather than fail.
```

## File structure

| File | Responsibility |
|---|---|
| `crates/liostunnel-ffi/src/lib.rs` | FRB entry point, module wiring |
| `crates/liostunnel-ffi/src/dto/profile.rs` | Flat, codegen-friendly profile DTOs + `From` conversions |
| `crates/liostunnel-ffi/src/dto/protocol.rs` | IPC message types — the single source of truth for the wire format |
| `crates/liostunnel-ffi/src/api/config.rs` | FRB-exposed profile operations (parse, export, summary) |
| `crates/liostunnel-ffi/src/api/protocol.rs` | FRB-exposed wire codec, so Dart never encodes or decodes protocol JSON itself |
| `crates/liostunnel-helper/src/main.rs` | Daemon entry, arg parsing, socket lifecycle |
| `crates/liostunnel-helper/src/auth.rs` | Peer-uid check (both platforms) + secret-path ownership check |
| `crates/liostunnel-helper/src/session.rs` | One tunnel at a time; engine lifecycle |
| `crates/liostunnel-helper/src/dispatch.rs` | Protocol request → action, event emission |
| `app/lib/services/helper_client.dart` | Socket, framing, reconnect, event stream |
| `app/lib/services/connection_model.dart` | `ChangeNotifier` holding state + stats |
| `app/lib/screens/profiles.dart` | Profiles list |
| `app/lib/screens/connection.dart` | Connect/disconnect + live stats |
| `packaging/liostunnel-helper.plist` | launchd (macOS) |
| `packaging/liostunnel-helper.service` | systemd (Linux) |
| `packaging/install-helper.sh` | Installs the unit with the authorized uid baked in |

**Milestones**

| | Tasks | Deliverable | Needs root? |
|---|---|---|---|
| A — the privileged helper | 1–6 | A daemon fully drivable with `socat`, with both authorization gates A/B-verified | no |
| B — the FFI layer | 7–9 | Profile DTOs and the wire codec, mirrored to Dart by codegen | no |
| C — the Flutter app | 10–11 | Helper client, connection model, two screens | no |
| D — install and verify | 12–13 | Units, installer, and the recorded exit-criteria run | Task 13 only |

Milestone A is deliberately built and verified before any UI exists — it is the security boundary, and Phase 0 proved that headless-testable components get tested properly while UI-coupled ones do not. Only Task 13 needs root; everything before it runs on an unprivileged developer machine.

---

# Milestone A — The privileged helper

---

### Task 1: Workspace scaffolding and protocol types

**Files:**
- Create: `crates/liostunnel-ffi/Cargo.toml`, `crates/liostunnel-ffi/src/lib.rs`, `crates/liostunnel-ffi/src/dto/mod.rs`, `crates/liostunnel-ffi/src/dto/protocol.rs`
- Create: `crates/liostunnel-helper/Cargo.toml`, `crates/liostunnel-helper/src/main.rs`
- Modify: `Cargo.toml` (workspace members)

**Interfaces:**
- Consumes: nothing.
- Produces: `liostunnel_ffi::dto::protocol::{Request, Response, Event, ErrorKind, ConnectParams, StatsSnapshot, PROTOCOL_VERSION}`. All `serde::Serialize + Deserialize`, all `#[serde(tag = "type")]` so the wire format is self-describing and inspectable by hand.

- [ ] **Step 1: Add both crates to the workspace**

In the root `Cargo.toml`, extend `members`:

```toml
[workspace]
members = [
    "crates/liostunnel-core",
    "crates/liostunnel-cli",
    "crates/liostunnel-ffi",
    "crates/liostunnel-helper",
]
resolver = "3"
```

- [ ] **Step 2: Create the FFI crate manifest**

`crates/liostunnel-ffi/Cargo.toml`:

```toml
[package]
name = "liostunnel-ffi"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[lib]
crate-type = ["cdylib", "staticlib", "rlib"]

[dependencies]
liostunnel-core = { path = "../liostunnel-core" }
serde.workspace = true
serde_json.workspace = true
```

`crate-type` includes `rlib` deliberately: the helper depends on this crate for the protocol types (spec §8), and a pure `cdylib` cannot be used as a Rust dependency.

- [ ] **Step 3: Write the failing protocol round-trip tests**

`crates/liostunnel-ffi/src/dto/protocol.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wire_format_is_self_describing() {
        // Every message carries a "type" tag, so a human debugging with socat
        // can read the traffic without a schema in front of them.
        let json = serde_json::to_string(&Request::Disconnect { id: 3 }).unwrap();
        assert!(json.contains(r#""type":"disconnect""#), "got {json}");
    }

    #[test]
    fn requests_round_trip() {
        let cases = vec![
            Request::Hello { id: 1, protocol_version: PROTOCOL_VERSION },
            Request::Disconnect { id: 2 },
            Request::GetStatus { id: 3 },
        ];
        for c in cases {
            let s = serde_json::to_string(&c).unwrap();
            assert_eq!(serde_json::from_str::<Request>(&s).unwrap(), c);
        }
    }

    #[test]
    fn an_error_response_carries_a_machine_readable_kind() {
        // The UI reacts to `kind`; `message` is for humans only. A UI that has
        // to string-match on `message` breaks the first time wording changes.
        let r = Response::Error {
            id: 9,
            kind: ErrorKind::VersionMismatch,
            message: "helper speaks v1, client speaks v2".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""kind":"version_mismatch""#), "got {json}");
        assert_eq!(serde_json::from_str::<Response>(&json).unwrap(), r);
    }

    #[test]
    fn events_round_trip() {
        let e = Event::Stats {
            snapshot: StatsSnapshot {
                bytes_up: 100,
                bytes_down: 200,
                active_flows: 3,
                flows_failed: 1,
                dns_queries: 7,
            },
        };
        let s = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<Event>(&s).unwrap(), e);
    }

    #[test]
    fn stats_omits_the_counters_core_never_populates() {
        // Spec 8.2: udp_dropped, syn_dropped, malformed_dropped and
        // bytes_discarded are computed in StackCore but have no callers, so
        // ConnectionStats reports them as permanently zero. They are omitted
        // from the protocol entirely rather than rendered as a fake measurement.
        let json = serde_json::to_string(&StatsSnapshot {
            bytes_up: 0, bytes_down: 0, active_flows: 0, flows_failed: 0, dns_queries: 0,
        }).unwrap();
        for absent in ["udp_dropped", "syn_dropped", "malformed_dropped", "bytes_discarded"] {
            assert!(!json.contains(absent), "{absent} must not appear in the wire format: {json}");
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test -p liostunnel-ffi protocol`
Expected: FAIL — `cannot find type Request in this scope`.

- [ ] **Step 5: Implement the protocol types**

Prepend to `crates/liostunnel-ffi/src/dto/protocol.rs`:

```rust
use serde::{Deserialize, Serialize};

/// Bumped on any breaking change to the message shapes below.
///
/// The helper is installed once and is privileged; the app updates
/// independently through normal channels. A newer app talking to an older
/// helper must fail with `ErrorKind::VersionMismatch` rather than
/// misinterpret a field. Spec §8.
pub const PROTOCOL_VERSION: u32 = 1;

/// Client → helper. `id` correlates a `Response` back to its request.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Hello { id: u64, protocol_version: u32 },
    Connect { id: u64, params: ConnectParams },
    Disconnect { id: u64 },
    GetStatus { id: u64 },
}

/// Helper → client, in reply to a specific `Request`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Ack { id: u64 },
    Error { id: u64, kind: ErrorKind, message: String },
}

/// Helper → client, unsolicited.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    State { state: String },
    Stats { snapshot: StatsSnapshot },
}

/// Machine-readable failure category. The UI branches on this; `message` is
/// for humans and must never be parsed.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    VersionMismatch,
    Unauthorized,
    SecretNotPermitted,
    AlreadyConnected,
    NotConnected,
    AuthFailed,
    BadRequest,
    Internal,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConnectParams {
    /// The profile as the UI holds it, in the same on-disk JSON form the
    /// user imported. Converted to a core `ServerProfile` by the helper
    /// *after* authorization, never before -- that ordering is the whole
    /// point of spec 7.2.
    pub profile_json: String,
    pub user: String,
    /// "test" or "default".
    pub route_mode: String,
    /// Only meaningful when `route_mode == "test"`.
    pub cidrs: Vec<String>,
    pub capture_dns: bool,
    pub tun_address: String,
}

/// Only fields the engine actually populates. See the omission test above.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub active_flows: u32,
    pub flows_failed: u64,
    pub dns_queries: u64,
}
```

`crates/liostunnel-ffi/src/dto/mod.rs`:

```rust
pub mod protocol;
```

`crates/liostunnel-ffi/src/lib.rs`:

```rust
//! FFI surface for the LiosTunnel desktop app.
//!
//! Owns its own DTOs rather than exporting `liostunnel-core` types, so that
//! `flutter_rust_bridge`'s type constraints cannot reach into the core and
//! core changes cannot silently break Dart codegen. Spec §9.

pub mod dto;
```

- [ ] **Step 6: Create the helper crate**

`crates/liostunnel-helper/Cargo.toml`:

```toml
[package]
name = "liostunnel-helper"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[[bin]]
name = "liostunnel-helper"
path = "src/main.rs"

[dependencies]
liostunnel-core = { path = "../liostunnel-core" }
liostunnel-ffi  = { path = "../liostunnel-ffi" }
serde.workspace = true
serde_json.workspace = true
tokio.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
clap.workspace = true
libc.workspace = true

[target.'cfg(target_os = "linux")'.dependencies]
nix = { version = "0.31", features = ["socket"] }
```

`crates/liostunnel-helper/src/main.rs`:

```rust
fn main() {
    println!("liostunnel-helper {}", env!("CARGO_PKG_VERSION"));
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-ffi protocol`
Expected: PASS — 5 passed.

- [ ] **Step 8: Verify the whole workspace still builds**

Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: the existing 244 core/cli tests still pass, plus 5 new; no warnings.

- [ ] **Step 9: Commit**

```bash
git add Cargo.toml Cargo.lock crates/liostunnel-ffi crates/liostunnel-helper
git commit -F - <<'EOF'
feat: protocol types for the helper daemon

Adds liostunnel-ffi and liostunnel-helper crates. The protocol messages
live in the FFI crate because they are the single source of truth for the
wire format: the helper depends on them as a Rust rlib, and Dart gets them
via flutter_rust_bridge codegen, so there are no hand-written Dart structs
to drift.

Every message is serde-tagged so traffic is readable by hand with socat --
which matters most for the one component running as root.

StatsSnapshot deliberately omits udp_dropped, syn_dropped,
malformed_dropped and bytes_discarded: StackCore computes them but nothing
reads them, so ConnectionStats reports them as permanently zero. A test
pins their absence rather than letting a UI render a hardcoded zero as
though it were a measurement.
EOF
```

---

### Task 2: Peer-uid authorization

This is gate one of the trust boundary (spec §7.1), and it is platform-split in a way `nix` does not paper over.

**Files:**
- Create: `crates/liostunnel-helper/src/auth.rs`
- Modify: `crates/liostunnel-helper/src/main.rs`

**Interfaces:**
- Consumes: `ErrorKind` (Task 1).
- Produces: `auth::peer_uid(fd: RawFd) -> Result<u32, AuthError>` and `auth::AuthError`.

- [ ] **Step 1: Write the failing tests**

`crates/liostunnel-helper/src/auth.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn peer_uid_of_a_socketpair_is_our_own_uid() {
        // Both ends of a socketpair belong to this process, so the peer uid
        // must be our own. This is the only assertion available without
        // spawning a process as another user, and it is enough to prove the
        // platform-specific getsockopt path is wired correctly — the failure
        // mode it guards against is "returns garbage" or "returns 0", not
        // "returns the wrong real user".
        let (a, _b) = UnixStream::pair().unwrap();
        let got = peer_uid(a.as_raw_fd()).expect("peer_uid must succeed on a socketpair");
        // SAFETY: getuid cannot fail and has no preconditions.
        let expected = unsafe { libc::getuid() };
        assert_eq!(got, expected);
    }

    #[test]
    fn peer_uid_on_getsockopt_failure_does_not_silently_report_uid_zero() {
        // THE zero-buffer guard. It must use an fd where the syscall really
        // fails: /dev/null is not a socket, so getsockopt returns ENOTSOCK on
        // macOS and nix's PeerCredentials errors on Linux. An implementation
        // that ignores the failure falls through to the zeroed xucred and
        // hands back Ok(0) -- every caller authorised as root.
        //
        // A socketpair CANNOT test this. getsockopt always succeeds there and
        // fills the buffer correctly whether or not the caller checks the
        // return code, so a test on that fixture passes against both the
        // correct and the broken implementation.
        let f = std::fs::File::open("/dev/null").unwrap();
        let result = peer_uid(f.as_raw_fd());
        assert!(result.is_err(), "must be an error, not Ok(0); got {result:?}");
    }

    #[test]
    fn authorize_accepts_our_own_uid() {
        let (a, _b) = UnixStream::pair().unwrap();
        let ours = unsafe { libc::getuid() };
        assert!(authorize(a.as_raw_fd(), ours).is_ok());
    }

    #[test]
    fn authorize_rejects_a_mismatched_uid() {
        // The function P1a-5 is actually about. Without this, an inverted
        // comparison passes every other test in the file.
        let (a, _b) = UnixStream::pair().unwrap();
        let ours = unsafe { libc::getuid() };
        match authorize(a.as_raw_fd(), ours.wrapping_add(1)) {
            Err(AuthError::WrongUid { expected, actual }) => {
                assert_eq!(expected, ours.wrapping_add(1));
                assert_eq!(actual, ours);
            }
            other => panic!("expected WrongUid, got {other:?}"),
        }
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p liostunnel-helper auth`
Expected: FAIL — `cannot find function peer_uid in this scope`.

- [ ] **Step 3: Implement**

Prepend to `crates/liostunnel-helper/src/auth.rs`:

```rust
use std::os::fd::RawFd;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("cannot read peer credentials: {0}")]
    PeerCred(std::io::Error),
    #[error("connection from uid {actual} refused; only uid {expected} is authorized")]
    WrongUid { expected: u32, actual: u32 },
}

/// The uid of the process on the other end of a connected unix socket.
///
/// Platform-split, and `nix` does not cover both: nix 0.31 provides
/// `sockopt::PeerCredentials` (Linux `SO_PEERCRED`) and has no macOS
/// equivalent, so macOS calls `getsockopt(SOL_LOCAL, LOCAL_PEERCRED)`
/// directly for a `xucred`.
///
/// Filesystem permissions on the socket are not a substitute: they are
/// advisory against a root-adjacent attacker and say nothing about *which*
/// user connected. Spec §7.1.
#[cfg(target_os = "linux")]
pub fn peer_uid(fd: RawFd) -> Result<u32, AuthError> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use std::os::fd::BorrowedFd;

    // SAFETY: the caller owns `fd` for the duration of this call; we only
    // borrow it to read a socket option and never retain it.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let cred = getsockopt(&borrowed, PeerCredentials)
        .map_err(|e| AuthError::PeerCred(std::io::Error::from(e)))?;
    Ok(cred.uid())
}

#[cfg(target_os = "macos")]
pub fn peer_uid(fd: RawFd) -> Result<u32, AuthError> {
    use std::mem;

    let mut cred: libc::xucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::xucred>() as libc::socklen_t;

    // SAFETY: `cred` is a correctly-sized, zeroed xucred and `len` describes
    // it accurately; getsockopt writes at most `len` bytes and updates it.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERCRED,
            &mut cred as *mut libc::xucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(AuthError::PeerCred(std::io::Error::last_os_error()));
    }
    Ok(cred.cr_uid)
}

/// Refuses any uid but the authorized one.
pub fn authorize(fd: RawFd, expected: u32) -> Result<(), AuthError> {
    let actual = peer_uid(fd)?;
    if actual != expected {
        return Err(AuthError::WrongUid { expected, actual });
    }
    Ok(())
}
```

Add `thiserror.workspace = true` to `crates/liostunnel-helper/Cargo.toml`, and `pub mod auth;` to `main.rs` — **in Step 1**, not here, or the RED run fails on a missing module instead of the missing function.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-helper auth`
Expected: PASS — 5 passed.

- [ ] **Step 5: A/B both guards**

The two arms fail through different mechanisms, so the injected defect is not the same edit on both. Do each on its own platform and paste all four transcripts.

**The zero-buffer guard.** On macOS, delete the `if rc != 0` check so the zeroed `xucred` falls through. On Linux, swallow the `?` and default to `0`. Confirm `peer_uid_on_getsockopt_failure_does_not_silently_report_uid_zero` FAILS with `got Ok(0)`. Restore, confirm green.

Note what does *not* move: `peer_uid_of_a_socketpair_is_our_own_uid` stays green through both breaks, because `getsockopt` always succeeds on a socketpair and fills the buffer correctly whether or not the caller checks the return code. That test proves the happy path is wired; it cannot prove the guard exists. Keeping the distinction visible is the point.

**The authorization comparison.** Invert `actual != expected` to `==`. Confirm `authorize_rejects_a_mismatched_uid` FAILS. Restore, confirm green.

This matters because "authorises everyone as root" is the exact failure mode an unchecked `getsockopt` produces, and it is invisible to a test that only asserts success on a fixture where the syscall never fails.

- [ ] **Step 6: Commit**

```bash
git add crates/liostunnel-helper
git commit -F - <<'EOF'
feat: peer-uid authorization for the helper socket

Gate one of the trust boundary. A root daemon taking instructions over a
socket must answer "who is allowed to talk to me"; filesystem permissions
do not, since they are advisory against a root-adjacent attacker and say
nothing about which user connected.

Platform-split because nix does not cover both: nix 0.31 provides
sockopt::PeerCredentials for Linux SO_PEERCRED and has no macOS
equivalent, so macOS calls getsockopt(SOL_LOCAL, LOCAL_PEERCRED) directly
for a xucred. Both paths verified against the real headers before writing.

The not-silently-zero test guards the specific failure where an unchecked
getsockopt leaves its output buffer zeroed and every caller is authorised
as root.
EOF
```

---

### Task 3: Secret-path ownership — the privilege escalation gate

This is gate two (spec §7.2) and the single most important task in the plan.

**Files:**
- Modify: `crates/liostunnel-helper/src/auth.rs`

**Interfaces:**
- Consumes: `AuthError` (Task 2).
- Produces: `auth::secret_readable_by(path: &Path, uid: u32) -> Result<(), AuthError>`.

**Why this exists.** If the UI sends a profile and the helper resolves its `SecretRef::File { path }` as root, any local user can make root read any file — name `/etc/shadow` as your private key and the contents land in an SSH authentication attempt, recoverable from an error message or through the tunnel. The vulnerability exists precisely because Phase 0's `FileSecretStore` was built for a CLI running as the invoking user, where "can this process read this file" and "may this user read this file" were the same question. Under a daemon they are not.

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module in `crates/liostunnel-helper/src/auth.rs`:

```rust
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("lios-auth-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_owned(dir: &std::path::Path, mode: u32) -> PathBuf {
        let p = dir.join("secret");
        let mut f = std::fs::OpenOptions::new()
            .write(true).create(true).truncate(true).mode(mode)
            .open(&p).unwrap();
        f.write_all(b"KEYMATERIAL").unwrap();
        p
    }

    #[test]
    fn a_file_the_caller_owns_is_permitted() {
        let d = scratch("owned");
        let p = write_owned(&d, 0o600);
        let me = unsafe { libc::getuid() };
        assert!(secret_readable_by(&p, me).is_ok());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_file_owned_by_another_uid_is_refused() {
        // THE ESCALATION. A root-owned file that this uid does not own must be
        // refused even though the helper, running as root, could trivially read
        // it. /etc/shadow is the canonical target: name it as your private key
        // and its contents leave via an auth attempt or an error message.
        let me = unsafe { libc::getuid() };
        if me == 0 {
            eprintln!("skipped: running as root, every file is 'ours'");
            return;
        }
        let target = std::path::Path::new("/etc/shadow");
        if !target.exists() {
            eprintln!("skipped: /etc/shadow absent on this platform");
            return;
        }
        let err = secret_readable_by(target, me)
            .expect_err("a file owned by another uid must be refused");
        assert!(
            matches!(err, AuthError::SecretNotOwned { .. }),
            "expected SecretNotOwned, got {err:?}"
        );
    }

    #[test]
    fn a_world_readable_file_is_still_refused_even_if_owned() {
        // Phase 0's FileSecretStore already rejects looser-than-0600. This
        // check runs first, so the mode rule is not lost by moving ownership
        // enforcement into the helper.
        let d = scratch("loose");
        let p = write_owned(&d, 0o644);
        let me = unsafe { libc::getuid() };
        assert!(secret_readable_by(&p, me).is_err());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_missing_file_is_an_error_not_a_panic() {
        let me = unsafe { libc::getuid() };
        assert!(secret_readable_by(std::path::Path::new("/nonexistent/lios"), me).is_err());
    }

    #[test]
    fn a_symlink_is_judged_by_its_target_not_the_link() {
        // A symlink the caller owns pointing at a file they do not is the
        // obvious bypass. `metadata` follows the link, which is what we want —
        // this test pins that we did not reach for `symlink_metadata`.
        let me = unsafe { libc::getuid() };
        if me == 0 {
            eprintln!("skipped: running as root");
            return;
        }
        let target = std::path::Path::new("/etc/shadow");
        if !target.exists() {
            eprintln!("skipped: /etc/shadow absent");
            return;
        }
        let d = scratch("symlink");
        let link = d.join("link");
        std::os::unix::fs::symlink(target, &link).unwrap();
        assert!(
            secret_readable_by(&link, me).is_err(),
            "a symlink to a file the caller does not own must be refused"
        );
        std::fs::remove_dir_all(&d).ok();
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p liostunnel-helper auth`
Expected: FAIL — `cannot find function secret_readable_by in this scope`.

- [ ] **Step 3: Implement**

Add to `crates/liostunnel-helper/src/auth.rs`:

```rust
use std::path::Path;

// Extend AuthError with:
//     #[error("secret file {path} is not owned by uid {uid}")]
//     SecretNotOwned { path: String, uid: u32 },
//     #[error("secret file {path}: {reason}")]
//     SecretRejected { path: String, reason: String },

/// Whether `uid` may have this file used as a secret.
///
/// The helper runs as root and can read anything; this is what stops a
/// caller from borrowing that power. Ownership is checked against the
/// *calling* uid, and the mode rule Phase 0 established is preserved.
///
/// Deliberately uses `metadata` (which follows symlinks) rather than
/// `symlink_metadata`: a link the caller owns pointing at a file they do
/// not is exactly the bypass this must refuse.
pub fn secret_readable_by(path: &Path, uid: u32) -> Result<(), AuthError> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::metadata(path).map_err(|e| AuthError::SecretRejected {
        path: path.display().to_string(),
        reason: format!("cannot stat: {e}"),
    })?;

    if !meta.is_file() {
        return Err(AuthError::SecretRejected {
            path: path.display().to_string(),
            reason: "not a regular file".into(),
        });
    }

    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(AuthError::SecretRejected {
            path: path.display().to_string(),
            reason: format!("mode {mode:o} grants access beyond the owner"),
        });
    }

    if meta.uid() != uid {
        return Err(AuthError::SecretNotOwned {
            path: path.display().to_string(),
            uid,
        });
    }

    Ok(())
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-helper auth -- --nocapture`
Expected: PASS — 8 passed (3 from Task 2 plus 5 new). Note any `skipped:` lines printed.

- [ ] **Step 5: A/B the escalation test — this is exit criterion P1a-6**

Temporarily delete the `meta.uid() != uid` check — the naive implementation, which is what you would write if you had not thought about the daemon case. Run the tests. Confirm `a_file_owned_by_another_uid_is_refused` and `a_symlink_is_judged_by_its_target_not_the_link` both FAIL. Restore and confirm they pass.

Paste both transcripts. A security test that has never been seen failing is not evidence.

- [ ] **Step 6: Commit**

```bash
git add crates/liostunnel-helper
git commit -F - <<'EOF'
feat: refuse secret files the calling user does not own

Gate two of the trust boundary, and a privilege escalation if unhandled.

The helper runs as root. If it resolved a caller-supplied
SecretRef::File as root, any local user could make root read any file --
name /etc/shadow as your private key and its contents leave through an SSH
auth attempt or an error message.

The vulnerability exists precisely because Phase 0's FileSecretStore was
built for a CLI running as the invoking user, where "can this process read
this file" and "may this user read this file" were the same question.
Under a daemon they are not.

Checks ownership against the calling uid and preserves Phase 0's
0600-or-stricter mode rule. Uses metadata rather than symlink_metadata on
purpose: a link the caller owns pointing at a file they do not is exactly
the bypass this must refuse, and a test pins it.

A/B verified -- both the ownership and symlink tests fail against the
naive implementation that omits the uid check.
EOF
```

---

### Task 4: Daemon socket lifecycle

**Files:**
- Modify: `crates/liostunnel-helper/src/main.rs`
- Create: `crates/liostunnel-helper/src/listener.rs`

**Interfaces:**
- Consumes: `auth::authorize` (Task 2).
- Produces: `listener::Listener` with `bind(path: &Path, authorized_uid: u32) -> Result<Self, io::Error>` and `accept(&self) -> Result<UnixStream, AcceptError>`; `main`'s CLI: `--socket <path> --uid <n>`.

- [ ] **Step 1: Write the failing tests**

`crates/liostunnel-helper/src/listener.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn sock(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("lios-lis-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.join("s.sock")
    }

    #[test]
    fn binding_creates_the_socket_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let p = sock("perms");
        let me = unsafe { libc::getuid() };
        let l = Listener::bind(&p, me).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket must not be reachable by other users");
        drop(l);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn a_stale_socket_file_does_not_prevent_binding() {
        // A crash leaves the socket file behind; bind(2) then fails with
        // EADDRINUSE and the helper never starts again until someone deletes
        // it by hand. Unlink first.
        let p = sock("stale");
        std::fs::write(&p, b"not a socket").unwrap();
        let me = unsafe { libc::getuid() };
        let l = Listener::bind(&p, me).expect("a stale file must not block startup");
        drop(l);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn dropping_the_listener_removes_the_socket_file() {
        let p = sock("cleanup");
        let me = unsafe { libc::getuid() };
        let l = Listener::bind(&p, me).unwrap();
        assert!(p.exists());
        drop(l);
        assert!(!p.exists(), "the socket file must not outlive the listener");
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn a_connection_from_the_authorized_uid_is_accepted() {
        let p = sock("ok");
        let me = unsafe { libc::getuid() };
        let l = Listener::bind(&p, me).unwrap();
        let _client = UnixStream::connect(&p).unwrap();
        assert!(l.accept().is_ok());
        drop(l);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn a_connection_from_a_different_uid_is_refused() {
        // We cannot connect as another user from a test, so authorize against
        // a uid we are definitely not. The accept must be refused rather than
        // returning a usable stream.
        let p = sock("wronguid");
        let me = unsafe { libc::getuid() };
        let not_me = if me == 12345 { 54321 } else { 12345 };
        let l = Listener::bind(&p, not_me).unwrap();
        let _client = UnixStream::connect(&p).unwrap();
        let err = l.accept().expect_err("a foreign uid must be refused");
        assert!(matches!(err, AcceptError::Unauthorized(_)), "got {err:?}");
        drop(l);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p liostunnel-helper listener`
Expected: FAIL — `cannot find type Listener in this scope`.

- [ ] **Step 3: Implement**

Prepend to `crates/liostunnel-helper/src/listener.rs`:

```rust
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use crate::auth::{self, AuthError};

#[derive(Debug, thiserror::Error)]
pub enum AcceptError {
    #[error("accept failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Unauthorized(AuthError),
}

/// Owns the listening socket and removes it on drop.
pub struct Listener {
    inner: UnixListener,
    path: PathBuf,
    authorized_uid: u32,
}

impl Listener {
    pub fn bind(path: &Path, authorized_uid: u32) -> std::io::Result<Self> {
        // A crash leaves the socket file behind and bind(2) then fails with
        // EADDRINUSE forever. Remove it first; the permissions on the parent
        // directory are what stop an attacker planting one.
        let _ = std::fs::remove_file(path);

        let inner = UnixListener::bind(path)?;

        // Owner-only. Not sufficient on its own (spec §7.1) but there is no
        // reason to be reachable by other users at all.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

        Ok(Self { inner, path: path.to_path_buf(), authorized_uid })
    }

    /// Accepts a connection and authorizes it, refusing any other uid.
    pub fn accept(&self) -> Result<UnixStream, AcceptError> {
        let (stream, _) = self.inner.accept()?;
        auth::authorize(stream.as_raw_fd(), self.authorized_uid)
            .map_err(AcceptError::Unauthorized)?;
        Ok(stream)
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
```

- [ ] **Step 4: Wire up the CLI**

`crates/liostunnel-helper/src/main.rs`:

```rust
mod auth;
mod listener;

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "liostunnel-helper", version, about = "Privileged tunnel helper")]
struct Args {
    /// Unix socket to listen on.
    #[arg(long, default_value = "/var/run/liostunnel.sock")]
    socket: PathBuf,

    /// The only uid permitted to connect. Written into the launchd plist /
    /// systemd unit by the installer, so it is root-owned configuration an
    /// unprivileged process cannot alter. Spec §7.1.
    #[arg(long)]
    uid: Option<u32>,
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "info".into()),
    ).init();

    let args = Args::parse();

    // Refuse to run permissively. A helper with no authorized uid would accept
    // anyone, which is strictly worse than not starting.
    let Some(uid) = args.uid else {
        eprintln!("error: --uid is required; refusing to accept connections from any user");
        return std::process::ExitCode::FAILURE;
    };

    match listener::Listener::bind(&args.socket, uid) {
        Ok(_l) => {
            tracing::info!(socket = %args.socket.display(), uid, "helper listening");
            // The accept loop arrives in Task 5.
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: cannot bind {}: {e}", args.socket.display());
            std::process::ExitCode::FAILURE
        }
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-helper listener`
Expected: PASS — 5 passed.

- [ ] **Step 6: Verify the permissive-default refusal by hand**

Run: `cargo run -p liostunnel-helper -- --socket /tmp/x.sock`
Expected: exits non-zero with `--uid is required`. Paste the output.

- [ ] **Step 7: Commit**

```bash
git add crates/liostunnel-helper
git commit -F - <<'EOF'
feat: helper socket lifecycle with uid enforcement at accept

Binds owner-only, unlinks a stale socket first (a crash otherwise leaves a
file that makes every later bind fail with EADDRINUSE), removes the socket
on drop, and authorizes the peer uid at accept rather than trusting
filesystem permissions.

A helper started without --uid refuses to run at all. Defaulting to
permissive would mean a misconfigured unit silently accepts every local
user, which is worse than failing to start.
EOF
```

---

### Task 5: Protocol dispatch and the version gate

**Files:**
- Create: `crates/liostunnel-helper/src/dispatch.rs`
- Modify: `crates/liostunnel-helper/src/main.rs`

**Interfaces:**
- Consumes: protocol types (Task 1).
- Produces: `dispatch::Session` with `new() -> Self` and `handle(&mut self, line: &str) -> Vec<String>` — pure line-in, lines-out, so the whole protocol is testable without a socket.

**Design note.** `handle` takes and returns strings rather than owning the socket. That is what makes the protocol testable without spawning a daemon, and it is the same separation that made Phase 0's `StackCore` testable without a TUN device.

- [ ] **Step 1: Write the failing tests**

`crates/liostunnel-helper/src/dispatch.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use liostunnel_ffi::dto::protocol::*;

    fn parse_one(out: &[String]) -> serde_json::Value {
        assert_eq!(out.len(), 1, "expected exactly one reply, got {out:?}");
        serde_json::from_str(&out[0]).unwrap()
    }

    #[test]
    fn hello_with_a_matching_version_is_acked() {
        let mut s = Session::new();
        let req = serde_json::to_string(&Request::Hello {
            id: 1, protocol_version: PROTOCOL_VERSION,
        }).unwrap();
        let v = parse_one(&s.handle(&req));
        assert_eq!(v["type"], "ack");
        assert_eq!(v["id"], 1);
    }

    #[test]
    fn hello_with_a_mismatched_version_is_refused() {
        // The helper is installed once and privileged; the app updates
        // independently. A newer app must be told to reinstall, not allowed to
        // misinterpret fields. Spec §8.
        let mut s = Session::new();
        let req = serde_json::to_string(&Request::Hello {
            id: 1, protocol_version: PROTOCOL_VERSION + 1,
        }).unwrap();
        let v = parse_one(&s.handle(&req));
        assert_eq!(v["type"], "error");
        assert_eq!(v["kind"], "version_mismatch");
    }

    #[test]
    fn requests_before_hello_are_refused() {
        // Without this, a client that never handshakes gets full access and
        // the version gate is decorative.
        let mut s = Session::new();
        let req = serde_json::to_string(&Request::GetStatus { id: 5 }).unwrap();
        let v = parse_one(&s.handle(&req));
        assert_eq!(v["type"], "error");
        assert_eq!(v["kind"], "bad_request");
    }

    #[test]
    fn malformed_json_is_an_error_not_a_panic() {
        let mut s = Session::new();
        let v = parse_one(&s.handle("{not json"));
        assert_eq!(v["type"], "error");
        assert_eq!(v["kind"], "bad_request");
    }

    #[test]
    fn a_malformed_line_does_not_carry_its_contents_back() {
        // serde_json's Display echoes the offending input. Phase 0 shipped
        // exactly this leak in profile_io::load, where a misplaced secret came
        // back in the error text. The same rule crosses the socket.
        let mut s = Session::new();
        let out = s.handle(r#"{"type":"connect","id":1,"params":{"profile_json":"hunter2-SECRET"}}"#);
        let joined = out.join(" ");
        assert!(
            !joined.contains("hunter2-SECRET"),
            "the error must not echo request content: {joined}"
        );
    }

    #[test]
    fn get_status_after_hello_reports_disconnected() {
        let mut s = Session::new();
        s.handle(&serde_json::to_string(&Request::Hello {
            id: 1, protocol_version: PROTOCOL_VERSION,
        }).unwrap());
        let out = s.handle(&serde_json::to_string(&Request::GetStatus { id: 2 }).unwrap());
        let joined = out.join("\n");
        assert!(joined.contains(r#""type":"state""#), "got {joined}");
        assert!(joined.contains("Disconnected"), "got {joined}");
    }

    #[test]
    fn disconnect_when_not_connected_is_refused_cleanly() {
        let mut s = Session::new();
        s.handle(&serde_json::to_string(&Request::Hello {
            id: 1, protocol_version: PROTOCOL_VERSION,
        }).unwrap());
        let v = parse_one(&s.handle(&serde_json::to_string(&Request::Disconnect { id: 2 }).unwrap()));
        assert_eq!(v["type"], "error");
        assert_eq!(v["kind"], "not_connected");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p liostunnel-helper dispatch`
Expected: FAIL — `cannot find type Session in this scope`.

- [ ] **Step 3: Implement**

Prepend to `crates/liostunnel-helper/src/dispatch.rs`:

```rust
use liostunnel_ffi::dto::protocol::{ErrorKind, Event, Request, Response, PROTOCOL_VERSION};

/// One client connection's protocol state.
///
/// Deliberately line-in, lines-out with no socket and no I/O: the entire
/// protocol is then testable without spawning a daemon, the same separation
/// that made Phase 0's `StackCore` testable without a TUN device.
pub struct Session {
    greeted: bool,
    connected: bool,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        Self { greeted: false, connected: false }
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Handles one line, returning zero or more lines to write back.
    pub fn handle(&mut self, line: &str) -> Vec<String> {
        let req: Request = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => {
                // Deliberately does NOT include the serde error: its Display
                // echoes the offending input, and the input may contain secret
                // material. Phase 0 shipped exactly this leak once already.
                return vec![err(0, ErrorKind::BadRequest, "malformed request")];
            }
        };

        let id = request_id(&req);

        if let Request::Hello { protocol_version, .. } = req {
            if protocol_version != PROTOCOL_VERSION {
                return vec![err(
                    id,
                    ErrorKind::VersionMismatch,
                    &format!(
                        "helper speaks protocol {PROTOCOL_VERSION}, client speaks \
                         {protocol_version}; reinstall the helper"
                    ),
                )];
            }
            self.greeted = true;
            return vec![ack(id)];
        }

        if !self.greeted {
            return vec![err(id, ErrorKind::BadRequest, "expected hello first")];
        }

        match req {
            Request::Hello { .. } => unreachable!("handled above"),
            Request::GetStatus { id } => vec![
                ack(id),
                event(&Event::State {
                    state: if self.connected { "Connected" } else { "Disconnected" }.into(),
                }),
            ],
            Request::Disconnect { id } => {
                if !self.connected {
                    return vec![err(id, ErrorKind::NotConnected, "no tunnel is running")];
                }
                self.connected = false;
                vec![ack(id), event(&Event::State { state: "Disconnected".into() })]
            }
            // Wired to the engine in Task 6.
            Request::Connect { id, .. } => {
                if self.connected {
                    return vec![err(
                        id,
                        ErrorKind::AlreadyConnected,
                        "a tunnel is already running; there is one routing table",
                    )];
                }
                vec![err(id, ErrorKind::Internal, "connect is not wired yet")]
            }
        }
    }
}

fn request_id(r: &Request) -> u64 {
    match r {
        Request::Hello { id, .. }
        | Request::Connect { id, .. }
        | Request::Disconnect { id }
        | Request::GetStatus { id } => *id,
    }
}

fn ack(id: u64) -> String {
    serde_json::to_string(&Response::Ack { id }).expect("Ack always serializes")
}

fn err(id: u64, kind: ErrorKind, message: &str) -> String {
    serde_json::to_string(&Response::Error { id, kind, message: message.into() })
        .expect("Error always serializes")
}

fn event(e: &Event) -> String {
    serde_json::to_string(e).expect("Event always serializes")
}
```

Add `mod dispatch;` to `main.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-helper dispatch`
Expected: PASS — 7 passed.

- [ ] **Step 5: A/B the secret-echo test**

Temporarily change the malformed-JSON arm to include the serde error:
`&format!("malformed request: {e}")`. Run the tests. Confirm
`a_malformed_line_does_not_carry_its_contents_back` FAILS. Restore and confirm it passes.

Paste both. This is the same leak Phase 0 shipped and had to fix in Task 8; the test only means something if it has been seen catching it.

- [ ] **Step 6: Commit**

```bash
git add crates/liostunnel-helper
git commit -F - <<'EOF'
feat: protocol dispatch with a version gate

Session is line-in, lines-out with no socket and no I/O, so the whole
protocol is testable without spawning a daemon -- the same separation that
made Phase 0's StackCore testable without a TUN device.

Requests before hello are refused, or the version gate would be
decorative: a client that simply never handshakes would otherwise get full
access.

Malformed input is reported without echoing its contents. serde_json's
Display includes the offending text, and Phase 0 shipped exactly that leak
in profile_io::load, where a misplaced secret came back in the error. A/B
verified against the echoing version.
EOF
```

---

### Task 6: Connect, disconnect, and the stats stream

**Files:**
- Create: `crates/liostunnel-helper/src/session.rs`
- Modify: `crates/liostunnel-helper/src/dispatch.rs`, `crates/liostunnel-helper/src/main.rs`

**Interfaces:**
- Consumes: `ConnectParams` (Task 1), `auth::secret_readable_by` (Task 3), and from `liostunnel-core`: `ServerProfile`, `SshTunnel`, `HostKeyPolicy`, `TunDevice`, `TunConfig`, `SmoltcpStack`, `StackConfig`, `Engine`, `RouteGuard`, `RoutePlan`, `RouteMode`, `platform_manager`, `route::state`.
- Produces: `session::Tunnel` with `start(params, caller_uid) -> Result<Self, TunnelError>`, `stats() -> StatsSnapshot`, `stop(self)`.

**This task reuses Phase 0's `connect.rs` wiring almost verbatim.** Read `crates/liostunnel-cli/src/commands/connect.rs` first — it establishes the ordering (SSH before routes, so a failed handshake never strands routes), the `StackShutdownOnDrop` guard, the state-file-before-apply rule, and the engine-task select. Do not re-derive any of it; the differences are only that the profile arrives over a socket and secrets are checked against the caller's uid first.

- [ ] **Step 1: Write the failing tests**

`crates/liostunnel-helper/src/session.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use liostunnel_ffi::dto::protocol::ConnectParams;

    fn params_with_secret(path: &str) -> ConnectParams {
        ConnectParams {
            profile_json: format!(
                r#"{{"id":"00000000-0000-0000-0000-000000000000","name":"t",
                    "protocol":"ssh","host":"127.0.0.1","port":22,
                    "auth":{{"type":"password","password":{{"source":"file","path":"{path}"}}}},
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
    fn a_secret_the_caller_does_not_own_is_refused_before_anything_is_created() {
        // The escalation, at the layer that matters: this must be refused
        // before a TUN device exists, before a route is installed, and before
        // any file is read.
        let me = unsafe { libc::getuid() };
        if me == 0 {
            eprintln!("skipped: running as root");
            return;
        }
        if !std::path::Path::new("/etc/shadow").exists() {
            eprintln!("skipped: /etc/shadow absent");
            return;
        }
        let err = Tunnel::authorize_params(&params_with_secret("/etc/shadow"), me)
            .expect_err("a root-owned secret must be refused");
        assert!(matches!(err, StartError::SecretNotPermitted(_)), "got {err:?}");
    }

    #[test]
    fn a_profile_that_does_not_parse_is_refused_without_echoing_it() {
        let me = unsafe { libc::getuid() };
        let mut p = params_with_secret("/tmp/whatever");
        p.profile_json = r#"{"host":"SECRET-VALUE-HERE"}"#.into();
        let err = Tunnel::authorize_params(&p, me).expect_err("must not parse");
        let text = format!("{err}");
        assert!(!text.contains("SECRET-VALUE-HERE"), "error echoed input: {text}");
    }

    #[test]
    fn an_unknown_route_mode_is_refused() {
        let me = unsafe { libc::getuid() };
        let mut p = params_with_secret("/tmp/whatever");
        p.route_mode = "wide-open".into();
        assert!(Tunnel::authorize_params(&p, me).is_err());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p liostunnel-helper session`
Expected: FAIL — `cannot find type Tunnel in this scope`.

- [ ] **Step 3: Implement authorization, separated from the connect itself**

`crates/liostunnel-helper/src/session.rs`:

```rust
use liostunnel_core::config::profile::{AuthMethod, ServerProfile};
use liostunnel_core::config::secret::SecretRef;
use liostunnel_ffi::dto::protocol::{ConnectParams, StatsSnapshot};

use crate::auth::{self, AuthError};

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("profile is not valid")]
    BadProfile,
    #[error("route mode must be `test` or `default`")]
    BadRouteMode,
    #[error("{0}")]
    SecretNotPermitted(AuthError),
    #[error("{0}")]
    Tunnel(#[from] liostunnel_core::TunnelError),
}

pub struct Tunnel {
    /* filled in by Step 5 */
}

impl Tunnel {
    /// Everything that must be checked *before* any privileged action.
    ///
    /// Split out from `start` deliberately: it is pure, so the escalation
    /// guard is testable without root, a TUN device, or a routing table.
    pub fn authorize_params(
        params: &ConnectParams,
        caller_uid: u32,
    ) -> Result<ServerProfile, StartError> {
        // Note the discarded error: serde_json's Display echoes the offending
        // input, which may be secret material.
        let profile: ServerProfile =
            serde_json::from_str(&params.profile_json).map_err(|_| StartError::BadProfile)?;

        if params.route_mode != "test" && params.route_mode != "default" {
            return Err(StartError::BadRouteMode);
        }

        // THE ESCALATION GATE. The helper runs as root and could read any of
        // these; this is what stops the caller borrowing that power.
        for r in profile.auth.secret_refs() {
            if let SecretRef::File { path } = r {
                auth::secret_readable_by(path, caller_uid)
                    .map_err(StartError::SecretNotPermitted)?;
            }
        }

        Ok(profile)
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-helper session -- --nocapture`
Expected: PASS — 3 passed (note any `skipped:` lines).

- [ ] **Step 5: Wire the engine, following the CLI's ordering exactly**

Extend `Tunnel` with `start`, `stats`, and `stop`, mirroring
`crates/liostunnel-cli/src/commands/connect.rs`:

1. `authorize_params` first — nothing privileged happens before it returns.
2. `SshTunnel::connect` — the tunnel must be up before any route exists, so a
   failed handshake cannot strand routes pointing at a dead interface.
3. `TunDevice::open`, then `SmoltcpStack::start`, guarded by the same
   `StackShutdownOnDrop` pattern the CLI uses — otherwise a failure between
   `start` and `Engine::new` leaks the stack thread and the TUN device.
4. `route::state::recover_if_stale`, then write the state file, *then*
   `RouteGuard::apply`. The write-before-apply order is deliberate: a crash
   between them leaves a record of routes that were never installed, and
   reverting a nonexistent route is harmless. The reverse loses them.
5. `Engine::new(protocol, resolver, handles)` and spawn `run`.

`stats()` reads the `StatsHandle` and maps it to `StatsSnapshot`. `stop()`
signals shutdown, reverts routes, clears the state file, and aborts the engine
task — the same four actions the CLI performs on Ctrl-C.

- [ ] **Step 6: Push stats from dispatch**

In `dispatch.rs`, replace the `Request::Connect` stub: call
`Tunnel::authorize_params`, then `Tunnel::start`, map `StartError` to the right
`ErrorKind` (`SecretNotPermitted` → `ErrorKind::SecretNotPermitted`,
`BadProfile`/`BadRouteMode` → `ErrorKind::BadRequest`, auth failures →
`ErrorKind::AuthFailed`), and on success emit `Ack` plus a `State` event.

The accept loop in `main.rs` spawns a task per connection that reads lines,
feeds them to `Session::handle`, writes the replies, and — while connected —
emits a `Stats` event every second from `Tunnel::stats()`.

- [ ] **Step 7: Verify the helper end to end with `socat`**

With the Docker SSH fixture up (`make -C testing/docker up`):

```bash
sudo ./target/debug/liostunnel-helper --socket /tmp/lios.sock --uid "$(id -u)" &
printf '%s\n' '{"type":"hello","id":1,"protocol_version":1}' | socat - UNIX-CONNECT:/tmp/lios.sock
```

Expected: `{"type":"ack","id":1}`. Then send a `connect` with a real profile and
confirm `ack`, a `state` event, and `stats` events arriving about once a second.

This is why the protocol is hand-inspectable (D5) — the privileged component can
be driven and observed directly, without a UI in the way.

- [ ] **Step 8: Commit**

```bash
git add crates/liostunnel-helper
git commit -F - <<'EOF'
feat: connect/disconnect and the stats stream

Reuses Phase 0's connect.rs wiring rather than re-deriving it: SSH before
routes so a failed handshake cannot strand routes, StackShutdownOnDrop so
a failure between stack start and Engine::new does not leak the thread and
TUN device, and the state file written before routes are applied so a
kill -9 leaves a recoverable record.

authorize_params is split out from start and is pure, so the privilege
escalation guard is testable without root, a TUN device, or a routing
table. Nothing privileged happens before it returns.
EOF
```

---

# Milestone B — The FFI layer

---

### Task 7: Prove the FRB toolchain before writing real DTOs

The spec (§9) mandates this task exist and come first. Every unfamiliar API surface in Phase 0 produced at least one genuine plan error — `polling`'s `AsSource: AsFd` bound, `tokio-util`'s nonexistent `sync` feature. FRB v2 codegen is this slice's equivalent, and its exact config keys were the one thing I could not verify from documentation while writing this plan.

**Files:**
- Create: `app/` (Flutter project), `flutter_rust_bridge.yaml`
- Modify: `crates/liostunnel-ffi/src/lib.rs`, `crates/liostunnel-ffi/src/api/mod.rs`, `crates/liostunnel-ffi/src/api/probe.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: a working codegen pipeline and `api::probe::echo_probe(input: ProbeDto) -> ProbeDto`.

- [ ] **Step 1: Create the Flutter desktop project**

```bash
cd /Users/hanif/Labs/personal/liostunnel
flutter create --platforms=macos,linux --project-name liostunnel_app app
cd app && flutter run -d macos --help >/dev/null && cd ..
```

Expected: `app/` exists with `macos/` and `linux/` runner directories.

- [ ] **Step 2: Install the codegen tool at the pinned version**

```bash
cargo install flutter_rust_bridge_codegen --version 2.12.0 --locked
flutter_rust_bridge_codegen --version
```

Expected: prints `2.12.0`. **If only a prerelease installs, stop and report it** — do not silently accept `2.13.0-beta.5` (Global Constraints).

- [ ] **Step 3: Write a deliberately awkward probe DTO**

`crates/liostunnel-ffi/src/api/probe.rs`:

```rust
/// Exists only to prove codegen handles the shapes the real DTOs need:
/// a struct, an Option, a Vec, and a tagged enum. If FRB cannot express
/// one of these, better to find out here than halfway through Task 8.
#[derive(Clone, Debug, PartialEq)]
pub struct ProbeDto {
    pub name: String,
    pub count: u32,
    pub maybe: Option<String>,
    pub items: Vec<String>,
    pub choice: ProbeChoice,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProbeChoice {
    First,
    Second { detail: String },
}

/// Round-trips its argument. Dart asserts the value survives unchanged.
pub fn echo_probe(input: ProbeDto) -> ProbeDto {
    input
}
```

`crates/liostunnel-ffi/src/api/mod.rs`:

```rust
pub mod probe;
```

Add `pub mod api;` and `pub mod frb_generated;` to `crates/liostunnel-ffi/src/lib.rs`, and add `flutter_rust_bridge = "=2.12.0"` to its dependencies. The `=` is deliberate: codegen and runtime versions must match exactly.

- [ ] **Step 4: Configure and run codegen**

`flutter_rust_bridge.yaml` at the repo root:

```yaml
rust_input: crates/liostunnel-ffi/src/api/mod.rs
rust_root: crates/liostunnel-ffi
dart_output: app/lib/src/rust
```

```bash
flutter_rust_bridge_codegen generate
```

**If the config keys differ from the above, that is expected — this task exists to find out.** Consult `flutter_rust_bridge_codegen generate --help` and the generated error, use what actually works, and record the working configuration verbatim in your report so Task 8 inherits it.

- [ ] **Step 5: Write the Dart round-trip test**

`app/test/probe_test.dart`:

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:liostunnel_app/src/rust/api/probe.dart';
import 'package:liostunnel_app/src/rust/frb_generated.dart';

void main() {
  setUpAll(() async => await RustLib.init());

  test('a DTO with option, vec and tagged enum survives the bridge', () async {
    final sent = ProbeDto(
      name: 'x',
      count: 7,
      maybe: 'present',
      items: ['a', 'b'],
      choice: const ProbeChoice.second(detail: 'd'),
    );
    final got = await echoProbe(input: sent);
    expect(got.name, 'x');
    expect(got.count, 7);
    expect(got.maybe, 'present');
    expect(got.items, ['a', 'b']);
    expect(got.choice, isA<ProbeChoice_Second>());
  });

  test('a null Option survives as null', () async {
    final got = await echoProbe(
      input: ProbeDto(
        name: 'y', count: 0, maybe: null, items: [],
        choice: const ProbeChoice.first(),
      ),
    );
    expect(got.maybe, isNull);
    expect(got.items, isEmpty);
  });
}
```

- [ ] **Step 6: Run it**

```bash
cd app && flutter test test/probe_test.dart
```

Expected: PASS, 2 tests. If the generated Dart names differ from what the test assumes (`ProbeChoice_Second`, named vs positional arguments), fix the *test* to match the generated API and record the actual shape — the generator's conventions are the ground truth here, not my guess at them.

- [ ] **Step 7: Commit, recording what actually worked**

```bash
git add app crates/liostunnel-ffi flutter_rust_bridge.yaml Cargo.toml Cargo.lock
git commit -F - <<'EOF'
feat: prove the flutter_rust_bridge toolchain with a probe DTO

Verifies codegen before any real DTO is written, per spec 9. The probe
type deliberately includes a struct, an Option, a Vec and a tagged enum --
the shapes the profile and protocol DTOs need -- so an FRB limitation
surfaces here rather than halfway through the real work.

Pinned to flutter_rust_bridge 2.12.0 with an exact-version requirement:
it is the latest stable, 2.13.0-beta.5 is a prerelease, and codegen and
runtime versions must match.

Every unfamiliar API in Phase 0 produced at least one genuine plan error.
This task is the cheap version of that lesson.
EOF
```

---

### Task 8: Profile DTOs and conversions

**Files:**
- Create: `crates/liostunnel-ffi/src/dto/profile.rs`
- Create: `crates/liostunnel-ffi/src/api/config.rs`
- Modify: `crates/liostunnel-ffi/src/dto/mod.rs`, `crates/liostunnel-ffi/src/api/mod.rs`

**Interfaces:**
- Consumes: `liostunnel_core::config::profile::ServerProfile`.
- Produces: `dto::profile::ProfileDto` with `From<ServerProfile>` and `TryFrom<ProfileDto> for ServerProfile`; FRB functions `api::config::parse_profile(json: String) -> Result<ProfileDto, String>`, `api::config::export_profile(dto: ProfileDto) -> Result<String, String>`, and `api::config::profile_summary(dto: ProfileDto) -> String`.

**Why a DTO rather than exporting the core type.** `ServerProfile` holds `Uuid`, `IpAddr`, and nested tagged enums. Binding Dart to it directly would let any core change break codegen, and would start shaping the core around what FRB finds convenient (spec §9, D7).

- [ ] **Step 1: Write the failing conversion tests**

`crates/liostunnel-ffi/src/dto/profile.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"Home VPS",
        "protocol":"ssh","host":"198.51.100.7","port":22,
        "auth":{"type":"password","password":{"source":"env","var":"PW"}},
        "dns":["1.1.1.1","1.0.0.1"],
        "split_tunnel":{"type":"all_traffic"},"kill_switch":false}"#;

    #[test]
    fn a_core_profile_converts_to_a_flat_dto() {
        let core: ServerProfile = serde_json::from_str(SAMPLE).unwrap();
        let dto = ProfileDto::from(core);
        assert_eq!(dto.name, "Home VPS");
        assert_eq!(dto.host, "198.51.100.7");
        assert_eq!(dto.port, 22);
        assert_eq!(dto.protocol, "ssh");
        assert_eq!(dto.dns_servers, vec!["1.1.1.1", "1.0.0.1"]);
        assert_eq!(dto.dns_mode, "tcp");
        // UUIDs and IPs cross as strings so FRB never has to model them.
        assert_eq!(dto.id, "b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f");
    }

    #[test]
    fn the_dto_round_trips_back_to_an_equal_core_profile() {
        let core: ServerProfile = serde_json::from_str(SAMPLE).unwrap();
        let back = ServerProfile::try_from(ProfileDto::from(core.clone())).unwrap();
        assert_eq!(back, core);
    }

    #[test]
    fn the_dto_never_carries_secret_material() {
        // The DTO crosses into Dart and over the socket. It may describe where
        // a secret lives; it must never contain one.
        let core: ServerProfile = serde_json::from_str(SAMPLE).unwrap();
        let dto = ProfileDto::from(core);
        let rendered = format!("{dto:?}");
        for forbidden in ["BEGIN", "PRIVATE KEY", "hunter2"] {
            assert!(!rendered.contains(forbidden), "secret-shaped content in DTO: {rendered}");
        }
        // It records the *kind* of auth and where the material lives, no more.
        assert_eq!(dto.auth_kind, "password");
        assert_eq!(dto.auth_secret_source, "env:PW");
    }

    #[test]
    fn a_malformed_uuid_is_rejected_on_the_way_back() {
        let core: ServerProfile = serde_json::from_str(SAMPLE).unwrap();
        let mut dto = ProfileDto::from(core);
        dto.id = "not-a-uuid".into();
        assert!(ServerProfile::try_from(dto).is_err());
    }

    #[test]
    fn a_malformed_ip_is_rejected_on_the_way_back() {
        let core: ServerProfile = serde_json::from_str(SAMPLE).unwrap();
        let mut dto = ProfileDto::from(core);
        dto.dns_servers = vec!["999.999.999.999".into()];
        assert!(ServerProfile::try_from(dto).is_err());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p liostunnel-ffi profile`
Expected: FAIL — `cannot find type ProfileDto in this scope`.

- [ ] **Step 3: Implement the DTO and conversions**

Write `ProfileDto` as a flat struct with `String` fields for `id`, `host`, `protocol`, `dns_mode`, `auth_kind`, `auth_secret_source`, `split_tunnel`, plus `port: u16`, `dns_servers: Vec<String>`, `kill_switch: bool`, and `doh_sni`/`doh_path` as `Option<String>`.

`From<ServerProfile>` maps each field; `auth_secret_source` renders a `SecretRef` as `"file:/path"` or `"env:NAME"` — a *description* of where the secret lives, never its contents.

`TryFrom<ProfileDto>` parses the strings back, returning an error type carrying the offending field name but **not** the offending value (the value may be secret-adjacent — the same rule that bit Phase 0's `profile_io::load`).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-ffi profile`
Expected: PASS — 5 passed.

- [ ] **Step 5: Expose the FRB config functions and regenerate**

Spec §9 requires the FFI expose "profile parse/validate, portable import/export". Import is `parse_profile`; export is `export_profile`. Both directions exist so a profile can leave the app and come back unchanged — §4 puts in-app *editing* out of scope, not portability.

`crates/liostunnel-ffi/src/api/config.rs`:

```rust
use crate::dto::profile::ProfileDto;

/// Parses a profile JSON document into a UI-shaped DTO.
///
/// Returns a description of the profile, never its secret material.
pub fn parse_profile(json: String) -> Result<ProfileDto, String> {
    let core: liostunnel_core::config::profile::ServerProfile =
        serde_json::from_str(&json).map_err(|_| "not a valid profile".to_string())?;
    Ok(ProfileDto::from(core))
}

/// Renders a DTO back to the canonical on-disk profile JSON.
///
/// The output is a profile document, so it names where secrets live and
/// never carries them -- exactly what parse_profile accepted.
pub fn export_profile(dto: ProfileDto) -> Result<String, String> {
    let core = liostunnel_core::config::profile::ServerProfile::try_from(dto)
        .map_err(|e| e.to_string())?;
    serde_json::to_string_pretty(&core).map_err(|_| "could not serialize".to_string())
}

/// One-line summary for the profiles list.
pub fn profile_summary(dto: ProfileDto) -> String {
    format!("{} — {}:{}", dto.name, dto.host, dto.port)
}
```

- [ ] **Step 6: Pin that export is the exact inverse of parse**

Append to the test module in `dto/profile.rs`:

```rust
#[test]
fn exporting_a_parsed_profile_reproduces_an_equal_document() {
    // Portability means a profile can leave the app and come back
    // unchanged. Comparing parsed values, not text, because key order and
    // whitespace are not part of the contract.
    let dto = crate::api::config::parse_profile(SAMPLE.to_string()).unwrap();
    let out = crate::api::config::export_profile(dto).unwrap();
    let a: ServerProfile = serde_json::from_str(SAMPLE).unwrap();
    let b: ServerProfile = serde_json::from_str(&out).unwrap();
    assert_eq!(a, b);
}

#[test]
fn an_exported_profile_carries_no_secret_material() {
    let dto = crate::api::config::parse_profile(SAMPLE.to_string()).unwrap();
    let out = crate::api::config::export_profile(dto).unwrap();
    // It records the source of the secret, not the secret.
    assert!(out.contains("\"env\""), "got {out}");
    assert!(!out.contains("BEGIN"), "exported document contains key material");
}
```

Run: `cargo test -p liostunnel-ffi profile`
Expected: PASS — 7 passed.

- [ ] **Step 7: Regenerate and check the Dart side still builds**

Run `flutter_rust_bridge_codegen generate`, then `cd app && flutter test`.

- [ ] **Step 8: Commit**

```bash
git add crates/liostunnel-ffi app/lib/src/rust
git commit -F - <<'EOF'
feat: profile DTOs for the UI

The FFI crate owns its own flat DTOs rather than exporting core types.
ServerProfile holds Uuid, IpAddr and nested tagged enums; binding Dart
directly to it would let any core change break Dart codegen and would
start shaping the core around what FRB finds convenient.

auth_secret_source describes where a secret lives ("file:/path",
"env:NAME") and never what it is. A test pins that the DTO's Debug
rendering contains no secret-shaped content, because this type crosses
both into Dart and over the socket.

Conversion errors name the offending field but not its value -- Phase 0
shipped exactly that leak in profile_io::load.
EOF
```

---

### Task 9: The protocol codec, exposed to Dart

**Files:**
- Create: `crates/liostunnel-ffi/src/api/protocol.rs`
- Modify: `crates/liostunnel-ffi/src/api/mod.rs`

**Interfaces:**
- Consumes: `dto::protocol::{Request, Response, Event, ErrorKind, ConnectParams, StatsSnapshot, PROTOCOL_VERSION}` (Task 1).
- Produces: FRB functions `api::protocol::encode_request(req: RequestDto) -> Result<String, String>`, `api::protocol::decode_message(line: String) -> Result<IncomingDto, String>`, and `api::protocol::protocol_version() -> u32`; plus the generated Dart mirrors of `RequestDto`, `IncomingDto`, and `ErrorKind`.

**Why this task exists.** The plan's architecture states the message types are "defined once in Rust and mirrored to Dart by FRB", and spec §3 puts "IPC message types" in the FFI's scope. Dart therefore does socket framing and nothing else: it never calls `jsonEncode` on a request or `jsonDecode` on a reply.

The reason is the same one behind exit criterion P1a-1. A wire format re-implemented in a second language drifts from the first. For profiles the drift is a parse failure the user sees; here it is worse — add an `ErrorKind` variant in Rust and a hand-written Dart decoder silently mishandles it, most likely by falling into a default branch that reports success.

- [ ] **Step 1: Write the failing codec tests**

`crates/liostunnel-ffi/src/api/protocol.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_encoded_request_is_exactly_one_wire_line() {
        // Dart appends nothing but a newline. If encode ever emitted a bare
        // newline of its own, framing would break in a way that looks like a
        // helper bug rather than a client bug.
        let line = encode_request(RequestDto::Disconnect { id: 4 }).unwrap();
        assert!(!line.contains('\n'), "encoded request must be newline-free: {line}");
        assert!(line.contains(r#""type":"disconnect""#), "got {line}");
    }

    #[test]
    fn encoding_matches_what_the_helper_parses() {
        // The whole point of the codec: what Dart sends must deserialize as
        // the Request the helper's dispatcher matches on.
        let line = encode_request(RequestDto::Hello { id: 1 }).unwrap();
        let parsed: crate::dto::protocol::Request = serde_json::from_str(&line).unwrap();
        assert_eq!(
            parsed,
            crate::dto::protocol::Request::Hello { id: 1, protocol_version: PROTOCOL_VERSION }
        );
    }

    #[test]
    fn hello_carries_the_version_the_client_never_chooses() {
        // RequestDto::Hello has no version field. The version is a property of
        // this build, not something the UI can get wrong or a caller can spoof
        // by constructing a DTO.
        let line = encode_request(RequestDto::Hello { id: 1 }).unwrap();
        assert!(line.contains(&format!(r#""protocol_version":{PROTOCOL_VERSION}"#)), "got {line}");
    }

    #[test]
    fn an_error_reply_decodes_with_its_kind_intact() {
        let line = r#"{"type":"error","id":9,"kind":"secret_not_permitted","message":"nope"}"#;
        match decode_message(line.to_string()).unwrap() {
            IncomingDto::Error { id, kind, .. } => {
                assert_eq!(id, 9);
                assert_eq!(kind, ErrorKindDto::SecretNotPermitted);
            }
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_message_type_is_an_error_not_a_silent_default() {
        // A helper newer than the app must not have its messages swallowed.
        // Returning Err makes the client log and ignore deliberately; a
        // default branch would make it report success for something it never
        // understood.
        let r = decode_message(r#"{"type":"quantum_flux","id":1}"#.to_string());
        assert!(r.is_err(), "unknown message types must not decode");
    }

    #[test]
    fn a_truncated_line_is_an_error() {
        assert!(decode_message(r#"{"type":"sta"#.to_string()).is_err());
    }

    #[test]
    fn every_error_kind_survives_the_round_trip() {
        // Exhaustive by construction: adding an ErrorKind without adding it
        // here fails to compile, which is the point.
        use crate::dto::protocol::ErrorKind as K;
        let all = [
            K::VersionMismatch, K::Unauthorized, K::SecretNotPermitted,
            K::AlreadyConnected, K::NotConnected, K::AuthFailed,
            K::BadRequest, K::Internal,
        ];
        for k in all {
            let line = serde_json::to_string(&crate::dto::protocol::Response::Error {
                id: 1, kind: k, message: String::new(),
            }).unwrap();
            match decode_message(line).unwrap() {
                IncomingDto::Error { .. } => {}
                other => panic!("{k:?} decoded as {other:?}"),
            }
        }
    }

    #[test]
    fn stats_events_decode_with_their_counters() {
        let line = serde_json::to_string(&crate::dto::protocol::Event::Stats {
            snapshot: crate::dto::protocol::StatsSnapshot {
                bytes_up: 10, bytes_down: 20, active_flows: 1,
                flows_failed: 0, dns_queries: 3,
            },
        }).unwrap();
        match decode_message(line).unwrap() {
            IncomingDto::Stats { bytes_up, active_flows, .. } => {
                assert_eq!(bytes_up, 10);
                assert_eq!(active_flows, 1);
            }
            other => panic!("expected stats, got {other:?}"),
        }
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p liostunnel-ffi protocol::tests`
Expected: FAIL — `cannot find function encode_request in this scope`.

- [ ] **Step 3: Implement the codec**

```rust
use crate::dto::protocol::{self, PROTOCOL_VERSION};

/// What the UI can ask the helper to do.
///
/// Deliberately smaller than `Request`: `protocol_version` is not a field
/// here, because the version belongs to this build rather than to the caller.
#[derive(Clone, Debug)]
pub enum RequestDto {
    Hello { id: u64 },
    Connect { id: u64, params: ConnectParamsDto },
    Disconnect { id: u64 },
    GetStatus { id: u64 },
}

/// Mirrors `protocol::ConnectParams` field for field. Every field is a
/// String or a primitive, so nothing here needs FRB to model a core type.
#[derive(Clone, Debug)]
pub struct ConnectParamsDto {
    pub profile_json: String,
    pub user: String,
    /// "test" or "default".
    pub route_mode: String,
    /// Only meaningful when `route_mode == "test"`.
    pub cidrs: Vec<String>,
    pub capture_dns: bool,
    pub tun_address: String,
}

/// Anything that arrives from the helper — replies and pushed events alike.
/// Flattened into one enum so the Dart side has a single switch.
#[derive(Clone, Debug)]
pub enum IncomingDto {
    Ack { id: u64 },
    Error { id: u64, kind: ErrorKindDto, message: String },
    State { state: String },
    /// Field types match `StatsSnapshot` exactly — flows_failed is u64 there,
    /// and narrowing it here would silently truncate.
    Stats {
        bytes_up: u64, bytes_down: u64, active_flows: u32,
        flows_failed: u64, dns_queries: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKindDto {
    VersionMismatch, Unauthorized, SecretNotPermitted,
    AlreadyConnected, NotConnected, AuthFailed, BadRequest, Internal,
}

/// Serializes a request to a single wire line, without the trailing newline.
pub fn encode_request(req: RequestDto) -> Result<String, String> { /* map + to_string */ }

/// Parses one wire line. Unknown message types are an error, never a default.
pub fn decode_message(line: String) -> Result<IncomingDto, String> { /* try Response, then Event */ }

/// The protocol version this build speaks.
pub fn protocol_version() -> u32 { PROTOCOL_VERSION }
```

`encode_request` maps `RequestDto::Hello { id }` to `protocol::Request::Hello { id, protocol_version: PROTOCOL_VERSION }`, then `serde_json::to_string`. `decode_message` attempts `Response` first, then `Event`, and returns `Err` if neither matches — the tag is `#[serde(tag = "type")]` on both, so an unknown tag fails both attempts. Error strings describe the failure shape, never the line's contents: a malformed line may hold a partial secret-bearing field.

Add `pub mod protocol;` to `api/mod.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p liostunnel-ffi protocol::tests`
Expected: PASS — 8 passed.

- [ ] **Step 5: A/B the unknown-type guard**

This one names the defect it prevents, so it must be shown catching it (Global Constraints). Temporarily change `decode_message`'s final arm to return `Ok(IncomingDto::Ack { id: 0 })` instead of `Err`.

Run: `cargo test -p liostunnel-ffi protocol::tests`
Expected: FAIL — `an_unknown_message_type_is_an_error_not_a_silent_default` panics on `assert!(r.is_err())`.

Restore the `Err` and confirm green. **Paste both outputs in your report.**

- [ ] **Step 6: Regenerate and confirm the Dart mirrors exist**

```bash
flutter_rust_bridge_codegen generate
grep -r "IncomingDto\|RequestDto" app/lib/src/rust/api/protocol.dart | head
```

Expected: generated Dart classes for both. Record the exact generated names and constructor shapes — Task 10 is written against them, and Task 7 established that the generator's conventions are ground truth, not my guess at them.

- [ ] **Step 7: Commit**

```bash
git add crates/liostunnel-ffi app/lib/src/rust
git commit -F - <<'EOF'
feat: expose the IPC codec to Dart through FRB

The wire format is defined once, in Rust, and mirrored to Dart by codegen.
Dart does socket framing and nothing else -- it never jsonEncodes a request
or jsonDecodes a reply.

This is exit criterion P1a-1's reasoning applied to the protocol. A format
re-implemented in a second language drifts from the first; for profiles the
drift is a visible parse failure, but here a new ErrorKind would fall into a
hand-written default branch and get reported as success.

RequestDto has no protocol_version field. The version belongs to the build,
so a caller cannot set it wrong or spoof it by constructing a DTO.

Unknown message types decode to an error rather than a default, so a helper
newer than the app is ignored deliberately instead of silently.
EOF
```

---

# Milestone C — The Flutter app

---

### Task 10: The helper client

**Files:**
- Create: `app/lib/services/helper_client.dart`
- Create: `app/test/helper_client_test.dart`

**Interfaces:**
- Consumes: `api::protocol::{encode_request, decode_message}` via their generated Dart bindings (Task 9).
- Produces: `HelperClient({Duration retryDelay})` with `connect(String socketPath)`, `Future<void> hello()`, `Future<void> sendConnect(ConnectParamsDto params)`, `Future<void> disconnect()`, `Future<void> getStatus()`, `Stream<HelperEvent> events`, `Future<void> get whenReconnected`, and `close()`; plus `HelperUnavailable`, `HelperForbidden`, and `HelperError`.

**Verified Dart facts** (confirmed by running them on this machine — see the plan's API reference): unix sockets work via `InternetAddress(path, type: InternetAddressType.unix)` with a required-and-ignored port argument; `utf8.decoder` + `LineSplitter` framing works. **A live `ServerSocket` listener keeps the isolate alive**, so tests must cancel the subscription and close the server or they hang rather than fail.

Dart's job here is framing and lifecycle only. Encoding and decoding go through the generated bindings from Task 9 — `jsonEncode`/`jsonDecode` appear in this file's *tests* (to build fixtures) but never in the client itself.

- [ ] **Step 1: Write the failing tests**

`app/test/helper_client_test.dart`:

```dart
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:liostunnel_app/services/helper_client.dart';

/// A stand-in helper: replies to hello, then pushes whatever it is told to.
class FakeHelper {
  late final ServerSocket _server;
  late final StreamSubscription _sub;
  final List<String> received = [];
  final List<String> _toPush;
  final String _path;

  FakeHelper(this._path, {List<String> push = const []}) : _toPush = push;

  Future<void> start() async {
    try { File(_path).deleteSync(); } catch (_) {}
    final addr = InternetAddress(_path, type: InternetAddressType.unix);
    _server = await ServerSocket.bind(addr, 0);
    _sub = _server.listen((sock) {
      sock.cast<List<int>>().transform(utf8.decoder)
          .transform(const LineSplitter()).listen((line) {
        received.add(line);
        final msg = jsonDecode(line) as Map<String, dynamic>;
        sock.write('${jsonEncode({"type": "ack", "id": msg["id"]})}\n');
        for (final p in _toPush) {
          sock.write('$p\n');
        }
      });
    });
  }

  Future<void> stop() async {
    await _sub.cancel();     // or the isolate never exits and the test hangs
    await _server.close();
    try { File(_path).deleteSync(); } catch (_) {}
  }
}

void main() {
  test('hello is acked and the handshake completes', () async {
    final path = '/tmp/lios-test-hello.sock';
    final helper = FakeHelper(path);
    await helper.start();

    final client = HelperClient();
    await client.connect(path);
    await client.hello();

    expect(helper.received.length, 1);
    expect(jsonDecode(helper.received.first)['type'], 'hello');

    await client.close();
    await helper.stop();
  });

  test('pushed stats events reach the event stream', () async {
    final path = '/tmp/lios-test-stats.sock';
    final stats = jsonEncode({
      "type": "stats",
      "snapshot": {"bytes_up": 10, "bytes_down": 20, "active_flows": 1,
                   "flows_failed": 0, "dns_queries": 3}
    });
    final helper = FakeHelper(path, push: [stats]);
    await helper.start();

    final client = HelperClient();
    await client.connect(path);
    final first = client.events.first;
    await client.hello();
    final ev = await first.timeout(const Duration(seconds: 5));

    expect(ev, isA<StatsEvent>());
    expect((ev as StatsEvent).bytesUp, 10);

    await client.close();
    await helper.stop();
  });

  test('connecting to a missing socket reports helperNotInstalled', () async {
    final client = HelperClient();
    await expectLater(
      client.connect('/tmp/definitely-not-here.sock'),
      throwsA(isA<HelperUnavailable>()),
    );
  });

  test('a partial line is buffered until its newline arrives', () async {
    // Framing regression: JSON split across socket reads must not be parsed
    // twice or dropped. LineSplitter handles it, and this pins that we did
    // not replace it with a naive per-chunk decode.
    final path = '/tmp/lios-test-partial.sock';
    try { File(path).deleteSync(); } catch (_) {}
    final addr = InternetAddress(path, type: InternetAddressType.unix);
    final server = await ServerSocket.bind(addr, 0);
    final sub = server.listen((sock) async {
      sock.write('{"type":"sta');
      await Future.delayed(const Duration(milliseconds: 50));
      sock.write('te","state":"Connected"}\n');
    });

    final client = HelperClient();
    await client.connect(path);
    final ev = await client.events.first.timeout(const Duration(seconds: 5));
    expect(ev, isA<StateEvent>());
    expect((ev as StateEvent).state, 'Connected');

    await client.close();
    await sub.cancel();
    await server.close();
    try { File(path).deleteSync(); } catch (_) {}
  });

  test('a socket the user cannot open reports unauthorized, not missing',
      () async {
    // Spec 10 lists "socket permission denied" as its own case. It means the
    // helper is installed but this user is not authorized -- the opposite
    // advice from "helper not installed", so the two must not collapse.
    final path = '/tmp/lios-test-noperm.sock';
    try { File(path).deleteSync(); } catch (_) {}
    final addr = InternetAddress(path, type: InternetAddressType.unix);
    final server = await ServerSocket.bind(addr, 0);
    final sub = server.listen((_) {});
    await Process.run('chmod', ['000', path]);

    final client = HelperClient();
    await expectLater(client.connect(path), throwsA(isA<HelperForbidden>()));

    await sub.cancel();
    await server.close();
    try { File(path).deleteSync(); } catch (_) {}
  }, skip: Platform.environment['USER'] == 'root'
      ? 'root bypasses file permissions'
      : null);

  test('the helper dying mid-session surfaces as a disconnect, not a hang',
      () async {
    // The UI must not sit on "Connected" forever after the daemon dies.
    final path = '/tmp/lios-test-death.sock';
    try { File(path).deleteSync(); } catch (_) {}
    final addr = InternetAddress(path, type: InternetAddressType.unix);
    final server = await ServerSocket.bind(addr, 0);
    final sub = server.listen((sock) async {
      sock.write('{"type":"state","state":"Connected"}\n');
      await Future.delayed(const Duration(milliseconds: 50));
      await sock.close();       // the daemon dies
    });

    final client = HelperClient(retryDelay: const Duration(milliseconds: 20));
    await client.connect(path);
    final states = <String>[];
    client.events.listen((e) {
      if (e is StateEvent) states.add(e.state);
    });
    await Future.delayed(const Duration(milliseconds: 300));

    expect(states.first, 'Connected');
    expect(states, contains('Disconnected'),
        'a dropped socket must produce a Disconnected state event');

    await client.close();
    await sub.cancel();
    await server.close();
    try { File(path).deleteSync(); } catch (_) {}
  });

  test('an in-flight request fails when the socket drops', () async {
    // Otherwise the future never completes and the connect button spins
    // forever.
    final path = '/tmp/lios-test-inflight.sock';
    try { File(path).deleteSync(); } catch (_) {}
    final addr = InternetAddress(path, type: InternetAddressType.unix);
    final server = await ServerSocket.bind(addr, 0);
    final sub = server.listen((sock) async {
      await Future.delayed(const Duration(milliseconds: 30));
      await sock.close();       // never acks
    });

    final client = HelperClient(retryDelay: const Duration(milliseconds: 20));
    await client.connect(path);
    await expectLater(
      client.hello().timeout(const Duration(seconds: 2)),
      throwsA(isA<HelperUnavailable>()),
    );

    await client.close();
    await sub.cancel();
    await server.close();
    try { File(path).deleteSync(); } catch (_) {}
  });

  test('the client reconnects after the helper comes back', () async {
    // Spec 10 requires a reconnect loop. The helper is the long-lived
    // process; the app must re-attach rather than require a restart.
    final path = '/tmp/lios-test-reconnect.sock';
    final first = FakeHelper(path);
    await first.start();

    final client = HelperClient(retryDelay: const Duration(milliseconds: 20));
    await client.connect(path);
    await client.hello();
    await first.stop();                       // helper goes away

    await Future.delayed(const Duration(milliseconds: 60));
    final second = FakeHelper(path);          // and comes back
    await second.start();

    // The client re-attaches on its own and re-handshakes.
    await client.whenReconnected.timeout(const Duration(seconds: 5));
    expect(second.received.length, greaterThanOrEqualTo(1));
    expect(jsonDecode(second.received.first)['type'], 'hello');

    await client.close();
    await second.stop();
  });
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd app && flutter test test/helper_client_test.dart`
Expected: FAIL — `Target of URI doesn't exist: 'package:liostunnel_app/services/helper_client.dart'`.

- [ ] **Step 3: Implement `HelperClient`**

`app/lib/services/helper_client.dart` defines:
- `sealed class HelperEvent` with `StateEvent(String state)` and `StatsEvent({bytesUp, bytesDown, activeFlows, flowsFailed, dnsQueries})`.
- `class HelperUnavailable implements Exception` — the helper is not reachable (socket missing, or the connection dropped).
- `class HelperForbidden implements Exception` — the socket exists but this user cannot open it.
- `class HelperError implements Exception { final ErrorKindDto kind; final String message; }` — the helper answered with a refusal.
- `HelperClient({Duration retryDelay = const Duration(seconds: 2)})` holding the `Socket`, a broadcast `StreamController<HelperEvent>`, a monotonic request id, and a `Map<int, Completer<void>>` correlating acks.

**Encoding and decoding go through Task 9's generated bindings.** Writing a request is `socket.write('${await encodeRequest(req: r)}\n')`; reading is `decodeMessage(line: line)`. There is no `jsonEncode`/`jsonDecode` in this file.

`connect` wraps `Socket.connect` and maps `SocketException` by errno: `ENOENT` (2) → `HelperUnavailable`, `EACCES`/`EPERM` (13/1) → `HelperForbidden`. Read `e.osError?.errorCode`; anything else is `HelperUnavailable`. These are different problems with different fixes — one means "run the installer", the other means "you are not the authorized user" — so collapsing them would tell the user to do the wrong thing.

The read pipeline is `cast<List<int>>()` → `utf8.decoder` → `LineSplitter` → `decodeMessage`, dispatching `Ack`/`Error` to the pending completer and `State`/`Stats` to the event stream. An `Error` reply completes its request with `HelperError(kind, message)` so callers branch on `kind`, never on `message`. A `decodeMessage` failure is logged and the line dropped — a helper newer than the app must not take the client down.

On `onDone`/`onError` the client: completes every pending request with `HelperUnavailable`, emits `StateEvent('Disconnected')`, then schedules a reconnect after `retryDelay`, re-sending `hello` on success and completing the `whenReconnected` future. Backoff is a fixed delay, not exponential — the helper is local, and a user who just ran the installer should not wait 30 seconds.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd app && flutter test test/helper_client_test.dart`
Expected: PASS — 8 tests.

- [ ] **Step 4a: A/B the errno split**

Temporarily map every `SocketException` to `HelperUnavailable`.

Run: `cd app && flutter test test/helper_client_test.dart`
Expected: FAIL — `a socket the user cannot open reports unauthorized, not missing` gets `HelperUnavailable`. Restore and confirm green. **Paste both outputs** — this test names a defect, so Global Constraints require it be shown catching one.

- [ ] **Step 5: Commit**

```bash
git add app/lib/services app/test
git commit -F - <<'EOF'
feat: Dart client for the helper socket

Unix socket plus newline-delimited JSON, both verified against a real
socket before this was written. Encoding and decoding go through the FFI
codec, so this file does framing and lifecycle and nothing else.

Acks are correlated by request id; state and stats arrive on a broadcast
stream. Errors surface as HelperError carrying the machine-readable kind,
so the UI branches on kind and never string-matches on message.

Connect failures split by errno: ENOENT means the helper is not installed,
EACCES means this user is not authorized. Different problems with
different fixes, so collapsing them would send the user after the wrong
one.

A dropped socket completes every in-flight request with HelperUnavailable
and emits Disconnected before retrying. Without that the UI sits on
"Connected" after the daemon dies and the connect button spins forever.

The partial-line test pins the framing: JSON split across reads must be
buffered until its newline, not parsed per chunk. Tests cancel their
listener subscriptions explicitly -- a live ServerSocket keeps the isolate
alive, so a leaked one hangs the suite instead of failing it.
EOF
```

---

### Task 11: Connection model and the two screens

**Files:**
- Create: `app/lib/services/connection_model.dart`, `app/lib/screens/profiles.dart`, `app/lib/screens/connection.dart`
- Modify: `app/lib/main.dart`, `app/pubspec.yaml`

**Interfaces:**
- Consumes: `HelperClient` (Task 10), `parse_profile` (Task 8), `ErrorKindDto` (Task 9).
- Produces: `ConnectionModel extends ChangeNotifier`.

- [ ] **Step 1: Add `provider`**

Add `provider: ^6.1.0` to `app/pubspec.yaml`, then `cd app && flutter pub get`.

- [ ] **Step 2: Write the failing model tests**

`app/test/connection_model_test.dart`:

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:liostunnel_app/services/connection_model.dart';
import 'package:liostunnel_app/services/helper_client.dart';

void main() {
  test('starts disconnected with zeroed stats', () {
    final m = ConnectionModel();
    expect(m.state, 'Disconnected');
    expect(m.bytesUp, 0);
  });

  test('a state event updates state and notifies listeners', () {
    final m = ConnectionModel();
    var notified = 0;
    m.addListener(() => notified++);
    m.applyEvent(StateEvent('Connected'));
    expect(m.state, 'Connected');
    expect(notified, 1);
  });

  test('a stats event updates counters', () {
    final m = ConnectionModel();
    m.applyEvent(StatsEvent(
      bytesUp: 5, bytesDown: 9, activeFlows: 2, flowsFailed: 1, dnsQueries: 4,
    ));
    expect(m.bytesUp, 5);
    expect(m.activeFlows, 2);
  });

  test('a helper refusal is surfaced by kind, not message text', () {
    final m = ConnectionModel();
    m.applyError(HelperError(ErrorKindDto.versionMismatch, 'helper speaks v1'));
    expect(m.lastFault, Fault.versionMismatch);
    // The UI decides its own wording from the kind; the helper's message is
    // diagnostic only, and never rendered.
    expect(m.userFacingError, isNot(contains('helper speaks v1')));
    expect(m.userFacingError, contains('out of date'));
  });

  test('an unreachable helper and a forbidden one read differently', () {
    // These are the two the user can actually fix, and the fixes are
    // opposites: install it, versus you are not the authorized user.
    final a = ConnectionModel()..applyError(HelperUnavailable());
    final b = ConnectionModel()..applyError(HelperForbidden());
    expect(a.userFacingError, contains('not installed'));
    expect(b.userFacingError, contains('not authorized'));
    expect(a.userFacingError, isNot(b.userFacingError));
  });

  test('a successful action clears the previous fault', () {
    final m = ConnectionModel()..applyError(HelperUnavailable());
    expect(m.lastFault, isNotNull);
    m.applyEvent(StateEvent('Connected'));
    expect(m.lastFault, isNull, 'a stale banner outlives the problem it named');
  });
}
```

- [ ] **Step 3: Run to verify failure, then implement**

Run: `cd app && flutter test test/connection_model_test.dart` — expect FAIL on the missing import.

`ConnectionModel` holds `state`, the five stat fields, a nullable `Fault lastFault`, and a `userFacingError` getter. `Fault` is the model's own enum covering both the helper's `ErrorKindDto` variants and the two client-side conditions the helper can never report, because the socket never opened:

| `Fault` | Raised by | Wording |
|---|---|---|
| `helperNotInstalled` | `HelperUnavailable` | "The helper is not installed or not running. Run `packaging/install-helper.sh`." |
| `notAuthorized` | `HelperForbidden` | "You are not authorized to use the helper. It was installed for a different user." |
| `versionMismatch` | `ErrorKindDto.versionMismatch` | "The helper is out of date. Reinstall it." |
| `unauthorized` | `ErrorKindDto.unauthorized` | "This user is not authorized to use the helper." |
| `secretNotPermitted` | `ErrorKindDto.secretNotPermitted` | "That profile points at a file you do not own." |
| `alreadyConnected` | `ErrorKindDto.alreadyConnected` | "A tunnel is already running." |
| `notConnected` | `ErrorKindDto.notConnected` | "No tunnel is running." |
| `authFailed` | `ErrorKindDto.authFailed` | "The server rejected the credentials." |
| `badRequest` | `ErrorKindDto.badRequest` | "The helper rejected the request. Reinstall and try again." |
| `internal` | `ErrorKindDto.internal` | "The helper hit an internal error. Check its log." |

`applyError` accepts any of the three exception types; the `ErrorKindDto` switch is exhaustive, so a new variant in Task 9 fails to compile here rather than falling through to a generic message. `applyEvent` and `applyError` mutate and call `notifyListeners()`; `applyEvent` also clears `lastFault`, because a banner that outlives its cause is worse than no banner.

- [ ] **Step 4: Build the two screens**

`profiles.dart`: a `ListView` of profiles loaded from `~/.liostunnel/*.json`, each parsed through `parse_profile` (Task 8) — **not** re-parsed in Dart, which is exit criterion P1a-1. Tapping one selects it.

`connection.dart`: the selected profile, a connect/disconnect button driven by `ConnectionModel.state`, live `bytesUp`/`bytesDown`/`activeFlows`, and an error banner fed by `userFacingError`.

`main.dart` wires `RustLib.init()`, a `ChangeNotifierProvider<ConnectionModel>`, and a two-tab scaffold.

- [ ] **Step 5: Widget tests**

`app/test/widget_test.dart`: pump the connection screen with a model in each of `Disconnected`, `Connected`, and faulted states; assert the button label changes, the error banner appears only when `lastFault` is set, and the banner shows `userFacingError` rather than any text originating from the helper.

- [ ] **Step 6: Run everything**

```bash
cd app && flutter test && flutter analyze
```
Expected: all tests pass; analyzer clean.

- [ ] **Step 7: Commit**

```bash
git add app
git commit -F - <<'EOF'
feat: connection model and the profiles/connection screens

A single ChangeNotifier holds state and stats; two screens do not justify
Riverpod or Bloc.

The model maps each fault to user-facing wording rather than displaying the
helper's message. The message is diagnostic; the kind is the contract. The
switch over ErrorKindDto is exhaustive, so adding a variant to the protocol
fails to compile here instead of falling through to a generic message.

Fault covers two conditions the helper can never report -- not installed,
and not authorized -- because in both cases the socket never opened.

Profiles are parsed through the FFI, not re-implemented in Dart. That is
exit criterion P1a-1, and re-implementing the schema in a second language
is how the two drift.
EOF
```

---

# Milestone D — Install and verification

---

### Task 12: Install scripts

**Files:**
- Create: `packaging/liostunnel-helper.plist`, `packaging/liostunnel-helper.service`, `packaging/install-helper.sh`, `packaging/uninstall-helper.sh`

- [ ] **Step 1: Write the launchd plist**

`packaging/liostunnel-helper.plist` — `RunAtLoad`, `KeepAlive`, and `ProgramArguments` of `[<path>, --socket, /var/run/liostunnel.sock, --uid, <UID>]`. `<UID>` is substituted by the installer, so the authorized uid is root-owned configuration an unprivileged process cannot alter (spec §7.1).

- [ ] **Step 2: Write the systemd unit**

`packaging/liostunnel-helper.service` — `Type=simple`, `ExecStart` with the same arguments, `Restart=on-failure`, `[Install] WantedBy=multi-user.target`.

- [ ] **Step 3: Write the installer**

`packaging/install-helper.sh` must: refuse to run without root; refuse if `SUDO_UID` is unset or zero, since installing with the authorized uid set to root would defeat the whole boundary; copy the release binary to `/usr/local/libexec/`; substitute the invoking user's uid into the unit; load it; and print the socket path.

- [ ] **Step 4: Verify the refusal paths without installing anything**

```bash
./packaging/install-helper.sh            # expect: refuses, not root
sudo SUDO_UID= ./packaging/install-helper.sh   # expect: refuses, no target uid
```

Paste both. **Do not run a successful install as part of this task** — that is Task 13's job, under supervision.

- [ ] **Step 5: Commit**

```bash
git add packaging
git commit -F - <<'EOF'
feat: install scripts for the privileged helper

launchd and systemd units with the authorized uid substituted at install
time, so it is root-owned configuration an unprivileged process cannot
alter.

The installer refuses to run without root, and refuses when SUDO_UID is
unset or zero: authorizing uid 0 would mean the helper accepts a root
client, which defeats the boundary it exists to enforce.

SMAppService registration is deliberately out of scope (spec 11) -- it is
entangled with code signing and distribution, which is a separate problem.
EOF
```

---

### Task 13: Exit criteria verification

**Files:**
- Create: `docs/superpowers/phase1a-verification.md`

This task runs the real thing. It needs root and the Docker SSH fixture, and it is the only task that does.

- [ ] **Step 1: Install the helper and confirm it is listening**

```bash
cargo build --release
sudo ./packaging/install-helper.sh
ls -l /var/run/liostunnel.sock     # expect srw------- root
```

- [ ] **Step 2: P1a-5 — an unauthorized uid is refused**

```bash
sudo -u nobody socat - UNIX-CONNECT:/var/run/liostunnel.sock
```
Expected: connection refused or immediately closed; the helper logs a refusal naming the uid. Record the log line.

- [ ] **Step 3: P1a-7 — a version mismatch fails cleanly**

```bash
printf '%s\n' '{"type":"hello","id":1,"protocol_version":99}' \
  | socat - UNIX-CONNECT:/var/run/liostunnel.sock
```
Expected: `{"type":"error","id":1,"kind":"version_mismatch",...}`.

- [ ] **Step 4: P1a-6 — a secret the caller does not own is refused**

Send a `connect` whose profile names `/etc/shadow` as its private key.
Expected: `kind: "secret_not_permitted"`, **no TUN device created, no route installed**. Confirm both with `ip -br addr` / `ifconfig` and `ip route` / `netstat -rn` before and after.

This is the escalation the design exists to prevent; record the full exchange.

- [ ] **Step 5: P1a-1, P1a-2, P1a-3 — the app end to end**

With the fixture up (`make -C testing/docker up`), launch the app, confirm the profiles list renders profiles parsed through the FFI, connect, and confirm traffic flows and stats increment while a download runs.

- [ ] **Step 6: P1a-4 — the tunnel outlives the UI**

Quit the app while connected. Confirm the tunnel still carries traffic (`curl` through it). Relaunch and confirm it re-syncs to `Connected` via `GetStatus` rather than showing `Disconnected`.

- [ ] **Step 7: Record results and uninstall**

Write `docs/superpowers/phase1a-verification.md` with each criterion, the exact command, and the verbatim output — including anything that failed. Then `sudo ./packaging/uninstall-helper.sh` and confirm the socket is gone.

- [ ] **Step 8: Commit**

```bash
git add docs/superpowers/phase1a-verification.md
git commit -F - <<'EOF'
docs: Phase 1a exit criteria verification

Records each of P1a-1 through P1a-7 with the exact command and verbatim
output.

P1a-6 is the one that matters most: a profile naming a file the calling
user does not own is refused, with no TUN device created and no route
installed. That is the privilege escalation this design exists to
prevent, verified against a running privileged helper rather than only in
unit tests.
EOF
```

---

## Phase 1a completion checklist

| Criterion | Verified by |
|---|---|
| P1a-1 — profiles parsed through FRB, not Dart | Tasks 8, 9 and Task 13, Step 5 |
| P1a-2 — connect brings up a real tunnel | Task 13, Step 5 |
| P1a-3 — stats update live | Task 13, Step 5 |
| P1a-4 — tunnel survives the UI | Task 13, Step 6 |
| P1a-5 — unauthorized uid refused | Task 2 (A/B) and Task 13, Step 2 |
| P1a-6 — foreign secret file refused | Task 3 (A/B) and Task 13, Step 4 |
| P1a-7 — version mismatch fails cleanly | Task 5 and Task 13, Step 3 |

Spec §10's four failure modes — helper not installed, version mismatch, socket permission denied, helper dying mid-session — are covered by Task 10 (the first, third and fourth, with the errno split A/B'd) and Task 5 plus Task 13 Step 3 (the second).

P1a-5 and P1a-6 are what make this a security boundary rather than a convenience layer. Both carry tests that must be **shown failing** against a naive implementation — Phase 0 shipped three tests that passed while their bug was still present, and that is the failure mode this discipline exists to catch.

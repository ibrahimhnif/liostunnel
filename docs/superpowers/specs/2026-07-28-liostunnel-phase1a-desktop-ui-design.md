# LiosTunnel Phase 1a — Desktop UI Design Spec

**Status:** Approved
**Date:** 2026-07-28
**Owner:** Hanif
**Parent documents:** [`PRD.md`](../../../PRD.md) §10 (Phase 1), [Phase 0 spec](2026-07-27-liostunnel-phase0-design.md)
**Scope:** The first slice of PRD Phase 1 — a Flutter desktop UI driving the existing engine through a privileged helper daemon.

---

## 1. Purpose

Phase 0 produced a working tunnel with no interface. This slice puts a UI on it
without compromising the engine that earned all seven of Phase 0's exit
criteria.

The engine already works and is verified. What does not exist is any way for a
non-technical user to reach it, and any answer to the question the CLI never had
to ask: **how does an unprivileged GUI perform privileged work?** That question,
not the UI itself, is what this slice exists to settle.

## 2. Scope decomposition — why this is a slice, not all of Phase 1

PRD §10 describes Phase 1 as "Flutter desktop UI wired via `flutter_rust_bridge`,
add WireGuard support, ship Windows + macOS + Linux." That is four independent
subsystems:

1. `flutter_rust_bridge` FFI layer and the Flutter desktop UI — **this slice**
2. WireGuard as a second `Protocol` implementation
3. Windows support — a third TUN backend (`wintun`), Windows routing, DNS, UAC
4. UI polish beyond the MVP

Each gets its own spec → plan → implement cycle, as Phase 0 did. Phase 0's
22-task plan was already at the edge of what one plan can hold.

**Windows is deferred to its own phase.** "Ship Windows + macOS + Linux" hides a
third platform seam comparable in size to WireGuard itself. Landing it
simultaneously with a new UI, a new FFI layer, and a new privileged daemon would
make every failure ambiguous.

**WireGuard is deferred and is the more interesting deferral.** Phase 0 has
exactly one `Protocol` implementation, so the trait is currently an SSH-shaped
hole rather than a proven abstraction. WireGuard is what tests it — and it is
shaped very differently (SSH multiplexes logical streams over one TCP
connection; WireGuard is UDP-native with its own handshake state machine, and
`Protocol::send_udp` is `Unsupported` everywhere today). That is worth knowing
before its own spec is written.

## 3. In scope

- `liostunnel-ffi`: a `cdylib` exposing profile operations and IPC message types
  to Dart via `flutter_rust_bridge` v2.
- `liostunnel-helper`: a privileged daemon owning the TUN device, routes, and
  engine, listening on a unix domain socket.
- A JSON line protocol between them, with peer-uid authorization.
- A Flutter desktop app: profiles list, connect/disconnect, live stats.
- macOS and Linux.

## 4. Out of scope

- Windows (own phase). WireGuard (own spec). Mobile (Phases 2–3).
- `SMAppService` registration and code signing — install is a script for now.
- Profile creation/editing in-app; profiles are imported as JSON.
- Live log streaming in the UI.
- Changes to `liostunnel-core` or `liostunnel-cli`, which stay untouched.

## 5. Decisions and rationale

| # | Decision | Rationale |
|---|---|---|
| D1 | Build the FFI + UI slice before WireGuard | Chosen for a visible deliverable early; WireGuard's abstraction test is deferred knowingly |
| D2 | Defer Windows | A third platform seam concurrent with a new UI, FFI layer, and daemon makes failures ambiguous |
| D3 | Split privilege: FRB for config, daemon for the tunnel | A GUI cannot sensibly run as root, and macOS offers no way to elevate an already-running GUI process. Spec §4 of Phase 0 claimed otherwise; it was wrong |
| D4 | Privileged helper daemon now, not CLI-spawn-with-elevation | Better steady state (authenticate once, not per connect), and the tunnel survives the UI. Retrofitting it later would mean rewriting the UI's whole connection layer |
| D5 | Unix socket + newline-delimited JSON, not gRPC or XPC/D-Bus | One implementation across both platforms, no second codegen toolchain atop FRB, and hand-inspectable with `socat` — which matters most for the privileged component |
| D6 | Protocol types defined in Rust, mirrored to Dart by FRB | Single source of truth; no hand-maintained Dart structs to drift |
| D7 | `liostunnel-ffi` defines its own DTOs; it does not export core types | Keeps FRB's type constraints out of the core, so core changes cannot silently break Dart codegen |
| D8 | No state-management framework in Flutter | Two screens do not justify Riverpod or Bloc |

### 5.1 Approaches considered and rejected

**gRPC/tonic over the socket.** Typed generated stubs, well-trodden. Rejected:
it stacks protobuf codegen on top of the FRB codegen already being introduced,
pulls a substantial dependency into a privileged binary, and adds a Dart gRPC
runtime — heavy for a protocol with seven messages.

**XPC (macOS) + D-Bus/polkit (Linux).** Best platform citizenship, and polkit
gives a real authorization framework rather than a hand-rolled uid check.
Rejected for this slice: two entirely separate implementations, thin Dart
bindings for both, and roughly double the privileged surface area — the part
least worth doubling. Its authorization story is genuinely stronger than ours;
revisit if the uid check proves insufficient.

**`flutter_rust_bridge` in-process with the whole app elevated.** What Phase 0's
spec §4 described. Rejected: requires the entire GUI to run as root, which macOS
makes awkward and which is a real security smell for a process rendering
untrusted content.

**UI spawns the CLI with `osascript`/`pkexec`.** Smallest possible surface, and
reuses the verified CLI verbatim. Rejected per D4 — a password prompt on every
connect, and the tunnel dies with the UI.

## 6. Architecture

```
┌──────────────────────────┐
│  Flutter app  (user uid) │  profiles UI, connect control, stats
│  links liostunnel-ffi ───┼── flutter_rust_bridge → config ops,
└───────────┬──────────────┘   protocol types (no engine, no privilege)
            │ unix socket, JSON lines
┌───────────▼──────────────┐
│ liostunnel-helper (root) │  owns TUN, routes, engine
│  links liostunnel-core   │  launchd (macOS) / systemd (Linux)
└──────────────────────────┘

liostunnel CLI — unchanged, still works standalone
```

```
crates/liostunnel-core/     unchanged
crates/liostunnel-cli/      unchanged
crates/liostunnel-ffi/      new — cdylib, FRB-annotated, DTOs + conversions
crates/liostunnel-helper/   new — privileged daemon
app/                        new — Flutter desktop
  lib/src/rust/               FRB-generated, committed
  lib/services/helper_client.dart
  lib/screens/profiles.dart
  lib/screens/connection.dart
```

The helper consumes `liostunnel-core` exactly as the CLI does. The engine that
passed Phase 0's exit criteria is shared, not forked.

## 7. The trust boundary

A root daemon taking instructions over a socket is an attack surface Phase 0
never had — the CLI ran as whoever invoked it. Two gates.

### 7.1 Gate one — who may connect

The socket lives at `/var/run/liostunnel.sock`, mode `0600`, **owned by the
authorized uid** — not by root. On `accept`, the helper reads the peer's uid
(`LOCAL_PEERCRED` on macOS, `SO_PEERCRED` on Linux) and refuses any uid other
than the authorized one.

The ownership detail is not cosmetic. Both platforms enforce the socket file's
permission bits on `connect()`, so a root-owned `0600` socket is unreachable by
the very GUI it exists to serve — the daemon would run correctly and the app
could never reach it. The helper is root at bind time and chowns the socket to
the uid it was configured to serve. Verified on macOS: connecting to a mode-`0000`
socket fails `EACCES` even for its owner.

The authorized uid is written by the install script into the launchd plist /
systemd unit as a command-line argument, so it is root-owned configuration the
helper reads at startup and an unprivileged process cannot alter it. A helper
started without one refuses every connection rather than defaulting to
permissive.

Filesystem permissions alone are insufficient: they are advisory against a
root-adjacent attacker and say nothing about *which* user connected.

The helper must unlink a stale socket before binding — a crash leaves the file
behind. It must not unlink a *live* one: a supervisor restarting the helper
under load can start a replacement before the old process exits, and an
unconditional unlink lets the newcomer steal the path while the original serves
on unaware. `connect()` alone cannot tell the two apart — a live listener whose
backlog is full also refuses connections — so liveness is decided by an
advisory lock on a sibling lockfile, which the kernel releases on process death
however abrupt.

### 7.2 Gate two — whose secrets the helper may read

**This is a privilege escalation if unhandled.** If the UI sends a
`ServerProfile` and the helper resolves its `SecretRef::File { path }` as root,
any local user can make root read any file: send a profile whose private key is
`/etc/shadow` and the contents land in an SSH authentication attempt,
recoverable from an error message or through the tunnel.

The vulnerability exists precisely because Phase 0's `FileSecretStore` was
designed for a CLI running as the invoking user, where "can this process read
this file" and "may this user read this file" were the same question. Under the
daemon they are not.

**Requirement:** the helper resolves secrets as the *calling uid*, never as
root. Before opening a secret file it verifies the file is owned by and readable
by that uid. Phase 0's `FileSecretStore` already enforces `0600`-or-stricter; it
must now additionally enforce *whose* `0600`.

This is exit criterion P1a-6 and carries a test that fails against a naive
implementation.

## 8. The IPC protocol

Newline-delimited JSON. Message types are defined once in Rust and mirrored to
Dart by `flutter_rust_bridge` (D6).

| Direction | Message | Purpose |
|---|---|---|
| → | `Hello { protocol_version }` | First message; version handshake |
| → | `Connect { profile, user, route_mode, tun_address }` | Bring the tunnel up |
| → | `Disconnect` | Tear it down |
| → | `GetStatus` | Current state, for re-sync |
| ← | `Ack { id }` / `Error { id, kind, message }` | Request outcome, correlated by id |
| ← | `State { ConnectionState }` | Pushed on every transition |
| ← | `Stats { bytes_up, bytes_down, active_flows, flows_failed, dns_queries }` | Pushed ~1s while connected |

**The version handshake is load-bearing.** The helper is installed once and is
privileged; the app updates independently. A v2 app talking to a v1 helper must
fail with `VersionMismatch`, not misinterpret a field. Cheap now, expensive to
retrofit.

**One tunnel at a time**, because there is one routing table. A second `Connect`
while connected is refused with a specific error rather than silently replacing
the first.

**`Error.kind` is a machine-readable enum**, not just a string, so the UI can
respond rather than dump text: `AuthFailed`, `HelperNotInstalled`,
`VersionMismatch`, `AlreadyConnected`, `Unauthorized`, `SecretNotPermitted`.

**No error message may carry secret material.** Phase 0's discipline crosses the
socket unchanged. That rule already caught a real leak, where a malformed-profile
error echoed a misplaced secret verbatim through `serde_json`'s `Display`.

**The wire types are the FFI DTOs, not core types.** `Connect.profile` is
`liostunnel-ffi`'s flat DTO — the same type Dart holds — and the helper converts
it to `liostunnel_core::ServerProfile` after authorization. So `liostunnel-helper`
depends on both `liostunnel-core` and `liostunnel-ffi`, taking the protocol
definitions from the latter. This keeps one definition of the wire format rather
than two that must agree (D6, D7).

### 8.1 Lifecycle properties

Two fall out of the daemon architecture, and they are why D4 was worth its cost:

- **The UI may crash or quit while the tunnel keeps running.** On relaunch it
  sends `GetStatus` and re-syncs. This is exit criterion P1a-4.
- **If the helper dies, Phase 0's crash recovery already handles it.** The state
  file written before routes are applied is replayed on next start
  (`route::state::recover_if_stale`). That machinery now has a second consumer,
  which is evidence the abstraction was right.

### 8.2 A Phase 0 gap this slice exposes

`StackCore` computes `udp_dropped`, `syn_dropped`, `malformed_dropped` and
`bytes_discarded`, but they have no callers outside its own tests, so
`ConnectionStats` reports them as permanently zero. Phase 0's final review
classified this Minor on the grounds that nothing read them. **A UI reads them.**

**Decision: the `Stats` message carries only fields that are actually
populated** — `bytes_up`, `bytes_down`, `active_flows`, `flows_failed`,
`dns_queries`. The unwired counters are omitted from the protocol entirely for
this slice, so there is nothing for the UI to render wrongly. Adding them later
is an additive protocol change requiring no version bump for older clients.

Wiring the counters through to `ConnectionStats` is worth doing — `udp_dropped`
in particular explains a real user-visible symptom, since all non-DNS UDP is
blackholed and that is why QUIC and HTTP/3 do not work through the tunnel — but
it is core work, not UI work, and belongs in its own change rather than riding
along here.

## 9. The FFI layer

`liostunnel-ffi` defines its own DTOs and converts to and from core types (D7).
`ServerProfile` contains `Uuid`, `IpAddr`, and nested tagged enums like
`SecretRef` — types `flutter_rust_bridge` handles with varying enthusiasm. If
the UI bound directly to core types, any change inside `liostunnel-core` could
break Dart codegen, and the core would start being shaped by what FRB finds
convenient.

The FFI crate therefore exposes flat, codegen-friendly structs (UUIDs and IP
addresses as `String`) with `From` conversions in both directions. The
conversions are pure and unit-tested.

It exposes profile parse/validate, portable import/export, and the IPC message
types. **Not the engine** — that lives behind the socket.

**Integration risk.** FRB v2 codegen against these DTOs is the least-known
surface in this slice. Every unfamiliar API in Phase 0 produced at least one
genuine error in the plan — `polling`'s `AsSource: AsFd` bound, `tokio-util`'s
nonexistent `sync` feature. Verify generated bindings compile against a trivial
DTO *before* writing the real ones.

## 10. The Flutter app

Dart speaks unix sockets natively (`InternetAddressType.unix`). The client is
`utf8.decoder` → `LineSplitter` → JSON → generated types, with a reconnect loop
and a broadcast stream of events.

**No state-management framework** (D8): a single `ChangeNotifier` holding
connection state and latest stats, exposed with `provider`.

Two screens: a profiles list, and a connection screen with connect/disconnect,
state, and live stats.

The UI must handle: helper not installed, version mismatch, socket permission
denied, and the helper dying mid-session.

## 11. Install and lifecycle

Deliberately unglamorous for this slice. macOS 13+ offers
`SMAppService.daemon()` to register a launchd daemon from inside a signed app
bundle — the right long-term answer, but entangled with code signing and
distribution, which is a separate problem this slice should not inherit.

For now: an install script dropping a launchd plist (macOS) or systemd unit
(Linux), authorized once. `SMAppService` and signing become their own slice.

## 12. Testing

Following Phase 0's shape: the boundaries are designed so most tests need no
privilege.

| Layer | Covers | Root? |
|---|---|---|
| DTO + protocol serde round-trips | FFI conversions, wire format | no |
| Authorization over a `socketpair` | peer-uid check, secret-path ownership | no |
| Headless helper on a test socket | full protocol, version mismatch, double-connect | no |
| Dart client against a fake server | framing, reconnect, event stream | no |
| Widget tests | both screens | no |
| Live connect on macOS + Linux | the real thing | **yes** |

Phase 0's standing discipline applies: **a test that passes must be shown
failing against the defect it names.** Three tests in Phase 0 passed while the
bug they were written for was still present — one masked by a retransmit timer,
one rescued by a different mechanism, one whose scenario made the assertion
unreachable. Each was caught by reverting the fix and confirming red.

## 13. Exit criteria

Phase 1a is complete when all seven hold, verified and recorded:

- **P1a-1** — the app lists profiles parsed through FRB, not re-implemented in Dart.
- **P1a-2** — connect through the helper brings up a real tunnel and traffic flows.
- **P1a-3** — stats update live in the UI while traffic moves.
- **P1a-4** — quitting and relaunching the UI re-syncs to a still-running tunnel.
- **P1a-5** — a connection from an unauthorized uid is refused.
- **P1a-6** — a profile naming a secret file the caller does not own is refused,
  demonstrated with a test that fails against a naive implementation.
- **P1a-7** — a version-mismatched client fails cleanly with `VersionMismatch`.

P1a-5 and P1a-6 are what make this a security boundary rather than a convenience
layer. They are this slice's equivalent of Phase 0's EC5 and EC6 — the results
that would invalidate the design if they failed.

## 14. Risks

| Risk | Mitigation |
|---|---|
| FRB v2 codegen fights the DTOs | Verify against a trivial DTO before writing real ones (§9) |
| Peer-uid authorization is weaker than polkit | Accepted for this slice; XPC/D-Bus revisit if insufficient (§5.1) |
| Install flow is manual and unsigned | Explicitly scoped out (§11); `SMAppService` + signing is its own slice |
| Helper is a new privileged binary | Kept minimal — it owns no logic of its own, only wiring the verified core to a socket |
| Stats gaps become user-visible | Named explicitly as a decision this slice must make (§8.2) |

## 15. Next step

Implementation plan via the writing-plans skill. This spec is the input to that
plan.

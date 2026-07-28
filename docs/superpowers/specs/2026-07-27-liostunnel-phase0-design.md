# LiosTunnel Phase 0 — Design Spec

**Status:** Approved
**Date:** 2026-07-27
**Owner:** Hanif
**Parent document:** [`PRD.md`](../../../PRD.md)
**Scope:** PRD Phase 0 (core validation) + the config/profile layer from PRD §5.2

---

## 1. Purpose

Prove the packet engine works before anything is built on top of it.

Phase 0 delivers a CLI-only Rust binary that routes real TCP traffic from a real TUN device
through a real SSH tunnel to a real server, on both macOS and Linux, with working DNS and no
DNS leaks. It ships no UI, no mobile hosts, and no WireGuard or Shadowsocks.

The reason to build this first is risk, not sequencing. If the smoltcp pipeline can't hit the
CPU and throughput targets in PRD §8, the architecture is wrong for mobile — and every hour
spent on Flutter, JNI, or Network Extension plumbing before that is known is an hour at risk.
Phase 0 exists to make that answer cheap and early.

## 2. In scope

- Cross-platform TUN device abstraction: macOS `utun` and Linux `/dev/net/tun`.
- Userspace TCP/IP handling via `smoltcp`, behind a swappable `NetStack` seam.
- SSH tunnel protocol via `russh`, implementing the `Protocol` trait from PRD §5.1.
- The full `ServerProfile` config schema from PRD §5.2, forward-compatible with all three
  protocols.
- DNS through the tunnel, two backends: DNS-over-TCP (default) and DNS-over-HTTPS.
- Route management in two modes: `test` (explicit CIDRs) and `default` (full system default
  route override) with crash-safe cleanup.
- Test suite in six layers, four of which need neither root nor a TUN device.

## 3. Out of scope

- Flutter UI, `flutter_rust_bridge`, C ABI, uniffi, iOS Network Extension, Android VpnService.
  All Phase 1+.
- WireGuard and Shadowsocks protocol implementations. `ProtocolKind` parses them;
  `Protocol::for_kind()` returns `TunnelError::Unsupported`.
- Enforcement of `kill_switch` and `split_tunnel`. Both are parsed and validated; neither is
  enforced. See §9.3 for the required startup warning.
- UDP forwarding for arbitrary destinations. Only DNS (UDP:53) is handled. Per PRD §11, SSH
  is TCP-only in V1.
- OS keychain integration. Phase 0 uses a file-backed `SecretStore` behind the trait that
  Phase 1 will swap.
- QR code encode/decode. Deferred to Phase 2 (mobile onboarding).

## 4. Decisions and rationale

Decisions taken during brainstorming, recorded here so they aren't relitigated.

| # | Decision | Rationale |
|---|---|---|
| D1 | Build Phase 0 **plus** the config layer, not Phase 0 alone | Locks the `.liostunnel.json` format before any profiles exist in the wild, so nothing needs migrating later |
| D2 | Target macOS `utun` **and** Linux TUN from the start | macOS is the dev machine (fast iteration); Linux is CI and the PRD's stated target. Forces the cross-platform seam early, which Phase 1 needs regardless |
| D3 | Handle DNS via **both** DNS-over-TCP and DoH | PRD §11 descopes UDP, but PRD §7 requires DNS leak protection — irreconcilable without this. DNS-over-TCP is the zero-dependency default; DoH is opt-in per profile |
| D4 | Keep the name **LiosTunnel** | Renaming a Rust workspace later means touching every `Cargo.toml`, directory, and `use` path, then bundle IDs. Cheapest to commit now |
| D5 | Implement the **full** PRD §5.2 schema, forward-compatible | Consequence of D1 |
| D6 | Both route modes, `test` first | `test` mode carries no risk of locking the dev machine out mid-debug; `default` mode is the real validation and is inherited by Phase 1 |
| D7 | **Own** the smoltcp integration, behind a narrow seam ("approach C") | Owning it means being able to debug it inside an iOS Network Extension in Phase 3, where there is no debugger and no stdout. The seam is cheap insurance if smoltcp becomes a tarpit, and is the same boundary WireGuard and Shadowsocks plug into later — so it is a required boundary, not speculative abstraction |

### 4.1 Approaches considered and rejected

**Build on `ipstack` 1.0.1 or `netstack-smoltcp` 0.2.4.** Both yield async `TcpStream`-like
handles directly from a TUN fd, reducing the accept loop to roughly thirty lines. Rejected
because it degrades Phase 0's goal from "prove our packet engine works" to "prove someone
else's does," and puts unfamiliar code on the critical path at exactly the point — mobile,
under memory pressure — where debugging is hardest. `ipstack` is additionally not
smoltcp-based, which contradicts PRD §3.

`netstack-smoltcp` remains the closest prior art and should be read for reference during
implementation, and remains the documented fallback behind the `NetStack` seam.

**Hand-rolled TCP state machine, no smoltcp.** Rejected: writing TCP is not the point of this
project, and PRD §3 already selected smoltcp.

## 5. Dependency status

Verified against the crates.io sparse index on 2026-07-27.

| Purpose | Crate | Version | Note |
|---|---|---|---|
| Userspace TCP/IP | `smoltcp` | 0.13.1 | |
| SSH | `russh` | 0.62.4 | Resolves PRD §12's open question: `russh` is maintained, `thrussh` is dead |
| TUN device | `tun-rs` | 2.8.8 | Preferred over `tun` 0.8.14 — more active, better macOS/Windows parity, which D2 needs |
| Event loop | `polling` | 3.11.0 | Cross-platform fd wait plus `notify()` wakeup. `mio` 1.2.2 is an equivalent alternative if tokio-ecosystem consistency outweighs binary weight |
| Async runtime | `tokio` | 1.53.x | |
| CIDR types | `ipnet` | 2.12.0 | `RouteMode::Test { cidrs }` |
| DoH transport | `hyper` + `tokio-rustls` | 1.11 / 0.26 | Must ride a `TunnelStream`, not a `TcpStream` — rules out `reqwest` |
| DNS wire format | `hickory-proto` | 0.26.1 | Not needed to *relay* a query — the payload is opaque bytes both ways. Used to extract query id and qname for logs and stats, and for T3's reply-shape assertions. Feature-gate if it proves heavy |
| Serialization | `serde`, `serde_json` | | |
| Logging | `tracing` | | |

Deferred to later phases: `boringtun`, `shadowsocks`, `flutter_rust_bridge`, `uniffi`,
`cbindgen`.

## 6. Workspace layout

```
liostunnel/
├── Cargo.toml                       # workspace
├── crates/
│   ├── liostunnel-core/             # library — PRD §5
│   └── liostunnel-cli/              # Phase 0 binary
├── testing/
│   ├── docker/                      # sshd fixture + compose
│   └── fixtures/                    # pcap captures
└── docs/superpowers/specs/
```

A workspace from the first commit because Phase 1 adds a `cdylib` for `flutter_rust_bridge`,
Phase 2 adds uniffi bindings, and Phase 3 adds a `staticlib` for iOS — separate crate targets
over one shared core. Starting flat means restructuring later for no gain.

### 6.1 `liostunnel-core` modules

```
src/
├── lib.rs
├── error.rs                  # TunnelError
├── config/
│   ├── profile.rs            # ServerProfile, ProtocolKind, AuthMethod, SplitTunnelRule, DnsConfig
│   └── secret.rs             # SecretRef, SecretStore, Redacted<T>
├── protocols/
│   ├── mod.rs                # Protocol + TunnelStream traits
│   └── ssh.rs                # russh implementation
├── net/
│   ├── mod.rs                # NetStack trait — the D7 seam
│   ├── tun.rs                # TunDevice: utun AF-prefix vs Linux bare IP
│   ├── smoltcp_stack/
│   │   ├── device.rs         # smoltcp::phy::Device over queued buffers
│   │   ├── poll.rs           # the poll loop and its wakeup
│   │   └── listener_pool.rs  # any-IP accept machinery
│   └── nat_table.rs          # endpoint→listener registry, in-flight DNS query state
├── dns/
│   ├── mod.rs                # Resolver trait
│   ├── over_tcp.rs
│   └── over_https.rs
├── route/
│   ├── mod.rs                # RouteManager trait, RouteMode, RouteGuard
│   ├── macos.rs
│   └── linux.rs
├── engine.rs                 # wires NetStack + Protocol + Resolver + RouteManager
└── stats.rs                  # ConnectionStats, ConnectionState
```

### 6.2 Deviations from PRD §5's layout

| Change | Reason |
|---|---|
| `net/stack.rs` → `net/smoltcp_stack/` + `NetStack` trait in `net/mod.rs` | D7. The poll loop, the phy device, and the listener pool are three distinct responsibilities and should not share a file |
| `dns/` added | PRD assumed DNS was descoped (§11); D3 reverses that |
| `route/` added | PRD §6.1 describes route override but never homes it in the module tree |
| `error.rs` added | PRD §5.1 references `TunnelError` without giving it a home |
| `config/secret.rs` added | Resolves the §7 contradiction, below |
| `ffi/` omitted | Phase 1+ |
| `protocols/{wireguard,shadowsocks}.rs` omitted | Phase 1 / Phase 2 |

### 6.3 Resolving the PRD's secrets contradiction

PRD §5.2 embeds `"private_key": "..."` inline in the profile JSON. PRD §7 requires secrets to
live in the OS keychain and never in plaintext files. Both cannot hold. Phase 0 splits the
representation:

- **`ServerProfile`** — in-memory and at-rest. Key material is a `SecretRef`, an opaque handle
  resolved through a `SecretStore`.
- **`PortableProfile`** — the shareable `.liostunnel.json` and future QR payload. Secrets
  inline. Produced *only* by an explicit `export --include-secrets`, which prints a warning.

Phase 0's `SecretStore` is file-backed with enforced `0600` permissions (startup rejects
looser modes). Phase 1 swaps in the OS keychain behind the same trait with no call-site
changes.

## 7. The packet engine

### 7.1 The `NetStack` seam

```rust
pub trait NetStack: Send + 'static {
    fn start(self, tun: TunDevice, cfg: StackConfig) -> Result<StackHandles, TunnelError>;
}

pub struct StackHandles {
    pub tcp_accept:   mpsc::Receiver<TcpFlow>,
    pub udp_inbound:  mpsc::Receiver<Datagram>,
    pub udp_outbound: mpsc::Sender<Datagram>,
    pub shutdown:     ShutdownHandle,
}

pub struct TcpFlow {
    pub src: SocketAddr,
    pub dst: SocketAddr,     // the real destination, not the TUN's own address
    pub stream: LocalStream, // AsyncRead + AsyncWrite, speaks to the app on the device
}
```

The engine never learns which implementation it received. Swapping in `netstack-smoltcp`
means writing one more impl of this trait.

### 7.2 Thread model

One dedicated OS thread owns the `Interface`, the `SocketSet`, and the TUN file descriptor,
and is entirely synchronous. Tokio owns everything else: the russh session, DNS resolution,
and the per-flow copy loops.

Bytes cross the boundary on **bounded** `mpsc` channels, which yields correct end-to-end
backpressure with no custom flow control: when a channel fills, the stack thread stops
draining smoltcp's receive buffer, smoltcp shrinks the advertised TCP window, and the
application on the device slows down.

### 7.3 The poll loop

```
loop {
    1. drain TUN fd → rx queue, inspecting each packet on the way past
    2. iface.poll(now, &mut device, &mut sockets)
    3. flush tx queue → TUN fd
    4. move bytes: smoltcp sockets ↔ async channels; reap closed sockets, re-arm listeners
    5. poller.wait(&mut events, iface.poll_delay(now, &sockets))
}
```

Step 5 is load-bearing. It waits simultaneously on the TUN fd becoming readable, a wakeup
handle signalled by the async side, and smoltcp's own next timer deadline. The `polling`
crate's `Poller::notify()` provides the cross-platform wakeup (eventfd on Linux, pipe on
macOS). Idle-connected therefore means genuinely sleeping, not spinning — which is what
PRD §6.3's battery constraint and PRD §8's battery target require, and what exit
criterion EC5 (§12) measures.

### 7.4 Accepting connections to arbitrary destinations

smoltcp can only accept on a socket already listening at a specific endpoint, and listening
on port 0 is rejected — so "accept connections to anywhere" is not directly expressible.

**Chosen: SYN-triggered listener injection.** Step 1 parses each packet as it is drained from
the TUN fd. On a SYN addressed to an endpoint not currently listened on, a `TcpSocket`
listening on exactly that `(dst_ip, dst_port)` is injected into the `SocketSet` *before* step 2
processes the packet. `iface.set_any_ip(true)` allows the interface to accept packets not
addressed to its own address. When a listener transitions to Established it is handed off as a
`TcpFlow` and a fresh listener for that endpoint is re-armed.

Packets stay byte-identical: no header rewriting, no checksum recomputation.

This is only possible because of the queue-backed device in step 1 — the `SocketSet` cannot be
mutated from inside `Device::receive()` during a poll, so packets must be inspected before the
poll rather than during it.

**Documented fallback: destination-rewriting NAT.** Rewrite the destination to the TUN's own
address and a fixed port, record the original in `nat_table`, rewrite back on egress. This is
what Go's tun2socks does. To be adopted only if listener injection proves unworkable.

Under the chosen design `nat_table.rs` therefore does **not** hold address translations. It
holds the registry of endpoints currently listened on (so step 1 can tell a SYN to a known
endpoint from one needing injection) and the in-flight DNS query state keyed by
`(src_addr, query_id)`. It only becomes a rewrite table if the fallback is adopted.

### 7.5 TCP and UDP take different paths

TCP goes through smoltcp's stack proper. UDP does not.

Phase 0's only UDP requirement is DNS; SSH cannot forward UDP regardless; and
`smoltcp::wire` is usable standalone as a pure parser. So step 1 detects UDP:53, hands the
payload to the `Resolver`, and synthesizes the reply packet directly — no `UdpSocket`, no
socket lifecycle, materially less code.

Non-DNS UDP is dropped **and counted** in `stats`. Silently dropped packets are miserable to
debug.

When WireGuard requires real UDP forwarding in Phase 1, `Protocol::send_udp` and the datagram
channels already exist; only the stack-side handling needs revisiting.

### 7.6 End-to-end data flow

```
app → TUN → stack thread → smoltcp accept → TcpFlow{src, dst, LocalStream}
    → engine → Protocol::open_tcp_stream(dst) → russh direct-tcpip channel
    → copy_bidirectional → back out the TUN

DNS → TUN → UDP:53 intercepted → Resolver
    ├─ over_tcp:   open_tcp_stream(resolver) + RFC 7766 two-byte length prefix
    └─ over_https: hyper + tokio-rustls over a TunnelStream
    → synthesize UDP/IP reply → TUN
```

## 8. SSH protocol

Implements PRD §5.1's `Protocol` trait via `russh` 0.62.

- `connect()` — TCP to `host:port`, SSH transport, host key verification, authentication.
- `open_tcp_stream(dst)` — `channel_open_direct_tcpip(dst.ip(), dst.port(), originator_ip,
  originator_port)`, wrapped as a `TunnelStream` (`AsyncRead + AsyncWrite`).
- `send_udp()` — returns `TunnelError::Unsupported`. Per PRD §11.
- `disconnect()` — closes channels, then the session.
- `stats()` — bytes up/down, active channel count, session state.

**Host key verification is enforced by default** (PRD §7). Known hosts are stored in
OpenSSH format at `~/.liostunnel/known_hosts`. First connection to an unknown host prompts
trust-on-first-use. A `--insecure-accept-any-hostkey` flag exists for self-signed lab setups
and prints a prominent warning on every use.

Concurrent channels are bounded by a semaphore. SSH keepalives detect a dead session directly
rather than inferring it from a stalled flow.

## 9. Configuration

### 9.1 Schema

PRD §5.2 stands, with one widened field.

```rust
pub struct ServerProfile {
    pub id: Uuid,
    pub name: String,
    pub protocol: ProtocolKind,        // Ssh | WireGuard | Shadowsocks
    pub host: String,
    pub port: u16,
    pub auth: AuthMethod,
    pub dns: DnsConfig,                // widened — see below
    pub split_tunnel: SplitTunnelRule,
    pub kill_switch: bool,
}

pub struct DnsConfig {
    pub mode: DnsMode,                 // Tcp | Https
    pub servers: Vec<IpAddr>,          // always IP literals
    pub https: Option<DohConfig>,      // { sni: String, path: String }
}
```

`dns: Vec<IpAddr>` cannot express DoH, so it becomes `DnsConfig`. A custom deserializer still
accepts PRD §5.2's bare `["1.1.1.1", "1.0.0.1"]` array and defaults it to `Tcp` mode — the
PRD's own JSON example remains valid and is used verbatim as a test fixture.

`servers` holds IP literals only. This is what sidesteps the DoH bootstrap problem: resolving
`cloudflare-dns.com` would itself require DNS, so the DoH backend connects to an IP and
supplies `https.sni` for TLS verification and `Host:`.

`AuthMethod` carries `SecretRef`s rather than inline strings (§6.3). `peer_public_key` remains
a plain `String` — it is public by definition.

### 9.2 Validation

Enforced at parse time, returning `TunnelError::Config` with the offending field path:
non-empty `host`; `port != 0`; non-empty `dns.servers`; `https` present and populated when
`mode == Https`; `SecretRef`s resolvable in the `SecretStore`; secret files at mode `0600` or
stricter.

### 9.3 Unimplemented fields

`ProtocolKind::WireGuard` and `::Shadowsocks` parse and validate, then fail at
`Protocol::for_kind()` with `TunnelError::Unsupported`.

`kill_switch` and `split_tunnel` parse and validate but are **not enforced** in Phase 0. When
`kill_switch: true`, the CLI emits a prominent startup warning stating that the flag is not
honoured in this build. Silently accepting a security flag without honouring it is worse than
rejecting it.

## 10. Route management

One `RouteManager` trait with macOS and Linux implementations.

```rust
pub enum RouteMode {
    Test { cidrs: Vec<IpNet> },   // route only these through the TUN
    Default,                      // full system default route override
}
```

**`test` mode** installs routes for the listed CIDRs only. It cannot lock the developer out of
the machine mid-debug, which is why D6 builds it first.

DNS interception is a property of the TUN, not of the route mode: any UDP:53 packet that
reaches the TUN is intercepted (§7.5). In `test` mode that only happens if the resolver's
address is itself routed, so `test` mode additionally accepts `--capture-dns`, which installs
host routes for each address in `dns.servers`. Without that flag, `test` mode leaves system
DNS untouched — which is the desired default when routing a single CIDR for a focused
experiment. `default` mode always captures DNS.

**`default` mode** installs `0.0.0.0/1` and `128.0.0.0/1` rather than replacing the real
default route — both are more specific than `0.0.0.0/0`, so they win without deleting
anything, and removing them restores the original state exactly.

It also **pins a host route to the SSH server via the original gateway**. Without this the
tunnel's own transport routes through itself and the connection deadlocks on establishment.
This is the single most common failure mode in this class of tool and is called out here so it
is handled by construction rather than discovered.

DNS is overridden via `networksetup -setdnsservers` on macOS and `/etc/resolv.conf` or
systemd-resolved on Linux.

**Cleanup runs three ways**, because PRD §8 requires surviving a crash:

1. An RAII `RouteGuard` — covers normal exit and unwinding panics.
2. A SIGINT/SIGTERM handler.
3. A state file written *before* routes are applied. A `kill -9` leaves it behind; the next
   startup detects it and cleans up the recorded routes before doing anything else.

## 11. Errors, logging, statistics

```rust
pub enum TunnelError {
    Config, Auth, HostKey, Transport, Protocol, Unsupported, Dns, Route, Tun,
}
```

**Per-flow failures stay per-flow.** A failed `open_tcp_stream` sends RST to the local socket,
logs at debug, increments a counter, and never touches the engine. Session loss transitions
`ConnectionState` to `Reconnecting` and reconnects with exponential backoff; in-flight flows
are reset.

**No payload logging, ever** (PRD §7). Logging is via `tracing`, metadata only. Secrets are
wrapped in `Redacted<T>`, whose `Debug` and `Display` print `<redacted>` — so §7 holds even in
a panic backtrace.

`stats.rs` tracks bytes up/down, active flows, dropped non-DNS UDP datagrams, DNS queries by
backend, connection state, and reconnect count.

## 12. Testing

Test-driven throughout: tests precede implementation for each unit.

| # | Layer | Covers | Root/TUN? |
|---|---|---|---|
| T1 | Config unit | serde round-trips, PRD §5.2's JSON verbatim as a fixture, validation rejections, `Redacted` output | no |
| T2 | Packet engine unit | synthetic packet sequences + pcap fixtures: SYN → listener injection → `TcpFlow` with correct `dst`; bidirectional data; FIN teardown; RST on upstream failure | no |
| T3 | DNS unit | RFC 7766 framing, DoH request shape, reply synthesis with correct IP/UDP checksums | no |
| T4 | Integration | real `sshd` + target HTTP server in Docker; `TcpFlow`s injected directly into the engine | no |
| T5 | E2E | real macOS `utun` and Linux `/dev/net/tun` (`--cap-add=NET_ADMIN --device /dev/net/tun`) | **yes** |
| T6 | Leak test | zero UDP:53 observed on the physical interface while connected | **yes** |

The layering is the point. Because `TunDevice` is queue-backed, the hardest code in the
project — the poll loop — is fully testable without a TUN device or elevated privileges.
T1–T4 run anywhere, on every commit. Only T5 and T6 need privilege; they are gated behind a
feature flag and run in the Linux CI job and locally on macOS.

T6 is a release gate, not manual QA, per PRD §9.

## 13. Exit criteria

Phase 0 is complete when all seven hold, verified and recorded:

- **EC1** — `liostunnel connect --profile home.json --route-mode test --cidr <net>` followed by
  `curl http://<ip>` succeeds through the SSH tunnel.
- **EC2** — the same request by hostname succeeds on both `dns.mode = tcp` and
  `dns.mode = https`, in `test --capture-dns` mode and in `default` mode.
- **EC3** — `--route-mode default` carries all system traffic; `curl ifconfig.me` returns the
  VPS's address; routes are restored after Ctrl-C, after `kill -9` (via the state file on next
  start), and after a panic.
- **EC4** — the DNS leak test (T6) passes.
- **EC5** — idle-connected CPU is approximately 0% over five minutes. This is the falsifiable
  proof that the poll loop does not busy-wait.
- **EC6** — throughput is within 20% of raw `ssh -D` SOCKS for a large download, meeting
  PRD §8's SSH target.
- **EC7** — the same code path passes T5 on both macOS `utun` and Linux TUN.

EC5 and EC6 are what make Phase 0 a validation rather than a demonstration. They are the two
results that, if negative, invalidate the architecture for mobile — which is the entire reason
this phase exists.

## 14. Risks

| Risk | Mitigation |
|---|---|
| SYN-triggered listener injection proves unworkable in smoltcp | Destination-rewriting NAT is specified as the fallback (§7.4); `nat_table.rs` exists either way |
| The smoltcp poll loop becomes a tarpit | The `NetStack` seam (D7) makes swapping in `netstack-smoltcp` a contained change |
| EC6 throughput missed because of the sync/async boundary | Bounded channels and buffer sizes are the tuning surface; measure before optimising. If SSH itself is the ceiling rather than the bridge, that is a PRD §8 assumption to revise, not an architecture failure |
| macOS `utun` and Linux TUN diverge more than expected | D2 forces both from the first commit rather than discovering the gap in Phase 1 |
| DoH pulls significant TLS/HTTP weight into the core | Feature-gated so DNS-over-TCP builds stay lean; matters for the PRD §8 mobile binary size target |

**Correction — the Apple entitlement is not a schedule risk.** An earlier version of
this section, following PRD §11, said the `com.apple.developer.networking.networkextension`
entitlement had to be requested from Apple with unpredictable lead time, and called it the
single largest schedule risk in the programme. That is false.

The packet-tunnel-provider entitlement is **self-serve**. Apple DTS engineer Quinn
"The Eskimo!" states it plainly on the developer forums: *"There is no approval process for
creating an NE packet tunnel provider. Any paid developer can do that"* — footnoted with
*"Other than approval to join the Apple Developer Program itself"* and *"That wasn't always
the case."* It was approval-gated historically and became self-serve around 2016. In Xcode
it is: Signing & Capabilities → Network Extension → tick Packet Tunnel, on both the app and
the extension target.

The stale belief is easy to acquire — Apple's old `/contact/request/network-extension/` URL
now redirects to the **hotspot-helper** request form, a different entitlement that does still
require approval.

The genuine Phase 3 risk is not obtaining the entitlement but the rules governing its use:
[TN3120 — Expected use cases for packet tunnel providers](https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers)
(*"Do not try to use a packet tunnel provider for something other than VPN"*),
[TN3134 — Network Extension provider deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment),
and App Store Review Guideline §5.4 on VPN apps. PRD §11 flags the App Store review stance
separately, and that part stands. Read both technotes before committing to Phase 3's design.

Source: [Apple Developer Forums thread 819032](https://developer.apple.com/forums/thread/819032).

## 15. Next step

Implementation plan via the writing-plans skill. This spec is the input to that plan.

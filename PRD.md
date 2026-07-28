# PRD & Technical Specification: LiosTunnel
### Cross-Platform Tunnel Client (Rust Core + Flutter UI)

**Status:** Draft v1.0
**Owner:** Hanif
**Last updated:** 2026-07-23

> Naming note: "LiosTunnel" is a placeholder project name used throughout this doc. Swap it out with `find/replace` once you've picked a real name.

---

## 1. Overview

LiosTunnel is a cross-platform tunnel client — desktop (Windows/macOS/Linux), Android, and iOS — that lets a user route traffic through a remote server using standard, open tunneling protocols (SSH, WireGuard, Shadowsocks). It is architected as **one shared Rust core** (protocol logic, packet processing) driving **one shared Flutter UI**, with thin, platform-specific glue code where the OS mandates it (iOS Network Extension, Android VpnService).

### 1.1 Problem statement
Existing apps in this space (HTTP Injector, KPN Tunnel, NapsternetV) are closed-source, Android-first, often bundle payload-injection tricks aimed at bypassing carrier billing (not something we're building), and have inconsistent UX across platforms. There's no single, maintainable, open-protocol client that behaves identically on desktop and mobile.

### 1.2 Goals
- One core engine, one behavior, across 4 platforms.
- Support SSH tunnel, WireGuard, and Shadowsocks as first-class protocols (in that build order).
- Config-file based server profiles (import/export/share, QR code for mobile).
- Kill switch + DNS leak protection by default.
- Acceptable battery/CPU overhead on mobile (comparable to commercial VPN apps).

### 1.3 Non-goals (explicitly out of scope)
- No carrier-billing bypass, SNI-spoofing-to-defraud-zero-rating, or "free internet" payload tricks. Protocol support here is for legitimate encrypted tunneling only.
- No traffic analysis/inspection features (this is a client, not a firewall/DPI product).
- No custom crypto — we use vetted implementations only (`boringtun`, `russh`, `shadowsocks-rust`).
- V1 does not support multi-hop chaining or obfuscation plugins (V2 candidate).

### 1.4 Target users
- Privacy-conscious users wanting a personal always-on tunnel to a VPS they control.
- Users in restrictive network environments needing SSH/Shadowsocks-based circumvention.
- Power users who currently juggle separate WireGuard app + separate SSH tunnel app + separate Shadowsocks app, and want one client with saved profiles for all three.

---

## 2. Prior art / reference implementations

Worth studying before writing code — don't reinvent what's already solved well:

- **leaf** (eycorsican/leaf) — Rust, cross-platform proxy/tunnel engine, supports iOS/Android/desktop. Closest architectural sibling to what we're building; good reference for how to structure the packet-processing pipeline in Rust.
- **sing-box** — Go-based, but the de-facto reference for "one core, many protocols, many platforms" done well. Useful for feature/UX parity checks even though the language differs.
- **boringtun** (Cloudflare) — userspace WireGuard implementation in Rust. We consume this directly rather than reimplementing the protocol.
- **shadowsocks-rust** — reference Rust implementation of Shadowsocks; consumable as a library for the client side.

We are not forking these — we're building our own core so the Flutter integration and UX are ours — but the packet-pipeline design below borrows heavily from leaf's approach.

---

## 3. Core technical challenge (read this before the architecture section)

The hard part of this project isn't UI — it's this: **on mobile, you don't get raw socket access to route traffic.** iOS and Android both hand you a `TUN` file descriptor (a virtual network interface) that spits out raw IP packets. Your job is to:

1. Read raw IP packets off the TUN fd.
2. Parse them into TCP/UDP streams (you need a mini userspace TCP/IP stack for this — you can't just pass raw IP to a socket API).
3. Re-open each logical stream against your outbound tunnel (SSH channel / WireGuard peer / Shadowsocks server).
4. Write response packets back into the TUN fd, correctly reconstructed as IP packets.

This is what `smoltcp` (a Rust embedded-style TCP/IP stack) is for. Desktop is comparatively easier because you can often use SOCKS5 system proxy settings instead of a full TUN interface, but for a consistent kill-switch experience we'll use TUN on desktop too.

---

## 4. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Flutter UI                           │
│   (Dart) — profiles, connect/disconnect, stats, settings     │
└───────────────────────────┬───────────────────────────────────┘
                             │ flutter_rust_bridge (Dart <-> Rust FFI)
┌───────────────────────────▼───────────────────────────────────┐
│                    LiosTunnel-core (Rust crate)                   │
│  ┌───────────┐ ┌──────────────┐ ┌───────────────┐             │
│  │ config     │ │ protocols     │ │ packet engine │             │
│  │ (serde)    │ │ - ssh (russh) │ │ (smoltcp +    │             │
│  │            │ │ - wg (boring- │ │  tun2socks-   │             │
│  │            │ │   tun)        │ │  style loop)  │             │
│  │            │ │ - ss (shadow- │ │               │             │
│  │            │ │   socks-rust) │ │               │             │
│  └───────────┘ └──────────────┘ └───────────────┘             │
└──────────────────────────┬──────────────────────────────────────┘
                            │ C ABI (cbindgen headers) — used ONLY
                            │ by the two mobile OS-mandated hosts below
              ┌─────────────┴──────────────┐
              ▼                             ▼
┌──────────────────────────┐   ┌──────────────────────────────┐
│ iOS: NEPacketTunnelProvider│   │ Android: VpnService (Kotlin) │
│ (Swift, separate App      │   │ + JNI bridge to LiosTunnel-core  │
│ Extension target)         │   │ (foreground service)         │
└──────────────────────────┘   └──────────────────────────────┘
```

**Key architectural decision:** the Rust core is consumed *two different ways* depending on platform:
- **Desktop:** Flutter app calls into `LiosTunnel-core` directly via `flutter_rust_bridge`. No separate process needed — the Rust code opens the TUN device itself (with an OS elevation prompt).
- **Mobile:** The OS *forces* a separate privileged component to own the TUN fd (Network Extension on iOS, VpnService on Android). These are thin Swift/Kotlin shims that link `LiosTunnel-core` as a static/shared library via plain C FFI (not `flutter_rust_bridge`, which is Dart-specific) and hand packets to it. The Flutter app itself never touches the TUN fd on mobile — it just starts/stops the extension and reads status via a shared app-group container (iOS) or a bound service (Android).

This split is unavoidable — it's an OS sandboxing restriction, not a design choice.

---

## 5. Core Rust crate structure

```
LiosTunnel-core/
├── Cargo.toml
├── src/
│   ├── lib.rs                  # public API surface, re-exports
│   ├── config/
│   │   ├── mod.rs
│   │   └── profile.rs          # ServerProfile struct, serde (de)serialization
│   ├── protocols/
│   │   ├── mod.rs              # Protocol trait
│   │   ├── ssh_tunnel.rs       # wraps russh, exposes SOCKS5-like connect()
│   │   ├── wireguard.rs        # wraps boringtun
│   │   └── shadowsocks.rs      # wraps shadowsocks-rust
│   ├── net/
│   │   ├── tun_device.rs       # cross-platform TUN fd wrapper
│   │   ├── stack.rs            # smoltcp Interface setup, packet pump
│   │   └── nat_table.rs        # tracks active TCP/UDP sessions -> tunnel streams
│   ├── engine.rs               # ties tun_device + stack + protocol together
│   ├── stats.rs                # bytes up/down, latency, connection state enum
│   └── ffi/
│       ├── dart_bridge.rs      # flutter_rust_bridge annotated functions
│       └── capi.rs             # #[no_mangle] extern "C" fns for iOS/Android hosts
```

### 5.1 `Protocol` trait (the core abstraction)

```rust
#[async_trait]
pub trait Protocol: Send + Sync {
    /// Establish the outbound tunnel connection (SSH session, WG handshake, SS handshake).
    async fn connect(&mut self, profile: &ServerProfile) -> Result<(), TunnelError>;

    /// Open a logical TCP stream through the tunnel to `dest`.
    async fn open_tcp_stream(&self, dest: SocketAddr) -> Result<Box<dyn TunnelStream>, TunnelError>;

    /// Send/receive a UDP datagram through the tunnel (WG and SS support this natively;
    /// SSH tunnel emulates it via netcat-style forwarding or is simply unsupported in V1).
    async fn send_udp(&self, dest: SocketAddr, data: &[u8]) -> Result<(), TunnelError>;

    async fn disconnect(&mut self) -> Result<(), TunnelError>;

    fn stats(&self) -> ConnectionStats;
}
```

Each protocol module implements this trait. The packet engine (`net/stack.rs`) doesn't know or care which protocol is active — it just calls `Protocol::open_tcp_stream()` whenever `smoltcp` reports a new TCP SYN it needs to proxy.

### 5.2 Config schema (`ServerProfile`)

```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerProfile {
    pub id: Uuid,
    pub name: String,
    pub protocol: ProtocolKind,       // Ssh | WireGuard | Shadowsocks
    pub host: String,
    pub port: u16,
    pub auth: AuthMethod,             // Password | PrivateKey | PresharedKey
    pub dns: Vec<IpAddr>,             // custom DNS to push once connected
    pub split_tunnel: SplitTunnelRule,// AllTraffic | ExcludeApps(Vec<String>) | IncludeOnly(Vec<String>)
    pub kill_switch: bool,
}
```

JSON example (this is also the shareable/importable file format, `.LiosTunnel.json`):

```json
{
  "id": "b6f1...e2",
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

For mobile onboarding, this JSON is also encodable as a QR code — scan-to-import, same pattern users already expect from WireGuard's official app.

---

## 6. Platform integration details

### 6.1 Desktop (Windows / macOS / Linux)
- Flutter desktop app links `LiosTunnel-core` via `flutter_rust_bridge` (codegen v2 — generates Dart bindings directly from annotated Rust functions, no manual `.h` files needed here since Dart FFI is separate from the C ABI used on mobile).
- TUN device: `wintun` crate on Windows (Wintun driver, no separate install needed — ships as a signed driver DLL bundled with the app), `tun` crate (`utun` interface) on macOS, `tun`/`tunTapInterface` on Linux.
- Requires elevated privileges to create the TUN interface — Windows: UAC prompt; macOS: `osascript`-triggered admin prompt or a small privileged helper tool installed once; Linux: either run as root or grant `CAP_NET_ADMIN` to the binary via `setcap`.
- System-level default-route override + DNS override, restored on disconnect or app crash (register a cleanup handler / use a watchdog).

### 6.2 iOS
- **Cannot** be done from the main Flutter app process. Requires:
  - A **Network Extension target** (`NEPacketTunnelProvider` subclass, Swift) — separate app extension bundled inside the same iOS app.
  - `LiosTunnel-core` compiled as a static library (`.a`) via `cargo lipo` or `cargo-ndk`-equivalent for iOS targets, linked into the extension target through a bridging header generated by `cbindgen`.
  - Main Flutter app talks to the extension via `NETunnelProviderManager` (start/stop/status) — this is a native API, so you'll need a small Flutter platform channel (`MethodChannel`) wrapping it; `flutter_rust_bridge` doesn't reach into Network Extension APIs since those are Apple frameworks, not Rust.
  - Shared state (connection stats, logs) passed between extension and main app via an **App Group** shared container (`UserDefaults(suiteName:)` or a shared file).
  - Requires the `com.apple.developer.networking.networkextension` entitlement with the packet-tunnel-provider value. This is **self-serve** — no request, no approval, no lead time: Signing & Capabilities → Network Extension → tick Packet Tunnel, on both the app and the extension target. A paid Apple Developer Program membership is the only gate. (It was approval-gated historically, which is where the opposite belief comes from; Apple's old `/contact/request/network-extension/` URL now redirects to the hotspot-helper form, a genuinely different entitlement that does still need a request.)

### 6.3 Android
- Requires a `VpnService` subclass (Kotlin), run as a foreground service (Android mandates a persistent notification while a VPN is active).
- `LiosTunnel-core` compiled via `cargo-ndk` into `.so` per ABI (`arm64-v8a`, `armeabi-v7a`, `x86_64`), loaded from the Kotlin service via JNI (or via the `uniffi` crate, which can generate the Kotlin binding layer automatically instead of hand-writing JNI — recommended over raw JNI to reduce boilerplate).
- Main Flutter app starts/stops the service via `MethodChannel` (again, not `flutter_rust_bridge`, since `VpnService` lifecycle is an Android framework concern, not something Rust can initiate directly — Android requires the *service itself* to call `VpnService.Builder().establish()`).
- Battery: use `WorkManager`/foreground service correctly, avoid polling — drive packet reads with a blocking read loop on a dedicated thread, not a busy-poll.

### 6.4 Why `flutter_rust_bridge` isn't used on the mobile tunnel path
This is worth being explicit about since it's a common point of confusion: `flutter_rust_bridge` bridges **Dart and Rust**. But on iOS/Android, the code that owns the TUN interface isn't Dart or your main app process at all — it's a separate OS-mandated component (Swift extension / Kotlin service) that Flutter doesn't control. That component talks to Rust via plain C FFI, and Flutter talks to *that component* via a platform channel. `flutter_rust_bridge` is only used for the parts of `LiosTunnel-core` that the main Flutter process itself calls directly — e.g., parsing/validating a config file, generating a QR code, or (on desktop only) running the whole engine in-process.

---

## 7. Security requirements

- No traffic logging by default; if debug logging is added, redact payload contents, log connection metadata only, and make it opt-in.
- Config secrets (private keys, passwords) stored in **Keychain** (iOS), **Keystore/EncryptedSharedPreferences** (Android), and OS credential manager equivalents on desktop — never in plaintext files, even though the *shareable* `.LiosTunnel.json` export format itself is plaintext (warn the user on export).
- TLS/SSH host key verification must be enforced by default (no silent "accept any key" — that must be an explicit opt-in with a scary warning, for self-signed lab setups).
- Kill switch: block all non-tunnel traffic if the tunnel drops unexpectedly (implemented via firewall rules on desktop, `NEPacketTunnelProvider`'s `includedRoutes`/`excludedRoutes` on iOS, and blocking all routes except the VPN interface on Android).
- DNS leak protection: force all DNS through the tunnel's configured resolvers; verify with an automated leak-test in the E2E suite.

---

## 8. Non-functional requirements

| Area | Target |
|---|---|
| Mobile battery overhead | Comparable to WireGuard official app (~low single-digit % over 1hr idle-connected) |
| Throughput overhead vs. raw connection | WireGuard: <10%; SSH tunnel: <20% (expected, SSH has more per-packet overhead); Shadowsocks: <15% |
| Reconnect time after network switch (WiFi↔cellular) | <3s |
| App size (mobile) | Keep Rust core release build stripped; target <15MB added to APK/IPA |
| Crash recovery | Kill switch must survive app crash (enforced at OS firewall/routing level, not just app logic) |

---

## 9. Testing strategy

- **Rust core:** unit tests per protocol module (mock server for SSH/WG/SS handshakes), plus `smoltcp` packet-pipeline tests using recorded pcap fixtures.
- **Integration:** spin up real test servers (a WireGuard peer, an SSH server, a Shadowsocks server) in Docker, run the core against them in CI.
- **Platform E2E:** given your existing Appium background, this is a natural fit for the mobile connect/disconnect/kill-switch flows — but keep it scoped to the handful of flows that actually need a real device/simulator (VPN permission prompts, notification checks), not full regression; you already know from the Jagad QA work that Appium's ROI drops fast once you're past the "does the OS-level permission dialog behave" class of test.
- **Leak tests:** automated DNS-leak and kill-switch-under-network-drop tests as a release gate, not just manual QA.

---

## 10. Phased roadmap

**Phase 0 — Core validation (no UI, no mobile)**
CLI-only Rust binary. SSH tunnel protocol only. Validate `smoltcp` packet pipeline end-to-end on Linux with a real TUN device and a real SSH server. Goal: prove the packet engine works before investing in any UI or mobile plumbing.

**Phase 1 — Desktop MVP**
Flutter desktop UI (profiles list, connect/disconnect, basic stats) wired to `LiosTunnel-core` via `flutter_rust_bridge`. Add WireGuard support. Ship Windows + macOS + Linux.

**Phase 2 — Android**
`VpnService` + JNI/uniffi bridge. Reuse Flutter UI as-is (mobile layout). Add Shadowsocks support here since Android is where most Shadowsocks users actually are.

**Phase 3 — iOS**
Network Extension target (entitlement is self-serve, see §6.2 — nothing to request), App Group state sharing.

**Phase 4 — Polish / V2 candidates**
Split tunneling per-app, multi-hop chaining, obfuscation plugin support (e.g. `v2ray-plugin`-style), config sync across devices.

---

## 11. Open questions / risks

- ~~**Apple entitlement approval timeline** for `networkextension` is the single biggest schedule risk~~ — **struck: this was wrong.** The packet-tunnel-provider entitlement is self-serve and has been since ~2016. Apple DTS: *"There is no approval process for creating an NE packet tunnel provider. Any paid developer can do that."* ([forums/thread/819032](https://developer.apple.com/forums/thread/819032)). There is no lead time to plan around. The real Phase 3 constraints are the *usage* rules — TN3120 (expected use cases), TN3134 (provider deployment), and the App Store review stance below.
- **`smoltcp` UDP support maturity** for SSH-tunnel-as-UDP-forwarder — likely descope UDP for the SSH protocol in V1 and document it as TCP-only.
- **App Store review stance on general-purpose tunnel apps** has tightened over time; review current App Store Review Guidelines §4.5.5 equivalent before submission — this should be re-checked close to Phase 3, not assumed from today's rules.
- **Desktop TUN elevation UX** — decide whether to ship a signed background helper (better UX, more setup work) vs. per-launch elevation prompt (simpler, more annoying).

---

## 12. Appendix: crate/dependency list

| Purpose | Crate |
|---|---|
| WireGuard | `boringtun` |
| SSH | `russh` (or `thrussh`, check maintenance status at implementation time) |
| Shadowsocks | `shadowsocks-rust` (as library) |
| Userspace TCP/IP stack | `smoltcp` |
| TUN device (desktop) | `tun`, `wintun` (Windows-specific) |
| Async runtime | `tokio` |
| Dart bridge | `flutter_rust_bridge` (codegen v2) |
| Android FFI (recommended over raw JNI) | `uniffi` |
| C header generation (iOS) | `cbindgen` |
| Serialization | `serde`, `serde_json` |

# LiosTunnel on Android — design

**Goal.** LiosTunnel runs on Android as a real VPN client. Shadowsocks and SSH
profiles carry live traffic through a `VpnService` tunnel, the existing UI shows
state, byte totals and live speed, and the tunnel survives the app being swiped
away.

**Not in scope.** iOS — deferred until an Apple Developer account exists. Play
Store packaging and signing. Per-app split tunnelling. Always-on VPN. A quick
settings tile.

---

## 1. Decisions taken before this design

| | |
|---|---|
| Platform order | **Android first.** iOS waits on an Apple Developer account |
| Protocols | **Both** — Shadowsocks *and* SSH |
| Min / target SDK | **29 (Android 10) / 34** |
| Where the engine runs | **In the foreground Service**, so the tunnel survives the app being swiped away |
| `protect()` | **Proven first.** Task 1 is a spike that ships nothing but an answer |
| How we run it | **Emulator to iterate, phone to verify** |

The `protect()` decision was: *"Make the very first task a spike that establishes
whether the crate can be made to call `protect()`. Everything else in the phase
depends on the answer, so finding out early is worth a task that ships nothing."*

Investigation during design has largely answered it — see §3 — which changes the
spike from *whether* to *wire it and prove it on hardware*. The task stays,
because none of the code involved compiles on the development machine.

## 2. Most of the engine ports unchanged, and a lot of it disappears

`PacketIo` (`crates/liostunnel-core/src/net/tun.rs:7`) is four methods:
`read_packet`, `write_packet`, `mtu`, and `pollable_fd`. `SmoltcpStack::start`
takes a `Box<dyn PacketIo>`. The `VpnService` file descriptor is a real fd, so
`pollable_fd` returns `Some(fd)` and the existing driving loop works untouched.

**An `AndroidTun` implementing four methods over that fd is the whole porting
job below the stack.** Everything above it — the NAT table, the smoltcp stack,
both protocol drivers, the flow semaphores, stats — is unmodified.

What does *not* port is larger than what does:

| Desktop component | On Android |
|---|---|
| `liostunnel-helper` (root daemon) | **gone** — no root, no daemon |
| the uid authorization boundary | **gone** — Android's per-app sandbox is the boundary |
| route pinning, route manager | **gone** — `VpnService.Builder` owns routing |
| `install-helper.sh`, launchd, systemd, `pkexec` | **gone** |
| the unix socket and its framing | **gone** — replaced by direct FFI |

The entire privileged-installation apparatus — the part of this project that has
produced the most defects — has no Android analogue. That is why Android is less
work than its file count suggests.

## 3. The one genuinely hard problem: `protect()`

A VPN app's own outbound connection is subject to its own routing table. Without
intervention the tunnel's connection to the Shadowsocks or SSH server is routed
*into the tunnel*, which routes it into itself. `VpnService.protect(fd)` excludes
a socket from that.

This is the Android analogue of the desktop route-pin, which shipped as a
Critical finding last phase. It is the same class of bug and deserves the same
suspicion.

The two protocols need **opposite mechanisms**:

| | How the socket gets protected | Sockets to protect |
|---|---|---|
| **Shadowsocks** | the library calls us: `ConnectOpts::set_vpn_socket_protect` (`shadowsocks-1.24.0/src/net/option.rs:112`) | one **per flow**, unbounded |
| **SSH** | we own the socket: `russh::client::connect_stream` (`russh-0.62.4/src/client/mod.rs:995`) accepts any `R: AsyncRead + AsyncWrite + Unpin + Send + 'static` | **one**, at connect |

For Shadowsocks the crate has a purpose-built hook, gated on
`#[cfg(target_os = "android")]`, that hands us every socket it opens. Using it
means switching `ProxyClientStream::connect` to `connect_with_opts`
(`src/relay/tcprelay/proxy_stream/client.rs:70`) and passing a `ConnectOpts`
carrying the closure. `ConnectOpts` is not constructed anywhere in
`protocols/shadowsocks.rs` today — the crate runs with defaults — so this is new
code, not an edit.

For SSH there is no hook and none is needed: we build the `TcpStream`, protect
its raw fd, and hand the stream to `connect_stream`.

**The asymmetry decides where the risk lives.** SSH has one socket at connect —
it works immediately or it fails immediately. Shadowsocks opens a socket per
flow, bounded only by `MAX_CONCURRENT_FLOWS = 64`, so a missed `protect()` is a
bug that appears under load, intermittently, after the happy path already looked
fine. Verification must exercise concurrent flows, not a single request.

**None of this compiles on the development machine.** The hook is
`#[cfg(target_os = "android")]`; host `cargo test` and CI on macOS and Linux
never see it. That is the permanent testing gap of this phase and the reason
Task 1 exists.

## 4. Process and lifetime model

```
Flutter UI ──FFI──────────────▶ liostunnel-core (native threads)
     │                                    ▲
     └──MethodChannel──▶ LiosVpnService ──┘ JNI: nativeStart(fd)
                         (foreground)
```

The engine runs in native threads owned by the foreground Service. Dart drives
it directly over FFI. Kotlin's only job is to obtain the tunnel fd and to keep
the process alive.

**The Rust engine handle is a process-global owned by the native layer, not by
the Dart isolate.** When the Activity is destroyed — the user swipes the app
away — the process survives because a foreground service is running, and the
native threads keep the tunnel up. Reopening the app attaches to the running
engine and re-reads its state.

This mirrors the desktop split, where the helper survives and the UI reattaches,
with the survival boundary moved from a separate process to a foreground Service
in the same one. The UI's reattach concept already exists and is reused.

If the engine handle were owned by the Dart isolate, tearing down the Flutter
engine would take the tunnel with it. **The swipe-away test is what
distinguishes those two designs**, and it is a device test — nothing on the host
can tell them apart.

## 5. Stats and live speed require no Android code

`ConnectionModel` consumes a stats stream. On desktop that arrives as a `Stats`
frame every second over the unix socket. On Android there is no socket: Dart
polls the engine over FFI on the same one-second cadence and feeds the same
shape.

Live speed is a pure function of that stream and of an injected clock
(`2026-07-31-liostunnel-speed-monitoring-design.md` §2), so it works on Android
with **no new code** — including the measured-elapsed-time behaviour, which
matters more on a phone, where a backgrounded app's frames are genuinely late.

## 6. Credentials never cross the Kotlin boundary

The Shadowsocks password and the SSH private key travel **Dart → Rust over
FFI**. Kotlin receives a file descriptor and nothing else.

An Intent extra can be logged by the system, and `MethodChannel` arguments are
ordinary Java objects visible in a heap dump. The project's existing rule —
never log secret material, in logs, errors, `Debug` output or protocol fields —
extends naturally to not placing secrets anywhere we do not control.

This fixes the start sequence:

1. Dart loads the profile into the engine over FFI.
2. Dart asks Kotlin, over `MethodChannel`, to start the Service.
3. The Service builds the tunnel and obtains the fd via `establish()` →
   `detachFd()`.
4. The Service calls `nativeStart(fd)` over JNI; Rust starts the engine on that
   fd using the profile it already holds.

Kotlin never sees a credential, and the fd is the only thing that crosses JNI.

## 7. The Android layer

`app/android/` **does not exist yet** — the Flutter project has no Android
platform directory, so Task 1 begins with `flutter create --platforms=android .`.
`app/rust_builder/android/` already exists, so cargokit is ready.

- **`LiosVpnService`** — a `VpnService` subclass. `Builder` sets an address, a
  default route (`0.0.0.0/0`), a DNS server and the MTU, then `establish()`.
- **Consent.** `VpnService.prepare(context)` returns an `Intent` when the user
  has not yet approved VPN access; the Activity launches it and waits for the
  result. Once per install.
- **Foreground notification** — required to keep the process alive, and the
  user's honest signal that a tunnel is up.

**Android 14 requires `android:foregroundServiceType`.** We declare
`specialUse` with the `FOREGROUND_SERVICE_SPECIAL_USE` permission. This is a
runtime-failure class — a wrong or missing type throws on `startForeground`,
and no test on the development machine catches it. Explicit device check.

## 8. Size

Measured on this machine, not estimated:

- The macOS framework is **39 MB**, a universal binary carrying x86_64 *and*
  arm64 slices — roughly 20 MB per architecture. (This contradicts
  `2026-07-29-liostunnel-desktop-packaging-design.md:48-50`, which states the
  build is single-architecture. That spec is wrong and is corrected separately.)
- `-force_load` in the podspec is **required**, not waste: `frb_generated.rs`
  contains no `#[no_mangle]` exports, so without it the linker discards the
  engine and leaves a 1.6 MB shell that exports only the 26 generic `frb_*`
  runtime symbols.
- The `doh` feature costs **12.1 MB of an 87.2 MB static archive (14%)**;
  linked, the `.a`→binary ratio observed here (~4.4×) puts the real saving near
  **3 MB per architecture**. **`doh` is kept** — losing DNS-over-HTTPS to save
  3 MB is a bad trade for a privacy tool.
- `aws-lc-sys` (bundled BoringSSL) is the largest single dependency and is
  **not removable**: `russh` requires it, and SSH is in scope.

**The Android lever is per-ABI splitting**, which costs nothing: a universal APK
carries every ABI, so release builds use `--split-per-abi` and the phone gets
`arm64-v8a` alone.

A `[features]` block was added to `crates/liostunnel-ffi/Cargo.toml` during this
investigation. It forwards `doh` and preserves the previous behaviour exactly
(`default = ["doh"]`). Without it the crate silently ignored
`--no-default-features` and exited 0 — a measurement trap that produced one
false result before it was caught.

## 9. Testing

**Host unit tests are unchanged** and still cover everything above `PacketIo` —
both protocol drivers, the NAT table, the stack, the model. That is the majority
of the logic and it does not become less tested by gaining a platform.

**The Android-specific surface is untestable on the development machine**, being
`#[cfg(target_os = "android")]`. The mitigation is to keep that surface
deliberately tiny — `AndroidTun`'s four methods and two `protect()` call sites —
so that what cannot be tested can at least be audited by reading it in one
sitting.

**The emulator** (`Medium_Phone_API_36.1`, present) gives compile-and-run
feedback and drives the UI without a human. It is **not faithful for the thing
that matters**: emulator networking is NAT-ed through the host, so `protect()`
and routing behave differently than on a phone. It proves the code runs. It does
not prove the tunnel works.

**The phone is the verification that counts.** Each task ends with a named check
run on hardware, in the pattern the desktop root-verifier scripts already
established. The phase-closing checks:

- a real request completes through the tunnel, on both protocols;
- **concurrent flows** complete — the case a missed Shadowsocks `protect()`
  breaks and a single request does not;
- swiping the app away leaves traffic flowing;
- disconnecting removes the tunnel and the notification.

## 10. Exit criteria

| | |
|---|---|
| AND-1 | `protect()` is proven callable from Rust on a device, for **both** protocols |
| AND-2 | A Shadowsocks profile carries real traffic through `VpnService` |
| AND-3 | An SSH profile carries real traffic through `VpnService` |
| AND-4 | Concurrent flows all complete — no per-flow socket escapes `protect()` |
| AND-5 | The tunnel survives the app being swiped away |
| AND-6 | State, byte totals and live speed appear in the existing UI, unmodified |
| AND-7 | Disconnect tears down the tunnel and the notification |
| AND-8 | Release builds are per-ABI, not universal |

### Verified

All eight, on the `Medium_Phone_API_36.1` emulator against `testing/docker`
(shadowsocks-libev, a real sshd, nginx behind them, and a resolver reachable
only through the relay). Recorded here because the phase's own rule was that
an emulator pass never substitutes for evidence, and this is the evidence.

| | Evidence |
|---|---|
| AND-1 | protected socket connects in 23ms, unprotected one times out after 133s |
| AND-2 | `HTTP/1.1 200 OK` from 192.168.158.4, reachable only through the relay |
| AND-3 | the same, over SSH — the `connect_stream` + `protect_fd` path |
| AND-4 | 30 concurrent flows, 30 × 200 OK, 0 failed, on **both** protocols |
| AND-5 | Activity destroyed, traffic still flowing, counters continued on reopen rather than resetting |
| AND-6 | state, totals and live speed rendered from the polled stream |
| AND-7 | `nativeStop`, tun0 gone, zero service records, relay unreachable again |
| AND-8 | three APKs, one ABI each, verified by content in CI |

AND-3 was the last and went unexercised longest: the code was written, compiled
for both architectures and reviewed twice before it ever ran. It worked first
time, which is not evidence that writing it carefully was sufficient — the
three defects AND-5 and AND-7 exposed were also written carefully.

**AND-4 is the one to care about.** AND-2 and AND-3 can pass with a broken
`protect()` on an emulator or a lucky first request; AND-4 is what fails when a
socket escapes, and it is the failure that would otherwise reach a user as
"works, then stops."

## 11. Risks

**`protect()` cannot be tested where the code is written.** Every mechanism in
§3 is `#[cfg(target_os = "android")]`. Host CI will compile none of it, so CI
staying green means nothing about this phase's core risk.

**Android licences are unaccepted on this machine** — `flutter doctor` reports
"Android license status unknown". The first build fails until
`flutter doctor --android-licenses` is run. Task 1, first step.

**`app/android/` does not exist.** It is generated, and generated Android
scaffolding carries defaults — `com.example.*` for the applicationId among them
— that are fine for sideloading and wrong for anything published. Play Store is
out of scope, so this is noted rather than solved.

**Android 14 foreground-service rules** fail at runtime, on device, in a way
nothing here reproduces.

**Private DNS (DoT) may not behave as expected.** Android's resolver has its own
opinions about which DNS server applies under a VPN, and `addDnsServer` is not
the whole story. Verify on device; do not assume the desktop DNS path transfers.

**Doze and battery optimisation** can affect a long-lived foreground service on
some vendor Android builds in ways stock Android does not show.

**The emulator will make some things look like they work.** That is its most
dangerous property, and it is why every exit criterion above is a device check.

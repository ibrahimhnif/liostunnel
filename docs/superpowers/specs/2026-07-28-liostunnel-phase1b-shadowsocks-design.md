# LiosTunnel Phase 1b — Shadowsocks Design Spec

**Status:** Approved
**Date:** 2026-07-28
**Author:** Hanif
**Context:** [`PRD.md`](../../../PRD.md) §2 (protocols), [Phase 0 spec](2026-07-27-liostunnel-phase0-design.md), [Phase 1a spec](2026-07-28-liostunnel-phase1a-desktop-ui-design.md)
**Summary:** A second tunnel protocol, which is also the first real test of whether `Protocol` is an abstraction or an SSH-shaped hole.

---

## 1. Purpose

Phase 0 built an engine and one protocol. Phase 1a put a UI on it. Everything
since has been driven by one SSH implementation, so `Protocol` has never had to
describe anything but SSH.

This slice adds Shadowsocks over TCP. It is worth doing for two reasons that
are independent of each other, and both should be true at the end:

1. **It is a better tunnel to actually use.** SSH tunnel providers hand out
   expiring per-server accounts and routinely block outbound port 53 — the
   symptom observed in the field was every DNS lookup taking ten seconds
   before failing. Shadowsocks servers are cheap, self-hostable, not tied to
   an account, and designed to survive networks that interfere with traffic.
2. **It tells us whether the abstraction holds.** Two places already look
   SSH-shaped: `HostKeyPolicy` is threaded through `Tunnel::start`, and the
   helper keeps a `known_hosts` store. Shadowsocks has no host key. Finding
   out what else assumes SSH is the point, not a side effect.

## 2. Scope decomposition — why TCP now and UDP next

Shadowsocks supports UDP relay, and UDP is what stops QUIC and HTTP/3 falling
back to TCP. It is deliberately **not** in this slice.

`Protocol::send_udp` is fire-and-forget:

```rust
async fn send_udp(&self, dest: SocketAddr, data: &[u8]) -> Result<(), TunnelError>;
```

There is no return path, so a reply has nowhere to go. DNS works today only
because `open_dns_stream` is a separate, stream-shaped method. Real UDP needs a
trait change, a NAT table with association timeouts, and engine changes to stop
discarding non-DNS UDP.

Designing that return path with exactly one UDP-capable protocol to generalise
from is how an abstraction ends up shaped like its first implementation — which
is the mistake this slice exists to detect in the *existing* trait. UDP gets its
own slice, once there is a second protocol in hand.

**The PRD's stated build order is SSH → WireGuard → Shadowsocks. This inverts
the last two, deliberately.** That order was written before we knew WireGuard
does not fit `Protocol` at all: it is L3, so there is no `open_tcp_stream` to
implement, and the packet engine is bypassed rather than reused. WireGuard is
closer to a second architecture than a second implementation, and it belongs
after we know what the trait actually needs.

## 3. In scope

- `protocols/shadowsocks.rs` implementing `Protocol` over TCP.
- A protocol factory in the helper, replacing the hardcoded `SshTunnel`.
- `AuthMethod::Shadowsocks { method, password }` and its path through the FFI
  DTO to the editor.
- `ss://` import (SIP002 and the legacy form), parsed in Rust.
- A Shadowsocks fixture in `testing/docker`, and an end-to-end run.

## 4. Out of scope

- UDP relay (own slice, §2). WireGuard (own phase). Windows (own phase).
- Shadowsocks plugins (`v2ray-plugin`, `obfs`). They are a separate transport
  layer and nothing here depends on them.
- QR-code import. A paste box covers desktop; a camera dependency does not earn
  its place until mobile.
- Changes to the packet engine, smoltcp stack, or UI beyond the editor fields.

## 5. Decisions and rationale

| # | Decision | Why |
|---|---|---|
| D1 | Shadowsocks before WireGuard | WireGuard does not fit `Protocol`; Shadowsocks does. Test the abstraction with something that can pass before rewriting it for something that cannot. |
| D2 | `shadowsocks` crate 1.24, `--no-default-features --features aead-cipher` | Verified by compiling: `ProxyClientStream::connect(ctx, &cfg, Address)` returns a type satisfying `TunnelStream`'s exact bounds. No custom crypto, per PRD §2. |
| D3 | Connect-time probe query | Shadowsocks cannot authenticate at connect. Without a probe, `Connected` would mean "a socket opened", and a wrong password would look identical to a working tunnel. See §7. |
| D4 | The SS password is a `SecretRef` | It *is* key material. Making it a `SecretRef` means it lives in a `0600` file and the Phase 1a ownership gate applies unchanged, rather than inventing a second rule for a second protocol. |
| D5 | `ss://` parsed in Rust | Same rule as `parse_profile` (P1a-1): the format has one owner. A URI parser in Dart would be a second one, free to drift. |
| D6 | Two server fixtures | `shadowsocks-libev` proves interoperation with the C reference implementation. A Rust client tested only against a Rust server lets a bug shared by both sides pass — the same shape as a mock written to match the code it tests. |
| D7 | `HostKeyPolicy` becomes protocol-specific | It is meaningless for Shadowsocks. Leaving it in the universal path would be the SSH-shaped hole this slice exists to find. |
| D8 | Reuse `verify-phase1a.sh` unchanged | It already takes `LIOS_PROFILE`. If fourteen checks pass against a second protocol with no edits to the script, that is evidence the abstraction held. If the script needs edits, that is evidence it did not — and the edits are the finding. |

## 6. Architecture

```
                 ┌────────────────────────────┐
   TUN ─ smoltcp │ Engine                     │
                 │   open_tcp_stream(dest) ───┼──▶ dyn Protocol
                 │   open_dns_stream(server) ─┼──▶      │
                 └────────────────────────────┘         │
                                            ┌───────────┴───────────┐
                                            │                       │
                                       SshTunnel            ShadowsocksTunnel
                                    direct-tcpip           ProxyClientStream
```

The engine, stack, helper socket layer and UI are untouched. `open_tcp_stream`
and `open_dns_stream` both become `ProxyClientStream::connect` — Shadowsocks
makes no distinction between a DNS stream and any other, so the DNS-over-TCP
resolver works through it with no special case.

`Tunnel::start` gains a factory:

```rust
let protocol: Arc<dyn Protocol> = match profile.protocol {
    ProtocolKind::Ssh => /* SshTunnel, with the host-key policy */,
    ProtocolKind::Shadowsocks => /* ShadowsocksTunnel */,
    ProtocolKind::WireGuard => return Err(/* not in this build */),
};
```

`HostKeyPolicy` moves inside the SSH arm. Anything else that cannot be
constructed protocol-neutrally is a finding for §13's P1b-6.

## 7. The connect-time probe

**Shadowsocks has no handshake.** Each stream is independent; the server
decrypts the first bytes with its key and silently discards the connection if
they do not decrypt. A wrong password or cipher therefore produces a TCP
connection that is accepted and then goes nowhere.

`connect()` returning `Ok` on that basis would be a lie of exactly the kind
this project keeps finding: a green result over something unverified. The UI
would show `Connected`, routes would be installed, and nothing would work.

So `connect()` performs one real DNS query through a probe stream to the
profile's first DNS server. If it round-trips, the cipher and password are
correct and the server relays traffic. If it does not, `connect` fails with
`TunnelError::Auth` and the UI says the credentials were rejected — which by
then is true.

Cost: one DNS query and its round trip, once per connect. The alternative is a
tunnel that reports success and carries nothing, which is the failure mode we
have spent this project learning to distrust.

**The probe must not be mistaken for authentication in the SSH sense.** It
proves the server relays traffic for these credentials; it does not
authenticate the server to us. Shadowsocks offers no server identity at all,
which is a property of the protocol and is recorded here so nobody later reads
`Connected` as meaning more than it does.

## 8. Profile schema

```rust
AuthMethod::Shadowsocks {
    /// A cipher name as Shadowsocks spells it, e.g. `aes-256-gcm`
    /// or `chacha20-ietf-poly1305`.
    method: String,
    password: SecretRef,
}
```

`secret_refs()` returns the password, so the Phase 1a escalation gate covers it
with no new code: a Shadowsocks profile naming a key file the caller does not
own is refused exactly as an SSH one is.

Supported ciphers:

| family | names |
|---|---|
| AEAD | `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` |

`shadowsocks.rs`'s `OFFERED` constant is the authority; this table follows it.

Stream ciphers (`rc4-md5`, `aes-256-cfb`) are **not** offered. They are broken,
the crate gates them behind a separate feature, and offering a cipher we would
have to warn about is worse than not offering it.

**AEAD-2022 is not offered either** — corrected 2026-07-29, after the Task 2
review. This table originally carried a `2022-blake3-*` row, read from the
names present in `shadowsocks-crypto`'s `kind.rs`. Those names are there, but
their `FromStr` arms are `#[cfg(feature = "v2")]`, reachable only through
`shadowsocks/aead-cipher-2022` — which D2 forbids. Building against D2's exact
dependency line and calling `CipherKind::from_str` on all three returns
`Err(ParseCipherKindError)`. So the row described what the source spells, not
what this build can construct, and the offered list it produced recommended
three ciphers to a user who had just typo'd one — each of which then failed as
unknown. D2 governs. Supporting AEAD-2022 later is a feature-flag decision
with its own dependency cost, not a table edit.

Ripples: core `AuthMethod` → `secret_refs()` → `ProfileDto` (`auth_kind:
"shadowsocks"`, plus a `cipher` field) → the editor's dropdown.

## 9. `ss://` import

Two forms are in circulation and both are accepted:

```
ss://base64(method:password)@host:port#tag        SIP002
ss://base64(method:password@host:port)#tag        legacy
```

One FFI function takes the URI and returns a `ProfileDto`, so Dart never learns
the format. The password is written to a `0600` file by the same code path the
editor already uses for a typed password, and the profile stores only that
path.

**A parse error must never echo the URI.** It contains the password. This is
the rule Phase 0 broke in `profile_io::load` and Phase 1a broke again in the
protocol codec, and it gets a test that fails against an echoing
implementation.

## 10. Fixture

`testing/docker` gains two servers beside `sshd`:

| service | image | covers |
|---|---|---|
| `ss-libev` | `shadowsocks/shadowsocks-libev` | AEAD interop against the C reference |
| `ss-rust` | `teddysun/shadowsocks-rust` | AEAD-2022, which libev predates |

Both verified pullable before this spec was written. Credentials are generated
by the fixture, never committed, exactly as `sshd/gen-keys.sh` does.

## 11. Testing

| Layer | Covers | Root? |
|---|---|---|
| URI parsing | both forms, no tag, malformed, no echo of the URI | no |
| Cipher mapping | every offered name maps to a `CipherKind`; an unknown one is refused | no |
| Schema round-trip | `AuthMethod::Shadowsocks` through core, DTO and back | no |
| Protocol against a live server | `open_tcp_stream`, `open_dns_stream`, wrong password | no (Docker) |
| Interop | the same tests against `ss-libev` | no (Docker) |
| End to end | `verify-phase1a.sh` with a Shadowsocks profile | **yes** |

The standing discipline applies unchanged: **a test that passes must be shown
failing against the defect it names.** This project has produced at least
thirteen tests that were green while the thing they named was broken —
including one whose fixture could not reach the branch it claimed to test, and
one that asserted a feature existed while it was absent from the screen. Every
A/B in this slice is run, and its transcript recorded.

## 12. What this slice must not break

The Phase 1a exit criteria are regression tests now, not history. P1a-5 and
P1a-6 in particular must hold for a Shadowsocks profile: a connection from an
unauthorized uid refused, and a profile naming a secret file the caller does not
own refused before a TUN device exists. §11's end-to-end row is how that is
checked, and it is why the script is reused rather than rewritten.

## 13. Exit criteria

- **P1b-1** — a Shadowsocks profile connects and carries traffic, proven by a
  packet capture on the tunnel device and byte counters that move, as P1a-2/3
  were.
- **P1b-2** — the same works against `shadowsocks-libev`, not only the Rust
  server.
- **P1b-3** — a wrong password or cipher fails at connect with a clear error,
  rather than producing a tunnel that reports success and carries nothing.
- **P1b-4** — an `ss://` link imports to a working profile; a malformed one is
  refused without echoing it.
- **P1b-5** — the secret-ownership gate applies to a Shadowsocks password
  exactly as to an SSH key, demonstrated by a test that fails against a naive
  implementation.
- **P1b-6** — `Protocol` required no SSH-shaped concession, **or** this spec is
  amended to record what it required and why.

P1b-6 is the one that cannot be satisfied by writing more code. It is answered
by what the factory in §6 turns out to need.

## 14. Risks

**The probe design (§7) is the debatable call.** It trades a round trip at
connect for `Connected` meaning something. If it proves noisy in practice — a
server that rate-limits, a DNS server that is slow — the fallback is to make it
optional per profile, not to remove it silently.

**`shadowsocks` 1.24 pulls a large dependency tree.** The build is already
gated to `--no-default-features --features aead-cipher`; if it drags in more
than expected, that is a finding worth recording rather than absorbing.

**Interop may not be clean.** libev and rust disagree on some cipher naming and
on AEAD-2022 support. Discovering that is the point of D6, and a disagreement
is a result, not a failure.

## 15. Next step

An implementation plan via the writing-plans skill, executed task by task with
the same discipline: failing test first, A/B every guard, and a verification
run against a real server before anything is called done.

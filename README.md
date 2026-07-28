# LiosTunnel

Cross-platform tunnel client with one shared Rust core. **Phase 0: CLI only.**

Routes TCP traffic from a TUN device through an SSH tunnel on macOS and
Linux, with DNS resolved over the tunnel via one of two backends
(DNS-over-TCP or DNS-over-HTTPS). No UI, no mobile, no WireGuard or
Shadowsocks yet — profiles for those protocols parse, but connecting with
one is rejected. See [`PRD.md`](PRD.md) for the full roadmap and
[`docs/superpowers/specs/2026-07-27-liostunnel-phase0-design.md`](docs/superpowers/specs/2026-07-27-liostunnel-phase0-design.md)
for exactly what Phase 0 does and does not include.

## Build

Requires Rust 1.93 (edition 2024) — `rust-toolchain.toml` pins this for you
if you use `rustup`.

```bash
cargo build --release
```

A lean build drops the DNS-over-HTTPS stack (`hyper`, `rustls`,
`tokio-rustls`, `webpki-roots`) entirely, for a smaller binary:

```bash
cargo build --release -p liostunnel-core --no-default-features
```

## Use

```bash
# Check a profile without connecting.
liostunnel validate myserver.liostunnel.json

# Open one SSH channel to a destination and proxy stdin/stdout through it —
# useful to sanity-check auth and connectivity before bringing up the TUN device.
liostunnel probe myserver.liostunnel.json --user me --dest example.com:80

# Route one prefix through the tunnel — safe, cannot lock you out of the
# machine (a /0 "test" CIDR is rejected before anything with side effects
# runs).
sudo liostunnel connect myserver.liostunnel.json --user me \
  --route-mode test --cidr 93.184.216.0/24 --capture-dns

# Route everything through the tunnel.
sudo liostunnel connect myserver.liostunnel.json --user me --route-mode default
```

`liostunnel import`/`liostunnel export --include-secrets` convert between the
two profile representations described below.

## Profile format

Two representations. `ServerProfile` (what `validate`/`connect`/`probe` read)
references secrets by pointer and is safe to store or commit by mistake; the
shareable, portable form inlines the secret material in plaintext and is
produced only by `liostunnel export --include-secrets` (which prints a loud
warning first) and consumed by `liostunnel import` (which writes each secret
to its own `0600` file under `~/.liostunnel/secrets/` and never keeps the
plaintext in memory longer than the conversion itself).

```json
{
  "id": "b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f",
  "name": "Home VPS",
  "protocol": "ssh",
  "host": "198.51.100.7",
  "port": 22,
  "auth": {
    "type": "private_key",
    "private_key": { "source": "file", "path": "/home/me/.ssh/id_ed25519" }
  },
  "dns": { "mode": "tcp", "servers": ["1.1.1.1", "1.0.0.1"], "https": null },
  "split_tunnel": { "type": "all_traffic" },
  "kill_switch": false
}
```

`dns` also accepts the PRD's original bare-array shorthand
(`"dns": ["1.1.1.1", "1.0.0.1"]`), which defaults to `mode: "tcp"`. Setting
`dns.mode` to `"https"` requires a `dns.https` block (`{"sni": "...",
"path": "/dns-query"}`).

`kill_switch` and `split_tunnel` are parsed and validated but **not
enforced** in Phase 0 — setting either prints a loud warning at every
startup rather than silently doing nothing.

Secret files (referenced via `{"source": "file", "path": "..."}`) must be
mode `0600` or stricter, checked before every read.

## Testing

```bash
cargo test --workspace                                       # 227 tests: no root, no TUN, no network, no ~/.liostunnel
make -C testing/docker up && \
  cargo test -p liostunnel-core --test ssh_integration -- --ignored   # 10 tests, real sshd in Docker
cargo test -p liostunnel-core --lib dns::over_https -- --ignored     # 1 test, needs outbound network to 1.1.1.1:443
sudo -E cargo test -p liostunnel-core --test tun_e2e -- --ignored    # 2 tests, real TUN device, needs root
```

CI (`.github/workflows/ci.yml`) runs the first two on every push/PR (on both
Linux and macOS for the hermetic suite), the DoH network test as a
non-blocking job, and the TUN e2e tests as root on a Linux runner. It does
not and cannot run the release gates below — those need a real server and a
human's own machine.

Release gates for the exit criteria that need a live network, a real route
table, or a real server live in [`testing/gates/`](testing/gates/README.md).

## Security

Host key verification is enforced by default (trust-on-first-use, recorded
in `~/.liostunnel/known_hosts`). `--insecure-accept-any-hostkey` disables it
and prints a loud warning; use it only against a server you control on a
network you control. Secret files must be mode `0600` or stricter, checked
before every read. DNS query names and answers, and proxied payload bytes,
are never logged — only counts, IP addresses, and error shapes are.

## Limitations (Phase 0, as implemented)

These are current, real gaps — not aspirational TODOs. Each is discussed in
more detail in the referenced task report under `.superpowers/sdd/`.

- **Linux's `default` route mode does not override DNS at all.**
  `/etc/resolv.conf` keeps pointing at whatever resolver was configured
  before `connect` ran, and it stays reachable via a route more specific
  than the split-default halves the tunnel installs — so on Linux, DNS
  genuinely leaves the machine outside the tunnel today. macOS's `default`
  mode does override DNS (`networksetup -setdnsservers`). This is expected
  to make `testing/gates/dns_leak_test.sh` fail on Linux; see that script's
  own header and `testing/gates/README.md`.
- **IPv6 is entirely uncovered.** Only the IPv4 split-default
  (`0.0.0.0/1` + `128.0.0.0/1`) is installed; `::/0` is untouched on both
  platforms, so all IPv6 traffic — including IPv6-only DNS — bypasses the
  tunnel entirely.
- **macOS's DNS-override revert does not restore a pre-existing manual DNS
  configuration.** It resets to "automatic" (DHCP-assigned) DNS, which is a
  no-op for the common case (no manual override already in place) but is not
  an exact restore for an operator who had one.
- **macOS's DNS override hardcodes the `"Wi-Fi"` network service**
  (`route/macos.rs`). `networksetup -setdnsservers Wi-Fi ...` silently
  targets the wrong (or a nonexistent) service on any machine connected via
  Ethernet, Thunderbolt, or a `Wi-Fi` service renamed or localised to
  something else — the DNS override simply does not take effect, with no
  error surfaced to the operator. Worse, because this `networksetup` command
  is the *last* command in `default` mode's apply list, a failure there
  (e.g. the service genuinely doesn't exist, so the command itself errors)
  means `RouteGuard::apply` returns `Err` *before* the `RouteGuard` is ever
  constructed — so its `Drop`-based revert never runs, and the server pin
  plus both `/1` split-default halves are left installed with no in-process
  path to remove them (only the crash-recovery state file, on the *next*
  `connect` run, cleans them up).
- **Windows has no TUN implementation and no descriptor-based wakeup path.**
  The PRD lists Windows as a target platform; Phase 0 is macOS/Linux only.
- **No kill switch and no split-tunnel enforcement.** Both fields parse and
  validate; neither is acted on. A dropped tunnel does not block traffic,
  and traffic is always all-or-nothing per the chosen route mode regardless
  of what `split_tunnel` says.
- **No graceful SSH disconnect.** The session is simply dropped when the
  process exits; nothing sends an explicit "goodbye" to the server.
- **No session-loss detection or reconnect.** Spec §11 calls for
  exponential-backoff reconnect on a dropped SSH session; that is entirely
  unimplemented. What Phase 0 *does* do (as of the final-review fix pass):
  `connect` now selects on the packet engine's own task alongside Ctrl-C and
  `SIGTERM`, so a dead tunnel (stack thread panic, or any other unrequested
  stack exit) is noticed immediately — routes are reverted, the state file
  is cleared, and the process exits non-zero with a loud log line — instead
  of the process sitting in `ctrl_c().await` forever with the routes still
  installed and nothing behind them. It still does not reconnect; the
  operator has to run `connect` again.
- **A `connect` run with multiple `--cidr` values is not atomic if one of
  several route commands fails partway through** — commands already applied
  before the failing one are not automatically rolled back within that
  single `apply_commands` call (the crash-recovery state file still reverts
  everything on the next start).
- **The accepted-flow backlog is unbounded** by design (an accepted
  connection must never silently vanish); only the socket buffers behind it
  are bounded.
- **DNS concurrency is bounded by a small, reserved channel budget, separate
  from ordinary proxied flows.** DNS queries (`over_tcp::TcpResolver`,
  `over_https::DohResolver`) now open channels via
  `Protocol::open_dns_stream`, which `SshTunnel` gates with its own
  `MAX_CONCURRENT_DNS_CHANNELS` semaphore (8) instead of the 64-permit one
  ordinary proxied TCP flows use — so a tunnel busy with bulk traffic can no
  longer starve DNS resolution out behind it. That reserved allowance is
  still a fixed size (8): more than 8 truly concurrent DNS queries at once
  will still queue behind each other, just no longer behind unrelated bulk
  flows.
- **A DNS answer larger than the TUN MTU is now truncated (TC bit set) rather
  than silently failing to resolve.** `StackCore::inject_datagram` compares
  a synthesised answer against the configured MTU and, when it doesn't fit,
  replies with an RFC 1035 §4.1.1 truncated response (the 12-byte header,
  unmodified ID and flags except TC, every record count zeroed) instead of
  handing the device a packet it cannot carry. This does not retain the
  echoed question section in the truncated reply (doing so correctly needs
  real DNS message parsing — walking the QNAME label encoding — which this
  fix deliberately avoided to not risk corrupting the one packet it exists
  to make safe); most resolvers key off the TC bit alone and retry over TCP
  regardless.

## Phase 0 exit criteria

| Criterion | Status | Verified by |
|---|---|---|
| EC1 — TCP through the tunnel in `test` mode | needs human (root + Docker fixture) | Task 17 report; unit/argument-parsing coverage only so far |
| EC2 — hostname resolution on both DNS backends | needs human (root + Docker fixture) | Task 19/20 reports; unit coverage plus one network-gated DoH test |
| EC3 — `default` mode plus all three cleanup paths | needs human (root, real routing table) | Task 21 report; unit coverage for command construction and state-file recovery |
| EC4 — DNS leak test | **known failure on Linux** (not merely unverified — Linux `default` mode installs no DNS override at all, so DNS provably leaves the tunnel there by construction, not by an untested edge case); macOS still needs human verification | `testing/gates/dns_leak_test.sh`, never executed by an agent |
| EC5 — idle CPU ≈ 0% | **verified** | Task 14: 0.00 user + 0.00 sys CPU over a 6.67s window, ~2 poll passes/s idle-connected, instrumented counter distinguished a real spin (116,075 passes/0.5s) from the fix |
| EC6 — within 20% of `ssh -D` | needs human (real SSH server) | `testing/gates/throughput_test.sh`, never executed by an agent |
| EC7 — same code path on macOS utun and Linux TUN | needs human (root, both platforms) | `crates/liostunnel-core/tests/tun_e2e.rs` — written and compiles, but proves far less than "same code path": it only opens a device and reads back one packet, checking that the AF-prefix header is stripped. No smoltcp interface, no `Engine`, no proxied flow, and no DNS path is exercised through a real device by this or any other test. It proves the TUN framing codec (Decision D2) works identically on both platforms, and nothing beyond that; never executed against a real device by an agent either way |

EC5 is the one criterion independently verified without root: Task 14
instrumented the poll loop itself with a pass counter and measured it
directly against a live, idle, connected in-memory flow. Every other
criterion needs either root, a real routing table, a real TUN device, or a
real SSH server, none of which a sandboxed development session touches — see
`.superpowers/sdd/task-22-report.md` for the exact executed/not-executed line
on all of the above.

## License

MIT OR Apache-2.0.

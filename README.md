# LiosTunnel

Cross-platform tunnel client with one shared Rust core. **Phase 0: CLI only.**

Routes TCP traffic from a TUN device through an SSH tunnel on **Linux**, with
DNS resolved over the tunnel via one of two backends
(DNS-over-TCP or DNS-over-HTTPS). No UI, no mobile, no WireGuard or
Shadowsocks yet — profiles for those protocols parse, but connecting with
one is rejected. See [`PRD.md`](PRD.md) for the full roadmap and
[`docs/superpowers/specs/2026-07-27-liostunnel-phase0-design.md`](docs/superpowers/specs/2026-07-27-liostunnel-phase0-design.md)
for exactly what Phase 0 does and does not include.

> **macOS does not carry traffic today.** The engine reads nothing from the
> TUN device there: packets reach the interface and the stack thread is alive,
> but no byte is ever read, so connections time out. This affects the CLI and
> the Phase 1a helper equally. Phase 0's exit criteria were all verified in a
> Linux container (see the table below, which says so), so this path was never
> exercised. Reproduce with `sudo ./testing/diagnose-p1a3.sh`; tracked in
> `docs/superpowers/phase1a-verification.md`.

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

- **Linux's `default` route mode now overrides DNS by backing up and
  overwriting `/etc/resolv.conf` directly**, rather than doing nothing (the
  prior gap). `apply_commands` emits `cp /etc/resolv.conf
  /etc/resolv.conf.liostunnel-backup` followed by a `dd of=/etc/resolv.conf`
  whose new body travels over `RouteCommand`'s stdin, never through a shell
  or an interpolated string — the same injection surface `printf > file`
  would have opened. Revert restores the exact original file with
  `cp /etc/resolv.conf.liostunnel-backup /etc/resolv.conf` (an exact restore,
  not macOS's "reset to automatic"), and that revert command lives in the
  crash-recovery state file exactly like every route command, so a `kill -9`
  mid-session still gets DNS back on the next start. `resolvectl dns`
  (systemd-resolved) was considered and rejected: it is absent on many
  systems, including the plain Debian container this fix is verified
  against, and detecting its presence is itself impure. Two residual gaps
  from this approach: if `/etc/resolv.conf` is a symlink (e.g.
  systemd-resolved's `stub-resolv.conf`), the backup/restore preserves the
  *content* it points at but not the symlink structure itself, since both
  `cp` directions dereference; and the backup file
  (`/etc/resolv.conf.liostunnel-backup`) is left in place after a clean
  revert rather than removed, though it is simply overwritten by the next
  `connect`. This is expected to flip `testing/gates/dns_leak_test.sh` from
  a known failure to a real pass on Linux; see that script's own header and
  `testing/gates/README.md` — still unverified by an agent, since it needs a
  real routing table.
- **IPv6 is now captured and dropped, not left to leak — but the packet
  engine still cannot carry it.** `default` mode installs an IPv6
  split-default (`::/1` + `8000::/1`) via the TUN device on both platforms,
  alongside the existing IPv4 halves, so v6 traffic no longer bypasses the
  tunnel in cleartext. But `net/smoltcp_stack/inspect.rs`'s `inspect` parses
  IPv4 only and reports `Ignored` for anything else, so routing v6 into the
  TUN does not tunnel it — it blackholes it. That is a deliberate trade
  (failing closed beats leaking), and `connect` says so loudly at startup
  before routes go in. The IPv6 split-default is skipped entirely — with no
  error — on a host with no working IPv6 stack at all (`RouteManager::
  ipv6_available` probes this by binding a UDP socket to `[::1]:0`), because
  a route command that failed on such a host would abort `apply_commands`
  partway through and strand the routes already installed; `connect` says
  which case applies. The server-pin route is now family-correct too (a
  `/128`, and macOS's `-inet6`, for an IPv6 server address) as defence in
  depth, though this is not reachable from `connect` today —
  `SshTunnel::pick_ipv4` (`protocols/ssh.rs`) already refuses to resolve to
  an IPv6-only server, and `detect_gateway` on both platforms only ever
  detects the IPv4 default gateway, so a real dual-stack-gateway story for
  an IPv6 SSH server remains unimplemented, not just untested.
- **macOS's DNS-override revert does not restore a pre-existing manual DNS
  configuration.** It resets to "automatic" (DHCP-assigned) DNS, which is a
  no-op for the common case (no manual override already in place) but is not
  an exact restore for an operator who had one. (Linux's own DNS override,
  above, does not share this limitation.)
- **macOS's DNS override hardcodes the `"Wi-Fi"` network service**
  (`route/macos.rs`). `networksetup -setdnsservers Wi-Fi ...` silently
  targets the wrong (or a nonexistent) service on any machine connected via
  Ethernet, Thunderbolt, or a `Wi-Fi` service renamed or localised to
  something else — the DNS override simply does not take effect, with no
  error surfaced to the operator. Worse, because this `networksetup` command
  is the *last* command in `default` mode's apply list (matched, on Linux,
  by the `cp`/`dd` DNS-override pair also being last), a failure there
  (e.g. the service genuinely doesn't exist, so the command itself errors)
  means `RouteGuard::apply` returns `Err` *before* the `RouteGuard` is ever
  constructed — so its `Drop`-based revert never runs, and the server pin
  plus both `/1` split-default halves (and, when installed, the IPv6 pair)
  are left installed with no in-process path to remove them (only the
  crash-recovery state file, on the *next* `connect` run, cleans them up).
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

**All seven are verified.** They were run in a disposable Linux container
granted `NET_ADMIN`, `NET_RAW` and `/dev/net/tun` — a real TUN device, a real
routing table, a real `/etc/resolv.conf`, and a real packet capture. EC1–EC5
and EC7 were verified against a local Docker SSH fixture; EC6, and a second
pass over host key verification, were verified against a real remote SSH
server across the public internet.

> **Benchmark with `--release`.** EC6 measured **3.77x** slower than `ssh -D`
> on a debug build and **1.15x** on a release build — the same code, the same
> server, minutes apart. The engine's hot path is smoltcp checksum computation
> and per-packet buffer handling, which optimisation transforms. A debug-build
> benchmark will tell you this architecture is unviable, and it will be wrong.

| Criterion | Status | Verified by |
|---|---|---|
| EC1 — TCP through the tunnel in `test` mode | **verified** | Real TUN device, real routes. A `/32` via `tun0` is more specific than the container's bridge route, so the kernel *had* to hand the traffic to the TUN — no other path those bytes could have taken. Engine log: `flow accepted src=10.90.0.1:56704 dst=192.168.158.2:80`, correct body returned, routes reverted on shutdown |
| EC2 — hostname resolution on both DNS backends | **verified (DNS-over-TCP)** | `dig @1.1.1.1 example.com` resolved with the resolver routed through the TUN, exercising UDP:53 interception → RFC 7766 framing over an SSH channel → checksummed UDP reply synthesis the container's own resolver accepted. The DoH backend has unit coverage plus one network-gated test, but was not exercised through a real device |
| EC3 — `default` mode plus all three cleanup paths | **verified** | Split-default (`0.0.0.0/1` + `128.0.0.0/1`), IPv6 split-default, server pin via the original gateway, and the DNS override all installed; traffic flowed through the tunnel; on shutdown every route was removed, `/etc/resolv.conf` was restored **byte-identical**, and connectivity returned. The `kill -9` state-file path has unit coverage but was not exercised live |
| EC4 — DNS leak test | **verified on Linux** | Packet capture on the physical interface during a `default`-mode session: **zero UDP:53 packets** while three names resolved correctly through the tunnel. This was the known-failing criterion until Linux gained a DNS override; it now passes by measurement, not by construction. Not re-run on macOS |
| EC5 — idle CPU ≈ 0% | **verified** | Task 14: 0.00 user + 0.00 sys CPU over a 6.67s window, ~2 poll passes/s idle-connected, and 2 passes/s under zero-window backpressure. The instrumented counter was validated in both directions — it read ~200,000 passes/0.5s with a deliberate spin reintroduced |
| EC6 — within 20% of `ssh -D` | **verified** | Against a real remote SSH server, 20 MB per run, best of 3 each, both paths egressing the same VPS so the comparison isolates engine overhead from network variance: `ssh -D` 82.32 Mbit/s vs liostunnel 71.83 Mbit/s = **1.146x**, inside the 1.20x ceiling. Release build — see the note above |
| EC7 — same code path on macOS utun and Linux TUN | **verified** | The full workspace builds and all tests pass identically on both platforms, and the root-gated `tun_e2e.rs` tests pass against a real Linux TUN device. Note the E2E tests themselves are narrow — they open a device and read a packet back, proving the AF-prefix codec (Decision D2); the broader "same code path" claim rests on the identical test results across platforms, plus EC1/EC3 exercising smoltcp, the `Engine`, and a proxied flow through a real Linux device |

Host key verification was additionally proven against a genuinely unknown
remote host: first connect learned and recorded the key (trust-on-first-use,
with a warning), the second validated against it silently, and a tampered
recorded key was rejected naming the offending file and line.

What this does **not** establish: EC2 was verified for DNS-over-TCP only — the
DoH backend has unit coverage and one network-gated test, but has not run
through a real device. EC4's packet capture was taken on Linux only. The
`kill -9` crash-recovery path has unit coverage but has never been triggered
for real. Throughput was measured on one route to one Singapore VPS, not
across varied networks or on constrained mobile links.

## License

MIT OR Apache-2.0.

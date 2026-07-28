# Phase 0 release gates

Each script here maps to an exit criterion in the design spec §13 that
**cannot be verified without root, a real routing table, and (for EC6) a
real SSH server** — properties a sandboxed development session must not
touch. They are written for a human operator to run, on their own machine,
after reading what each one does.

| Script | Criterion | Needs |
|---|---|---|
| `dns_leak_test.sh` | EC4 — no DNS escapes the tunnel | root, tunnel up in `default` mode, `tcpdump` |
| `idle_cpu_test.sh` | EC5 — the poll loop sleeps | a connected, idle tunnel |
| `throughput_test.sh` | EC6 — within 20% of `ssh -D` | a real SSH server, `ssh`/`curl` |

EC1 (TCP in `test` mode), EC2 (hostname resolution on both DNS backends),
EC3 (`default` mode plus all three cleanup paths), and EC7 (same code path
on macOS `utun` and Linux TUN) are verified by the manual procedures and
inspection recorded in the Task 17/20/21/22 reports under
`.superpowers/sdd/`, plus `crates/liostunnel-core/tests/tun_e2e.rs` for EC7 —
not by a script in this directory. `tun_e2e.rs`'s two tests are `#[ignore]`d
and must be run explicitly, as root, against a real device:

```bash
# macOS
sudo -E cargo test -p liostunnel-core --test tun_e2e -- --ignored
# Linux
docker run --rm -v "$PWD:/w" -w /w --cap-add=NET_ADMIN --device /dev/net/tun \
  rust:1.93 cargo test -p liostunnel-core --test tun_e2e -- --ignored
```

## Running the gates

All three scripts:

- print, in their own output, what a PASS actually means — not just an exit
  code;
- fail loudly and specifically rather than exiting 0 because a measurement
  silently produced nothing (e.g. `dns_leak_test.sh` refuses to call zero
  captured packets a PASS unless it also proved DNS resolution traffic was
  actually generated during the capture window; `throughput_test.sh` checks
  both downloads actually completed and transferred a non-trivial amount of
  data before trusting either timing);
- clean up after themselves on every exit path, including failure and
  Ctrl-C (`trap ... EXIT INT TERM`): no capture process or temp file is left
  behind, and no route or interface is touched by any of them at all —
  routing changes are always the operator's own action, driven from a
  second shell, never something these scripts do on your behalf.

```bash
sudo ./testing/gates/dns_leak_test.sh en0        # or eth0 on Linux
./testing/gates/idle_cpu_test.sh "$(pgrep -f 'liostunnel.*connect')" 300
./testing/gates/throughput_test.sh me@myserver https://speed.hetzner.de/100MB.bin
```

Record the measured idle-CPU percentage and throughput ratio in the commit
that closes Phase 0 — EC5 and EC6 are the architecture's evidence for the
mobile phases, and a number nobody wrote down is a number nobody can compare
against later.

## Known gaps that bear directly on `dns_leak_test.sh` (EC4)

These are properties of the tunnel itself, not of the script — recorded here
so a FAIL is legible instead of mysterious, and in `README.md`'s own
Limitations section at the repository root:

- **Linux's `default` route mode installs no DNS override at all.**
  `/etc/resolv.conf` still points at whatever LAN resolver was configured
  before `connect` ran, and that resolver is reachable via a connected route
  more specific than either `0.0.0.0/1` half the tunnel installs — so DNS
  genuinely leaves the machine outside the tunnel on Linux today. Running
  `dns_leak_test.sh` on Linux is **expected to FAIL** for exactly this
  reason; the script prints an explicit note about this before it starts
  capturing, so the failure isn't mistaken for a bug in the gate itself.
- **IPv6 is entirely uncovered.** Only the IPv4 split-default
  (`0.0.0.0/1` + `128.0.0.0/1`) is installed in `default` mode; `::/0` is
  untouched, so all IPv6 traffic — including IPv6-only DNS — bypasses the
  tunnel. `dns_leak_test.sh`'s capture filter (`port 53`) is
  address-family-agnostic, so it **will** catch an IPv6 leak; that's the
  gate doing its job, not a false positive.

Both gaps are current, real limitations of Phase 0 as implemented through
Task 21, not something introduced by this task's gate scripts.

## What was and was not run when these gates were written

The scripts were written, `bash -n`-syntax-checked, and linted clean with
`shellcheck` (`shellcheck testing/gates/*.sh` — exit 0, no warnings on any of
the three). None of the three was ever executed end-to-end: doing so would
mean running as root, opening a real TUN device, mutating this machine's
routing table, and/or connecting to a real SSH server, all of which are
outside what a sandboxed agent session should do. See the Task 22 report
(`.superpowers/sdd/task-22-report.md`) for the full executed/not-executed
accounting.

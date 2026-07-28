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

- **Linux's `default` route mode now backs up and overwrites
  `/etc/resolv.conf` directly** (`cp` for the backup, then a `dd` write over
  stdin — no shell, no interpolated resolver strings) rather than doing
  nothing, closing what used to be an unconditional failure here. Revert
  restores the exact original file, and that revert command rides in the
  crash-recovery state file like any route command, so a `kill -9` still
  restores DNS on the next start. `dns_leak_test.sh` prints a note on Linux
  reflecting this; running it is now expected to **PASS**, but that has not
  yet been confirmed against a real routing table by an agent — see
  `README.md`'s Limitations section and
  `.superpowers/sdd/dns-ipv6-fixes-report.md` for the mechanism and its
  residual edge cases (a symlinked `/etc/resolv.conf`, and the leftover
  backup file after a clean revert).
- **IPv6 is now routed into the TUN device in `default` mode on both
  platforms** (`::/1` + `8000::/1`, skipped only when the host has no
  working IPv6 stack), rather than left completely untouched — but the
  packet engine still cannot carry IPv6 (`net/smoltcp_stack/inspect.rs`
  parses IPv4 only), so that traffic is blackholed, not tunnelled.
  `dns_leak_test.sh`'s capture filter (`port 53`) is address-family-agnostic,
  so it will still catch an IPv6 DNS leak if the blackhole ever fails to
  apply (e.g. the host-has-no-IPv6 skip guessed wrong) — that would now be a
  real FAIL, not an expected one.

Both gaps are current, real properties of Phase 0 as implemented, not
something introduced by this task's gate scripts. The fixes above have only
been verified through pure unit tests (command construction, not real routes
or a real network); running these gates against a live system is still
unverified by an agent.

## What was and was not run when these gates were written

The scripts were written, `bash -n`-syntax-checked, and linted clean with
`shellcheck` (`shellcheck testing/gates/*.sh` — exit 0, no warnings on any of
the three). None of the three was ever executed end-to-end: doing so would
mean running as root, opening a real TUN device, mutating this machine's
routing table, and/or connecting to a real SSH server, all of which are
outside what a sandboxed agent session should do. See the Task 22 report
(`.superpowers/sdd/task-22-report.md`) for the full executed/not-executed
accounting.

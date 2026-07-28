# Phase 1a — exit criteria verification

**Date:** 2026-07-28
**Branch:** `phase1a-implementation`
**Reproduce:** `./testing/verify-linux.sh` (Linux, no host privilege needed)
and `sudo ./testing/verify-phase1a.sh` (macOS)

Both platforms run the *same* script. Two scripts that each decided what
"verified" meant would drift, and a criterion that means something different
per platform is worth less than one that means nothing.

## Result

| | Linux | macOS |
|---|---|---|
| P1a-1 — profiles parsed through FRB, not Dart | ✅ | ✅ |
| P1a-2 — connect brings up a real tunnel and traffic flows | ✅ | ✅ in use, script re-run pending |
| P1a-3 — stats update live while traffic moves | ✅ | ✅ in use, script re-run pending |
| P1a-4 — the tunnel outlives the UI | ✅ | ✅ |
| P1a-5 — an unauthorized uid is refused | ✅ | ✅ |
| P1a-6 — a secret the caller does not own is refused | ✅ | ✅ |
| P1a-7 — a version-mismatched client fails cleanly | ✅ | ✅ |

**Linux: 14 checks, 0 failures.**

macOS was 12 of 14 when this was first written, with P1a-2 and P1a-3 blocked
by the double-framing defect described below. That defect is fixed, and the
tunnel has since been observed carrying real traffic on macOS through the app
— a live SSH session to a remote server, with the helper logging DNS activity
over it. **The verification script has not been re-run there since the fix**,
so those two rows are reported as observed rather than as measured. Run
`sudo ./testing/verify-phase1a.sh` to close them properly.

P1a-1 is covered by the automated suites rather than this script: 9 Dart tests
parse real profile documents through the FFI, and the widget tests render what
comes back. No profile schema is implemented in Dart.

## P1a-2 and P1a-3 — the evidence

Flat counters cannot distinguish "traffic bypassed the tunnel" from "traffic
entered the tunnel and vanished", so the run captures on the tunnel device
while it fetches:

```
10.90.0.1.47022 > 192.168.158.3.80: Flags [S],  seq 1074111891
192.168.158.3.80 > 10.90.0.1.47022: Flags [S.], seq 986182308, ack 1074111892
10.90.0.1.47022 > 192.168.158.3.80: Flags [P.], length 117: HTTP: GET / HTTP/1.1
192.168.158.3.80 > 10.90.0.1.47022: Flags [P.], length 231: HTTP: HTTP/1.1 200 OK

stats after traffic: {'bytes_up': 468, 'bytes_down': 1156, ...}
```

Source `10.90.0.1` is the TUN address, so those packets can only have crossed
the tunnel. The target is routed as a `/32`, which beats the container's `/24`
by longest prefix, so the kernel has no other path for it.

**The first attempt at this proved nothing.** It targeted the Docker network,
for which the host already had a route via its own bridge — ours never won,
the fetch succeeded anyway, and a green result would have meant nothing. The
counters caught it. A `/32` with no competing route is what makes success
attributable.

## P1a-5 and P1a-6 — the security boundary

```
P1a-5  REFUSED:PermissionError: [Errno 13] Permission denied
P1a-6  {"kind":"secret_not_permitted",
        "message":"secret file /tmp/lios-verify/rootkey is not owned by uid 1500"}
       no TUN device created
       no route installed
P1a-6b {"kind":"bad_request",
        "message":"env-var secrets are not available through the helper"}
```

The bait for P1a-6 is a root-owned `0600` file created by the run itself.
System files are unusable here: `/etc/master.passwd` does not exist on Linux
and `/etc/shadow` is mode `0640` on Debian, so each is refused for the wrong
reason — a missing file or a loose mode — without ever reaching the ownership
check the criterion is about. An earlier version of this script passed exactly
that way.

P1a-6b covers a hole the plan did not: `SecretRef::Env` resolves against the
*process* environment, and this process is root, so an env reference could
only ever name something that was never the caller's.

## Defects this verification found

**1. Routes were reverted after the stack was torn down.** Fixed
(`ca200d6`). The revert ran after the TUN device was destroyed, so
`route delete -net CIDR -interface utunN` failed with `bad address: utunN`
every single time; cleanup happened only as a side effect of the OS
reclaiming an interface's routes. `liostunnel-cli` still has this ordering
and still logs the failure — out of scope here, worth a follow-up.

I first diagnosed this as a syntax bug in `route/macos.rs` and was wrong.
`testing/probe-route-delete.sh` showed the syntax is correct when the
interface exists. The probe cost ten seconds; the wrong diagnosis nearly cost
a change to a file that needed none.

**2. `bytes_up`/`bytes_down` were permanently zero.** Fixed (`91e1307`).
`StatsHandle::load` built `ConnectionStats` with `..Default::default()` while
`SshTunnel` counted the bytes correctly — two counter sets, and the reachable
one had no bytes. Spec §8.2 already ruled that an unpopulated counter must not
be reported as a measurement; these were left in on the assumption they
worked. No unit test could have caught it: every mock reported zero and zero
was what the assertions expected.

**3. macOS: the engine read nothing from the TUN device.** FIXED (`231b8ef`).
`tun-rs` builds its macOS device with `ignore_packet_information: true`, so it
already strips the four-byte utun address-family header on `recv` and prepends
it on `send` — and this crate did it a second time. The extra strip ate the
first four bytes of every inbound IP header, smoltcp discarded the result
silently, and the extra prefix on write produced a double header the kernel
rejected. Packets reached the interface, the stack thread stayed alive, every
counter read zero.

It was *not* introduced by this slice — Phase 0's own CLI failed identically,
which is what ruled out the new helper:

```
helper: SYN on utun9, retransmitted 5x, engine counters flat, curl times out
CLI:    same profile, same CIDR, run as root — curl http_code=000, 0 flows
```

Phase 0 claims all seven of its exit criteria verified, but its own table
records that they ran **in a Linux container** — so the macOS packet path was
never exercised, and a bug that made the platform carry nothing at all went
unnoticed through an entire phase. That is the lesson worth keeping from this,
more than the bug itself.

`sudo ./testing/diagnose-p1a3.sh` still reproduces the measurement: it
captures on the TUN device and then runs the same connection through the CLI
for comparison.

## Defects in the verification itself

Recorded because they are the same class the project keeps producing, and
three of them reported green over a real failure:

- **The tally counted a printed FAIL as two passes.** The traffic block only
  exited non-zero when *connect* failed, so a run that printed
  `FAIL P1a-3` summarised as `14 passed, 0 failed`. A harness that reports
  green over a visible failure is worse than no harness.
- **The teardown check grepped for the TUN address only**, so it passed while
  every route revert was failing. It now checks the routed CIDR, any tunnel
  interface, *and* the helper log for revert errors.
- **P1a-5's client could not start.** `sudo -u nobody python3` died on
  `getcwd` in a directory it could not read, so it never reached the socket —
  reported as a security failure that had not been tested at all.
- **`stat -f` means "filesystem status" on Linux** and succeeds, so a
  `stat -f ... || stat -c ...` fallback never fired and a wall of filesystem
  statistics was compared against a uid.

## Scope notes

The run does **not** install a launchd or systemd daemon: the helper runs on a
temporary socket and is killed at the end. The installer's own refusal paths
are verified separately — not root, `SUDO_UID` unset, `SUDO_UID=0`, missing
binary.

It does **not** touch the default route. Route mode is `test` with a single
CIDR, and the run records the default route and interface list before and
after, failing loudly if either changed. Both were unchanged on both
platforms.

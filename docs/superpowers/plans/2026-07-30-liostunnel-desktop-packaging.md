# Desktop Packaging and First-Launch Install Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One download per platform that is a working LiosTunnel — the app with the helper embedded inside it, installed on first launch through the OS's own password dialog — built by CI on every push to `main`.

**Architecture:** The helper binary, its unit file and the install script ship inside the app bundle. On startup, if the socket is absent, the app runs the install script under `osascript` (macOS) or `pkexec` (Linux), which raise the OS authorization dialog. Assembly lives in a script CI calls, not in YAML, so a wrong bundle is debugged locally.

**Tech Stack:** Bash, GitHub Actions, Flutter desktop (macOS + Linux), cargokit.

## Global Constraints

Every task's requirements implicitly include this section.

- **The uid baked into the unit file is the human's, never the elevated process's.** `install-helper.sh` must refuse uid 0 and must refuse when it cannot tell. There is deliberately **no fallback to `id -u`** — under `sudo`, `pkexec` and `osascript` alike that answer is 0, and a helper that authorizes root has no boundary at all. This is PKG-3 and it is the criterion this phase turns on.
- **No signing, no CI secrets, no Apple Developer account.** `SMAppService` is therefore unavailable; `osascript`/`pkexec` are the unsupported-but-working route.
- **The install attempt is made at most once per process launch.** `HelperClient` retries an absent socket on a timer; prompting from that would re-raise the password dialog every few seconds after a cancel, which the user cannot escape without force-quitting.
- **The install runs only for `HelperUnavailable`** (ENOENT — never installed), never for `HelperForbidden` (EACCES — installed for another user).
- **Every path is quoted before interpolation**, for the shell and again for AppleScript. `/Applications/` is not the only place an app lands, and a space breaks `do shell script`.
- **TDD, strictly.** Failing test first, run it, confirm it fails for the *expected* reason, then implement. Report RED and GREEN transcripts.
- **A test that passes must be shown failing against the defect it names.** On the previous branch a plan-specified A/B failed to discriminate in four of five tasks, twice on that task's own deliverable test. When an A/B does not reproduce, that is a finding to report, not a step to skip.
- `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check` and `flutter analyze` must pass. **Check clippy's exit code without piping** — a pipe masks it, which is how a failing commit was made once.
- **Dart changes require `./testing/build-ffi-for-tests.sh` before `flutter test`.**
- **Commit messages go through a file with `git commit -F`** — backticks inside `-m` are command substitution and have run a destructive command in this repo once.
- No test may run a real `install`, `launchctl`, `systemctl`, `osascript` or `pkexec`, or write to the operator's real `~/.liostunnel`.

## File structure

| File | Responsibility |
|---|---|
| `packaging/install-helper.sh` | uid from three sources, binary from two locations |
| `packaging/make-bundle.sh` | assemble `dist/liostunnel-<os>-<sha>.tar.gz` |
| `testing/verify-bundle.sh` | prove the archive contains a working, correct bundle |
| `app/lib/services/helper_install.dart` | resolve the bundled script, build the command, run it privileged |
| `app/lib/services/connection_model.dart` | the `installing` state and its wording |
| `app/lib/screens/connection.dart` | the panel: command text and retry |
| `app/lib/main.dart` | run the install once, on the right failure |
| `.github/workflows/ci.yml` | the `package` job |

**Milestones.** A (Tasks 1–2) is the bundle. B (Task 3) is CI. C (Tasks 4–5) is first launch.

---

### Task 1: `install-helper.sh` learns the uid three ways

**Files:**
- Modify: `packaging/install-helper.sh`
- Create: `testing/verify-install-script.sh`

**Interfaces:**
- Produces: `install-helper.sh [--uid N]`, honouring `LIOS_UID`, `SUDO_UID`, `PKEXEC_UID` in that order.

**Why this is first and why it matters most.** The script bakes an authorized uid into a root-owned unit file. Neither `osascript` nor `pkexec` sets `SUDO_UID` — `pkexec` sets `PKEXEC_UID`, `osascript` sets neither and runs with `USER=root`. A script reading only `SUDO_UID` either dies on the new path, or, if someone "fixes" it by falling back to the current user, silently authorizes **uid 0**.

- [ ] **Step 1: Write the failing test**

Create `testing/verify-install-script.sh`:

```bash
#!/usr/bin/env bash
#
# Proves install-helper.sh authorizes the right uid and refuses the wrong
# ones, without root and without installing anything.
#
#     ./testing/verify-install-script.sh
#
# The privileged commands are stubbed on PATH. A stub that is never called
# leaves no marker, so "did it reach the install step" is observable.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
pass=0; fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
bad() { echo "  FAIL  $*"; fail=$((fail+1)); }

stub_dir="$(mktemp -d)"
out="$stub_dir/marker"
trap 'rm -rf "$stub_dir"' EXIT
for cmd in install launchctl systemctl chown chmod sed; do
  cat > "$stub_dir/$cmd" <<STUB
#!/usr/bin/env bash
echo "$cmd \$*" >> "$out"
exit 0
STUB
  chmod 755 "$stub_dir/$cmd"
done
# `sed` is stubbed above but the script uses it to write the unit file; give
# it back its real behaviour so the uid substitution is observable.
cat > "$stub_dir/sed" <<STUB
#!/usr/bin/env bash
echo "sed \$*" >> "$out"
exec /usr/bin/sed "\$@"
STUB
chmod 755 "$stub_dir/sed"

# A fake helper binary beside a copy of the script, i.e. the bundle layout.
bundle="$stub_dir/bundle"; mkdir -p "$bundle"
cp "$repo/packaging/install-helper.sh" "$bundle/"
cp "$repo/packaging/liostunnel-helper.plist" "$bundle/" 2>/dev/null || true
cp "$repo/packaging/liostunnel-helper.service" "$bundle/" 2>/dev/null || true
printf '#!/bin/sh\necho fake\n' > "$bundle/liostunnel-helper"
chmod 755 "$bundle/liostunnel-helper"

run() {  # run() <expect-exit> <label> [args...]
  local want="$1" label="$2"; shift 2
  : > "$out"
  local o rc
  o="$(cd "$bundle" && PATH="$stub_dir:$PATH" bash ./install-helper.sh "$@" 2>&1)"
  rc=$?
  if [ "$rc" -eq "$want" ]; then ok "$label"; else
    bad "$label (exit $rc, wanted $want)"; printf '        %s\n' "$o"
  fi
}

echo "=== the uid must come from a human, never the elevated process ==="

# PKG-3. Each of the three sources reaches the install step.
: > "$out"
(cd "$bundle" && PATH="$stub_dir:$PATH" LIOS_UID=501 bash ./install-helper.sh >/dev/null 2>&1)
grep -q "501" "$out" && ok "LIOS_UID reaches the unit file" || bad "LIOS_UID did not reach the unit file"

: > "$out"
(cd "$bundle" && PATH="$stub_dir:$PATH" SUDO_UID=502 bash ./install-helper.sh >/dev/null 2>&1)
grep -q "502" "$out" && ok "SUDO_UID reaches the unit file" || bad "SUDO_UID did not reach the unit file"

: > "$out"
(cd "$bundle" && PATH="$stub_dir:$PATH" PKEXEC_UID=503 bash ./install-helper.sh >/dev/null 2>&1)
grep -q "503" "$out" && ok "PKEXEC_UID reaches the unit file" || bad "PKEXEC_UID did not reach the unit file"

: > "$out"
(cd "$bundle" && PATH="$stub_dir:$PATH" bash ./install-helper.sh --uid 504 >/dev/null 2>&1)
grep -q "504" "$out" && ok "--uid reaches the unit file" || bad "--uid did not reach the unit file"

echo
echo "=== and the two refusals must survive all of it ==="

# THE assertion of this file. A helper that authorizes uid 0 accepts a root
# client, which is the entire boundary gone.
run 1 "uid 0 is refused (LIOS_UID)"   --uid 0
: > "$out"
o="$(cd "$bundle" && PATH="$stub_dir:$PATH" SUDO_UID=0 bash ./install-helper.sh 2>&1)"
[ $? -ne 0 ] && ok "uid 0 is refused (SUDO_UID)" || bad "uid 0 was ACCEPTED via SUDO_UID"
: > "$out"
o="$(cd "$bundle" && PATH="$stub_dir:$PATH" PKEXEC_UID=0 bash ./install-helper.sh 2>&1)"
[ $? -ne 0 ] && ok "uid 0 is refused (PKEXEC_UID)" || bad "uid 0 was ACCEPTED via PKEXEC_UID"

# No source at all: must die, NOT fall back to the current user.
: > "$out"
o="$(cd "$bundle" && env -u SUDO_UID -u PKEXEC_UID -u LIOS_UID \
      PATH="$stub_dir:$PATH" bash ./install-helper.sh 2>&1)"
if [ $? -ne 0 ] && [ ! -s "$out" ]; then
  ok "no uid available is refused, and nothing was installed"
else
  bad "ran with no uid available — it must not guess"
fi

echo
echo "=== the binary is found beside the script, and in a checkout ==="
: > "$out"
(cd "$bundle" && PATH="$stub_dir:$PATH" LIOS_UID=501 bash ./install-helper.sh >/dev/null 2>&1)
grep -q "$bundle/liostunnel-helper" "$out" \
  && ok "the bundled binary is used" || bad "did not install the binary beside the script"

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
```

- [ ] **Step 2: Run it to verify it fails**

Run: `chmod +x testing/verify-install-script.sh && ./testing/verify-install-script.sh`
Expected: FAIL — `--uid` is an unknown argument, `LIOS_UID`/`PKEXEC_UID` are not read, and the bundled binary is not found.

- [ ] **Step 3: Parse `--uid` and widen the uid sources**

In `packaging/install-helper.sh`, replace the `uid=` block:

```sh
# `--uid N` is how the app passes it: the app knows its own uid, and neither
# osascript nor pkexec preserves the one sudo would have set.
while [ $# -gt 0 ]; do
  case "$1" in
    --uid) LIOS_UID="${2:-}"; shift 2 ;;
    --uid=*) LIOS_UID="${1#--uid=}"; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

# Three ways in, one rule: the uid to authorize is the HUMAN's, never the
# elevated process's.
#   LIOS_UID    --uid, from the app
#   SUDO_UID    set by sudo
#   PKEXEC_UID  set by pkexec
# There is deliberately NO fallback to `id -u`. Under sudo, pkexec and
# osascript alike that answer is 0, and a helper that authorizes root accepts
# a root client -- which is the whole boundary this design exists to draw.
uid="${LIOS_UID:-${SUDO_UID:-${PKEXEC_UID:-}}}"
[ -n "$uid" ] || die "cannot tell which account to authorize; run with sudo, or pass --uid N"
case "$uid" in ''|*[!0-9]*) die "not a uid: $uid" ;; esac
[ "$uid" -ne 0 ] || die "refusing to authorize uid 0; the helper must serve an unprivileged user"
user="$(id -un "$uid" 2>/dev/null || echo "uid $uid")"
```

Delete the old two lines that read `SUDO_UID` and its `die`, and the old `[ "$uid" -ne 0 ]` line, so there is one of each.

- [ ] **Step 4: Widen the binary lookup**

Replace the `src=` block:

```sh
# Beside this script in a bundle, under target/release in a checkout. One
# script serving both beats a second copy free to drift from the first --
# the same argument the profile format makes for having one parser.
#
# Beside-the-script wins: unpacking a bundle inside a checkout should use the
# bundle's binary, not whatever is stale in target/.
if [ -f "$here/$BINARY" ]; then
  src="$here/$BINARY"
elif [ -f "$repo/target/release/$BINARY" ]; then
  src="$repo/target/release/$BINARY"
else
  die "no helper binary beside this script or at $repo/target/release/$BINARY — in a checkout, run: cargo build --release -p liostunnel-helper"
fi
```

- [ ] **Step 5: Run it to verify it passes**

Run: `./testing/verify-install-script.sh`
Expected: `=== 9 passed, 0 failed ===`

- [ ] **Step 6: A/B each assertion**

Run each, capture the failure, revert:

| Change | Assertion that must fail |
|---|---|
| `uid="${LIOS_UID:-${SUDO_UID:-${PKEXEC_UID:-$(id -u)}}}"` | `no uid available is refused` |
| delete the `-ne 0` guard | all three `uid 0 is refused` |
| drop `PKEXEC_UID` from the chain | `PKEXEC_UID reaches the unit file` |
| put `target/release` first in the lookup | `the bundled binary is used` (run it inside a checkout with a built binary) |

- [ ] **Step 7: Commit**

```bash
git add packaging/install-helper.sh testing/verify-install-script.sh
git commit -F /tmp/msg-p1.txt
```

`/tmp/msg-p1.txt`:

```
feat: let the installer learn the uid from sudo, pkexec or the app

The uid baked into the unit file is the authorization boundary: a helper that
authorizes uid 0 accepts a root client, which is the whole thing the design
exists to prevent. It was read from SUDO_UID alone.

Neither of the paths the app will use sets that. pkexec sets PKEXEC_UID;
osascript with administrator privileges sets neither and runs with USER=root.
So the script either dies on the new path, or -- if the guard were relaxed to
"fall back to the current user" -- authorizes root, silently, on exactly the
path being added.

Three sources in, both refusals unchanged, and deliberately no fallback to
`id -u`: under sudo, pkexec and osascript alike that answer is 0.
```

---

### Task 2: `make-bundle.sh` and its verifier

**Files:**
- Create: `packaging/make-bundle.sh`, `testing/verify-bundle.sh`

**Interfaces:**
- Consumes: `install-helper.sh [--uid N]` (Task 1).
- Produces: `dist/liostunnel-<os>-<sha>.tar.gz`, unpacking to a directory containing the app bundle with `helper/` inside it.

- [ ] **Step 1: Write `make-bundle.sh`**

```bash
#!/usr/bin/env bash
#
# Assembles the release archive. Assumes both builds have already run:
#
#     cargo build --release -p liostunnel-helper
#     cd app && flutter build macos --release     # or: flutter build linux --release
#     ./packaging/make-bundle.sh
#
# Assembly is separate from building so a failed build is never reported as a
# packaging problem -- and so this runs on the machine that is confused,
# rather than only inside a CI runner.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
sha="$(git -C "$repo" rev-parse --short HEAD)"
helper="$repo/target/release/liostunnel-helper"

die() { echo "error: $*" >&2; exit 1; }

[ -f "$helper" ] || die "no helper at $helper — run: cargo build --release -p liostunnel-helper"

case "$(uname -s)" in
  Darwin)
    os=macos
    app="$(find "$repo/app/build/macos/Build/Products/Release" -maxdepth 1 -name '*.app' | head -1)"
    [ -n "$app" ] || die "no .app under app/build/macos/… — run: cd app && flutter build macos --release"
    unit=liostunnel-helper.plist
    ;;
  Linux)
    os=linux
    app="$(find "$repo/app/build/linux" -maxdepth 3 -type d -name bundle | head -1)"
    [ -n "$app" ] || die "no bundle under app/build/linux/… — run: cd app && flutter build linux --release"
    unit=liostunnel-helper.service
    ;;
  *) die "unsupported platform $(uname -s)" ;;
esac

name="liostunnel-$os-$sha"
dist="$repo/dist"
stage="$dist/$name"
# A partial dist/ from an earlier failed run must never be uploaded as if it
# were current.
rm -rf "$dist"
mkdir -p "$stage"

if [ "$os" = macos ]; then
  cp -R "$app" "$stage/"
  inner="$stage/$(basename "$app")/Contents/Resources/helper"
else
  cp -R "$app" "$stage/liostunnel"
  inner="$stage/liostunnel/helper"
fi

# The helper lives INSIDE the app, so app and helper cannot be separated and
# therefore cannot mismatch. PROTOCOL_VERSION is a wire contract between them.
mkdir -p "$inner"
install -m 0755 "$helper" "$inner/liostunnel-helper"
install -m 0755 "$here/install-helper.sh" "$inner/install-helper.sh"
install -m 0755 "$here/uninstall-helper.sh" "$inner/uninstall-helper.sh"
# Only this platform's unit file. Shipping both would put a systemd unit in a
# macOS archive, which reads as an oversight rather than symmetry.
install -m 0644 "$here/$unit" "$inner/$unit"

cat > "$stage/README.txt" <<EOF
LiosTunnel — $os — $sha

The app installs its privileged helper on first launch: it will raise your
operating system's password dialog. Nothing is installed until you approve it.
EOF

if [ "$os" = macos ]; then
  cat >> "$stage/README.txt" <<'EOF'

macOS refuses a downloaded unsigned app until you allow it once:

    xattr -dr com.apple.quarantine LiosTunnel.app

or right-click the app and choose Open. This happens before first launch, so
no amount of in-app polish removes it. This build is arm64 only.
EOF
fi

cat >> "$stage/README.txt" <<'EOF'

To install the helper by hand instead, from inside the app bundle:

    sudo ./helper/install-helper.sh

Run it from the account that will use the app: it bakes that uid into a
root-owned unit file, and refuses to run as a root login or to authorize uid 0.

The app and the helper in this archive are one build. Mixing versions fails at
the handshake with `version_mismatch`.

Remove it with: sudo ./helper/uninstall-helper.sh
EOF

tar -C "$dist" -czf "$dist/$name.tar.gz" "$name"
echo "$dist/$name.tar.gz"
```

- [ ] **Step 2: Write `verify-bundle.sh`**

```bash
#!/usr/bin/env bash
#
# Proves the archive make-bundle.sh produced is a bundle that would work.
#
#     ./testing/verify-bundle.sh dist/liostunnel-macos-abc1234.tar.gz
#
set -uo pipefail
archive="${1:-}"
[ -f "$archive" ] || { echo "usage: $0 <archive.tar.gz>"; exit 1; }
pass=0; fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
bad() { echo "  FAIL  $*"; fail=$((fail+1)); }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
tar -C "$tmp" -xzf "$archive" || { echo "cannot unpack"; exit 1; }
root="$(find "$tmp" -maxdepth 1 -mindepth 1 -type d | head -1)"

case "$(uname -s)" in
  Darwin)
    appexe="$(find "$root" -maxdepth 4 -path '*/Contents/MacOS/*' -type f | head -1)"
    inner="$(dirname "$(find "$root" -maxdepth 5 -name install-helper.sh | head -1)")"
    want_unit=liostunnel-helper.plist; other_unit=liostunnel-helper.service
    ;;
  *)
    appexe="$root/liostunnel/liostunnel"
    inner="$root/liostunnel/helper"
    want_unit=liostunnel-helper.service; other_unit=liostunnel-helper.plist
    ;;
esac

[ -x "$appexe" ] && ok "the app executable is present and executable" \
                 || bad "no executable app at $appexe"
[ -f "$inner/$want_unit" ] && ok "this platform's unit file is present" \
                           || bad "missing $want_unit"
[ ! -f "$inner/$other_unit" ] && ok "the other platform's unit file is absent" \
                              || bad "$other_unit should not be in a $(uname -s) archive"
for f in liostunnel-helper install-helper.sh uninstall-helper.sh; do
  [ -x "$inner/$f" ] && ok "$f is present and executable" || bad "missing or not executable: $f"
done
[ -f "$root/README.txt" ] && ok "README.txt is present" || bad "missing README.txt"

# A binary that runs on this platform, not a placeholder or one built for the
# wrong arch. clap already provides --version.
v="$("$inner/liostunnel-helper" --version 2>&1)"
if [ $? -eq 0 ] && [ "${v#liostunnel-helper }" != "$v" ]; then
  ok "the bundled helper runs: $v"
else
  bad "the bundled helper did not run: $v"
fi

# The install script must reach the install step from inside the bundle,
# without root and without installing anything.
stub="$(mktemp -d)"
for cmd in install launchctl systemctl chown chmod; do
  printf '#!/usr/bin/env bash\nexit 0\n' > "$stub/$cmd"; chmod 755 "$stub/$cmd"
done
if (cd "$inner" && PATH="$stub:$PATH" bash ./install-helper.sh --uid 501 >/dev/null 2>&1); then
  ok "install-helper.sh finds the bundled binary and reaches the install step"
else
  bad "install-helper.sh failed from inside the bundle"
fi
rm -rf "$stub"

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
```

- [ ] **Step 3: Run both against a real build**

```bash
chmod +x packaging/make-bundle.sh testing/verify-bundle.sh
cargo build --release -p liostunnel-helper
cd app && flutter build macos --release && cd ..
./packaging/make-bundle.sh
./testing/verify-bundle.sh dist/liostunnel-macos-*.tar.gz
```
Expected: the bundle path is printed, then `=== 8 passed, 0 failed ===`.

**If `flutter build macos` fails, that is this task's finding, not a step to work around.** Report the error verbatim.

- [ ] **Step 4: A/B each assertion**

| Change to `make-bundle.sh` | Assertion that must fail |
|---|---|
| install **both** unit files | `the other platform's unit file is absent` |
| `install -m 0644` the helper binary | `liostunnel-helper is present and executable` |
| write a zero-byte `liostunnel-helper` | `the bundled helper runs` |
| skip copying `install-helper.sh` | `install-helper.sh is present`, and the reaches-install-step check |

- [ ] **Step 5: Commit**

```bash
git add packaging/make-bundle.sh testing/verify-bundle.sh
git commit -F /tmp/msg-p2.txt
```

`/tmp/msg-p2.txt`:

```
feat: assemble a release bundle with the helper inside the app

The helper, its unit file and the install script go inside the app bundle, so
app and helper are one file built from one commit and cannot mismatch --
PROTOCOL_VERSION is a wire contract between them and a mismatched pair fails
at the handshake.

Assembly is a script CI calls rather than steps CI owns. A wrong bundle is
then debugged on the machine that is confused, instead of by pushing commits
at a runner and waiting.

verify-bundle.sh runs the bundled helper with --version rather than checking
the file exists: a zero-byte placeholder, or a binary built for the wrong
architecture, both pass a stat and fail a user.
```

---

### Task 3: The CI packaging job

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `packaging/make-bundle.sh`, `testing/verify-bundle.sh` (Task 2).

- [ ] **Step 1: Add the job**

Append to `.github/workflows/ci.yml`:

```yaml
  # The first thing in this workflow that runs `flutter build`. `flutter test`
  # exercises none of cargokit, CMake, the Xcode project or the podspec, so a
  # change that breaks the macOS bundle passed every other check here.
  package:
    runs-on: ${{ matrix.os }}
    strategy:
      # A macOS failure should still produce the Linux archive: the two share
      # nothing but the assembly script.
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: "1.93"
      - uses: Swatinem/rust-cache@v2
      - uses: subosito/flutter-action@v2
        with:
          channel: stable
      # `flutter build linux` needs these, and without them it fails with a
      # CMake error that reads like a Flutter bug rather than a missing
      # package.
      - name: linux build dependencies
        if: runner.os == 'Linux'
        run: sudo apt-get update && sudo apt-get install -y ninja-build libgtk-3-dev
      - name: build the helper
        run: cargo build --release -p liostunnel-helper
      - name: flutter pub get
        run: flutter pub get
        working-directory: app
      # cargokit compiles the FFI crate during this, which is why the Rust
      # toolchain is installed above rather than only for the step before.
      - name: build the app
        run: flutter build ${{ runner.os == 'macOS' && 'macos' || 'linux' }} --release
        working-directory: app
      - name: assemble the bundle
        run: ./packaging/make-bundle.sh
      - name: verify the bundle
        run: ./testing/verify-bundle.sh dist/*.tar.gz
      - uses: actions/upload-artifact@v4
        with:
          name: liostunnel-${{ runner.os }}-${{ github.sha }}
          path: dist/*.tar.gz
```

- [ ] **Step 2: Validate the workflow parses**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ok')"`
Expected: `ok`

- [ ] **Step 3: Confirm the job would run the right build per platform**

Run: `grep -n "flutter build" .github/workflows/ci.yml`
Expected: one line, containing both `macos` and `linux` in the conditional.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -F /tmp/msg-p3.txt
```

`/tmp/msg-p3.txt`:

```
ci: build and package the app on both platforms

This is the first thing in the workflow that runs `flutter build`. Everything
else runs `flutter test`, which exercises none of cargokit, CMake, the Xcode
project or the podspec -- so until now a change that broke the macOS bundle
passed every check on main.

The Linux apt packages are explicit because their absence presents as a CMake
error that reads like a Flutter bug.
```

---

### Task 4: `helper_install.dart` — paths, quoting, and the privileged runner

**Files:**
- Create: `app/lib/services/helper_install.dart`
- Test: `app/test/helper_install_test.dart`

**Interfaces:**
- Produces:
  - `String helperBundleDir({String? resolvedExecutable})`
  - `String installCommand(int uid, {String? resolvedExecutable})`
  - `enum InstallOutcome { installed, cancelled, failed }`
  - `class InstallResult { final InstallOutcome outcome; final String message; }`
  - `Future<InstallResult> runInstallPrivileged(int uid, {String? resolvedExecutable, Future<ProcessResult> Function(String, List<String>)? run})`
  - `Future<int> currentUid()`

- [ ] **Step 1: Write the failing test**

Create `app/test/helper_install_test.dart`:

```dart
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:liostunnel_app/services/helper_install.dart';

void main() {
  test('the helper directory is beside the executable, per platform', () {
    if (Platform.isMacOS) {
      expect(
        helperBundleDir(
          resolvedExecutable: '/Applications/LiosTunnel.app/Contents/MacOS/LiosTunnel',
        ),
        '/Applications/LiosTunnel.app/Contents/Resources/helper',
      );
    } else {
      expect(
        helperBundleDir(resolvedExecutable: '/opt/liostunnel/liostunnel'),
        '/opt/liostunnel/helper',
      );
    }
  });

  test('the command names the script and the uid', () {
    final exe = Platform.isMacOS
        ? '/Applications/LiosTunnel.app/Contents/MacOS/LiosTunnel'
        : '/opt/liostunnel/liostunnel';
    final cmd = installCommand(501, resolvedExecutable: exe);
    expect(cmd, contains('install-helper.sh'));
    expect(cmd, contains('--uid 501'));
  });

  test('a path with a space survives quoting', () async {
    // `/Applications/` is not the only place an app lands, and an unquoted
    // space breaks `do shell script` in a way that reads as "the installer is
    // broken" rather than "the path has a space in it".
    late List<String> args;
    await runInstallPrivileged(
      501,
      resolvedExecutable: Platform.isMacOS
          ? '/Users/me/My Apps/LiosTunnel.app/Contents/MacOS/LiosTunnel'
          : '/Users/me/My Apps/liostunnel/liostunnel',
      run: (exe, a) async {
        args = a;
        return ProcessResult(0, 0, '', '');
      },
    );
    final joined = args.join(' ');
    expect(joined, contains('My Apps'));
    // Quoted, so the shell sees one word. Either quoting style is fine; an
    // unquoted space is not.
    expect(
      RegExp(r"""('[^']*My Apps[^']*'|\\ )""").hasMatch(joined),
      isTrue,
      reason: 'the space must be quoted or escaped: $joined',
    );
  });

  test('a cancel is not a failure', () async {
    // macOS: osascript exits 1 saying "User canceled". Linux: pkexec exits
    // 126. Neither is an error the user should see red text about -- they
    // said no.
    final macos = await runInstallPrivileged(
      501,
      resolvedExecutable: '/a/LiosTunnel.app/Contents/MacOS/LiosTunnel',
      run: (_, __) async =>
          ProcessResult(0, 1, '', 'execution error: User canceled. (-128)'),
    );
    final linux = await runInstallPrivileged(
      501,
      resolvedExecutable: '/a/liostunnel/liostunnel',
      run: (_, __) async => ProcessResult(0, 126, '', ''),
    );
    expect(
      Platform.isMacOS ? macos.outcome : linux.outcome,
      InstallOutcome.cancelled,
    );
  });

  test('a missing pkexec names the manual command', () async {
    final r = await runInstallPrivileged(
      501,
      resolvedExecutable: '/a/liostunnel/liostunnel',
      run: (_, __) async => ProcessResult(0, 127, '', ''),
    );
    expect(r.outcome, InstallOutcome.failed);
    expect(r.message, contains('install-helper.sh'));
  });

  test("a failing script's own words are shown", () async {
    final r = await runInstallPrivileged(
      501,
      resolvedExecutable: Platform.isMacOS
          ? '/a/LiosTunnel.app/Contents/MacOS/LiosTunnel'
          : '/a/liostunnel/liostunnel',
      run: (_, __) async =>
          ProcessResult(0, 1, '', 'error: refusing to authorize uid 0'),
    );
    expect(r.outcome, InstallOutcome.failed);
    expect(r.message, contains('refusing to authorize uid 0'));
  });

  test('success is reported as installed', () async {
    final r = await runInstallPrivileged(
      501,
      resolvedExecutable: Platform.isMacOS
          ? '/a/LiosTunnel.app/Contents/MacOS/LiosTunnel'
          : '/a/liostunnel/liostunnel',
      run: (_, __) async => ProcessResult(0, 0, 'helper installed', ''),
    );
    expect(r.outcome, InstallOutcome.installed);
  });
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd app && flutter test test/helper_install_test.dart`
Expected: FAIL — `Target of URI doesn't exist: 'package:liostunnel_app/services/helper_install.dart'`.

- [ ] **Step 3: Implement it**

Create `app/lib/services/helper_install.dart`:

```dart
import 'dart:io';

/// Installing the privileged helper that ships inside this app bundle.
///
/// The helper creates a TUN device and rewrites the routing table, which an
/// unprivileged process cannot do — so it runs as a root daemon, and getting
/// it there needs an authorization the app does not have.
///
/// `SMAppService` is the supported way to do this and requires the app to be
/// signed with a Developer ID. This build is unsigned by decision, so it uses
/// the unsupported route instead: `osascript`'s `with administrator
/// privileges` on macOS and `pkexec` on Linux, both of which raise the
/// operating system's own password dialog. **The OS prompt is the consent
/// gate**, and nothing here escalates without it.
library;

/// Where the bundled helper, its unit file and the install script live.
///
/// macOS puts resources beside the executable's grandparent
/// (`…/Contents/MacOS/App` → `…/Contents/Resources`); a Linux Flutter bundle
/// is a flat directory with the executable at its root.
String helperBundleDir({String? resolvedExecutable}) {
  final exe = resolvedExecutable ?? Platform.resolvedExecutable;
  final dir = File(exe).parent; // …/Contents/MacOS  or  …/liostunnel
  if (Platform.isMacOS) {
    return '${dir.parent.path}/Resources/helper';
  }
  return '${dir.path}/helper';
}

/// The command the app would run, in the form a user could run themselves.
///
/// Shown before the OS dialog appears, and again if they cancel. It is what
/// remains of "read the script before it runs as root" once the running is
/// automatic.
String installCommand(int uid, {String? resolvedExecutable}) =>
    '${helperBundleDir(resolvedExecutable: resolvedExecutable)}'
    '/install-helper.sh --uid $uid';

enum InstallOutcome { installed, cancelled, failed }

class InstallResult {
  const InstallResult(this.outcome, this.message);
  final InstallOutcome outcome;
  final String message;
}

/// Single-quotes a string for `/bin/sh`.
///
/// `/Applications/` is not the only place an app lands, and an unquoted space
/// breaks `do shell script` in a way that reads as "the installer is broken"
/// rather than "the path has a space in it".
String _shellQuote(String s) => "'${s.replaceAll("'", r"'\''")}'";

/// Escapes a string to sit inside an AppleScript double-quoted literal.
///
/// Two levels of quoting are in play: the shell command inside
/// `do shell script`, and the AppleScript string carrying it. Escaping only
/// one of them is the classic way this breaks.
String _appleScriptLiteral(String s) =>
    '"${s.replaceAll(r'\', r'\\').replaceAll('"', r'\"')}"';

/// This process's real uid.
///
/// Read from `id -u` rather than assumed: the app must tell the install script
/// which account to authorize, and the script deliberately refuses to guess —
/// under sudo, pkexec and osascript alike, guessing yields 0.
Future<int> currentUid() async {
  final r = await Process.run('id', ['-u']);
  return int.parse('${r.stdout}'.trim());
}

/// Runs the bundled install script with privileges, raising the OS dialog.
///
/// [run] is injected so tests never escalate: no test in this repo may invoke
/// a real `osascript` or `pkexec`.
Future<InstallResult> runInstallPrivileged(
  int uid, {
  String? resolvedExecutable,
  Future<ProcessResult> Function(String, List<String>)? run,
}) async {
  final script =
      '${helperBundleDir(resolvedExecutable: resolvedExecutable)}/install-helper.sh';
  final exec = run ?? (e, a) => Process.run(e, a);

  late ProcessResult r;
  if (Platform.isMacOS) {
    final inner = '${_shellQuote(script)} --uid $uid';
    r = await exec('osascript', [
      '-e',
      'do shell script ${_appleScriptLiteral(inner)} with administrator privileges',
    ]);
  } else {
    // pkexec takes argv directly, so no shell is involved and the path needs
    // no quoting — but it is quoted in the *displayed* command, which a user
    // does paste into a shell.
    r = await exec('pkexec', [script, '--uid', '$uid']);
  }

  final err = '${r.stderr}'.trim();
  if (r.exitCode == 0) {
    return const InstallResult(InstallOutcome.installed, 'The helper is installed.');
  }
  // A cancel is not an error. macOS reports it as -128 with "User canceled";
  // pkexec uses exit 126 for "not authorized", which covers both a dismissed
  // dialog and a refused authorization.
  if (r.exitCode == 126 || err.contains('User canceled') || err.contains('-128')) {
    return const InstallResult(
      InstallOutcome.cancelled,
      'Installation was cancelled.',
    );
  }
  if (r.exitCode == 127) {
    return InstallResult(
      InstallOutcome.failed,
      'This system has no pkexec, so the helper cannot be installed from the '
      'app. Run it yourself: sudo $script',
    );
  }
  // The script is ours and its messages are fixed strings we wrote, so quoting
  // it is safe — unlike the helper's own error text, which the app never
  // renders.
  return InstallResult(
    InstallOutcome.failed,
    err.isEmpty ? 'The installer failed (exit ${r.exitCode}).' : err,
  );
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd app && flutter analyze && flutter test test/helper_install_test.dart`
Expected: analyze clean, 7 tests pass.

**Known limitation, stated rather than discovered.** `helperBundleDir` branches
on `Platform.isMacOS`, so a test can only exercise the branch for the machine
it runs on. The other branch is covered by CI running this suite on both
platforms — which is a reason the Task 3 job matters beyond producing
artifacts. Do not fake it with a platform override parameter that production
never passes; that would test a code path the app cannot reach.

- [ ] **Step 5: A/B each assertion**

| Change | Test that must fail |
|---|---|
| `helperBundleDir` returns `'${dir.path}/helper'` on every platform | `the helper directory is beside the executable` (macOS) |
| drop `_shellQuote`, interpolate the raw path | `a path with a space survives quoting` |
| treat 126 as `failed` | `a cancel is not a failure` |
| return a fixed string instead of `err` | `a failing script's own words are shown` |
| drop the 127 branch | `a missing pkexec names the manual command` |

- [ ] **Step 6: Commit**

```bash
git add app/lib/services/helper_install.dart app/test/helper_install_test.dart
git commit -F /tmp/msg-p4.txt
```

`/tmp/msg-p4.txt`:

```
feat: run the bundled install script under the OS authorization dialog

osascript's `with administrator privileges` on macOS, pkexec on Linux. Both
raise the operating system's own password prompt, and neither needs signing --
SMAppService is the supported route and requires a Developer ID this build
does not have.

Two levels of quoting are in play on macOS: the shell command inside
`do shell script`, and the AppleScript string carrying it. Escaping only one
is the classic way this breaks, and it breaks on any path with a space --
/Applications/ is not the only place an app lands.

A cancel is not a failure. osascript reports -128 with "User canceled",
pkexec exits 126; both mean the user said no, which is not a thing to show
red text about.

The runner is injected so no test in this repo ever escalates.
```

---

### Task 5: Install on first launch, once

**Files:**
- Modify: `app/lib/main.dart`, `app/lib/services/connection_model.dart`, `app/lib/screens/connection.dart`
- Test: `app/test/widget_test.dart`

**Interfaces:**
- Consumes: `runInstallPrivileged`, `installCommand`, `InstallOutcome` (Task 4).

- [ ] **Step 1: Write the failing tests**

Add to `app/test/widget_test.dart`:

```dart
  testWidgets('a missing helper installs itself, once', (tester) async {
    // PKG-7. HelperClient retries an absent socket on a timer; prompting from
    // that would re-raise the password dialog every few seconds after a
    // cancel, which the user cannot escape without force-quitting. So the
    // attempt is made at most once per process launch — and this test drives
    // several retry cycles to prove it.
    var calls = 0;
    await pumpHomeWithInstaller(
      tester,
      installer: (uid) async {
        calls++;
        return const InstallResult(InstallOutcome.cancelled, 'Installation was cancelled.');
      },
    );
    await tester.pump(const Duration(seconds: 5));
    await tester.pump(const Duration(seconds: 5));
    expect(calls, 1, reason: 'a second prompt is a loop the user cannot escape');
  });

  testWidgets('a cancelled install shows the command, not an error',
      (tester) async {
    await pumpHomeWithInstaller(
      tester,
      installer: (uid) async => const InstallResult(
        InstallOutcome.cancelled,
        'Installation was cancelled.',
      ),
    );
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('install-panel')), findsOneWidget);
    expect(find.textContaining('install-helper.sh'), findsOneWidget,
        reason: 'what remains of "read it before it runs as root"');
    expect(find.textContaining('--uid'), findsOneWidget);
  });

  testWidgets('the panel offers a retry that runs the installer again',
      (tester) async {
    var calls = 0;
    await pumpHomeWithInstaller(
      tester,
      installer: (uid) async {
        calls++;
        return const InstallResult(InstallOutcome.cancelled, 'cancelled');
      },
    );
    await tester.pumpAndSettle();
    expect(calls, 1);
    await tester.tap(find.byKey(const Key('install-retry')));
    await tester.pumpAndSettle();
    expect(calls, 2, reason: 'asked for explicitly, so it runs');
  });
```

`widget_test.dart` will need `import 'package:liostunnel_app/services/helper_install.dart';`
for `InstallResult` and `InstallOutcome`. Add this helper beside the other
`pump*` helpers in that file:

```dart
/// Pumps the home page with the privileged installer replaced.
///
/// No test in this repo may raise a real authorization dialog, so the
/// installer is always injected. The socket path points at a directory that
/// cannot hold one, so the client fails with ENOENT — the "never installed"
/// case, which is the only one that triggers an install.
Future<void> pumpHomeWithInstaller(
  WidgetTester tester, {
  required Future<InstallResult> Function(int) installer,
}) async {
  final dir = Directory.systemTemp.createTempSync('lios-install');
  addTearDown(() => dir.deleteSync(recursive: true));
  await tester.pumpWidget(
    ChangeNotifierProvider(
      create: (_) => ConnectionModel(),
      child: MaterialApp(
        home: HomePage(
          profilesDirectory: dir.path,
          socketPath: '${dir.path}/nonexistent.sock',
          installer: installer,
        ),
      ),
    ),
  );
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd app && flutter test test/widget_test.dart`
Expected: FAIL — `No named parameter with the name 'installer'`.

- [ ] **Step 3: Add the installing state to the model**

In `app/lib/services/connection_model.dart`, add a field and its setter:

```dart
  /// What the first-launch installer is doing, if anything.
  ///
  /// Separate from [Fault] because it is not a fault: an install in progress
  /// is a normal startup, and a cancelled one is the user's answer rather
  /// than an error.
  String? _installNotice;
  String? get installNotice => _installNotice;

  set installNotice(String? v) {
    _installNotice = v;
    notifyListeners();
  }
```

And correct the now-wrong wording, since an archive has no `packaging/`:

```dart
    Fault.helperNotInstalled =>
      'The helper is not installed or not running.',
```

- [ ] **Step 4: Run the installer once, on the right failure**

In `app/lib/main.dart`, add to `HomePage`:

```dart
  /// Injected so no test raises a real authorization dialog.
  final Future<InstallResult> Function(int)? installer;
```

with `this.installer` in the constructor. Then in `_HomePageState`:

```dart
  /// At most once per process launch. See `_attach`.
  bool _installAttempted = false;
  String? _installCommandText;
```

and replace `_attach`'s `catch`:

```dart
    } catch (e) {
      model.applyError(e);
      // Only ENOENT. `HelperForbidden` means the helper IS installed, for
      // somebody else — reinstalling over it is a different decision with a
      // different consequence, and it keeps its own message.
      if (e is HelperUnavailable) await _installHelper();
    }
```

and add:

```dart
  /// Installs the bundled helper, raising the OS password dialog.
  ///
  /// Guarded by [_installAttempted] because `HelperClient` retries an absent
  /// socket on a timer: prompting from that would re-raise the dialog every
  /// few seconds after a cancel, which the user cannot escape without
  /// force-quitting. A user who cancels has said no; asking again unprompted
  /// is how an app becomes something you close. The panel's retry button is
  /// the way back, because that one was asked for.
  Future<void> _installHelper({bool force = false}) async {
    if (_installAttempted && !force) return;
    _installAttempted = true;
    final model = context.read<ConnectionModel>();
    final uid = await currentUid();
    setState(() => _installCommandText = installCommand(uid));
    model.installNotice =
        'Installing the privileged helper. Your system is asking for your '
        'password.';
    final run = widget.installer ?? runInstallPrivileged;
    final result = await run(uid);
    if (!mounted) return;
    switch (result.outcome) {
      case InstallOutcome.installed:
        model.installNotice = null;
        setState(() => _installCommandText = null);
        await _attach();
      case InstallOutcome.cancelled:
      case InstallOutcome.failed:
        model.installNotice = result.message;
    }
  }
```

- [ ] **Step 5: Show the panel**

In `app/lib/screens/connection.dart`, add above the error banner. The screen takes two new parameters, `installCommandText` and `onRetryInstall`, passed from `main.dart`:

```dart
            if (m.installNotice != null)
              Card(
                key: const Key('install-panel'),
                color: Theme.of(context).colorScheme.secondaryContainer,
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(m.installNotice!),
                      if (installCommandText != null) ...[
                        const SizedBox(height: 8),
                        // What remains of "read it before it runs as root".
                        SelectableText(
                          installCommandText!,
                          style: const TextStyle(fontFamily: 'monospace'),
                        ),
                        const SizedBox(height: 8),
                        FilledButton.tonal(
                          key: const Key('install-retry'),
                          onPressed: onRetryInstall,
                          child: const Text('Install the helper'),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
```

`onRetryInstall` is `() => _installHelper(force: true)`.

- [ ] **Step 6: Run everything**

```bash
./testing/build-ffi-for-tests.sh
cd app && flutter analyze && flutter test
```
Expected: analyze clean, all tests pass.

- [ ] **Step 7: A/B each assertion**

| Change | Test that must fail |
|---|---|
| drop the `_installAttempted` guard | `a missing helper installs itself, once` |
| call `_installHelper` for any exception, not just `HelperUnavailable` | add a case pumping a `HelperForbidden` socket and assert no call |
| show `result.message` without `_installCommandText` | `a cancelled install shows the command, not an error` |
| make the retry button call `_installHelper()` without `force` | `the panel offers a retry that runs the installer again` |

- [ ] **Step 8: Commit**

```bash
git add app/lib app/test
git commit -F /tmp/msg-p5.txt
```

`/tmp/msg-p5.txt`:

```
feat: install the helper on first launch, once

When the socket is absent the app raises the OS password dialog itself
instead of telling the user to run a script. The OS prompt is the consent
gate; nothing escalates without it.

At most once per process launch. HelperClient retries an absent socket on a
timer, and prompting from that would re-raise the dialog every few seconds
after a cancel -- a loop the user cannot escape without force-quitting. A user
who cancels has said no. The panel's retry button is the way back, because
that one was asked for.

Only for ENOENT. HelperForbidden means the helper is installed for somebody
else, which is a different decision with a different consequence.

The panel shows the exact command including the uid, which is what remains of
"read it before it runs as root" once the running is automatic. Also corrects
the not-installed message, which named packaging/install-helper.sh -- a path
that does not exist in a release bundle.
```

---

## Exit criteria

| Criterion | Verified by |
|---|---|
| PKG-1 — CI builds the app on both platforms | Task 3; a `flutter build` failure fails the job |
| PKG-2 — one archive per platform, helper embedded | Task 2 step 3, `verify-bundle.sh` |
| PKG-3 — uid from three sources, uid 0 refused, no guessing | Task 1 step 1, the three refusal assertions |
| PKG-4 — the bundled binary is found, and `target/release` still works | Task 1 step 1, `the bundled binary is used` |
| PKG-5 — the bundled helper is a working executable | Task 2, `the bundled helper runs: liostunnel-helper 0.1.0` |
| PKG-6 — first launch raises the dialog and installs on approval | Task 5 step 1 |
| PKG-7 — cancelling leaves the app usable and produces no second prompt | Task 5, `a missing helper installs itself, once` |
| PKG-8 — a path with a space works; a missing `pkexec` names the manual command | Task 4 step 1 |

**PKG-3 is the one to care about.** The others make the artifact usable; that one is the authorization boundary surviving a new way of being invoked. A helper installed with uid 0 authorized would accept a root client, which is the whole thing the design exists to prevent.

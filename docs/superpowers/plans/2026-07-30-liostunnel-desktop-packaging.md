# Desktop Packaging Implementation Plan — macOS `.pkg`, Linux AppImage

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A macOS `.pkg` that drops the app in `/Applications` and installs the privileged helper in the same run, and a Linux `.AppImage` that runs on any distro and installs the helper on first launch — both built by CI on every push to `main`.

**Architecture:** The helper, its unit file and `install-helper.sh` live inside the app bundle on both platforms. On macOS the package's `postinstall` runs that script as root with the console user's uid. On Linux there is no install step, so the app runs it under `pkexec` at first launch. One install script, three ways of invoking it.

**Tech Stack:** `pkgbuild`, `appimagetool`, Bash, GitHub Actions, Flutter desktop, cargokit.

## Global Constraints

Every task's requirements implicitly include this section.

- **The uid baked into the unit file is the human's, never the elevated process's.** `install-helper.sh` refuses uid 0, a non-numeric uid, one with leading zeros, one ≥ 2³², and the case where it cannot tell. **Do not modify `packaging/install-helper.sh` or `testing/verify-install-script.sh`** — Task 1 settled them over three rounds. If you believe one needs changing, report it.
- **A macOS console uid below 500 is a system account, not a person.** During Setup Assistant it is `_mbsetupuser` (248), which the uid-0 guard does not catch. This is PKG-3 and it is the criterion this phase turns on.
- **The app is built as `liostunnel_app.app` (macOS) and `liostunnel_app` (Linux).** Not `LiosTunnel`. Use the real names; renaming is a separate change with its own breakage risk.
- **No signing, no CI secrets.** Both artifacts are unsigned; Gatekeeper blocks a double-clicked `.pkg`, which the README addresses.
- **TDD, strictly.** Failing test first, run it, confirm it fails for the *expected* reason, then implement. Report RED and GREEN.
- **A test that passes must be shown failing against the defect it names.** Task 1 needed three rounds because assertions kept not discriminating — one grepped a stub's argv instead of the file it claimed to check. **Before trusting an assertion, ask what it actually reads.** If an A/B does not reproduce, that is a finding to report.
- **No test may install anything, run a real `installer`, or require root.** Packages are inspected with `pkgutil --expand`; AppImages with `--appimage-extract`.
- **There is a live helper installed on this machine** (`/Library/LaunchDaemons/com.liostunnel.helper.plist`, `/usr/local/libexec/liostunnel-helper`, authorizing uid 501). Nothing may modify or remove it.
- `flutter analyze` must pass; `./testing/build-ffi-for-tests.sh` before `flutter test`.
- **Commit messages go through a file with `git commit -F`** — backticks inside `-m` are command substitution and have run a destructive command in this repo once.

## File structure

| File | Responsibility |
|---|---|
| `packaging/install-helper.sh` | **unchanged** — Task 1; the one owner of install logic |
| `packaging/macos-pkg/postinstall` | read the console uid, refuse system accounts, call the script |
| `packaging/make-pkg.sh` | stage the payload, run `pkgbuild` |
| `packaging/make-appimage.sh` | build the AppDir, run `appimagetool` |
| `testing/verify-pkg.sh` | expand and assert, without installing |
| `testing/verify-appimage.sh` | extract and assert |
| `app/lib/services/helper_install.dart` | resolve the bundled script, run it under `pkexec` |
| `app/lib/main.dart`, `.../connection_model.dart`, `.../connection.dart` | run it once, on the right failure, on the right platform |
| `.github/workflows/ci.yml` | the `package` job |

**Milestones.** A (Task 2) is the macOS package. B (Task 3) is the AppImage. C (Task 4) is CI. D (Task 5) is first launch on Linux.

---

### Task 2: The macOS package

**Files:**
- Create: `packaging/macos-pkg/postinstall`, `packaging/make-pkg.sh`, `testing/verify-pkg.sh`

**Interfaces:**
- Consumes: `install-helper.sh --uid N` (Task 1).
- Produces: `dist/LiosTunnel-<sha>.pkg`.

**Why the helper is not a second payload component.** It would be simpler to
have `pkgbuild` place `liostunnel-helper` at `/usr/local/libexec` directly. It
is not done that way because installing the helper means more than copying a
file: it bakes an authorized uid into a root-owned unit file and loads a
daemon. Doing that in two places is how they drift, on the one operation in
this project that draws a security boundary.

- [ ] **Step 1: Write the verifier first**

Create `testing/verify-pkg.sh`:

```bash
#!/usr/bin/env bash
#
# Proves the package would install what it claims, without installing it.
#
#     ./testing/verify-pkg.sh dist/LiosTunnel-abc1234.pkg
#
# `pkgutil --expand` unpacks the payload; nothing is run, nothing needs root.
set -uo pipefail
pkg="${1:-}"
[ -f "$pkg" ] || { echo "usage: $0 <package.pkg>"; exit 1; }
pass=0; fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
bad() { echo "  FAIL  $*"; fail=$((fail+1)); }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
pkgutil --expand "$pkg" "$tmp/x" || { echo "cannot expand"; exit 1; }

# The payload is a cpio archive; extract it to look inside.
payload="$(find "$tmp/x" -name Payload | head -1)"
[ -n "$payload" ] || { echo "no Payload in the package"; exit 1; }
mkdir -p "$tmp/p" && (cd "$tmp/p" && tar xzf "$payload" 2>/dev/null || \
  (cd "$tmp/p" && cat "$payload" | gunzip -dc | cpio -i --quiet))

app="$tmp/p/Applications/liostunnel_app.app"
helper="$app/Contents/Resources/helper"

[ -d "$app" ] && ok "the payload installs the app to /Applications" \
              || bad "no Applications/liostunnel_app.app in the payload"
[ -x "$app/Contents/MacOS/liostunnel_app" ] \
  && ok "the app executable is present and executable" \
  || bad "no executable at Contents/MacOS/liostunnel_app"

for f in liostunnel-helper install-helper.sh uninstall-helper.sh; do
  [ -x "$helper/$f" ] && ok "$f is inside the app and executable" \
                      || bad "missing or not executable: $f"
done
[ -f "$helper/liostunnel-helper.plist" ] && ok "the launchd plist is present" \
                                         || bad "missing liostunnel-helper.plist"
# A systemd unit in a macOS package reads as an oversight, not symmetry.
[ ! -f "$helper/liostunnel-helper.service" ] \
  && ok "the systemd unit is absent" || bad "a systemd unit is in a macOS package"

# A binary that runs on THIS platform -- not a placeholder, not the wrong arch.
v="$("$helper/liostunnel-helper" --version 2>&1)"
if [ $? -eq 0 ] && [ "${v#liostunnel-helper }" != "$v" ]; then
  ok "the bundled helper runs: $v"
else
  bad "the bundled helper did not run: $v"
fi

# The postinstall: present, executable, and carrying both rules.
post="$(find "$tmp/x" -name postinstall | head -1)"
[ -n "$post" ] && [ -x "$post" ] && ok "postinstall is present and executable" \
                                 || bad "no executable postinstall"
if [ -n "$post" ]; then
  grep -q -- '--uid' "$post" && ok "postinstall passes --uid" \
                             || bad "postinstall does not pass --uid"
  grep -q '/dev/console' "$post" && ok "postinstall reads the console user" \
                                 || bad "postinstall does not read the console user"
  # PKG-3. uid 0 is caught by install-helper.sh; _mbsetupuser (248) is not,
  # and a helper serving an account that stops existing is the failure.
  grep -qE '\-ge 500|\-lt 500' "$post" \
    && ok "postinstall refuses a system account (uid < 500)" \
    || bad "postinstall would authorize _mbsetupuser during Setup Assistant"
fi

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
```

- [ ] **Step 2: Run it against nothing, to see it fail**

Run: `chmod +x testing/verify-pkg.sh && ./testing/verify-pkg.sh dist/does-not-exist.pkg`
Expected: `usage: …` and exit 1. Then, after Step 3 builds a package but before Step 4 writes the postinstall, it must fail the three postinstall assertions.

- [ ] **Step 3: Write `make-pkg.sh`**

```bash
#!/usr/bin/env bash
#
# Builds the macOS installer package. Assumes both builds have run:
#
#     cargo build --release -p liostunnel-helper
#     cd app && flutter build macos --release
#     ./packaging/make-pkg.sh
#
# Assembly is separate from building so a failed build is never reported as a
# packaging problem -- and so this runs on the machine that is confused.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
sha="$(git -C "$repo" rev-parse --short HEAD)"
helper="$repo/target/release/liostunnel-helper"
built="$repo/app/build/macos/Build/Products/Release/liostunnel_app.app"

die() { echo "error: $*" >&2; exit 1; }
[ "$(uname -s)" = Darwin ] || die "this builds a macOS package; run it on macOS"
[ -f "$helper" ] || die "no helper at $helper — run: cargo build --release -p liostunnel-helper"
[ -d "$built" ] || die "no app at $built — run: cd app && flutter build macos --release"

dist="$repo/dist"
stage="$dist/stage"
# A partial dist/ from an earlier failed run must never be shipped as current.
rm -rf "$dist"
mkdir -p "$stage/Applications"

cp -R "$built" "$stage/Applications/"
inner="$stage/Applications/liostunnel_app.app/Contents/Resources/helper"
mkdir -p "$inner"
install -m 0755 "$helper"                       "$inner/liostunnel-helper"
install -m 0755 "$here/install-helper.sh"       "$inner/install-helper.sh"
install -m 0755 "$here/uninstall-helper.sh"     "$inner/uninstall-helper.sh"
# Only the launchd plist. A systemd unit in a macOS package reads as an
# oversight rather than symmetry.
install -m 0644 "$here/liostunnel-helper.plist" "$inner/liostunnel-helper.plist"

out="$dist/LiosTunnel-$sha.pkg"
pkgbuild \
  --root "$stage" \
  --scripts "$here/macos-pkg" \
  --identifier com.liostunnel.pkg \
  --version "0.1.0-$sha" \
  --install-location / \
  "$out"

rm -rf "$stage"
echo "$out"
```

- [ ] **Step 4: Write the postinstall**

Create `packaging/macos-pkg/postinstall`:

```bash
#!/bin/bash
#
# Runs as root under Installer.app, after the payload is in place.
#
# Installing the helper is not a file copy: it bakes an authorized uid into a
# root-owned unit file and loads a daemon. So this defers to the one script
# that owns that logic, rather than being a second implementation of it.
set -euo pipefail
helper=/Applications/liostunnel_app.app/Contents/Resources/helper

# Who is actually using this machine. The installer runs as root and neither
# SUDO_UID nor PKEXEC_UID exists here, so the console user is the only honest
# source -- `id -u` would say 0, and a helper authorizing root accepts a root
# client, which is the whole boundary gone.
uid="$(stat -f %u /dev/console)"

# And refuse the system accounts. During Setup Assistant the console user is
# `_mbsetupuser` (uid 248) -- not 0, so install-helper.sh's uid-0 guard would
# let it through, and the helper would end up serving an account that stops
# existing the moment setup finishes. Regular macOS accounts start at 501.
if [ "$uid" -lt 500 ]; then
  echo "no logged-in user to authorize (console uid $uid)" >&2
  exit 1
fi

exec "$helper/install-helper.sh" --uid "$uid"
```

`chmod 755 packaging/macos-pkg/postinstall`.

- [ ] **Step 5: Build and verify**

```bash
chmod +x packaging/make-pkg.sh
cargo build --release -p liostunnel-helper
cd app && flutter build macos --release && cd ..
./packaging/make-pkg.sh
./testing/verify-pkg.sh dist/LiosTunnel-*.pkg
```
Expected: the package path, then `=== 11 passed, 0 failed ===`.

**If `flutter build macos --release` fails, that is this task's finding.**
Report the error verbatim; do not work around it.

- [ ] **Step 6: A/B each assertion**

| Change to `make-pkg.sh` or `postinstall` | Assertion that must fail |
|---|---|
| also install `liostunnel-helper.service` into `$inner` | `the systemd unit is absent` |
| `install -m 0644` the helper binary | `liostunnel-helper is inside the app and executable` |
| write a zero-byte `liostunnel-helper` | `the bundled helper runs` |
| delete the `-lt 500` block from the postinstall | `postinstall refuses a system account` |
| `exec "$helper/install-helper.sh"` with no `--uid` | `postinstall passes --uid` |

- [ ] **Step 7: Confirm the live install is untouched**

Run: `ls -l /Library/LaunchDaemons/com.liostunnel.helper.plist /usr/local/libexec/liostunnel-helper`
Expected: both present, mtimes unchanged from before this task. Record them.

- [ ] **Step 8: Commit**

```bash
git add packaging testing/verify-pkg.sh
git commit -F /tmp/msg-t2.txt
```

`/tmp/msg-t2.txt`:

```
feat: a macOS package that installs the app and its helper

The payload is the app alone, with the helper inside
Contents/Resources/helper, and the postinstall runs install-helper.sh from
there. The helper is deliberately not a second payload component: installing
it means baking an authorized uid into a root-owned unit file and loading a
daemon, and doing that in two places is how they drift -- on the one operation
here that draws a security boundary.

The postinstall adds exactly one rule the script cannot know. It reads the
console user, because the installer runs as root and neither SUDO_UID nor
PKEXEC_UID exists there, and it refuses a uid below 500. The uid-0 guard alone
would not catch that: during Setup Assistant the console user is _mbsetupuser
at 248, and the helper would end up serving an account that stops existing.

verify-pkg.sh expands the package rather than installing it, and runs the
bundled helper with --version -- a zero-byte placeholder and a binary built
for the wrong architecture both pass a stat and fail a user.
```

---

### Task 3: The Linux AppImage

**Files:**
- Create: `packaging/make-appimage.sh`, `packaging/appimage/liostunnel.desktop`, `testing/verify-appimage.sh`

**Interfaces:**
- Consumes: `install-helper.sh --uid N` (Task 1).
- Produces: `dist/LiosTunnel-<sha>-x86_64.AppImage`.

**This has never been run.** Neither `flutter build linux` nor `appimagetool`
has executed anywhere in this repo, and the author's machine is macOS. **Write
the scripts; do not claim they work.** If you cannot run them, say so — CI is
where they first run, and a report claiming a green run that did not happen is
worse than one saying it could not.

- [ ] **Step 1: Write the desktop entry**

Create `packaging/appimage/liostunnel.desktop`:

```ini
[Desktop Entry]
Type=Application
Name=LiosTunnel
Exec=liostunnel_app
Icon=liostunnel
Categories=Network;
Terminal=false
```

- [ ] **Step 2: Write `make-appimage.sh`**

```bash
#!/usr/bin/env bash
#
# Builds the Linux AppImage. Assumes both builds have run:
#
#     cargo build --release -p liostunnel-helper
#     cd app && flutter build linux --release
#     ./packaging/make-appimage.sh
#
# appimagetool is downloaded if absent: it is not in this repo and not on the
# author's machine, so CI is where it first runs.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
sha="$(git -C "$repo" rev-parse --short HEAD)"
helper="$repo/target/release/liostunnel-helper"

die() { echo "error: $*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || die "this builds a Linux AppImage; run it on Linux"
[ -f "$helper" ] || die "no helper at $helper — run: cargo build --release -p liostunnel-helper"
bundle="$(find "$repo/app/build/linux" -maxdepth 3 -type d -name bundle | head -1)"
[ -n "$bundle" ] || die "no bundle under app/build/linux/… — run: cd app && flutter build linux --release"

dist="$repo/dist"; appdir="$dist/AppDir"
rm -rf "$dist"; mkdir -p "$appdir/usr/bin"

cp -R "$bundle/." "$appdir/usr/bin/"
inner="$appdir/usr/bin/helper"
mkdir -p "$inner"
install -m 0755 "$helper"                         "$inner/liostunnel-helper"
install -m 0755 "$here/install-helper.sh"         "$inner/install-helper.sh"
install -m 0755 "$here/uninstall-helper.sh"       "$inner/uninstall-helper.sh"
# Only the systemd unit. A launchd plist in a Linux AppImage reads as an
# oversight rather than symmetry.
install -m 0644 "$here/liostunnel-helper.service" "$inner/liostunnel-helper.service"

install -m 0644 "$here/appimage/liostunnel.desktop" "$appdir/liostunnel.desktop"
# Reuse the macOS icon rather than adding a second one to keep in step.
install -m 0644 "$repo/app/macos/Runner/Assets.xcassets/AppIcon.appiconset/app_icon_256.png" \
                "$appdir/liostunnel.png"

cat > "$appdir/AppRun" <<'RUN'
#!/bin/sh
# An AppImage mounts itself at /tmp/.mount_XXXXXX, so $APPDIR is where
# everything actually lives at runtime. The app finds its bundled helper
# relative to its own executable, which is inside this same tree.
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/liostunnel_app" "$@"
RUN
chmod 755 "$appdir/AppRun"

tool="$dist/appimagetool"
if [ ! -x "$tool" ]; then
  curl -fsSL -o "$tool" \
    https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage
  chmod 755 "$tool"
fi

out="$dist/LiosTunnel-$sha-x86_64.AppImage"
# --appimage-extract-and-run because CI containers have no FUSE.
ARCH=x86_64 "$tool" --appimage-extract-and-run "$appdir" "$out"
echo "$out"
```

- [ ] **Step 3: Write `verify-appimage.sh`**

```bash
#!/usr/bin/env bash
#
# Proves the AppImage carries what it claims, without mounting it.
#
#     ./testing/verify-appimage.sh dist/LiosTunnel-abc1234-x86_64.AppImage
#
set -uo pipefail
img="${1:-}"
[ -f "$img" ] || { echo "usage: $0 <file.AppImage>"; exit 1; }
pass=0; fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
bad() { echo "  FAIL  $*"; fail=$((fail+1)); }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
chmod +x "$img"
# --appimage-extract needs no FUSE, so this works in a container.
(cd "$tmp" && "$img" --appimage-extract >/dev/null 2>&1) \
  || { echo "cannot extract"; exit 1; }
root="$tmp/squashfs-root"

[ -x "$root/AppRun" ] && ok "AppRun is present and executable" || bad "no executable AppRun"
[ -x "$root/usr/bin/liostunnel_app" ] && ok "the app executable is present" \
                                      || bad "no executable at usr/bin/liostunnel_app"
[ -f "$root/liostunnel.desktop" ] && ok "the desktop entry is present" || bad "no .desktop"
[ -f "$root/liostunnel.png" ] && ok "the icon is present" || bad "no icon"

inner="$root/usr/bin/helper"
for f in liostunnel-helper install-helper.sh uninstall-helper.sh; do
  [ -x "$inner/$f" ] && ok "$f is inside the AppImage and executable" \
                     || bad "missing or not executable: $f"
done
[ -f "$inner/liostunnel-helper.service" ] && ok "the systemd unit is present" \
                                          || bad "missing liostunnel-helper.service"
[ ! -f "$inner/liostunnel-helper.plist" ] \
  && ok "the launchd plist is absent" || bad "a launchd plist is in a Linux AppImage"

v="$("$inner/liostunnel-helper" --version 2>&1)"
if [ $? -eq 0 ] && [ "${v#liostunnel-helper }" != "$v" ]; then
  ok "the bundled helper runs: $v"
else
  bad "the bundled helper did not run: $v"
fi

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
```

- [ ] **Step 4: Confirm they at least parse**

```bash
chmod +x packaging/make-appimage.sh testing/verify-appimage.sh
bash -n packaging/make-appimage.sh && bash -n testing/verify-appimage.sh && echo "syntax ok"
./packaging/make-appimage.sh 2>&1 | head -2
```
Expected: `syntax ok`, then `error: this builds a Linux AppImage; run it on macOS` — the platform guard firing, which is the only thing testable here.

**Report that the Linux path is unexercised.** Do not claim otherwise.

- [ ] **Step 5: Commit**

```bash
git add packaging/make-appimage.sh packaging/appimage testing/verify-appimage.sh
git commit -F /tmp/msg-t3.txt
```

`/tmp/msg-t3.txt`:

```
feat: a Linux AppImage carrying its own helper

One file that runs on any distro, rather than a .deb that serves Debian and
Ubuntu and nothing else. The helper, its unit file and the install script ride
inside it.

An AppImage has no install step and nothing runs as root, which is why the app
keeps a first-launch install path on Linux and does not need one on macOS.

Unexercised: neither flutter build linux nor appimagetool has run anywhere in
this repo, and the author's machine is macOS. CI is where these first run, and
the scripts are written on that understanding rather than on a green run that
did not happen.
```

---

### Task 4: CI builds and packages both

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add the job**

Append to `.github/workflows/ci.yml`:

```yaml
  # The first thing in this workflow that runs `flutter build`. `flutter test`
  # exercises none of cargokit, CMake, the Xcode project or the podspec, so a
  # change that broke the macOS bundle passed every other check here.
  package:
    runs-on: ${{ matrix.os }}
    strategy:
      # A macOS failure should still produce the Linux artifact: the two share
      # nothing but install-helper.sh.
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
      # package. libfuse2 is for appimagetool.
      - name: linux build dependencies
        if: runner.os == 'Linux'
        run: sudo apt-get update && sudo apt-get install -y ninja-build libgtk-3-dev libfuse2
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
      - name: build the macOS package
        if: runner.os == 'macOS'
        run: ./packaging/make-pkg.sh
      - name: verify the macOS package
        if: runner.os == 'macOS'
        run: ./testing/verify-pkg.sh dist/*.pkg
      - name: build the AppImage
        if: runner.os == 'Linux'
        run: ./packaging/make-appimage.sh
      - name: verify the AppImage
        if: runner.os == 'Linux'
        run: ./testing/verify-appimage.sh dist/*.AppImage
      - uses: actions/upload-artifact@v4
        with:
          name: liostunnel-${{ runner.os }}-${{ github.sha }}
          path: |
            dist/*.pkg
            dist/*.AppImage
```

- [ ] **Step 2: Validate it parses**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('ok')"`
Expected: `ok`

- [ ] **Step 3: Confirm the install-script suite still runs in CI**

Run: `grep -n "verify-install-script" .github/workflows/ci.yml || echo MISSING`

If `MISSING`, add it to the existing `unit` job — Task 1's 24 assertions are
the phase's security gate and running nowhere is not acceptable:

```yaml
      - name: install-script guards
        run: ./testing/verify-install-script.sh
```

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -F /tmp/msg-t4.txt
```

`/tmp/msg-t4.txt`:

```
ci: build and package the app on both platforms

The first thing in this workflow that runs `flutter build`. Everything else
runs `flutter test`, which exercises none of cargokit, CMake, the Xcode
project or the podspec -- so until now a change that broke the macOS bundle
passed every check on main.

The apt packages are explicit because their absence presents as a CMake error
that reads like a Flutter bug, and libfuse2 is what appimagetool needs.
```

---

### Task 5: First launch installs the helper, on Linux

**Files:**
- Create: `app/lib/services/helper_install.dart`
- Modify: `app/lib/main.dart`, `app/lib/services/connection_model.dart`, `app/lib/screens/connection.dart`
- Test: `app/test/helper_install_test.dart`, `app/test/widget_test.dart`

**Interfaces:**
- Produces: `helperBundleDir({String? resolvedExecutable})`, `installCommand(int uid, …)`, `currentUid()`, `InstallOutcome`, `InstallResult`, `runInstallPrivileged(int uid, …)`.

**macOS does not get this.** The package installed the helper; a missing one
there means something reinstalling from the app would paper over. Its message
names the package instead.

**Found during Task 3, and it changes this task's design.** An AppImage mounts
its squashfs through libfuse **without `allow_other`**, so the kernel denies
that mountpoint to every user except the one who mounted it — **including
root**. Pointing `pkexec` at
`/tmp/.mount_XXXXXX/usr/bin/helper/install-helper.sh` gets EACCES and the
script never runs.

So the app must **copy `helper/` out of the mount to a real filesystem path
before elevating**, and run the copy. A temporary directory the invoking user
owns is the right place; `install-helper.sh` finds its binary beside itself,
so the whole directory moves together or nothing works. Delete the copy
afterwards.

`helperBundleDir()` therefore has two jobs that must not be conflated: *where
the bundled helper is read from* (inside the mount) and *what path is handed
to `pkexec`* (the copy). A test must assert they differ, because the version
that "works" on a developer machine — where the app runs from a plain
directory rather than a mount — is exactly the version that fails only under
an AppImage.

- [ ] **Step 1: Write the failing unit tests**

Create `app/test/helper_install_test.dart`:

```dart
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:liostunnel_app/services/helper_install.dart';

void main() {
  test('the helper directory is beside the executable', () {
    // An AppImage mounts itself at /tmp/.mount_XXXXXX, so this must be
    // relative to the executable rather than any fixed path.
    expect(
      helperBundleDir(resolvedExecutable: '/tmp/.mount_abc/usr/bin/liostunnel_app'),
      '/tmp/.mount_abc/usr/bin/helper',
    );
  });

  test('the command names the script and the uid', () {
    final cmd = installCommand(501,
        resolvedExecutable: '/tmp/.mount_abc/usr/bin/liostunnel_app');
    expect(cmd, contains('install-helper.sh'));
    expect(cmd, contains('--uid 501'));
  });

  test('a path with a space survives quoting', () async {
    late List<String> args;
    await runInstallPrivileged(
      501,
      resolvedExecutable: '/home/me/My Apps/usr/bin/liostunnel_app',
      run: (exe, a) async {
        args = a;
        return ProcessResult(0, 0, '', '');
      },
    );
    // pkexec takes argv directly, so the path is one element rather than a
    // quoted string -- which is the point: no shell means nothing to break.
    expect(args.any((a) => a.contains('My Apps')), isTrue);
    expect(args, contains('--uid'));
  });

  test('a cancel is not a failure', () async {
    // pkexec exits 126 when the dialog is dismissed or authorization is
    // refused. The user said no; that is not an error to show red text about.
    final r = await runInstallPrivileged(
      501,
      resolvedExecutable: '/a/usr/bin/liostunnel_app',
      run: (_, __) async => ProcessResult(0, 126, '', ''),
    );
    expect(r.outcome, InstallOutcome.cancelled);
  });

  test('a missing pkexec names the manual command', () async {
    final r = await runInstallPrivileged(
      501,
      resolvedExecutable: '/a/usr/bin/liostunnel_app',
      run: (_, __) async => ProcessResult(0, 127, '', ''),
    );
    expect(r.outcome, InstallOutcome.failed);
    expect(r.message, contains('install-helper.sh'));
  });

  test("a failing script's own words are shown", () async {
    final r = await runInstallPrivileged(
      501,
      resolvedExecutable: '/a/usr/bin/liostunnel_app',
      run: (_, __) async =>
          ProcessResult(0, 1, '', 'error: refusing to authorize uid 0'),
    );
    expect(r.outcome, InstallOutcome.failed);
    expect(r.message, contains('refusing to authorize uid 0'));
  });

  test('success is reported as installed', () async {
    final r = await runInstallPrivileged(
      501,
      resolvedExecutable: '/a/usr/bin/liostunnel_app',
      run: (_, __) async => ProcessResult(0, 0, 'helper installed', ''),
    );
    expect(r.outcome, InstallOutcome.installed);
  });
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd app && flutter test test/helper_install_test.dart`
Expected: FAIL — `Target of URI doesn't exist: '…/helper_install.dart'`.

- [ ] **Step 3: Implement it**

Create `app/lib/services/helper_install.dart`:

```dart
import 'dart:io';

/// Installing the privileged helper that ships inside this app.
///
/// **Linux only.** The macOS package installs the helper from its own
/// `postinstall`, which runs as root under Installer.app — so on macOS a
/// missing helper means something that reinstalling from the app would paper
/// over, and the app says so instead.
///
/// An AppImage has no install step and nothing runs as root, so on Linux the
/// app asks `pkexec` to run the same `install-helper.sh` the package would
/// have. **The polkit dialog is the consent gate**; nothing here escalates
/// without it.
library;

/// Where the bundled helper and its install script live.
///
/// Relative to the executable, because an AppImage mounts itself at
/// `/tmp/.mount_XXXXXX` and any fixed path would be wrong.
String helperBundleDir({String? resolvedExecutable}) =>
    '${File(resolvedExecutable ?? Platform.resolvedExecutable).parent.path}/helper';

/// The command the app runs, in the form a user could run themselves.
///
/// Shown if they cancel. It is what remains of "read the script before it runs
/// as root" once the running is automatic.
String installCommand(int uid, {String? resolvedExecutable}) =>
    '${helperBundleDir(resolvedExecutable: resolvedExecutable)}'
    '/install-helper.sh --uid $uid';

/// This process's real uid.
///
/// The install script deliberately refuses to guess: under `sudo`, `pkexec`
/// and a package's postinstall alike, guessing yields 0, and a helper
/// authorizing root accepts a root client.
Future<int> currentUid() async {
  final r = await Process.run('id', ['-u']);
  return int.parse('${r.stdout}'.trim());
}

enum InstallOutcome { installed, cancelled, failed }

class InstallResult {
  const InstallResult(this.outcome, this.message);
  final InstallOutcome outcome;
  final String message;
}

/// Runs the bundled install script under `pkexec`, raising the polkit dialog.
///
/// [run] is injected so tests never escalate: no test in this repo may invoke
/// a real `pkexec`.
Future<InstallResult> runInstallPrivileged(
  int uid, {
  String? resolvedExecutable,
  Future<ProcessResult> Function(String, List<String>)? run,
}) async {
  final script =
      '${helperBundleDir(resolvedExecutable: resolvedExecutable)}/install-helper.sh';
  final exec = run ?? (e, a) => Process.run(e, a);
  // pkexec takes argv directly, so no shell is involved and a path with a
  // space needs no quoting -- there is nothing to misparse it.
  final r = await exec('pkexec', [script, '--uid', '$uid']);

  final err = '${r.stderr}'.trim();
  if (r.exitCode == 0) {
    return const InstallResult(
        InstallOutcome.installed, 'The helper is installed.');
  }
  // 126 is "dismissed or not authorized". The user said no.
  if (r.exitCode == 126) {
    return const InstallResult(
        InstallOutcome.cancelled, 'Installation was cancelled.');
  }
  if (r.exitCode == 127) {
    return InstallResult(
      InstallOutcome.failed,
      'This system has no pkexec, so the helper cannot be installed from the '
      'app. Run it yourself: sudo $script --uid $uid',
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

- [ ] **Step 4: Run to verify they pass**

Run: `cd app && flutter analyze && flutter test test/helper_install_test.dart`
Expected: analyze clean, 7 pass.

- [ ] **Step 5: Write the failing widget tests**

Add to `app/test/widget_test.dart` (it needs
`import 'package:liostunnel_app/services/helper_install.dart';`):

```dart
  testWidgets('a missing helper installs itself, once', (tester) async {
    // PKG-7. HelperClient retries an absent socket on a timer; prompting from
    // that would re-raise the polkit dialog every few seconds after a cancel,
    // which the user cannot escape without force-quitting. So the attempt is
    // made at most once per process launch — and this drives several retry
    // cycles to prove it.
    var calls = 0;
    await pumpHomeWithInstaller(
      tester,
      installer: (uid) async {
        calls++;
        return const InstallResult(
            InstallOutcome.cancelled, 'Installation was cancelled.');
      },
    );
    await tester.pump(const Duration(seconds: 5));
    await tester.pump(const Duration(seconds: 5));
    expect(calls, Platform.isLinux ? 1 : 0,
        reason: 'a second prompt is a loop the user cannot escape');
  });

  testWidgets('a cancelled install shows the command, not an error',
      (tester) async {
    if (!Platform.isLinux) return; // macOS is installed by its package
    await pumpHomeWithInstaller(
      tester,
      installer: (uid) async => const InstallResult(
          InstallOutcome.cancelled, 'Installation was cancelled.'),
    );
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('install-panel')), findsOneWidget);
    expect(find.textContaining('install-helper.sh'), findsOneWidget,
        reason: 'what remains of "read it before it runs as root"');
  });

  testWidgets('macOS never runs a privileged command', (tester) async {
    if (Platform.isLinux) return;
    var calls = 0;
    await pumpHomeWithInstaller(
      tester,
      installer: (uid) async {
        calls++;
        return const InstallResult(InstallOutcome.installed, '');
      },
    );
    await tester.pumpAndSettle();
    expect(calls, 0,
        reason: 'the package installs the helper; the app must not');
  });
```

with this helper beside the other `pump*` helpers:

```dart
/// Pumps the home page with the privileged installer replaced.
///
/// No test may raise a real authorization dialog, so the installer is always
/// injected. The socket path names a file that cannot exist, so the client
/// fails with ENOENT — the "never installed" case, which is the only one that
/// triggers an install.
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

- [ ] **Step 6: Run to verify they fail**

Run: `cd app && flutter test test/widget_test.dart`
Expected: FAIL — `No named parameter with the name 'installer'`.

- [ ] **Step 7: Add the installing state to the model**

In `app/lib/services/connection_model.dart`, add:

```dart
  /// What the first-launch installer is doing, if anything.
  ///
  /// Separate from [Fault] because it is not a fault: an install in progress
  /// is a normal startup, and a cancelled one is the user's answer.
  String? _installNotice;
  String? get installNotice => _installNotice;

  set installNotice(String? v) {
    _installNotice = v;
    notifyListeners();
  }
```

and correct the now-wrong wording, since neither artifact has a `packaging/`:

```dart
    Fault.helperNotInstalled => Platform.isMacOS
        ? 'The helper is not installed. Reinstall LiosTunnel from its '
              'installer package.'
        : 'The helper is not installed or not running.',
```

(`import 'dart:io';` for `Platform`.)

- [ ] **Step 8: Run the installer once, on the right failure, on Linux**

In `app/lib/main.dart`, add to `HomePage`:

```dart
  /// Injected so no test raises a real authorization dialog.
  final Future<InstallResult> Function(int)? installer;
```

with `this.installer` in the constructor. In `_HomePageState`:

```dart
  /// At most once per process launch. See `_installHelper`.
  bool _installAttempted = false;
  String? _installCommandText;
```

Replace `_attach`'s `catch`:

```dart
    } catch (e) {
      model.applyError(e);
      // Only ENOENT, and only on Linux. `HelperForbidden` means the helper IS
      // installed, for somebody else. macOS is installed by its package.
      if (e is HelperUnavailable && Platform.isLinux) await _installHelper();
    }
```

and add:

```dart
  /// Installs the bundled helper under pkexec, raising the polkit dialog.
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
    if (!mounted) return;
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

- [ ] **Step 9: Show the panel**

`app/lib/screens/connection.dart` takes `installCommandText` and
`onRetryInstall`, passed from `main.dart` as `_installCommandText` and
`() => _installHelper(force: true)`. Above the error banner:

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

- [ ] **Step 10: Run everything**

```bash
./testing/build-ffi-for-tests.sh
cd app && flutter analyze && flutter test
```
Expected: analyze clean, all tests pass.

- [ ] **Step 11: A/B each assertion**

| Change | Test that must fail |
|---|---|
| drop the `_installAttempted` guard | `a missing helper installs itself, once` |
| drop `&& Platform.isLinux` | `macOS never runs a privileged command` |
| call `_installHelper` for any exception, not just `HelperUnavailable` | add a case pumping an EACCES socket and assert no call |
| show `result.message` without `_installCommandText` | `a cancelled install shows the command` |

- [ ] **Step 12: Commit**

```bash
git add app/lib app/test
git commit -F /tmp/msg-t5.txt
```

`/tmp/msg-t5.txt`:

```
feat: install the helper on first launch, on Linux, once

An AppImage has no install step and nothing runs as root, so on Linux the app
asks pkexec to run the same install-helper.sh the macOS package runs from its
postinstall. The polkit dialog is the consent gate.

macOS does not get this. Its package already installed the helper, so a
missing one there means something reinstalling from the app would paper over,
and the message names the package instead.

At most once per process launch. HelperClient retries an absent socket on a
timer, and prompting from that would re-raise the dialog every few seconds
after a cancel -- a loop the user cannot escape without force-quitting. The
panel's retry button is the way back, because that one was asked for.

Also corrects the not-installed message, which named packaging/install-helper.sh
-- a path that exists in neither artifact.
```

---

## Exit criteria

| Criterion | Verified by |
|---|---|
| PKG-1 — CI builds the app on both platforms | Task 4 |
| PKG-2 — the package places the app in `/Applications` with the helper inside | Task 2 step 1, `verify-pkg.sh` |
| PKG-3 — the postinstall passes the console uid and refuses a uid below 500 | Task 2 step 1, the two postinstall assertions |
| PKG-4 — the AppImage is one file, carries the helper, `AppRun` is executable | Task 3 step 3 |
| PKG-5 — the bundled helper is a working executable for its platform | Tasks 2 and 3, `--version` |
| PKG-6 — Linux first launch raises the polkit dialog and installs on approval | Task 5 step 5 |
| PKG-7 — cancelling leaves the app usable and produces no second prompt | Task 5, `installs itself, once` |
| PKG-8 — macOS never runs a privileged command from the app | Task 5, `macOS never runs a privileged command` |

**PKG-3 is the one to care about.** The rest make the artifacts usable; that
one is the authorization boundary surviving a new way of being invoked. A
helper authorizing uid 0 — or `_mbsetupuser`, which the uid-0 guard does not
catch — accepts a client the design exists to exclude.

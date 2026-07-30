# Desktop packaging: a macOS `.pkg` and a Linux AppImage — design

**Goal.** One artifact per platform that gets you a working LiosTunnel. On
macOS a `.pkg` that drops the app in `/Applications` and installs the
privileged helper in the same run. On Linux a single-file `.AppImage` that
runs on any distro and installs the helper on first launch. Both built by CI
on every push to `main`.

**Not in scope.** Code signing and notarization. `SMAppService`. Windows.
`.deb`/`.rpm`. Auto-update. Universal (fat) macOS binaries.

---

## 1. Why this is not just convenience

CI today runs `flutter test` and never `flutter build`. Those are different
code paths: the build is where cargokit, CMake, the Xcode project and the
podspec live, and none of them is exercised by a test run. **A change that
breaks the macOS bundle passes every check on `main` right now.**

## 2. The asymmetry, stated first because it drives everything

**A `.pkg` installs. An AppImage does not.**

`Installer.app` runs a package's `postinstall` script as root, so the macOS
artifact can place the app, install the helper and load the launchd daemon in
one operation. An AppImage is a single portable file you `chmod +x` and run —
there is no install step and nothing runs as root.

| | macOS | Linux |
|---|---|---|
| Artifact | `LiosTunnel-<sha>.pkg` | `LiosTunnel-<sha>.AppImage` |
| App lands at | `/Applications/LiosTunnel.app` | wherever the file is |
| Helper installed by | the `postinstall`, as root | the app, first launch, via `pkexec` |
| App carries privileged code | no | yes |

So the app keeps a first-launch install path, for Linux only. That is the
price of "one file, any distro" instead of a `.deb` that serves Debian and
Ubuntu and nothing else.

## 3. What follows from being unsigned

- **Both artifacts are unsigned.** No Developer ID, no CI secrets, no $99/yr.
- **Gatekeeper blocks a double-clicked unsigned `.pkg`.** Right-click → Open
  once, or `sudo installer -pkg LiosTunnel-<sha>.pkg -target /` from a
  terminal. A consequence of the decision, stated in the README rather than
  discovered.
- **The macOS build is single-architecture.** cargokit compiles the Rust
  static library for the runner's host arch and GitHub's `macos-latest` is
  arm64, so the `.pkg` will not run on an Intel Mac.

## 4. The macOS package

**Payload: the app alone.** `/Applications/LiosTunnel.app`, with the helper,
its plist and the install scripts inside `Contents/Resources/helper/`.

The helper is *not* a second payload component installed to
`/usr/local/libexec` by the package. It is placed there by `install-helper.sh`,
run from the postinstall — so **the install logic has one owner** whether it
runs from a package, from a terminal, or (on Linux) from the app. Two
implementations of "install the helper" is how they drift, and this one bakes
an authorization boundary into a root-owned file.

```sh
# packaging/macos-pkg/postinstall  — runs as root, under Installer.app
helper=/Applications/LiosTunnel.app/Contents/Resources/helper

# Who is actually using this machine. The installer runs as root and neither
# SUDO_UID nor PKEXEC_UID exists here, so the console user is the only honest
# source. `install-helper.sh` refuses uid 0, so a package run at the login
# window fails loudly rather than authorizing root.
uid="$(stat -f %u /dev/console)"

# And refuse the system accounts too. During Setup Assistant the console user
# is `_mbsetupuser` (uid 248) -- not 0, so the uid-0 guard would let it
# through, and the helper would end up serving an account that stops existing.
# Regular macOS accounts start at 501.
[ "$uid" -ge 500 ] || { echo "no logged-in user to authorize (uid $uid)" >&2; exit 1; }

exec "$helper/install-helper.sh" --uid "$uid"
```

`install-helper.sh` already accepts `--uid N` and already refuses uid 0, a
non-numeric uid, one with leading zeros, and one it cannot determine. **The
postinstall adds exactly one rule the script cannot know** — that a console
uid below 500 is a system account, not a person.

Built with `pkgbuild --root <stage> --scripts <scripts> --install-location /`.
`productbuild` is not used: it adds a distribution wrapper for choices and
licence panes this package does not have.

## 5. The Linux AppImage

An AppDir assembled from the Flutter Linux bundle, with the helper inside it,
turned into a single file by `appimagetool`:

```
AppDir/
  AppRun                       → usr/bin/liostunnel
  liostunnel.desktop
  liostunnel.png
  usr/bin/liostunnel           the Flutter bundle's executable
  usr/lib/…                    its libraries
  usr/bin/helper/              liostunnel-helper, .service, install-helper.sh
```

**An AppImage mounts itself at `/tmp/.mount_XXXXXX` at runtime**, so
`Platform.resolvedExecutable` points inside an ephemeral mount. The helper
binary is read from there and copied to `/usr/local/libexec` by
`install-helper.sh` while the mount is live, which works — and is pinned by a
test rather than assumed, because "it worked when I tried it" and "it is
guaranteed" are different claims.

`appimagetool` is downloaded by CI. It is not in this repo and not on the
author's machine, which is worth saying plainly: along with
`flutter build linux`, its first run is in CI.

## 6. First launch, Linux only

The app already distinguishes the two socket failures: `HelperUnavailable`
(ENOENT — never installed) and `HelperForbidden` (EACCES — installed for a
different user). **The install runs only for the first**, and only on Linux.

On macOS the package installed the helper, so a missing one means something is
wrong that reinstalling from the app would paper over. Its message names the
package instead.

On Linux, at startup, after the first attach fails with `HelperUnavailable`:
`pkexec <mount>/usr/bin/helper/install-helper.sh --uid <uid>`, which raises the
polkit password dialog. On success the client retries the socket.

### Once per launch, and this is not negotiable

`HelperClient` retries an absent socket on a timer. Prompting from that would
re-raise the password dialog every few seconds after a cancel — a loop the
user cannot escape without force-quitting.

**At most one attempt per process launch.** After a cancel or a failure the
screen shows a panel naming the exact command and offering a retry button, and
nothing prompts on its own again. A user who cancels has said no.

### Failure modes

| | |
|---|---|
| User cancels | `pkexec` exits **126**. Not an error — the panel appears, nothing red |
| `pkexec` absent | Exit **127**. The panel names the manual command |
| Script fails | Its stderr shown verbatim. It is our script and its messages are fixed strings we wrote — unlike the helper's, which the app never renders |
| Succeeds | The client retries the socket; the panel never appears |

## 7. Testing

**`testing/verify-pkg.sh`** — expands the package with `pkgutil --expand`, so
nothing is installed and no root is needed. Asserts: the payload contains
`Applications/LiosTunnel.app`; the helper, its plist and `install-helper.sh`
are inside `Contents/Resources/helper`; the systemd unit is **not**; the
`postinstall` exists, is executable, passes `--uid`, and carries the ≥500
guard; the bundled helper runs (`--version` prints and exits 0), proving a
binary for this platform rather than a placeholder or the wrong arch.

**`testing/verify-appimage.sh`** — runs the AppImage with `--appimage-extract`
(no mount, no FUSE, works in CI), then asserts the same shape for the Linux
layout, plus that `AppRun` is executable.

**Dart tests** for the first-launch path, with the privileged runner injected
so no test escalates: the install runs on `HelperUnavailable` and not on
`HelperForbidden`; **it runs at most once per launch**, asserted by driving
several socket-retry cycles and counting invocations; a cancel shows the panel
and raises no error; the resolved script path is correct for an AppImage mount
layout; a path containing a space survives quoting.

**Deliberately not tested:** that a real install succeeds, or that the app
launches. Those need root and a display server — the verification script's
job, not CI's.

## 8. Exit criteria

| | |
|---|---|
| PKG-1 | CI builds the app on both platforms; a broken `flutter build` fails the workflow |
| PKG-2 | The `.pkg` payload places the app in `/Applications` with the helper inside it |
| PKG-3 | The postinstall passes the console user's uid, and refuses a uid below 500 |
| PKG-4 | The AppImage is one file, carries the helper, and its `AppRun` is executable |
| PKG-5 | The bundled helper is a working executable for its platform |
| PKG-6 | On Linux, first launch with no helper raises the polkit dialog and installs on approval |
| PKG-7 | Cancelling leaves the app usable and **produces no second prompt** for the life of the process |
| PKG-8 | On macOS a missing helper names the package, and no privileged command is run |

**PKG-3 is the one to care about.** Everything else makes the artifacts
usable; that one is the authorization boundary surviving a new way of being
invoked. A helper installed authorizing uid 0 — or `_mbsetupuser` — accepts a
client the design exists to exclude.

## 9. Risks

**`flutter build linux` has never run anywhere in this repo**, and neither has
`appimagetool`. Their first run is in CI, and it may need more than the two
apt packages named in the workflow. That is the expected outcome of a first
attempt, not a design failure.

**cargokit builds Rust during the Flutter build**, so the Rust toolchain must
be present before `flutter build`, not only before `cargo build`.

**`stat -f %u /dev/console` is a macOS idiom with a fast-user-switching
caveat.** With two accounts logged in it names whoever owns the console at
that moment, which is the right answer for "who is installing this" and the
wrong one if someone installs from a switched-to session on another's behalf.
The helper serves one uid by design; a second user reinstalls.

**An unsigned `.pkg` and an unsigned AppImage both carry a binary that becomes
a root daemon.** Acceptable for machines whose owner built them from their own
source; not for anyone else's. That is the line the audience decision drew and
this is where it has teeth.

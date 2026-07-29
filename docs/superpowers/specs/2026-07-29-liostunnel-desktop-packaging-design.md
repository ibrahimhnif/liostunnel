# Desktop packaging, build CI, and first-launch install — design

**Goal.** One download per platform that is a working LiosTunnel: the app,
with the helper it needs embedded inside it, installed on first launch through
the operating system's own authorization dialog. Built by CI on every push to
`main`, so a change that breaks the build is caught the day it breaks.

**Not in scope.** Code signing and notarization. `SMAppService`. Windows.
`.dmg` and `.deb`. Version stamping beyond the commit sha. Universal (fat)
macOS binaries. Auto-update.

---

## 1. Why this is not just convenience

CI today runs `flutter test` and never `flutter build`. Those are different
code paths: the build is where cargokit, CMake, the Xcode project and the
podspec live, and none of them is exercised by a test run. **A change that
breaks the macOS bundle passes every check on `main` right now.** The
packaging job is the first thing that would catch it, and that is the larger
half of its value.

## 2. The audience decision, and what follows

The artifacts are for the author's own machines. That settles four things:

- **No signing**, so no Developer ID, no certificate in CI secrets, no $99/yr.
- **`SMAppService` is unavailable.** It is the supported way for an app to
  install a privileged daemon, and it requires the app to be signed with a
  Developer ID and the helper embedded with a matching signature. Without
  signing there is no supported route, which is why §5 uses an unsupported
  one.
- **The `.app` will be quarantined.** macOS refuses a downloaded unsigned
  bundle until it is opened once from the context menu, or
  `xattr -dr com.apple.quarantine LiosTunnel.app` is run. A consequence of the
  decision, not a defect. It happens *before* first launch, so it is the one
  step no amount of in-app polish removes.
- **The macOS build is single-architecture.** cargokit compiles the Rust
  static library for the runner's host arch, and GitHub's `macos-latest` is
  arm64. The archive will not run on an Intel Mac.

**Stated plainly, because it is the trade this phase makes:** running the
install script yourself means you can read it before it runs as root. Letting
the app do it means approving a dialog and trusting the app to have chosen
what runs. For an unsigned binary, that is the weaker posture. For machines
whose owner built it from their own source it is fine; for anyone else's it
would not be, and that is the same line the audience decision already drew.

## 3. The helper lives inside the app

```
macOS   LiosTunnel.app/Contents/Resources/helper/
Linux   liostunnel/helper/
            liostunnel-helper
            liostunnel-helper.plist      (macOS)
            liostunnel-helper.service    (Linux)
            install-helper.sh
            uninstall-helper.sh
```

Found at runtime from `Platform.resolvedExecutable`, which is
`…/Contents/MacOS/LiosTunnel` on macOS and `…/liostunnel` on Linux — so the
directory is `../Resources/helper` and `./helper` respectively. One function,
`helperBundleDir()`, owns that difference.

**App and helper cannot mismatch**, because they are one file built from one
commit. `PROTOCOL_VERSION` is a wire contract between them and a mismatched
pair fails at the `hello` handshake; shipping them together is what makes that
unreachable.

## 4. `install-helper.sh` must learn the uid three ways

This is the load-bearing change, and getting it wrong collapses the boundary
the helper exists to enforce.

The script bakes an authorized uid into a root-owned unit file. Today it reads
`SUDO_UID`, refuses to run without it, and refuses uid 0 — because a helper
that accepts a root client defeats a design whose entire premise is that the
caller is unprivileged and must have its secrets checked against its own
ownership.

**Neither `osascript` nor `pkexec` sets `SUDO_UID`.** `pkexec` sets
`PKEXEC_UID`; `osascript … with administrator privileges` sets neither, and
runs with `USER=root`. So a script that only reads `SUDO_UID` either dies, or
— if the guard were relaxed to "fall back to the current user" — would
authorize **uid 0**, silently, on exactly the path this phase adds.

```sh
# Three ways in, one rule. The uid to authorize is the HUMAN's, never the
# elevated process's:
#   SUDO_UID    set by sudo
#   PKEXEC_UID  set by pkexec
#   --uid N     passed by the app, which knows its own uid
# There is deliberately no fallback to `id -u`: under every one of these the
# answer would be 0, and a helper that authorizes root is a helper with no
# boundary at all.
uid="${LIOS_UID:-${SUDO_UID:-${PKEXEC_UID:-}}}"
[ -n "$uid" ] || die "cannot tell which account to authorize; run with sudo, or pass --uid"
[ "$uid" -ne 0 ] || die "refusing to authorize uid 0; the helper must serve an unprivileged user"
```

`--uid N` sets `LIOS_UID`. The existing refusals stay exactly as they are —
this widens where the uid may come from and changes nothing about what is
rejected.

**The binary lookup also widens**, since in a bundle there is no `target/`:

```sh
# Beside this script in a bundle, under target/release in a checkout. One
# script serving both beats a second copy free to drift from the first.
# Beside-the-script wins: unpacking a bundle inside a checkout should use the
# bundle's binary, not whatever is stale in target/.
```

## 5. First launch installs the helper

**Automatic, on the first detection, with the operating system's own password
dialog as the consent gate.** No button in front of it: the OS prompt is the
real gate, and an app-drawn confirmation ahead of it is friction that adds
nothing a user reads.

The app already distinguishes the two failures the socket can give it:
`HelperUnavailable` (ENOENT — never installed) and `HelperForbidden`
(EACCES/EPERM — installed for a different user). **The install runs only for
the first.** Installing over a helper someone else owns is a different
decision with a different consequence, and that case keeps its current
message.

So, at startup, after the first attach fails with `HelperUnavailable`:

- **macOS:** `osascript -e 'do shell script "…" with administrator privileges'`
- **Linux:** `pkexec …`

Both raise the OS password dialog. Neither needs signing. On success the
client retries the socket and the screen shows Disconnected.

While the dialog is up the screen says what is happening — *"Installing the
privileged helper. macOS is asking for your password."* — so a prompt that
appears the instant the app opens is explained rather than mysterious.

### Once per launch, and this is not negotiable

`HelperClient` retries a dropped or absent socket on a timer. Wiring the
prompt to that would re-raise the password dialog every few seconds after a
cancel — a loop the user cannot escape without force-quitting the app.

**The attempt is made at most once per process launch.** After a cancel or a
failure the screen falls back to a panel that names the exact command
(`…/helper/install-helper.sh --uid 501`) and offers a button to try again, and
no further prompt appears on its own. A user who cancels has said no; asking
again unprompted is how an app becomes something you close.

### Failure modes, each with its own message

| | |
|---|---|
| User cancels | `osascript` exits 1 with `User canceled` (error `-128`); `pkexec` exits **126**. Not an error — the panel appears, no toast, nothing red |
| Wrong password | The OS retries and then fails. Reported as "authorization failed", not as an install failure |
| `pkexec` absent | Exit **127**, or the spawn fails. The panel names the manual command instead |
| Script fails | Its stderr shown verbatim. It is our script and its messages are fixed strings we wrote — unlike the helper's, whose wording the app never renders |
| Succeeds | The client retries the socket; the panel never appears |

**A path containing a space breaks `do shell script`** if built by string
concatenation, and `/Applications/` is not the only place an app lands. Every
path is quoted for the shell before interpolation, and a test covers a
directory whose name contains a space.

### What this costs, recorded because it was a deliberate choice

Running the script by hand means reading it before it runs as root. This
replaces that with an OS dialog and trust that the app chose what runs. For an
unsigned binary that is the weaker posture — and it is the same line the
audience decision drew, so it is consistent rather than new. The panel's
command text is what remains of "see it before it runs", available after a
cancel and in the README.

## 6. The CI job

```yaml
  package:
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest]
```

Checkout → Rust 1.93 → `Swatinem/rust-cache` → `subosito/flutter-action` →
**Linux apt packages** → `cargo build --release -p liostunnel-helper` →
`flutter build` → `packaging/make-bundle.sh` → `testing/verify-bundle.sh` →
`actions/upload-artifact`.

**`ninja-build` and `libgtk-3-dev` on Ubuntu are the most likely first
failure**, and it presents as a Flutter bug rather than a missing package.
Installed explicitly, with a comment saying why.

`fail-fast: false`, so a macOS failure still produces the Linux archive.

**Assembly lives in `packaging/make-bundle.sh`, which CI calls** — not in
YAML. A wrong bundle is then debugged on the machine that is confused, instead
of by pushing commits at a runner and waiting. The script assumes both builds
have run and fails naming the command that produces a missing input; assembly
and building stay separate so a failed build is not reported as a packaging
problem.

Output: `dist/liostunnel-<os>-<short-sha>.tar.gz`, containing the app bundle
with the helper inside it, plus a `README.txt` written by the script (it names
the platform and the sha, so it is generated rather than committed).

## 7. Testing

Packaging is shell and YAML, so the tests differ in kind from the rest of this
repo — but the rule holds: a check that cannot fail is not a check.

**`testing/verify-bundle.sh`**, run by CI after the bundle is built and
runnable locally:

- the archive exists and unpacks;
- every file §3 lists is present **inside the app bundle**, and the other
  platform's unit file is not;
- `liostunnel-helper --version` prints `liostunnel-helper <version>` and exits
  0 — proving a binary that runs on this platform, not a placeholder or one
  built for the wrong arch. (Verified against the current binary: clap's
  `version` attribute is already on `Args`, so no code change is needed.)
- the app's executable exists and is executable, at
  `LiosTunnel.app/Contents/MacOS/LiosTunnel` or `liostunnel/liostunnel`;
- **`install-helper.sh --uid 501` reaches the install step**, checked with
  stubbed `install`/`launchctl`/`systemctl` on `PATH`, so no root is needed
  and nothing is installed;
- **`install-helper.sh` with no uid available refuses**, and
  **`--uid 0` refuses** — the two guards §4 must not have weakened. These are
  the assertions that matter most in the whole file.

**Dart tests** for the first-launch path, with the privileged runner injected
as a function so no test ever escalates:

- the install runs on `HelperUnavailable` and **not** on `HelperForbidden`;
- **it runs at most once per launch** — the covering test drives several
  socket-retry cycles and asserts the privileged runner was invoked exactly
  once. This is the assertion that stops a password-prompt loop;
- the panel's command text names the resolved script path and the real uid;
- a cancel (exit 126 / `User canceled`) shows the panel and raises no error;
- a failure shows the script's stderr;
- success re-tries the socket;
- `helperBundleDir()` resolves correctly for both platforms' executable
  layouts, and a path containing a space survives quoting.

**Deliberately not tested:** that the app launches, or that a real install
succeeds. Those need a display server and root — the verification script's
job (`testing/verify-phase1a.sh`), not CI's.

## 8. Error handling

`make-bundle.sh` runs under `set -euo pipefail`, fails on a missing input
naming the command that produces it, and removes a partial `dist/` so a stale
archive cannot be uploaded as current.

The app never renders the helper's own error text — that rule is unchanged and
already enforced. It *does* render `install-helper.sh`'s stderr, which is
different: that script is ours, its messages are fixed strings we wrote, and
the alternative is a failure the user cannot act on.

## 9. Exit criteria

| | |
|---|---|
| PKG-1 | CI builds the app on both platforms; a change that breaks `flutter build` fails the workflow |
| PKG-2 | Each run uploads one archive per platform, with the helper embedded in the app bundle |
| PKG-3 | `install-helper.sh` accepts a uid from `SUDO_UID`, `PKEXEC_UID` or `--uid`, still refuses uid 0, and still refuses when it cannot tell |
| PKG-4 | `install-helper.sh` finds the bundled binary, and still finds `target/release` in a checkout |
| PKG-5 | The bundled helper is a working executable for its platform |
| PKG-6 | First launch with no helper raises the OS password dialog automatically and installs on approval |
| PKG-7 | Cancelling leaves the app usable, raises no error, and **produces no second prompt** for the life of the process |
| PKG-8 | A path containing a space still works; `pkexec` being absent names the manual command |

**PKG-3 is the one to care about.** The others make the artifact usable; that
one is the security boundary surviving a new way of being invoked. A helper
installed with uid 0 authorized would accept a root client, which is the whole
thing the design exists to prevent.

## 10. Risks

**The Linux Flutter build has never run anywhere.** `app/linux/` exists and
cargokit is wired for it, but nothing in this repo has executed
`flutter build linux`. The first CI run is that build's first run, and it may
need more than the two apt packages named. That is the expected outcome of the
first attempt.

**cargokit builds Rust during the Flutter build**, so the Rust toolchain must
be present before `flutter build`, not only before `cargo build`. Ordering the
steps wrong produces an error about CMake.

**The macOS authorization dialog's wording is not fully under our control.**
It may name the app or it may name `osascript`, depending on how the process
is bundled and signed. This is checked on the first real run and the panel's
copy adjusted to match what actually appears — promising the user a dialog
that says something else is worse than saying less.

**`pkexec` is not installed everywhere.** It is present on Ubuntu, Fedora and
Debian desktops, absent on minimal installs. Exit 127 is handled by naming the
manual command.

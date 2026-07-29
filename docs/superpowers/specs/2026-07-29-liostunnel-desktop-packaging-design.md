# Desktop packaging and build CI — design

**Goal.** One download per platform that gets you a working LiosTunnel: the
app, the helper it needs, and a script that installs the helper. Built by CI
on every push to `main`, so a change that breaks the build is caught the day
it breaks rather than the day you need a build.

**Not in scope.** Code signing and notarization. Windows. `.dmg` and `.deb`.
Version stamping beyond the commit sha. Universal (fat) macOS binaries.
Auto-update.

---

## 1. Why this is not just convenience

CI today runs `flutter test` and never `flutter build`. Those are different
code paths: the build is where cargokit, CMake, the Xcode project and the
podspec live, and none of them is exercised by a test run. **A change that
breaks the macOS bundle passes every check on `main` right now.** The
packaging job is the first thing that would catch it, and that is the larger
half of its value.

## 2. The audience decision, and what follows from it

The artifacts are for the author's own machines. That settles three things:

- **No signing.** A Developer ID certificate and its private key in CI
  secrets, plus $99/yr, buy nothing for a build only its author runs.
- **The `.app` will be quarantined.** macOS refuses a downloaded unsigned
  bundle until it is opened once from the context menu, or
  `xattr -dr com.apple.quarantine LiosTunnel.app` is run. This is a
  consequence of the decision, not a defect, and the archive's README says so
  in those words.
- **The macOS build is single-architecture.** cargokit compiles the Rust
  static library for the runner's host arch, and GitHub's `macos-latest` is
  arm64. The archive will not run on an Intel Mac. Recorded rather than
  solved; a universal build is a later decision with its own cost.

## 3. A script CI calls, not steps CI owns

`packaging/make-bundle.sh` does the assembly. CI installs the toolchain, runs
the script, and uploads what it produced.

The alternative — build steps written inline in the workflow — fails the same
way every time: the bundle is wrong, and the only way to see why is to push a
commit at a runner and wait. A script runs on the machine that is confused.

```
packaging/make-bundle.sh            # → dist/liostunnel-<os>-<sha>.tar.gz
```

It assumes the two builds have already run (`cargo build --release -p
liostunnel-helper`, `flutter build macos|linux --release`) and **fails loudly
naming the missing command** if either output is absent. Assembly and building
are separate so a failed build is not reported as a packaging problem.

## 4. What is in the archive

```
liostunnel-<os>-<short-sha>/
  LiosTunnel.app/                  macOS: the bundle from build/macos/…/Release
  liostunnel/                      Linux: the bundle dir from build/linux/…/release/bundle
  liostunnel-helper                the release binary
  liostunnel-helper.plist          macOS only
  liostunnel-helper.service        Linux only
  install-helper.sh                adapted; see §5
  uninstall-helper.sh              unchanged — it removes installed paths and
                                   never reads the source binary
  README.txt
```

Only the current platform's unit file ships. Carrying both would put a
systemd unit in a macOS archive, which reads as an oversight rather than
symmetry.

**App and helper travel together on purpose.** `PROTOCOL_VERSION` is a wire
contract between them; a mismatched pair fails at the `hello` handshake. Built
from one commit and shipped in one archive, they cannot mismatch. This is also
why two separate artifacts were rejected.

## 5. `install-helper.sh` gains one lookup

Today it insists on `$repo/target/release/liostunnel-helper` and dies with the
`cargo build` command otherwise. In the archive there is no `target/`.

```sh
# The binary sits beside this script in a release archive, and under
# target/release in a checkout. Looking in both means one script serves both
# rather than a second copy free to drift from the first -- which is the same
# argument the profile format makes for having one parser.
if [ -f "$here/$BINARY" ]; then
  src="$here/$BINARY"
elif [ -f "$repo/target/release/$BINARY" ]; then
  src="$repo/target/release/$BINARY"
else
  die "no helper binary beside this script or at $repo/target/release/$BINARY — in a checkout, run: cargo build --release -p liostunnel-helper"
fi
```

Order matters: beside-the-script first. Someone who unpacks an archive inside
a checkout should get the archive's binary, not whatever is stale in
`target/`.

Everything else about the script is unchanged, including the parts that carry
the security argument: it refuses to run without `SUDO_UID`, refuses to
authorize uid 0, and bakes the authorized uid into a root-owned unit file.

## 6. The CI job

```yaml
  package:
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest]
```

Steps: checkout, Rust 1.93, `Swatinem/rust-cache`, `subosito/flutter-action`,
**the Linux apt packages**, `cargo build --release -p liostunnel-helper`,
`flutter build`, `packaging/make-bundle.sh`, `actions/upload-artifact`.

**`ninja-build` and `libgtk-3-dev` on Ubuntu are the most likely first
failure**, and the way it fails reads like a Flutter bug rather than a missing
package. They are installed explicitly, with a comment saying why.

Triggered on push to `main` and on pull requests, matching the rest of the
workflow. Artifacts are named `liostunnel-<os>-<short-sha>`.

`fail-fast: false` so a macOS failure still produces the Linux archive — the
two builds share nothing but the script.

## 7. The README in the archive

Written by `make-bundle.sh`, not committed, because it names the platform and
the sha. It says, in this order:

1. Install the helper: `sudo ./install-helper.sh`, run **from the account that
   will use the app** — the script bakes that uid into the unit file and
   refuses to run without it.
2. macOS only: the quarantine flag, and both ways to clear it.
3. Where the socket is and how to check the helper is running.
4. That the app and helper in this archive are a matched pair, and mixing
   versions fails at the handshake with `version_mismatch`.
5. `sudo ./uninstall-helper.sh` to remove it.

## 8. Testing

Packaging is shell and YAML, so the tests are of a different kind than the
rest of this repo — but the same rule applies: a check that cannot fail is
not a check.

**`make-bundle.sh` gets a test script**, `testing/verify-bundle.sh`, run by CI
after the bundle is built and runnable locally. It asserts:

- the archive exists and unpacks;
- every file §4 lists is present, and the *other* platform's unit file is not;
- `liostunnel-helper` is executable and `./liostunnel-helper --version`
  prints `liostunnel-helper <version>` and exits 0 — proving a binary that
  actually runs on this platform, not a zero-byte placeholder or one built
  for the wrong arch. (Verified against the current binary: clap's `version`
  attribute is already on `Args`, so no code change is needed for this.)
- `install-helper.sh` finds the bundled binary rather than dying — checked by
  running it with a stubbed `install`/`launchctl`/`systemctl` on `PATH` and a
  fake `SUDO_UID`, so **no root is needed and nothing is installed**;
- the app's executable exists and is executable, at
  `LiosTunnel.app/Contents/MacOS/LiosTunnel` on macOS and `liostunnel/liostunnel`
  on Linux.

The last two are the ones that would catch a real regression. The others catch
a bundle assembled wrong.

**What is deliberately not tested:** that the app launches. That needs a
display server and a working helper, which is the verification script's job
(`testing/verify-phase1a.sh`), not CI's.

## 9. Error handling

`make-bundle.sh` runs under `set -euo pipefail` and fails on a missing input
naming the command that produces it — the same shape `install-helper.sh`
already uses for its missing-binary case. A partially assembled `dist/` is
removed on failure, so a stale archive from an earlier run cannot be uploaded
as if it were current.

## 10. Exit criteria

| | |
|---|---|
| PKG-1 | CI builds the app on both platforms; a change that breaks `flutter build` fails the workflow |
| PKG-2 | Each run uploads one archive per platform containing everything §4 lists |
| PKG-3 | `install-helper.sh` finds the bundled binary, and still finds `target/release` in a checkout |
| PKG-4 | The archive carries only its own platform's unit file |
| PKG-5 | The bundled helper is a working executable for its platform, not a placeholder |
| PKG-6 | The README names the quarantine step and the run-as-your-own-user rule |

PKG-1 is the one that pays for itself. The others make the artifact usable;
that one catches the breakage nothing currently catches.

## 11. Risks

**The Linux Flutter build has never run anywhere.** `app/linux/` exists and
cargokit is wired for it, but nothing in this repo has executed
`flutter build linux`. The first CI run is that build's first run, and it may
need more than the two apt packages named above. That is the expected outcome
of the first attempt, not a failure of the design.

**cargokit builds Rust during the Flutter build**, so the Rust toolchain must
be present before `flutter build`, not only before `cargo build`. Ordering the
steps wrong produces an error message about CMake.

**The archive is unsigned and downloaded over HTTPS from GitHub.** It carries
a binary that gets installed as a root daemon. That is acceptable for the
author's own machines and would not be for anyone else's — which is the same
line the audience decision drew, restated here because this is where it has
teeth.

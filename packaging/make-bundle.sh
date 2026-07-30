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

# `2>/dev/null || true` is what makes the die messages below reachable. When
# the build has not run the whole directory is absent, so find exits non-zero
# -- and under `set -e` with pipefail that killed this script on the
# assignment itself, printing find's own "No such file or directory" and never
# reaching the line that says which command to run. The guard read as a guard
# and was one only when the directory happened to exist but was empty.
case "$(uname -s)" in
  Darwin)
    os=macos
    app="$(find "$repo/app/build/macos/Build/Products/Release" -maxdepth 1 -name '*.app' 2>/dev/null | head -1 || true)"
    [ -n "$app" ] || die "no .app under app/build/macos/… — run: cd app && flutter build macos --release"
    unit=liostunnel-helper.plist
    ;;
  Linux)
    os=linux
    app="$(find "$repo/app/build/linux" -maxdepth 3 -type d -name bundle 2>/dev/null | head -1 || true)"
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

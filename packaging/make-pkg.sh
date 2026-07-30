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

# Refuse relocation. `pkgbuild --root` marks an app bundle relocatable by
# default, which means Installer.app looks up the bundle id on the target
# machine and redirects the payload onto whatever copy it finds -- a stray one
# in ~/Downloads, say. The app would land there instead of /Applications, and
# the postinstall's fixed path would then not exist, so it would fail AFTER the
# app had already moved. This says: install where I said.
comp="$dist/component.plist"
pkgbuild --analyze --root "$stage" "$comp"
/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" "$comp"

out="$dist/LiosTunnel-$sha.pkg"
pkgbuild \
  --root "$stage" \
  --component-plist "$comp" \
  --scripts "$here/macos-pkg" \
  --identifier com.liostunnel.pkg \
  --version "0.1.0-$sha" \
  --install-location / \
  "$out"

rm -rf "$stage" "$comp"
echo "$out"

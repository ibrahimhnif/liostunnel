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
  # AppImage/AppImageKit's "continuous" release is now marked obsolete by its
  # maintainers, who moved the tool to its own repo; the old URL still
  # resolves but only serves a stale, unmaintained build.
  curl -fsSL -o "$tool" \
    https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
  chmod 755 "$tool"
fi

out="$dist/LiosTunnel-$sha-x86_64.AppImage"
# --appimage-extract-and-run because CI containers have no FUSE.
ARCH=x86_64 "$tool" --appimage-extract-and-run "$appdir" "$out"
echo "$out"

#!/usr/bin/env bash
#
# Regenerates every platform's app icon from the one source SVG.
#
#     ./packaging/make-icons.sh
#
# macOS only: `qlmanage` is the rasteriser, because this repo has no
# ImageMagick or rsvg-convert and adding one for an icon nobody regenerates
# weekly is not worth a dependency. The outputs ARE committed, so a Linux or
# CI checkout never needs to run this -- it is a maintenance tool, not a build
# step.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
src="$repo/assets/logo/liostunnel.svg"

die() { echo "error: $*" >&2; exit 1; }
[ -f "$src" ] || die "no source at $src"
[ "$(uname -s)" = Darwin ] || die "needs macOS's qlmanage to rasterise; outputs are committed, so this is only for changing the logo"
command -v qlmanage >/dev/null || die "qlmanage not found"

# Parse both sources as XML first. An SVG that is not well-formed does not
# make qlmanage fail -- it makes it fall back to thumbnailing the file as a
# TEXT DOCUMENT, so a PNG is produced, `[ -f ]` passes, and the app ships an
# icon of grey lines on white. That happened here, from a `--` inside an XML
# comment, which XML forbids. The guard is the parse, not the file's presence.
for f in "$src" "$repo/assets/logo/liostunnel-small.svg"; do
  python3 -c "import sys,xml.etree.ElementTree as E; E.parse(sys.argv[1])" "$f" \
    || die "not well-formed XML, so qlmanage would thumbnail it as text: $f"
done

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
qlmanage -t -s 1024 -o "$tmp" "$src" >/dev/null 2>&1
master="$tmp/$(basename "$src").png"
[ -f "$master" ] || die "qlmanage produced no PNG from $src"

# The canonical raster, committed: the AppImage uses it directly, and anything
# that cannot run qlmanage has something to fall back on.
cp "$master" "$repo/assets/logo/liostunnel-1024.png"

# macOS. The sizes come from Contents.json, which references each file at both
# 1x and 2x -- so 32, 128, 256 and 512 each serve two entries.
icons="$repo/app/macos/Runner/Assets.xcassets/AppIcon.appiconset"
[ -d "$icons" ] || die "no macOS icon set at $icons"
# 16 and 32 come from the simplified glyph. The full mark's two concentric
# arches merge below roughly 48px and its light dot all but disappears --
# established by rendering them enlarged and looking, not by assuming a
# vector scales. Everything from 64 up uses the full mark.
qlmanage -t -s 1024 -o "$tmp" "$repo/assets/logo/liostunnel-small.svg" >/dev/null 2>&1
small="$tmp/liostunnel-small.svg.png"
[ -f "$small" ] || die "qlmanage produced no PNG from the small glyph"

for s in 16 32; do
  sips -z "$s" "$s" "$small" --out "$icons/app_icon_$s.png" >/dev/null
done
for s in 64 128 256 512 1024; do
  sips -z "$s" "$s" "$master" --out "$icons/app_icon_$s.png" >/dev/null
done

echo "wrote $repo/assets/logo/liostunnel-1024.png"
echo "wrote $icons/app_icon_{16,32,64,128,256,512,1024}.png"
echo
echo "Android and iOS have no runner directories yet; when they exist, add"
echo "them here rather than generating their icons by hand."

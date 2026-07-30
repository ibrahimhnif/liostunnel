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

# An extraction that produced nothing would make every path assertion below
# vacuous: they would all report a missing file, and none of them would be
# reading the AppImage.
[ -n "$(ls -A "$root" 2>/dev/null)" ] || { echo "the AppImage extracted to nothing"; exit 1; }

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
# The directory has to exist before its absence means anything: `[ ! -f ]`
# against a path under a directory that is not there is trivially true, so a
# payload with no usr/bin/helper at all would pass this line while claiming
# to have looked inside it.
if [ ! -d "$inner" ]; then
  bad "no helper directory, so nothing was checked for a launchd plist"
elif [ ! -f "$inner/liostunnel-helper.plist" ]; then
  ok "the launchd plist is absent"
else
  bad "a launchd plist is in a Linux AppImage"
fi

v="$("$inner/liostunnel-helper" --version 2>&1)"
if [ $? -eq 0 ] && [ "${v#liostunnel-helper }" != "$v" ]; then
  ok "the bundled helper runs: $v"
else
  bad "the bundled helper did not run: $v"
fi

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]

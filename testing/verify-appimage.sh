#!/usr/bin/env bash
#
# Proves the AppImage carries what it claims, without mounting it.
#
#     ./testing/verify-appimage.sh dist/LiosTunnel-abc1234-x86_64.AppImage
#
set -uo pipefail
img="${1:-}"
[ -f "$img" ] || { echo "usage: $0 <file.AppImage>"; exit 1; }
# Absolutised here, because the extraction below runs from a temp directory and
# a RELATIVE path re-resolves against that cwd instead of this one. The `-f`
# test above and the `chmod +x` below both run from the original cwd and pass,
# so the failure landed three lines later as "cannot extract" -- a message
# pointing at appimagetool rather than at this line. Every invocation in this
# file's own usage line is relative, and so is the CI step, so that was every
# run: `./testing/verify-appimage.sh dist/x.AppImage` failed 100% of the time.
img="$(cd "$(dirname "$img")" && pwd)/$(basename "$img")"
pass=0; fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
bad() { echo "  FAIL  $*"; fail=$((fail+1)); }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
chmod +x "$img"
# --appimage-extract needs no FUSE, so this works in a container. Its stderr is
# KEPT (`2>&1 >/dev/null` sends stderr to the substitution and stdout to the
# bin): discarding it is what turned the relative-path bug above into an
# undiagnosable "cannot extract" with nothing to go on.
if ! err="$(cd "$tmp" && "$img" --appimage-extract 2>&1 >/dev/null)"; then
  echo "cannot extract $img"
  [ -n "$err" ] && echo "$err"
  exit 1
fi
root="$tmp/squashfs-root"

# An extraction that produced nothing would make every path assertion below
# vacuous: they would all report a missing file, and none of them would be
# reading the AppImage.
[ -n "$(ls -A "$root" 2>/dev/null)" ] || { echo "the AppImage extracted to nothing"; exit 1; }

[ -x "$root/AppRun" ] && ok "AppRun is present and executable" || bad "no executable AppRun"
[ -x "$root/usr/bin/liostunnel_app" ] && ok "the app executable is present" \
                                      || bad "no executable at usr/bin/liostunnel_app"
# One path does not certify a payload. A Flutter Linux bundle is the executable
# PLUS the engine it links at runtime PLUS the assets it loads at startup, and
# the ways to lose the last two while keeping the first are ordinary: an
# interrupted build, a stale tree, a `cp -R` that hit ENOSPC part-way -- which
# is not fatal per file, so it copies what it can and returns. Asserting only
# usr/bin/liostunnel_app passed every one of those, and the AppImage then died
# at launch with a loader error no assertion here had looked for. This is the
# same hole as the deleted Info.plist in verify-pkg.sh: an assertion whose
# subject is "the app" and whose object is a single path.
[ -s "$root/usr/bin/lib/libflutter_linux_gtk.so" ] \
  && ok "the Flutter engine library is present and non-empty" \
  || bad "missing or empty usr/bin/lib/libflutter_linux_gtk.so — the app would not load"
# Non-empty, not merely present: a `cp -R` interrupted between mkdir and the
# contents leaves the directory behind, and `-d` alone calls that a payload.
[ -n "$(ls -A "$root/usr/bin/data/flutter_assets" 2>/dev/null)" ] \
  && ok "the Flutter assets are present" \
  || bad "missing or empty usr/bin/data/flutter_assets — the app would not start"

# Presence is not correctness for either of these. `Exec=liostunnel` builds,
# scores a clean sweep, and integrates into the desktop menu as an entry that
# launches nothing; the name has to be the executable that is actually in
# there. Same for Icon=, which the AppImage spec resolves against the icon
# file's basename at the AppDir root.
if [ ! -f "$root/liostunnel.desktop" ]; then
  bad "no .desktop"
elif ! grep -qE '^Exec=liostunnel_app( |$)' "$root/liostunnel.desktop"; then
  bad "the desktop entry does not exec liostunnel_app: $(grep -E '^Exec=' "$root/liostunnel.desktop" || echo '<no Exec= line>')"
elif ! grep -qE '^Icon=liostunnel( |$)' "$root/liostunnel.desktop"; then
  bad "the desktop entry's Icon= does not name liostunnel.png: $(grep -E '^Icon=' "$root/liostunnel.desktop" || echo '<no Icon= line>')"
else
  ok "the desktop entry execs liostunnel_app and names the bundled icon"
fi
[ -s "$root/liostunnel.png" ] && ok "the icon is present and non-empty" || bad "no icon, or a zero-byte one"

inner="$root/usr/bin/helper"
for f in liostunnel-helper install-helper.sh uninstall-helper.sh; do
  [ -x "$inner/$f" ] && ok "$f is inside the AppImage and executable" \
                     || bad "missing or not executable: $f"
done
# Present is not usable. `-f` passes on a zero-byte file and on one whose
# @UID@ placeholder has already been substituted or deleted -- and the
# placeholder is the only thing that makes this file a template.
# install-helper.sh does `sed "s/@UID@/$uid/" … > "$unit"`: with nothing left
# to substitute, the unit installs with whatever uid was baked in (someone
# else's) or with the literal string (which the helper's u32 parse rejects on
# startup). Either way the failure surfaces as a daemon that never serves
# anyone and that systemd's Restart=on-failure keeps resurrecting, which is
# nobody's idea of a diagnostic.
if [ ! -f "$inner/liostunnel-helper.service" ]; then
  bad "missing liostunnel-helper.service"
elif ! grep -q '@UID@' "$inner/liostunnel-helper.service"; then
  bad "liostunnel-helper.service has no @UID@ for install-helper.sh to substitute"
else
  ok "the systemd unit is present, with its @UID@ placeholder intact"
fi
# Artifact-wide, not one directory. A plist at the AppDir root or under
# usr/share ships exactly as far as one in usr/bin/helper, and a check scoped
# to that directory does not see it. Searching $root also retires the "does
# $inner exist" guard this needed before: `find` over the whole tree cannot go
# vacuous when a subdirectory is missing, the way `[ ! -f "$inner/x" ]` does.
# verify-pkg.sh's mirror of this check was equally narrow and is now equally
# wide -- the mirror argument cuts both ways.
strays="$(find "$root" -name '*.plist' 2>/dev/null | tr '\n' ' ')"
if [ -z "$strays" ]; then
  ok "no launchd plist anywhere in the AppImage"
else
  bad "a launchd plist is in a Linux AppImage: $strays"
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

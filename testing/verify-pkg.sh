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

# An extraction that produced nothing would make every path assertion below
# vacuous: they would all report a missing file, and none of them would be
# reading the package. On macOS the payload is a gzip-compressed cpio archive
# and bsdtar reads it directly; the cpio branch is for a tar that cannot.
[ -n "$(ls -A "$tmp/p")" ] || { echo "the payload extracted to nothing"; exit 1; }

app="$tmp/p/Applications/liostunnel_app.app"
helper="$app/Contents/Resources/helper"

# Located, not assumed. A productbuild wrapper puts the component's
# PackageInfo one level down inside <component>.pkg/, and a hardcoded
# "$tmp/x/PackageInfo" would then fail a package that is perfectly correct for
# being wrapped. Everything else in this file already uses `find`.
pkginfo="$(find "$tmp/x" -name PackageInfo | head -1)"
[ -n "$pkginfo" ] || { echo "no PackageInfo in the package"; exit 1; }

# Where the payload lands is TWO facts and only one of them is in the payload.
# The cpio holds `Applications/liostunnel_app.app` -- a RELATIVE path, which
# says nothing about the root it is unpacked under. PackageInfo's
# install-location supplies that root. Built with `--install-location
# /tmp/wrong` the payload is byte-identical and the app installs to
# /tmp/wrong/Applications/liostunnel_app.app; the postinstall's fixed path
# then does not exist, `exec` fails, and the install dies AFTER the app has
# landed in the wrong place -- the same failure relocation causes, approached
# from the other end. Reading the relative path alone passed that package
# 13 out of 13.
[ -d "$app" ] && ok "the payload carries Applications/liostunnel_app.app" \
              || bad "no Applications/liostunnel_app.app in the payload"
loc="$(sed -n 's/.*install-location="\([^"]*\)".*/\1/p' "$pkginfo" | head -1)"
# pkgbuild omits the attribute entirely when --install-location is not passed,
# and an absent one means "/" -- so absent is correct, and anything else is not.
if [ -z "$loc" ] || [ "$loc" = "/" ]; then
  ok "the package installs relative to / -- the app lands in /Applications"
else
  bad "install-location is \"$loc\"; the app would land in $loc/Applications"
fi
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
# The directory has to exist before its absence means anything: `[ ! -f ]`
# against a path under a directory that is not there is trivially true, so a
# payload with no Contents/Resources/helper at all passed this line while
# claiming to have looked inside it.
if [ ! -d "$helper" ]; then
  bad "no helper directory, so nothing was checked for a systemd unit"
elif [ ! -f "$helper/liostunnel-helper.service" ]; then
  ok "the systemd unit is absent"
else
  bad "a systemd unit is in a macOS package"
fi

# A binary that runs on THIS platform -- not a placeholder, not the wrong arch.
v="$("$helper/liostunnel-helper" --version 2>&1)"
if [ $? -eq 0 ] && [ "${v#liostunnel-helper }" != "$v" ]; then
  ok "the bundled helper runs: $v"
else
  bad "the bundled helper did not run: $v"
fi

# Relocation. `pkgbuild --root` marks an app bundle relocatable by default,
# and Installer.app then redirects the payload onto any existing copy of that
# bundle id -- so the app lands somewhere else and the postinstall's fixed
# /Applications path does not exist. The top-level relocatable="false"
# attribute is a different thing and does not cover this.
# An empty `<relocate/>` is the correct state; `<relocate><bundle .../></relocate>`
# is the defect. Assert on the element's emptiness specifically -- `<bundle `
# alone appears throughout PackageInfo's own inventory (`<bundle-version>`,
# `<upgrade-bundle>`, `<strict-identifier>`), so grepping for it fails a
# perfectly good package. That mistake was made here first.
#
# But an empty `<relocate/>` only means something if there is a bundle to
# relocate. Delete Contents/Info.plist from the payload and pkgbuild registers
# no bundle components at all: `<relocate/>` is empty for want of anything to
# list, and the suite scored 13 of 13 on an app that cannot launch. So pair
# them -- the app must BE a registered bundle, and that bundle must not be
# relocatable. Anchored on the app's own path, which appears once, and not on
# the nested framework bundles that share its prefix.
if grep -q '<bundle path="\./Applications/liostunnel_app\.app"' "$pkginfo"; then
  ok "the app is a registered bundle component"
else
  bad "no bundle component for ./Applications/liostunnel_app.app -- is Contents/Info.plist missing?"
fi
if grep -q '<relocate/>' "$pkginfo"; then
  ok "the payload is not relocatable"
else
  bad "the payload is relocatable; it would install over a stray copy elsewhere"
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

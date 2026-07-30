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

[ -d "$app" ] && ok "the payload installs the app to /Applications" \
              || bad "no Applications/liostunnel_app.app in the payload"
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
[ ! -f "$helper/liostunnel-helper.service" ] \
  && ok "the systemd unit is absent" || bad "a systemd unit is in a macOS package"

# A binary that runs on THIS platform -- not a placeholder, not the wrong arch.
v="$("$helper/liostunnel-helper" --version 2>&1)"
if [ $? -eq 0 ] && [ "${v#liostunnel-helper }" != "$v" ]; then
  ok "the bundled helper runs: $v"
else
  bad "the bundled helper did not run: $v"
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

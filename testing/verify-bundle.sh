#!/usr/bin/env bash
#
# Proves the archive make-bundle.sh produced is a bundle that would work.
#
#     ./testing/verify-bundle.sh dist/liostunnel-macos-abc1234.tar.gz
#
# Runs as a normal user and installs nothing: the privileged commands are
# stubbed onto PATH and the unit-file write is redirected, so this can be run
# on a machine that already has a real helper installed without touching it.
#
set -uo pipefail
archive="${1:-}"
[ -f "$archive" ] || { echo "usage: $0 <archive.tar.gz>"; exit 1; }
pass=0; fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
bad() { echo "  FAIL  $*"; fail=$((fail+1)); }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
tar -C "$tmp" -xzf "$archive" || { echo "cannot unpack"; exit 1; }
root="$(find "$tmp" -maxdepth 1 -mindepth 1 -type d | head -1)"

case "$(uname -s)" in
  Darwin)
    app="$(find "$root" -maxdepth 1 -name '*.app' -type d | head -1)"
    appexe="$(find "$app" -maxdepth 3 -path '*/Contents/MacOS/*' -type f 2>/dev/null | head -1)"
    # Derived from the app bundle, NOT by locating install-helper.sh. Deriving
    # it from the file being checked makes "install-helper.sh is present" read
    # "the directory that contains install-helper.sh contains install-helper.sh"
    # -- true no matter what make-bundle.sh did. It also mislabels the failure:
    # with the script missing, `dirname ""` is "." and every other assertion
    # then reports a missing file that is actually there.
    inner="$app/Contents/Resources/helper"
    want_unit=liostunnel-helper.plist; other_unit=liostunnel-helper.service
    ;;
  *)
    appexe="$root/liostunnel/liostunnel"
    inner="$root/liostunnel/helper"
    want_unit=liostunnel-helper.service; other_unit=liostunnel-helper.plist
    ;;
esac

[ -n "$appexe" ] && [ -x "$appexe" ] && ok "the app executable is present and executable" \
                 || bad "no executable app at ${appexe:-$root}"
[ -f "$inner/$want_unit" ] && ok "this platform's unit file is present" \
                           || bad "missing $want_unit"
[ ! -f "$inner/$other_unit" ] && ok "the other platform's unit file is absent" \
                              || bad "$other_unit should not be in a $(uname -s) archive"
for f in liostunnel-helper install-helper.sh uninstall-helper.sh; do
  [ -x "$inner/$f" ] && ok "$f is present and executable" || bad "missing or not executable: $f"
done
[ -f "$root/README.txt" ] && ok "README.txt is present" || bad "missing README.txt"

# A binary that runs on this platform, not a placeholder or one built for the
# wrong arch. clap already provides --version.
v="$("$inner/liostunnel-helper" --version 2>&1)"
if [ $? -eq 0 ] && [ "${v#liostunnel-helper }" != "$v" ]; then
  ok "the bundled helper runs: $v"
else
  bad "the bundled helper did not run: $v"
fi

# The install script must reach the install step from inside the bundle,
# without root and without installing anything.
stub="$(mktemp -d)"
for cmd in install launchctl systemctl chown chmod; do
  printf '#!/usr/bin/env bash\nexit 0\n' > "$stub/$cmd"; chmod 755 "$stub/$cmd"
done
# Stubbing PATH is not enough on its own: install-helper.sh writes the unit
# file with a shell redirection, which no stub can intercept. Left alone that
# write targets /Library/LaunchDaemons (or /etc/systemd/system) -- it would
# fail here for lack of root, reporting a broken bundle, and would clobber a
# real installed helper on any machine where this was run as root.
# LIOS_UNIT_PATH exists for exactly this and redirects the whole branch, name
# included.
unitdir="$(mktemp -d)"
if (cd "$inner" && PATH="$stub:$PATH" LIOS_UNIT_PATH="$unitdir/$want_unit" \
      bash ./install-helper.sh --uid 501 >/dev/null 2>&1); then
  ok "install-helper.sh finds the bundled binary and reaches the install step"
else
  bad "install-helper.sh failed from inside the bundle"
fi
rm -rf "$stub" "$unitdir"

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]

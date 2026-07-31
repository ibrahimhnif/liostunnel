#!/usr/bin/env bash
#
# Proves install-helper.sh authorizes the right uid and refuses the wrong
# ones, without root and without installing anything.
#
#     ./testing/verify-install-script.sh
#
# The privileged commands are stubbed on PATH. A stub that is never called
# leaves no marker, so "did it reach the install step" is observable.
#
# The marker is evidence about ARGV and nothing else. Whether the authorized
# uid actually landed in the root-owned unit file is a question only the unit
# file can answer, so every assertion about the uid reads the file itself --
# see unit_has() below, and the git history of this line.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
pass=0; fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
bad() { echo "  FAIL  $*"; fail=$((fail+1)); }

stub_dir="$(mktemp -d)"
out="$stub_dir/marker"
# The real destination (/Library/LaunchDaemons or /etc/systemd/system) is
# root-owned; writing there is what installing for real means. Redirect it
# into the sandbox so the uid substitution is observable without root.
export LIOS_UNIT_PATH="$stub_dir/unit-file"
trap 'rm -rf "$stub_dir"' EXIT
for cmd in install launchctl systemctl chown chmod sed; do
  cat > "$stub_dir/$cmd" <<STUB
#!/usr/bin/env bash
echo "$cmd \$*" >> "$out"
exit 0
STUB
  chmod 755 "$stub_dir/$cmd"
done
# `sed` is stubbed above but the script uses it to write the unit file; give
# it back its real behaviour so the uid substitution is observable.
cat > "$stub_dir/sed" <<STUB
#!/usr/bin/env bash
echo "sed \$*" >> "$out"
exec /usr/bin/sed "\$@"
STUB
chmod 755 "$stub_dir/sed"

# `id` is stubbed so the script's root guard passes without this test running
# as root. This does NOT weaken the uid-0 assertions: that refusal reads the
# uid being AUTHORIZED (from --uid/SUDO_UID/PKEXEC_UID), never `id -u`. The
# two are different numbers and the script is written so they stay different.
cat > "$stub_dir/id" <<'STUB'
#!/usr/bin/env bash
case "${1:-}" in
  -u)  echo 0 ;;                       # the script's root check
  -un) echo "test-user-${2:-}" ;;      # the friendly name for the report
  *)   exec /usr/bin/id "$@" ;;
esac
STUB
chmod 755 "$stub_dir/id"

# `uname` is stubbed so BOTH platform branches are reachable from either host.
# Without it the Linux unit write, its default path and its activation are
# unexecuted code on a macOS developer machine, and the Darwin ones are
# unexecuted in CI. FAKE_UNAME is read only by this stub -- the script under
# test knows nothing about it.
real_uname="$(command -v uname)"
cat > "$stub_dir/uname" <<STUB
#!/usr/bin/env bash
if [ "\${1:-}" = "-s" ] && [ -n "\${FAKE_UNAME:-}" ]; then
  echo "\$FAKE_UNAME"
else
  exec "$real_uname" "\$@"
fi
STUB
chmod 755 "$stub_dir/uname"

# What the uid looks like once it has actually landed in the unit file. The
# stub marker records `sed s/@UID@/501/ ...`, which proves only that the uid
# reached sed's ARGV -- it says nothing about the file that was written, and a
# script whose substitution pattern no longer matches the template leaves that
# marker unchanged. So the assertions below read the file, and they read it in
# the format this platform's template actually uses.
case "$(uname -s)" in
  Darwin) unit_str() { printf '<string>%s</string>' "$1"; } ;;
  Linux)  unit_str() { printf -- '--uid %s' "$1"; } ;;
  *) echo "this suite covers Darwin and Linux; got $(uname -s)" >&2; exit 1 ;;
esac
unit_has() { grep -qF -- "$(unit_str "$1")" "$LIOS_UNIT_PATH" 2>/dev/null; }

# Every run starts from no marker and NO unit file: a unit left behind by the
# previous case would satisfy the next case's grep on its own.
reset() { : > "$out"; rm -f "$LIOS_UNIT_PATH"; }

# refused() <rc> <output> <substring> <label>
#
# A refusal has to be checked by its MESSAGE, not its exit code. `set -e` on a
# failed `shift`, a `set -u` abort on a typo'd variable, a missing stub and a
# deliberate `exit 1` are indistinguishable by status, so an exit-code-only
# assertion passes against the very defects it is there to catch -- and the
# caller (osascript, pkexec) surfaces only what the script said.
refused() {
  local rc="$1" o="$2" msg="$3" label="$4"
  if [ "$rc" -eq 1 ] && [ ! -s "$out" ] && [ ! -e "$LIOS_UNIT_PATH" ] \
     && case "$o" in *"$msg"*) true ;; *) false ;; esac; then
    ok "$label"
  else
    bad "$label (exit $rc, wanted 1 and '$msg'; said: $o)"
    [ -s "$out" ] && printf '        ran: %s\n' "$(tr '\n' ';' < "$out")"
    [ -e "$LIOS_UNIT_PATH" ] && printf '        and WROTE a unit file\n'
  fi
}

# A fake helper binary beside a copy of the script, i.e. the bundle layout.
bundle="$stub_dir/bundle"; mkdir -p "$bundle"
cp "$repo/packaging/install-helper.sh" "$bundle/"
cp "$repo/packaging/liostunnel-helper.plist" "$bundle/" 2>/dev/null || true
cp "$repo/packaging/liostunnel-helper.service" "$bundle/" 2>/dev/null || true
printf '#!/bin/sh\necho fake\n' > "$bundle/liostunnel-helper"
chmod 755 "$bundle/liostunnel-helper"

# And a DIFFERENT binary where a checkout would keep one, so the lookup order
# is genuinely ambiguous. Without this the two branches cannot be told apart
# and the "beside the script wins" assertion proves nothing -- which is the
# gap this task's own report flagged.
checkout="$stub_dir/checkout"
mkdir -p "$checkout/packaging" "$checkout/target/release"
cp "$repo/packaging/install-helper.sh" "$checkout/packaging/"
cp "$repo/packaging/liostunnel-helper.plist" "$checkout/packaging/" 2>/dev/null || true
cp "$repo/packaging/liostunnel-helper.service" "$checkout/packaging/" 2>/dev/null || true
printf '#!/bin/sh\necho stale\n' > "$checkout/target/release/liostunnel-helper"
chmod 755 "$checkout/target/release/liostunnel-helper"

echo "=== the uid must come from a human, never the elevated process ==="

# PKG-3. Every way a uid gets in reaches the unit file -- the root-owned file
# that IS the authorization boundary. Nothing short of reading it counts: with
# these greps pointed at the stub marker instead, changing the substitution to
# s/@XUID@/ so that no uid ever reached the plist left all of them green.
reset
(cd "$bundle" && PATH="$stub_dir:$PATH" LIOS_UID=501 bash ./install-helper.sh >/dev/null 2>&1)
unit_has 501 && ok "LIOS_UID reaches the unit file" || bad "LIOS_UID did not reach the unit file"

reset
(cd "$bundle" && PATH="$stub_dir:$PATH" SUDO_UID=502 bash ./install-helper.sh >/dev/null 2>&1)
unit_has 502 && ok "SUDO_UID reaches the unit file" || bad "SUDO_UID did not reach the unit file"

reset
(cd "$bundle" && PATH="$stub_dir:$PATH" PKEXEC_UID=503 bash ./install-helper.sh >/dev/null 2>&1)
unit_has 503 && ok "PKEXEC_UID reaches the unit file" || bad "PKEXEC_UID did not reach the unit file"

reset
(cd "$bundle" && PATH="$stub_dir:$PATH" bash ./install-helper.sh --uid 504 >/dev/null 2>&1)
unit_has 504 && ok "--uid reaches the unit file" || bad "--uid did not reach the unit file"

reset
(cd "$bundle" && PATH="$stub_dir:$PATH" bash ./install-helper.sh --uid=505 >/dev/null 2>&1)
unit_has 505 && ok "--uid=N reaches the unit file" || bad "--uid=N did not reach the unit file"

echo
echo "=== and the two refusals must survive all of it ==="

# THE assertion of this file. A helper that authorizes uid 0 accepts a root
# client, which is the entire boundary gone. Every one of the four ways a uid
# gets in has to be refused, and refused OUT LOUD: replacing the guard with a
# bare `exit 1` left the exit-code-only versions of these green, and under
# osascript or pkexec a bare failure is all the app ever sees.
uid0="refusing to authorize uid 0"
reset
o="$(cd "$bundle" && PATH="$stub_dir:$PATH" bash ./install-helper.sh --uid 0 2>&1)"; rc=$?
refused "$rc" "$o" "$uid0" "uid 0 is refused (--uid)"
reset
o="$(cd "$bundle" && PATH="$stub_dir:$PATH" LIOS_UID=0 bash ./install-helper.sh 2>&1)"; rc=$?
refused "$rc" "$o" "$uid0" "uid 0 is refused (LIOS_UID)"
reset
o="$(cd "$bundle" && PATH="$stub_dir:$PATH" SUDO_UID=0 bash ./install-helper.sh 2>&1)"; rc=$?
refused "$rc" "$o" "$uid0" "uid 0 is refused (SUDO_UID)"
reset
o="$(cd "$bundle" && PATH="$stub_dir:$PATH" PKEXEC_UID=0 bash ./install-helper.sh 2>&1)"; rc=$?
refused "$rc" "$o" "$uid0" "uid 0 is refused (PKEXEC_UID)"

# No source at all: must die, NOT fall back to the current user.
: > "$out"
o="$(cd "$bundle" && env -u SUDO_UID -u PKEXEC_UID -u LIOS_UID \
      PATH="$stub_dir:$PATH" bash ./install-helper.sh 2>&1)"
rc=$?
# The MESSAGE, not just the exit code. A fallback to `id -u` is also refused
# -- by the uid-0 guard, once the elevated process's own uid is 0 -- so an
# exit-code-only assertion passes against the very defect it names. It has to
# say it could not TELL, which only the no-fallback version says.
if [ $rc -ne 0 ] && [ ! -s "$out" ] && case "$o" in *"cannot tell which account"*) true ;; *) false ;; esac; then
  ok "no uid available is refused for the right reason, and nothing was installed"
else
  bad "ran with no uid available, or refused for the wrong reason: $o"
fi

# The root guard. Nothing else here covers it: `id -u` is stubbed to 0 for
# every case above, so the script always looks like it is running as root.
# Without this, deleting the guard leaves the whole suite green, and a normal
# user running the script gets part-way through and fails on a permission
# error from `install` -- which reads as a broken installer rather than a
# missing `sudo`.
o="$(cd "$bundle" && PATH="$(dirname "$(command -v env)"):/usr/bin:/bin" \
      LIOS_UID=501 bash ./install-helper.sh 2>&1)"
if [ $? -ne 0 ] && case "$o" in *"must run as root"*) true ;; *) false ;; esac; then
  ok "a non-root run is refused, saying so"
else
  bad "a non-root run was not refused with 'must run as root': $o"
fi

echo
echo "=== the argument parser refuses what it cannot honour, and says so ==="

# The parser had no coverage whatsoever. Three independent mutations each left
# the suite green: deleting the digit check, deleting the `--uid=N` branch, and
# replacing the unknown-argument `die` with a bare `shift`. In an installer
# that runs under osascript or pkexec, an argument that is silently dropped is
# an authorization that is silently wrong, and the message is the only channel
# back to the app.
parse() {  # parse() <substring> <label> [args...]
  local msg="$1" label="$2"; shift 2
  reset
  local o rc
  o="$(cd "$bundle" && env -u LIOS_UID -u SUDO_UID -u PKEXEC_UID \
        PATH="$stub_dir:$PATH" bash ./install-helper.sh "$@" 2>&1)"
  rc=$?
  refused "$rc" "$o" "$msg" "$label"
}

parse "--uid needs a value"       "--uid with no value is refused"   --uid
parse "not a uid: alice"          "--uid alice is refused"           --uid alice
parse "not a uid: -1"             "--uid -1 is refused"              --uid -1
parse "unknown argument: --bogus" "an unknown argument is refused"   --bogus

# Out of range is not a hypothetical. The helper parses --uid as a u32 and
# exits when it cannot; launchd's KeepAlive and systemd's Restart=on-failure
# then respawn it forever. The refusal belongs here, while a human is still
# watching the installer.
parse "uid out of range: 4294967296"           "a uid above the u32 range is refused"     --uid 4294967296
parse "uid out of range: 99999999999999999999" "a uid too long to even compare is refused" --uid 99999999999999999999
parse "not a uid: 010"            "a leading-zero uid is refused"     --uid 010

echo
echo "=== with no redirect, the write targets the real root-owned unit path ==="

# LIOS_UNIT_PATH exists only so this suite can observe the write. That it is
# unset -- and so the destination is the real, root-owned one -- on every
# actual install was asserted by a comment and by nothing else: repointing
# both defaults at /tmp/pwned.* left the entire suite green.
#
# Pinning it needs neither root nor a write. The real destinations are
# root-owned on their own platform and absent on the other, so bash's redirect
# fails either way and names the path it could not open.
if [ "$(/usr/bin/id -u)" -eq 0 ]; then
  bad "this suite must not be run as root: an unredirected run would write the real unit file"
else
  for plat in Darwin Linux; do
    case "$plat" in
      Darwin) want="/Library/LaunchDaemons/com.liostunnel.helper.plist" ;;
      Linux)  want="/etc/systemd/system/liostunnel-helper.service" ;;
    esac
    reset
    o="$(cd "$bundle" && env -u LIOS_UNIT_PATH PATH="$stub_dir:$PATH" \
          FAKE_UNAME="$plat" LIOS_UID=501 bash ./install-helper.sh 2>&1)"
    rc=$?
    if [ "$rc" -ne 0 ] && case "$o" in *"$want"*) true ;; *) false ;; esac; then
      ok "$plat: an unredirected install writes $want"
    else
      bad "$plat: an unredirected install did not target $want (exit $rc): $o"
    fi
  done
fi

echo
echo "=== the Linux branch enables the unit it just wrote ==="

# LIOS_UNIT_PATH redirected the write and nothing else: `systemctl enable`
# still spelled liostunnel-helper.service out literally, so a redirected Linux
# install wrote one file and enabled another. Deriving the name from the path
# is what makes the redirect coherent, and it changes nothing about a real
# install -- the basename of the default path IS liostunnel-helper.service,
# which the assertion above pins independently.
reset
lin_unit="$stub_dir/probe-unit.service"; rm -f "$lin_unit"
(cd "$bundle" && PATH="$stub_dir:$PATH" FAKE_UNAME=Linux LIOS_UNIT_PATH="$lin_unit" \
   LIOS_UID=506 bash ./install-helper.sh >/dev/null 2>&1)
if grep -qF -- "--uid 506" "$lin_unit" 2>/dev/null \
   && grep -qF "systemctl enable --now probe-unit.service" "$out"; then
  ok "Linux: the unit written and the unit enabled are the same one"
else
  bad "Linux: wrote probe-unit.service but enabled [$(grep 'systemctl enable' "$out" || echo nothing)]"
fi

# The other half of the same pin: the canonical name comes out of the
# canonical basename, so a real install still enables liostunnel-helper.service.
reset
lin_unit="$stub_dir/liostunnel-helper.service"; rm -f "$lin_unit"
(cd "$bundle" && PATH="$stub_dir:$PATH" FAKE_UNAME=Linux LIOS_UNIT_PATH="$lin_unit" \
   LIOS_UID=507 bash ./install-helper.sh >/dev/null 2>&1)
grep -qF "systemctl enable --now liostunnel-helper.service" "$out" \
  && ok "Linux: a unit at .../liostunnel-helper.service is enabled by that name" \
  || bad "Linux: did not enable liostunnel-helper.service"

echo
echo "=== the binary is found beside the script, and in a checkout ==="

# A bundle that ALSO sits inside a checkout: both candidates exist, so this
# tells the two branches apart rather than merely finding something.
both="$checkout/packaging"
cp "$bundle/liostunnel-helper" "$both/liostunnel-helper"
chmod 755 "$both/liostunnel-helper"
: > "$out"
(cd "$both" && PATH="$stub_dir:$PATH" LIOS_UNIT_PATH="$stub_dir/unit" LIOS_UID=501 \
  bash ./install-helper.sh >/dev/null 2>&1)
if grep -q "$both/liostunnel-helper" "$out" && ! grep -q "target/release" "$out"; then
  ok "beside the script wins over target/release"
else
  bad "used target/release when a binary sat beside the script"
fi

# And a checkout with no bundled binary still finds target/release.
rm -f "$both/liostunnel-helper"
: > "$out"
(cd "$both" && PATH="$stub_dir:$PATH" LIOS_UNIT_PATH="$stub_dir/unit" LIOS_UID=501 \
  bash ./install-helper.sh >/dev/null 2>&1)
grep -q "target/release/liostunnel-helper" "$out" \
  && ok "a checkout still finds target/release" \
  || bad "did not fall back to target/release"

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]

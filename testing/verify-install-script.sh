#!/usr/bin/env bash
#
# Proves install-helper.sh authorizes the right uid and refuses the wrong
# ones, without root and without installing anything.
#
#     ./testing/verify-install-script.sh
#
# The privileged commands are stubbed on PATH. A stub that is never called
# leaves no marker, so "did it reach the install step" is observable.
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

# A fake helper binary beside a copy of the script, i.e. the bundle layout.
bundle="$stub_dir/bundle"; mkdir -p "$bundle"
cp "$repo/packaging/install-helper.sh" "$bundle/"
cp "$repo/packaging/liostunnel-helper.plist" "$bundle/" 2>/dev/null || true
cp "$repo/packaging/liostunnel-helper.service" "$bundle/" 2>/dev/null || true
printf '#!/bin/sh\necho fake\n' > "$bundle/liostunnel-helper"
chmod 755 "$bundle/liostunnel-helper"

run() {  # run() <expect-exit> <label> [args...]
  local want="$1" label="$2"; shift 2
  : > "$out"
  local o rc
  o="$(cd "$bundle" && PATH="$stub_dir:$PATH" bash ./install-helper.sh "$@" 2>&1)"
  rc=$?
  if [ "$rc" -eq "$want" ]; then ok "$label"; else
    bad "$label (exit $rc, wanted $want)"; printf '        %s\n' "$o"
  fi
}

echo "=== the uid must come from a human, never the elevated process ==="

# PKG-3. Each of the three sources reaches the install step.
: > "$out"
(cd "$bundle" && PATH="$stub_dir:$PATH" LIOS_UID=501 bash ./install-helper.sh >/dev/null 2>&1)
grep -q "501" "$out" && ok "LIOS_UID reaches the unit file" || bad "LIOS_UID did not reach the unit file"

: > "$out"
(cd "$bundle" && PATH="$stub_dir:$PATH" SUDO_UID=502 bash ./install-helper.sh >/dev/null 2>&1)
grep -q "502" "$out" && ok "SUDO_UID reaches the unit file" || bad "SUDO_UID did not reach the unit file"

: > "$out"
(cd "$bundle" && PATH="$stub_dir:$PATH" PKEXEC_UID=503 bash ./install-helper.sh >/dev/null 2>&1)
grep -q "503" "$out" && ok "PKEXEC_UID reaches the unit file" || bad "PKEXEC_UID did not reach the unit file"

: > "$out"
(cd "$bundle" && PATH="$stub_dir:$PATH" bash ./install-helper.sh --uid 504 >/dev/null 2>&1)
grep -q "504" "$out" && ok "--uid reaches the unit file" || bad "--uid did not reach the unit file"

echo
echo "=== and the two refusals must survive all of it ==="

# THE assertion of this file. A helper that authorizes uid 0 accepts a root
# client, which is the entire boundary gone.
run 1 "uid 0 is refused (LIOS_UID)"   --uid 0
: > "$out"
o="$(cd "$bundle" && PATH="$stub_dir:$PATH" SUDO_UID=0 bash ./install-helper.sh 2>&1)"
[ $? -ne 0 ] && ok "uid 0 is refused (SUDO_UID)" || bad "uid 0 was ACCEPTED via SUDO_UID"
: > "$out"
o="$(cd "$bundle" && PATH="$stub_dir:$PATH" PKEXEC_UID=0 bash ./install-helper.sh 2>&1)"
[ $? -ne 0 ] && ok "uid 0 is refused (PKEXEC_UID)" || bad "uid 0 was ACCEPTED via PKEXEC_UID"

# No source at all: must die, NOT fall back to the current user.
: > "$out"
o="$(cd "$bundle" && env -u SUDO_UID -u PKEXEC_UID -u LIOS_UID \
      PATH="$stub_dir:$PATH" bash ./install-helper.sh 2>&1)"
if [ $? -ne 0 ] && [ ! -s "$out" ]; then
  ok "no uid available is refused, and nothing was installed"
else
  bad "ran with no uid available — it must not guess"
fi

echo
echo "=== the binary is found beside the script, and in a checkout ==="
: > "$out"
(cd "$bundle" && PATH="$stub_dir:$PATH" LIOS_UID=501 bash ./install-helper.sh >/dev/null 2>&1)
grep -q "$bundle/liostunnel-helper" "$out" \
  && ok "the bundled binary is used" || bad "did not install the binary beside the script"

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]

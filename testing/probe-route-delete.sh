#!/usr/bin/env bash
#
# Determines the correct macOS `route delete` form for an interface route.
#
#     sudo ./testing/probe-route-delete.sh
#
# Uses TEST-NET-2 (198.51.100.0/24, RFC 5737 — reserved for documentation and
# never routable) via lo0, so nothing real is touched. Every form is tried
# against a freshly-added route and the route is removed afterwards either
# way.
#
set -uo pipefail
NET=198.51.100.0/24
IF=lo0

[ "$(id -u)" -eq 0 ] || { echo "must run as root (sudo)"; exit 1; }

cleanup() { route -n delete -net "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT

try() {
  local label="$1"; shift
  cleanup
  route -n add -net "$NET" -interface "$IF" >/dev/null 2>&1 \
    || { echo "  SKIP  $label (could not add the probe route)"; return; }
  local out rc
  out="$(route "$@" 2>&1)"; rc=$?
  if [ $rc -eq 0 ] && ! netstat -rn -f inet | grep -q '^198\.51\.100'; then
    echo "  WORKS $label"
    printf '        %s\n' "$out"
  else
    echo "  FAILS $label"
    printf '        %s\n' "$out"
  fi
}

echo "probing macOS route delete forms against $NET via $IF"
echo

# What the code does today, and what the helper log showed failing.
try "route -n delete -net CIDR -interface IF   (current code)" \
    -n delete -net "$NET" -interface "$IF"

# Destination only. Unambiguous, but would also remove someone else's route to
# the same destination — which is why it is not automatically the answer.
try "route -n delete -net CIDR                 (destination only)" \
    -n delete -net "$NET"

# Interface-scoped delete.
try "route -n delete -net CIDR -ifscope IF     (ifscope)" \
    -n delete -net "$NET" -ifscope "$IF"

# Explicit address family, in case the parser needs it before -interface.
try "route -n delete -inet -net CIDR -interface IF" \
    -n delete -inet -net "$NET" -interface "$IF"

echo
echo "done; probe route removed"

#!/usr/bin/env bash
#
# Removes the LiosTunnel privileged helper.
#
# Stopping the daemon reverts any routes it installed and clears its state
# file, so this leaves the machine's networking as it found it. The lockfile
# is removed here rather than by the helper, which deliberately never unlinks
# it while running.
#
set -euo pipefail

LIBEXEC=/usr/local/libexec
BINARY=liostunnel-helper
SOCKET=/var/run/liostunnel.sock
PLIST_LABEL=com.liostunnel.helper

die() { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"

case "$(uname -s)" in
  Darwin)
    unit=/Library/LaunchDaemons/$PLIST_LABEL.plist
    launchctl bootout system "$unit" 2>/dev/null || true
    rm -f "$unit"
    ;;
  Linux)
    systemctl disable --now liostunnel-helper.service 2>/dev/null || true
    rm -f /etc/systemd/system/liostunnel-helper.service
    systemctl daemon-reload 2>/dev/null || true
    ;;
  *)
    die "unsupported platform $(uname -s)"
    ;;
esac

rm -f "$LIBEXEC/$BINARY"
# The daemon unlinks its own socket on a clean stop; these cover a kill -9.
rm -f "$SOCKET" "$SOCKET.lock" "$SOCKET.routes.json"

echo "helper removed. $SOCKET is gone."
echo "note: $SOCKET.known_hosts is kept — it holds host keys you accepted."

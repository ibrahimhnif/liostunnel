#!/usr/bin/env bash
#
# Installs the LiosTunnel privileged helper as a system daemon.
#
# The authorized uid is baked into the unit file at install time, so it is
# root-owned configuration an unprivileged process cannot alter (spec §7.1).
# Run this with sudo as the user who will actually use the app:
#
#     sudo ./packaging/install-helper.sh
#
set -euo pipefail

LIBEXEC=/usr/local/libexec
BINARY=liostunnel-helper
SOCKET=/var/run/liostunnel.sock
PLIST_LABEL=com.liostunnel.helper
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"

die() { echo "error: $*" >&2; exit 1; }

# `--uid N` is how the app passes it: the app knows its own uid, and neither
# osascript nor pkexec preserves the one sudo would have set.
while [ $# -gt 0 ]; do
  case "$1" in
    --uid) LIOS_UID="${2:-}"; shift 2 ;;
    --uid=*) LIOS_UID="${1#--uid=}"; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

# Three ways in, one rule: the uid to authorize is the HUMAN's, never the
# elevated process's.
#   LIOS_UID    --uid, from the app
#   SUDO_UID    set by sudo
#   PKEXEC_UID  set by pkexec
# There is deliberately NO fallback to `id -u`. Under sudo, pkexec and
# osascript alike that answer is 0, and a helper that authorizes root accepts
# a root client -- which is the whole boundary this design exists to draw.
uid="${LIOS_UID:-${SUDO_UID:-${PKEXEC_UID:-}}}"
[ -n "$uid" ] || die "cannot tell which account to authorize; run with sudo, or pass --uid N"
case "$uid" in ''|*[!0-9]*) die "not a uid: $uid" ;; esac
[ "$uid" -ne 0 ] || die "refusing to authorize uid 0; the helper must serve an unprivileged user"
user="$(id -un "$uid" 2>/dev/null || echo "uid $uid")"

# Root last, deliberately, and this ordering is load-bearing.
#
# It used to come first, which made every uid assertion below unreachable in a
# test: the script died here before the uid logic ran, so deleting the uid-0
# refusal entirely left the suite green. Validating the arguments before
# demanding the privilege fixes that AND is the better order anyway -- a user
# who types `--uid 0` should be told that is the problem, not told to try again
# with sudo and only then be refused.
#
# The guard itself is not optional. Without it, running this as a normal user
# gets part-way through and fails on a permission error from `install`, which
# reads as a broken installer rather than a missing `sudo`.
[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"

# Beside this script in a bundle, under target/release in a checkout. One
# script serving both beats a second copy free to drift from the first --
# the same argument the profile format makes for having one parser.
#
# Beside-the-script wins: unpacking a bundle inside a checkout should use the
# bundle's binary, not whatever is stale in target/.
if [ -f "$here/$BINARY" ]; then
  src="$here/$BINARY"
elif [ -f "$repo/target/release/$BINARY" ]; then
  src="$repo/target/release/$BINARY"
else
  die "no helper binary beside this script or at $repo/target/release/$BINARY — in a checkout, run: cargo build --release -p liostunnel-helper"
fi

echo "installing $BINARY for $user (uid $uid)"

install -d -m 0755 "$LIBEXEC"
install -m 0755 "$src" "$LIBEXEC/$BINARY"

case "$(uname -s)" in
  Darwin)
    # LIOS_UNIT_PATH lets tests redirect this write off the real, root-owned
    # /Library/LaunchDaemons; it is unset (so this is the real path) for every
    # actual install.
    unit="${LIOS_UNIT_PATH:-/Library/LaunchDaemons/$PLIST_LABEL.plist}"
    sed "s/@UID@/$uid/" "$here/liostunnel-helper.plist" > "$unit"
    chown root:wheel "$unit"
    chmod 0644 "$unit"
    launchctl bootout system "$unit" 2>/dev/null || true
    launchctl bootstrap system "$unit"
    ;;
  Linux)
    unit="${LIOS_UNIT_PATH:-/etc/systemd/system/liostunnel-helper.service}"
    sed "s/@UID@/$uid/" "$here/liostunnel-helper.service" > "$unit"
    chown root:root "$unit"
    chmod 0644 "$unit"
    systemctl daemon-reload
    systemctl enable --now liostunnel-helper.service
    ;;
  *)
    die "unsupported platform $(uname -s); Windows is its own phase"
    ;;
esac

echo
echo "helper installed. socket: $SOCKET"
echo "it will accept connections only from uid $uid ($user)."
echo "uninstall with: sudo $here/uninstall-helper.sh"

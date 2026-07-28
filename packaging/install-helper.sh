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

[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"

# The uid to authorize is the invoking user's, not root's. Installing with the
# authorized uid set to 0 would mean the helper accepts a root client, which
# defeats the boundary it exists to enforce: the whole design assumes the
# caller is unprivileged and must have its secrets checked against its own
# ownership.
uid="${SUDO_UID:-}"
[ -n "$uid" ] || die "SUDO_UID is unset; run this with sudo from the account that will use the app, not as a root login"
[ "$uid" -ne 0 ] || die "refusing to authorize uid 0; the helper must serve an unprivileged user"
user="$(id -un "$uid" 2>/dev/null || echo "uid $uid")"

src="$repo/target/release/$BINARY"
[ -f "$src" ] || die "no release binary at $src — run: cargo build --release -p liostunnel-helper"

echo "installing $BINARY for $user (uid $uid)"

install -d -m 0755 "$LIBEXEC"
install -m 0755 "$src" "$LIBEXEC/$BINARY"

case "$(uname -s)" in
  Darwin)
    unit=/Library/LaunchDaemons/$PLIST_LABEL.plist
    sed "s/@UID@/$uid/" "$here/liostunnel-helper.plist" > "$unit"
    chown root:wheel "$unit"
    chmod 0644 "$unit"
    launchctl bootout system "$unit" 2>/dev/null || true
    launchctl bootstrap system "$unit"
    ;;
  Linux)
    unit=/etc/systemd/system/liostunnel-helper.service
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

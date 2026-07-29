#!/usr/bin/env bash
#
# Phase 1a exit-criteria verification against a real privileged helper.
#
# Run as root, from the account that will act as the client:
#
#     sudo ./testing/verify-phase1a.sh
#
# What this does NOT do, deliberately:
#   * It does not install a launchd/systemd daemon. The helper is run
#     directly on a temporary socket and killed at the end, so nothing
#     persists. The installer's own refusal paths are verified separately.
#   * It does not touch the default route. Route mode is `test` with a single
#     CIDR — the Docker fixture's network — so ordinary connectivity is
#     unaffected throughout.
#
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=testing/lib-verify.sh
. "$repo/testing/lib-verify.sh"

SOCK=/tmp/lios-verify/helper.sock
PROFILE=${LIOS_PROFILE:-/tmp/lios-verify/profile.json}
SSH_HOST=${LIOS_SSH_HOST:-127.0.0.1}
SSH_PORT=${LIOS_SSH_PORT:-22022}

# The fixture's own nginx, routed as a /32.
#
# The target must be one the host cannot reach except through the tunnel. A
# /32 beats a /24 or a default route by longest-prefix match, so the kernel
# has no other path for it. Routing the whole /24 does NOT work: the first
# attempt did that, tied with Docker's own bridge route, and the fetch
# succeeded around the tunnel entirely — a green result proving nothing.
#
# NEVER point this at a public DNS resolver. 1.1.1.1 was the default here
# once, and on a machine that uses 1.1.1.1 as its nameserver it routes every
# DNS query on the box into a tunnel whose own resolver is that same address.
# That produced 83 stalled flows from four fetches, nothing returning, and a
# criterion that passed anyway.
TARGET=${LIOS_TARGET:-$(docker inspect docker-target-1 \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)}
[ -n "$TARGET" ] || { echo "fixture not up — run: make -C testing/docker up"; exit 1; }
FIXTURE_CIDR=${LIOS_CIDR:-$TARGET/32}
HELPER=${LIOS_HELPER:-$repo/target/release/liostunnel-helper}
# Read from the source of truth. Hardcoding it meant a bump turned every check
# in this script into a version_mismatch, and the script would have reported
# that as the gate working.
WIRE_VERSION=$(sed -n 's/^pub const PROTOCOL_VERSION: u32 = \([0-9]*\);.*/\1/p' \
  "$repo/crates/liostunnel-ffi/src/dto/protocol.rs")
[ -n "$WIRE_VERSION" ] || { echo "cannot read PROTOCOL_VERSION"; exit 1; }

pass=0; fail=0
ok()   { echo "  PASS  $*"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail+1)); }
hdr()  { echo; echo "=== $* ==="; }

[ "$(id -u)" -eq 0 ] || { echo "must run as root (sudo)"; exit 1; }
CLIENT_UID="${SUDO_UID:-}"
[ -n "$CLIENT_UID" ] || { echo "SUDO_UID unset; run via sudo from your own account"; exit 1; }
[ -f "$HELPER" ] || { echo "no release helper; run: cargo build --release -p liostunnel-helper"; exit 1; }
[ -f "$PROFILE" ] || { echo "no profile at $PROFILE"; exit 1; }

# Fills the fixture details into an embedded python client.
# The protocol under test, read from the profile itself. The two escalation
# checks below build their own bait profiles, and a bait profile of the WRONG
# protocol proves the gate for a protocol nobody is testing -- which is what
# this script did for every Shadowsocks run before the substitutions below.
PROTO=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["protocol"])' "$PROFILE")
case "$PROTO" in
  shadowsocks)
    BAITFILE='{"type":"shadowsocks","method":"aes-256-gcm","password":{"source":"file","path":"/tmp/lios-verify/rootkey"}}'
    BAITENV='{"type":"shadowsocks","method":"aes-256-gcm","password":{"source":"env","var":"HOME"}}'
    ;;
  *)
    BAITFILE='{"type":"private_key","private_key":{"source":"file","path":"/tmp/lios-verify/rootkey"}}'
    BAITENV='{"type":"password","password":{"source":"env","var":"HOME"}}'
    ;;
esac

subst() {
  sed -e "s|__HOST__|$SSH_HOST|g" -e "s|__PORT__|$SSH_PORT|g" \
      -e "s|__CIDR__|$FIXTURE_CIDR|g" -e "s|__SSHUSER__|${LIOS_SSH_USER:-tunneluser}|g" \
      -e "s|__VER__|$WIRE_VERSION|g" -e "s|__PROTO__|$PROTO|g" \
      -e "s|__BAITFILE__|$BAITFILE|g" -e "s|__BAITENV__|$BAITENV|g"
}

echo "helper : $HELPER"
echo "client : uid $CLIENT_UID"
echo "target : $TARGET via $FIXTURE_CIDR"
echo "wire   : protocol_version $WIRE_VERSION, protocol $PROTO"

# ---------------------------------------------------------------- baseline
DEFAULT_BEFORE="$(default_route)"
IFACES_BEFORE="$(iface_list)"

rm -f "$SOCK" "$SOCK.lock" "$SOCK.routes.json"
"$HELPER" --socket "$SOCK" --uid "$CLIENT_UID" > /tmp/lios-verify/helper.log 2>&1 &
HPID=$!
trap 'kill $HPID 2>/dev/null; wait $HPID 2>/dev/null; rm -f "$SOCK" "$SOCK.lock"' EXIT
for _ in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 0.25; done
[ -S "$SOCK" ] || { echo "helper never bound; log:"; cat /tmp/lios-verify/helper.log; exit 1; }

hdr "socket ownership (spec §7.1 — both platforms enforce mode bits on connect)"
echo "  socket: mode=$(file_mode "$SOCK") owner=$(file_owner "$SOCK")"
SOCK_OWNER="$(file_owner "$SOCK")"
[ "$SOCK_OWNER" = "$CLIENT_UID" ] \
  && ok "socket belongs to the uid it serves, not root" \
  || bad "socket owner is $SOCK_OWNER, expected $CLIENT_UID — the app could never open it"

# ------------------------------------------------------------------ P1a-7
hdr "P1a-7 — a version-mismatched client fails cleanly"
OUT=$(subst <<'PY' | sudo -u "#$CLIENT_UID" python3 - "$SOCK"
import socket,sys,json,time
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(sys.argv[1])
s.sendall(b'{"type":"hello","id":1,"protocol_version":99}\n'); time.sleep(0.4)
print(s.recv(65536).decode().strip())
PY
)
echo "  $OUT"
echo "$OUT" | grep -q '"kind":"version_mismatch"' \
  && ok "refused with version_mismatch" || bad "expected version_mismatch"

# ------------------------------------------------------------------ P1a-5
hdr "P1a-5 — a connection from an unauthorized uid is refused"
# Written to a world-readable file and run from /tmp: `nobody` cannot read the
# repo directory, and a python that cannot getcwd() dies before it ever reaches
# the socket — which looks like a security failure but is not one.
cat > /tmp/lios-verify/asnobody.py <<'PYEOF'
import socket, sys, time
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sys.argv[1])
    s.sendall(b'{"type":"hello","id":1,"protocol_version":__VER__}\n')
    time.sleep(0.4)
    print("REPLY:" + repr(s.recv(65536)))
except Exception as e:
    print("REFUSED:" + type(e).__name__ + ": " + str(e))
PYEOF
chmod 755 /tmp/lios-verify
chmod 644 /tmp/lios-verify/asnobody.py
OUT=$(cd /tmp && sudo -u "$(other_user)" python3 /tmp/lios-verify/asnobody.py "$SOCK" 2>&1)
echo "  $OUT"
case "$OUT" in
  REFUSED:*)        ok "$(other_user) could not even open the socket (mode bits)";;
  "REPLY:b''")      ok "$(other_user) was authenticated and dropped without a reply";;
  *)                bad "$(other_user) got served: $OUT";;
esac
grep -c "refused a connection" /tmp/lios-verify/helper.log >/dev/null 2>&1 \
  && echo "  helper log: $(grep 'refused a connection' /tmp/lios-verify/helper.log | tail -1)"

# ------------------------------------------------------------------ P1a-6
hdr "P1a-6 — a secret the caller does not own is refused, with nothing created"
# A root-owned 0600 file made here, rather than a system file. /etc/shadow is
# absent on macOS and mode 0640 on Debian, and /etc/master.passwd is absent on
# Linux — each of which makes the refusal happen for the WRONG reason (missing
# file, or loose mode) without ever reaching the ownership check. This one can
# only be refused for the reason the criterion is about.
install -o 0 -g 0 -m 600 /dev/null /tmp/lios-verify/rootkey 2>/dev/null || {
  : > /tmp/lios-verify/rootkey; chown 0 /tmp/lios-verify/rootkey; chmod 600 /tmp/lios-verify/rootkey; }
echo "  bait: $(file_mode /tmp/lios-verify/rootkey) owned by uid $(file_owner /tmp/lios-verify/rootkey)"
IF_PRE="$(iface_list)"
RT_PRE="$(routes | wc -l | tr -d ' ')"
OUT=$(subst <<'PY' | sudo -u "#$CLIENT_UID" python3 - "$SOCK"
import socket,sys,json,time
prof=json.dumps({"id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"evil","protocol":"__PROTO__",
  "host":"__HOST__","port":__PORT__,
  "auth":__BAITFILE__,
  "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},"kill_switch":False})
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(sys.argv[1])
s.sendall(b'{"type":"hello","id":1,"protocol_version":__VER__}\n')
s.sendall((json.dumps({"type":"connect","id":2,"params":{"profile_json":prof,"user":"__SSHUSER__",
  "route_mode":"test","cidrs":["__CIDR__"],"capture_dns":False,
  "tun_address":"10.90.0.1"}})+"\n").encode())
time.sleep(1.0)
print(s.recv(65536).decode().strip())
PY
)
echo "$OUT" | sed 's/^/  /'
IF_POST="$(iface_list)"
RT_POST="$(routes | wc -l | tr -d ' ')"
echo "$OUT" | grep -q '"kind":"secret_not_permitted"' \
  && ok "root-owned secret refused" || bad "expected secret_not_permitted (check it is the OWNERSHIP branch, not a stat or mode failure)"
[ "$IF_PRE" = "$IF_POST" ] && ok "no TUN device created" || bad "interfaces changed: $IF_PRE -> $IF_POST"
[ "$RT_PRE" = "$RT_POST" ] && ok "no route installed" || bad "route count $RT_PRE -> $RT_POST"

hdr "P1a-6b — an env-var secret is refused (it would read ROOT's environment)"
OUT=$(subst <<'PY' | sudo -u "#$CLIENT_UID" python3 - "$SOCK"
import socket,sys,json,time
prof=json.dumps({"id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"evil2","protocol":"__PROTO__",
  "host":"__HOST__","port":__PORT__,
  "auth":__BAITENV__,
  "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},"kill_switch":False})
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(sys.argv[1])
s.sendall(b'{"type":"hello","id":1,"protocol_version":__VER__}\n')
s.sendall((json.dumps({"type":"connect","id":2,"params":{"profile_json":prof,"user":"__SSHUSER__",
  "route_mode":"test","cidrs":["__CIDR__"],"capture_dns":False,
  "tun_address":"10.90.0.1"}})+"\n").encode())
time.sleep(1.0)
print(s.recv(65536).decode().strip())
PY
)
echo "$OUT" | sed 's/^/  /'
echo "$OUT" | grep -q 'env-var secrets are not available' \
  && ok "env-var secret refused" || bad "expected the env-var refusal"

# --------------------------------------------------------- P1a-2 / 3 / 4
hdr "P1a-2, P1a-3, P1a-4 — a real tunnel, live stats, and surviving the client"
# Watch the tunnel device during the fetches. Flat counters alone cannot say
# whether the packets went around the tunnel or into it and vanished; this
# separates the two.
rm -f /tmp/lios-fetching
( for _ in $(seq 1 150); do [ -f /tmp/lios-fetching ] && break; sleep 0.2; done
  # Bounded: an unbounded wait here hangs `wait $DUMPER` forever whenever the
  # client dies before it arms the capture, which turns a failed run into a
  # hung one.
  TUN="$(tun_iface)"
  [ -n "$TUN" ] && timeout 15 tcpdump -n -i "$TUN" -c 20 \
    > /tmp/lios-verify/traffic.pcap.txt 2>&1 ) &
DUMPER=$!
subst <<'PY' | sudo -u "#$CLIENT_UID" python3 - "$SOCK" "$TARGET"
import socket,sys,json,time,subprocess,urllib.request
sock, target = sys.argv[1], sys.argv[2]
prof=open(sys.argv[3] if len(sys.argv)>3 else "/tmp/lios-verify/profile.json").read()
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(sock)
f=s.makefile("rwb")
def send(o): f.write((json.dumps(o)+"\n").encode()); f.flush()
def read(n=1, t=15):
    out=[]; s.settimeout(t)
    for _ in range(n):
        line=f.readline()
        if not line: break
        out.append(json.loads(line))
    return out

send({"type":"hello","id":1,"protocol_version":__VER__}); read(1)
send({"type":"connect","id":2,"params":{"profile_json":prof,"user":"__SSHUSER__",
      "route_mode":"test","cidrs":["__CIDR__"],"capture_dns":False,
      "tun_address":"10.90.0.1"}})
msgs=read(2, t=30)
print("  connect reply:", json.dumps(msgs))
if not any(m.get("type")=="ack" for m in msgs):
    print("  FAIL  P1a-2: the tunnel did not come up"); sys.exit(3)
print("  PASS  P1a-2: connect brought up a real tunnel")

# Collect a couple of stats frames, then drive traffic and collect more.
before=None; after=None
for _ in range(3):
    m=read(1, t=5)
    if m and m[0].get("type")=="stats": before=m[0]["snapshot"]; break
print("  stats before traffic:", before)

open("/tmp/lios-fetching", "w").write("go")   # arms the capture
time.sleep(1.5)                                       # let tcpdump attach
fetched = 0
for _ in range(4):
    try:
        urllib.request.urlopen(f"http://{target}/", timeout=8).read()
        fetched += 1
    except Exception as e:
        print("  fetch:", e)
for _ in range(6):
    m=read(1, t=5)
    if m and m[0].get("type")=="stats": after=m[0]["snapshot"]
print("  stats after traffic :", after)

# Bytes DOWN and a fetch that actually returned. Bytes up alone only prove
# we pushed data at the tunnel — an earlier version passed on that and
# reported success over four timed-out fetches and bytes_down=0.
moved_down = bool(before and after and after["bytes_down"] > before["bytes_down"])
if fetched and moved_down:
    print(f"  PASS  P1a-3: {fetched}/4 fetches returned and bytes came back through the engine")
else:
    print(f"  FAIL  P1a-3: {fetched}/4 fetches returned, bytes_down moved: {moved_down}")
    print("        traffic did not complete a round trip through the tunnel")
    sys.exit(2)          # scored by the shell — a printed FAIL must not tally as a pass
PY
RC=$?
wait $DUMPER 2>/dev/null
echo "  packets on the tunnel device during those fetches:"
sed 's/^/    /' /tmp/lios-verify/traffic.pcap.txt 2>/dev/null | head -8 || echo "    <none captured>"
# 0 = both criteria met; 2 = tunnel up but no traffic through it; 3 = no tunnel.
case $RC in
  0) pass=$((pass+2)) ;;
  2) pass=$((pass+1)); fail=$((fail+1)) ;;   # P1a-2 yes, P1a-3 no
  *) fail=$((fail+2)) ;;
esac

hdr "P1a-4 — the tunnel outlives the client that started it"
echo "  (the python client above has exited; the helper should still hold the tunnel)"
RT_TUN="$(routes | grep -F "$TARGET" | head -2)"
echo "  route: ${RT_TUN:-<none>}"
OUT=$(subst <<'PY' | sudo -u "#$CLIENT_UID" python3 - "$SOCK"
import socket,sys,json,time
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(sys.argv[1])
s.sendall(b'{"type":"hello","id":1,"protocol_version":__VER__}\n')
s.sendall(b'{"type":"get_status","id":2}\n'); time.sleep(0.8)
print(s.recv(65536).decode().strip())
PY
)
echo "$OUT" | sed 's/^/  /'
echo "$OUT" | grep -q '"state":"Connected"' \
  && ok "a fresh client re-synced to the still-running tunnel" \
  || bad "a reconnecting client did not see the tunnel"

hdr "teardown"
subst <<'PY' | sudo -u "#$CLIENT_UID" python3 - "$SOCK"
import socket,sys,time
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(sys.argv[1])
s.sendall(b'{"type":"hello","id":1,"protocol_version":__VER__}\n')
s.sendall(b'{"type":"disconnect","id":2}\n'); time.sleep(1.5)
print("  "+s.recv(65536).decode().strip().replace("\n","\n  "))
PY

kill $HPID 2>/dev/null; wait $HPID 2>/dev/null; trap - EXIT
sleep 1
DEFAULT_AFTER="$(default_route)"
IFACES_AFTER="$(iface_list)"
[ "$DEFAULT_BEFORE" = "$DEFAULT_AFTER" ] \
  && ok "default route unchanged throughout" || bad "DEFAULT ROUTE CHANGED"
[ "$IFACES_BEFORE" = "$IFACES_AFTER" ] \
  && ok "no interface left behind" || bad "interfaces differ: $IFACES_BEFORE -> $IFACES_AFTER"
LEFTOVER="$(routes | grep -E "$(tun_pattern)|10\.90\.0|$(echo "$TARGET" | sed 's/\./\\./g')" || true)"
[ -z "$LEFTOVER" ] \
  && ok "no tunnel or utun route survived teardown" \
  || bad "left behind: $LEFTOVER"
grep -q 'route revert step failed' /tmp/lios-verify/helper.log \
  && bad "a revert command FAILED (see helper log) - cleanup happened by accident" \
  || ok "every revert command succeeded"
rm -f "$SOCK" "$SOCK.lock" "$SOCK.routes.json"

echo; echo "=== $pass passed, $fail failed ==="
echo "helper log: /tmp/lios-verify/helper.log"
exit $((fail > 0))

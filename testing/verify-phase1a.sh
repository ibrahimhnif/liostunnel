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

SOCK=/tmp/lios-verify/helper.sock
PROFILE=/tmp/lios-verify/profile.json
# A public /32 with no competing host route. Longest-prefix match means it
# beats the default route, so traffic to it can only go through the tunnel.
# The docker network is NOT usable as the target: Docker Desktop already
# installs a route for it via its own bridge, so ours never wins, traffic
# bypasses the engine entirely, and the curl still succeeds — which looks
# like a working tunnel while proving nothing.
FIXTURE_CIDR=1.1.1.1/32
TARGET=1.1.1.1
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$repo/target/release/liostunnel-helper"

pass=0; fail=0
ok()   { echo "  PASS  $*"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail+1)); }
hdr()  { echo; echo "=== $* ==="; }

[ "$(id -u)" -eq 0 ] || { echo "must run as root (sudo)"; exit 1; }
CLIENT_UID="${SUDO_UID:-}"
[ -n "$CLIENT_UID" ] || { echo "SUDO_UID unset; run via sudo from your own account"; exit 1; }
[ -f "$HELPER" ] || { echo "no release helper; run: cargo build --release -p liostunnel-helper"; exit 1; }
[ -f "$PROFILE" ] || { echo "no profile at $PROFILE"; exit 1; }

echo "helper : $HELPER"
echo "client : uid $CLIENT_UID"
echo "target : $TARGET via $FIXTURE_CIDR"

# ---------------------------------------------------------------- baseline
DEFAULT_BEFORE="$(netstat -rn -f inet 2>/dev/null | grep '^default' || ip route show default 2>/dev/null)"
IFACES_BEFORE="$(ifconfig -l 2>/dev/null || ip -br link | awk '{print $1}' | tr '\n' ' ')"

rm -f "$SOCK" "$SOCK.lock" "$SOCK.routes.json"
"$HELPER" --socket "$SOCK" --uid "$CLIENT_UID" > /tmp/lios-verify/helper.log 2>&1 &
HPID=$!
trap 'kill $HPID 2>/dev/null; wait $HPID 2>/dev/null; rm -f "$SOCK" "$SOCK.lock"' EXIT
for _ in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 0.25; done
[ -S "$SOCK" ] || { echo "helper never bound; log:"; cat /tmp/lios-verify/helper.log; exit 1; }

hdr "socket ownership (spec §7.1 — both platforms enforce mode bits on connect)"
stat -f '  socket: mode=%Lp owner=%u' "$SOCK" 2>/dev/null || stat -c '  socket: mode=%a owner=%u' "$SOCK"
SOCK_OWNER="$(stat -f '%u' "$SOCK" 2>/dev/null || stat -c '%u' "$SOCK")"
[ "$SOCK_OWNER" = "$CLIENT_UID" ] \
  && ok "socket belongs to the uid it serves, not root" \
  || bad "socket owner is $SOCK_OWNER, expected $CLIENT_UID — the app could never open it"

# ------------------------------------------------------------------ P1a-7
hdr "P1a-7 — a version-mismatched client fails cleanly"
OUT=$(sudo -u "#$CLIENT_UID" python3 - "$SOCK" <<'PY'
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
    s.sendall(b'{"type":"hello","id":1,"protocol_version":1}\n')
    time.sleep(0.4)
    print("REPLY:" + repr(s.recv(65536)))
except Exception as e:
    print("REFUSED:" + type(e).__name__ + ": " + str(e))
PYEOF
chmod 755 /tmp/lios-verify
chmod 644 /tmp/lios-verify/asnobody.py
OUT=$(cd /tmp && sudo -u nobody python3 /tmp/lios-verify/asnobody.py "$SOCK" 2>&1)
echo "  $OUT"
case "$OUT" in
  REFUSED:*)        ok "nobody could not even open the socket (mode bits)";;
  "REPLY:b''")      ok "nobody was authenticated and dropped without a reply";;
  *)                bad "nobody got served: $OUT";;
esac
grep -c "refused a connection" /tmp/lios-verify/helper.log >/dev/null 2>&1 \
  && echo "  helper log: $(grep 'refused a connection' /tmp/lios-verify/helper.log | tail -1)"

# ------------------------------------------------------------------ P1a-6
hdr "P1a-6 — a secret the caller does not own is refused, with nothing created"
IF_PRE="$(ifconfig -l 2>/dev/null || ip -br link | awk '{print $1}' | tr '\n' ' ')"
RT_PRE="$(netstat -rn -f inet 2>/dev/null | wc -l | tr -d ' ')"
OUT=$(sudo -u "#$CLIENT_UID" python3 - "$SOCK" <<'PY'
import socket,sys,json,time
prof=json.dumps({"id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"evil","protocol":"ssh",
  "host":"127.0.0.1","port":22022,
  "auth":{"type":"private_key","private_key":{"source":"file","path":"/etc/master.passwd"}},
  "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},"kill_switch":False})
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(sys.argv[1])
s.sendall(b'{"type":"hello","id":1,"protocol_version":1}\n')
s.sendall((json.dumps({"type":"connect","id":2,"params":{"profile_json":prof,"user":"tunneluser",
  "route_mode":"test","cidrs":["1.1.1.1/32"],"capture_dns":False,
  "tun_address":"10.90.0.1"}})+"\n").encode())
time.sleep(1.0)
print(s.recv(65536).decode().strip())
PY
)
echo "$OUT" | sed 's/^/  /'
IF_POST="$(ifconfig -l 2>/dev/null || ip -br link | awk '{print $1}' | tr '\n' ' ')"
RT_POST="$(netstat -rn -f inet 2>/dev/null | wc -l | tr -d ' ')"
echo "$OUT" | grep -q '"kind":"secret_not_permitted"' \
  && ok "root-owned secret refused" || bad "expected secret_not_permitted"
[ "$IF_PRE" = "$IF_POST" ] && ok "no TUN device created" || bad "interfaces changed: $IF_PRE -> $IF_POST"
[ "$RT_PRE" = "$RT_POST" ] && ok "no route installed" || bad "route count $RT_PRE -> $RT_POST"

hdr "P1a-6b — an env-var secret is refused (it would read ROOT's environment)"
OUT=$(sudo -u "#$CLIENT_UID" python3 - "$SOCK" <<'PY'
import socket,sys,json,time
prof=json.dumps({"id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"evil2","protocol":"ssh",
  "host":"127.0.0.1","port":22022,
  "auth":{"type":"password","password":{"source":"env","var":"HOME"}},
  "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},"kill_switch":False})
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(sys.argv[1])
s.sendall(b'{"type":"hello","id":1,"protocol_version":1}\n')
s.sendall((json.dumps({"type":"connect","id":2,"params":{"profile_json":prof,"user":"tunneluser",
  "route_mode":"test","cidrs":["1.1.1.1/32"],"capture_dns":False,
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
sudo -u "#$CLIENT_UID" python3 - "$SOCK" "$TARGET" <<'PY'
import socket,sys,json,time,subprocess,urllib.request
sock, target = sys.argv[1], sys.argv[2]
prof=open("/tmp/lios-verify/profile.json").read()
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

send({"type":"hello","id":1,"protocol_version":1}); read(1)
send({"type":"connect","id":2,"params":{"profile_json":prof,"user":"tunneluser",
      "route_mode":"test","cidrs":["1.1.1.1/32"],"capture_dns":False,
      "tun_address":"10.90.0.1"}})
msgs=read(2, t=30)
print("  connect reply:", json.dumps(msgs))
if not any(m.get("type")=="ack" for m in msgs):
    print("  FAIL  the tunnel did not come up"); sys.exit(1)
print("  PASS  P1a-2: connect brought up a real tunnel")

# Collect a couple of stats frames, then drive traffic and collect more.
before=None; after=None
for _ in range(3):
    m=read(1, t=5)
    if m and m[0].get("type")=="stats": before=m[0]["snapshot"]; break
print("  stats before traffic:", before)

for _ in range(4):
    try: urllib.request.urlopen(f"http://{target}/", timeout=8).read()
    except Exception as e: print("  curl:", e)
for _ in range(6):
    m=read(1, t=5)
    if m and m[0].get("type")=="stats": after=m[0]["snapshot"]
print("  stats after traffic :", after)

if before and after and (after["bytes_up"]>before["bytes_up"] or after["bytes_down"]>before["bytes_down"]):
    print("  PASS  P1a-3: stats moved in response to traffic — the bytes went through the engine")
else:
    print("  FAIL  P1a-3: stats did not move")
PY
RC=$?
[ $RC -eq 0 ] && pass=$((pass+2)) || fail=$((fail+1))

hdr "P1a-4 — the tunnel outlives the client that started it"
echo "  (the python client above has exited; the helper should still hold the tunnel)"
RT_TUN="$(netstat -rn -f inet 2>/dev/null | grep '1\.1\.1\.1' | head -2)"
echo "  route: ${RT_TUN:-<none>}"
OUT=$(sudo -u "#$CLIENT_UID" python3 - "$SOCK" <<'PY'
import socket,sys,json,time
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(sys.argv[1])
s.sendall(b'{"type":"hello","id":1,"protocol_version":1}\n')
s.sendall(b'{"type":"get_status","id":2}\n'); time.sleep(0.8)
print(s.recv(65536).decode().strip())
PY
)
echo "$OUT" | sed 's/^/  /'
echo "$OUT" | grep -q '"state":"Connected"' \
  && ok "a fresh client re-synced to the still-running tunnel" \
  || bad "a reconnecting client did not see the tunnel"

hdr "teardown"
sudo -u "#$CLIENT_UID" python3 - "$SOCK" <<'PY'
import socket,sys,time
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(sys.argv[1])
s.sendall(b'{"type":"hello","id":1,"protocol_version":1}\n')
s.sendall(b'{"type":"disconnect","id":2}\n'); time.sleep(1.5)
print("  "+s.recv(65536).decode().strip().replace("\n","\n  "))
PY

kill $HPID 2>/dev/null; wait $HPID 2>/dev/null; trap - EXIT
sleep 1
DEFAULT_AFTER="$(netstat -rn -f inet 2>/dev/null | grep '^default' || ip route show default 2>/dev/null)"
IFACES_AFTER="$(ifconfig -l 2>/dev/null || ip -br link | awk '{print $1}' | tr '\n' ' ')"
[ "$DEFAULT_BEFORE" = "$DEFAULT_AFTER" ] \
  && ok "default route unchanged throughout" || bad "DEFAULT ROUTE CHANGED"
[ "$IFACES_BEFORE" = "$IFACES_AFTER" ] \
  && ok "no interface left behind" || bad "interfaces differ: $IFACES_BEFORE -> $IFACES_AFTER"
LEFTOVER="$(netstat -rn -f inet 2>/dev/null | grep -E 'utun|10\.90\.0|^1\.1\.1\.1' || true)"
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

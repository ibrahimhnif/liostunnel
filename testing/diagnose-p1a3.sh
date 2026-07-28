#!/usr/bin/env bash
#
# Why does traffic to a routed CIDR never reach the engine?
#
#     sudo ./testing/diagnose-p1a3.sh
#
# Answers one question decisively: do packets actually arrive at the TUN
# device? tcpdump sits on the utun while a curl runs.
#
#   packets on utun, engine counters zero  -> the stack is not reading them
#   no packets on utun                     -> the route is not steering them
#
# Then repeats the same test with Phase 0's CLI, which is the known-good
# path, so we can tell a Task 6 wiring problem from a pre-existing one.
#
set -uo pipefail

SOCK=/tmp/lios-verify/diag.sock
PROFILE=/tmp/lios-verify/profile.json
TARGET=1.1.1.1
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "must run as root (sudo)"; exit 1; }
CLIENT_UID="${SUDO_UID:-}"
[ -n "$CLIENT_UID" ] || { echo "SUDO_UID unset; run via sudo"; exit 1; }

echo "############ PART 1: the helper ############"
rm -f "$SOCK" "$SOCK.lock" "$SOCK.routes.json"
RUST_LOG=liostunnel_core=debug,liostunnel_helper=info \
  "$repo/target/release/liostunnel-helper" --socket "$SOCK" --uid "$CLIENT_UID" \
  > /tmp/lios-verify/diag-helper.log 2>&1 &
HPID=$!
trap 'kill $HPID 2>/dev/null; wait $HPID 2>/dev/null; pkill -f "tcpdump -i utun" 2>/dev/null; rm -f "$SOCK" "$SOCK.lock"' EXIT
for _ in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 0.25; done

cat > /tmp/lios-verify/diag.py <<'PYEOF'
import socket, sys, json, time, urllib.request
sock, target, phase = sys.argv[1], sys.argv[2], sys.argv[3]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sock)
f = s.makefile("rwb")
def send(o): f.write((json.dumps(o) + "\n").encode()); f.flush()
def read(n=1, t=20):
    out = []; s.settimeout(t)
    for _ in range(n):
        line = f.readline()
        if not line: break
        out.append(json.loads(line))
    return out

send({"type": "hello", "id": 1, "protocol_version": 1}); read(1)
send({"type": "connect", "id": 2, "params": {
    "profile_json": open("/tmp/lios-verify/profile.json").read(),
    "user": "tunneluser", "route_mode": "test", "cidrs": ["1.1.1.1/32"],
    "capture_dns": False, "tun_address": "10.90.0.1"}})
print("  connect:", json.dumps(read(2, t=30)))
open("/tmp/lios-verify/ready", "w").write("go")
time.sleep(14)                      # the shell curls and dumps during this
last = None
for _ in range(8):
    m = read(1, t=3)
    if m and m[0].get("type") == "stats": last = m[0]["snapshot"]
print("  engine counters after traffic:", last)
send({"type": "disconnect", "id": 3}); read(2, t=10)
PYEOF
chmod 644 /tmp/lios-verify/diag.py

rm -f /tmp/lios-verify/ready
(cd /tmp && sudo -u "#$CLIENT_UID" python3 /tmp/lios-verify/diag.py "$SOCK" "$TARGET" helper) &
CLIENT=$!
for _ in $(seq 1 60); do [ -f /tmp/lios-verify/ready ] && break; sleep 0.5; done

TUN="$(ifconfig -l | tr ' ' '\n' | grep '^utun' | tail -1)"
echo "  tun device : $TUN"
echo "  route      : $(netstat -rn -f inet | grep '^1\.1\.1\.1' || echo '<NONE — the route is missing>')"
echo "  ifconfig   : $(ifconfig "$TUN" 2>/dev/null | tr '\n' ' ' | sed 's/  */ /g')"

echo "  --- tcpdump on $TUN while curling $TARGET ---"
timeout 10 tcpdump -n -i "$TUN" -c 10 > /tmp/lios-verify/dump.txt 2>&1 &
DUMP=$!
sleep 1
curl -s -m 6 -o /dev/null -w "  curl http_code=%{http_code} time=%{time_total}s\n" "http://$TARGET/" || echo "  curl failed"
wait $DUMP 2>/dev/null
echo "  packets seen on $TUN:"
sed 's/^/    /' /tmp/lios-verify/dump.txt | head -12
wait $CLIENT 2>/dev/null

kill $HPID 2>/dev/null; wait $HPID 2>/dev/null
echo
echo "  helper log tail:"
tail -20 /tmp/lios-verify/diag-helper.log | sed 's/^/    /'

echo
echo "############ PART 2: Phase 0's CLI, same parameters ############"
echo "  (the known-good path — if this works and the helper does not,"
echo "   the difference is in Task 6's wiring, not in the engine)"
install -m 700 -d /tmp/lios-verify/clihome
install -m 600 "$PROFILE" /tmp/lios-verify/clihome/fixture.json

# AS ROOT. Creating a TUN device needs privilege — the previous version of
# this script dropped to the client uid here, so the CLI died with
# "Operation not permitted" and the comparison never actually ran.
HOME=/tmp/lios-verify/clihome RUST_LOG=liostunnel_core=debug \
  "$repo/target/release/liostunnel" connect /tmp/lios-verify/clihome/fixture.json \
  --user tunneluser --route-mode test --cidr 1.1.1.1/32 \
  > /tmp/lios-verify/cli.log 2>&1 &
CPID=$!
sleep 12
echo "  tun device : $(ifconfig -l | tr ' ' '\n' | grep '^utun' | tail -1)"
echo "  route      : $(netstat -rn -f inet | grep '^1\.1\.1\.1' || echo '<none>')"
curl -s -m 8 -o /dev/null -w "  curl http_code=%{http_code} time=%{time_total}s\n" "http://$TARGET/" || echo "  curl failed"
kill -INT $CPID 2>/dev/null; sleep 3; kill $CPID 2>/dev/null; wait $CPID 2>/dev/null
echo "  cli log (last 20):"
tail -20 /tmp/lios-verify/cli.log | sed 's/^/    /'

rm -rf /tmp/lios-verify/clihome
echo
echo "done"

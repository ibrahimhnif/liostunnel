#!/usr/bin/env bash
#
# Runs the Phase 1a verification inside the Linux fixture, where Phase 0's
# engine is known to carry traffic.
#
#     ./testing/verify-linux.sh
#
# Needs no sudo on the host: root lives inside the container, which gets only
# NET_ADMIN, NET_RAW and /dev/net/tun. Nothing on the host's routing table or
# interfaces is touched.
#
# The target is the fixture's own nginx, routed as a /32. That beats the
# container's /24 bridge route by longest prefix, so the kernel has no path
# for it except the TUN device — a successful fetch cannot have gone around
# the tunnel.
#
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

NET=docker_lios
IMAGE=lios-verifier

docker network inspect "$NET" >/dev/null 2>&1 || {
  echo "fixture network $NET is not up — run: make -C testing/docker up"; exit 1; }

TARGET_IP="$(docker inspect docker-target-1 \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
SSH_IP="$(docker inspect docker-sshd-1 \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
[ -n "$TARGET_IP" ] && [ -n "$SSH_IP" ] || { echo "fixture containers not found"; exit 1; }
echo "fixture: sshd=$SSH_IP  target=$TARGET_IP"

echo "building the Linux helper..."
docker run --rm -v "$repo":/w -w /w -e CARGO_TARGET_DIR=/w/target-linux \
  rust:1.93-slim cargo build --release -p liostunnel-helper 2>&1 | tail -2

echo "building the verifier image..."
docker build -q -t "$IMAGE" testing/docker/verifier

echo "running the verification..."
docker run --rm \
  --network "$NET" \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun \
  -v "$repo":/w -w /w \
  -e LIOS_TARGET="$TARGET_IP" \
  -e LIOS_CIDR="$TARGET_IP/32" \
  -e LIOS_SSH_HOST="$SSH_IP" \
  -e LIOS_SSH_PORT=22 \
  -e LIOS_SSH_USER=tunneluser \
  -e LIOS_HELPER=/w/target-linux/release/liostunnel-helper \
  -e LIOS_PROFILE=/tmp/lios-verify/profile.json \
  "$IMAGE" -c '
set -e
mkdir -p /tmp/lios-verify
# The key must be owned by the client uid and 0600, which is what the P1a-6
# gate checks. Copying rather than bind-mounting so ownership is ours to set.
install -o 1500 -g 1500 -m 600 testing/docker/sshd/keys/client_ed25519 /tmp/lios-verify/key
cat > /tmp/lios-verify/profile.json <<JSON   # expanded by the container shell
{"id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"Docker fixture",
 "protocol":"ssh","host":"$LIOS_SSH_HOST","port":22,
 "auth":{"type":"private_key","private_key":{"source":"file","path":"/tmp/lios-verify/key"}},
 "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},"kill_switch":false}
JSON
chown 1500 /tmp/lios-verify/profile.json
chmod 755 /tmp/lios-verify
# The script expects SUDO_UID to name the client account.
SUDO_UID=1500 bash testing/verify-phase1a.sh
'

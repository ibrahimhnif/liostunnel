#!/usr/bin/env bash
# Generates throwaway keys for the test fixture. Never committed — see .gitignore.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p keys
[ -f keys/ssh_host_ed25519_key ] || \
  ssh-keygen -t ed25519 -N "" -C "liostunnel-test-host" -f keys/ssh_host_ed25519_key
[ -f keys/client_ed25519 ] || \
  ssh-keygen -t ed25519 -N "" -C "liostunnel-test-client" -f keys/client_ed25519
cp keys/client_ed25519.pub keys/authorized_keys
chmod 600 keys/ssh_host_ed25519_key keys/client_ed25519 keys/authorized_keys
echo "keys ready in $(pwd)/keys"

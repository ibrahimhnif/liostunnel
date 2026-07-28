#!/usr/bin/env bash
# EC6 / PRD §8, spec §13. Throughput through liostunnel must be within 20% of
# raw `ssh -D` SOCKS proxying, for a large download.
#
# Usage:
#   ./testing/gates/throughput_test.sh <ssh-user@host> <url> [min-bytes]
#
# Example:
#   ./testing/gates/throughput_test.sh me@myserver https://speed.hetzner.de/100MB.bin
#
# What "PASS" means: `curl`ing <url> through the tunnel takes no more than
# 1.20x as long, wall-clock, as `curl`ing the same URL through a plain
# `ssh -D` SOCKS proxy to the same server — both downloads must actually
# complete successfully and transfer at least [min-bytes] (default 1,000,000)
# bytes; a failed or truncated download invalidates the timing on whichever
# side it happened, so this script treats that as a hard failure rather than
# silently comparing a real download against a broken one.
#
# This script drives the *baseline* (ssh -D) itself, but the *tunnel* side
# depends on a `liostunnel connect ... --route-mode default` you bring up by
# hand in another shell — this script cannot do that safely from here (see
# testing/gates/README.md for why route mutation is never automated).
set -euo pipefail

TARGET="${1:?usage: throughput_test.sh <user@host> <url> [min-bytes]}"
URL="${2:?usage: throughput_test.sh <user@host> <url> [min-bytes]}"
MIN_BYTES="${3:-1000000}"
SOCKS_PORT=11080
CEILING=1.20

case "$TARGET" in
  *@*) ;;
  *)
    echo "FAIL: '$TARGET' does not look like user@host" >&2
    exit 1
    ;;
esac
case "$URL" in
  http://* | https://*) ;;
  *)
    echo "FAIL: '$URL' is not an http(s) URL" >&2
    exit 1
    ;;
esac

for bin in ssh curl awk; do
  command -v "$bin" >/dev/null 2>&1 || {
    echo "FAIL: required tool '$bin' not found on PATH" >&2
    exit 1
  }
done

SSH_PID=""
cleanup() {
  if [ -n "$SSH_PID" ] && kill -0 "$SSH_PID" 2>/dev/null; then
    kill "$SSH_PID" 2>/dev/null || true
    wait "$SSH_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

secs() { date +%s.%N; }

port_is_listening() {
  # Opened and closed entirely inside the subshell — the fd never leaks into
  # this script's own shell, so there is nothing to explicitly close here.
  (exec 3<>"/dev/tcp/127.0.0.1/$SOCKS_PORT") 2>/dev/null
}

# curl -w output: "<http_code> <size_download>". Fails loudly (rather than
# returning a fabricated 0/0) if curl itself cannot even be invoked.
fetch() {
  # $1: extra curl args (e.g. --socks5-hostname host:port), unquoted on
  # purpose so an empty string expands to nothing.
  # shellcheck disable=SC2086
  curl -s -o /dev/null --max-time 120 $1 \
    -w '%{http_code} %{size_download}' "$URL"
}

assert_download_ok() {
  local label="$1" http_code="$2" size="$3"
  case "$http_code" in
    2*) ;;
    *)
      echo "FAIL: $label download returned HTTP $http_code, not 2xx" >&2
      exit 1
      ;;
  esac
  if awk -v s="$size" -v m="$MIN_BYTES" 'BEGIN { exit !(s+0 >= m+0) }'; then
    :
  else
    echo "FAIL: $label download was only $size bytes (expected at least $MIN_BYTES)" >&2
    echo "      — too small to trust the timing; check the URL is really a" >&2
    echo "      large file and not, e.g., a redirect or an error page." >&2
    exit 1
  fi
}

echo "== baseline: ssh -D SOCKS proxy =="
ssh -N -D "$SOCKS_PORT" \
  -o ExitOnForwardFailure=yes -o BatchMode=yes -o ConnectTimeout=10 \
  "$TARGET" &
SSH_PID=$!

READY=0
for _ in $(seq 1 50); do
  if ! kill -0 "$SSH_PID" 2>/dev/null; then
    break
  fi
  if port_is_listening; then
    READY=1
    break
  fi
  sleep 0.2
done
if [ "$READY" -ne 1 ]; then
  echo "FAIL: ssh -D never bound 127.0.0.1:$SOCKS_PORT within 10s" \
    "(auth failure? host unreachable? forwarding disabled server-side?)" >&2
  exit 1
fi

T0=$(secs)
if ! read -r BASE_CODE BASE_SIZE < <(fetch "--socks5-hostname 127.0.0.1:$SOCKS_PORT"); then
  echo "FAIL: baseline curl produced no measurable output at all" >&2
  exit 1
fi
BASE=$(awk -v a="$(secs)" -v b="$T0" 'BEGIN { printf "%.3f", a - b }')
assert_download_ok "baseline" "$BASE_CODE" "$BASE_SIZE"
kill "$SSH_PID" 2>/dev/null || true
wait "$SSH_PID" 2>/dev/null || true
SSH_PID=""
echo "baseline: ${BASE}s ($BASE_SIZE bytes, HTTP $BASE_CODE)"

echo "== through liostunnel =="
echo "Bring the tunnel up now: sudo liostunnel connect <profile> --user <u> --route-mode default"
echo "Then press enter here."
read -r _

T0=$(secs)
if ! read -r TUN_CODE TUN_SIZE < <(fetch ""); then
  echo "FAIL: tunnel curl produced no measurable output at all" >&2
  exit 1
fi
TUNNEL=$(awk -v a="$(secs)" -v b="$T0" 'BEGIN { printf "%.3f", a - b }')
assert_download_ok "tunnel" "$TUN_CODE" "$TUN_SIZE"
echo "liostunnel: ${TUNNEL}s ($TUN_SIZE bytes, HTTP $TUN_CODE)"

RATIO=$(awk -v t="$TUNNEL" -v b="$BASE" 'BEGIN { printf "%.3f", t / b }')
echo "ratio: ${RATIO}x (ceiling ${CEILING}x)"

OVER=$(awk -v r="$RATIO" -v c="$CEILING" 'BEGIN { print (r > c) ? 1 : 0 }')
if [ "$OVER" -eq 1 ]; then
  echo "FAIL: ${RATIO}x is more than ${CEILING}x — more than 20% slower than raw ssh -D" >&2
  echo "      Tune StackConfig::tcp_buffer_bytes and channel_depth before concluding" >&2
  echo "      the architecture is at fault — see spec §14." >&2
  exit 1
fi
echo "PASS: ${RATIO}x is within the PRD §8 budget (ceiling ${CEILING}x)"

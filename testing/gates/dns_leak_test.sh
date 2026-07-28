#!/usr/bin/env bash
# EC4 / spec §12 T6, §13. Proves that no DNS query left this machine outside
# the tunnel while it was up in `default` route mode.
#
# Usage (tunnel already connected, in `default` route mode):
#   sudo ./testing/gates/dns_leak_test.sh <physical-interface> [window-seconds]
#
# Examples: `sudo ./testing/gates/dns_leak_test.sh en0`
#           `sudo ./testing/gates/dns_leak_test.sh eth0 30`
#
# What "PASS" means: over the whole capture window, on the *physical*
# interface (never on the tunnel interface — that traffic is expected and
# irrelevant), zero packets were observed that carry a DNS query or answer,
# by any of the transports DNS can use: plain UDP/TCP port 53, DNS-over-TLS
# (TCP 853), and DNS-over-HTTPS to an IP address that is essentially never
# anything but a public DNS resolver (TCP 443 to 1.1.1.1, 8.8.8.8, 9.9.9.9,
# etc. — see KNOWN_DOH_IPS below). A single leaked packet is a FAIL, not a
# rounding error: EC4 is "no DNS query escapes the tunnel," not "most don't."
#
# What this script cannot prove:
#   - DoH to a resolver IP *not* in KNOWN_DOH_IPS is indistinguishable from
#     ordinary HTTPS traffic to that same IP from the outside. This is a
#     heuristic over the common public resolvers, not a proof over every
#     possible DoH deployment.
#   - That the queries below are representative of what every application
#     on the box will do. Route/firewall/systemd-resolved changes made after
#     this script was written could reopen a leak this exact command list
#     does not happen to trigger.
#
# KNOWN, EXPECTED-TO-FAIL GAPS as of Task 22 (see README.md's Limitations
# section and the Task 22 report for detail — do not treat either as a bug in
# THIS script):
#   - Linux `default` route mode installs no DNS override at all today.
#     `/etc/resolv.conf` still points at the LAN resolver, reachable via a
#     route more specific than the tunnel's split-default halves, so DNS
#     genuinely leaves the machine outside the tunnel. Running this gate on
#     Linux today is expected to FAIL, loudly, for exactly that reason.
#   - IPv6 is not covered by routing in either platform's `default` mode
#     (only `0.0.0.0/1` + `128.0.0.0/1` are installed; `::/0` is untouched).
#     Any IPv6-only DNS traffic bypasses the tunnel entirely and this script
#     WILL catch it (the capture filter below is address-family-agnostic),
#     which is correct — it is not a false positive.
set -euo pipefail

IFACE="${1:?usage: dns_leak_test.sh <physical-interface> [window-seconds]}"
WINDOW="${2:-20}"

# Cloudflare, Google, Quad9, Quad9 secondary, OpenDNS, AdGuard. Anycast
# addresses effectively dedicated to DNS — traffic to these on 443 is
# overwhelmingly likely to be DoH, not an unrelated website hosted there.
KNOWN_DOH_IPS=(1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112 208.67.222.222 208.67.220.220 94.140.14.14)

# --- Preflight: fail loudly and specifically before touching anything. ----

if [ "$(id -u)" -ne 0 ]; then
  echo "FAIL: must run as root (tcpdump needs raw socket access on $IFACE)" >&2
  exit 1
fi

for bin in tcpdump getent curl; do
  command -v "$bin" >/dev/null 2>&1 || {
    echo "FAIL: required tool '$bin' not found on PATH" >&2
    exit 1
  }
done

if ! (ip link show "$IFACE" >/dev/null 2>&1 || ifconfig "$IFACE" >/dev/null 2>&1); then
  echo "FAIL: interface '$IFACE' does not exist on this machine" >&2
  exit 1
fi

case "$(uname -s)" in
  Linux)
    echo "NOTE: running on Linux. As of Task 22, Linux's \`default\` route mode" >&2
    echo "      installs no DNS override — this gate is EXPECTED TO FAIL on" >&2
    echo "      Linux today. See README.md Limitations. A FAIL here is not a" >&2
    echo "      bug in this script; it is this script doing its job." >&2
    ;;
esac

CAPTURE="$(mktemp -t liosleak-main.XXXXXX).pcap"
DOH_CAPTURE="$(mktemp -t liosleak-doh.XXXXXX).pcap"
TCPDUMP_LOG="$(mktemp -t liosleak-tcpdump.XXXXXX).log"
MAIN_PID=""
DOH_PID=""

cleanup() {
  # Idempotent and safe to call more than once (trap fires on EXIT no matter
  # how the script leaves — success, a failed assertion, or a signal). A
  # capture process left running, or a temp pcap left on disk, is exactly the
  # kind of operator cost the task brief calls out.
  for pid in "$MAIN_PID" "$DOH_PID"; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -f "$CAPTURE" "$DOH_CAPTURE" "$TCPDUMP_LOG"
}
trap cleanup EXIT INT TERM

# --- Start both captures before generating any traffic. -------------------
#
# `port 53` matches both UDP and TCP, both IPv4 and IPv6 — the IPv6 known gap
# above is caught by this filter, not excluded by it. `tcp port 853` is
# DNS-over-TLS. Both are the "genuinely, unambiguously DNS" filter: any hit
# here is a hard FAIL, no judgment call required.
tcpdump -i "$IFACE" -n -U -w "$CAPTURE" '(port 53) or (tcp port 853)' \
  >"$TCPDUMP_LOG" 2>&1 &
MAIN_PID=$!

doh_filter="tcp port 443 and ("
first=true
for ip in "${KNOWN_DOH_IPS[@]}"; do
  $first || doh_filter+=" or "
  doh_filter+="host $ip"
  first=false
done
doh_filter+=")"
tcpdump -i "$IFACE" -n -U -w "$DOH_CAPTURE" "$doh_filter" \
  >>"$TCPDUMP_LOG" 2>&1 &
DOH_PID=$!

# Confirm both captures are actually attached before relying on the window —
# a tcpdump that failed to start (bad permissions, no such device, BPF syntax
# error) must not be mistaken for "no leak observed."
for _ in $(seq 1 50); do
  if grep -q "listening on" "$TCPDUMP_LOG" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if ! kill -0 "$MAIN_PID" 2>/dev/null || ! kill -0 "$DOH_PID" 2>/dev/null; then
  echo "FAIL: tcpdump exited immediately instead of capturing — log follows:" >&2
  cat "$TCPDUMP_LOG" >&2
  exit 1
fi
if ! grep -q "listening on" "$TCPDUMP_LOG" 2>/dev/null; then
  echo "FAIL: tcpdump never reported it was listening within 5s; the capture" >&2
  echo "      window cannot be trusted to cover the traffic generated below." >&2
  cat "$TCPDUMP_LOG" >&2
  exit 1
fi

echo "capturing on $IFACE for ${WINDOW}s (port 53, tcp/853, and DoH-shaped tcp/443)"

# --- Generate resolution traffic that must travel through the tunnel. -----
#
# Both `getent` (goes through the OS resolver / nsswitch, so it exercises
# whatever /etc/resolv.conf or systemd-resolved actually does) and a `curl`
# per host (exercises an application's own resolution path, which on some
# platforms differs from `getent`'s) are used, and successes are counted —
# a script that "generates traffic" nobody can prove happened, then reports
# zero leaked packets, has proven nothing.
HOSTS=(example.com wikipedia.org debian.org rust-lang.org)
RESOLVED=0
for host in "${HOSTS[@]}"; do
  if getent hosts "$host" >/dev/null 2>&1; then
    RESOLVED=$((RESOLVED + 1))
  fi
  curl -s -o /dev/null --max-time 5 "http://$host/" || true
done

# Tail grace period: let in-flight queries and tcpdump's own write buffer
# catch up before the window closes.
remaining=$((WINDOW - 2))
[ "$remaining" -gt 0 ] && sleep "$remaining"
sleep 2

for pid in "$MAIN_PID" "$DOH_PID"; do
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
done
MAIN_PID=""
DOH_PID=""

if [ "$RESOLVED" -eq 0 ]; then
  echo "FAIL (inconclusive): none of ${#HOSTS[@]} test hostnames resolved via" >&2
  echo "      getent — this run generated no proven DNS activity, so a" >&2
  echo "      'zero packets leaked' result below would not mean anything." >&2
  echo "      Check that the tunnel is actually up and DNS is functional at" >&2
  echo "      all before re-running this gate." >&2
  exit 1
fi

# --- Analyze. ---------------------------------------------------------------

MAIN_COUNT=$(tcpdump -r "$CAPTURE" -n 2>/dev/null | wc -l | tr -d ' ')
DOH_COUNT=$(tcpdump -r "$DOH_CAPTURE" -n 2>/dev/null | wc -l | tr -d ' ')

FAILED=0
if [ "$MAIN_COUNT" -ne 0 ]; then
  echo "FAIL: $MAIN_COUNT plain-DNS/DoT packet(s) left via $IFACE outside the tunnel:" >&2
  tcpdump -r "$CAPTURE" -n 2>/dev/null | head -20 >&2
  FAILED=1
fi
if [ "$DOH_COUNT" -ne 0 ]; then
  echo "FAIL: $DOH_COUNT packet(s) to a known public DNS-over-HTTPS resolver" >&2
  echo "      (tcp/443) left via $IFACE outside the tunnel:" >&2
  tcpdump -r "$DOH_CAPTURE" -n 2>/dev/null | head -20 >&2
  FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
  exit 1
fi

echo "PASS: $RESOLVED/${#HOSTS[@]} test hostnames resolved, and zero DNS-shaped" \
  "packets (plain/DoT/known-DoH) were observed on $IFACE during the ${WINDOW}s window"

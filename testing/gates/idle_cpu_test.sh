#!/usr/bin/env bash
# EC5 / spec §13. The falsifiable proof that the poll loop does not busy-wait:
# a spinning loop shows ~100% of a core; a correctly sleeping one shows ~0%.
#
# Usage (tunnel already connected and left idle — no traffic driven through
# it during the sampling window):
#   ./testing/gates/idle_cpu_test.sh <pid-of-liostunnel> [seconds] [threshold-percent]
#
# Example: ./testing/gates/idle_cpu_test.sh "$(pgrep -f 'liostunnel.*connect')" 300
#
# What "PASS" means: the process's reported %CPU, averaged over the whole
# window, stays at or below the threshold (default 2.0% of one core). This is
# deliberately generous — Task 14's own instrumented measurement (see
# README.md / the design spec's EC5 note) found ~2 poll passes per idle
# second and 0.00 user + 0.00 sys CPU time over a 6.67s window, so 2% is a
# ceiling with headroom, not a number tuned to just barely pass.
#
# Caveat this script cannot fully resolve: on Linux, `ps -o %cpu=` reports a
# time-decayed average of CPU usage since the process started, not a strictly
# instantaneous rate — a process that has been running a long time before
# this gate is run could under-report a *recent* regression. For the
# strongest signal, run this against a freshly started `connect` process
# whose only activity before sampling was bringing the tunnel up.
set -euo pipefail

PID="${1:?usage: idle_cpu_test.sh <pid> [seconds] [threshold-percent]}"
DURATION="${2:-300}"
THRESHOLD="${3:-2.0}"
SAMPLE_INTERVAL=5

if ! kill -0 "$PID" 2>/dev/null; then
  echo "FAIL: no process with pid $PID (is the tunnel actually running?)" >&2
  exit 1
fi

# Soft check only — not every platform's `ps` renders args the same way, and
# a mismatch here should not block a legitimate run, only warn.
CMD=$(ps -p "$PID" -o command= 2>/dev/null || ps -p "$PID" -o args= 2>/dev/null || echo "")
case "$CMD" in
  *liostunnel*) ;;
  *)
    echo "WARN: pid $PID's command line ('$CMD') does not look like liostunnel;" >&2
    echo "      continuing anyway, but double check you passed the right pid." >&2
    ;;
esac

if [ "$DURATION" -lt "$SAMPLE_INTERVAL" ]; then
  echo "FAIL: duration (${DURATION}s) is shorter than the ${SAMPLE_INTERVAL}s sample interval" >&2
  exit 1
fi

echo "sampling pid $PID for ${DURATION}s at ${SAMPLE_INTERVAL}s intervals" \
  "(tunnel must be connected and idle — no traffic driven through it)"

SAMPLES=0
TOTAL=0
MAX=0
END=$(($(date +%s) + DURATION))
while [ "$(date +%s)" -lt "$END" ]; do
  CPU=$(ps -p "$PID" -o %cpu= 2>/dev/null | tr -d ' ')
  if [ -z "$CPU" ]; then
    echo "FAIL: process $PID exited during sampling (after $SAMPLES sample(s))" >&2
    exit 1
  fi
  TOTAL=$(awk -v t="$TOTAL" -v c="$CPU" 'BEGIN { printf "%.6f", t + c }')
  MAX=$(awk -v m="$MAX" -v c="$CPU" 'BEGIN { print (c > m) ? c : m }')
  SAMPLES=$((SAMPLES + 1))
  sleep "$SAMPLE_INTERVAL"
done

if [ "$SAMPLES" -eq 0 ]; then
  echo "FAIL: took zero samples — nothing was measured" >&2
  exit 1
fi

AVG=$(awk -v t="$TOTAL" -v n="$SAMPLES" 'BEGIN { printf "%.4f", t / n }')
echo "average CPU over $SAMPLES sample(s): ${AVG}% (peak single sample: ${MAX}%)"

OVER=$(awk -v avg="$AVG" -v thr="$THRESHOLD" 'BEGIN { print (avg > thr) ? 1 : 0 }')
if [ "$OVER" -eq 1 ]; then
  echo "FAIL: ${AVG}% exceeds the ${THRESHOLD}% ceiling — the loop may be spinning" >&2
  exit 1
fi
echo "PASS: idle CPU (${AVG}% avg over ${SAMPLES} samples) is within the ${THRESHOLD}% budget"

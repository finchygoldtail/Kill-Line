#!/usr/bin/env bash
# KillLine overhead benchmark. Run as root on an idle machine:
#   bench/bench.sh [N_OPEN] [N_EXEC]
# Reports per-operation latency for: no monitor; a bystander process while
# KillLine monitors something else; and the monitored process itself.
# Also reports monitor CPU time, peak RSS, events recorded and drops.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
KL="${KILLLINE:-$HERE/../target/release/killline}"
N_OPEN="${1:-100000}"; N_EXEC="${2:-200}"
WORK="$(mktemp -d)"; chmod 777 "$WORK"
export KILLLINE_HOME="$(mktemp -d)"
POL="$KILLLINE_HOME/bench-policy.yaml"
cat >"$POL" <<P
agent: bench
filesystem:
  allow: [$WORK, $HERE]
network: { mode: deny }
processes: { allow: [python3, true] }
anomaly: { enabled: false }
P
run() { python3 "$HERE/workload.py" "$WORK" "$N_OPEN" "$N_EXEC"; }
cpu_of() { awk '{print ($14+$15)/100}' "/proc/$1/stat"; }

echo "== baseline (no monitor)"; run; run

echo "== bystander (KillLine monitoring an idle 'sleep', workload not monitored)"
sleep 300 & SLEEPER=$!
"$KL" --no-color monitor --pid "$SLEEPER" --policy "$POL" >/dev/null 2>&1 & MON=$!
sleep 2; run; kill -INT $MON; wait $MON || true; kill $SLEEPER || true

echo "== monitored (killline run: the workload IS the agent)"
LOG="$KILLLINE_HOME/run.log"
"$KL" --no-color run --policy "$POL" --user 65534 -- python3 "$HERE/workload.py" "$WORK" "$N_OPEN" "$N_EXEC" >"$LOG" 2>&1 &
MON=$!; CPU=0; RSS=0
while kill -0 $MON 2>/dev/null; do
  CPU=$(awk '{print ($14+$15)/100}' /proc/$MON/stat 2>/dev/null || echo "$CPU")
  RSS=$(awk '/VmHWM/{print $2}' /proc/$MON/status 2>/dev/null || echo "$RSS")
  sleep 0.1
done
grep -E "open_read|Events recorded|Dropped events|^Status" "$LOG" || true
echo "monitor cpu_seconds=$CPU peak_rss_kb=$RSS"
rm -rf "$WORK"
echo "(data in $KILLLINE_HOME)"

#!/usr/bin/env bash
# Runs the Kill Line demonstrations against the Docker test lab.
#   sudo test-lab/run-demo.sh 1     # GREEN work, then outbound network attempt
#   sudo test-lab/run-demo.sh 2     # fake credential file access
#   sudo test-lab/run-demo.sh 3     # behavioural shift: AMBER then RED
#   sudo test-lab/run-demo.sh all   # every test-agent mode
# Requires: the lab running (docker compose up -d) and a built killline.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
KL="${KILLLINE:-$HERE/../target/release/killline}"
[ -x "$KL" ] || KL="$HERE/../target/debug/killline"
POLICY="${POLICY:-$HERE/no-network.yaml}"
DEMO="${1:-1}"
LOG="$(mktemp -t killline-demo.XXXXXX)"

agent() { docker exec test-agent python3 /app/test_agent.py "$@" | sed 's/^/    agent| /'; }

"$KL" monitor --container test-agent --policy "$POLICY" >"$LOG" 2>&1 &
MON=$!
trap 'kill -INT $MON 2>/dev/null || true' EXIT
sleep 2
case "$DEMO" in
  1) agent normal; sleep 1; agent network ;;
  2) agent normal; sleep 1; agent sensitive-file ;;
  3) docker exec -e KL_PAUSE=1 test-agent python3 /app/test_agent.py behaviour-shift | sed 's/^/    agent| /' ;;
  all) agent all ;;
  *) echo "unknown demo $DEMO"; exit 2 ;;
esac
sleep 7   # let incident bundles collect post-trigger context
kill -INT $MON; wait $MON || true
trap - EXIT
cat "$LOG"
echo
echo "(monitor output saved in $LOG)"

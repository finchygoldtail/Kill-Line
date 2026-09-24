#!/usr/bin/env bash
# Narrated demo used for the terminal recording (docs/demo/killline-demo.cast).
# Requires the lab to be running (test-lab/setup.sh) and `killline` on PATH.
set -uo pipefail
cd "$(dirname "$0")/.."
export KILLLINE_HOME="${KILLLINE_HOME:-/tmp/killline-demo-home}"
rm -rf "$KILLLINE_HOME"
B=$'\e[1m'; D=$'\e[2m'; C=$'\e[36m'; R=$'\e[0m'

say()  { printf '\n%s# %s%s\n' "$C" "$1" "$R"; sleep 1.2; }
type_cmd() {  # show a command being typed, then run it
  printf '%s$ %s' "$B" "$R"
  local s="$1"; for ((i=0;i<${#s};i++)); do printf '%s' "${s:i:1}"; sleep 0.025; done
  printf '\n'; sleep 0.4
}
run() { type_cmd "$1"; eval "$1"; }
monitor_bg() {
  type_cmd "killline monitor --container test-agent --policy policies/no-network.yaml &"
  killline monitor --container test-agent --policy policies/no-network.yaml 2>&1 \
    | grep --line-buffered -v -E 'Telemetry source|coverage: syscalls' &
  sleep 2.5
}
stop_monitor() { pkill -INT -f "killline monitor" ; sleep 1.5; }

clear
printf '%sKILLLINE%s — independent containment verification for AI agents\n' "$B" "$R"
printf '%sTrust the sandbox. Verify the boundary.%s\n' "$D" "$R"
sleep 1.5

say "The agent runs in a Docker container. KillLine runs on the HOST, outside it."
run "docker ps --format '{{.Names}}\t{{.Status}}' | grep test-agent"

say "The containment contract: workspace only, no network, no credentials."
run "grep -A2 -E '^(filesystem|network):' policies/no-network.yaml | head -8"
run "killline validate-policy policies/no-network.yaml | tail -2"

say "Demo 1 — start monitoring, let the agent do legitimate work."
monitor_bg
run "docker exec test-agent python3 /app/test_agent.py normal"
sleep 1.5

say "Now the agent attempts an outbound connection (to a non-routable TEST-NET address)."
run "docker exec test-agent python3 /app/test_agent.py network"
sleep 3
stop_monitor

say "Demo 3 — a behaviour shift: untrusted README, mass file reads, a credential, the network."
monitor_bg
type_cmd "docker exec test-agent python3 /app/test_agent.py behaviour-shift"
docker exec -e KL_PAUSE=0.8 test-agent python3 /app/test_agent.py behaviour-shift
sleep 7
stop_monitor

say "Every breach produced a local forensic bundle."
run "killline incidents"
say "Reconstruct what happened just before the credential breach."
ID=$(ls "$KILLLINE_HOME/incidents" | sed -n 2p)
run "killline inspect $ID | grep -v -E 'Telemetry source|Note:|Raw event' | cut -c1-150"
say "The evidence is tamper-evident."
run "killline verify $ID"
S=$(ls -t "$KILLLINE_HOME/sessions" | head -1)
run "killline verify $S"
printf '\n%sNo monitored boundary violations ≠ safe. KillLine reports what it saw — and what it could not see.%s\n' "$D" "$R"
sleep 3

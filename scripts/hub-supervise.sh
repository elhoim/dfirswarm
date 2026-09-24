#!/usr/bin/env bash
# The VM hub's keeper, for the length of a microVM run.
#
# The hub is the VMs' board, their trace door and the stop that does not
# depend on them. It used to come back after a crash only when the idle
# watchdog noticed, and a run started with --idle-nudge-sec 0, or one past
# its sentinel, has no watchdog: a dead hub then left the VMs with no board
# and no stop but msb's own time limit. This process waits on the hub and
# brings it back with `--resume` (same tokens, same stop clock; the hub keeps
# them in its own directory) until the run's stop says it is over (a `.stop`
# file in the hub directory) or the run is gone.
#
#   hub-supervise.sh <sandbox> <hub dir> <hub script> <first hub pid>
set -u

SANDBOX="$1"
HUB_DIR="$2"
HUB_SCRIPT="$3"
PID="$4"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# A hub that dies this often in a row is not going to stay up: say so and stop trying.
MAX_RESTARTS="${SWARM_HUB_MAX_RESTARTS:-20}"

over() { [[ -e "$HUB_DIR/.stop" || ! -d "$SANDBOX" || ! -f "$HUB_DIR/hub-input.json" ]]; }

restarts=0
while :; do
  while kill -0 "$PID" 2>/dev/null; do sleep 2; done
  over && exit 0
  restarts=$((restarts + 1))
  if (( restarts > MAX_RESTARTS )); then
    echo "hub-supervise: the hub died ${MAX_RESTARTS} times; not restarting it again" >> "$SANDBOX/traces/vm-hub.log"
    exit 1
  fi
  sleep 2
  over && exit 0
  node --experimental-strip-types --no-warnings "$HUB_SCRIPT" --resume "$HUB_DIR" >>"$SANDBOX/traces/vm-hub.log" 2>&1 </dev/null &
  PID=$!
  echo "$PID" > "$SANDBOX/hub.pid"
  ok=false
  for ((i = 0; i < 100; i++)); do
    [[ -S "$HUB_DIR/admin.sock" ]] && kill -0 "$PID" 2>/dev/null && { ok=true; break; }
    sleep 0.1
  done
  line="$(jq -nc --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg d "$HUB_DIR" --argjson ok "$ok" --argjson n "$restarts" \
    '{ts: $ts, agent: "system", tool: "hub_restarted", args: {dir: $d, by: "hub-supervise", restart: $n}, result: {ok: $ok}}')"
  printf '%s' "$line" | node "$ROOT/scripts/trace-emit.mjs" "$SANDBOX" >/dev/null 2>&1 || printf '%s\n' "$line" >> "$HUB_DIR/hub-spill.jsonl"
done

#!/usr/bin/env bash
# Observer: tail the mailbox, locks, and sentinel. The file is the clock.
# Chat "we're done" is not.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SANDBOX="${SWARM_SANDBOX:-$ROOT/sandbox}"
INTERVAL="${WATCH_INTERVAL:-2}"
ONCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --once) ONCE=1; shift ;;
    --sandbox) SANDBOX="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

snapshot() {
  echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) cwd=$SANDBOX ==="
  echo "DONE"
  if [[ -e "$SANDBOX/done/SWARM_DONE" ]]; then
    echo "SWARM_DONE present — stop spending"
    sed -n '1,12p' "$SANDBOX/done/SWARM_DONE" || true
  else
    echo "(no SWARM_DONE)"
  fi
  echo
  echo "AGENT DONE"
  ls -1 "$SANDBOX/done/agents" 2>/dev/null || true
  echo
  echo "STALL / REAP"
  shopt -s nullglob
  deads=("$SANDBOX"/done/agents/*.dead)
  if [[ ${#deads[@]} -eq 0 ]]; then
    echo "(no .dead files)"
  else
    for f in "${deads[@]}"; do
      echo "? $(basename "$f")"
    done
  fi
  shopt -u nullglob
  echo
  echo "LOCKS"
  shopt -s nullglob
  locks=("$SANDBOX"/locks/*.json)
  if [[ ${#locks[@]} -eq 0 ]]; then
    echo "(none)"
  else
    for f in "${locks[@]}"; do
      echo "-- $(basename "$f")"
      cat "$f"
    done
  fi
  shopt -u nullglob
  echo
  echo "MAIN"
  post_n="$(ls -1 "$SANDBOX/threads/main" 2>/dev/null | wc -l | tr -d ' ')"
  echo "posts=${post_n:-0}"
  ls -1 "$SANDBOX/threads/main" 2>/dev/null | tail -n 40
  echo
  echo "WORK"
  if [[ -f "$SANDBOX/work/hello.txt" ]]; then
    cat "$SANDBOX/work/hello.txt"
  else
    echo "(no work/hello.txt)"
  fi
  echo
  echo "BUDGET"
  if [[ -f "$SANDBOX/budget.json" ]]; then
    jq -c '{spent_usd, tokens, calls, cap_usd, agents:(.agents|length)}' "$SANDBOX/budget.json" 2>/dev/null || cat "$SANDBOX/budget.json"
  else
    echo "(no budget.json)"
  fi
  echo
  echo "EVENTS"
  if [[ -f "$SANDBOX/traces/events.jsonl" && -s "$SANDBOX/traces/events.jsonl" ]]; then
    tail -n 16 "$SANDBOX/traces/events.jsonl" | jq -r '
      [
        .ts,
        .agent,
        .tool,
        ((.args // {}) | to_entries | map("\(.key)=\(.value)") | join(" ")),
        ((.result // {}) | to_entries | map("\(.key)=\(.value)") | join(" "))
      ] | join("  ")
    ' 2>/dev/null || tail -n 16 "$SANDBOX/traces/events.jsonl"
  else
    echo "(no traces/events.jsonl)"
  fi
  echo
  if command -v herdr >/dev/null 2>&1; then
    echo "HERDR"
    herdr agent list 2>/dev/null | jq -r '
      (.result.agents // []) as $a
      | "agents=\($a|length)  " +
        ([($a | group_by(.agent_status)[] | "\(.[0].agent_status)=\(length)")] | join(" "))
      , ($a | .[:40][] | "\(.name // "?")\t\(.agent_status // "?")\t\(.pane_id // "-")")
    ' 2>/dev/null || herdr agent list 2>/dev/null | head -c 4000 || true
  fi
  if [[ -e "$SANDBOX/done/SWARM_DONE" ]]; then
    return 0
  fi
  return 1
}

if [[ "$ONCE" -eq 1 ]]; then
  snapshot || true
  exit 0
fi

if command -v watch >/dev/null 2>&1; then
  exec watch -n "$INTERVAL" "$0" --once --sandbox "$SANDBOX"
fi

echo "watch(1) not found; polling every ${INTERVAL}s. Ctrl-C to stop."
while true; do
  snapshot || true
  echo
  sleep "$INTERVAL"
done

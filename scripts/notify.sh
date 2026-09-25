#!/usr/bin/env bash
# notify: tell the operator's own command that something happened to a run.
#
# `swarm.sh start --notify CMD` keeps CMD outside the run, in
# $SWARM_RUNS_DIR/notify/<run id>.cmd (0600): a webhook's URL is often its
# secret, and nothing an agent can write may name what the host runs. This
# script finds the run by its sandbox in the registry, never by anything in
# the sandbox, and runs CMD detached with one JSON line on its stdin:
#
#   {"event": "...", "run": "<id>", "at": "<UTC>", "detail": {...}}
#
# Events: finished, finish_failed, stop_incomplete, budget_cap, wall_clock,
# evidence_changed, chain_broken, agent_dead, collector_unreachable,
# hub_down. CMD gets 30 seconds. What it
# said on failure goes to <sandbox>/traces/notify.log. This script never
# blocks its caller and never fails it: a notification is a courtesy, not a
# step of the run.
#
# Usage: notify.sh <sandbox> <event> [<detail json>]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SANDBOX="${1:-}"
EVENT="${2:-}"
DETAIL="${3:-}"
[[ -n "$DETAIL" ]] || DETAIL='{}'
[[ -n "$SANDBOX" && -n "$EVENT" && -d "$SANDBOX" ]] || exit 0
RUNS_DIR="${SWARM_RUNS_DIR:-$ROOT/runs}"
REGISTRY="$RUNS_DIR/registry.json"
[[ -f "$REGISTRY" ]] || exit 0
command -v jq >/dev/null 2>&1 || exit 0

sandbox_real="$(cd "$SANDBOX" && pwd -P)"
# The run whose sandbox this is, by the resolved path (a record may name it
# through a link); the latest such record wins.
run="" r_id="" r_sb=""
while IFS=$'\t' read -r r_id r_sb; do
  [[ -n "$r_id" && -n "$r_sb" ]] || continue
  if [[ "$r_sb" == "$SANDBOX" || "$r_sb" == "$sandbox_real" ]] || { [[ -d "$r_sb" ]] && [[ "$(cd "$r_sb" && pwd -P)" == "$sandbox_real" ]]; }; then
    run="$r_id"
  fi
done < <(jq -r '.runs[]? | [.id, (.sandbox // "")] | @tsv' "$REGISTRY" 2>/dev/null)
[[ -n "$run" && "$run" =~ ^[A-Za-z0-9_-]+$ ]] || exit 0
cmd_file="$RUNS_DIR/notify/$run.cmd"
# Only a regular file the operator's own kickoff wrote.
[[ -f "$cmd_file" && ! -L "$cmd_file" && -O "$cmd_file" ]] || exit 0
cmd="$(cat "$cmd_file" 2>/dev/null || true)"
[[ -n "$cmd" ]] || exit 0

jq -e . >/dev/null 2>&1 <<<"$DETAIL" || DETAIL="$(jq -nc --arg d "$DETAIL" '{text: $d}')"
line="$(jq -nc --arg e "$EVENT" --arg r "$run" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson d "$DETAIL" \
  '{event: $e, run: $r, at: $at, detail: $d}')" || exit 0
log="$sandbox_real/traces/notify.log"
# 30 seconds; a test sets less.
LIMIT="${SWARM_NOTIFY_TIMEOUT:-30}"
[[ "$LIMIT" =~ ^[1-9][0-9]*$ ]] || LIMIT=30
[[ -d "$sandbox_real/traces" ]] || log=/dev/null

# Detached: its own session where setsid exists, so a caller that exits (a
# stop, the watchdog's loop) does not take it along; stdin is the line, and
# nothing of the caller's terminal.
runner() {
  local out rc=0
  out="$(mktemp "${TMPDIR:-/tmp}/dfs-notify.XXXXXX")"
  printf '%s\n' "$line" | bash -c "$cmd" >"$out" 2>&1 &
  local pid=$! waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if [[ "$waited" -ge "$LIMIT" ]]; then
      kill -TERM "$pid" 2>/dev/null || true
      sleep 1
      kill -KILL "$pid" 2>/dev/null || true
      rc=124
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done
  [[ "$rc" -eq 124 ]] || { wait "$pid"; rc=$?; }
  if [[ "$rc" -ne 0 ]]; then
    {
      printf '%s %s: the notify command %s (exit %s)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$EVENT" "$([[ "$rc" -eq 124 ]] && echo "took more than $LIMIT seconds and was stopped" || echo failed)" "$rc"
      sed 's/^/  /' "$out"
    } >>"$log" 2>/dev/null
  fi
  rm -f "$out"
}
if command -v setsid >/dev/null 2>&1; then
  export -f runner
  export line cmd log EVENT LIMIT
  setsid bash -c runner </dev/null >/dev/null 2>&1 &
else
  runner </dev/null >/dev/null 2>&1 &
fi
exit 0

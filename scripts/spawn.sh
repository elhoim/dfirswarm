#!/usr/bin/env bash
# Thin wrapper around scripts/swarm.sh start.
# Keeps the old flags. Unique sandbox + agent prefix come from swarm.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
N="${SWARM_N:-2}"
SWARM_MODEL="${SWARM_MODEL:-}"
SANDBOX="${SWARM_SANDBOX:-}"
SWARM_LABEL="${SWARM_LABEL:-}"
DRY_RUN=0
START_AGENTS=1
CAP_USD="${SWARM_CAP_USD:-3}"
GOAL="${SWARM_GOAL:-}"
GOAL_FILE="${SWARM_GOAL_FILE:-}"

usage() {
  cat <<EOF
Usage: scripts/spawn.sh [--dry-run] [--no-start] [--sandbox DIR] [--n 1-30] [--model provider/id] [--label NAME]

  --dry-run    Run the fixture test (mailbox, lock, sentinel, events, budget). No model.
  Other flags  Forwarded to scripts/swarm.sh start (unique id prefix, no agent_name_taken).

Env: SWARM_N, SWARM_MODEL, SWARM_SANDBOX, SWARM_LABEL, SWARM_CAP_USD,
     SWARM_GOAL_FILE / SWARM_GOAL (a goal document with a definition of done)
The provider key comes from Pi's own store; see swarm.sh --key-from-env.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --no-start) START_AGENTS=0; shift ;;
    --sandbox) SANDBOX="$2"; shift 2 ;;
    --n) N="$2"; shift 2 ;;
    --model) SWARM_MODEL="$2"; shift 2 ;;
    --label) SWARM_LABEL="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ "$DRY_RUN" -eq 1 ]]; then
  exec node --experimental-strip-types --test "$ROOT/tests/dry-run.test.ts"
fi

args=(start --n "$N" --cap-usd "$CAP_USD")
# Both are optional: swarm.sh falls back to prompts/goals/hello.md, and it is
# the one place that decides what a valid goal document looks like.
if [[ -n "$GOAL_FILE" ]]; then
  args+=(--goal-file "$GOAL_FILE")
elif [[ -n "$GOAL" ]]; then
  args+=(--goal "$GOAL")
fi
if [[ -n "$SWARM_MODEL" ]]; then
  args+=(--model "$SWARM_MODEL")
elif [[ "$START_AGENTS" -eq 1 ]]; then
  echo "spawn.sh now needs --model provider/id (or SWARM_MODEL)." >&2
  exit 2
fi
if [[ -n "$SANDBOX" ]]; then
  args+=(--sandbox "$SANDBOX")
fi
if [[ -n "$SWARM_LABEL" ]]; then
  args+=(--label "$SWARM_LABEL")
fi
if [[ "$START_AGENTS" -eq 0 ]]; then
  args+=(--no-start)
fi

exec bash "$ROOT/scripts/swarm.sh" "${args[@]}"

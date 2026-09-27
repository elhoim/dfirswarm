#!/usr/bin/env bash
# What the hardware tests share: the opt-in gate, a temporary signers' home
# and runs directory (never the real ~/.dfirswarm), a stopped fixture run,
# and plain prompts for the person at the keyboard. Sourced, not run.
set -euo pipefail

if [[ "${DFIRSWARM_HW_TESTS:-}" != 1 ]]; then
  echo "skipped: the hardware tests touch a real FIDO key or e-signature token; run them with DFIRSWARM_HW_TESTS=1 (tests/hw/README.md)"
  exit 0
fi
[[ -t 0 ]] || { echo "the hardware tests ask on the terminal: run them from one" >&2; exit 2; }

HW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HW_TMP="$(mktemp -d "${TMPDIR:-/tmp}/dfs-hw.XXXXXX")"
HW_RUN_BASE=""
cleanup() {
  chmod -R u+w "$HW_TMP" ${HW_RUN_BASE:+"$HW_RUN_BASE"} 2>/dev/null
  rm -rf "$HW_TMP" ${HW_RUN_BASE:+"$HW_RUN_BASE"}
}
trap cleanup EXIT

node_ts() { node --experimental-strip-types --no-warnings "$@"; }
say() { printf '\n>> %s\n' "$*"; }
ok() { printf 'ok - %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# A stopped run with its dispositions made, and a signers' home of its own.
hw_run() { # <run id> <examiner name> <examiner id>
  local j
  j="$(node_ts "$HW_ROOT/tests/hw/fixture.ts" "$1" "$2" "$3")"
  RUNS="$(jq -r .runs <<<"$j")"
  SANDBOX="$(jq -r .root <<<"$j")"
  RUN_ID="$(jq -r .id <<<"$j")"
  HW_RUN_BASE="$(dirname "$RUNS")"
  export SWARM_SIGNERS_HOME="$HW_TMP/signers" DFIRSWARM_HOME="$HW_TMP/signers" SWARM_RUNS_DIR="$RUNS"
  mkdir -p "$SWARM_SIGNERS_HOME"
}

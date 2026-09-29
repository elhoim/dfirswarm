#!/usr/bin/env bash
# swarm.sh metrics <id> [--json] and metrics --compare <id-A> <id-B>: a run
# found by its id in the registry, its metrics read from its own registers
# (scripts/metrics.ts; tests/metrics.test.ts checks each figure), nothing
# written into it; an unknown id and a wrong number of ids are refused.
set -uo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/metrics-cli.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
export SWARM_RUNS_DIR="$TMP/runs"
mkdir -p "$SWARM_RUNS_DIR"
swarm() { bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
sandbox_of() { printf '%s\n' "$1" | sed -n 's/^SANDBOX=//p' | tail -1; }
id_of() { printf '%s\n' "$1" | sed -n 's/^Swarm id: *//p' | tail -1; }

cat > "$TMP/goal.md" <<'GOAL'
## Goal

Examine the archive.

### Questions

1. Which account created the archive?
2. Was it opened on another machine?

## Definition of done

Every question answered in the ledger.

## Checks

- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,summary,narrative`
GOAL
out="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/goal.md" --label metrics-a)"
A="$(id_of "$out")"; SA="$(sandbox_of "$out")"
out="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/goal.md" --label metrics-b)"
B="$(id_of "$out")"
[[ -n "$A" && -n "$B" && -d "$SA" ]] || fail "no runs: $out"
# One answer in run A, so the two runs differ on a question.
mkdir -p "$SA/ledger"
printf '%s\n' '{"v":4,"seq":1,"kind":"answer","section":"question:1","result":"bounded_negative","value":"v","source":"s","evidence":"e","by":"a1","authors":["a1"],"at":"2026-09-28T10:00:00.000Z"}' >> "$SA/ledger/entries.jsonl"
before="$(find "$SA" -type f -print0 | sort -z | xargs -0 shasum 2>/dev/null | shasum)"

table="$(swarm metrics "$A")" || fail "metrics failed: $table"
grep -q "^Metrics: run " <<<"$table" || fail "no table: $table"
grep -q "Questions in scope: 2 (from the register)" <<<"$table" || fail "the goal's two questions are not in scope: $table"
grep -q "Unreviewed negatives *1 material (Q-1 E-1)" <<<"$table" || fail "the unreviewed negative is not named: $table"
pass "metrics <id> prints the table"

json="$(swarm metrics "$A" --json)" || fail "metrics --json failed: $json"
[[ "$(jq -r '.format' <<<"$json")" == "dfirswarm-metrics/1" ]] || fail "not the metrics JSON: $json"
[[ "$(jq -r '.negatives.unreviewed_material[0].id' <<<"$json")" == "Q-1" ]] || fail "the JSON does not name Q-1: $json"
pass "metrics <id> --json"

cmp="$(swarm metrics --compare "$A" "$B" --json)" || fail "compare failed: $cmp"
[[ "$(jq -r '.summary.one_sided' <<<"$cmp")" == 1 && "$(jq -r '.same_questions' <<<"$cmp")" == true ]] || fail "the comparison is wrong: $cmp"
grep -q "Agreement is not confirmation" <<<"$(swarm metrics --compare "$A" "$B")" || fail "the comparison's table does not say it"
pass "metrics --compare <id-A> <id-B>"

after="$(find "$SA" -type f -print0 | sort -z | xargs -0 shasum 2>/dev/null | shasum)"
[[ "$before" == "$after" ]] || fail "metrics wrote into the run"
pass "nothing is written into a run"

swarm metrics nosuchrun >/dev/null; [[ $? -eq 1 ]] || fail "an unknown id is not refused with 1"
swarm metrics >/dev/null; [[ $? -eq 2 ]] || fail "no id is not a usage error"
swarm metrics --compare "$A" >/dev/null; [[ $? -eq 2 ]] || fail "--compare with one id is not a usage error"
swarm metrics "$A" --nope >/dev/null; [[ $? -eq 2 ]] || fail "an unknown option is not a usage error"
pass "refusals"

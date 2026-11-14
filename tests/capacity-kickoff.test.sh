#!/usr/bin/env bash
# What the other microVM runs on this host may ask for (swarm.sh
# other_runs_load, the arguments of `vm.ts capacity`), read from the registry
# and the starts' claims: a run whose hub lives; a run still in its kickoff
# (the catalogue, the image pull: no hub yet), known by its launcher in its
# record; a start that has no record yet, by its claim (in the temporary area,
# so a refused start leaves nothing under runs/).
# Three starts launched together each count the ones before them. A launcher
# that ended, or a pid now another process's, counts nothing. No VM.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/capacity-kickoff.XXXXXX")"
PIDS=()
trap 'for p in ${PIDS[@]+"${PIDS[@]}"}; do { kill "$p"; wait "$p"; } >/dev/null 2>&1 || true; done; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
export TMPDIR="$TMP/tmp"; mkdir -p "$TMPDIR"
eval "$(sed -n '/^proc_started()/p; /^kickoffs_dir()/p; /^launcher_alive()/,/^}/p; /^kickoff_claim()/,/^}/p; /^other_runs_load()/,/^}/p' "$ROOT/scripts/swarm.sh")"
declare -F other_runs_load kickoff_claim launcher_alive proc_started kickoffs_dir >/dev/null || fail "the functions were not found in swarm.sh"

RUNS_DIR="$TMP/runs"; REGISTRY="$RUNS_DIR/registry.json"; mkdir -p "$RUNS_DIR"
# A process that lives (its output away from any command substitution) or one that has ended, by its pid in LAST.
live() { sleep 300 >/dev/null 2>&1 </dev/null & LAST=$!; PIDS+=("$LAST"); }
dead() { true >/dev/null 2>&1 & LAST=$!; wait "$LAST" || true; }
live; hub="$LAST"; live; k1="$LAST"; live; k2="$LAST"; dead; gone="$LAST"; live; other="$LAST"
mkdir -p "$TMP/sa" "$TMP/sb" "$TMP/sc" "$TMP/sd" "$TMP/se" "$TMP/sf"
echo "$hub" > "$TMP/sa/hub.pid"
echo "$gone" > "$TMP/se/hub.pid"
vm() { jq -nc --arg id "$1" --arg sb "$2" --arg st "$3" --argjson n "$4" --arg kp "${5:-}" --arg ks "${6:-}" \
  '{id: $id, sandbox: $sb, state: $st, n: $n, isolation: {mode: "microvm", cpus: 2, memory_mib: 4096, jobs: {workers: 2, cpus: 2, memory_mib: 8192}}}
   + (if $kp == "" then {} else {kickoff: {pid: ($kp | tonumber), started: $ks}} end)'; }
jq -n --argjson a "$(vm sa "$TMP/sa" running 2)" \
  --argjson b "$(vm sb "$TMP/sb" prepared 3 "$k1" "$(proc_started "$k1")")" \
  --argjson c "$(vm sc "$TMP/sc" prepared 1 "$gone" "Thu Jan  1 00:00:00 2026")" \
  --argjson d "$(vm sd "$TMP/sd" prepared 1 "$other" "Thu Jan  1 00:00:00 2026")" \
  --argjson e "$(vm se "$TMP/se" running 4)" \
  --argjson f "$(vm sf "$TMP/sf" stopped 4 "$k2" "$(proc_started "$k2")")" \
  '{runs: [$a, $b, $c, $d, $e, $f]}' > "$REGISTRY"

# a: hub alive, 2 x 4096 + 2 x 8192 MiB, 2 x 2 + 2 x 2 vCPU. b: in its kickoff, 3 x 4096 + 16384, 6 + 4.
# c: its launcher ended; d: its pid is another process now; e: running, its hub dead; f: stopped.
out="$(other_runs_load "")"
[[ "$out" == "--others-memory $(( 2*4096 + 16384 + 3*4096 + 16384 )) --others-cpus $(( 4 + 4 + 6 + 4 )) --others-runs 2" ]] || fail "a run with a hub and one in its kickoff: $out"
other_runs_load "" >/dev/null
[[ "$OTHER_RUNS_KICKING" -eq 1 ]] || fail "the run in its kickoff is not said to be: $OTHER_RUNS_KICKING"
out="$(other_runs_load sb)"
[[ "$out" == "--others-memory $(( 2*4096 + 16384 )) --others-cpus 8 --others-runs 1" ]] || fail "a run is counted beside itself: $out"
pass "the registry: a run whose hub lives and a run still in its kickoff are counted; an ended launcher, a reused pid, a dead hub and a stopped run are not"

# Starts with no record yet: their claims. A claim of a launcher already in a record is not counted twice.
KD="$(kickoffs_dir)"; mkdir -p "$KD"
claim() { # <pid> <seats> <workers>
  jq -n --argjson pid "$1" --arg st "$(proc_started "$1")" --argjson n "$2" --argjson w "$3" \
    '{pid: $pid, started: $st, seats: $n, workers: $w, memory_mib: ($n * 4096 + $w * 8192), cpus: ($n * 2 + $w * 2)}' > "$KD/$1.json"
}
live; s1="$LAST"
claim "$s1" 2 2
claim "$k1" 3 2
claim "$gone" 9 9
printf '{"pid": %s, "started": "Thu Jan  1 00:00:00 2026", "memory_mib": 99999, "cpus": 99}\n' "$other" > "$KD/$other.json"
out="$(other_runs_load "")"
[[ "$out" == "--others-memory $(( 2*4096 + 16384 + 3*4096 + 16384 + 2*4096 + 16384 )) --others-cpus $(( 8 + 10 + 8 )) --others-runs 3" ]] || fail "the claims: $out"
other_runs_load "" >/dev/null
[[ "$OTHER_RUNS_KICKING" -eq 2 ]] || fail "two runs are in their kickoff, said $OTHER_RUNS_KICKING"
[[ ! -e "$KD/$gone.json" ]] || fail "an ended launcher's claim was left"
[[ ! -e "$KD/$other.json" ]] || fail "a claim whose pid is another process now was left"
pass "a start with no record yet counts by its claim; one already in the registry counts once; an ended or reused one's claim is removed"

# Three starts launched together: each writes its claim before it asks, so the second counts the first and the third both.
rm -rf "$RUNS_DIR" "$KD"; mkdir -p "$RUNS_DIR"; echo '{"runs": []}' > "$REGISTRY"
# Each stands in for a launcher: it claims, counts the others, says what it counted, and stays (as a kickoff does).
for i in 1 2 3; do
  bash -c '
    eval "$(sed -n "/^proc_started()/p; /^kickoffs_dir()/p; /^launcher_alive()/,/^}/p; /^kickoff_claim()/,/^}/p; /^other_runs_load()/,/^}/p" "$1/scripts/swarm.sh")"
    RUNS_DIR="$2"; REGISTRY="$2/registry.json"
    kickoff_claim 2 2 4096 2 2 8192
    other_runs_load "" > "$3"
    exec sleep 300' _ "$ROOT" "$RUNS_DIR" "$TMP/start$i.out" >/dev/null 2>&1 </dev/null &
  PIDS+=("$!")
  for _ in $(seq 1 50); do [[ -s "$TMP/start$i.out" || ( "$i" -eq 1 && -e "$TMP/start$i.out" ) ]] && break; sleep 0.1; done
done
[[ "$(ls "$KD" | grep -c '\.json$')" -eq 3 ]] || fail "three starts left $(ls "$KD") claims"
[[ -z "$(ls -A "$RUNS_DIR" | grep -v '^registry.json$')" ]] || fail "a claim was written under the runs directory: $(ls -A "$RUNS_DIR")"
[[ "$(cat "$TMP/start2.out")" == "--others-memory $(( 2*4096 + 2*8192 )) --others-cpus 8 --others-runs 1" ]] || fail "the second start did not count the first: $(cat "$TMP/start2.out")"
[[ "$(cat "$TMP/start3.out")" == "--others-memory $(( 2 * (2*4096 + 2*8192) )) --others-cpus 16 --others-runs 2" ]] || fail "the third start did not count both: $(cat "$TMP/start3.out")"
out="$(other_runs_load "")"
[[ "$out" == "--others-memory $(( 3 * (2*4096 + 2*8192) )) --others-cpus $(( 3 * 8 )) --others-runs 3" ]] || fail "three starts in their kickoff: $out"
pass "three starts launched together: the second counts the first, the third both, while none has a record or a hub"

# The kickoff writes its launcher into the run's record, and claims before it asks vm.ts capacity.
grep -q 'kickoff: {pid: \$kickoff_pid, started: \$kickoff_started}' "$ROOT/scripts/swarm.sh" || fail "the run's record does not name its launcher"
body="$(sed -n '/This start.s own claim first/,/vm_cli capacity --n/p' "$ROOT/scripts/swarm.sh")"
grep -q 'kickoff_claim "\$n"' <<<"$body" && grep -q 'other_runs_load' <<<"$body" || fail "the start does not claim before it counts the others: $body"
pass "a start names its launcher in its record and claims before it counts the others"

#!/usr/bin/env bash
# The pause for the model provider's limit, from the watchdog's side, and the
# operator's pause and unpause from the command line (docs/adr/0013). A run
# whose every seat was refused on a stated wait of days is paused by the
# watchdog, said once on the board and once to the operator's notify command,
# and nobody is nudged; at the named end the harness lifts it and wakes every
# seat with words that say so. swarm.sh pause holds a run and unpause lifts
# it, both on the operator's record; unpause refuses a cap's pause still over
# its cap. No model, no VM; Herdr is a stand-in that records what it is told.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/provider-pause.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
HELLO="$ROOT/prompts/goals/hello.md"
export SWARM_RUNS_DIR="$TMP/runs"
kick() { bash "$ROOT/scripts/swarm.sh" start --model solo/model --n 2 --no-start --goal-file "$HELLO" --toolbox off "$@" 2>&1; }
sandbox_of() { jq -r --arg l "$1" '.runs[] | select(.label == $l) | .sandbox' "$TMP/runs/registry.json"; }
id_of() { jq -r --arg l "$1" '.runs[] | select(.label == $l) | .id' "$TMP/runs/registry.json"; }
running() { local tmp; tmp="$(mktemp)"; jq --arg id "$1" '(.runs[] | select(.id == $id) | .state) = "running"' "$TMP/runs/registry.json" > "$tmp" && mv "$tmp" "$TMP/runs/registry.json"; }
budget_set() { local tmp; tmp="$(mktemp)"; jq "$2" "$1/budget.json" > "$tmp" && mv "$tmp" "$1/budget.json"; }
iso_ago() { date -u -d "@$(( $(date +%s) - $1 ))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r $(( $(date +%s) - $1 )) +%Y-%m-%dT%H:%M:%SZ; }

out="$(kick --until-solved --label u1)" || fail "an until-solved kickoff was refused: $out"
SB="$(sandbox_of u1)"
ID="$(id_of u1)"
running "$ID"
ids="$(jq -r '.agents[].id' "$SB/team.json" | tr '\n' ' ')"
mkdir -p "$TMP/runs/notify"
printf 'cat >> %q\n' "$TMP/notified.jsonl" > "$TMP/runs/notify/$ID.cmd"
chmod 600 "$TMP/runs/notify/$ID.cmd"
: > "$TMP/notified.jsonl"

mkdir -p "$TMP/bin"
cat > "$TMP/bin/herdr" <<'SH'
#!/usr/bin/env bash
case "$1 $2" in
  "agent get") printf '{"result":{"agent":{"agent_status":"idle"}}}\n' ;;
  "agent prompt") printf '%s\t%s\n' "$3" "$4" >> "$PROMPT_LOG" ;;
  *) : ;;
esac
SH
chmod +x "$TMP/bin/herdr"
export PROMPT_LOG="$TMP/prompts.txt"
: > "$PROMPT_LOG"
old="$(date -v-900S +%Y%m%d%H%M.%S 2>/dev/null || date -d '900 seconds ago' +%Y%m%d%H%M.%S)"
for a in $ids; do
  mkdir -p "$SB/.pi-sessions/$a"
  : > "$SB/.pi-sessions/$a/s.jsonl"
  touch -t "$old" "$SB/.pi-sessions/$a/s.jsonl"
done
watch_once() { HERDR_BIN="$TMP/bin/herdr" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$SB" --once --idle-sec 60 >>"$TMP/watch.log" 2>&1 || true; }

echo "# the watchdog: every seat refused on a stated wait of days"
t="$(iso_ago 60)"
for a in $ids; do
  printf '{"ts":"%s","recv_ts":"%s","agent":"%s","tool":"bash","args":{},"result":{"ok":true}}\n' "$(iso_ago 900)" "$(iso_ago 900)" "$a" >> "$SB/traces/events.jsonl"
  printf '{"ts":"%s","recv_ts":"%s","agent":"%s","tool":"agent_error","args":{"model":"openai-codex/gpt-6-sol"},"result":{"ok":false,"reason":"You have hit your ChatGPT usage limit (pro plan). Try again in ~6904 min."}}\n' "$t" "$t" "$a" >> "$SB/traces/events.jsonl"
done
watch_once
jq -e '.paused.reason == "provider_limit" and .paused.by == "harness" and (.paused.until | type) == "string" and .paused.models == ["openai-codex/gpt-6-sol"]' "$SB/budget.json" >/dev/null \
  || fail "the run was not paused for the provider's limit: $(jq -c '.paused' "$SB/budget.json"); $(cat "$TMP/watch.log")"
grep -q '"tool":"run_paused".*"reason":"provider_limit"' "$SB/traces/events.jsonl" || fail "the pause is not on the trace"
[[ ! -s "$PROMPT_LOG" ]] || fail "a seat was prompted while the run is paused: $(cat "$PROMPT_LOG")"
grep -rq 'The run is paused: the model provider refused every live seat' "$SB/threads/main/" || fail "the pause is not on the board"
for _ in $(seq 1 40); do grep -q '"event":"paused"' "$TMP/notified.jsonl" && break; sleep 0.25; done
jq -e 'select(.event == "paused") | .detail.reason == "provider_limit" and (.detail.until | type) == "string"' "$TMP/notified.jsonl" >/dev/null \
  || fail "the operator was not told of the provider's limit and its end: $(cat "$TMP/notified.jsonl")"
watch_once
sleep 1
[[ "$(grep -c '"event":"paused"' "$TMP/notified.jsonl")" -eq 1 ]] || fail "the pause was told more than once: $(cat "$TMP/notified.jsonl")"
[[ "$(grep -rl 'The run is paused: the model provider refused' "$SB/threads/main/" | wc -l | tr -d ' ')" -eq 1 ]] || fail "the pause was said on the board more than once"
[[ ! -s "$PROMPT_LOG" ]] || fail "a seat was prompted on the second pass: $(cat "$PROMPT_LOG")"
pass "every seat refused on a stated wait of days: the run pauses under --stop operator, said once on the board and once to the operator, and nobody is nudged"

echo "# the harness's try at the named end"
budget_set "$SB" ".paused.until = \"$(iso_ago 120)\""
watch_once
jq -e '(has("paused") | not) and (.pauses | last | .reason == "provider_limit" and .resumed_by == "harness")' "$SB/budget.json" >/dev/null \
  || fail "the pause was not lifted at its end: $(jq -c '{paused, pauses}' "$SB/budget.json")"
grep -q '"tool":"run_unpaused".*"by":"harness"' "$SB/traces/events.jsonl" || fail "the lift is not on the trace"
for a in $ids; do
  grep -q "^$a	The harness lifted the pause for the model provider's limit at .*, to try again" "$PROMPT_LOG" || fail "$a was not woken after the harness's lift: $(cat "$PROMPT_LOG")"
done
[[ "$(grep -c 'The harness lifted the pause' "$PROMPT_LOG")" -eq "$(wc -w <<<"$ids" | tr -d ' ')" ]] || fail "a seat was woken more than once: $(cat "$PROMPT_LOG")"
if grep -q 'Your last turn ended in a provider error' "$PROMPT_LOG"; then fail "a seat woken by the lift was also nudged for its error in the same pass: $(cat "$PROMPT_LOG")"; fi
pass "at the named end the harness lifts the pause, on the trace, and wakes each seat once with words that say so"

echo "# swarm.sh pause and unpause"
: > "$PROMPT_LOG"
out="$(bash "$ROOT/scripts/swarm.sh" pause "$ID" --why "a disk to swap" 2>&1)" || fail "pause was refused: $out"
grep -q "Paused $ID since" <<<"$out" || fail "pause does not say so: $out"
jq -e '.paused.reason == "operator" and .paused.by == "operator" and .paused.detail == "a disk to swap"' "$SB/budget.json" >/dev/null || fail "the hold is not recorded: $(jq -c '.paused' "$SB/budget.json")"
grep -q '"command":"pause"' "$TMP/runs/operator-audit.jsonl" || fail "the pause is not on the operator's record"
grep -rq 'The operator paused the run: a disk to swap' "$SB/threads/main/" || fail "the pause is not on the board"
set +e
out="$(bash "$ROOT/scripts/swarm.sh" pause "$ID" 2>&1)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'paused already' <<<"$out" || fail "a second pause was not refused (rc $rc): $out"
watch_once
[[ ! -s "$PROMPT_LOG" ]] || fail "a held run's seat was prompted: $(cat "$PROMPT_LOG")"
out="$(bash "$ROOT/scripts/swarm.sh" unpause "$ID" 2>&1)" || fail "unpause was refused: $out"
grep -q 'The operator lifted the pause (operator)' <<<"$out" || fail "unpause does not say so: $out"
jq -e '(has("paused") | not) and (.pauses | last | .reason == "operator" and .resumed_by == "operator")' "$SB/budget.json" >/dev/null || fail "the hold was not lifted"
grep -q '"command":"unpause"' "$TMP/runs/operator-audit.jsonl" || fail "the unpause is not on the operator's record"
watch_once
for a in $ids; do
  grep -q "^$a	The operator lifted the pause for the operator's hold at " "$PROMPT_LOG" || fail "$a was not woken after unpause: $(cat "$PROMPT_LOG")"
done
set +e
out="$(bash "$ROOT/scripts/swarm.sh" unpause "$ID" 2>&1)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'the run is not paused' <<<"$out" || fail "unpause of a going run was not refused (rc $rc): $out"
pass "pause holds a run and unpause lifts it, on the board, the trace and the operator's record; the seats are woken once"

echo "# unpause refuses a cap's pause still over its cap"
out="$(kick --cap-usd 5 --label c1)" || fail "a cap-pause kickoff was refused: $out"
SC="$(sandbox_of c1)"
IC="$(id_of c1)"
running "$IC"
budget_set "$SC" ".tokens = 100000500 | .paused = {at: \"$(iso_ago 30)\", reason: \"cap\", detail: \"the token cap passed\"}"
before="$(shasum -a 256 "$SC/budget.json" 2>/dev/null || sha256sum "$SC/budget.json")"
set +e
out="$(bash "$ROOT/scripts/swarm.sh" unpause "$IC" 2>&1)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q "still over the token cap .*swarm.sh extend $IC gives it room" <<<"$out" || fail "unpause of a cap's pause still over it was not refused (rc $rc): $out"
[[ "$(shasum -a 256 "$SC/budget.json" 2>/dev/null || sha256sum "$SC/budget.json")" == "$before" ]] || fail "a refused unpause changed the budget"
bash "$ROOT/scripts/swarm.sh" help | grep -q 'pause|unpause <id> holds it and lifts a pause' || fail "help does not list pause and unpause"
bash "$ROOT/scripts/swarm.sh" help unpause | grep -q 'Lift a pause whose cause is gone' || fail "help unpause has no page"
pass "unpause refuses a cap's pause still over its cap and names extend; help lists both"

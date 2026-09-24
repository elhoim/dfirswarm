#!/usr/bin/env bash
# The operator's notify command (swarm.sh start --notify, scripts/notify.sh):
# kept outside the run, found by the run's sandbox in the registry, given one
# JSON line on stdin, bounded in time, and never in the caller's way. No
# model, no Herdr, no VM.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/notify-test.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
wait_for() { # <file> <seconds>
  local i
  for ((i = 0; i < $2 * 10; i++)); do [[ -s "$1" ]] && return 0; sleep 0.1; done
  return 1
}

RUNS="$TMP/runs"
export SWARM_RUNS_DIR="$RUNS"
SB="$RUNS/snt1"
mkdir -p "$SB/traces" "$SB/done/agents" "$RUNS/notify"
printf '{"swarm_id":"snt1","n":1,"agents":[{"id":"snt100","role":"worker"}]}\n' > "$SB/team.json"
record() { # <state> <notify true|false>
  jq -n --arg sb "$SB" --arg st "$1" --argjson nt "$2" \
    '{runs: [{id: "snt1", label: "notify-test", state: $st, sandbox: $sb, n: 1, notify: $nt, isolation: {mode: "host"}}]}' > "$RUNS/registry.json"
}

echo "# the command gets one JSON line, and the run is found by its sandbox"
record stopped true
printf 'cat > %q\n' "$TMP/got.json" > "$RUNS/notify/snt1.cmd"
chmod 600 "$RUNS/notify/snt1.cmd"
started=$SECONDS
bash "$ROOT/scripts/notify.sh" "$SB" evidence_changed '{"changed":["inputs/a"]}' || fail "notify.sh failed its caller"
(( SECONDS - started < 3 )) || fail "notify.sh blocked its caller"
wait_for "$TMP/got.json" 10 || fail "the command was not run"
jq -e '.event == "evidence_changed" and .run == "snt1" and .detail.changed == ["inputs/a"] and (.at | test("Z$"))' "$TMP/got.json" >/dev/null \
  || fail "the line is not {event, run, at, detail}: $(cat "$TMP/got.json")"
pass "the operator's command gets {event, run, at, detail} on stdin, detached"

echo "# a command that fails or hangs is written down, bounded, and harms nothing"
printf 'echo broke >&2; exit 7\n' > "$RUNS/notify/snt1.cmd"
bash "$ROOT/scripts/notify.sh" "$SB" chain_broken || fail "a failing command failed the caller"
wait_for "$SB/traces/notify.log" 10 || fail "the failure was not logged"
grep -q 'chain_broken: the notify command failed (exit 7)' "$SB/traces/notify.log" || fail "the log does not say what failed: $(cat "$SB/traces/notify.log")"
grep -q '  broke' "$SB/traces/notify.log" || fail "the log does not keep what the command said"
: > "$SB/traces/notify.log"
printf 'sleep 30\n' > "$RUNS/notify/snt1.cmd"
SWARM_NOTIFY_TIMEOUT=1 bash "$ROOT/scripts/notify.sh" "$SB" agent_dead || fail "a hanging command failed the caller"
wait_for "$SB/traces/notify.log" 15 || fail "the timeout was not logged"
grep -q 'agent_dead: the notify command took more than 1 seconds and was stopped' "$SB/traces/notify.log" || fail "the timeout is not said: $(cat "$SB/traces/notify.log")"
pass "a failing or hanging command is logged in traces/notify.log and stopped at its limit"

echo "# nothing in the sandbox names what runs"
rm -f "$RUNS/notify/snt1.cmd" "$TMP/got.json"
printf 'cat > %q\n' "$TMP/got.json" > "$SB/notify.cmd"
bash "$ROOT/scripts/notify.sh" "$SB" finished
sleep 1
[[ ! -e "$TMP/got.json" ]] || fail "a command in the sandbox was run"
ln -s "$SB/notify.cmd" "$RUNS/notify/snt1.cmd"
bash "$ROOT/scripts/notify.sh" "$SB" finished
sleep 1
[[ ! -e "$TMP/got.json" ]] || fail "a link in runs/notify/ was followed"
rm -f "$RUNS/notify/snt1.cmd"
pass "only the kickoff's own file under runs/notify/ is run; no link, nothing in the sandbox"

echo "# stop tells it: finished, and stop_incomplete"
record running true
printf 'cat >> %q\n' "$TMP/events.jsonl" > "$RUNS/notify/snt1.cmd"
chmod 600 "$RUNS/notify/snt1.cmd"
out="$(bash "$ROOT/scripts/swarm.sh" stop snt1 --no-custody 2>&1)" || fail "stop failed: $out"
wait_for "$TMP/events.jsonl" 10 || fail "stop did not notify"
jq -e 'select(.event == "finished" and .detail.state == "stopped")' "$TMP/events.jsonl" >/dev/null || fail "stop's notification is not finished/stopped: $(cat "$TMP/events.jsonl")"
# A VM left up: stop_incomplete, and the command hears it.
: > "$TMP/events.jsonl"
cat > "$TMP/msb" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  list) printf '[{"name":"dfs-snt1-snt100","status":"running","labels":{"dev.dfirswarm.run":"snt1","dev.dfirswarm.agent":"snt100"}}]\n' ;;
  inspect) printf '{"config":{"labels":{"dev.dfirswarm.run":"snt1","dev.dfirswarm.agent":"snt100"}}}\n' ;;
  stop) exit 1 ;;
  --version) echo "msb 0.7.2" ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$TMP/msb"
jq -n --arg sb "$SB" '{runs: [{id: "snt1", label: "notify-test", state: "running", sandbox: $sb, n: 1, notify: true, isolation: {mode: "microvm", snapshot: false}}]}' > "$RUNS/registry.json"
mkdir -p "$SB/vm"
set +e
out="$(SWARM_MSB_BIN="$TMP/msb" bash "$ROOT/scripts/swarm.sh" stop snt1 --no-custody 2>&1)"
rc=$?
set -e
[[ $rc -eq 3 ]] || fail "a stop with a VM left up exited $rc: $out"
wait_for "$TMP/events.jsonl" 10 || fail "stop_incomplete was not notified"
jq -e 'select(.event == "stop_incomplete")' "$TMP/events.jsonl" >/dev/null || fail "the notification is not stop_incomplete: $(cat "$TMP/events.jsonl")"
pass "stop notifies finished, and stop_incomplete when a VM is still up"

echo "# the kickoff keeps the command outside the run, and says only that there is one"
HELLO="$ROOT/prompts/goals/hello.md"
out="$(bash "$ROOT/scripts/swarm.sh" start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --toolbox off \
  --label notified --notify 'curl -s https://hooks.example.test/T0KEN-secret -d @-' 2>&1)" || fail "a kickoff with --notify failed: $out"
id="$(printf '%s\n' "$out" | sed -n 's/^Swarm id: *//p' | tail -1)"
sb="$(printf '%s\n' "$out" | sed -n 's/^SANDBOX=//p' | tail -1)"
[[ -n "$id" && -n "$sb" ]] || fail "no run: $out"
[[ "$(jq -r --arg id "$id" '.runs[] | select(.id == $id) | .notify' "$RUNS/registry.json")" == true ]] || fail "the registry does not say there is a notify command"
grep -rq 'T0KEN-secret' "$RUNS/registry.json" "$RUNS/operator-audit.jsonl" "$sb" 2>/dev/null && fail "the notify command (a webhook's secret) is in the registry, the audit or the run"
[[ -f "$RUNS/notify/$id.cmd" ]] || fail "the command was not kept under runs/notify/"
mode="$(stat -c %a "$RUNS/notify/$id.cmd" 2>/dev/null || stat -f %Lp "$RUNS/notify/$id.cmd")"
[[ "$mode" == 600 ]] || fail "the kept command is mode $mode, not 600"
grep -q 'T0KEN-secret' "$RUNS/notify/$id.cmd" || fail "the kept command is not the operator's"
pass "--notify is kept in runs/notify/<id>.cmd (0600), the registry says only that there is one, and the command line is redacted everywhere"

echo "# the reaper tells it when a seat is marked dead"
RS="$RUNS/srp9"
mkdir -p "$RS/traces" "$RS/done/agents" "$RS/locks" "$RS/threads/main"
printf '{"swarm_id":"srp9","n":1,"agents":[{"id":"srp900","role":"worker"}]}\n' > "$RS/team.json"
printf '{"cap_usd":1,"spent_usd":0,"wall_clock_minutes":60,"started_at":"2026-01-01T00:00:00Z","agents":{}}\n' > "$RS/budget.json"
: > "$RS/traces/events.jsonl"
jq -n --arg sb "$RS" '{runs: [{id: "srp9", state: "running", sandbox: $sb, n: 1, notify: true}]}' > "$RUNS/registry.json"
printf 'cat >> %q\n' "$TMP/dead.jsonl" > "$RUNS/notify/srp9.cmd"
chmod 600 "$RUNS/notify/srp9.cmd"
out="$(SWARM_REGISTRY="$RUNS/registry.json" HERDR_BIN=/usr/bin/false bash "$ROOT/scripts/reap.sh" --sandbox "$RS" --timeout 1 2>&1)" || true
[[ -f "$RS/done/agents/srp900.dead" ]] || fail "the silent seat was not reaped: $out"
wait_for "$TMP/dead.jsonl" 10 || fail "agent_dead was not notified"
jq -e 'select(.event == "agent_dead" and .detail.agent == "srp900" and .detail.reason == "stall")' "$TMP/dead.jsonl" >/dev/null || fail "the notification is not agent_dead for srp900: $(cat "$TMP/dead.jsonl")"
pass "the reaper notifies agent_dead with the seat it marked"

echo "notify.test.sh: all checks passed"

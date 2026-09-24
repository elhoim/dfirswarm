#!/usr/bin/env bash
# Who sent a line, on a host where the token is not a secret.
#
# Every pane runs as one uid. On macOS that is fine for attribution: a pane's
# token sits in its environment and no other process can read it. On Linux
# /proc/<pid>/environ is readable across processes of one uid, so a pane can
# take a peer's token and write lines as that peer. The gate in front of the
# collector (scripts/trace-gate.py) answers with SO_PEERCRED and the process
# tree instead: a line is attributed to the pane whose root is an ancestor
# of the sender, whatever token the line carries. The collector counts a
# token only on a line the gate vouched for with a key no pane can read.
#
# Asserted here, on Linux: a process inside pane B sending pane A's token is
# written as B; the same token straight to the collector is unverified; an
# orphan that climbed out of the pane is still B because the pane's root is
# a subreaper; and the kickoff records `attribution: ancestry`. On macOS the
# gate is not started and the suite says so.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "skip - the trace gate is Linux-only (a pane's environment is private here, measured); the token attributes"
  exit 0
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/trace-gate.XXXXXX")"
GATE_PID=""; COLL_PID=""
cleanup() {
  [[ -n "$GATE_PID" ]] && kill "$GATE_PID" 2>/dev/null || true
  [[ -n "$COLL_PID" ]] && kill "$COLL_PID" 2>/dev/null || true
  stop_sandbox_daemons "$TMP/run" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT
eval "$(sed -n '/^stop_sandbox_daemons()/,/^}/p' "$ROOT/scripts/swarm.sh")"

SB="$TMP/sb"
mkdir -p "$SB/traces"
STDIN='{"tokens":{"tok-a":"a","tok-b":"b","tok-sys":"system"},"gate":"the-gate-key"}'

printf '%s' "$STDIN" | python3 "$ROOT/scripts/trace-gate.py" "$SB" --tokens --quiet >"$TMP/gate.log" 2>&1 &
GATE_PID=$!
printf '%s' "$STDIN" | node "$ROOT/scripts/trace-collector.mjs" "$SB" --tokens --anchor "$TMP/anchor.json" --quiet >"$TMP/coll.log" 2>&1 &
COLL_PID=$!
for _ in $(seq 1 80); do
  [[ -S "$SB/traces/.collector-gate.sock" && -S "$SB/traces/.collector.sock" ]] && break
  sleep 0.05
done
[[ -S "$SB/traces/.collector-gate.sock" ]] || fail "the gate did not come up: $(cat "$TMP/gate.log")"
[[ -S "$SB/traces/.collector.sock" ]] || fail "the collector did not come up: $(cat "$TMP/coll.log")"
GATE="$SB/traces/.collector-gate.sock"
EVENTS="$SB/traces/events.jsonl"

line() { # line <ts> <claimed agent>
  printf '{"ts":"%s","agent":"%s","tool":"bash","args":{"command":"id"},"result":{"ok":true}}' "$1" "$2"
}
last() { tail -n 1 "$EVENTS"; }

# --- a process in pane B, sending pane A's token, is written as B ---------------
env SWARM_TRACE_TOKEN=tok-b bash -c '
  printf "%s" "$1" | env SWARM_TRACE_TOKEN=tok-a SWARM_TRACE_SOCKET="$2" node "$3/scripts/trace-emit.mjs" "$4"
' _ "$(line t1 a)" "$GATE" "$ROOT" "$SB" || fail "sending through the gate failed"
[[ "$(last | jq -r .agent)" == "b" ]] || fail "a line from inside pane B should be B's, got: $(last)"
[[ "$(last | jq -r .claimed_agent)" == "a" ]] || fail "the body's claim should be kept as claimed_agent: $(last)"
[[ "$(last | jq -r '.token // empty')" == "" && "$(last | jq -r '.gate // empty')" == "" ]] || fail "neither token nor key belongs on the record: $(last)"
pass "a process inside pane B sending pane A's token is written as B, with the claim kept"

# --- the same token straight at the collector: no gate, no key, unverified ------
printf '%s' "$(line t2 a)" | env SWARM_TRACE_TOKEN=tok-a node "$ROOT/scripts/trace-emit.mjs" "$SB" || fail "direct send failed"
[[ "$(last | jq -r .agent_unverified)" == "true" ]] || fail "a token without the gate's key should not attribute: $(last)"
pass "a token taken from /proc and sent straight to the collector is written unverified"

# --- a line with no pane above it, through the gate ---------------------------------
printf '%s' "$(line t3 a)" | env -u SWARM_TRACE_TOKEN SWARM_TRACE_SOCKET="$GATE" node "$ROOT/scripts/trace-emit.mjs" "$SB" || fail "tokenless send failed"
[[ "$(last | jq -r .agent_unverified)" == "true" ]] || fail "no pane in the ancestry should be unverified: $(last)"
pass "a sender with no pane in its ancestry is written unverified"

# --- the harness's own sidecars: the system token, no pane above -----------------
printf '%s' "$(line t4 system)" | env SWARM_TRACE_TOKEN=tok-sys SWARM_TRACE_SOCKET="$GATE" node "$ROOT/scripts/trace-emit.mjs" "$SB" || fail "system send failed"
[[ "$(last | jq -r .agent)" == "system" && "$(last | jq -r '.agent_unverified // empty')" == "" ]] || fail "a sidecar carrying the system token should be system: $(last)"
pass "a sidecar carrying the system token is written as system"

# --- an orphan: the pane's root is a subreaper, so it is still inside the pane ----
# The pane's root outlives a grandchild whose parent exits. Without a
# subreaper the grandchild is reparented above the pane and the walk finds
# only the token it chose to carry — measured as the control below.
send_as_orphan='
  ( env SWARM_TRACE_TOKEN=tok-a SWARM_TRACE_SOCKET="$2" bash -c "sleep 0.3; printf %s \"\$0\" | node \"$3/scripts/trace-emit.mjs\" \"$4\"" "$1" & )
  sleep 1.2
'
if python3 "$ROOT/scripts/landlock.py" --dry-run -- true 2>/dev/null | grep -q '^abi: [1-9]'; then
  env SWARM_TRACE_TOKEN=tok-b python3 "$ROOT/scripts/landlock.py" --subreaper --rw "$TMP" -- \
    bash -c "$send_as_orphan" _ "$(line t5 a)" "$GATE" "$ROOT" "$SB" || fail "the subreaper pane failed"
  [[ "$(last | jq -r .agent)" == "b" ]] || fail "an orphan inside a subreaper pane should still be B: $(last)"
  pass "an orphan inside the pane is reparented to the pane's root and written as B"
else
  echo "skip - no Landlock on this kernel; the subreaper case needs landlock.py to reach its exec"
fi
env SWARM_TRACE_TOKEN=tok-b bash -c "$send_as_orphan" _ "$(line t6 a)" "$GATE" "$ROOT" "$SB" || fail "the control pane failed"
case "$(last | jq -r .agent)" in
  a) pass "control: without a subreaper the orphan climbs out and is written as the token it carries (why the subreaper exists)" ;;
  b) pass "control: this host reparents orphans to a subreaper above the test already; the orphan stayed attributable" ;;
  *) fail "the control orphan came out as neither: $(last)" ;;
esac

# --- the kickoff: the gate is started, the panes are pointed at it, the record says so
mkdir -p "$TMP/runs"
out="$(SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" start --model solo/model --n 2 --cap-usd 1 \
  --no-start --goal-file "$ROOT/prompts/goals/hello.md" --sandbox "$TMP/run" 2>&1)" || fail "kickoff failed: $out"
# The gate came up (its own log says so) and, --no-start being a prepared run
# nothing talks to yet, was put away again with the collector: a real start
# starts its own.
grep -q 'trace-gate: up' "$TMP/run/traces/trace-gate.log" 2>/dev/null || fail "the kickoff did not start the gate: $out"
[[ ! -S "$TMP/run/traces/.collector-gate.sock" && ! -f "$TMP/run/gate.pid" ]] \
  || fail "--no-start left the gate running after the kickoff"
[[ "$(jq -r '.runs[-1].attribution' "$TMP/runs/registry.json")" == "ancestry" ]] \
  || fail "the record should say attribution: ancestry, got $(jq -r '.runs[-1].attribution' "$TMP/runs/registry.json")"
pass "the kickoff starts the gate, records attribution: ancestry, and --no-start puts the gate away"

# --- and both processes hold the key: the gate marks, the collector counts ----------
# The gate was once started with the flat token map (no key) while the
# collector came up keyed, and every forwarded line was written unverified
# under a record that said ancestry. Each process logs what it was given.
grep -q 'trace-gate: up, .* key: yes' "$TMP/run/traces/trace-gate.log" \
  || fail "the gate was started without the key: $(cat "$TMP/run/traces/trace-gate.log")"
grep -q 'trace-collector: up, .* gate key: yes' "$TMP/run/traces/collector.log" \
  || fail "the collector was started without the gate's key: $(cat "$TMP/run/traces/collector.log")"
# And the kickoff's own line went through: the harness posts through the
# gate with the system token, and that line must count.
if grep -q '"agent":"system"' "$TMP/run/traces/events.jsonl" 2>/dev/null; then
  ! grep '"agent":"system"' "$TMP/run/traces/events.jsonl" | grep -q '"agent_unverified":true' \
    || fail "a system line through the kickoff's gate came out unverified"
fi
pass "the gate and the collector were both handed the key, and the kickoff's lines count"

stop_sandbox_daemons "$TMP/run" >/dev/null 2>&1 || true
[[ ! -S "$TMP/run/traces/.collector-gate.sock" ]] || fail "stop left the gate's socket behind"
pass "stopping the run's daemons takes the gate down with them"

echo "trace-gate: all checks passed"

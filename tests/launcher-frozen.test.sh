#!/usr/bin/env bash
# The launcher runs from a frozen copy (plan 0.13): `swarm.sh start`, `stop`
# and `resume` copy the script first and run the copy, so an edit to the
# checkout while they run changes neither what they do nor their exit status;
# the copy goes when the launcher ends, however it ends; a VM run's frozen
# host copy takes the launcher's own bytes for swarm.sh. Every
# line of the logs the launcher's daemons write carries its time, and so do
# the hub keeper's own lines. No model, no Herdr, no VM.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK
export SWARM_ISOLATION=host
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d /tmp/lfz.XXXXXX)"
# The launchers' copies go in the suite's own temporary area, where what is left of them can be seen.
export TMPDIR="$TMP/tmp"; mkdir -p "$TMPDIR"
copies_left() { ls -d "$TMPDIR"/dfirswarm-launcher.* 2>/dev/null || true; }
gone_soon() { # <path>: within three seconds
  local _
  for _ in $(seq 1 30); do [[ -e "$1" ]] || return 0; sleep 0.1; done
  return 1
}
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
TS='^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z '

echo "# start runs a copy: the checkout's file edited in place while it runs changes nothing"
# A checkout of links to this one, but for scripts/swarm.sh, which is its own file to edit.
CO="$TMP/checkout"; mkdir -p "$CO/scripts"
for e in "$ROOT"/* "$ROOT"/.[!.]*; do
  n="$(basename "$e")"
  [[ "$n" == scripts || "$n" == runs || "$n" == .git ]] && continue
  ln -s "$e" "$CO/$n"
done
for e in "$ROOT"/scripts/*; do [[ "$(basename "$e")" == swarm.sh ]] || ln -s "$e" "$CO/scripts/$(basename "$e")"; done
cp "$ROOT/scripts/swarm.sh" "$CO/scripts/swarm.sh"
# The first node the launcher runs says which file its bash runs, keeps that file's bytes (the copy is gone once the
# launcher ends), and rewrites the checkout's swarm.sh in place.
FAKE="$TMP/bin"; mkdir -p "$FAKE"
REAL_NODE="$(command -v node)"
cat > "$FAKE/node" <<EOF2
#!/usr/bin/env bash
if [[ ! -e "$TMP/seen" ]]; then
  : > "$TMP/seen"
  ps -o command= -p "\$PPID" > "$TMP/launcher-command"
  c="\$(grep -o '[^ ]*dfirswarm-launcher\.[0-9]*\.[A-Za-z0-9]*' "$TMP/launcher-command" | head -1)"
  [[ -n "\$c" ]] && cp "\$c/swarm.sh" "$TMP/copy-bytes"
  printf '%s\n' 'echo EDITED-CHECKOUT-RAN; exit 9' 'syntax error here (' > "$CO/scripts/swarm.sh.new"
  cat "$CO/scripts/swarm.sh.new" > "$CO/scripts/swarm.sh"
fi
exec "$REAL_NODE" "\$@"
EOF2
chmod +x "$FAKE/node"
GOAL="$TMP/goal.md"
printf '## Goal\n\nSay hello.\n\n## Definition of done\n\nd\n' > "$GOAL"
export SWARM_RUNS_DIR="$TMP/runs" DFIRSWARM_HOME="$TMP/home" SWARM_SIGNERS_HOME="$TMP/home"
mkdir -p "$DFIRSWARM_HOME"
rc=0
out="$(PATH="$FAKE:$PATH" bash "$CO/scripts/swarm.sh" start --model solo/model --n 1 --cap-usd 1 --no-start --toolbox off --goal-file "$GOAL" --label lfz 2>&1)" || rc=$?
[[ -e "$TMP/seen" ]] || fail "the launcher ran no node: $out"
[[ "$rc" -eq 0 ]] || fail "a start whose checkout was edited while it ran ended with exit $rc: $out"
grep -q 'EDITED-CHECKOUT-RAN\|syntax error' <<<"$out" && fail "the launcher read the edited checkout: $out"
grep -q '^SANDBOX=' <<<"$out" || fail "the start did not finish: $out"
cmd="$(cat "$TMP/launcher-command")"
grep -q 'dfirswarm-launcher\.[0-9]*\.[A-Za-z0-9]*/swarm.sh start' <<<"$cmd" || fail "the launcher's bash does not run a copy: $cmd"
grep -q "$CO/scripts/swarm.sh" <<<"$cmd" && fail "the launcher's bash runs the checkout's file: $cmd"
copy="$(grep -o '[^ ]*dfirswarm-launcher\.[0-9]*\.[A-Za-z0-9]*' <<<"$cmd" | head -1)"
[[ -n "$copy" ]] || fail "no launcher copy named in $cmd"
cmp -s "$TMP/copy-bytes" "$ROOT/scripts/swarm.sh" || fail "the copy is not the file as the launcher began"
gone_soon "$copy" || fail "the start's copy is still there after it ended: $(copies_left)"
sb="$(sed -n 's/^SANDBOX=//p' <<<"$out" | tail -1)"
[[ -d "$sb" ]] || fail "no sandbox: $out"
pass "a start runs a copy of swarm.sh; the checkout's file rewritten while it ran changes neither its output nor its exit status; the copy goes with it"

echo "# a command that is not start, stop or resume runs where it stands; a stop's status is its own, and its copy goes"
cp "$ROOT/scripts/swarm.sh" "$CO/scripts/swarm.sh"
rc=0; out="$(bash "$CO/scripts/swarm.sh" stop no-such-run 2>&1)" || rc=$?
[[ "$rc" -ne 0 ]] || fail "a stop of no run succeeded: $out"
grep -q 'no-such-run' <<<"$out" || fail "the stop of no run said nothing of it: $out"
for _ in $(seq 1 30); do [[ -z "$(copies_left)" ]] && break; sleep 0.1; done
[[ -z "$(copies_left)" ]] || fail "the stop's copy is still there after it ended: $(copies_left)"
rc2=0; bash "$CO/scripts/swarm.sh" list >/dev/null 2>&1 || rc2=$?
[[ "$rc2" -eq 0 ]] || fail "list failed ($rc2)"
pass "a stop's status passes through the copy, which goes with it; list runs as it stands"

echo "# a resume runs from a copy too; a launcher killed outright leaves no copy"
# The first jq a launcher runs says which file its bash runs. resume starts the run again inside its own process
# (cmd_start), for minutes: the same reading as it goes. Here it is refused (the run never started), with its status.
JQB="$TMP/jq-bin"; mkdir -p "$JQB"
REAL_JQ="$(command -v jq)"
cat > "$JQB/jq" <<EOF2
#!/usr/bin/env bash
[[ -e "$TMP/jq-seen" ]] || { : > "$TMP/jq-seen"; ps -o command= -p "\$PPID" > "$TMP/resume-command"; }
exec "$REAL_JQ" "\$@"
EOF2
chmod +x "$JQB/jq"
lfz_id="$(jq -r '[.runs[] | select(.label == "lfz") | .id] | last' "$SWARM_RUNS_DIR/registry.json")"
rc=0; out="$(PATH="$JQB:$PATH" bash "$CO/scripts/swarm.sh" resume "$lfz_id" 2>&1)" || rc=$?
[[ "$rc" -eq 2 ]] && grep -q "is prepared and never started" <<<"$out" || fail "the resume of a run never started ($rc): $out"
grep -q 'dfirswarm-launcher\.[0-9]*\.[A-Za-z0-9]*/swarm.sh resume' "$TMP/resume-command" || fail "the resume does not run a copy: $(cat "$TMP/resume-command" 2>/dev/null)"
for _ in $(seq 1 30); do [[ -z "$(copies_left)" ]] && break; sleep 0.1; done
[[ -z "$(copies_left)" ]] || fail "the resume's copy is still there after it ended: $(copies_left)"
# A launcher killed with SIGKILL runs no trap of its own: its copy still goes.
cat > "$FAKE/node" <<EOF2
#!/usr/bin/env bash
echo "\$\$" > "$TMP/node-waits"
exec sleep 30
EOF2
chmod +x "$FAKE/node"
PATH="$FAKE:$PATH" bash "$CO/scripts/swarm.sh" start --model solo/model --n 1 --cap-usd 1 --no-start --toolbox off --goal-file "$GOAL" --label lfk >/dev/null 2>&1 </dev/null &
killed=$!
for _ in $(seq 1 100); do [[ -e "$TMP/node-waits" ]] && break; sleep 0.1; done
[[ -e "$TMP/node-waits" ]] || fail "the start to be killed never reached its first node"
kcopy="$(copies_left | head -1)"
[[ -n "$kcopy" && "$kcopy" == *"/dfirswarm-launcher.$killed."* ]] || fail "the running start's copy is not named for its pid $killed: $(copies_left)"
kill -9 "$killed"; wait "$killed" 2>/dev/null || true
kill "$(cat "$TMP/node-waits")" 2>/dev/null || true
gone_soon "$kcopy" || fail "a launcher killed outright left its copy: $(copies_left)"
pass "a resume runs a copy and its status passes through; a killed launcher's copy goes within a second or two"

echo "# the run's frozen host copy has the launcher's bytes for swarm.sh"
eval "$(sed -n '/^harness_commit()/,/^}/p; /^harness_dirty()/,/^}/p; /^freeze_harness()/,/^}/p' "$ROOT/scripts/swarm.sh")"
HUB="$TMP/hub"; mkdir -p "$HUB"
printf '# the launcher began with these bytes\n' > "$TMP/launcher-copy.sh"
LAUNCHER_COPY="$TMP/launcher-copy.sh" freeze_harness "$HUB" >/dev/null 2>&1 || fail "freeze_harness failed"
cmp -s "$HUB/host/scripts/swarm.sh" "$TMP/launcher-copy.sh" || fail "the host copy's swarm.sh is not the launcher's"
cmp -s "$HUB/harness/scripts/swarm.sh" "$TMP/launcher-copy.sh" || fail "the VMs' copy's swarm.sh is not the launcher's"
cmp -s "$HUB/host/scripts/render-contract.ts" "$ROOT/scripts/render-contract.ts" || fail "the other scripts are not the checkout's"
pass "freeze_harness takes the launcher's own swarm.sh: the hub and the launcher run one file"

echo "# every line of a daemon's log carries its time"
eval "$(sed -n '/^log_stamper()/,/^}/p; /^detach_exec()/,/^}/p' "$ROOT/scripts/swarm.sh")"
LOG="$TMP/daemon.log"; : > "$LOG"
( detach_exec bash -c 'echo one; echo two >&2; echo "idle-nudge: three"; printf "no newline"' > >(log_stamper "$LOG") 2>&1 & )
for _ in $(seq 1 50); do [[ "$(wc -l < "$LOG" | tr -d ' ')" -ge 4 ]] && break; sleep 0.1; done
[[ "$(wc -l < "$LOG" | tr -d ' ')" -eq 4 ]] || fail "the log has not its four lines: $(cat "$LOG")"
grep -Evq "$TS" "$LOG" && fail "a line carries no time: $(cat "$LOG")"
grep -Eq "${TS}[0-9]{4}-" "$LOG" && fail "a line carries two times: $(cat "$LOG")"
grep -Eq "${TS}idle-nudge: three$" "$LOG" && grep -Eq "${TS}two$" "$LOG" && grep -Eq "${TS}no newline$" "$LOG" || fail "the lines are not whole: $(cat "$LOG")"
body="$(grep -A1 'bash "\$nudge_script" --sandbox' "$ROOT/scripts/swarm.sh")"
[[ "$(grep -c 'log_stamper "\$sandbox/traces/idle-nudge.log"' <<<"$body")" -eq 2 ]] || fail "the watchdog's two starts do not both stamp its log: $body"
grep -q 'SWARM_LOG_TS=1' "$ROOT/scripts/swarm.sh" && fail "the watchdog is still asked to stamp its own lines too (each would carry two times)"
pass "a daemon's output, stdout and stderr, is stamped line by line, once; the watchdog's log is written so"

echo "# the hub keeper's own lines carry their time"
SB2="$TMP/sb2"; HUB2="$TMP/hub2"; mkdir -p "$SB2/traces" "$HUB2"
printf '{"tokens": {}}\n' > "$HUB2/hub-input.json"
true & dead=$!; wait "$dead" || true
rc=0; SWARM_HUB_MAX_RESTARTS=0 bash "$ROOT/scripts/hub-supervise.sh" "$SB2" "$HUB2" "$TMP/no-hub.mjs" "$dead" >/dev/null 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || fail "the keeper with no restarts left exited $rc"
grep -Eq "${TS}hub-supervise: the hub died 0 times in a row; not restarting it again$" "$SB2/traces/vm-hub.log" || fail "the keeper's line carries no time: $(cat "$SB2/traces/vm-hub.log")"
pass "the hub keeper's lines in the logs carry their time"

echo "# a start's output ends when the launcher ends, while the watchdog it left behind runs on"
# A host start that goes the whole way, against a stand-in Herdr and Pi: the run's daemons and the idle watchdog stay up
# after the launcher exits. Whatever reads the launcher's output (a command substitution, the console's start job, a
# pipe into tee, ssh) waits for the end of that output, so no daemon may hold it: the watchdog's log stamper held it
# for the whole run, and the console's job stayed "running" with no exit code.
STUB="$TMP/stub-bin"; mkdir -p "$STUB"
cat > "$STUB/pi" <<'SH'
#!/bin/sh
echo '{"status":"ready","authType":"api_key","provider":"solo"}'
SH
cat > "$STUB/herdr" <<'SH'
#!/bin/sh
case "$1 $2" in
  "status server") if [ "$3" = --json ]; then echo '{"status":"running","running":true}'; else echo "status: running"; fi ;;
  "agent list") echo '{"result":{"agents":[]}}' ;;
  "workspace create") echo '{"result":{"root_pane":{"pane_id":"p1"},"workspace":{"workspace_id":"w1"}}}' ;;
  *) echo '{"result":{}}' ;;
esac
SH
chmod +x "$STUB/pi" "$STUB/herdr"
LIVE="$TMP/runs-live"; mkdir -p "$LIVE" "$TMP/hubs"
live() { PATH="$STUB:$PATH" SWARM_RUNS_DIR="$LIVE" SWARM_HUBS_DIR="$TMP/hubs" bash "$@"; }
live_start=(start --model solo/model --n 1 --cap-usd 1 --toolbox off --no-write-guard --accept-signer-exposure --no-netguard --goal-file "$GOAL")
# Every run this section starts is stopped at the end, also when a check fails: its watchdog and the host's
# keep-awake are the run's.
stop_live() {
  local id
  for id in $(jq -r '.runs[]? | select(.state == "running") | .id' "$LIVE/registry.json" 2>/dev/null); do
    live "$ROOT/scripts/swarm.sh" stop "$id" --no-custody >/dev/null 2>&1 || true
  done
}
trap 'stop_live; chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
watchdog_of() { # <label> -> the watchdog's pid of that run, when it runs
  local sb p
  sb="$(jq -r --arg l "$1" '[.runs[]? | select(.label == $l) | .sandbox] | last // empty' "$LIVE/registry.json" 2>/dev/null)"
  p="$(cat "$sb/idle-nudge.pid" 2>/dev/null || true)"
  [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null && ps -ww -o command= -p "$p" 2>/dev/null | grep -q 'idle-nudge.sh' && echo "$p"
  return 0
}
# Under a command substitution, as a script or a test reads it.
( got="$( { live "$ROOT/scripts/swarm.sh" "${live_start[@]}" --label lfo-cs 2>&1; echo "$?" > "$TMP/cs.rc"; } )"
  { printf '%s\n' "$got" > "$TMP/cs.out"; : > "$TMP/cs.eof"; } 2>/dev/null ) &
for _ in $(seq 1 1800); do [[ -e "$TMP/cs.rc" ]] && break; sleep 0.1; done
[[ -e "$TMP/cs.rc" ]] || fail "the launcher under a command substitution did not end in three minutes"
for _ in $(seq 1 50); do [[ -e "$TMP/cs.eof" ]] && break; sleep 0.1; done
wd="$(watchdog_of lfo-cs)"
if [[ ! -e "$TMP/cs.eof" ]]; then
  stop_live
  fail "the launcher exited ($(cat "$TMP/cs.rc")) and a command substitution of its output had no end five seconds later: a process it left behind holds its output"
fi
[[ "$(cat "$TMP/cs.rc")" -eq 0 ]] || fail "the start under a command substitution exited $(cat "$TMP/cs.rc"): $(cat "$TMP/cs.out")"
grep -q '^Agents prompted\.' "$TMP/cs.out" || fail "the start did not go the whole way: $(cat "$TMP/cs.out")"
[[ -n "$wd" ]] || fail "no watchdog runs after the start, so nothing was measured: $(cat "$TMP/cs.out")"
# Under a Node spawn with pipes, as the console's start job runs it (scripts/ui/actions.ts): its status is set on close.
spawn_js='
const { spawn } = require("node:child_process");
const [sh, ...argv] = process.argv.slice(1);
const c = spawn("bash", [sh, ...argv], { stdio: ["ignore", "pipe", "pipe"] });
let out = "", exitAt = 0, code = null;
c.stdout.on("data", (d) => { out += d; });
c.stderr.on("data", (d) => { out += d; });
c.on("exit", (n) => {
  code = n; exitAt = Date.now();
  setTimeout(() => { console.log(JSON.stringify({ exit: code, close_ms: null, out })); process.exit(0); }, 5000);
});
c.on("close", () => { console.log(JSON.stringify({ exit: code, close_ms: Date.now() - exitAt, out })); process.exit(0); });
'
res="$(PATH="$STUB:$PATH" SWARM_RUNS_DIR="$LIVE" SWARM_HUBS_DIR="$TMP/hubs" node -e "$spawn_js" "$ROOT/scripts/swarm.sh" "${live_start[@]}" --label lfo-spawn)"
wd2="$(watchdog_of lfo-spawn)"
[[ "$(jq -r '.close_ms' <<<"$res")" != null ]] || { stop_live; fail "the launcher exited ($(jq -r '.exit' <<<"$res")) and its piped output had not closed five seconds later: $(jq -r '.out' <<<"$res" | tail -3)"; }
[[ "$(jq -r '.exit' <<<"$res")" == 0 ]] || fail "the spawned start exited $(jq -r '.exit' <<<"$res"): $(jq -r '.out' <<<"$res")"
[[ -n "$wd2" ]] || fail "no watchdog runs after the spawned start, so nothing was measured: $(jq -r '.out' <<<"$res")"
# The watchdog's log is still written: its stamper took the daemon's output, not the launcher's.
sb2="$(jq -r '[.runs[]? | select(.label == "lfo-spawn") | .sandbox] | last' "$LIVE/registry.json")"
[[ -f "$sb2/traces/idle-nudge.log" ]] || fail "the watchdog has no log"
stop_live
pass "the launcher's output ends within five seconds of its exit, under a command substitution and a Node spawn with pipes, while the watchdog it started runs on"

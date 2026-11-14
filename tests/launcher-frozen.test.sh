#!/usr/bin/env bash
# The launcher runs from a frozen copy (plan 0.13): `swarm.sh start` and
# `stop` copy the script first and run the copy, so an edit to the checkout
# while they run changes neither what they do nor their exit status; a VM
# run's frozen host copy takes the launcher's own bytes for swarm.sh. Every
# line of the logs the launcher's daemons write carries its time, and so do
# the hub keeper's own lines. No model, no Herdr, no VM.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK
export SWARM_ISOLATION=host
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d /tmp/lfz.XXXXXX)"
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
# The first node the launcher runs says which file its bash runs, and rewrites the checkout's swarm.sh in place.
FAKE="$TMP/bin"; mkdir -p "$FAKE"
REAL_NODE="$(command -v node)"
cat > "$FAKE/node" <<EOF2
#!/usr/bin/env bash
if [[ ! -e "$TMP/seen" ]]; then
  : > "$TMP/seen"
  ps -o command= -p "\$PPID" > "$TMP/launcher-command"
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
[[ -n "$copy" && -d "$copy" ]] || fail "no launcher copy named in $cmd"
cmp -s "$copy/swarm.sh" "$ROOT/scripts/swarm.sh" || fail "the copy is not the file as the launcher began"
sb="$(sed -n 's/^SANDBOX=//p' <<<"$out" | tail -1)"
[[ -d "$sb" ]] || fail "no sandbox: $out"
pass "a start runs a copy of swarm.sh; the checkout's file rewritten while it ran changes neither its output nor its exit status"

echo "# a command that is not start or stop runs where it stands; a stop's status is its own; an ended launcher's copy goes"
cp "$ROOT/scripts/swarm.sh" "$CO/scripts/swarm.sh"
rc=0; out="$(bash "$CO/scripts/swarm.sh" stop no-such-run 2>&1)" || rc=$?
[[ "$rc" -ne 0 ]] || fail "a stop of no run succeeded: $out"
grep -q 'no-such-run' <<<"$out" || fail "the stop of no run said nothing of it: $out"
[[ ! -e "$copy" ]] || fail "the next stop left the ended start's copy: $copy"
rc2=0; bash "$CO/scripts/swarm.sh" list >/dev/null 2>&1 || rc2=$?
[[ "$rc2" -eq 0 ]] || fail "list failed ($rc2)"
pass "a stop's status passes through the copy; list runs as it stands"

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

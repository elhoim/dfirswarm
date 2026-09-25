#!/usr/bin/env bash
# A second start --sandbox DIR must not keep the previous proxy allowlist or
# a leftover idle-nudge after overwriting the pid file.
set -euo pipefail
# This suite tests host runs, and a run is in microVMs unless it says
# otherwise: it names host. An image, a lock file or another pack home
# exported in the shell would point its kickoffs somewhere else.
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/netguard-sidecar.XXXXXX")"
# The VM hubs' directory is the suite's own (a kickoff makes it for its pane
# guard), never the operator's ~/.dfirswarm/hubs.
export SWARM_HUBS_DIR="$TMP/dfirswarm-hubs"
NG_PID=""
NG2_PID=""
cleanup() {
  stop_sandbox_daemons "$TMP/sb" 2>/dev/null || true
  stop_sandbox_daemons "$TMP/side" 2>/dev/null || true
  [[ -n "$NG_PID" ]] && kill "$NG_PID" 2>/dev/null || true
  [[ -n "$NG2_PID" ]] && kill "$NG2_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

eval "$(sed -n '/^port_in_use()/,/^}/p' "$ROOT/scripts/swarm.sh")"
eval "$(sed -n '/^pick_free_port()/,/^}/p' "$ROOT/scripts/swarm.sh")"
eval "$(sed -n '/^stop_sandbox_daemons()/,/^}/p' "$ROOT/scripts/swarm.sh")"
eval "$(sed -n '/^detach_exec()/,/^}/p' "$ROOT/scripts/swarm.sh")"
eval "$(sed -n '/^start_netguard_sidecar()/,/^}/p' "$ROOT/scripts/swarm.sh")"
[[ "$(type -t stop_sandbox_daemons)" == function ]] || fail "stop_sandbox_daemons missing from swarm.sh"
[[ "$(type -t start_netguard_sidecar)" == function ]] || fail "start_netguard_sidecar missing from swarm.sh"
# The sidecar has to outlive the terminal the kickoff ran in; detach_run is how.
[[ "$(type -t detach_exec)" == function ]] || fail "detach_exec missing from swarm.sh"

mkdir -p "$TMP/sb/traces" "$TMP/runs"
# Leftover daemons from a previous run in this directory. stop ends a daemon
# only when its command line is that daemon's for this sandbox (a pid file
# can name any process after a reboot), so these look like the run's own:
# its netguard with its log, its idle watchdog with its sandbox, by the
# resolved path, as the kickoff resolves the sandbox.
SBR="$(cd "$TMP/sb" && pwd -P)"
bash -c "exec -a 'bash netguard.sh --mode proxy-only --log $SBR/traces/netguard.log' sleep 3600" >/dev/null 2>&1 &
old_ng=$!
echo "$old_ng" > "$TMP/sb/netguard.pid"
echo 43178 > "$TMP/sb/netguard.port"
echo "old.example" > "$TMP/sb/netguard.allow"
bash -c "exec -a 'bash idle-nudge.sh --sandbox $SBR' sleep 3600" >/dev/null 2>&1 &
old_idle=$!
echo "$old_idle" > "$TMP/sb/idle-nudge.pid"
kill -0 "$old_ng" && kill -0 "$old_idle" || fail "fixture daemons did not start"

SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" start --model solo/model --n 1 --cap-usd 1 \
  --no-start --goal-file "$ROOT/prompts/goals/hello.md" --sandbox "$TMP/sb" >/dev/null
kill -0 "$old_ng" 2>/dev/null && fail "start left the previous netguard sidecar running"
kill -0 "$old_idle" 2>/dev/null && fail "start left the previous idle-nudge running"
[[ ! -f "$TMP/sb/netguard.pid" ]] || fail "start --no-start should clear netguard.pid"
[[ ! -f "$TMP/sb/idle-nudge.pid" ]] || fail "start --no-start should clear idle-nudge.pid"
pass "start --sandbox DIR stops leftover netguard and idle-nudge pids"

mkdir -p "$TMP/side/traces"
SWARM_NETGUARD_PORT=$(( 45000 + RANDOM % 1000 ))
start_netguard_sidecar "$TMP/side" "api.openai.com"
NG_PID="$(cat "$TMP/side/netguard.pid")"
port1="$(cat "$TMP/side/netguard.port")"
[[ -n "$NG_PID" ]] && kill -0 "$NG_PID" || fail "sidecar did not start"
# The pid has to be the sidecar's own. Backgrounding a shell function forks a
# subshell, and without the exec inside detach_exec the pid file named that
# subshell: `stop` killed a shell that had already gone and left the proxy
# running. Measured on a server, where seventeen daemons piled up over five
# kickoffs, every one of them with its pid file already deleted.
ps -o args= -p "$NG_PID" 2>/dev/null | grep -q "netguard.sh" \
  || fail "netguard.pid names $(ps -o args= -p "$NG_PID" 2>/dev/null | head -c 60), not the sidecar"
[[ "$(cat "$TMP/side/netguard.allow")" == "api.openai.com" ]] || fail "sidecar did not record its allowlist"
start_netguard_sidecar "$TMP/side" "api.openai.com"
[[ "$(cat "$TMP/side/netguard.pid")" == "$NG_PID" ]] || fail "identical allowlist should reuse the live sidecar"
start_netguard_sidecar "$TMP/side" "example.com"
NG2_PID="$(cat "$TMP/side/netguard.pid")"
[[ "$NG2_PID" != "$NG_PID" ]] || fail "a different allowlist must not reuse the old sidecar"
kill -0 "$NG_PID" 2>/dev/null && fail "the previous sidecar should be gone after an allowlist change"
[[ "$(cat "$TMP/side/netguard.allow")" == "example.com" ]] || fail "new allowlist was not recorded"
# --only vs --allow is part of the identity even when the host list matches.
SWARM_NETGUARD_ONLY=1
start_netguard_sidecar "$TMP/side" "example.com"
only_pid="$(cat "$TMP/side/netguard.pid")"
[[ "$only_pid" != "$NG2_PID" ]] || fail "--only must not reuse an --allow sidecar with the same hosts"
kill -0 "$NG2_PID" 2>/dev/null && fail "switching to --only should stop the previous sidecar"
NG2_PID="$only_pid"
pass "sidecar reuse requires the same allowlist and --only flag"

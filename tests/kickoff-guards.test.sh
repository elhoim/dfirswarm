#!/usr/bin/env bash
# Small guards of scripts/swarm.sh, taken from the script itself. No model,
# no Herdr, no VM.
#
# - the VM hubs' directory is one per user, not a link, not someone else's,
#   and a run whose hub sockets would not fit a Unix socket path is refused;
# - under a runs directory deep enough that no socket path in it fits, the
#   kickoff's line still reaches the collector (through the gate on Linux),
#   and so do the shell's and the CLI's lines from any directory; a line the
#   collector does not take is kept in the system spill, and events.jsonl
#   never gets one the collector did not write;
# - stop ends a daemon only when the pid names that daemon for that sandbox;
# - a run id is not allocated past a failed `msb list`;
# - a host process's temporary files go to work/.tmp and Node's compile cache
#   to the run's .runtime-cache/, so neither the artifact index nor the
#   package carries a runtime's cache as the run's work.
set -euo pipefail
unset SWARM_ISOLATION SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d /tmp/kguard.XXXXXX)"
PIDS=()
cleanup() { local p; for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

fn() { sed -n "/^$1() {/,/^}/p" "$ROOT/scripts/swarm.sh"; }
for f in hubs_parent hubs_parent_path hub_socket_path_max vm_hub_dir hub_dir_of daemon_pid_ours stop_sandbox_daemons hub_pid_ours alloc_prefix scratch_env_for; do
  eval "$(fn "$f")"
  type "$f" >/dev/null 2>&1 || fail "$f was not found in swarm.sh"
done

echo "# the hubs' directory"
export SWARM_HUBS_DIR="$TMP/hubs"
p="$(hubs_parent --create)" || fail "the hubs' directory was not made"
[[ "$(stat -c %a "$SWARM_HUBS_DIR" 2>/dev/null || stat -f %Lp "$SWARM_HUBS_DIR")" == "700" ]] || fail "the hubs' directory is not 0700"
[[ "$p" == "$(cd "$SWARM_HUBS_DIR" && pwd -P)" ]] || fail "hubs_parent did not resolve the directory"
unset SWARM_HUBS_DIR
[[ "$(HOME="$TMP/home" hubs_parent_path)" == "$TMP/home/.dfirswarm/hubs" ]] || fail "the default is not under the user's home"
[[ "$(HOME="$TMP/home" TMPDIR="$TMP/elsewhere" hubs_parent_path)" == "$TMP/home/.dfirswarm/hubs" ]] || fail "the hubs' directory follows TMPDIR"
export SWARM_HUBS_DIR="$TMP/hubs"
mkdir -p "$TMP/real"
ln -s "$TMP/real" "$TMP/linked"
out="$(SWARM_HUBS_DIR="$TMP/linked" hubs_parent --create 2>&1)" && fail "a hubs' directory that is a link was used: $out"
grep -q 'is a link' <<<"$out" || fail "the refusal does not say it is a link: $out"
if [[ "$(id -u)" -ne 0 && -d /private/var/root ]] && [[ ! -O /private/var/root ]]; then
  out="$(SWARM_HUBS_DIR=/private/var/root hubs_parent 2>&1)" && fail "another user's directory was taken for the hubs' directory"
  grep -q 'is not yours' <<<"$out" || fail "the refusal does not say it is not the user's: $out"
elif [[ "$(id -u)" -ne 0 && -d /root ]]; then
  out="$(SWARM_HUBS_DIR=/root hubs_parent 2>&1)" && fail "another user's directory was taken for the hubs' directory"
fi
pass "the hubs' directory is the user's own (0700), the same whatever TMPDIR, and a link or another user's directory is refused"

echo "# a hub socket past the Unix limit is refused at kickoff"
n="$(hub_socket_path_max s1a2b3c s1a2b3c09)" || fail "hub_socket_path_max failed"
(( n < 104 )) || fail "a short hubs' directory gave a socket path of $n bytes"
long="$TMP/$(printf 'x%.0s' $(seq 1 60))"
mkdir -p "$long"
n="$(SWARM_HUBS_DIR="$long/hubs" hub_socket_path_max s1a2b3c s1a2b3c09)"
(( n > 103 )) || fail "a long hubs' directory was not measured as too long ($n)"
# The kickoff checks it before anything is written.
grep -q 'this run.s hub sockets would be' "$ROOT/scripts/swarm.sh" || fail "the kickoff does not refuse a socket path that is too long"
pass "the longest hub socket path is measured in bytes, and one past 103 is caught"

echo "# stop ends only this sandbox's own daemons"
SB="$TMP/sb"
mkdir -p "$SB/traces"
SB="$(cd "$SB" && pwd -P)"
bash -c "exec -a 'node trace-collector.mjs $SB --tokens' sleep 300" >/dev/null 2>&1 &
ours=$!
disown "$ours" 2>/dev/null || true
PIDS+=("$ours")
sleep 300 >/dev/null 2>&1 &
stranger=$!
disown "$stranger" 2>/dev/null || true
PIDS+=("$stranger")
bash -c "exec -a 'node nudge-broker.mjs $TMP/other-sandbox --roster' sleep 300" >/dev/null 2>&1 &
other=$!
disown "$other" 2>/dev/null || true
PIDS+=("$other")
sleep 0.3
echo "$ours" > "$SB/collector.pid"
echo "$stranger" > "$SB/idle-nudge.pid"
echo "$other" > "$SB/nudge.pid"
stop_sandbox_daemons "$SB" keep-record
kill -0 "$ours" 2>/dev/null && fail "this sandbox's collector was not stopped"
kill -0 "$stranger" 2>/dev/null || fail "a process a pid file named, but not a daemon of this run, was killed"
kill -0 "$other" 2>/dev/null || fail "another sandbox's daemon, named in this sandbox's pid file, was killed"
pass "stop ends a daemon its pid file names only when the process is that daemon for this sandbox"

echo "# a run id is not allocated past a failed msb list"
herdr_agent_names() { :; }
json_get() { :; }
vm_cli() { printf '{"ok":false,"error":"msb list failed: the runtime is not running"}\n'; return 1; }
set +e
out="$(isolation=microvm alloc_prefix 2>&1)"
rc=$?
set -e
[[ $rc -eq 3 ]] || fail "a failed msb list exited $rc, wanted 3: $out"
grep -q 'msb could not list its VMs.*the runtime is not running' <<<"$out" || fail "the refusal does not say msb's list failed: $out"
grep -q 'Could not allocate' <<<"$out" && fail "a failed list was reported as ids that could not be had: $out"
vm_cli() { printf '{"ok":true,"vms":[]}\n'; }
id="$(isolation=microvm alloc_prefix)" || fail "an id was not allocated with msb answering"
[[ "$id" =~ ^s[0-9a-f]{6}$ ]] || fail "the id is not s and three bytes: $id"
pass "a failed msb list is said as that; with msb answering an id of three bytes is allocated"

echo "# a runtime's cache is not the run's work"
# Run s2a59b2 indexed and packaged eleven work/.tmp/node-compile-cache/ files:
# Pi's CLI turns Node's compile cache on, Node puts it under TMPDIR, and the
# kickoff's TMPDIR is work/.tmp. No agent wrote them.
SC="$TMP/scratch-run"
mkdir -p "$SC"
SC="$(cd "$SC" && pwd -P)"
scratch_env_for "$SC"
env_of() { # <name> -> its value in SCRATCH_ENV_ARGS
  local i
  for ((i = 0; i + 1 < ${#SCRATCH_ENV_ARGS[@]}; i += 2)); do
    [[ "${SCRATCH_ENV_ARGS[$i]}" == --env && "${SCRATCH_ENV_ARGS[$((i + 1))]}" == "$1="* ]] && printf '%s' "${SCRATCH_ENV_ARGS[$((i + 1))]#*=}"
  done
  return 0
}
[[ "$(env_of TMPDIR)" == "$SC/work/.tmp" ]] || fail "a pane's TMPDIR is not the run's work/.tmp: $(env_of TMPDIR)"
cache="$(env_of NODE_COMPILE_CACHE)"
[[ "$cache" == "$SC/.runtime-cache/node-compile-cache" ]] || fail "Node's compile cache is not pointed at the run's .runtime-cache/: '$cache'"
[[ -d "$SC/work/.tmp" && -d "$SC/.runtime-cache" ]] || fail "the scratch and cache directories were not made"
pass "a pane's scratch is work/.tmp and Node's compile cache is the run's .runtime-cache/, outside work/"
if command -v pi >/dev/null 2>&1; then
  # The same Pi, as the kickoff starts it: its cache lands where the harness
  # points it, and the index of work/ has nothing of it.
  env TMPDIR="$SC/work/.tmp" NODE_COMPILE_CACHE="$cache" pi --version >/dev/null 2>&1 || fail "pi --version failed"
  [[ -n "$(find "$cache" -type f 2>/dev/null | head -1)" ]] || fail "Pi wrote no compile cache where the harness points it"
  [[ -z "$(find "$SC/work" -type f 2>/dev/null | head -1)" ]] || fail "Pi wrote under work/: $(find "$SC/work" -type f | head -3)"
  index="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/artifacts.ts" "$SC")"
  jq -e '.files | length == 0' <<<"$index" >/dev/null || fail "the artifact index lists a runtime's cache: $(jq -c '[.files[].path]' <<<"$index")"
  # Without it, the measured fault: the same Pi puts the cache under work/,
  # and the index lists it as work.
  CTRL="$TMP/scratch-control"
  mkdir -p "$CTRL/work/.tmp"
  env -u NODE_COMPILE_CACHE TMPDIR="$CTRL/work/.tmp" pi --version >/dev/null 2>&1 || fail "pi --version failed"
  node --experimental-strip-types --no-warnings "$ROOT/scripts/artifacts.ts" "$CTRL" | jq -e '[.files[].path | select(startswith("work/.tmp/node-compile-cache/"))] | length > 0' >/dev/null \
    || fail "the control did not reproduce the cache under work/, so the check above proves nothing"
  pass "Pi's compile cache lands in .runtime-cache/, and the artifact index of work/ has none of it (without the variable it would)"
else
  echo "skip - pi is not on PATH: where Pi puts its compile cache is not measured"
fi

echo "# a deep runs directory: every trace socket reached from inside its directory, nothing appended unchained"
DEEP="$TMP/a-runs-directory-deep-enough-that-no-unix-socket-path-fits/under/it/runs"
mkdir -p "$DEEP"
out="$(cd / && SWARM_ISOLATION=host SWARM_RUNS_DIR="$DEEP" bash "$ROOT/scripts/swarm.sh" start --model solo/model --n 2 --cap-usd 1 --no-start \
  --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off --label deep1 2>&1)" || fail "a kickoff under a deep runs directory was refused: $out"
sb="$(printf '%s\n' "$out" | sed -n 's/^SANDBOX=//p' | tail -1)"
[[ -n "$sb" && -d "$sb/traces" ]] || fail "the kickoff made no sandbox: $out"
sock="$sb/traces/.collector-gate.sock"
[[ "$(printf '%s' "$sock" | LC_ALL=C wc -c | tr -d ' ')" -gt 108 ]] || fail "the runs directory is not deep enough to test anything: $sock"
first="$(head -n 1 "$sb/traces/events.jsonl")"
jq -e '.tool == "operator_action" and .args.command == "start" and (.prev | type) == "string" and (.recv_ts | type) == "string" and (.agent_unverified // false) == false' <<<"$first" >/dev/null \
  || fail "the kickoff's own line did not reach the collector: $first"
emit_from_root() { (cd / && . "$ROOT/scripts/lib/trace.sh" && trace_emit "$ROOT" "$1" "$2"); }
chained_only() { jq -se 'all(.[]; (.prev | type) == "string")' "$1/traces/events.jsonl" >/dev/null; }
# --no-start stopped the collector: the watchdog's line is kept in the spill.
emit_from_root "$sb" '{"ts":"2026-01-01T00:00:00.000Z","agent":"system","tool":"idle_nudge","args":{"agent":"x0"},"result":{"ok":true}}'
grep -q '"tool":"idle_nudge"' "$sb/traces/system-spill.jsonl" 2>/dev/null || fail "a line no collector took is not in the system spill"
chained_only "$sb" || fail "events.jsonl holds a line the collector did not write: $(cat "$sb/traces/events.jsonl")"
# A record not chained yet takes no appended line either: nothing can say who wrote it.
PLAIN="$TMP/plain"
mkdir -p "$PLAIN/traces"
printf '%s\n' '{"ts":"t1","agent":"a0","tool":"bash","args":{},"result":{"ok":true}}' > "$PLAIN/traces/events.jsonl"
emit_from_root "$PLAIN" '{"ts":"2026-01-01T00:00:00.000Z","agent":"system","tool":"idle_nudge","args":{"agent":"a0"},"result":{"ok":true}}'
[[ "$(wc -l < "$PLAIN/traces/events.jsonl" | tr -d ' ')" -eq 1 ]] || fail "a line was appended to a record not chained yet: $(cat "$PLAIN/traces/events.jsonl")"
grep -q '"tool":"idle_nudge"' "$PLAIN/traces/system-spill.jsonl" 2>/dev/null || fail "the line is not in the system spill"
# A collector at the deep path: the shell's line and the CLI's reach it from another directory.
node "$ROOT/scripts/trace-collector.mjs" "$sb" --quiet >"$TMP/deep-collector.log" 2>&1 &
coll=$!
PIDS+=("$coll")
for _ in $(seq 1 50); do [[ -S "$sb/traces/.collector.sock" ]] && break; sleep 0.1; done
[[ -S "$sb/traces/.collector.sock" ]] || fail "the collector did not come up under the deep runs directory: $(cat "$TMP/deep-collector.log")"
emit_from_root "$sb" '{"ts":"2026-01-01T00:00:01.000Z","agent":"system","tool":"resume_wake","args":{"agent":"x0"},"result":{"ok":true}}'
tail -n 1 "$sb/traces/events.jsonl" | jq -e '.tool == "resume_wake" and (.prev | type) == "string"' >/dev/null \
  || fail "the shell's line from another directory did not reach the collector: $(tail -n 1 "$sb/traces/events.jsonl")"
(cd / && node --experimental-strip-types --no-warnings --input-type=module -e '
  const P = await import(process.argv[1]);
  await P.traceHarnessEntry(process.argv[2], { seq: 1, kind: "finding", by: "a0", hash: "0".repeat(64) });
' "$ROOT/extensions/protocol.ts" "$sb") || fail "the CLI's harness line failed"
tail -n 1 "$sb/traces/events.jsonl" | jq -e '.tool == "harness_record" and (.prev | type) == "string"' >/dev/null \
  || fail "the CLI's line from another directory did not reach the collector: $(tail -n 1 "$sb/traces/events.jsonl")"
kill "$coll" 2>/dev/null || true
wait "$coll" 2>/dev/null || true
chained_only "$sb" || fail "events.jsonl holds a line the collector did not write: $(cat "$sb/traces/events.jsonl")"
pass "under a runs directory where no socket path fits, the kickoff's line, the shell's and the CLI's reach the collector; a line none took is kept in the spill, and events.jsonl holds only the collector's"

echo "kickoff-guards.test.sh: all checks passed"

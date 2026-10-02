#!/usr/bin/env bash
# `swarm.sh stop` of a microVM run, against a stand-in msb (SWARM_MSB_BIN).
# No model, no Herdr, no VM.
#
# What a stop must not do is say "Stopped" while a VM of the run is still up:
# a run whose VMs are up is not stopped, whatever the record says. And the
# hub's own clear-up after it finished a run keeps the state it recorded.
set -euo pipefail
unset SWARM_ISOLATION SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stop-test.XXXXXX")"
# A stop seals a draft release with the machine key: this suite's, in its own home.
export SWARM_SIGNERS_HOME="$TMP/signers"
cleanup() {
  for p in "${HHP:-}" "${HCP:-}"; do
    [[ -n "$p" ]] && kill -9 "$p" 2>/dev/null || true
  done
  chmod -R u+w "$TMP" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

# Nothing here reaches the operator's own msb database or VM hubs: a finish
# that removes a stand-in VM scrubs msb's database, and the hubs live in a
# directory of the user's own.
export MSB_HOME="$TMP/msb-home"
export SWARM_HUBS_DIR="$TMP/dfirswarm-hubs"
mkdir -p "$MSB_HOME" "$SWARM_HUBS_DIR"

RUNS="$TMP/runs"
SB="$RUNS/sstp1"
mkdir -p "$SB/traces" "$SB/done/agents" "$SB/vm"
printf '{"swarm_id":"sstp1","n":1,"agents":[{"id":"sstp100","role":"worker"}]}\n' > "$SB/team.json"
record() { # <state>
  jq -n --arg sb "$SB" --arg st "$1" '{runs: [{id: "sstp1", label: "stop-test", state: $st, sandbox: $sb, n: 1, isolation: {mode: "microvm", snapshot: false}}]}' > "$RUNS/registry.json"
}

# A stand-in msb: one VM of the run that will not stop.
cat > "$TMP/msb" <<EOF
#!/usr/bin/env bash
case "\$1" in
  list) printf '[{"name":"dfs-sstp1-sstp100","status":"running","labels":{"dev.dfirswarm.run":"sstp1","dev.dfirswarm.agent":"sstp100"}}]\n' ;;
  inspect) printf '{"config":{"labels":{"dev.dfirswarm.run":"sstp1","dev.dfirswarm.agent":"sstp100"}}}\n' ;;
  stop) echo "the VM will not stop" >&2; exit 1 ;;
  --version) echo "msb 0.7.2" ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$TMP/msb"

echo "# jobs are held before Herdr starts closing the panes"
ES="$RUNS/searly1"
EHD="$(cd "$SWARM_HUBS_DIR" && pwd -P)/dfs-searly1.x1"
mkdir -p "$ES/traces" "$EHD" "$TMP/control-bin"
(cd "$ES" && pwd -P) > "$EHD/sandbox"
printf '%s\n' "$EHD" > "$ES/hub.dir"
jq -n --arg sb "$ES" '{runs: [{id: "searly1", state: "running", sandbox: $sb, workspace_ids: ["pane-1"], isolation: {mode: "host"}}]}' > "$RUNS/registry.json"
cat > "$TMP/control-bin/herdr" <<EOF
#!/bin/sh
if [ "\$1 \$2" = "workspace close" ]; then
  test -f "$EHD/.stop" || touch "$TMP/panes-before-hold"
  touch "$TMP/panes-closed"
fi
EOF
chmod +x "$TMP/control-bin/herdr"
out="$(PATH="$TMP/control-bin:$PATH" SWARM_RUNS_DIR="$RUNS" bash "$ROOT/scripts/swarm.sh" stop searly1 --no-custody 2>&1)" || fail "the early hold stop failed: $out"
[[ -f "$TMP/panes-closed" ]] || fail "the stand-in Herdr was not called"
[[ ! -f "$TMP/panes-before-hold" ]] || fail "Herdr closed panes before the hub's jobs were held: $out"
pass "the job hold exists before a potentially slow workspace close"

echo "# a VM that is still up after stop: not stopped, and said so"
record running
set +e
out="$(SWARM_MSB_BIN="$TMP/msb" SWARM_RUNS_DIR="$RUNS" bash "$ROOT/scripts/swarm.sh" stop sstp1 --no-custody 2>&1)"
rc=$?
set -e
[[ $rc -eq 3 ]] || fail "stop with a VM still up exited $rc, wanted 3: $out"
grep -q "NOT STOPPED" <<<"$out" || fail "stop did not say the run is not stopped: $out"
grep -q "Stopped sstp1" <<<"$out" && fail "stop said Stopped with a VM up: $out"
[[ "$(jq -r '.runs[0].state' "$RUNS/registry.json")" == "stop_incomplete" ]] || fail "the record does not say stop_incomplete: $(jq -c '.runs[0]' "$RUNS/registry.json")"
pass "a stop that leaves a VM up exits 3 and records stop_incomplete"

echo "# the hub's own clear-up keeps the state the hub recorded"
cat > "$TMP/msb" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  list) printf '[]\n' ;;
  --version) echo "msb 0.7.2" ;;
  *) exit 0 ;;
esac
EOF
record finished
touch "$SB/done/SWARM_DONE"
out="$(SWARM_MSB_BIN="$TMP/msb" SWARM_RUNS_DIR="$RUNS" bash "$ROOT/scripts/swarm.sh" stop sstp1 --after-hub 2>&1)" || fail "the after-hub stop failed: $out"
[[ "$(jq -r '.runs[0].state' "$RUNS/registry.json")" == "finished" ]] || fail "the after-hub stop changed the hub's state: $(jq -c '.runs[0]' "$RUNS/registry.json")"
grep -q "Custody:.*skipped\|Cleared sstp1 after the hub finished it" <<<"$out" || fail "the after-hub stop did not say what it did: $out"
pass "a stop the hub runs after finishing the run clears up and keeps the state finished"

echo "# a reaped microVM seat has its VM put away, its disk kept"
RS="$TMP/reap-sb"
mkdir -p "$RS/traces" "$RS/done/agents" "$RS/vm" "$RS/locks" "$RS/threads/main"
printf '{"swarm_id":"srp1","n":1,"agents":[{"id":"srp100","role":"worker"}]}\n' > "$RS/team.json"
printf '{"cap_usd":1,"spent_usd":0,"wall_clock_minutes":60,"started_at":"2026-01-01T00:00:00Z","agents":{}}\n' > "$RS/budget.json"
printf '{"agent":"srp100","name":"dfs-srp1-srp100","run":"srp1"}\n' > "$RS/vm/srp100.json"
: > "$RS/traces/events.jsonl"
HUBS="$SWARM_HUBS_DIR"
mkdir -p "$HUBS/dfs-srp1.x1"
chmod 700 "$HUBS"
(cd "$RS" && pwd -P) > "$HUBS/dfs-srp1.x1/sandbox"
printf '{"agents":{"srp100":{"state":"idle"}}}\n' > "$HUBS/dfs-srp1.x1/status.json"
(cd "$HUBS/dfs-srp1.x1" && pwd -P) > "$RS/hub.dir"
cat > "$TMP/msb" <<EOF
#!/usr/bin/env bash
printf '%s\\n' "\$*" >> "$TMP/msb-calls.log"
case "\$1" in
  list) printf '[{"name":"dfs-srp1-srp100","status":"running","labels":{"dev.dfirswarm.run":"srp1","dev.dfirswarm.agent":"srp100"}}]\\n' ;;
  exec) printf '{"baseline":true,"apt":{},"venv":{}}\\n' ;;
  snapshot) for a in "\$@"; do [[ "\$prev" == "-o" ]] && printf 'disk' > "\$a"; prev="\$a"; done ;;
  --version) echo "msb 0.7.2" ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$TMP/msb"
out="$(TMPDIR="$TMP" SWARM_MSB_BIN="$TMP/msb" HERDR_BIN=/usr/bin/false PATH="/usr/bin:/bin:$(dirname "$(command -v node)"):$(dirname "$(command -v jq)")" bash "$ROOT/scripts/reap.sh" --sandbox "$RS" --timeout 1 --stop 2>&1)" || true
[[ -f "$RS/done/agents/srp100.dead" ]] || fail "the silent seat was not reaped: $out"
grep -q "^stop dfs-srp1-srp100" "$TMP/msb-calls.log" 2>/dev/null || fail "the reaped seat's VM was not stopped: $(cat "$TMP/msb-calls.log" 2>/dev/null); $out"
grep -q "^snapshot create" "$TMP/msb-calls.log" || fail "the reaped seat's disk was not kept"
grep -q "VM of srp100 put away" <<<"$out" || fail "the reaper did not say the VM was put away: $out"
pass "a reaped microVM seat has its VM stopped and its disk kept, as stop would"

echo "# a stop from a shell with another TMPDIR still ends the hub, its keeper and its directory"
TS="$RUNS/stmp1"
mkdir -p "$TS/traces" "$TS/done/agents" "$TS/vm"
printf '{"swarm_id":"stmp1","n":1,"agents":[{"id":"stmp100","role":"worker"}]}\n' > "$TS/team.json"
jq -n --arg sb "$TS" '{runs: [{id: "stmp1", label: "tmpdir", state: "running", sandbox: $sb, n: 1, isolation: {mode: "microvm", snapshot: false}}]}' > "$RUNS/registry.json"
HD="$(cd "$SWARM_HUBS_DIR" && pwd -P)/dfs-stmp1.x1"
mkdir -p "$HD"
(cd "$TS" && pwd -P) > "$HD/sandbox"
printf '{"finished":false}\n' > "$HD/status.json"
printf '{}\n' > "$HD/hub-input.json"
printf '%s\n' "$HD" > "$TS/hub.dir"
bash -c "exec -a 'node vm-hub.ts $TS --dir $HD' sleep 300" &
HUB=$!
disown "$HUB" 2>/dev/null || true
bash -c "exec -a 'bash hub-supervise.sh $TS' sleep 300" &
KEEP=$!
disown "$KEEP" 2>/dev/null || true
echo "$HUB" > "$TS/hub.pid"
echo "$KEEP" > "$HD/supervisor.pid"
cat > "$TMP/msb" <<'EOF2'
#!/usr/bin/env bash
case "$1" in
  list) printf '[]\n' ;;
  --version) echo "msb 0.7.2" ;;
  *) exit 0 ;;
esac
EOF2
chmod +x "$TMP/msb"
sleep 0.3
mkdir -p "$TMP/other-tmp"
out="$(TMPDIR="$TMP/other-tmp" SWARM_MSB_BIN="$TMP/msb" SWARM_RUNS_DIR="$RUNS" bash "$ROOT/scripts/swarm.sh" stop stmp1 --no-custody 2>&1)" || fail "the stop failed: $out"
alive=""
kill -0 "$HUB" 2>/dev/null && alive="the hub"
kill -0 "$KEEP" 2>/dev/null && alive="$alive the keeper"
kill "$HUB" "$KEEP" 2>/dev/null || true
[[ -z "$alive" ]] || fail "a stop with another TMPDIR left$alive running: $out"
[[ ! -d "$HD" ]] || fail "a stop with another TMPDIR left the hub's directory (its tokens): $out"
pass "a stop from a shell with another TMPDIR finds the hub, ends it and its keeper, and removes its directory"

echo "# a disk is never lost to a full disk or a failed second snapshot"
FS="$RUNS/sfs1"
mkdir -p "$FS/vm" "$FS/traces"
printf '{"agent":"sfs100","name":"dfs-sfs1-sfs100","run":"sfs1"}\n' > "$FS/vm/sfs100.json"
cat > "$TMP/msb" <<EOF2
#!/usr/bin/env bash
printf '%s\\n' "\$*" >> "$TMP/fs-calls.log"
case "\$1" in
  list) printf '[{"name":"dfs-sfs1-sfs100","status":"running","labels":{"dev.dfirswarm.run":"sfs1","dev.dfirswarm.agent":"sfs100"}}]\\n' ;;
  exec) printf '{"baseline":true,"apt":{},"venv":{}}\\n' ;;
  snapshot) [[ -n "\${SNAP_FAIL:-}" ]] && { echo "no room for the disk" >&2; exit 1; }; for a in "\$@"; do [[ "\$prev" == "-o" ]] && printf 'disk-v2' > "\$a"; prev="\$a"; done ;;
  --version) echo "msb 0.7.2" ;;
  *) exit 0 ;;
esac
EOF2
chmod +x "$TMP/msb"
: > "$TMP/fs-calls.log"
out="$(SWARM_MSB_BIN="$TMP/msb" SWARM_SNAPSHOT_MIN_FREE_BYTES=1000000000000000000 node --experimental-strip-types --no-warnings "$ROOT/scripts/vm.ts" finish --run sfs1 --sandbox "$FS" 2>&1)" && fail "a finish with no room reported success: $out"
grep -q '^snapshot' "$TMP/fs-calls.log" && fail "a snapshot was attempted with no room for it: $(cat "$TMP/fs-calls.log")"
grep -q '^rm ' "$TMP/fs-calls.log" && fail "a VM whose disk could not be kept was removed: $(cat "$TMP/fs-calls.log")"
jq -e '.snapshot.error | test("bytes free")' "$FS/vm/sfs100.json" >/dev/null || fail "the record does not say why the disk was not kept: $(cat "$FS/vm/sfs100.json")"
pass "below the free-space floor the VM is kept, not snapshotted and not removed, and its record says why"
# A disk an earlier finish kept stays when a second attempt fails.
mkdir -p "$FS.vm-snapshots"
printf 'disk-v1' > "$FS.vm-snapshots/sfs100.msb"
jq '.snapshot = {path: "'"$FS.vm-snapshots/sfs100.msb"'", sha256: "x", bytes: 7, integrity: true}' "$FS/vm/sfs100.json" > "$FS/vm/r.tmp" && mv "$FS/vm/r.tmp" "$FS/vm/sfs100.json"
: > "$TMP/fs-calls.log"
out="$(SNAP_FAIL=1 SWARM_MSB_BIN="$TMP/msb" SWARM_SNAPSHOT_MIN_FREE_BYTES=1 node --experimental-strip-types --no-warnings "$ROOT/scripts/vm.ts" finish --run sfs1 --sandbox "$FS" 2>&1)" && fail "a failed snapshot reported success: $out"
[[ "$(cat "$FS.vm-snapshots/sfs100.msb" 2>/dev/null)" == "disk-v1" ]] || fail "the disk an earlier finish kept was deleted by a failed second snapshot"
[[ "$(jq -r '.snapshot.path' "$FS/vm/sfs100.json")" == "$FS.vm-snapshots/sfs100.msb" ]] || fail "the record lost the earlier disk: $(cat "$FS/vm/sfs100.json")"
jq -e '.snapshot_retry_error | test("no room")' "$FS/vm/sfs100.json" >/dev/null || fail "the failed retry is not on the record"
grep -q '^rm ' "$TMP/fs-calls.log" && fail "the VM was removed after its snapshot failed"
# And a second attempt that works replaces it.
out="$(SWARM_MSB_BIN="$TMP/msb" SWARM_SNAPSHOT_MIN_FREE_BYTES=1 node --experimental-strip-types --no-warnings "$ROOT/scripts/vm.ts" finish --run sfs1 --sandbox "$FS" 2>&1)" || fail "a working second snapshot failed: $out"
[[ "$(cat "$FS.vm-snapshots/sfs100.msb")" == "disk-v2" && ! -e "$FS.vm-snapshots/sfs100.msb.new" ]] || fail "the new disk did not replace the earlier one"
jq -e '(.snapshot_retry_error | not) and (.msb_db != null)' "$FS/vm/sfs100.json" >/dev/null || fail "the record after the retry: $(cat "$FS/vm/sfs100.json")"
pass "a disk an earlier finish kept survives a failed second snapshot, and a working one replaces it; the record carries the msb database's outcome"

echo "# a custody that could not run does not pass an earlier verdict off as this stop's"
CS="$RUNS/scus1"
mkdir -p "$CS/traces"
printf '{"swarm_id":"scus1","n":1,"agents":[{"id":"scus100","role":"worker"}]}\n' > "$CS/team.json"
printf '{"at":"2020-01-01T00:00:00.000Z","summary":"OLD VERDICT FROM AN EARLIER STOP"}\n' > "$CS/custody.json"
jq -n --arg sb "$CS" '{runs: [{id: "scus1", label: "custody", state: "running", sandbox: $sb, n: 1, isolation: {mode: "host"}}]}' > "$RUNS/registry.json"
# traces/ not writable: custody's own log cannot be opened, so custody never runs.
chmod a-w "$CS/traces"
out="$(SWARM_RUNS_DIR="$RUNS" bash "$ROOT/scripts/swarm.sh" stop scus1 --custody-timeout 30 2>&1)" || true
chmod u+w "$CS/traces"
grep -q 'Custody: *OLD VERDICT' <<<"$out" && fail "stop printed an earlier verdict as this stop's: $out"
grep -q "the custody check did not finish" <<<"$out" || fail "stop did not say custody did not finish: $out"
grep -q "an earlier one (2020-01-01" <<<"$out" || fail "stop did not say the verdict on disk is an earlier one: $out"
grep -q "nothing of run scus1 was alive" <<<"$out" || fail "a run recorded as running with nothing alive was not said to have crashed or lost its host: $out"
pass "a custody that did not run is said, and the verdict left from an earlier stop is named as that; a run with nothing alive is said to have crashed or lost its host"

echo "# a run on hold keeps its VMs from the reaper"
HR="$TMP/hold-runs"
mkdir -p "$HR/shd1"
jq -n --arg sb "$HR/shd1" '{runs: [{id: "shd1", label: "held", state: "stopped", sandbox: $sb, n: 1, hold: {reason: "matter", at: "t", by: "x"}}]}' > "$HR/registry.json"
label="$(node --experimental-strip-types --no-warnings -e 'import(process.argv[2]).then((V) => console.log(V.registryLabel(process.argv[3])))' -- x "$ROOT/scripts/vm.ts" "$HR/registry.json")"
: > "$TMP/msb-hold.log"
cat > "$TMP/msb" <<EOF
#!/usr/bin/env bash
printf '%s\\n' "\$*" >> "$TMP/msb-hold.log"
case "\$1" in
  list) printf '[{"name":"dfs-shd1-shd100","status":"stopped","labels":{"dev.dfirswarm.run":"shd1","dev.dfirswarm.agent":"shd100","dev.dfirswarm.registry":"$label"}}]\\n' ;;
  inspect) printf '{"config":{"labels":{"dev.dfirswarm.run":"shd1","dev.dfirswarm.agent":"shd100","dev.dfirswarm.registry":"$label"}}}\\n' ;;
  --version) echo "msb 0.7.2" ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$TMP/msb"
out="$(SWARM_MSB_BIN="$TMP/msb" node --experimental-strip-types --no-warnings "$ROOT/scripts/vm.ts" reap --registry "$HR/registry.json" 2>&1)" || fail "reap failed: $out"
grep -q '^stop dfs-shd1\|^rm dfs-shd1\|^snapshot' "$TMP/msb-hold.log" && fail "the reaper touched a held run's VM: $(cat "$TMP/msb-hold.log")"
# Released, the same VM is the reaper's.
jq '.runs[0].hold = null' "$HR/registry.json" > "$HR/r" && mv "$HR/r" "$HR/registry.json"
out="$(SWARM_MSB_BIN="$TMP/msb" node --experimental-strip-types --no-warnings "$ROOT/scripts/vm.ts" reap --registry "$HR/registry.json" 2>&1)" || true
grep -q '^rm dfs-shd1-shd100\|^snapshot' "$TMP/msb-hold.log" || fail "a released run's VM was not reaped: $(cat "$TMP/msb-hold.log")"
pass "a held run's VM is left alone by the reaper, and reaped once released"

echo "# a job's worker started behind the stop: the hub is waited for, the worker removed, its staging sealed, and the run not stop_incomplete"
# The Breadcrumbs run: a job's worker was up when the stop counted the VMs,
# the hub was removing it, and the stop said stop_incomplete; the hub went
# with that job's staging unsealed. <case> is "hub" (the hub removes the
# worker on its way out) or "stop" (it leaves it; the stop's second finish does).
job_race() { # <run id> <case>
  local id="$1" how="$2" JS JD HUBP out
  JS="$RUNS/$id"
  rm -rf "$JS" "$JS.staging"
  mkdir -p "$JS/traces" "$JS/done/agents" "$JS/vm"
  printf '{"swarm_id":"%s","n":1,"agents":[{"id":"%s00","role":"worker"}]}\n' "$id" "$id" > "$JS/team.json"
  jq -n --arg sb "$JS" --arg id "$id" '{runs: [{id: $id, label: "job race", state: "running", sandbox: $sb, n: 1, isolation: {mode: "microvm", snapshot: false}}]}' > "$RUNS/registry.json"
  # The journal as the hub left it: the job finished, its worker not confirmed gone.
  node --experimental-strip-types --no-warnings --input-type=module -e "
    import { Journal } from '$ROOT/scripts/evidence-store.ts';
    const j = await Journal.open(process.argv[1]);
    await j.append({ type: 'job_accepted', job: 'j000001', spec: { kind: 'command', command: 'printf x', inputs: [], timeout_seconds: 60, network: 'off' }, requester: { agent: '${id}00' } });
    await j.append({ type: 'job_started', job: 'j000001', attempt: 1, worker: 'dfs-$id-job-j000001-1', image: 'img:test' });
    await j.append({ type: 'job_finished', job: 'j000001', attempt: 1, exit: null, status: 'cancelled', reason: 'cancelled by the harness' });
    await j.append({ type: 'job_fenced', job: 'j000001', attempt: 1, fenced: false, error: 'msb could not say whether dfs-$id-job-j000001-1 is gone: exit 1' });
  " "$JS" || fail "the journal could not be written"
  mkdir -p "$JS.staging/j000001-1/out" "$JS.staging/j000001-1/job"
  printf 'partial' > "$JS.staging/j000001-1/out/x"
  printf 'its log\n' > "$JS.staging/j000001-1/job/stderr.log"
  : > "$JS.staging/j000001-1/job/stdout.log"
  # The worker, up until something removes it, and made just after the stop's
  # first finish looked (msb's first list is that finish's): behind it.
  printf 'up' > "$TMP/$id.worker"
  rm -f "$TMP/$id.lists"
  cat > "$TMP/msb" <<MSB
#!/usr/bin/env bash
W="$TMP/$id.worker"
case "\$1" in
  list) n=\$(( \$(cat "$TMP/$id.lists" 2>/dev/null || echo 0) + 1 )); echo "\$n" > "$TMP/$id.lists"
    if [[ "\$n" -gt 1 && -f "\$W" ]]; then printf '[{"name":"dfs-$id-job-j000001-1","status":"running","labels":{"dev.dfirswarm.run":"$id","dev.dfirswarm.agent":"job-j000001","dev.dfirswarm.kind":"worker"}}]\\n'; else printf '[]\\n'; fi ;;
  inspect) if [[ -f "\$W" ]]; then printf '{"config":{"labels":{"dev.dfirswarm.run":"$id","dev.dfirswarm.kind":"worker"}}}\\n'; else echo "error: sandbox not found" >&2; exit 1; fi ;;
  rm) rm -f "\$W" ;;
  --version) echo "msb 0.7.2" ;;
  *) exit 0 ;;
esac
MSB
  chmod +x "$TMP/msb"
  # The hub: asked to go, it takes a moment (its job service at work), and in the "hub" case removes the worker.
  JD="$(cd "$SWARM_HUBS_DIR" && pwd -P)/dfs-$id.x1"
  mkdir -p "$JD/fake"
  (cd "$JS" && pwd -P) > "$JD/sandbox"
  printf '{"finished":false}\n' > "$JD/status.json"
  printf '%s\n' "$JD" > "$JS/hub.dir"
  cat > "$JD/fake/vm-hub.ts" <<HUB
#!/usr/bin/env bash
trap 'sleep 1; [[ "$how" == hub ]] && rm -f "$TMP/$id.worker"; exit 0' TERM
while :; do sleep 0.1; done
HUB
  chmod +x "$JD/fake/vm-hub.ts"
  bash "$JD/fake/vm-hub.ts" "$JD" &
  HUBP=$!
  disown "$HUBP" 2>/dev/null || true
  echo "$HUBP" > "$JS/hub.pid"
  sleep 0.3
  out="$(SWARM_MSB_BIN="$TMP/msb" SWARM_RUNS_DIR="$RUNS" SWARM_STOP_JOB_VM_WAIT_SEC=10 bash "$ROOT/scripts/swarm.sh" stop "$id" --no-custody 2>&1)" || fail "the stop ($how) failed: $out"
  kill -0 "$HUBP" 2>/dev/null && { kill "$HUBP"; fail "the stop ($how) did not wait for the hub to go: $out"; }
  grep -q "NOT STOPPED" <<<"$out" && fail "the stop ($how) said NOT STOPPED for a worker that went: $out"
  [[ "$(jq -r '.runs[0].state' "$RUNS/registry.json")" == "stopped" ]] || fail "the record ($how) says $(jq -r '.runs[0].state' "$RUNS/registry.json"): $out"
  [[ ! -e "$JS.staging/j000001-1" ]] || fail "the job's staging ($how) is left unsealed: $out"
  grep -q "job staging j000001-1: sealed (j000001, cancelled)" <<<"$out" || fail "the stop ($how) did not say it sealed the staging: $out"
  [[ "$(cat "$JS/store/jobs/j000001/out/x")" == partial ]] || fail "the partial output ($how) is not in the store"
  [[ "$(cat "$JS/store/jobs/j000001/stderr.log")" == "its log" ]] || fail "the job's log ($how) is not kept"
  node --experimental-strip-types --no-warnings "$ROOT/scripts/evidence-store.ts" verify "$JS" >/dev/null || fail "the journal ($how) does not verify"
  [[ "$(jq -sr '[.[] | select(.job == "j000001") | .type + (if .by then ":" + .by else "" end)] | join(",")' "$JS/store/journal.jsonl")" == "job_accepted,job_started,job_finished,job_fenced,job_fenced:stop,job_committed" ]] \
    || fail "the journal ($how) says: $(jq -sc '[.[] | select(.job == "j000001") | .type]' "$JS/store/journal.jsonl")"
  if [[ "$how" == stop ]]; then
    grep -q "a job's worker is still listed: removing it now that the hub has gone" <<<"$out" || fail "the stop did not say it removed the worker the hub left: $out"
  fi
  return 0
}
job_race sjrh1 hub
pass "a worker the hub removes on its way out is waited for, not called left up; its staging is sealed after the hub has gone"
job_race sjrs1 stop
pass "a worker the hub leaves is removed by the stop's second finish within the bound; its staging is sealed"

echo "# the harness's lines spilled once the collector was down are chained by the stop, its own line among them"
GS="$RUNS/sgat1"
mkdir -p "$GS/traces" "$GS/done/agents"
printf '{"swarm_id":"sgat1","n":1,"agents":[{"id":"sgat100","role":"worker"}]}\n' > "$GS/team.json"
jq -n --arg sb "$GS" '{runs: [{id: "sgat1", label: "gather", state: "stopped", sandbox: $sb, n: 1, isolation: {mode: "host"}}]}' > "$RUNS/registry.json"
: > "$GS/traces/events.jsonl"
GA="$(cd "$RUNS" && pwd -P)/sgat1.trace-anchor.json"
jq -nc --arg sb "$GS" '{sandbox: $sb, lines: 0, head: "", prev_head: "", pending: false}' > "$GA"
# A reap after the collector had gone, as on the Breadcrumbs run.
printf '{"ts":"2026-10-01T16:17:50.000Z","agent":"system","tool":"operator_action","args":{"command":"reap","argv":["sgat1","--stop"],"via":"cli"},"result":{"ok":true}}\n' > "$GS/traces/system-spill.jsonl"
out="$(SWARM_RUNS_DIR="$RUNS" bash "$ROOT/scripts/swarm.sh" stop sgat1 --no-custody 2>&1)" || fail "the stop failed: $out"
grep -q "Trace: *2 spilled line(s) chained (traces/system-spill.jsonl)" <<<"$out" || fail "the stop did not chain the spilled lines: $out"
[[ ! -s "$GS/traces/system-spill.jsonl" ]] || fail "lines are left outside the chain: $(cat "$GS/traces/system-spill.jsonl")"
[[ "$(jq -sr '[.[] | .args.command + ":" + (.gathered.from // "")] | join(",")' "$GS/traces/events.jsonl")" == "reap:traces/system-spill.jsonl,stop:traces/system-spill.jsonl" ]] \
  || fail "the chain does not hold the reap and this stop: $(cat "$GS/traces/events.jsonl")"
[[ "$(wc -l < "$GS/traces/system-spill.gathered.jsonl" | tr -d ' ')" == 2 ]] || fail "the spilled lines are not kept whole beside the trace"
[[ "$(jq -r '.lines' "$GA")" == 2 ]] || fail "the anchor did not move with the chain: $(cat "$GA")"
pass "a stop chains the lines spilled while the collector was down, its own line among them, and keeps them whole beside the trace"

echo "# a hub that does not go within the bound keeps its files, the run is not stopped, and the next stop seals after it"
# A stop that gave up on its hub used to drop hub.pid, hub.dir and the hub's
# directory: the next stop then could not see the hub and sealed the job's
# staging beside it, two writers on the journal.
HS="$RUNS/shng1"
rm -rf "$HS" "$HS.staging"
mkdir -p "$HS/traces" "$HS/done/agents" "$HS/vm"
printf '{"swarm_id":"shng1","n":1,"agents":[{"id":"shng100","role":"worker"}]}\n' > "$HS/team.json"
jq -n --arg sb "$HS" '{runs: [{id: "shng1", label: "hung hub", state: "running", sandbox: $sb, n: 1, isolation: {mode: "microvm", snapshot: false}}]}' > "$RUNS/registry.json"
node --experimental-strip-types --no-warnings --input-type=module -e "
  import { Journal } from '$ROOT/scripts/evidence-store.ts';
  const j = await Journal.open(process.argv[1]);
  await j.append({ type: 'job_accepted', job: 'j000001', spec: { kind: 'command', command: 'printf x', inputs: [], timeout_seconds: 60, network: 'off' }, requester: { agent: 'shng100' } });
  await j.append({ type: 'job_started', job: 'j000001', attempt: 1, worker: 'dfs-shng1-job-j000001-1', image: 'img:test' });
  await j.append({ type: 'job_finished', job: 'j000001', attempt: 1, exit: null, status: 'cancelled', reason: 'cancelled by the harness' });
  await j.append({ type: 'job_fenced', job: 'j000001', attempt: 1, fenced: false, error: 'msb could not say' });
" "$HS" || fail "the journal could not be written"
mkdir -p "$HS.staging/j000001-1/out" "$HS.staging/j000001-1/job"
printf 'partial' > "$HS.staging/j000001-1/out/x"
cat > "$TMP/msb" <<'MSB'
#!/usr/bin/env bash
case "$1" in
  list) printf '[]\n' ;;
  inspect) echo "error: sandbox not found" >&2; exit 1 ;;
  --version) echo "msb 0.7.2" ;;
  *) exit 0 ;;
esac
MSB
chmod +x "$TMP/msb"
HHD="$(cd "$SWARM_HUBS_DIR" && pwd -P)/dfs-shng1.x1"
mkdir -p "$HHD/fake"
(cd "$HS" && pwd -P) > "$HHD/sandbox"
printf '{"finished":true,"finish_done":false}\n' > "$HHD/status.json"
printf '%s\n' "$HHD" > "$HS/hub.dir"
# A hub that does not go when asked (its job service stuck on msb).
cat > "$HHD/fake/vm-hub.ts" <<'HUB'
#!/usr/bin/env bash
trap '' TERM
while :; do sleep 0.1; done
HUB
chmod +x "$HHD/fake/vm-hub.ts"
bash "$HHD/fake/vm-hub.ts" "$HS" --dir "$HHD" &
HHP=$!
disown "$HHP" 2>/dev/null || true
echo "$HHP" > "$HS/hub.pid"
# The collector and mounted evidence must outlive an incomplete stop too.
cat > "$HHD/fake/trace-collector.mjs" <<'COLLECTOR'
#!/usr/bin/env bash
trap 'exit 0' TERM
while :; do sleep 0.1; done
COLLECTOR
bash "$HHD/fake/trace-collector.mjs" "$HS" &
HCP=$!
disown "$HCP" 2>/dev/null || true
echo "$HCP" > "$HS/collector.pid"
printf 'test-evidence-device\n' > "$HS/inputs.device"
printf '{"at":"2020-01-01T00:00:00.000Z","summary":"earlier verdict"}\n' > "$HS/custody.json"
hung_fail() { kill -9 "$HHP" "$HCP" 2>/dev/null || true; fail "$*"; }
sleep 0.3
set +e
out="$(SWARM_MSB_BIN="$TMP/msb" SWARM_RUNS_DIR="$RUNS" SWARM_STOP_HUB_WAIT_SEC=1 SWARM_STOP_HUB_EXIT_SEC=1 bash "$ROOT/scripts/swarm.sh" stop shng1 --custody-timeout 30 2>&1)"
rc=$?
set -e
kill -0 "$HCP" 2>/dev/null || hung_fail "the incomplete stop ended the live hub's collector: $out"
[[ -f "$HS/collector.pid" && -f "$HS/inputs.device" ]] || hung_fail "the incomplete stop removed its collector or evidence mount record: $out"
[[ "$(jq -r '.at' "$HS/custody.json")" == "2020-01-01T00:00:00.000Z" ]] || hung_fail "custody ran beside a live hub: $out"
[[ ! -f "$HS/done/STOPPED" ]] || hung_fail "the incomplete stop wrote a stopped outcome"
[[ ! -d "$HS/release" ]] || hung_fail "a draft release was sealed beside the live hub"
grep -q "the hub is putting the VMs away itself; waiting for it" <<<"$out" || hung_fail "the stop did not wait for a hub already finishing: $out"
grep -q 'Custody:.*re-hashing\|sealing the draft\|Trace:.*chained' <<<"$out" && hung_fail "the incomplete stop ran finalisation: $out"
kill -0 "$HHP" 2>/dev/null || fail "the stand-in hub went (it should not have): $out"
[[ $rc -eq 3 ]] || { kill -9 "$HHP"; fail "a stop whose hub stayed up exited $rc, wanted 3: $out"; }
grep -q "did not exit within 1s of being asked" <<<"$out" || { kill -9 "$HHP"; fail "the stop did not say the hub stayed: $out"; }
[[ "$(jq -r '.runs[0].state' "$RUNS/registry.json")" == "stop_incomplete" ]] || { kill -9 "$HHP"; fail "the record says $(jq -r '.runs[0].state' "$RUNS/registry.json")"; }
[[ -f "$HS/hub.pid" && -f "$HS/hub.dir" && -d "$HHD" ]] || { kill -9 "$HHP"; fail "the hub's files were dropped while it may still write: $out"; }
[[ -d "$HS.staging/j000001-1" ]] || { kill -9 "$HHP"; fail "the staging was sealed beside a live hub: $out"; }
# A missing or stale pid file is not proof that the hub has gone. Find it
# by its process command line even when there is no staging to seal.
printf '{"finished":false}\n' > "$HHD/status.json"
for pid_state in missing stale; do
  if [[ "$pid_state" == missing ]]; then
    rm -f "$HS/hub.pid"
    mv "$HS.staging" "$HS.saved-staging"
  else
    printf '99999999\n' > "$HS/hub.pid"
  fi
  set +e
  out="$(SWARM_MSB_BIN="$TMP/msb" SWARM_RUNS_DIR="$RUNS" SWARM_STOP_HUB_EXIT_SEC=1 bash "$ROOT/scripts/swarm.sh" stop shng1 --custody-timeout 30 2>&1)"
  rc=$?
  set -e
  [[ "$pid_state" == missing ]] && mv "$HS.saved-staging" "$HS.staging"
  [[ $rc -eq 3 ]] || hung_fail "a live hub with a $pid_state pid file was finalised (rc $rc): $out"
  kill -0 "$HCP" 2>/dev/null || hung_fail "a $pid_state hub pid file let the stop end its collector: $out"
  [[ -f "$HS/inputs.device" && -d "$HHD" && ! -f "$HS/done/STOPPED" && ! -d "$HS/release" ]] || hung_fail "a $pid_state hub pid file let the stop finalise: $out"
  [[ "$(jq -r '.at' "$HS/custody.json")" == "2020-01-01T00:00:00.000Z" ]] || hung_fail "custody ran with a $pid_state hub pid file: $out"
done
# A failed process lookup cannot establish that the writer has gone.
mkdir -p "$TMP/no-ps"
printf '#!/bin/sh\nexit 1\n' > "$TMP/no-ps/ps"
chmod +x "$TMP/no-ps/ps"
rm -f "$HS/hub.pid"
set +e
out="$(PATH="$TMP/no-ps:$PATH" SWARM_MSB_BIN="$TMP/msb" SWARM_RUNS_DIR="$RUNS" bash "$ROOT/scripts/swarm.sh" stop shng1 --custody-timeout 30 2>&1)"
rc=$?
set -e
[[ $rc -eq 3 ]] || hung_fail "a failed hub process lookup allowed finalisation (rc $rc): $out"
grep -q "the run's hub could not be checked" <<<"$out" || hung_fail "a failed hub lookup was not said: $out"
kill -0 "$HCP" 2>/dev/null || hung_fail "a failed hub process lookup ended its collector: $out"
[[ -f "$HS/inputs.device" && -d "$HHD" && ! -f "$HS/done/STOPPED" && ! -d "$HS/release" ]] || hung_fail "a failed hub process lookup finalised the run: $out"
[[ "$(jq -r '.at' "$HS/custody.json")" == "2020-01-01T00:00:00.000Z" ]] || hung_fail "custody ran after a failed hub process lookup: $out"
sl="$(PATH="$TMP/no-ps:$PATH" SWARM_MSB_BIN="$TMP/msb" node --experimental-strip-types --no-warnings "$ROOT/scripts/vm.ts" seal-left --sandbox "$HS" 2>/dev/null)" && hung_fail "seal-left allowed a failed hub lookup: $sl"
grep -q "ps failed" <<<"$sl" || hung_fail "seal-left did not report its failed hub lookup: $sl"
# seal-left on its own refuses too, whatever hub.pid says.
rm -f "$HS/hub.pid"
sl="$(SWARM_MSB_BIN="$TMP/msb" node --experimental-strip-types --no-warnings "$ROOT/scripts/vm.ts" seal-left --sandbox "$HS" 2>/dev/null)" && { kill -9 "$HHP"; fail "seal-left sealed beside a live hub: $sl"; }
grep -q "is still up" <<<"$sl" || { kill -9 "$HHP"; fail "seal-left did not say the hub is up: $sl"; }
echo "$HHP" > "$HS/hub.pid"
kill -9 "$HHP"
sleep 0.3
out="$(SWARM_MSB_BIN="$TMP/msb" SWARM_RUNS_DIR="$RUNS" bash "$ROOT/scripts/swarm.sh" stop shng1 --no-custody 2>&1)" || fail "the second stop failed: $out"
kill -0 "$HCP" 2>/dev/null && hung_fail "the second stop left its collector running: $out"
[[ ! -f "$HS/inputs.device" ]] || fail "the second stop did not detach its evidence"
[[ "$(jq -r '.runs[0].state' "$RUNS/registry.json")" == "stopped" ]] || fail "the second stop's record says $(jq -r '.runs[0].state' "$RUNS/registry.json"): $out"
[[ ! -e "$HS.staging/j000001-1" && "$(cat "$HS/store/jobs/j000001/out/x")" == partial ]] || fail "the second stop did not seal the staging: $out"
[[ ! -d "$HHD" && ! -f "$HS/hub.dir" ]] || fail "the hub's directory outlived the hub: $out"
HHP="" HCP=""
pass "a hub that stays up keeps its pid file and directory, the run is stop_incomplete, seal-left refuses beside it, and the stop after it seals the staging"

echo "# an error sealing staging cannot be swallowed before finalisation"
BS="$RUNS/sbad1"
mkdir -p "$BS/traces" "$BS/store/journal.jsonl" "$BS.staging/unsealed"
printf 'partial\n' > "$BS.staging/unsealed/out"
jq -n --arg sb "$BS" '{runs: [{id: "sbad1", state: "running", sandbox: $sb, isolation: {mode: "microvm", snapshot: false}}]}' > "$RUNS/registry.json"
set +e
out="$(SWARM_MSB_BIN="$TMP/msb" SWARM_RUNS_DIR="$RUNS" bash "$ROOT/scripts/swarm.sh" stop sbad1 --custody-timeout 30 2>&1)"
rc=$?
set -e
[[ $rc -eq 3 ]] || fail "an unreadable journal was finalised (rc $rc): $out"
[[ "$(jq -r '.runs[0].state' "$RUNS/registry.json")" == "stop_incomplete" ]] || fail "a failed seal did not record stop_incomplete"
[[ ! -f "$BS/custody.json" && ! -d "$BS/release" && ! -f "$BS/done/STOPPED" ]] || fail "a failed seal ran finalisation: $out"
pass "a seal-left error defers finalisation and keeps staging for a retry"

echo "stop.test.sh: all checks passed"

#!/usr/bin/env bash
# The kickoff's and stop's housekeeping, taken from the script itself: the
# registry written by several writers at once, the host kept awake for a run
# and let go at stop.
#
# What must not go wrong: two writers of the registry must never lose each
# other's change (the hub and a stop, two kickoffs); a stale lock left by a
# writer that died must not block the next one for ever; the process that
# keeps the host awake must stop with the run, and a pid file that names
# something else must not stop that.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/lifecycle.XXXXXX")"
# The VM hubs' directory is the test's own: never the operator's.
HUBS_TMP="$(mktemp -d /tmp/dfh.XXXXXX)"
export SWARM_HUBS_DIR="$HUBS_TMP/dfirswarm-hubs"
PIDS=()
cleanup() { local p; for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null; done; rm -rf "$TMP" "$HUBS_TMP"; }
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

fn() { sed -n "/^$1() {/,/^}/p" "$ROOT/scripts/swarm.sh"; }
for f in ensure_registry registry_lock registry_unlock registry_upsert registry_update_state detach_exec keep_host_awake stop_sandbox_daemons hub_dir_of hubs_parent hub_pid_ours; do
  eval "$(fn "$f")"
  type "$f" >/dev/null 2>&1 || fail "$f was not found in swarm.sh"
done

# --- the registry, written by many at once ------------------------------------
RUNS_DIR="$TMP/runs"
REGISTRY="$RUNS_DIR/registry.json"
ensure_registry
for i in $(seq 1 12); do
  ( registry_upsert "{\"id\":\"s$i\",\"state\":\"running\"}" ) &
done
wait
[[ "$(jq '.runs | length' "$REGISTRY")" == 12 ]] || fail "concurrent upserts lost a run: $(jq -c '[.runs[].id]' "$REGISTRY")"
for i in $(seq 1 12); do
  ( registry_update_state "s$i" stopped ) &
done
wait
[[ "$(jq '[.runs[] | select(.state == "stopped")] | length' "$REGISTRY")" == 12 ]] || fail "concurrent state changes lost one: $(jq -c '[.runs[].state]' "$REGISTRY")"
[[ ! -d "$REGISTRY.lock" ]] || fail "the lock was left behind"
ls "$RUNS_DIR" | grep -q 'registry.json.tmp' && fail "a temporary registry was left behind"
pass "twelve writers at once lose nothing, and leave no lock or temporary file"

# A lock a writer left when it died goes stale after a minute.
mkdir "$REGISTRY.lock"
touch -t "$(date -v-5M +%Y%m%d%H%M 2>/dev/null || date -d '5 minutes ago' +%Y%m%d%H%M)" "$REGISTRY.lock"
registry_update_state s1 done || fail "a stale lock blocked the writer"
[[ "$(jq -r '.runs[] | select(.id == "s1") | .state' "$REGISTRY")" == done ]] || fail "the write after a stale lock did not land"
pass "a lock left by a writer that died does not block the next"

# --- the host kept awake, for the run and no longer -----------------------------
if command -v caffeinate >/dev/null 2>&1 || command -v systemd-inhibit >/dev/null 2>&1; then
  mkdir -p "$TMP/sb"
  out="$(keep_host_awake "$TMP/sb" 1 2>&1)"
  pid="$(cat "$TMP/sb/inhibit.pid" 2>/dev/null)"
  if [[ -z "$pid" ]]; then
    # The system refused the inhibitor (systemd-inhibit with no login
    # session): said as such, never claimed.
    printf '%s\n' "$out" | grep -q "could not be kept from sleeping" || fail "an inhibitor that died was not said: $out"
    printf '%s\n' "$out" | grep -q "kept from sleeping for the run" && fail "a refused inhibitor was claimed: $out"
  else
    kill -0 "$pid" 2>/dev/null || fail "nothing keeps the host awake: $out"
    PIDS+=("$pid")
    stop_sandbox_daemons "$TMP/sb"
    sleep 0.3
    kill -0 "$pid" 2>/dev/null && fail "the host is still kept awake after stop"
    [[ ! -f "$TMP/sb/inhibit.pid" ]] || fail "the pid file stayed"
  fi
  # A pid file naming something else is not obeyed.
  sleep 60 & other=$!
  disown "$other" 2>/dev/null || true
  PIDS+=("$other")
  echo "$other" > "$TMP/sb/inhibit.pid"
  stop_sandbox_daemons "$TMP/sb"
  kill -0 "$other" 2>/dev/null || fail "stop killed a process the pid file named that is not the run's"
  pass "the host is kept awake for a run (or the refusal is said), let go at stop, and a pid file that names something else is left alone"
else
  echo "skip - neither caffeinate nor systemd-inhibit on this host"
fi

# --- the harness a VM run started with ---------------------------------------------
for f in freeze_harness vm_build_spec vm_providers_json pi_agent_dir pi_auth_file credential_models distinct_models; do
  eval "$(fn "$f")"
done
mkdir -p "$TMP/hub/runs" "$TMP/sandbox/.pi-sessions"
freeze_harness "$TMP/hub"
for rel in extensions/agent-swarm.ts scripts/vm.ts prompts node_modules/typebox; do
  [[ -e "$TMP/hub/harness/$rel" ]] || fail "the frozen harness lacks $rel"
done
[[ -s "$TMP/hub/harness/COMMIT" ]] || fail "the frozen harness does not say which commit it is"
# The spec mounts the copy where the checkout is.
sandbox="$TMP/sandbox" swarm_id=s1 hard=0 wall=10 n=0 vm_image=img vm_cpus=1 vm_memory=1024 vm_disk=8192 \
  playwright=0 pack_dirs="" compact_prompt="" self_compact=0 forging=0 inbox_page_chars="" quarantine=0 local_only=0 \
  allow_install=0 install_hosts=0 allow_hosts="" use_netguard=1 PACK_SECRETS_VM='[]' PACK_SECRETS_ENV='{}' REGISTRY="$TMP/runs/registry.json" \
  vm_image_digest="" extra_env=() agent_ids=() AGENT_MODELS=() PI_TOOLS="" \
  vm_build_spec "$TMP/hub" "$TMP/spec.json" 2>/dev/null || true
[[ -f "$TMP/spec.json" ]] || fail "vm_build_spec wrote no spec"
jq -e --arg h "$TMP/hub/harness/extensions" --arg g "$ROOT/extensions" '.mounts[] | select(.host == $h and .guest == $g and .readonly)' "$TMP/spec.json" >/dev/null \
  || fail "the VMs do not get the frozen extensions at the checkout's path: $(jq -c .mounts "$TMP/spec.json")"
jq -e --arg h "$ROOT/extensions" '.mounts[] | select(.host == $h)' "$TMP/spec.json" >/dev/null && fail "the live checkout is still mounted"
pass "a VM run's harness is a copy taken at kickoff, mounted read-only where the checkout is"

echo "lifecycle: all checks passed"

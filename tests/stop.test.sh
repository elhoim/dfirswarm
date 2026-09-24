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
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

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

echo "# a VM that is still up after stop: not stopped, and said so"
record running
set +e
out="$(SWARM_MSB_BIN="$TMP/msb" SWARM_RUNS_DIR="$RUNS" bash "$ROOT/scripts/swarm.sh" stop sstp1 --no-custody 2>&1)"
rc=$?
set -e
[[ $rc -eq 3 ]] || fail "stop with a VM still up exited $rc, wanted 3: $out"
printf '%s\n' "$out" | grep -q "NOT STOPPED" || fail "stop did not say the run is not stopped: $out"
printf '%s\n' "$out" | grep -q "Stopped sstp1" && fail "stop said Stopped with a VM up: $out"
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
printf '%s\n' "$out" | grep -q "Custody:.*skipped\|Cleared sstp1 after the hub finished it" || fail "the after-hub stop did not say what it did: $out"
pass "a stop the hub runs after finishing the run clears up and keeps the state finished"

echo "stop.test.sh: all checks passed"

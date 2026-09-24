#!/usr/bin/env bash
# One finish of a run at a time (scripts/vm.ts finishRun), against a
# stand-in msb (SWARM_MSB_BIN). No model, no Herdr, no VM.
#
# A finish that was still snapshotting after half an hour had its lock
# broken for its age, and a second finish then worked the same VMs: one
# deleted the other's snapshot as it was written. The lock is now broken
# only when its owner is gone — dead, or silent past its heartbeat.
set -euo pipefail
unset SWARM_ISOLATION SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/finish-lock.XXXXXX")"
PIDS=()
cleanup() { local p; for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

export MSB_HOME="$TMP/msb-home"
mkdir -p "$MSB_HOME"
SB="$TMP/runs/sfl1"
mkdir -p "$SB/vm" "$SB/traces"
printf '{"agent":"sfl100","name":"dfs-sfl1-sfl100","run":"sfl1"}\n' > "$SB/vm/sfl100.json"

# A stand-in msb whose inventory takes a while, logging which finish calls it.
cat > "$TMP/msb" <<EOF
#!/usr/bin/env bash
printf '%s %s\n' "\$PPID" "\$1" >> "$TMP/calls.log"
case "\$1" in
  list) printf '[{"name":"dfs-sfl1-sfl100","status":"running","labels":{"dev.dfirswarm.run":"sfl1","dev.dfirswarm.agent":"sfl100"}}]\n' ;;
  exec) sleep 3; printf '{"baseline":true,"apt":{},"venv":{}}\n' ;;
  --version) echo "msb 0.7.2" ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$TMP/msb"
finish() {
  SWARM_MSB_BIN="$TMP/msb" SWARM_FINISH_LOCK_STALE_MS=1000 \
    exec node --experimental-strip-types --no-warnings "$ROOT/scripts/vm.ts" finish --run sfl1 --sandbox "$SB" --no-snapshot
}

echo "# a live finish holding the lock past the stale bound is waited for"
finish > "$TMP/a.out" 2>&1 &
A=$!
PIDS+=("$A")
sleep 1
finish > "$TMP/b.out" 2>&1 &
B=$!
PIDS+=("$B")
wait "$A" || fail "the first finish failed: $(cat "$TMP/a.out")"
wait "$B" || fail "the second finish failed: $(cat "$TMP/b.out")"
# Each finish's calls in one block: the second's first call after the first's last.
a_last="$(grep -n "^$A " "$TMP/calls.log" | tail -1 | cut -d: -f1 || true)"
b_first="$(grep -n "^$B " "$TMP/calls.log" | head -1 | cut -d: -f1 || true)"
[[ -n "$a_last" && -n "$b_first" ]] || fail "both finishes should have called msb: $(cat "$TMP/calls.log")"
(( b_first > a_last )) || fail "the second finish worked the VMs while the first held the lock (heartbeating past the 1 s stale bound): $(cat "$TMP/calls.log")"
pass "a second finish waits for a live one that holds the lock longer than the stale bound"

echo "# a lock whose owner went silent (its pid now another process's) is broken"
: > "$TMP/calls.log"
mkdir -p "$SB/vm/.finish.lock"
sleep 300 &
STRANGER=$!
disown "$STRANGER" 2>/dev/null || true
PIDS+=("$STRANGER")
echo "$STRANGER" > "$SB/vm/.finish.lock/pid"
touch -t "$(date -v-10M +%Y%m%d%H%M.%S 2>/dev/null || date -d '10 minutes ago' +%Y%m%d%H%M.%S)" "$SB/vm/.finish.lock"
out="$(SWARM_FINISH_LOCK_STALE_MS=1000 finish 2>&1)" || fail "a finish behind a silent owner's lock failed: $out"
grep -q " stop$" "$TMP/calls.log" || fail "the finish did not go on past a silent owner's lock: $(cat "$TMP/calls.log")"
kill -0 "$STRANGER" 2>/dev/null || fail "the stranger holding the old pid was touched"
pass "a lock nobody touches any more is broken, and the process that now has its pid is left alone"

echo "finish-lock.test.sh: all checks passed"

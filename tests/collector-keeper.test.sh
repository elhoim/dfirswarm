#!/usr/bin/env bash
# scripts/hub-supervise.sh keeps a VM run's trace collector as it keeps the
# hub: in a VM run the collector is the trace's only door, and one that died
# left the rest of the run in spill files outside the chain. Here the real
# collector, a stand-in hub (a sleeping process) and no VM.
set -euo pipefail
unset SWARM_ISOLATION SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Short, for the collector's socket path.
TMP="$(mktemp -d /tmp/ckeep.XXXXXX)"
PIDS=()
cleanup() {
  local p
  : > "$HUB/.stop" 2>/dev/null || true
  for p in ${PIDS[@]+"${PIDS[@]}"} $(cat "$SB/collector.pid" 2>/dev/null || true); do kill "$p" 2>/dev/null || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

SB="$TMP/runs/sck1"
HUB="$TMP/hubs/dfs-sck1.x1"
mkdir -p "$SB/traces" "$HUB"
SB="$(cd "$SB" && pwd -P)"
chmod 700 "$HUB"
: > "$SB/traces/events.jsonl"
printf '{"agents":["sck100"],"tokens":{"system":"tok-system","sck100":"tok-agent"},"collector":"%s"}\n' "$SB/traces/.collector.sock" > "$HUB/hub-input.json"
chmod 600 "$HUB/hub-input.json"
anchor="$(dirname "$SB")/$(basename "$SB").trace-anchor.json"
start_collector() {
  printf '{"tokens":{"tok-system":"system","tok-agent":"sck100"},"gate":""}' \
    | node "$ROOT/scripts/trace-collector.mjs" "$SB" --tokens --anchor "$anchor" --quiet >>"$SB/traces/collector.log" 2>&1 &
  echo $! > "$SB/collector.pid"
  local i
  for ((i = 0; i < 50; i++)); do [[ -S "$SB/traces/.collector.sock" ]] && return 0; sleep 0.1; done
  fail "the collector did not come up: $(cat "$SB/traces/collector.log")"
}
start_collector
first="$(cat "$SB/collector.pid")"
printf '{"ts":"2026-01-01T00:00:00Z","agent":"system","tool":"before","args":{},"result":{"ok":true}}' \
  | SWARM_TRACE_TOKEN=tok-system node "$ROOT/scripts/trace-emit.mjs" "$SB" || fail "the first line did not reach the collector"

# A stand-in hub that stays up: only the collector dies here.
sleep 600 &
HUBPID=$!
disown "$HUBPID" 2>/dev/null || true
PIDS+=("$HUBPID")
SWARM_HUB_STABLE_SEC=1 bash "$ROOT/scripts/hub-supervise.sh" "$SB" "$HUB" "$ROOT/scripts/vm-hub.ts" "$HUBPID" >/dev/null 2>&1 &
KEEPER=$!
disown "$KEEPER" 2>/dev/null || true
PIDS+=("$KEEPER")
sleep 1
kill "$first"
for _ in $(seq 1 60); do
  now="$(cat "$SB/collector.pid" 2>/dev/null || true)"
  [[ -n "$now" && "$now" != "$first" ]] && kill -0 "$now" 2>/dev/null && [[ -S "$SB/traces/.collector.sock" ]] && grep -q '"collector_restarted"' "$SB/traces/events.jsonl" && break
  sleep 0.25
done
now="$(cat "$SB/collector.pid" 2>/dev/null || true)"
[[ -n "$now" && "$now" != "$first" ]] && kill -0 "$now" 2>/dev/null || fail "the collector was not brought back (pid file: $now)"
line="$(grep '"collector_restarted"' "$SB/traces/events.jsonl" | tail -1)"
[[ -n "$line" ]] || fail "the restart is not on the trace: $(cat "$SB/traces/events.jsonl")"
[[ "$(jq -r '.agent' <<<"$line")" == "system" && "$(jq -r '.agent_unverified // false' <<<"$line")" == "false" ]] || fail "the restart line is not the harness's own: $line"
# One chain across the restart: each line names the one before.
python3 - "$SB/traces/events.jsonl" <<'PY' || fail "the chain broke across the collector's restart"
import hashlib, json, sys
lines = [l for l in open(sys.argv[1], encoding="utf-8").read().split("\n") if l]
prev = None
for i, l in enumerate(lines):
    rec = json.loads(l)
    if i and rec.get("prev") != prev:
        sys.exit(1)
    prev = hashlib.sha256(l.encode()).hexdigest()
PY
pass "a VM run's collector that dies is brought back with the run's tokens, says so on the trace, and the chain goes on"

: > "$HUB/.stop"
kill "$(cat "$SB/collector.pid")" 2>/dev/null || true
sleep 3
[[ -z "$(cat "$SB/collector.pid" 2>/dev/null)" ]] || ! kill -0 "$(cat "$SB/collector.pid")" 2>/dev/null || fail "the keeper brought the collector back after the stop"
pass "after the stop the collector is left down"

echo "# the keeper's restart limit counts crashes in a row, not over the run"
# A stand-in hub: binds admin.sock, stays up HUB_UP_MS, then dies.
cat > "$TMP/hub.mjs" <<'JS'
import { createServer } from "node:net";
import { rmSync } from "node:fs";
const dir = process.argv[process.argv.indexOf("--resume") + 1];
const sock = `${dir}/admin.sock`;
rmSync(sock, { force: true });
createServer().listen(sock);
setTimeout(() => { rmSync(sock, { force: true }); process.exit(1); }, Number(process.env.HUB_UP_MS ?? 0));
JS
run_keeper() { # <hub dir> <up ms> <stable sec>
  mkdir -p "$1"
  printf '{"agents":[],"tokens":{}}\n' > "$1/hub-input.json"
  sleep 0.2 &
  local first=$!
  HUB_UP_MS="$2" SWARM_HUB_MAX_RESTARTS=1 SWARM_HUB_STABLE_SEC="$3" bash "$ROOT/scripts/hub-supervise.sh" "$SB" "$1" "$TMP/hub.mjs" "$first" >/dev/null 2>&1 &
  echo $!
}
HUB2="$TMP/hubs/dfs-sck1.x2"
K2="$(run_keeper "$HUB2" 2500 1)"
disown "$K2" 2>/dev/null || true
PIDS+=("$K2")
sleep 16
kill -0 "$K2" 2>/dev/null || fail "a hub that stayed up between its crashes made the keeper give up: $(tail -3 "$SB/traces/vm-hub.log")"
[[ ! -e "$HUB2/.keeper-gave-up" ]] || fail "the keeper marked a hub that recovers each time as given up"
: > "$HUB2/.stop"
HUB3="$TMP/hubs/dfs-sck1.x3"
K3="$(run_keeper "$HUB3" 0 600)"
PIDS+=("$K3")
for _ in $(seq 1 60); do kill -0 "$K3" 2>/dev/null || break; sleep 0.5; done
kill -0 "$K3" 2>/dev/null && fail "a hub that dies at once, again and again, is still being restarted"
[[ -e "$HUB3/.keeper-gave-up" ]] || fail "a keeper that gave up left no mark for the idle watchdog"
grep -q 'in a row' "$SB/traces/vm-hub.log" || fail "the keeper did not say why it gave up"
pass "a hub that recovers between crashes keeps its keeper; one that dies at once, again and again, is given up on, and the mark says so"

echo "collector-keeper.test.sh: all checks passed"

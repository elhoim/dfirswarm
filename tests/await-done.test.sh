#!/usr/bin/env bash
# Fixture for scripts/await-done.sh. No model, no Herdr, no keys.
#
# The script decides whether a swarm actually finished, so the interesting
# cases are the ones where it could be fooled: a tampered contract, a check
# that eats the checks after it, a check that never returns, and a goal whose
# checks cannot be read at all.
set -euo pipefail
# This suite tests host runs, and a run is in microVMs unless it says
# otherwise: it names host. An image, a lock file or another pack home
# exported in the shell would point its kickoffs somewhere else.
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS="$(mktemp -d "${TMPDIR:-/tmp}/await-done.XXXXXX")"
# The VM hubs' directory is the suite's own (a kickoff makes it for its pane
# guard), never the operator's ~/.dfirswarm/hubs.
export SWARM_HUBS_DIR="$RUNS/dfirswarm-hubs"
trap 'rm -rf "$RUNS"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

# A sandbox with a registry entry, the way `swarm.sh start` leaves one.
# seed <id> <goal-markdown>
seed() {
  local id="$1" goal="$2"
  local sb="$RUNS/$id"
  mkdir -p "$sb/work" "$sb/done/agents" "$sb/threads/main" "$sb/locks" "$sb/traces"
  printf '{"swarm_id":"%s","n":1,"agents":[{"id":"%s00","role":"worker"}]}\n' "$id" "$id" > "$sb/team.json"
  printf '{"cap_usd":1,"spent_usd":0,"wall_clock_minutes":15,"started_at":"2026-01-01T00:00:00Z","agents":{}}\n' > "$sb/budget.json"
  printf -- '---\nby: %s00\nreason: done\n---\n' "$id" > "$sb/done/SWARM_DONE"
  { printf '# Swarm contract\n\n'; printf '%s\n' "$goal"; } > "$sb/SWARM.md"
  python3 - "$RUNS/registry.json" "$id" "$sb" "$goal" <<'PY'
import json, os, sys
path, run_id, sandbox, goal = sys.argv[1:]
data = {"runs": []}
if os.path.exists(path):
    data = json.load(open(path))
data["runs"] = [r for r in data["runs"] if r.get("id") != run_id]
data["runs"].append({"id": run_id, "label": run_id, "state": "running", "sandbox": sandbox, "n": 1, "goal": goal})
json.dump(data, open(path, "w"), indent=2)
PY
  echo "$sb"
}

run_await() {
  local sb="$1"
  shift
  SWARM_RUNS_DIR="$RUNS" bash "$ROOT/scripts/await-done.sh" --sandbox "$sb" --quiet --timeout 6 --interval 2 "$@" 2>&1
}

echo "# a passing goal certifies"
GOAL_OK='## Definition of done

`work/out.txt` exists.

## Checks

- `test -f work/out.txt`'
SB="$(seed sok "$GOAL_OK")"
echo hi > "$SB/work/out.txt"
out="$(run_await "$SB")" || fail "a satisfied goal should exit 0: $out"
grep -q "every check passed" <<<"$out" || fail "expected a pass message, got: $out"
pass "sentinel plus passing checks"

echo "# a failing check is not a finish"
SB="$(seed sfail "$GOAL_OK")"
if out="$(run_await "$SB")"; then fail "an unsatisfied goal must not exit 0: $out"; fi
pass "sentinel without the artifact"

echo "# the checks come from the registry, not the sandbox copy"
SB="$(seed stamper "$GOAL_OK")"
# An agent rewrites the contract in its own working directory to say the job
# is done. The registry copy is the one that counts.
cat > "$SB/SWARM.md" <<'EOF'
# Swarm contract

## Definition of done

Whatever I say it is.

## Checks

- `true`
EOF
if out="$(run_await "$SB")"; then fail "a rewritten contract must not certify the swarm: $out"; fi
pass "tampered contract is ignored"

echo "# a check cannot swallow the checks after it"
GOAL_GREEDY='## Definition of done

Two checks run.

## Checks

- `read -r ignored`
- `false`'
SB="$(seed sgreedy "$GOAL_GREEDY")"
if out="$(run_await "$SB")"; then fail "the second check must still run: $out"; fi
grep -q "2 passed\|1/2\|0/2" <<<"$out" || fail "expected both checks to be counted, got: $out"
pass "stdin is closed per check"

echo "# a check that never returns is bounded"
GOAL_HANG='## Definition of done

Never.

## Checks

- `sleep 30`'
SB="$(seed shang "$GOAL_HANG")"
start=$SECONDS
if out="$(run_await "$SB" --check-timeout 2)"; then fail "a hanging check must not pass: $out"; fi
elapsed=$((SECONDS - start))
(( elapsed < 25 )) || fail "the check timeout did not bound the wait (${elapsed}s)"
grep -q "TIMED OUT" <<<"$out" || fail "expected a timeout message, got: $out"
pass "hanging check killed after --check-timeout"

echo "# an appendix after the checks is not a check"
GOAL_APPENDIX='## Definition of done

`work/out.txt` exists.

## Checks

- `test -f work/out.txt`

## Appendix

- `false`'
SB="$(seed sappendix "$GOAL_APPENDIX")"
echo hi > "$SB/work/out.txt"
out="$(run_await "$SB")" || fail "the appendix bullet must not run as a check: $out"
grep -q "1/1 passed" <<<"$out" || fail "expected exactly one check, got: $out"
pass "section ends at the next heading"

echo "# every Checks section runs, not just the first"
GOAL_TWO='## Definition of done

Both sections matter.

## Checks

- `true`

## Notes

Prose.

## Checks

- `false`'
SB="$(seed stwo "$GOAL_TWO")"
if out="$(run_await "$SB")"; then fail "a later Checks section must still run: $out"; fi
pass "all Checks sections are collected"

echo "# a goal with no checks falls back to the sentinel"
GOAL_NONE='## Definition of done

Someone will know it when they see it.'
SB="$(seed snone "$GOAL_NONE")"
out="$(run_await "$SB")" || fail "no checks should still exit 0 on the sentinel: $out"
grep -q "no checks" <<<"$out" || fail "expected a no-checks message, got: $out"
pass "no checks defined"

echo "# an unreadable goal is a failure, not a pass"
SB="$(seed sbroken "$GOAL_OK")"
rm -f "$SB/SWARM.md"
python3 - "$RUNS/registry.json" sbroken <<'PY'
import json, sys
path, run_id = sys.argv[1:]
data = json.load(open(path))
for run in data["runs"]:
    if run["id"] == run_id:
        run["goal"] = ""
json.dump(data, open(path, "w"), indent=2)
PY
if out="$(run_await "$SB")"; then fail "an unreadable goal must not certify the swarm: $out"; fi
pass "missing goal document"

echo "# the shipped hello goal fails a broken team.json instead of passing it"
SB="$(seed shello "$(cat "$ROOT/prompts/goals/hello.md")")"
printf 'shello00\n' > "$SB/work/hello.txt"
out="$(run_await "$SB")" || fail "the hello goal should pass when satisfied: $out"
printf 'not json at all' > "$SB/team.json"
if out="$(run_await "$SB")"; then fail "a broken team.json must fail the id check, not skip it: $out"; fi
pass "hello checks fail closed"

echo "# a microVM run's unfinished agents are nudged through its own hub, never Herdr"
SB="$(seed svmnudge "Say hello; there is nothing to check.")"
# Started now: an agent idle since the seed's 2026-01-01 would be reaped as
# dead before anyone thought to nudge it.
printf '{"cap_usd":1,"spent_usd":0,"wall_clock_minutes":15,"started_at":"%s","agents":{}}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$SB/budget.json"
HUBS_TMP="$(mktemp -d /tmp/adt.XXXXXX)"
HUBS="$(cd "$HUBS_TMP" && pwd -P)/dfirswarm-hubs"
mkdir -p "$HUBS/dfs-svmnudge.1"
chmod 700 "$HUBS"
(cd "$SB" && pwd -P) > "$HUBS/dfs-svmnudge.1/sandbox"
printf '%s\n' "$HUBS/dfs-svmnudge.1" > "$SB/hub.dir"
node -e '
const net = require("node:net"); const fs = require("node:fs");
net.createServer((s) => { let b = ""; s.on("data", (d) => { b += d; if (b.includes("\n")) { fs.appendFileSync(process.argv[2], b); s.end("{\"ok\":true,\"delivered\":true}\n"); } }); }).listen(process.argv[1]);
' "$HUBS/dfs-svmnudge.1/admin.sock" "$HUBS_TMP/hub-ops.txt" >/dev/null 2>&1 &
HUB_FAKE=$!
trap 'kill "$HUB_FAKE" 2>/dev/null || true; rm -rf "$RUNS" "$HUBS_TMP"' EXIT
for _ in $(seq 50); do [[ -S "$HUBS/dfs-svmnudge.1/admin.sock" ]] && break; sleep 0.05; done
printf '#!/usr/bin/env bash\necho "$@" >> "%s"\n' "$HUBS_TMP/herdr-used.txt" > "$HUBS_TMP/herdr"
chmod +x "$HUBS_TMP/herdr"
# From a shell whose TMPDIR is anything at all: the hubs' directory is the
# user's own, not the shell's temp directory.
TMPDIR="$HUBS_TMP/elsewhere" SWARM_HUBS_DIR="$HUBS" HERDR_BIN="$HUBS_TMP/herdr" SWARM_RUNS_DIR="$RUNS" bash "$ROOT/scripts/await-done.sh" --sandbox "$SB" --nudge --timeout 1 --interval 1 >/dev/null 2>&1 || true
grep -q '"op":"prompt".*"agent":"svmnudge00".*"kind":"swarm_done"' "$HUBS_TMP/hub-ops.txt" 2>/dev/null || fail "the VM agent was not nudged through its hub: $(cat "$HUBS_TMP/hub-ops.txt" 2>/dev/null)"
[[ ! -s "$HUBS_TMP/herdr-used.txt" ]] || fail "Herdr was asked about a VM agent: $(cat "$HUBS_TMP/herdr-used.txt")"
# hub.dir naming a hub made for another sandbox is not that run's hub.
echo /somewhere/else > "$HUBS/dfs-svmnudge.1/sandbox"
: > "$HUBS_TMP/hub-ops.txt"
SWARM_HUBS_DIR="$HUBS" HERDR_BIN="$HUBS_TMP/herdr" SWARM_RUNS_DIR="$RUNS" bash "$ROOT/scripts/await-done.sh" --sandbox "$SB" --nudge --timeout 1 --interval 1 >/dev/null 2>&1 || true
[[ ! -s "$HUBS_TMP/hub-ops.txt" ]] || fail "another sandbox's hub was used"
kill "$HUB_FAKE" 2>/dev/null || true
wait "$HUB_FAKE" 2>/dev/null || true
rm -rf "$HUBS_TMP"
pass "a VM run's agents are nudged through its own hub, and another run's hub is never used"

echo "await-done.test.sh: all checks passed"

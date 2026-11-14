#!/usr/bin/env bash
# A pack brought into a running run (swarm.sh pack-add, E7): the memory pack,
# for a dump a catalogue lists inside an image after the kickoff, which only
# looked at the top of the inputs. Its tools are seeded into tools/ (the job
# service runs them as job_run(tool:)), its notes are files under notes/, the
# run's record names it with when, by whom and why, and every seat is told.
# The kickoff's rules hold: only a run with packs, never one --no-pack
# excluded, never one this host has not installed. The hub keeper adds it on
# its own when the job service's post says a catalogue lists a dump. Host
# runs, --no-start: no model, no VM, no Herdr.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK
export SWARM_ISOLATION=host
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d /tmp/padd.XXXXXX)"
PIDS=()
trap 'for p in ${PIDS[@]+"${PIDS[@]}"}; do { kill "$p"; wait "$p"; } >/dev/null 2>&1 || true; done; chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
export SWARM_RUNS_DIR="$TMP/runs" DFIRSWARM_HOME="$TMP/home" SWARM_SIGNERS_HOME="$TMP/signers"
mkdir -p "$DFIRSWARM_HOME"
swarm() { bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
sandbox_of() { jq -r --arg l "$1" '.runs[] | select(.label == $l) | .sandbox' "$TMP/runs/registry.json"; }
id_of() { jq -r --arg l "$1" '.runs[] | select(.label == $l) | .id' "$TMP/runs/registry.json"; }
GOAL="$TMP/goal.md"
printf '## Goal\n\nFind the key.\n\n### Questions\n\n1. Which key?\n\n## Definition of done\n\nd\n' > "$GOAL"
for p in computer-forensics-base memory-forensics; do bash "$ROOT/scripts/pack.sh" install "$ROOT/packs/$p" --no-secrets >/dev/null || fail "$p did not install"; done
kick() { swarm start --model solo/model --n 2 --cap-usd 1 --no-start --toolbox off --goal-file "$GOAL" "$@"; }
mem_tools="$(ls "$ROOT/packs/memory-forensics/tools" | sort)"

echo "# the operator brings the memory pack into a run that has packs"
out="$(kick --pack computer-forensics-base --label p1)" || fail "the kickoff was refused: $out"
id="$(id_of p1)"; sb="$(sandbox_of p1)"
[[ ! -e "$sb/tools/minidump_map" ]] || fail "the memory pack's tools were there before it was added"
out="$(swarm pack-add "$id" memory-forensics --why "a dump found by hand")" || fail "pack-add failed: $out"
grep -q "^Packs:        added to $id: memory-forensics 1\.[0-9.]* ([0-9]* tool(s), notes under notes/memory-forensics/)" <<<"$out" || fail "$out"
for t in $mem_tools; do jq -e '.pack == "memory-forensics"' "$sb/tools/$t/manifest.json" >/dev/null || fail "$t was not seeded with its pack"; done
[[ -f "$sb/notes/memory-forensics/INDEX.md" && -f "$sb/notes/memory-forensics/triage/process-dumps.md" ]] || fail "the notes are not in the run: $(ls "$sb/notes/memory-forensics" 2>&1)"
[[ ! -w "$sb/notes/memory-forensics/INDEX.md" ]] || fail "the notes are writable"
jq -e --arg id "$id" '.runs[] | select(.id == $id) | .packs | map(.id) | index("memory-forensics") != null' "$TMP/runs/registry.json" >/dev/null || fail "the record does not name the pack"
jq -e --arg id "$id" '.runs[] | select(.id == $id) | .packs[] | select(.id == "memory-forensics") | .added.by == "operator" and .added.why == "a dump found by hand" and (.added.tools | index("minidump_map")) != null and .added.notes == "notes/memory-forensics"' "$TMP/runs/registry.json" >/dev/null || fail "the record's entry: $(jq -c --arg id "$id" '.runs[] | select(.id == $id) | .packs' "$TMP/runs/registry.json")"
post="$(cat "$sb"/threads/main/*-system.md | grep 'PACK ADDED: memory-forensics')" || fail "no board post"
grep -q 'run one with job_run(tool: <name>, args: {...})' <<<"$post" && grep -q '`minidump_map`' <<<"$post" && grep -q 'notes/memory-forensics/INDEX.md' <<<"$post" || fail "the post: $post"
grep -q '"command":"pack-add"' "$TMP/runs/operator-audit.jsonl" || fail "the operator's act is not on the operator's record"
out="$(swarm pack-add "$id" memory-forensics)" || fail "a second pack-add failed: $out"
grep -q 'already among' <<<"$out" || fail "a second pack-add did not say it is there: $out"
pass "tools seeded with their pack, notes read-only under notes/, the record and the board say so; a second add changes nothing"

echo "# a pack whose files changed since it was installed is not added; an older install than the checkout's is said"
out="$(kick --pack computer-forensics-base --label pt)" || fail "$out"
idt="$(id_of pt)"; sbt="$(sandbox_of pt)"
inst="$DFIRSWARM_HOME/packs/memory-forensics"
chmod u+w "$inst/tools/minidump_map" "$inst/tools/minidump_map/run.py"
printf '\n# changed after it was installed\n' >> "$inst/tools/minidump_map/run.py"
rc=0; out="$(swarm pack-add "$idt" memory-forensics)" || rc=$?
[[ "$rc" -eq 3 ]] && grep -q "BLOCKER: memory-forensics was not added to $idt: pack memory-forensics does not verify against its own checksums" <<<"$out" || fail "a changed pack ($rc): $out"
[[ ! -e "$sbt/tools/minidump_map" && ! -e "$sbt/notes/memory-forensics" ]] || fail "a pack that does not verify was copied into the run"
jq -e --arg id "$idt" '.runs[] | select(.id == $id) | [.packs[]?.id] | index("memory-forensics") == null' "$TMP/runs/registry.json" >/dev/null || fail "the record names a pack that was refused"
ls "$sbt"/threads/main/*-system.md 2>/dev/null | xargs grep -l 'PACK ADDED' 2>/dev/null && fail "the seats were told of a refused pack"
bash "$ROOT/scripts/pack.sh" install "$ROOT/packs/memory-forensics" --no-secrets >/dev/null || fail "reinstall"
mkdir -p "$TMP/shipped/memory-forensics"
jq '.version = "99.0.0"' "$ROOT/packs/memory-forensics/pack.json" > "$TMP/shipped/memory-forensics/pack.json"
have="$(jq -r .version "$inst/pack.json")"
out="$(SWARM_SHIPPED_PACKS="$TMP/shipped" swarm pack-add "$idt" memory-forensics)" || fail "pack-add of an older install failed: $out"
grep -q "WARN: pack memory-forensics is installed at $have and this checkout ships 99.0.0; the run uses $have" <<<"$out" || fail "an older install is not said: $out"
pass "a pack that does not verify is refused before anything is copied (exit 3); an install older than the checkout's is said, as the kickoff says it"

echo "# the kickoff's rules: a run with no pack, a pack --no-pack excluded, a pack not installed"
out="$(kick --label p2)" || fail "$out"
rc=0; out="$(swarm pack-add "$(id_of p2)" memory-forensics)" || rc=$?
[[ "$rc" -eq 3 ]] && grep -q 'the run has no pack' <<<"$out" || fail "a run with no pack ($rc): $out"
out="$(kick --pack computer-forensics-base --no-pack memory-forensics --label p3)" || fail "$out"
jq -e '.runs[] | select(.label == "p3") | .no_packs == ["memory-forensics"]' "$TMP/runs/registry.json" >/dev/null || fail "the record does not keep --no-pack"
rc=0; out="$(swarm pack-add "$(id_of p3)" memory-forensics)" || rc=$?
[[ "$rc" -eq 3 ]] && grep -q 'its kickoff excluded it (--no-pack)' <<<"$out" || fail "an excluded pack ($rc): $out"
rc=0; out="$(swarm pack-add "$(id_of p1)" no-such-pack)" || rc=$?
[[ "$rc" -eq 3 ]] && grep -q 'not installed on this host' <<<"$out" || fail "a pack not installed ($rc): $out"
[[ ! -e "$(sandbox_of p2)/tools/minidump_map" && ! -e "$(sandbox_of p3)/tools/minidump_map" ]] || fail "a refused add seeded tools"
pass "a run with no pack, an excluded pack and one not installed are kept out, said, exit 3"

echo "# the hub keeper adds it when a catalogue lists a dump inside an image"
out="$(kick --pack computer-forensics-base --label p4)" || fail "$out"
id4="$(id_of p4)"; sb4="$(sandbox_of p4)"
node --experimental-strip-types --no-warnings --input-type=module -e '
  const P = await import(process.argv[1]);
  const D = await import(process.argv[2]);
  const body = D.dumpsPost("g3", "import:ev-1/disk.ad1", { total: 1, bytes: 4096, whole: true, top: [{ path: "Users/x/AppData/Local/Temp/app.dmp", bytes: 4096, kind: "process or crash dump" }] }, []);
  await P.systemPost(process.argv[3], { tag: "result", to: "all", key: "dumps:g3", body });
' "$ROOT/extensions/protocol.ts" "$ROOT/scripts/dump-members.ts" "$sb4" || fail "the job service's post could not be made"
HUB="$TMP/hub4"; mkdir -p "$HUB" "$sb4/traces"
printf '{"tokens": {}}\n' > "$HUB/hub-input.json"
sleep 300 >/dev/null 2>&1 </dev/null & hubpid=$!; PIDS+=("$hubpid")
SWARM_DUMP_SCAN_SEC=0 bash "$ROOT/scripts/hub-supervise.sh" "$sb4" "$HUB" "$TMP/no-hub.mjs" "$hubpid" >/dev/null 2>&1 </dev/null & keeper=$!; PIDS+=("$keeper")
for _ in $(seq 1 300); do [[ -e "$HUB/.dump-pack-done" ]] && break; sleep 0.2; done
[[ -e "$HUB/.dump-pack-done" ]] || fail "the keeper did not act on the dump: $(cat "$sb4/traces/vm-hub.log" 2>/dev/null)"
grep -q 'hub-supervise: pack-add memory-forensics (exit 0)' "$sb4/traces/vm-hub.log" || fail "the keeper's log: $(cat "$sb4/traces/vm-hub.log")"
jq -e --arg id "$id4" '.runs[] | select(.id == $id) | .packs[] | select(.id == "memory-forensics") | .added.by == "catalogue" and (.added.why | test("^the catalogue g3 of import:ev-1/disk.ad1 lists 1 member named as a process or memory dump$"))' "$TMP/runs/registry.json" >/dev/null \
  || fail "the record: $(jq -c --arg id "$id4" '.runs[] | select(.id == $id) | .packs' "$TMP/runs/registry.json")"
[[ -f "$sb4/tools/minidump_map/manifest.json" && -f "$sb4/notes/memory-forensics/INDEX.md" ]] || fail "the keeper's add did not seed the run"
cat "$sb4"/threads/main/*-system.md | grep -q 'PACK ADDED: memory-forensics .*the catalogue g3 of import:ev-1/disk.ad1 lists 1 member named as a process or memory dump (the harness adds the memory pack on its own' || fail "the seats were not told"
: > "$HUB/.stop"; { kill "$hubpid"; wait "$hubpid"; } >/dev/null 2>&1 || true
for _ in $(seq 1 50); do kill -0 "$keeper" 2>/dev/null || break; sleep 0.1; done
kill -0 "$keeper" 2>/dev/null && fail "the keeper did not end with the run's stop"
pass "a catalogue's dump post brings the memory pack in on its own, once, recorded as the catalogue's"

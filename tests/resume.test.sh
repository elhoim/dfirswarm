#!/usr/bin/env bash
# swarm.sh resume (docs/adr/0013): a stopped run goes on in the same sandbox,
# on the same chains. Refused while the run is going, and for a run whose
# start options were not kept (given after -- instead); the stop moved aside
# whole; the question asked for the continuation admitted as an analyst's;
# each seat's hand-off put where it starts; the resume on the operator's
# record, the registry and the custody anchor; the next stop seals a new
# verdict and a new draft, and custody-verify holds the first seal as a
# prefix of the run now. No model, no VM; Herdr is never started (--no-start).
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Short, for the collector's socket path: a trace no collector chained is
# not the run this test continues.
TMP="$(mktemp -d /tmp/rsm.XXXXXX)"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
HELLO="$ROOT/prompts/goals/hello.md"
export SWARM_RUNS_DIR="$TMP/runs" DFIRSWARM_HOME="$TMP/home" SWARM_SIGNERS_HOME="$TMP/home"
mkdir -p "$DFIRSWARM_HOME"
swarm() { bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
kick() { swarm start --model solo/model --n 2 --no-start --goal-file "$HELLO" --toolbox off "$@"; }
sandbox_of() { jq -r --arg l "$1" '.runs[] | select(.label == $l) | .sandbox' "$TMP/runs/registry.json"; }
id_of() { jq -r --arg l "$1" '.runs[] | select(.label == $l) | .id' "$TMP/runs/registry.json"; }
state_of() { jq -r --arg id "$1" '.runs[] | select(.id == $id) | .state' "$TMP/runs/registry.json"; }
set_state() { local t; t="$(mktemp)"; jq --arg id "$1" --arg s "$2" '(.runs[] | select(.id == $id) | .state) = $s' "$TMP/runs/registry.json" > "$t" && mv "$t" "$TMP/runs/registry.json"; }

echo "# the kickoff keeps its options for a resume"
out="$(kick --cap-usd 5 --wall-clock 30 --label r1)" || fail "the kickoff was refused: $out"
id="$(id_of r1)"; sb="$(sandbox_of r1)"
argv="$TMP/runs/resume/$id.argv.json"
[[ -f "$argv" ]] || fail "the start options were not kept"
[[ "$(stat -f %Lp "$argv" 2>/dev/null || stat -c %a "$argv")" == 600 ]] || fail "the kept options are not 0600"
jq -e 'index("--cap-usd") != null and index("--label") != null' "$argv" >/dev/null || fail "the kept options are not the kickoff's: $(cat "$argv")"
pass "the kickoff keeps its start options outside the run, 0600"

echo "# refused while the run is going, or never started"
set +e
out="$(swarm resume "$id" --no-start)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'is prepared and never started: there is nothing to continue' <<<"$out" || fail "a prepared run was resumed (rc $rc): $out"
set_state "$id" running
set +e
out="$(swarm resume "$id" --no-start)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q "a resume continues a run that has ended. A running or paused one is given more with swarm.sh extend $id" <<<"$out" || fail "a running run was resumed (rc $rc): $out"
pass "a running run is extended, not resumed; a prepared one is refused"

echo "# the stop, then the resume"
# A seat's hand-off note, as self-compaction writes it into its Pi session.
a0="$(jq -r '.agents[0].id' "$sb/team.json")"; a1="$(jq -r '.agents[1].id' "$sb/team.json")"
mkdir -p "$sb/.pi-sessions/$a0"
note="name $a0, slice: the logs; NEXT ACTION: read from line 5000; $(printf 'x%.0s' $(seq 1 3000))"
jq -nc --arg n "$note" '{type: "custom_message", id: "h1", parentId: null, timestamp: "2026-09-28T10:00:00.000Z", customType: "self-compact-handoff", content: "", details: {note: $n}, display: true}' > "$sb/.pi-sessions/$a0/s.jsonl"
out="$(swarm stop "$id")" || fail "stop failed: $out"
[[ "$(state_of "$id")" == stopped && -f "$sb/done/STOPPED" && -f "$sb/custody.json" ]] || fail "the stop did not end the run as stopped with a verdict: $out"
first_at="$(jq -r '.at' "$sb/custody.json")"
[[ -f "$sb/release/v0/release.json" ]] || fail "the stop wrote no draft: $out"
out="$(swarm resume "$id" --no-start --question "Was the host reached again after the first day?" --minutes 10)" || fail "the resume was refused: $out"
grep -q "^Resume:       run $id, which stopped, goes on; segment 1" <<<"$out" || fail "the resume does not say what goes on: $out"
grep -q "^Hand-off:     $a0 starts from its last hand-off note" <<<"$out" || fail "the hand-off is not named: $out"
grep -q "^Hand-off:     $a1 starts from the registers (it left no note)" <<<"$out" || fail "a seat with no note is not named: $out"
grep -q '^Question:     Q-[0-9]* (in_scope)' <<<"$out" || fail "the continuation's question was not admitted: $out"
grep -q "^Resume:       run $id goes on in $sb, on its own chains (nothing cleared)" <<<"$out" || fail "the start does not say it continues: $out"
[[ -f "$sb/done/history/1/STOPPED" && ! -f "$sb/done/STOPPED" ]] || fail "the stop was not moved aside whole"
grep -qF "$note" "$sb/inbox/$a0/resume.md" || fail "the hand-off note is not in the seat's resume file, whole"
[[ -f "$sb/ledger/entries.jsonl" || -d "$sb/ledger" ]] || fail "the ledger went"
jq -e '(.resumes | length) == 1 and .resumes[0].from == "stopped" and (.wall_clock_minutes == 40)' "$sb/budget.json" >/dev/null || fail "the budget does not hold the resume: $(jq -c '{resumes, wall_clock_minutes}' "$sb/budget.json")"
jq -e --arg id "$id" '.runs[] | select(.id == $id) | (.resumes | length) == 1 and .resumes[0].from == "stopped" and .state == "prepared"' "$TMP/runs/registry.json" >/dev/null || fail "the registry does not hold the resume"
jq -e '(.resumes | length) == 1 and .resumes[0].by == "operator" and .resumes[0].segment == 1' "$sb.custody-anchor.json" >/dev/null || fail "the resume is not anchored beside the run: $(jq -c '.resumes' "$sb.custody-anchor.json")"
grep -q '"command":"resume_prepared"' "$TMP/runs/operator-audit.jsonl" || fail "the resume is not on the operator's record"
grep -q '"origin":{"kind":"analyst"' "$sb/questions/questions.jsonl" || fail "the continuation's question is not an analyst's"
if grep -q '"after_done"' "$sb/questions/questions.jsonl"; then fail "the continuation's question was taken as a follow-up of an ended run"; fi
pass "the resume: the stop moved aside, the question admitted, the hand-offs placed, on the budget, the registry, the anchor and the operator's record"

echo "# a prepared resume is started as prepared, not prepared twice"
set +e
out="$(swarm resume "$id" --no-start --minutes 5)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'its caps are changed with swarm.sh caps' <<<"$out" || fail "a second prepare with caps was not refused (rc $rc): $out"
out="$(swarm resume "$id" --no-start)" || fail "the prepared resume was not started: $out"
grep -q 'was prepared for its resume already' <<<"$out" || fail "the prepared resume does not say so: $out"
jq -e '(.resumes | length) == 1' "$sb/budget.json" >/dev/null || fail "the resume was recorded twice"
jq -e --arg id "$id" '.runs[] | select(.id == $id) | (.resumes | length) == 1' "$TMP/runs/registry.json" >/dev/null || fail "the registry holds the resume twice"
pass "a prepared resume starts as prepared"

echo "# the next stop seals the continuation; the first seal holds as a prefix"
out="$(swarm stop "$id")" || fail "the second stop failed: $out"
[[ "$(jq -r '.at' "$sb/custody.json")" != "$first_at" ]] || fail "the second stop took no new verdict"
[[ -f "$sb/release/v1/release.json" ]] || fail "the second stop wrote no new draft: $out"
out="$(swarm custody-verify "$id")" || fail "custody-verify failed after the resume: $out"
grep -q "^Earlier seal: $first_at ([0-9a-f]*), before a resume: holds as a prefix: the trace" <<<"$out" || fail "custody-verify does not show the earlier seal: $out"
out="$(swarm releases "$id" --verify)" || fail "the releases do not verify after the resume: $out"
grep -q '^Release v0:.*binds an earlier custody verdict' <<<"$out" || fail "v0 is not verified as an earlier seal: $out"
pass "custody-verify shows both seals, and both drafts verify"

echo "# a run started before its options were kept"
out="$(kick --cap-usd 5 --label r2)" || fail "the second kickoff was refused: $out"
id2="$(id_of r2)"
set_state "$id2" running
swarm stop "$id2" --no-custody >/dev/null || fail "the second run's stop failed"
rm -f "$TMP/runs/resume/$id2.argv.json"
set +e
out="$(swarm resume "$id2" --no-start)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'was started before its start options were kept for a resume. Give them after --' <<<"$out" || fail "a resume with no kept options was not refused (rc $rc): $out"
[[ -f "$(sandbox_of r2)/done/STOPPED" ]] || fail "a refused resume moved the stop"
out="$(swarm resume "$id2" --no-start -- --model solo/model --n 2 --goal-file "$HELLO" --toolbox off --cap-usd 5 --label r2)" || fail "a resume with its options given was refused: $out"
[[ -f "$(sandbox_of r2)/done/history/1/STOPPED" ]] || fail "the given options' resume did not move the stop"
set_state "$id2" stopped
set +e
out="$(swarm resume "$id2" --no-start -- --model solo/model --n 3 --goal-file "$HELLO" --toolbox off --cap-usd 5)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'a resume continues the same seats (give --n 2)' <<<"$out" || fail "a resume with other seats was not refused (rc $rc): $out"
pass "a run with no kept options is resumed with them given after --, and with the same seats only"

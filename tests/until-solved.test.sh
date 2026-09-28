#!/usr/bin/env bash
# The kickoff of a run that goes on until every question is answered:
# --until-solved (or the goal's until_solved: true) takes no wall clock and no
# cap is required; budget.json and the registry say until_solved with the
# regroup's stall minutes; the contract says how the run ends and that there
# is no bail-out for the agents; a --wall-clock beside it, or a
# --stall-minutes without it, is refused. And the watchdog's regroup: posted
# when nothing moved for the stall minutes, again with backoff, never on a
# run that is not until solved. No model, no Herdr, no VM.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/until-solved.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
HELLO="$ROOT/prompts/goals/hello.md"
kick() { # <args...>
  SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" start --model solo/model --n 2 --no-start --goal-file "$HELLO" --toolbox off "$@" 2>&1
}
sandbox_of() { jq -r --arg l "$1" '.runs[] | select(.label == $l) | .sandbox' "$TMP/runs/registry.json"; }

out="$(kick --until-solved --label us1)" || fail "an until-solved kickoff with no cap was refused: $out"
grep -q 'Cap:          none: until solved' <<<"$out" || fail "the kickoff does not say there is no cap: $out"
# How the run ends: every question with a disposition under the bar, as any run (before 2026-09-28 it said "done only when every question is answered").
grep -q 'Until solved: no caps and no wall clock; done when every question in scope has a disposition under the bar (a reviewed not_determinable included: examination-limited); no abandon; a regroup after 15 minutes' <<<"$out" || fail "the kickoff does not say how the run ends: $out"
sb="$(sandbox_of us1)"
[[ "$(jq -r '.until_solved' "$sb/budget.json")" == true ]] || fail "budget.json does not say until_solved"
[[ "$(jq -r '.wall_clock_minutes' "$sb/budget.json")" == 0 ]] || fail "an until-solved run has a wall clock: $(jq -c . "$sb/budget.json")"
[[ "$(jq -r '.stall_minutes' "$sb/budget.json")" == 15 ]] || fail "the default stall is not 15 minutes"
[[ "$(jq -r '.runs[] | select(.label == "us1") | .until_solved' "$TMP/runs/registry.json")" == true ]] || fail "the registry does not say until_solved"
grep -q '^## Until solved$' "$sb/SWARM.md" || fail "the contract has no Until solved section"
grep -q 'There is none for the agents: only the operator stops this run' "$sb/SWARM.md" || fail "the contract still offers the agents a bail-out"
grep -q 'Wall clock:' "$sb/SWARM.md" && fail "the contract still names a wall clock"
grep -q 'nothing is stopped for it' "$sb/SWARM.md" || fail "the contract does not say the caps are advisory"
# The contract says the negative bar's path to an end, and no longer that an examination-limited end is refused.
grep -q 'it asks nothing more of an answer than any run does' "$sb/SWARM.md" || fail "the contract does not say the policy adds no answer requirement"
grep -q 'then answer not_determinable (or bounded_negative when' "$sb/SWARM.md" || fail "the contract does not say the not_determinable path"
grep -q 'examination-limited, which is a proper end' "$sb/SWARM.md" || fail "the contract does not say examination-limited is an end"
grep -q 'examination-limited finish is not accepted' "$sb/SWARM.md" && fail "the contract still refuses an examination-limited end"
pass "--until-solved: no wall clock, no cap required, the mode in budget.json, the registry and the contract"

out="$(kick --until-solved --cap-usd 50 --stall-minutes 20 --label us2)" || fail "an until-solved kickoff with an advisory cap was refused: $out"
grep -q 'advisory: \$50' <<<"$out" || fail "the advisory cap is not said: $out"
sb2="$(sandbox_of us2)"
jq -e '.cap_usd == 50 and .stall_minutes == 20' "$sb2/budget.json" >/dev/null || fail "the advisory cap or the stall is not kept: $(jq -c . "$sb2/budget.json")"
grep -q 'the figures given: \$50 USD' "$sb2/SWARM.md" || fail "the contract does not name the advisory cap"
pass "a cap given to an until-solved run is kept as a figure, and --stall-minutes is recorded"

set +e
out="$(kick --until-solved --wall-clock 60 --label us3)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'an until-solved run has no wall clock' <<<"$out" || fail "--wall-clock beside --until-solved was not refused (rc $rc): $out"
set +e
out="$(kick --cap-usd 1 --stall-minutes 5 --label us4)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q -- '--stall-minutes is for a run started --until-solved' <<<"$out" || fail "--stall-minutes without --until-solved was not refused (rc $rc): $out"
pass "a wall clock beside until-solved, and a stall without it, are refused"

{ printf -- '---\ntitle: t\nuntil_solved: true\nstall_minutes: 30\n---\n'; cat "$HELLO"; } > "$TMP/goal-us.md"
out="$(SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" start --model solo/model --n 2 --no-start --goal-file "$TMP/goal-us.md" --toolbox off --label us5 2>&1)" || fail "a goal that says until_solved was refused: $out"
sb5="$(sandbox_of us5)"
[[ "$(jq -r '.until_solved' "$sb5/budget.json")" == true && "$(jq -r '.stall_minutes' "$sb5/budget.json")" == 30 ]] || fail "the goal's metadata did not make the run until solved"
grep -q '^until_solved:' "$sb5/SWARM.md" && fail "the metadata block leaked into the contract"
pass "the goal's metadata block makes a run until solved, with its own stall"

# --- the regroup -------------------------------------------------------------
node --experimental-strip-types --no-warnings -e '
  const [protocol, leads, S] = process.argv.slice(1);
  Promise.all([import(protocol), import(leads)]).then(async ([P, L]) => {
    // Started an hour ago; nothing recorded since.
    const b = await P.readBudget(S);
    b.started_at = new Date(Date.now() - 60 * 60_000).toISOString();
    await P.writeBudget(S, b);
    const r = await L.openLead({ sandboxRoot: S, agentId: (await P.teamIds(S))[0] }, { title: "Open the container", why: "the answers are inside" });
    if (!r.ok) throw new Error(r.reason);
  }).catch((e) => { console.error(e.message); process.exit(1); });
' "$ROOT/extensions/protocol.ts" "$ROOT/extensions/leads.ts" "$sb" || fail "could not age the run"
# The lead just opened is not progress (a lead closed is): the run has not moved for an hour.
r="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/leads-cli.ts" regroup "$sb")"
[[ "$(jq -r '.posted' <<<"$r")" == true && "$(jq -r '.count' <<<"$r")" == 1 ]] || fail "no regroup after an hour without progress: $r"
post="$(ls "$sb"/threads/main/*.md | tail -1)"
grep -q '^from: system$' "$post" && grep -q 'REGROUP 1: nothing has moved for' "$post" || fail "the regroup post is not the harness's: $(cat "$post")"
grep -q 'Leads open, held by nobody (1):' "$post" && grep -q 'L-1 "Open the container"' "$post" || fail "the regroup does not list the open lead: $(cat "$post")"
grep -q 'Waiting on the operator (0):' "$post" || fail "the regroup does not say what waits on the operator"
grep -q 'Evidence no standing entry cites' "$post" || fail "the regroup does not list the uncited evidence"
grep -q 'the next regroup comes in 30 minutes' "$post" || fail "the regroup does not say when the next comes: $(tail -2 "$post")"
r="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/leads-cli.ts" regroup "$sb")"
[[ "$(jq -r '.posted' <<<"$r")" == false ]] || fail "a second regroup came at once: $r"
r="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/leads-cli.ts" regroup "$sb" --now "$(date -u -v+31M +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+31 minutes' +%Y-%m-%dT%H:%M:%SZ)")"
[[ "$(jq -r '.posted' <<<"$r")" == true && "$(jq -r '.count' <<<"$r")" == 2 && "$(jq -r '.next_minutes' <<<"$r")" == 60 ]] || fail "the second regroup, after the backoff, did not come: $r"
r="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/leads-cli.ts" regroup "$(sandbox_of us2)")"
[[ "$(jq -r '.posted' <<<"$r")" == false ]] || fail "a run that just started got a regroup: $r"
r="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/leads-cli.ts" regroup "$(sandbox_of us4 2>/dev/null || echo "$TMP/none")" 2>/dev/null || echo '{"posted":false}')"
[[ "$(jq -r '.posted' <<<"$r")" == false ]] || fail "a run that is not until solved got a regroup"
pass "the regroup comes when nothing moved for the stall, lists what is open, and comes again with backoff"

echo "until-solved.test.sh: all checks passed"

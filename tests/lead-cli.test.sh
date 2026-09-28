#!/usr/bin/env bash
# The operator's side of the lead register: swarm.sh lead <run> list, note
# and reopen. A lead an agent closed needs_operator is listed first with the
# command that answers it; the note is recorded on the lead, reopens it,
# reaches the board as the examiner addressed to whoever held it, and is on
# the trace and the operator's record; --allow-host adds the host for the
# run's jobs in a microVM run and is refused, with why, in a host run.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/lead-cli.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

RUNS="$TMP/runs"
mkdir -p "$RUNS"
export SWARM_RUNS_DIR="$RUNS"

# Two runs, one in microVMs and one on the host, each with a lead closed needs_operator.
make_run() { # <id> <isolation>
  local sb="$RUNS/$1"
  node --experimental-strip-types --no-warnings -e '
    const [protocol, leads, S, id] = process.argv.slice(1);
    Promise.all([import(protocol), import(leads)]).then(async ([P, L]) => {
      await P.initSandbox(S, { swarmId: id, agentIds: ["a0", "a1"], capUsd: 1, wallClockMinutes: 10 });
      const open = await L.openLead({ sandboxRoot: S, agentId: "a0" }, { title: "Follow the pointer outside the image", why: "part 3", take: true });
      if (!open.ok) throw new Error(open.reason);
      const closed = await L.closeLead({ sandboxRoot: S, agentId: "a0" }, "L-1", { disposition: "needs_operator", ref: "The key is on an outside resource named in the plaintext; allow its host so a job can fetch it" });
      if (!closed.ok) throw new Error(closed.reason);
    }).catch((e) => { console.error(e.message); process.exit(1); });
  ' "$ROOT/extensions/protocol.ts" "$ROOT/extensions/leads.ts" "$sb" "$1" || fail "could not seed $1"
  printf '%s\n' "$sb"
}
VM="$(make_run svm01 microvm)"
HOST="$(make_run shost1 host)"
jq -n --arg vm "$VM" --arg host "$HOST" '{runs: [{id: "svm01", sandbox: $vm, state: "running", isolation: {mode: "microvm"}}, {id: "shost1", sandbox: $host, state: "running"}]}' > "$RUNS/registry.json"

out="$(bash "$ROOT/scripts/swarm.sh" lead svm01 list 2>&1)" || fail "lead list failed: $out"
grep -q '^WAITING ON THE OPERATOR:' <<<"$out" || fail "the operator's requests are not listed first: $out"
grep -q 'asks: The key is on an outside resource' <<<"$out" || fail "the request is not said: $out"
grep -q 'answer: swarm.sh lead <run> note L-1' <<<"$out" || fail "the list does not say how to answer: $out"
[[ -f "$VM/operator-requests.jsonl" ]] && grep -q '"lead":"L-1"' "$VM/operator-requests.jsonl" || fail "no operator-requests.jsonl line"
pass "lead list shows the requests waiting on the operator first, with the command that answers each"

out="$(bash "$ROOT/scripts/swarm.sh" lead shost1 note L-1 "Allowed" --allow-host paste.example.org 2>&1)" && fail "--allow-host was taken in a host run: $out"
grep -q 'works live only in a microVM run' <<<"$out" || fail "the refusal does not say why: $out"
pass "a host run refuses --allow-host and says why"

out="$(bash "$ROOT/scripts/swarm.sh" lead svm01 note L-1 "The host is allowed now; fetch it in a job" --allow-host paste.example.org 2>&1)" || fail "lead note failed: $out"
grep -q 'Recorded on L-1, reopened, paste.example.org allowed for the run.s jobs' <<<"$out" || fail "the note's outcome is not said: $out"
post="$(ls "$VM"/threads/main/*-examiner.md | tail -1)"
[[ -n "$post" ]] || fail "no examiner post"
grep -q '^to: a0$' "$post" || fail "the note is not addressed to the lead's last holder: $(cat "$post")"
grep -q 'OPERATOR NOTE on L-1: The host is allowed now' "$post" || fail "the post does not carry the note"
grep -q 'lead_claim L-1' "$post" || fail "the post does not say the lead is open again"
grep -q '"host":"paste.example.org"' "$VM/operator-hosts.jsonl" || fail "the host is not in operator-hosts.jsonl"
grep -q '"ev":"note"' "$VM/leads/leads.jsonl" && grep -q '"ev":"reopen"' "$VM/leads/leads.jsonl" || fail "the note and the reopen are not events on the register"
grep -q '"tool":"operator_action"' "$VM/traces/events.jsonl" && grep -q '"command":"lead"' "$VM/traces/events.jsonl" || fail "the note is not on the trace"
grep -q '"lead"' "$RUNS/operator-audit.jsonl" || fail "the note is not on the operator's record"
pass "lead note records the answer, reopens the lead, allows the host for jobs, and posts it to the lead's holder"

out="$(bash "$ROOT/scripts/swarm.sh" lead svm01 reopen L-1 2>&1)" && fail "a lead already open was reopened: $out"
grep -q 'is not closed' <<<"$out" || fail "the refusal does not say why: $out"
pass "reopen refuses a lead that is open"

echo "lead-cli.test.sh: all checks passed"

#!/usr/bin/env bash
# The operator's side of the question register: swarm.sh question <run> …
# and swarm.sh lead <run> direct. A kickoff seeds the register from the goal
# (its questions as Q-n, its objectives, a front-matter objectives list
# carried into the goal); an act is refused with why, or recorded on the
# chain and only then acknowledged, posted from analyst:<person>, on the
# trace, and on the operator's record twice (the attempt, and the outcome
# naming the event). --as names an enrolled person (a claim); --sign signs
# with their key, the passphrase on fd 3 and nowhere else; an analyst's
# question outside an objective is proposed, and the operator admits it.
set -uo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/question-cli.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
export SWARM_RUNS_DIR="$TMP/runs"
export SWARM_SIGNERS_HOME="$TMP/signers"
mkdir -p "$SWARM_RUNS_DIR"
swarm() { bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
sandbox_of() { printf '%s\n' "$1" | sed -n 's/^SANDBOX=//p' | tail -1; }
id_of() { printf '%s\n' "$1" | sed -n 's/^Swarm id: *//p' | tail -1; }

# A goal with numbered questions, an answers check, and its objectives in front matter.
cat > "$TMP/goal.md" <<'EOF'
---
objectives:
  - O-1: Establish how the archive came to be on this machine
  - Establish who handled it afterwards
---
## Goal

Examine the archive.

### Questions

1. Which account created the archive?
2. Was it opened on another machine?

## Definition of done

Every question answered in the ledger.

## Checks

- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,summary,narrative`
EOF
out="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/goal.md" --label qcli)"
SB="$(sandbox_of "$out")"
RUN="$(id_of "$out")"
[[ -n "$SB" && -f "$SB/SWARM.md" && -n "$RUN" ]] || fail "no run: $out"
grep -q '^## Objectives' "$SB/SWARM.md" || fail "the front matter's objectives are not in the contract"
grep -q '^- O-1: Establish how the archive came to be on this machine' "$SB/SWARM.md" || fail "objective O-1 is not in the contract"
[[ -s "$SB/questions/questions.jsonl" ]] || fail "the kickoff did not seed the question register"
grep -q '"ev":"seed"' "$SB/questions/questions.jsonl" || fail "no seed event"
list="$(swarm question "$RUN" list)" || fail "question list failed: $list"
grep -q 'O-1: Establish how the archive came to be on this machine' <<<"$list" || fail "the list does not show O-1: $list"
grep -q 'O-2: Establish who handled it afterwards' <<<"$list" || fail "an objective without an id is O-<its place>: $list"
grep -q 'Q-1 rev 1 \[in_scope, admitted\] the goal' <<<"$list" && grep -q 'Which account created the archive?' <<<"$list" || fail "the goal's question 1 is not Q-1 with its words: $list"
pass "a kickoff seeds the register: the goal's questions as Q-n, its objectives (front matter carried into the goal)"

# Refusals say why and record nothing.
events_before="$(wc -l < "$SB/questions/questions.jsonl")"
out="$(swarm question "$RUN" add --text "Was the archive mailed?")" && fail "a question without why was taken: $out"
grep -q 'BLOCKER: why is required' <<<"$out" || fail "the refusal does not say why: $out"
out="$(swarm question "$RUN" add --text "Was it mailed?" --why "w" --as nobody)" && fail "--as an unknown person was taken: $out"
grep -q 'no one is enrolled on this install under nobody' <<<"$out" || fail "the refusal does not say who is unknown: $out"
[[ "$(wc -l < "$SB/questions/questions.jsonl")" -eq "$events_before" ]] || fail "a refused act wrote to the chain"
pass "a refused act says why and writes nothing"

# The operator's question: in scope by authority, acknowledged after the write, posted, on the trace and the record.
out="$(swarm question "$RUN" add --text "Was the archive mailed to an outside address?" --why "the client says it left by mail" --objective O-1 --priority urgent --reason "a hearing tomorrow")" || fail "add failed: $out"
grep -q "Recorded Q-3 (revision 1), in_scope: by the operator's authority" <<<"$out" || fail "the acknowledgement is not said: $out"
ack="$(tail -n 1 <<<"$out")"
seq="$(jq -r '.seq' <<<"$ack")"; hash="$(jq -r '.hash' <<<"$ack")"
[[ "$seq" =~ ^[0-9]+$ && ${#hash} -eq 64 ]] || fail "the acknowledgement does not name the chained event: $ack"
line="$(sed -n "${seq}p" "$SB/questions/questions.jsonl")"
[[ "$(jq -r '.hash' <<<"$line")" == "$hash" ]] || fail "the named event is not on the chain at $seq"
[[ "$(jq -r '.origin.enrolled' <<<"$line")" == false && "$(jq -r '.origin.role' <<<"$line")" == operator ]] || fail "the act is not the OS account's, not enrolled: $line"
[[ "$(jq -r '.admitted_by' <<<"$ack")" == "cli, no hub running" ]] || fail "a host run's act does not say the CLI admitted it, with no hub: $ack"
post="$(grep -l '^tag: question$' "$SB"/threads/main/*.md | head -1)"
[[ -n "$post" ]] || fail "no question post on the board"
grep -q '^from: analyst:' "$post" || fail "the post is not from analyst:<person>: $(cat "$post")"
grep -q 'QUESTION Q-3 (revision 1)' "$post" || fail "the post does not carry the question's id and revision"
grep -q 'Was the archive mailed to an outside address?' "$post" || fail "the post does not carry the question whole"
grep -q '"command":"question"' "$SWARM_RUNS_DIR/operator-audit.jsonl" || fail "the attempt is not on the operator's record"
grep '"command":"question_outcome"' "$SWARM_RUNS_DIR/operator-audit.jsonl" | grep -q "\"hash\":\"$hash\"" || fail "the outcome on the operator's record does not name the event"
grep -q '"tool":"operator_action"' "$SB/traces/events.jsonl" && grep -q '"command":"question"' "$SB/traces/events.jsonl" || fail "the act is not on the trace"
pass "an operator's question is in scope by authority, acknowledged after the chain write, posted from analyst:<person>, on the trace and the record (attempt and outcome)"

# An enrolled analyst: a claim outside an objective is proposed; a signed one inside it verifies.
enrol="$(bash "$ROOT/scripts/swarm.sh" examiner enroll --name "Ana Lyst" --organisation Lab --competence "mail forensics" --role analyst --id ana --generate-key --passphrase-fd 3 3<<<"correct horse battery" 2>&1)" || fail "enrol failed: $enrol"
grep -q 'ana namespaces="dfirswarm-question"' <<<"$enrol" || fail "the analyst's register line is not the question namespace: $enrol"
out="$(swarm question "$RUN" add --text "Who owns the printer?" --why "curious" --as ana)" || fail "the analyst's add failed: $out"
grep -q 'Recorded Q-4 (revision 1), proposed: outside the case' <<<"$out" || fail "an analyst's question outside an objective is not proposed: $out"
grep -q 'WAITING FOR YOUR TRIAGE:' <<<"$(swarm question "$RUN" list)" || fail "the proposed question is not in the triage"
out="$(swarm question "$RUN" add --text "When was the archive last opened?" --why "timeline" --objective O-1 --as ana --sign --secret-fd 3 3<<<"correct horse battery")" || fail "the signed add failed: $out"
grep -q 'Recorded Q-5 (revision 1), in_scope' <<<"$out" && grep -q 'Signed (event' <<<"$out" || fail "the signed act is not said: $out"
out="$(swarm question "$RUN" add --text "Was the archive split?" --why "x" --objective O-1 --as ana --sign --secret-fd 3 3<<<"a wrong passphrase")" && fail "a wrong passphrase signed: $out"
grep -q 'not signed, so nothing was recorded' <<<"$out" || fail "the wrong passphrase's refusal is not said: $out"
v="$(swarm question "$RUN" verify)" || fail "verify failed: $v"
grep -q 'Q-5 event .*signed by ana (ssh .*): unchecked' <<<"$v" || fail "the signature does not verify under the enrolled key: $v"
grep -q '"identity":"claimed"' <<<"$(grep '"q":"Q-4"' "$SB/questions/questions.jsonl" | head -1)" || fail "the --as claim is not recorded as claimed"
pass "--as names an enrolled analyst as a claim (proposed outside an objective); --sign signs with the passphrase on fd 3, a wrong one records nothing"

# The operator admits it; amendments are revision-bound; clarification round trip; withdraw; accept.
out="$(swarm question "$RUN" scope Q-4 in_scope --why "the printer is in the case")" || fail "scope failed: $out"
grep -q 'Recorded Q-4 (revision 1), in_scope: admitted by' <<<"$out" || fail "the admission is not said: $out"
out="$(swarm question "$RUN" amend Q-3 --expect-rev 2 --text "x")" && fail "a stale amendment was taken: $out"
grep -q 'is at revision 1 .*not 2' <<<"$out" || fail "the stale amendment's refusal does not say the revision: $out"
out="$(swarm question "$RUN" amend Q-3 --expect-rev 1 --text "Was the archive mailed or uploaded to an outside address?" --why "uploads came up")" || fail "amend failed: $out"
grep -q 'Recorded Q-3 (revision 2)' <<<"$out" || fail "the amendment is not revision 2: $out"
node --experimental-strip-types --no-warnings --input-type=module -e '
  const Q = await import(process.argv[1]);
  const r = await Q.questionAsk({ sandboxRoot: process.argv[2], agentId: "a0" }, "Q-3", "outside: outside the company, or outside the country?");
  if (!r.ok) { console.error(r.reason); process.exit(1); }
' "$ROOT/extensions/questions.ts" "$SB" || fail "an agent could not ask for a clarification"
grep -q '"kind":"clarification","id":"C-1","q":"Q-3"' "$SB/operator-requests.jsonl" || fail "the clarification is not an operator request"
grep -q 'CLARIFICATIONS WAITING:' <<<"$(swarm question "$RUN" list)" || fail "the list does not show the clarification waiting"
out="$(swarm question "$RUN" clarify-reply Q-3 C-1 outside the company)" || fail "clarify-reply failed: $out"
grep -q 'Clarification C-1' <<<"$out" || fail "the reply is not said: $out"
grep -l 'CLARIFICATION C-1 on Q-3' "$SB"/threads/main/*.md | xargs grep -q '^to: a0$' || fail "the answer is not posted to the asker"
out="$(swarm question "$RUN" withdraw Q-4)" && fail "a withdrawal without why was taken: $out"
out="$(swarm question "$RUN" withdraw Q-4 --why "the printer was replaced")" || fail "withdraw failed: $out"
grep -q 'Recorded Q-4' <<<"$out" || fail "the withdrawal is not said: $out"
out="$(swarm question "$RUN" accept Q-5 --as bounded --why "only one copy exists" --expect-rev 1)" || fail "accept failed: $out"
grep -q '"ev":"accept"' "$SB/questions/questions.jsonl" || fail "the acceptance is not on the chain"
out="$(swarm question "$RUN" accept Q-3 --as bounded --as ana --why "x" --expect-rev 2)" && fail "an analyst accepted: $out"
grep -q "not an analyst's" <<<"$out" || fail "the analyst's acceptance is refused without why: $out"
pass "admission, a revision-bound amendment, the clarification round trip, a withdrawal with why, and an acceptance only the operator or examiner makes"

# A directive: an unheld lead under a question, with its product.
out="$(swarm lead "$RUN" direct --question Q-3 --title "List the outgoing mails" --why "Q-3" --product "a table of outgoing mails with attachments" --acceptance "every sent item in the store is listed")" || fail "direct failed: $out"
grep -q 'Directive L-1 opened under Q-3, unheld' <<<"$out" || fail "the directive is not said: $out"
lead="$(grep '"ev":"open"' "$SB/leads/leads.jsonl" | head -1)"
[[ "$(jq -r '.product' <<<"$lead")" == "a table of outgoing mails with attachments" && "$(jq -r '.holder // "none"' <<<"$lead")" == none && "$(jq -r '.answers[0]' <<<"$lead")" == 3 ]] || fail "the directive is not an unheld lead under Q-3 with its product: $lead"
out="$(swarm lead "$RUN" direct --question Q-3 --title "x" --why "y")" && fail "a directive without its product was taken: $out"
leads_before="$(wc -l < "$SB/leads/leads.jsonl")"
out="$(swarm lead "$RUN" direct --question Q-3 --title "Signed" --why "y" --product "p" --acceptance "a" --as ana --sign --secret-fd 3 3<<<"correct horse battery")" && fail "a signed directive was taken: $out"
grep -q 'a directive is not signed' <<<"$out" || fail "the signed directive's refusal does not say why: $out"
[[ "$(wc -l < "$SB/leads/leads.jsonl")" -eq "$leads_before" ]] || fail "a refused signed directive wrote a lead"
pass "a directive is an unheld lead under its question, with its product and acceptance; --sign on a directive is refused"

help="$(swarm help question)"
grep -q 'question <id> add --text T --why W' <<<"$help" && grep -q 'dfirswarm-question' <<<"$help" || fail "help question does not describe the command: $help"
grep -q 'question <id> add|list' <<<"$(swarm --help)" || fail "the short usage does not name question"
pass "help question describes every act, and the short usage names it"

echo "question-cli.test.sh: all checks passed"

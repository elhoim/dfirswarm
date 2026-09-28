#!/usr/bin/env bash
# The examiner's review of a ledger (swarm.sh review, scripts/review.ts) and
# an earlier run's claims brought into a new run as hypotheses
# (--ledger-from). No model, no Herdr, no VM.
#
# - accept, reject and amend name an entry by seq and keep its hash; reject
#   and amend need a note; the sign-off is an enrolled examiner's release,
#   never the run's recorded examiner, over the ledger's head and the
#   report; it is refused while the run is running, with no examiner
#   enrolled, over no report and with no custody verdict; `show` exits 4
#   once either has moved since;
# - the review is a chain beside the registry: a line changed breaks it;
# - --ledger-from brings only the accepted (or amended) entries when there
#   is a review, every entry marked unreviewed when there is none, read-only,
#   never into the new ledger, and says so in SWARM.md; it refuses a run that
#   is still running, or held for another case.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/review-test.XXXXXX")"
# The install's machine key and its examiners, in the test's own home.
export DFIRSWARM_HOME="$TMP/home" SWARM_SIGNERS_HOME="$TMP/home"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
RUNS="$TMP/runs"
export SWARM_RUNS_DIR="$RUNS"
swarm() { bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
HELLO="$ROOT/prompts/goals/hello.md"
kick() { swarm start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --toolbox off "$@"; }
sandbox_of() { printf '%s\n' "$1" | sed -n 's/^SANDBOX=//p' | tail -1; }

# An earlier run, ended, with three chained entries.
OLD="$RUNS/srv1"
mkdir -p "$OLD/ledger"
cat > "$OLD/ledger/entries.jsonl" <<'EOF'
{"v":2,"seq":1,"kind":"event","ts":"2024-01-15T12:44:22Z","value":"Admin logon from 10.0.0.5","source":"Security.evtx 4624","evidence":"record 8812","confidence":"high","by":"srv100","authors":["srv100"],"at":"t","prev":"genesis","hash":"a1"}
{"v":2,"seq":2,"kind":"ioc","value":"evil.example.test","source":"hosts file","evidence":"line 3","by":"srv100","authors":["srv100"],"at":"t","prev":"a1","hash":"a2"}
{"v":2,"seq":3,"kind":"finding","value":"Persistence by a scheduled task\nnamed Updater","source":"Tasks","evidence":"XML","by":"srv100","authors":["srv100"],"at":"t","prev":"a2","hash":"a3"}
EOF
jq -n --arg sb "$OLD" '{runs: [{id: "srv1", label: "old", state: "running", sandbox: $sb, n: 1, case_id: "CASE-1", examiner: "Run Examiner"}]}' > "$RUNS/registry.json"

echo "# accept, reject, amend; the sign-off waits for the run to end"
out="$(swarm review srv1 --accept 1 --examiner "H. Examiner")" || fail "accept failed: $out"
set +e
out="$(swarm review srv1 --reject 2 --examiner "H. Examiner")"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'needs a note' <<<"$out" || fail "a reject with no note was taken (rc $rc): $out"
out="$(swarm review srv1 --reject 2 --note "the hosts file is the analyst's own" --examiner "H. Examiner")" || fail "reject failed: $out"
out="$(swarm review srv1 --amend 3 --note "the task is named Updater2" --examiner "H. Examiner")" || fail "amend failed: $out"
set +e
out="$(swarm review srv1 --accept 9 --examiner "H. Examiner")"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'no ledger entry 9' <<<"$out" || fail "an entry that does not exist was reviewed (rc $rc): $out"
set +e
out="$(swarm review srv1 --sign --examiner "H. Examiner")"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'still running' <<<"$out" || fail "a running run's ledger was signed off (rc $rc): $out"
jq '.runs[0].state = "done"' "$RUNS/registry.json" > "$TMP/r" && mv "$TMP/r" "$RUNS/registry.json"
# The sign-off is an enrolled examiner's: with none enrolled it is refused, and the run's recorded examiner is not taken for one.
set +e
out="$(swarm review srv1 --sign --yes)"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'no examiner is enrolled on this install' <<<"$out" || fail "a sign-off with no enrolled examiner was taken (rc $rc): $out"
out="$(swarm examiner enroll --name "H. Examiner" --organisation "Case Lab" --competence "Ten years of casework" --generate-key --no-passphrase </dev/null)" || fail "enrolment failed: $out"
grep -q "For the organisation's signer register" <<<"$out" && grep -q 'SHA256:' <<<"$out" && grep -q 'h-examiner namespaces="dfirswarm-release,dfirswarm-package" ssh-ed25519 ' <<<"$out" || fail "enrolment printed no fingerprint or register line: $out"
grep -q 'PRIVATE KEY' <<<"$out" && fail "enrolment printed a private key"
# A sign-off is over the report the examiner read: with none there, it is refused.
set +e
out="$(swarm review srv1 --sign --yes)"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'there is no work/report.md in run srv1 to sign over' <<<"$out" || fail "a sign-off over no report was taken (rc $rc): $out"
[[ ! -e "$RUNS/reviews/srv1.jsonl" ]] || [[ "$(wc -l < "$RUNS/reviews/srv1.jsonl" | tr -d ' ')" == 3 ]] || fail "a refused sign-off wrote a line"
mkdir -p "$OLD/work"
printf '# Report\n\nPersistence by a scheduled task [#3].\n' > "$OLD/work/report.md"
# With no custody verdict there is nothing a release can bind.
set +e
out="$(swarm review srv1 --sign --yes)"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'no custody verdict to release' <<<"$out" || fail "a sign-off with no custody verdict was taken (rc $rc): $out"
node --experimental-strip-types --no-warnings "$ROOT/scripts/custody.ts" "$OLD" --run srv1 --runs-dir "$RUNS" --quiet >/dev/null 2>&1 || true
out="$(swarm review srv1 --sign --yes)" || fail "the sign-off failed: $out"
grep -q 'v1 ADOPTED by H. Examiner (Case Lab)' <<<"$out" || fail "the sign-off is not the enrolled examiner's release: $out"
grep -q 'Run Examiner' <<<"$out" && fail "the run's recorded examiner was taken for the examiner: $out"
[[ -f "$OLD/release/v0/release.json" && -f "$OLD/release/v1/release.json.sig" ]] || fail "the sign-off wrote no release (v0, the machine's draft, and v1, the adoption)"
jq -e '.state == "draft" and .signer.kind == "machine"' "$OLD/release/v0/release.json" >/dev/null && jq -e '.state == "adopted" and .signer.kind == "examiner" and .signer.examiner.name == "H. Examiner" and .prev.version == 0' "$OLD/release/v1/release.json" >/dev/null \
  || fail "the releases are not a machine draft and the examiner's adoption: $(jq -c '{state, signer: .signer.kind}' "$OLD"/release/v*/release.json)"
F="$RUNS/reviews/srv1.jsonl"
[[ "$(wc -l < "$F" | tr -d ' ')" == 4 ]] || fail "the review holds $(wc -l < "$F") lines, wanted 4"
mode="$(stat -c %a "$F" 2>/dev/null || stat -f %Lp "$F")"
[[ "$mode" == 600 ]] || fail "the review is mode $mode"
jq -s -e '.[0].action == "accept" and .[0].entry_hash == "a1" and .[1].note == "the hosts file is the analyst'"'"'s own"
  and .[3].action == "sign" and .[3].ledger_head == "a3" and .[3].ledger_entries == 3 and .[3].examiner_id == "h-examiner" and .[3].release.version == 1 and (.[3].release.sha256 | length == 64)
  and .[0].prev == null and (.[1].prev | length == 64)' "$F" >/dev/null \
  || fail "the review lines are not what was done: $(cat "$F")"
out="$(swarm review srv1 --show)" || fail "show failed: $out"
grep -q 'the chain verifies' <<<"$out" && grep -q 'over ledger head a3' <<<"$out" && grep -q "With the enrolled examiner's key SHA256:.*: release v1" <<<"$out" || fail "show does not say what was reviewed: $out"
# The report changed after the sign-off: show says so and exits 4, not 0.
cp "$OLD/work/report.md" "$TMP/report.keep"
printf 'and a line added afterwards\n' >> "$OLD/work/report.md"
set +e
out="$(swarm review srv1 --show)"; rc=$?
set -e
[[ $rc -eq 4 ]] && grep -q 'the report has changed since' <<<"$out" && grep -q 'THE SIGN-OFF DOES NOT COVER THE RUN AS IT STANDS' <<<"$out" || fail "a sign-off over an earlier report showed as current (rc $rc): $out"
cp "$TMP/report.keep" "$OLD/work/report.md"
# The ledger moved on after the sign-off: the same.
cp "$OLD/ledger/entries.jsonl" "$TMP/ledger.keep"
printf '%s\n' '{"v":2,"seq":4,"kind":"ioc","value":"late","by":"srv100","authors":["srv100"],"at":"t","prev":"a3","hash":"a4"}' >> "$OLD/ledger/entries.jsonl"
set +e
out="$(swarm review srv1 --show)"; rc=$?
set -e
[[ $rc -eq 4 ]] && grep -q 'the ledger has changed since' <<<"$out" || fail "a sign-off over an earlier ledger showed as current (rc $rc): $out"
cp "$TMP/ledger.keep" "$OLD/ledger/entries.jsonl"
out="$(swarm review srv1 --show)" || fail "show over the signed ledger and report failed: $out"
grep -q '"command":"review"' "$RUNS/operator-audit.jsonl" || fail "the review is not on the operator's audit"
pass "accept, reject and amend name the entry and its hash, a reject needs a note, and the sign-off is over the ledger's head once the run has ended"

echo "# a review line changed breaks the chain, and nothing is added to it"
cp "$F" "$TMP/review.bak"
sed -i.bak 's/"accept"/"reject"/' "$F" && rm -f "$F.bak"
set +e
out="$(swarm review srv1 --show)"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'BROKEN' <<<"$out" || fail "a changed review line was not caught (rc $rc): $out"
set +e
out="$(swarm review srv1 --accept 2 --examiner x)"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'broken' <<<"$out" || fail "an act was added to a broken review (rc $rc): $out"
cp "$TMP/review.bak" "$F"
pass "the review is a chain: an edited line is BROKEN and nothing is added to it"

echo "# --ledger-from: the accepted and amended entries, as hypotheses"
out="$(kick --label new --ledger-from srv1 --case-id CASE-1)" || fail "a kickoff with --ledger-from failed: $out"
sb="$(sandbox_of "$out")"
P="$sb/prior/ledger.md"
[[ -f "$P" ]] || fail "no prior/ledger.md"
grep -q '## srv1#1 · event · accepted by the examiner' "$P" || fail "the accepted entry is not there: $(cat "$P")"
grep -q '## srv1#3 · finding · amended by the examiner' "$P" && grep -q "the task is named Updater2" "$P" || fail "the amended entry or its note is not there"
grep -q 'srv1#2' "$P" && fail "a rejected entry was brought in"
grep -q 'Entry hash: `a1`' "$P" || fail "an entry's hash is not given"
grep -q 'named Updater' "$P" || fail "a multi-line claim was cut"
has_write() { python3 -c 'import os, sys; sys.exit(0 if os.stat(sys.argv[1]).st_mode & 0o222 else 1)' "$1"; }
has_write "$P" && fail "prior/ledger.md is writable"
has_write "$sb/prior" && fail "prior/ is writable"
[[ ! -s "$sb/ledger/entries.jsonl" ]] || fail "the prior entries went into the new ledger"
grep -q "An earlier run's claims (prior/ledger.md)" "$sb/SWARM.md" && grep -q 'the ones its examiner accepted' "$sb/SWARM.md" || fail "SWARM.md does not say what prior/ledger.md is"
jq -e --arg sb "$sb" '.runs[] | select(.sandbox == $sb) | .ledger_from | .run == "srv1" and .entries == 2 and .reviewed == true and (.ledger_sha256 | length == 64)' "$RUNS/registry.json" >/dev/null \
  || fail "the registry does not record what was brought in"
pass "--ledger-from brings the accepted and amended entries, read-only, out of the new ledger, and SWARM.md says what they are"

echo "# without a review, every entry, marked unreviewed"
mv "$F" "$TMP/review.saved"
out="$(kick --label unreviewed --ledger-from srv1 --case-id CASE-1)" || fail "kickoff failed: $out"
sb="$(sandbox_of "$out")"
[[ "$(grep -c '^## srv1#' "$sb/prior/ledger.md")" == 3 ]] || fail "not every entry was brought in: $(cat "$sb/prior/ledger.md")"
grep -q 'unreviewed' "$sb/prior/ledger.md" && grep -q 'unreviewed: no examiner has accepted any of them' "$sb/SWARM.md" || fail "the entries are not marked unreviewed"
mv "$TMP/review.saved" "$F"
pass "without a review every entry comes, marked unreviewed"

echo "# refused: a run still running, one held for another case, one that does not exist"
jq '.runs[0].state = "running"' "$RUNS/registry.json" > "$TMP/r" && mv "$TMP/r" "$RUNS/registry.json"
set +e
out="$(kick --label r1 --ledger-from srv1)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'still running' <<<"$out" || fail "a running run's ledger was brought in (rc $rc): $out"
jq '(.runs[] | select(.id == "srv1")) |= (.state = "done" | .hold = {reason: "matter", at: "t", by: "x"})' "$RUNS/registry.json" > "$TMP/r" && mv "$TMP/r" "$RUNS/registry.json"
set +e
out="$(kick --label r2 --ledger-from srv1 --case-id CASE-2)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'on hold for case CASE-1' <<<"$out" || fail "a run held for another case lent its claims (rc $rc): $out"
out="$(kick --label r3 --ledger-from srv1 --case-id CASE-1)" || fail "the same case was refused: $out"
set +e
out="$(kick --label r4 --ledger-from snosuch)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'no such run' <<<"$out" || fail "a run that does not exist was not refused (rc $rc): $out"
pass "--ledger-from refuses a running run, a run held for another case, and a run that does not exist"

echo "# a FIFO or a link in the review's place is refused by name, never read or waited on"
F="$RUNS/reviews/srv1.jsonl"
cp "$F" "$TMP/review.keep"
rm -f "$F"
mkfifo "$F"
started=$SECONDS
set +e
out="$(swarm review srv1 --show)"; rc=$?
set -e
(( SECONDS - started < 10 )) || fail "a FIFO in the review's place hung the read"
[[ $rc -ne 0 ]] && grep -q 'is not a regular file; it is not read' <<<"$out" || fail "a FIFO was not refused by name (rc $rc): $out"
set +e
out="$(swarm review srv1 --accept 1 --examiner x)"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'not a regular file' <<<"$out" || fail "an act was written through a FIFO (rc $rc): $out"
rm -f "$F"
printf 'elsewhere\n' > "$TMP/elsewhere.jsonl"
ln -s "$TMP/elsewhere.jsonl" "$F"
set +e
out="$(swarm review srv1 --accept 1 --examiner x)"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'a link' <<<"$out" || fail "an act was written through a link (rc $rc): $out"
[[ "$(cat "$TMP/elsewhere.jsonl")" == elsewhere ]] || fail "the link's target was written"
rm -f "$F"
cp "$TMP/review.keep" "$F"
pass "a FIFO or a link in the review's place is refused by name; nothing is read through it, waited on or written through it"

echo "review.test.sh: all checks passed"

#!/usr/bin/env bash
# The report's releases through swarm.sh: the machine's draft when stop
# takes custody, an examiner enrolled on the install, each answer's
# disposition, the sign-off as the examiner's signed release (printed with
# --pdf), releases shown and verified (exit 3 without the organisation's
# register, 0 with it), a mirror line for the case file, a later timestamp
# refused without an authority, the package carrying every release and
# verify walking it, a certification template, a transparency log's
# receipt, --anchor-mirror at kickoff, and rerun's refusals. No model, no Herdr, no
# VM, no network: the run is track P's ledger version 4 fixture.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/release-test.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
RUNS="$TMP/runs"
export SWARM_RUNS_DIR="$RUNS" DFIRSWARM_HOME="$TMP/home" SWARM_SIGNERS_HOME="$TMP/home"
swarm() { bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }

# A stopped-to-be run of the fixture: its ledger, its store, a trace that
# carries every entry's record line, a report.
SB="$RUNS/s9"
mkdir -p "$SB/traces" "$SB/work" "$DFIRSWARM_HOME"
cp -R "$ROOT/tests/fixtures/ledger-v4/ledger" "$SB/ledger"
cp -R "$ROOT/tests/fixtures/ledger-v4/store" "$SB/store"
python3 - "$SB" <<'PY'
import hashlib, json, os, sys
root = sys.argv[1]
prev, out = "", ""
for l in open(os.path.join(root, "ledger", "entries.jsonl")):
    if not l.strip():
        continue
    e = json.loads(l)
    line = json.dumps({"ts": e["at"], "agent": e["by"], "tool": "record", "args": {}, "result": {"ok": True, "seq": e["seq"], "hash": e["hash"]}, "prev": prev}, separators=(",", ":"))
    out += line + "\n"
    prev = hashlib.sha256(line.encode()).hexdigest()
open(os.path.join(root, "traces", "events.jsonl"), "w").write(out)
PY
printf '# Report\n\nThe intruder uploaded shell.php [#14].\n' > "$SB/work/report.md"
jq -n --arg sb "$SB" '{runs: [{id: "s9", label: "fixture", state: "running", sandbox: $sb, n: 4, examiner: "Claude (CTF round 5, macOS)"}]}' > "$RUNS/registry.json"

echo "# stop takes custody and seals the machine's draft"
out="$(swarm stop s9)" || fail "stop failed: $out"
grep -q "Release:      v0 DRAFT, sealed by this install's machine key SHA256:" <<<"$out" || fail "stop wrote no draft: $out"
[[ -f "$SB/release/v0/release.json" && -f "$SB/release/v0/release.json.sig" && -f "$SB/release/v0/report.html" ]] || fail "no release/v0"
out="$(swarm releases s9)"
grep -q '^v0  DRAFT' <<<"$out" && grep -q 'sealed by the machine key SHA256:.*, adopted by no one' <<<"$out" && grep -q 'Evidence cutoff:' <<<"$out" || fail "releases does not show the draft: $out"
out="$(swarm releases s9 --draft)"
grep -q 'release v0 already binds this custody verdict' <<<"$out" || fail "a second draft was written for the same verdict: $out"
out="$(swarm examiner machine)"
grep -q 'Machine key:  SHA256:' <<<"$out" && grep -q 'It is not an examiner and adopts nothing' <<<"$out" || fail "the machine key does not say what it is: $out"
pass "stop seals the machine's draft once per verdict, and the machine key says it is no examiner"

echo "# the examiner is enrolled; the release waits on every defective answer's disposition"
set +e
out="$(swarm review s9 --sign --yes)"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'no examiner is enrolled on this install' <<<"$out" || fail "a sign-off with no examiner enrolled was taken (rc $rc): $out"
out="$(swarm examiner enroll --name "Ada Examiner" --organisation "Lab One" --competence "GCFA; ten years of casework" --generate-key --no-passphrase </dev/null)" || fail "enrolment failed: $out"
REGISTER_LINE="$(grep 'ada-examiner namespaces=' <<<"$out" | sed 's/^ *//')"
[[ -n "$REGISTER_LINE" ]] || fail "enrolment printed no register line: $out"
grep -q 'PRIVATE KEY' <<<"$out" && fail "enrolment printed a private key"
swarm examiner list | grep -q '^ada-examiner	Ada Examiner	Lab One	SHA256:' || fail "the examiner is not listed"
set +e
out="$(swarm review s9 --sign --yes)"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'E-16 (question:3) is not supported as it stands' <<<"$out" && grep -q 'E-17 (summary) is not supported as it stands' <<<"$out" || fail "the release was not refused on the defective answers (rc $rc): $out"
set +e
out="$(swarm review s9 --adopt 16)"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'An unsupported conclusion is not waived' <<<"$out" || fail "an unsupported answer was adopted (rc $rc): $out"
out="$(swarm review s9 --adopt 14)" && grep -q 'entry 14 adopted by Ada Examiner (enrolled examiner ada-examiner)' <<<"$out" || fail "adopt: $out"
swarm review s9 --inconclusive 16 --note "the archive's hash is stated in no entry it rests on" >/dev/null || fail "inconclusive"
swarm review s9 --reject 17 --note "it rests on the superseded answer to question 2" >/dev/null || fail "reject"
set +e
out="$(swarm review s9 --technical-review --reviewer "Bo Reviewer" --competence "EnCE" --checked "re-ran fls and the proxy-log search" --entries 4,10)"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'says its outcome (--outcome agreed|issues-resolved|disagreement)' <<<"$out" || fail "a technical review with no outcome was taken (rc $rc): $out"
out="$(swarm review s9 --technical-review --reviewer "Bo Reviewer" --competence "EnCE" --checked "re-ran fls and the proxy-log search" --entries 4,10 --outcome agreed)" || fail "technical review: $out"
grep -q "a technical review by Bo Reviewer (agreed), recorded by the examiner Ada Examiner; not signed by the reviewer" <<<"$out" || fail "technical review: $out"
pass "enrolment gives the register line; adoption refuses an unsupported answer; the release waits on each defective answer"

echo "# the sign-off is the examiner's release, printed with --pdf"
export SWARM_CHROME="$TMP/chrome"
cat > "$SWARM_CHROME" <<'SH'
#!/usr/bin/env bash
for a in "$@"; do case "$a" in --print-to-pdf=*) out="${a#--print-to-pdf=}" ;; esac; done
printf '%%PDF-1.4\n%% a stand-in print\n' > "$out"
SH
chmod +x "$SWARM_CHROME"
# With no terminal to confirm on, a sign-off without --yes is refused (only checked where this
# shell has none: at a terminal it would ask there).
if ! ( : </dev/tty ) 2>/dev/null; then
  set +e
  out="$(swarm review s9 --sign --pdf </dev/null)"; rc=$?
  set -e
  [[ $rc -ne 0 ]] && grep -q "asks for the examiner's confirmation on the terminal, and there is none" <<<"$out" || fail "a sign-off with no terminal and no --yes was taken (rc $rc): $out"
fi
out="$(swarm review s9 --sign --pdf --yes)" || fail "the sign-off failed: $out"
grep -q 'Consent:      presented; its confirmation was skipped (--yes)' <<<"$out" || fail "the sign-off does not say the consent was only presented: $out"
grep -q 'Release:      v1 ADOPTED by Ada Examiner (Lab One), signed with SHA256:.* (with report.pdf)' <<<"$out" || fail "no adopted release: $out"
grep -q 'a new examination is a new run' <<<"$out" || fail "the evidence cutoff is not said: $out"
[[ -f "$SB/release/v1/report.pdf" ]] || fail "no report.pdf in release v1"
grep -q 'class="watermark"' "$SB/release/v1/report.html" && fail "the adopted release's HTML carries the DRAFT mark"
grep -q 'class="watermark"' "$SB/release/v0/report.html" || fail "the draft's HTML has no DRAFT mark"
set +e
out="$(swarm releases s9 --verify)"; rc=$?
set -e
[[ $rc -eq 3 ]] && grep -q "RELEASES VERIFIED, THE EXAMINER'S KEY NOT CHECKED" <<<"$out" || fail "verify without a register (rc $rc): $out"
printf '%s\n' "$REGISTER_LINE" > "$TMP/register"
out="$(swarm releases s9 --verify --allowed-signers "$TMP/register")" || fail "verify with the register: $out"
grep -q 'signature verified, by ada-examiner' <<<"$out" && grep -q 'RELEASES VERIFIED\.' <<<"$out" || fail "verify with the register: $out"
out="$(swarm review s9 --show)"
grep -q "With the enrolled examiner's key SHA256:.*: release v1" <<<"$out" || fail "show does not name the release: $out"
pass "the sign-off renders, prints and signs release v1 with the examiner's key; verify says who, against the register"

echo "# a mirror line for the case file; a later timestamp needs an authority"
out="$(swarm releases s9 --mirror print)" || fail "mirror: $out"
grep -Eq 'QR-ready: DFSR1:S9:V1:[0-9A-F]{64}' <<<"$out" && [[ -f "$SB/release/v1/case-file.txt" ]] || fail "no case-file line: $out"
set +e
out="$(swarm timestamp s9)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'no timestamp authority' <<<"$out" || fail "a timestamp with no authority (rc $rc): $out"
pass "the digest line is printed for the case file; swarm.sh timestamp names the authority it needs"

echo "# the package carries every release; verify walks them"
out="$(swarm package s9)" || fail "package: $out"
PKG="$SB/package"
for f in release/v0/release.json release/v0/release.json.sig release/v1/release.json release/v1/report.html release/v1/report.pdf release/v1/case-file.txt ledger-disputes.jsonl; do
  [[ -f "$PKG/$f" ]] || fail "the package has no $f"
done
jq -e '.components[] | select(.path == "release") | .present == true' "$PKG/COMPONENTS.json" >/dev/null || fail "COMPONENTS.json does not list the releases"
set +e
out="$(swarm verify "$PKG" --allowed-signers "$TMP/register")"; rc=$?
set -e
[[ $rc -eq 4 ]] || fail "an unsigned package verified with exit $rc: $out"
grep -q 'Release v1:   ADOPTED, .*signature verified, by ada-examiner' <<<"$out" && grep -q 'Releases:     2 (v0..v1); the latest adoption is v1 by Ada Examiner' <<<"$out" || fail "verify does not walk the releases: $out"
chmod u+w "$PKG/release/v1/report.html"
printf 'edited\n' >> "$PKG/release/v1/report.html"
set +e
out="$(swarm verify "$PKG" --allowed-signers "$TMP/register")"; rc=$?
set -e
[[ $rc -eq 1 ]] && grep -q 'report.html NOT THE BOUND BYTES' <<<"$out" || fail "an edited release in the package passed (rc $rc): $out"
pass "the package carries every release byte for byte, and verify names an edited one"

echo "# certify: a template for a qualified person, with the verification verbatim"
swarm package s9 >/dev/null || fail "package again"
out="$(swarm certify "$PKG" --allowed-signers "$TMP/register" --out "$TMP/certification.txt")" || fail "certify: $out"
grep -q 'Wrote .*certification.txt: a certification template for .* (swarm.sh verify exit 4)' <<<"$out" || fail "certify: $out"
C="$TMP/certification.txt"
grep -q '^CERTIFICATION OF RECORDS GENERATED BY AN ELECTRONIC PROCESS' "$C" && grep -q 'v1: ADOPTED by Ada Examiner (Lab One), an enrolled examiner' "$C" \
  && grep -q '   Release v1:   ADOPTED, .*signature verified, by ada-examiner' "$C" && grep -q '   exit 4: every file matches the manifest, and the package is not signed' "$C" \
  && grep -q 'Name: *______' "$C" || fail "the certification template: $(cat "$C")"
out="$(swarm releases s9 --transparency "cat >/dev/null; echo '{\"logIndex\": 7}'")" || fail "transparency: $out"
grep -q 'the log answered; its receipt is transparency-1.json' <<<"$out" && [[ -f "$SB/release/v1/transparency-1.json" ]] || fail "transparency: $out"
pass "certify writes a template with the package's own record and verify's output verbatim; a transparency log's receipt is kept"

echo "# --anchor-mirror at kickoff: checked, and recorded"
HELLO="$ROOT/prompts/goals/hello.md"
kick() { swarm start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --toolbox off "$@"; }
set +e
out="$(kick --label m1 --anchor-mirror "dir:$TMP/absent")"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'is not a directory (it is made by whoever keeps it, not here)' <<<"$out" || fail "a mirror directory that is not there was taken (rc $rc): $out"
set +e
out="$(kick --label m2 --anchor-mirror "ftp://x")"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'takes cmd:COMMAND, dir:PATH or print' <<<"$out" || fail "a mirror that is none of the three was taken (rc $rc): $out"
out="$(kick --label m3 --anchor-mirror print)" || fail "kickoff with --anchor-mirror print: $out"
jq -e '.runs[] | select(.label == "m3") | .anchor_mirror == "print"' "$RUNS/registry.json" >/dev/null || fail "the registry does not record the mirror"
grep -q '"command":"releases"' "$RUNS/operator-audit.jsonl" && grep -q '"command":"examiner"' "$RUNS/operator-audit.jsonl" || fail "releases and examiner are not on the operator's audit"
pass "--anchor-mirror is checked and recorded; releases and examiner are on the operator's audit"

echo "# rerun: a finished run's sealed job, refused with why when it cannot be"
set +e
out="$(swarm rerun s9 notajob)"; rc=$?
set -e
[[ $rc -eq 1 ]] && grep -q 'is not a job id' <<<"$out" || fail "rerun took a job id that is none (rc $rc): $out"
set +e
out="$(swarm rerun s9 j000001)"; rc=$?
set -e
[[ $rc -eq 1 ]] && grep -q 'the run has no store journal: it ran no jobs' <<<"$out" || fail "rerun of a run with no journal (rc $rc): $out"
pass "rerun names why a job cannot be run again"

echo "release.test.sh: all checks passed"

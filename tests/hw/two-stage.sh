#!/usr/bin/env bash
# Hardware test 4: two-stage signing with two real keys. A technical reviewer
# whose key is an e-signature certificate on a token records the review and
# signs it with the token (the PIN typed on the terminal); the examiner, whose
# key is a FIDO key, then signs the release, which binds the reviewer's signed
# record. The policy that asks for a technical review is on, so the release
# is refused without it. Verify checks both signatures: the reviewer's CMS
# against the CA, the examiner's against the register line.
#
# One person holds both keys here; the test enrols them as two people with
# two names and two keys, which is what the independence check reads. The
# certificate's subject serialNumber is never printed (as in eimza.sh).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

MODULE="${DFIRSWARM_HW_PKCS11_MODULE:-/usr/local/lib/libeTPkcs11.dylib}"
OBJ_ID="${DFIRSWARM_HW_PKCS11_ID:-0416041476cf21a543b6b986e1106b6751705a1ac4ad1f06}"
CA="${DFIRSWARM_HW_CA:-}"
CA_INTER="${DFIRSWARM_HW_CA_INTERMEDIATE:-}"
[[ -f "$MODULE" ]] || fail "no PKCS#11 module at $MODULE (DFIRSWARM_HW_PKCS11_MODULE)"
[[ -n "$CA" && -f "$CA" ]] || fail "DFIRSWARM_HW_CA must name the issuer's root certificate (PEM)"
PKCS11_TOOL="$(command -v pkcs11-tool || true)"
[[ -n "$PKCS11_TOOL" ]] || fail "pkcs11-tool (OpenSC) is not on PATH"
OPENSSL="${DFIRSWARM_OPENSSL:-}"
[[ -n "$OPENSSL" ]] || { [[ -x /opt/homebrew/opt/openssl@3/bin/openssl ]] && OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl || OPENSSL="$(command -v openssl)"; }
SUBJECT_SERIAL="$("$PKCS11_TOOL" --module "$MODULE" --read-object --type cert --id "$OBJ_ID" 2>/dev/null | "$OPENSSL" x509 -inform DER -noout -subject -nameopt multiline 2>/dev/null | awk -F' = ' '/serialNumber/ {print $2; exit}')"
no_serial() { # <file> <what>
  if [[ -n "$SUBJECT_SERIAL" ]] && grep -rqF -- "$SUBJECT_SERIAL" "$1"; then fail "$2 shows the certificate subject's serialNumber"; fi
}

hw_run shwtwostage "HW Examiner" hw-exam
chain=()
[[ -n "$CA_INTER" ]] && chain=(--pkcs11-chain "$CA_INTER")

say "Enrolling the examiner's FIDO key. Touch the YubiKey every time it blinks: two touches, sometimes three."
node_ts "$HW_ROOT/scripts/signers.ts" enroll --name "HW Examiner" --id hw-exam --organisation "Hardware test" --competence "hardware test" --fido | tee "$HW_TMP/enrol-exam.txt" || fail "the examiner's FIDO key was not enrolled"
grep -E 'namespaces="dfirswarm-release,dfirswarm-package" sk-ssh-ed25519@openssh.com ' "$HW_TMP/enrol-exam.txt" | sed 's/^ *//' > "$HW_TMP/register"
[[ -s "$HW_TMP/register" ]] || fail "no register line for the examiner's FIDO key"
ok "the examiner is enrolled with a FIDO key"

say "Enrolling the reviewer's e-signature certificate (read without the PIN)."
node_ts "$HW_ROOT/scripts/signers.ts" enroll --role reviewer --name "HW Reviewer" --id hw-rev --organisation "Hardware test lab" --competence "technical reviewer, hardware test" --pkcs11-module "$MODULE" --pkcs11-id "$OBJ_ID" ${chain[@]+"${chain[@]}"} > "$HW_TMP/enrol-rev.txt" 2>&1 || { no_serial "$HW_TMP/enrol-rev.txt" "a failed enrolment"; cat "$HW_TMP/enrol-rev.txt"; fail "the reviewer was not enrolled"; }
no_serial "$HW_TMP/enrol-rev.txt" "the reviewer's enrolment"
ok "the reviewer is enrolled with the token's certificate"

export SWARM_REQUIRE_TECHNICAL_REVIEW=1
say "With the policy on, the release is refused before any technical review (no key is asked for)."
set +e
node_ts "$HW_ROOT/scripts/release.ts" sign --runs "$RUNS" --run "$RUN_ID" --sandbox "$SANDBOX" --examiner hw-exam --no-timestamp --yes > "$HW_TMP/refused.txt" 2>&1; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -qi 'technical review' "$HW_TMP/refused.txt" || { cat "$HW_TMP/refused.txt"; fail "the release was not refused for want of a technical review (rc $rc)"; }
ok "refused without a technical review"

say "The reviewer records and signs the review. Answer y, then type the e-imza PIN (it is not shown)."
node_ts "$HW_ROOT/scripts/technical-review.ts" record --runs "$RUNS" --run "$RUN_ID" --sandbox "$SANDBOX" --reviewer hw-rev --outcome agreed --checked "each adopted answer's method against the sealed job outputs" --all-answers 2>&1 | tee "$HW_TMP/review.txt"
[[ "${PIPESTATUS[0]}" -eq 0 ]] || { no_serial "$HW_TMP/review.txt" "a failed review"; fail "the technical review was not recorded and signed"; }
no_serial "$HW_TMP/review.txt" "the review's output"
ok "the technical review is recorded and signed on the token"

say "The examiner signs the release. Answer y, then touch the YubiKey when it blinks."
node_ts "$HW_ROOT/scripts/release.ts" sign --runs "$RUNS" --run "$RUN_ID" --sandbox "$SANDBOX" --examiner hw-exam --no-timestamp | tee "$HW_TMP/sign.txt" || fail "the release was not signed"
grep -q 'signed by the reviewer' "$HW_TMP/sign.txt" || fail "the release does not show the reviewer's signed review"
ok "release v1 was signed by the examiner and binds the reviewer's signed review"

say "Verify both signatures: the examiner's against the register line, the reviewer's against the CA"
vargs=(--allowed-signers "$HW_TMP/register" --ca "$CA")
[[ -n "$CA_INTER" ]] && vargs+=(--ca-intermediate "$CA_INTER")
node_ts "$HW_ROOT/scripts/release.ts" verify "$SANDBOX" --run "$RUN_ID" --runs "$RUNS" "${vargs[@]}" > "$HW_TMP/verify.txt" 2>&1 || { no_serial "$HW_TMP/verify.txt" "verify"; cat "$HW_TMP/verify.txt"; fail "verify did not pass"; }
no_serial "$HW_TMP/verify.txt" "verify"
cat "$HW_TMP/verify.txt"
grep -q 'RELEASES VERIFIED\.' "$HW_TMP/verify.txt" || fail "verify did not say RELEASES VERIFIED"
grep -q 'signed by the reviewer' "$HW_TMP/verify.txt" || fail "verify does not say the reviewer signed"
ok "both signatures verify: the examiner's FIDO key and the reviewer's e-signature"
echo "two-stage.sh: all checks passed"

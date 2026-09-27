#!/usr/bin/env bash
# Hardware test 2: an e-signature certificate on a token (a SafeNet eToken
# with a qualified certificate) enrolled without its PIN, then a release
# signed with the PIN typed on the terminal (a CAdES-BES CMS made on the
# token, the PDF signed beside it) and verified against the CA.
#
# The certificate's subject carries a national identity number. This test
# reads it once from the token, holds it in a shell variable it never
# prints, and checks that no output of the product carries it.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

MODULE="${DFIRSWARM_HW_PKCS11_MODULE:-/usr/local/lib/libeTPkcs11.dylib}"
OBJ_ID="${DFIRSWARM_HW_PKCS11_ID:-0416041476cf21a543b6b986e1106b6751705a1ac4ad1f06}"
CA="${DFIRSWARM_HW_CA:-}"
CA_INTER="${DFIRSWARM_HW_CA_INTERMEDIATE:-}"
[[ -f "$MODULE" ]] || fail "no PKCS#11 module at $MODULE (DFIRSWARM_HW_PKCS11_MODULE)"
[[ -n "$CA" && -f "$CA" ]] || fail "DFIRSWARM_HW_CA must name the issuer's root certificate (PEM): compare its sha256 with the national trust list first"
PKCS11_TOOL="$(command -v pkcs11-tool || true)"
[[ -n "$PKCS11_TOOL" ]] || fail "pkcs11-tool (OpenSC) is not on PATH"
OPENSSL="${DFIRSWARM_OPENSSL:-}"
[[ -n "$OPENSSL" ]] || { [[ -x /opt/homebrew/opt/openssl@3/bin/openssl ]] && OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl || OPENSSL="$(command -v openssl)"; }

# The subject's serialNumber, to hold every output to never showing it. Never printed.
SUBJECT_SERIAL="$("$PKCS11_TOOL" --module "$MODULE" --read-object --type cert --id "$OBJ_ID" 2>/dev/null | "$OPENSSL" x509 -inform DER -noout -subject -nameopt multiline 2>/dev/null | awk -F' = ' '/serialNumber/ {print $2; exit}')"
[[ -n "$SUBJECT_SERIAL" ]] || echo "(the certificate's subject has no serialNumber: the privacy check has nothing to look for)"
no_serial() { # <file> <what>
  if [[ -n "$SUBJECT_SERIAL" ]] && grep -rqF -- "$SUBJECT_SERIAL" "$1"; then fail "$2 shows the certificate subject's serialNumber"; fi
}

hw_run shweimza "HW Examiner" hw-eimza
chain=()
[[ -n "$CA_INTER" ]] && chain=(--pkcs11-chain "$CA_INTER")

say "Enrolling the token's certificate: it is read without the PIN."
node_ts "$HW_ROOT/scripts/signers.ts" enroll --name "HW Examiner" --id hw-eimza --organisation "Hardware test" --competence "hardware test" --pkcs11-module "$MODULE" --pkcs11-id "$OBJ_ID" ${chain[@]+"${chain[@]}"} > "$HW_TMP/enrol.txt" 2>&1 || { no_serial "$HW_TMP/enrol.txt" "a failed enrolment"; cat "$HW_TMP/enrol.txt"; fail "the certificate was not enrolled"; }
no_serial "$HW_TMP/enrol.txt" "the enrolment"
cat "$HW_TMP/enrol.txt"
grep -q '^Key: *e-signature certificate X509-SHA256:[0-9a-f]\{64\}: CN ' "$HW_TMP/enrol.txt" || fail "the enrolment does not show the certificate"
node_ts "$HW_ROOT/scripts/signers.ts" show hw-eimza > "$HW_TMP/show.txt" 2>&1
no_serial "$HW_TMP/show.txt" "examiner show"
no_serial "$SWARM_SIGNERS_HOME/examiners/hw-eimza.json" "the enrolment record's shown fields"
ok "the certificate is enrolled, shown by CN, issuer, validity and fingerprint only"

say "Now the release. Answer y to adopt it, then type the e-imza PIN (it is not shown)."
pdf=()
[[ "${DFIRSWARM_HW_PDF:-}" == 1 ]] && pdf=(--pdf)
node_ts "$HW_ROOT/scripts/release.ts" sign --runs "$RUNS" --run "$RUN_ID" --sandbox "$SANDBOX" --examiner hw-eimza --no-timestamp ${pdf[@]+"${pdf[@]}"} 2>&1 | tee "$HW_TMP/sign.txt"
[[ "${PIPESTATUS[0]}" -eq 0 ]] || { no_serial "$HW_TMP/sign.txt" "a failed signature"; fail "the release was not signed"; }
no_serial "$HW_TMP/sign.txt" "the signature's output"
[[ -f "$SANDBOX/release/v1/release.json.p7s" ]] || fail "release v1 has no CMS signature"
jq -e '.signer.key_kind == "pkcs11" and .signing.consent == "confirmed" and (.signing.openssl | length > 0)' "$SANDBOX/release/v1/release.json" >/dev/null || fail "release v1 does not record the e-signature and how it was made"
no_serial "$SANDBOX/release/v1/release.json" "release.json"
"$OPENSSL" cms -cmsout -print -inform DER -in "$SANDBOX/release/v1/release.json.p7s" 2>/dev/null | grep -q 'signingCertificateV2\|1.2.840.113549.1.9.16.2.47' || fail "the CMS carries no signing-certificate-v2 attribute (not CAdES-BES)"
ok "release v1 was signed on the token (CAdES-BES)"

say "Verify: without the CA (the chain not checked), then against it"
set +e
node_ts "$HW_ROOT/scripts/release.ts" verify "$SANDBOX" --run "$RUN_ID" --runs "$RUNS" > "$HW_TMP/verify-nochain.txt" 2>&1; rc=$?
set -e
no_serial "$HW_TMP/verify-nochain.txt" "verify"
[[ $rc -eq 3 ]] && grep -q 'certificate chain not checked' "$HW_TMP/verify-nochain.txt" || { cat "$HW_TMP/verify-nochain.txt"; fail "verify without a CA (rc $rc)"; }
vargs=(--ca "$CA")
[[ -n "$CA_INTER" && ${#chain[@]} -eq 0 ]] && vargs+=(--ca-intermediate "$CA_INTER")
node_ts "$HW_ROOT/scripts/release.ts" verify "$SANDBOX" --run "$RUN_ID" --runs "$RUNS" "${vargs[@]}" > "$HW_TMP/verify.txt" 2>&1 || { cat "$HW_TMP/verify.txt"; fail "verify against the CA"; }
no_serial "$HW_TMP/verify.txt" "verify"
cat "$HW_TMP/verify.txt"
grep -q 'its chain verified against the trust anchor(s)' "$HW_TMP/verify.txt" && grep -q 'RELEASES VERIFIED\.' "$HW_TMP/verify.txt" || fail "the chain was not verified"
ok "the e-signature verifies, its chain against the CA (the anchor's sha256 is in the line above)"
echo "eimza.sh: all checks passed"

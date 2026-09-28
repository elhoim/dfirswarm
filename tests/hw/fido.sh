#!/usr/bin/env bash
# Hardware test 1: a FIDO key (a YubiKey) enrolled, then a release signed and
# verified with it on the command line. Touches the key twice (once to make
# the key, once to sign) and asks for the FIDO PIN only when the key wants
# one. Everything is made in a temporary directory and removed after.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

say "FIDO test: which ssh-keygen will be used"
node_ts -e 'import("'"$HW_ROOT"'/scripts/signers.ts").then((m) => { const k = m.fidoKeygen(); console.log("why" in k ? `none: ${k.why}` : `${k.path} (${k.how})`); if ("why" in k) process.exit(1); })' || fail "no FIDO-capable ssh-keygen"

hw_run shwfido "HW Examiner" hw-examiner
extra=()
[[ "${DFIRSWARM_HW_FIDO_VERIFY:-}" == 1 ]] && extra+=(--fido-verify-required)

say "Touch the YubiKey every time it blinks, to make the key: two touches, sometimes three (type its FIDO PIN first if asked)."
node_ts "$HW_ROOT/scripts/signers.ts" enroll --name "HW Examiner" --id hw-examiner --organisation "Hardware test" --competence "hardware test" --fido ${extra[@]+"${extra[@]}"} | tee "$HW_TMP/enrol.txt" || fail "the FIDO key was not enrolled"
grep -q '^Key: *FIDO key SHA256:' "$HW_TMP/enrol.txt" || fail "the enrolment does not say it is a FIDO key"
grep -E 'namespaces="dfirswarm-release,dfirswarm-package" sk-ssh-ed25519@openssh.com ' "$HW_TMP/enrol.txt" | sed 's/^ *//' > "$HW_TMP/register"
[[ -s "$HW_TMP/register" ]] || fail "no register line for the FIDO key"
ok "a FIDO key was made on the authenticator and enrolled"

say "Now the release. Answer y to adopt it, then touch the YubiKey now, when it blinks (and type its FIDO PIN if asked)."
node_ts "$HW_ROOT/scripts/release.ts" sign --runs "$RUNS" --run "$RUN_ID" --sandbox "$SANDBOX" --examiner hw-examiner --no-timestamp | tee "$HW_TMP/sign.txt" || fail "the release was not signed"
grep -q 'ADOPTED by HW Examiner (Hardware test), signed with the FIDO key SHA256:' "$HW_TMP/sign.txt" || fail "the release does not name the FIDO key"
grep -q 'Consent:      confirmed at the terminal' "$HW_TMP/sign.txt" || fail "the consent was not confirmed on the terminal"
jq -e '.signer.key_kind == "fido" and .signing.consent == "confirmed" and .signing.via == "cli" and (.signing.ssh_keygen | test("ssh-keygen$"))' "$SANDBOX/release/v1/release.json" >/dev/null || fail "release v1 does not record the FIDO key and how it was signed"
ok "release v1 was signed with a touch"

say "Verify, against the register line the enrolment printed"
node_ts "$HW_ROOT/scripts/release.ts" verify "$SANDBOX" --run "$RUN_ID" --runs "$RUNS" --allowed-signers "$HW_TMP/register" | tee "$HW_TMP/verify.txt" || fail "verify did not pass"
grep -q 'RELEASES VERIFIED\.' "$HW_TMP/verify.txt" || fail "verify did not say RELEASES VERIFIED"
grep -q 'machine seal, self-checked' "$HW_TMP/verify.txt" || fail "v0 is not said to be the machine's self-checked seal"
ok "the FIDO signature verifies against the register; v0 is the machine's seal"
echo "fido.sh: all checks passed"

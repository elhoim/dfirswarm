#!/usr/bin/env bash
# Hardware test 3: the console's seal path with a real key. The console
# runs on loopback with a token; the release is prepared through its API,
# the prepared bytes fetched and hashed, and the seal sent with the secret
# read here with echo off and piped into curl's body (never in argv). The
# key is a FIDO key (DFIRSWARM_HW_KIND=fido, the default: touch it when
# asked) or the e-signature token (DFIRSWARM_HW_KIND=pkcs11: type the PIN).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

KIND="${DFIRSWARM_HW_KIND:-fido}"
hw_run shwconsole "HW Examiner" hw-console
case "$KIND" in
  fido)
    say "Touch the YubiKey now, when it blinks, to make the key."
    node_ts "$HW_ROOT/scripts/signers.ts" enroll --name "HW Examiner" --id hw-console --organisation "Hardware test" --competence "hardware test" --fido >/dev/null || fail "the FIDO key was not enrolled" ;;
  pkcs11)
    node_ts "$HW_ROOT/scripts/signers.ts" enroll --name "HW Examiner" --id hw-console --organisation "Hardware test" --competence "hardware test" \
      --pkcs11-module "${DFIRSWARM_HW_PKCS11_MODULE:-/usr/local/lib/libeTPkcs11.dylib}" --pkcs11-id "${DFIRSWARM_HW_PKCS11_ID:-0416041476cf21a543b6b986e1106b6751705a1ac4ad1f06}" >/dev/null 2>&1 || fail "the certificate was not enrolled" ;;
  *) fail "DFIRSWARM_HW_KIND is fido or pkcs11" ;;
esac

PORT="${DFIRSWARM_HW_PORT:-43977}"
TOKEN="$(openssl rand -hex 16)"
SWARM_UI_TOKEN="$TOKEN" node_ts "$HW_ROOT/scripts/ui-server.ts" --port "$PORT" --host 127.0.0.1 > "$HW_TMP/ui.log" 2>&1 &
UI_PID=$!
disown "$UI_PID" 2>/dev/null || true
trap 'kill $UI_PID 2>/dev/null; cleanup' EXIT
for _ in $(seq 1 50); do curl -fsS "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1 && break; sleep 0.2; done
api() { curl -sS -H "authorization: Bearer $TOKEN" -H "content-type: application/json" "$@"; }

jq -e '.people[] | select(.id == "hw-console") | .console == "ok"' <(curl -sS "http://127.0.0.1:$PORT/api/examiners") >/dev/null || fail "the console does not take the key"
P="$(api -X POST --data "{\"examiner\":\"hw-console\"}" "http://127.0.0.1:$PORT/api/runs/$RUN_ID/release/prepare")"
NONCE="$(jq -r '.nonce // empty' <<<"$P")"
[[ -n "$NONCE" ]] || fail "prepare: $(jq -r '.error // .' <<<"$P")"
curl -sS "http://127.0.0.1:$PORT$(jq -r .report_url <<<"$P")" -o "$HW_TMP/shown.html"
SHOWN="$(shasum -a 256 "$HW_TMP/shown.html" | cut -d' ' -f1)"
[[ "$SHOWN" == "$(jq -r .report.html.sha256 <<<"$P")" ]] || fail "the bytes fetched are not the bytes prepared"
ok "prepared release v$(jq -r .version <<<"$P"); the report fetched hashes to $SHOWN"

SECRET=""
if [[ "$KIND" == pkcs11 ]]; then
  read -rs -p "Type the e-imza PIN (not shown) and press Enter: " SECRET; echo
elif [[ "$(jq -r .signer.secret <<<"$P")" == fido-pin ]]; then
  read -rs -p "Type the FIDO PIN (not shown) and press Enter: " SECRET; echo
fi
[[ "$KIND" == fido ]] && say "Touch the YubiKey now, when it blinks."
# The secret goes from this shell's variable through printf (a builtin) and a pipe into jq and curl: in no argv.
R="$(printf '%s' "$SECRET" | jq -Rs --arg n "$NONCE" --arg s "$SHOWN" '{nonce: $n, shown_sha256: $s, examiner: "hw-console", consent: true, secret: .}' | api -X POST --data-binary @- "http://127.0.0.1:$PORT/api/runs/$RUN_ID/release/seal")"
SECRET=""
[[ "$(jq -r '.ok // false' <<<"$R")" == true ]] || fail "seal: $(jq -r '.error // .' <<<"$R")"
jq -e '.signing.via == "console" and .signing.consent == "confirmed"' "$SANDBOX/release/v1/release.json" >/dev/null || fail "release v1 does not say it was signed from the console"
grep -q '"command":"release-seal"' "$RUNS/operator-audit.jsonl" || fail "the seal is not on the operator's record"
ok "release v$(jq -r .version <<<"$R") was sealed from the console: $(jq -r .line <<<"$R")"
echo "console.sh: all checks passed"

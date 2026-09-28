#!/usr/bin/env bash
# A redacted package through swarm.sh: what redaction replaced is recorded
# (REDACTIONS.json), and a sensitive entry's words still in the package
# after it refuse the handover, named by file and entry and never by the
# words, unless the operator hands it over with the hits listed
# (--redact-leaks list), which verify then says. No model, no Herdr, no VM.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/redact-test.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
export SWARM_RUNS_DIR="$TMP/runs" SWARM_SIGNERS_HOME="$TMP/signers"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
swarm() { bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }

KEY="5f3c9a17e2b84d06a1c7f9e3b2d58a40"
out="$(swarm start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off --label redact)" || fail "kickoff: $out"
SB="$(sed -n 's/^SANDBOX=//p' <<<"$out" | tail -1)"
ID="$(jq -r --arg sb "$SB" '.runs[] | select(.sandbox == $sb) | .id' "$SWARM_RUNS_DIR/registry.json")"
[[ -n "$SB" && -n "$ID" ]] || fail "no sandbox from the kickoff: $out"
jq --arg id "$ID" '(.runs[] | select(.id == $id) | .state) = "done"' "$SWARM_RUNS_DIR/registry.json" > "$TMP/r" && mv "$TMP/r" "$SWARM_RUNS_DIR/registry.json"
ROOT="$ROOT" node --experimental-strip-types --no-warnings -e '
const [root, key] = process.argv.slice(1);
const P = await import(process.env.ROOT + "/extensions/protocol.ts");
const r = await P.recordEntry({ sandboxRoot: root, agentId: "a0" }, { kind: "ioc", value: `Vault key ${key}`, source: "memory", evidence: "strings over the dump", sensitive: true });
if (!r.ok) { console.error(r.reason); process.exit(1); }
' "$SB" "$KEY" || fail "the sensitive entry was not recorded"
mkdir -p "$SB/work/a0"
printf 'the key is %s\n' "$KEY" > "$SB/work/a0/notes.md"
# The same key in UTF-16: no word replacement reads it.
printf '\xff\xfe' > "$SB/work/a0/notes-utf16.txt"
printf 'key %s\n' "$KEY" | iconv -f UTF-8 -t UTF-16LE >> "$SB/work/a0/notes-utf16.txt"

echo "# a word left after redaction refuses the handover"
set +e
out="$(swarm package "$ID" --redact)"; rc=$?
set -e
[[ $rc -eq 1 ]] && grep -q "still hold a sensitive entry's words; nothing was handed over" <<<"$out" && grep -q "work/a0/notes-utf16.txt: entry 1's words (sha256 " <<<"$out" || fail "a leak did not refuse the package (rc $rc): $out"
grep -q "$KEY" <<<"$out" && fail "the refusal printed the key itself"
[[ ! -e "$SB/package" ]] || fail "a refused package was left behind"
pass "a sensitive entry's words left after redaction refuse the handover, named by file and entry, never the words"

echo "# handed over with the hits listed, and verify says so"
out="$(swarm package "$ID" --redact --redact-leaks list)" || fail "package with --redact-leaks list: $out"
grep -q 'the leak scan over [0-9]* file(s) FOUND 1 HIT(S), listed in REDACTIONS.json' <<<"$out" || fail "the hits are not said: $out"
jq -e '.leak_scan.mode == "list" and (.leak_scan.hits | length) == 1 and .leak_scan.hits[0].path == "work/a0/notes-utf16.txt" and (.changes | map(.path) | index("work/a0/notes.md")) != null' "$SB/package/REDACTIONS.json" >/dev/null || fail "REDACTIONS.json: $(cat "$SB/package/REDACTIONS.json")"
grep -q "$KEY" "$SB/package/work/a0/notes.md" && fail "the key is still in notes.md"
grep -q '"REDACTIONS.json"\|REDACTIONS.json' "$SB/package/MANIFEST.txt" || fail "REDACTIONS.json is not under the manifest"
set +e
out="$(swarm verify "$SB/package")"; rc=$?
set -e
[[ $rc -eq 4 ]] && grep -q 'the leak scan after it FOUND 1 HIT(S), LISTED: work/a0/notes-utf16.txt (entry 1)' <<<"$out" || fail "verify does not say the listed hit (rc $rc): $out"
pass "handed over with the hits listed in REDACTIONS.json, under the manifest; verify says them"

echo "# nothing left: the scan says so"
rm -f "$SB/work/a0/notes-utf16.txt"
out="$(swarm package "$ID" --redact)" || fail "package: $out"
grep -q 'the leak scan over [0-9]* file(s) found nothing' <<<"$out" || fail "a clean scan is not said: $out"
pass "a package with nothing left says the scan found nothing"

echo "redact.test.sh: all checks passed"

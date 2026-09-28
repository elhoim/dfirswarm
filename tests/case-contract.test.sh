#!/usr/bin/env bash
# The case contract at the operator's side (docs/adr/0014): the case policy's
# new fields set at kickoff and recorded in network/policy.json, SWARM.md,
# the registry and the anchor beside the run; its conflicts refused; the
# services a goal names warned about (B16); custody holding the policy to
# its anchor; a resume keeping the policy it was given; evidence and
# material added with swarm.sh, requests listed and acted on; typed notify
# targets kept outside the run and told ids only. Host runs, --no-start: no
# model, no VM, no Herdr.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Short, for the collector's socket path.
TMP="$(mktemp -d /tmp/cct.XXXXXX)"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
export SWARM_RUNS_DIR="$TMP/runs" DFIRSWARM_HOME="$TMP/home" SWARM_SIGNERS_HOME="$TMP/home"
mkdir -p "$DFIRSWARM_HOME"
swarm() { bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
sandbox_of() { jq -r --arg l "$1" '.runs[] | select(.label == $l) | .sandbox' "$TMP/runs/registry.json"; }
id_of() { jq -r --arg l "$1" '.runs[] | select(.label == $l) | .id' "$TMP/runs/registry.json"; }
sha() { { shasum -a 256 "$1" 2>/dev/null || sha256sum "$1"; } | cut -d' ' -f1; }

GOAL="$TMP/goal.md"
cat > "$GOAL" <<'EOF'
---
title: Supplier bank details
more_evidence: ask
material_use: case_material=none
---
## Goal

Establish how the supplier's bank details were changed. Look the sender's domain up in RDAP,
place the address with Nominatim, and do not search Google for the names.

### Questions

1. Which message changed the bank details?
2. What was paid, and when?

## Definition of done

d

## Checks

- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,summary,narrative`
EOF
kick() { swarm start --model solo/model --n 2 --cap-usd 1 --no-start --toolbox off --goal-file "$GOAL" "$@"; }

echo "# refused at kickoff: the contract contradicts itself"
out="$(kick --policy ctf --more-evidence yes --label c-bad1)" && fail "ctf with more evidence yes was accepted: $out"
grep -q "a published case's evidence is what was published" <<<"$out" || fail "the refusal does not say why: $out"
out="$(kick --material-use external_capture=evidence --label c-bad2)" && fail "a capture as evidence was accepted: $out"
grep -q "a capture's hash proves its bytes, not their truth" <<<"$out" || fail "$out"
out="$(kick --more-evidence maybe --label c-bad3)" && fail "an unknown more-evidence was accepted"
grep -q "more_evidence: \"maybe\" is not one of no, ask, yes (the kickoff's --more-evidence)" <<<"$out" || fail "$out"
[[ -z "$(jq -r '.runs[]? | select(.label | startswith("c-bad")) | .id' "$TMP/runs/registry.json" 2>/dev/null)" ]] || fail "a refused kickoff left a run"
pass "a contract that contradicts itself is refused before anything is written"

echo "# recorded four ways, anchored, and the goal's services warned about"
out="$(kick --more-evidence yes --legal "GDPR or similar laws; engagement letter 42" --provider-retention "thirty days" --notify desktop: --notify ntfy:dfs-test-topic --notify mailto:examiner@example.org --label c1)" || fail "the kickoff was refused: $out"
id="$(id_of c1)"; sb="$(sandbox_of c1)"
jq -e '.more_evidence == "yes" and .material_use.case_material == "none" and .material_use.acquired_evidence == "evidence" and .legal == "GDPR or similar laws; engagement letter 42" and .provider_retention == "thirty days" and .sources.more_evidence == "flag" and .sources.material_use == "goal"' "$sb/network/policy.json" >/dev/null || fail "network/policy.json: $(cat "$sb/network/policy.json")"
grep -q '^- More evidence during the run: yes (further evidence is expected' "$sb/SWARM.md" || fail "SWARM.md does not say the more-evidence setting"
grep -q 'case_material none' "$sb/SWARM.md" || fail "SWARM.md does not say the material use"
grep -q '^- Provider retention: thirty days' "$sb/SWARM.md" || fail "SWARM.md does not carry the provider retention"
[[ "$(jq -r --arg id "$id" '.runs[] | select(.id == $id) | .case_policy.more_evidence' "$TMP/runs/registry.json")" == yes ]] || fail "the registry does not carry the policy"
[[ "$(jq -r '.case_policy_sha256' "$sb.custody-anchor.json")" == "$(sha "$sb/network/policy.json")" ]] || fail "the anchor does not hold the policy's sha256"
grep -q 'WARN: the goal names rdap (adapter rdap_domain), and this run.s network is closed' <<<"$out" || fail "B16: no warning for RDAP under a closed network: $out"
grep -q 'WARN: the goal names nominatim' <<<"$out" || fail "B16: no warning for Nominatim: $out"
grep -q 'WARN: the goal names google, a service the case policy.s hard denials refuse (search' <<<"$out" || fail "B16: no warning for a denied service: $out"
pass "the case policy is in policy.json, SWARM.md, the registry and the anchor; the goal's services are warned about"

echo "# typed notify targets: outside the run, 0600, and told ids only"
tg="$TMP/runs/notify/$id.targets"
[[ -f "$tg" && "$(stat -f %Lp "$tg" 2>/dev/null || stat -c %a "$tg")" == 600 ]] || fail "the typed targets were not kept 0600"
grep -qx 'ntfy:dfs-test-topic' "$tg" && grep -qx 'desktop:' "$tg" && grep -qx 'mailto:examiner@example.org' "$tg" || fail "the targets file: $(cat "$tg")"
grep -rq 'dfs-test-topic' "$TMP/runs/registry.json" "$sb" 2>/dev/null && fail "the ntfy topic (its secret) is in the registry or the run"
out="$(kick --notify ntfy:'bad topic!' --label c-bad4)" && fail "a malformed ntfy topic was accepted"
grep -q 'takes a topic' <<<"$out" || fail "$out"
# Stand-ins for the programs a target uses: each writes what it was given.
FAKE="$TMP/fake"; mkdir -p "$FAKE"
for p in osascript notify-send curl mail; do
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> %q\ncat >> %q 2>/dev/null || true\n' "$TMP/$p.got" "$TMP/$p.got" > "$FAKE/$p"
  chmod +x "$FAKE/$p"
done
detail='{"request":"R-7","kind":"acquisition","run":"x","lead":"L-3","questions":["Q-2"],"urgency":"volatile","title":"the IBAN GB33BUKB20201555555555","request_text":"Need the export naming the IBAN"}'
PATH="$FAKE:$PATH" SWARM_NOTIFY_TIMEOUT=5 bash "$ROOT/scripts/notify.sh" "$sb" operator_request "$detail"
for f in curl mail; do
  for _ in $(seq 1 50); do [[ -s "$TMP/$f.got" ]] && break; sleep 0.1; done
  [[ -s "$TMP/$f.got" ]] || fail "the $f target was not told"
  grep -q 'R-7' "$TMP/$f.got" || fail "the $f notification does not name the request: $(cat "$TMP/$f.got")"
  grep -q 'GB33\|IBAN\|export' "$TMP/$f.got" && fail "the $f notification carried case content: $(cat "$TMP/$f.got")"
done
grep -q 'https://ntfy.sh/dfs-test-topic' "$TMP/curl.got" || fail "ntfy was not sent to its topic: $(cat "$TMP/curl.got")"
grep -q 'examiner@example.org' "$TMP/mail.got" || fail "the mail was not addressed: $(cat "$TMP/mail.got")"
{ [[ -s "$TMP/osascript.got" ]] || [[ -s "$TMP/notify-send.got" ]]; } || fail "the desktop target was not told"
pass "desktop, ntfy and mailto targets are told the request by its ids, never its words"

echo "# requests: listed, acknowledged, declined; the notification fired from the fallback"
node --experimental-strip-types --no-warnings --input-type=module -e '
  const L = await import(process.argv[1]);
  const ctx = { sandboxRoot: process.argv[2], agentId: process.argv[3] };
  let r = await L.openLead(ctx, { title: "The payment run", why: "Q2 wants what was paid", answers: ["2"], take: true });
  if (!r.ok) throw new Error(r.reason);
  r = await L.closeLead(ctx, "L-1", { disposition: "needs_operator", ref: "The payment run export is not in the evidence", ask: { kind: "acquisition", source: "the ERP export", where: "finance", expected_value: "what was paid and when", urgency: "urgent" } });
  if (!r.ok || r.request?.id !== "R-1" || r.request?.stage !== "authorised") throw new Error(JSON.stringify(r));
  r = await L.openLead(ctx, { title: "A host", why: "w", take: true });
  r = await L.closeLead(ctx, "L-2", { disposition: "needs_operator", ref: "allow the host example.org so a job can fetch the page" });
  if (!r.ok) throw new Error(r.reason);
' "$ROOT/extensions/leads.ts" "$sb" "$(jq -r '.agents[0].id' "$sb/team.json")" || fail "the agent's asks were not recorded"
out="$(swarm requests "$id" list)" || fail "requests list failed: $out"
grep -q '^WAITING ON THE OPERATOR:' <<<"$out" && grep -q '^R-1 \[acquisition, acknowledged, stage authorised\]' <<<"$out" && grep -q '^R-2 \[lead, pending\]' <<<"$out" || fail "the list: $out"
out="$(swarm requests "$id" ack R-2)" || fail "ack failed: $out"
grep -q 'R-2: ack recorded; it is acknowledged' <<<"$out" || fail "$out"
out="$(swarm requests "$id" decline R-2)" && fail "a decline without why was taken: $out"
out="$(swarm requests "$id" decline R-2 --why "no host is allowed in this case")" || fail "decline failed: $out"
grep -q 'it is declined' <<<"$out" || fail "$out"
jq -e 'select(.rid == "R-2") | .state == "declined" and .closed.text == "no host is allowed in this case"' "$sb/operator-requests.jsonl" >/dev/null || fail "the view does not hold the decline"
grep -q '"command":"requests"' "$TMP/runs/operator-audit.jsonl" || fail "the act is not on the operator's record"
# The watchdog's fallback delivers what the hub (none here) did not: once.
out="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/requests-cli.ts" fire "$sb" --runs "$TMP/runs")" || fail "fire failed: $out"
jq -e '.notified == ["R-1"]' <<<"$out" >/dev/null || fail "the fallback did not notify the open request once: $out"
out="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/requests-cli.ts" fire "$sb" --runs "$TMP/runs")"
jq -e '.notified == []' <<<"$out" >/dev/null || fail "a request was notified twice: $out"
pass "requests are listed with their ids and states, acted on with reasons, on the record, and notified once"

echo "# evidence and material added with swarm.sh"
mkdir -p "$TMP/late"
printf 'run,amount\n2026-06-16,48200.00\n' > "$TMP/late/export.csv"
out="$(swarm evidence "$id" add "$TMP/late/export.csv" --for R-1 --why "finance supplied the payment run export")" || fail "evidence add failed: $out"
grep -q '^Added ev-0001 (acquired_evidence; 1 file(s)' <<<"$out" || fail "$out"
grep -q 'Inventory revision 1\. R-1: received and validated\. Reopened: L-1' <<<"$out" || fail "$out"
grep -q 'The agents can read it now, read-only, at store/imports/ev-0001/out/' <<<"$out" || fail "$out"
[[ "$(cat "$sb/store/imports/ev-0001/out/export.csv")" == "$(cat "$TMP/late/export.csv")" ]] || fail "the import is not the file"
grep -q '"type":"evidence_added"' "$sb/store/journal.jsonl" || fail "no journal line"
grep -q '"command":"evidence_outcome"' "$TMP/runs/operator-audit.jsonl" || fail "the outcome is not on the operator's record"
out="$(swarm evidence "$id" list)" || fail "evidence list failed"
grep -q '^ev-0001 acquired_evidence' <<<"$out" || fail "$out"
printf 'the policy\n' > "$TMP/policy.txt"
out="$(swarm material "$id" add "$TMP/policy.txt" --class case_material --why "the payment policy")" || fail "material add failed: $out"
grep -q '^Added mat-0001 (case_material' <<<"$out" && grep -q 'use: none:' <<<"$out" || fail "$out"
out="$(swarm evidence "$id" add "$sb/SWARM.md" --why "x")" && fail "a path inside the run was added"
grep -q 'is inside the run' <<<"$out" || fail "$out"
pass "evidence add seals, journals, answers the acquisition and reopens; material add records its class and use"

echo "# custody holds the case policy to its anchor"
node --experimental-strip-types --no-warnings "$ROOT/scripts/custody.ts" "$sb" --run "$id" --quiet >/dev/null 2>&1 || true
jq -e '.case_policy.anchored == true and .seal.case_policy.sha256 != null and (.checks[] | select(.name == "case policy") | .status == "passed") and (.checks[] | select(.name == "operator requests") | .status == "passed")' "$sb/custody.json" >/dev/null || fail "custody did not seal the policy: $(jq -c '{case_policy, checks: [.checks[] | select(.name == "case policy" or .name == "operator requests")]}' "$sb/custody.json")"
chmod u+w "$sb/network/policy.json" 2>/dev/null || true
jq '.more_evidence = "no"' "$sb/network/policy.json" > "$TMP/p.json" && cat "$TMP/p.json" > "$sb/network/policy.json"
node --experimental-strip-types --no-warnings "$ROOT/scripts/custody.ts" "$sb" --run "$id" --quiet >/dev/null 2>&1 || true
jq -e '.case_policy.anchored == false and (.summary | test("CASE POLICY REWRITTEN")) and (.checks[] | select(.name == "case policy") | .status == "failed")' "$sb/custody.json" >/dev/null || fail "custody did not catch the rewritten policy: $(jq -c '{case_policy, summary}' "$sb/custody.json")"
pass "custody seals the case policy by its sha256 and names a rewrite"

echo "# a resume keeps the case policy its kickoff recorded"
out="$(kick --more-evidence yes --label c2)" || fail "the second kickoff was refused: $out"
id2="$(id_of c2)"; sb2="$(sandbox_of c2)"
before="$(sha "$sb2/network/policy.json")"
out="$(swarm stop "$id2")" || fail "stop failed: $out"
# The kept options now say otherwise (as a goal edited since would): the
# file is {argv, dropped_env, notify}, the options under argv.
argv="$TMP/runs/resume/$id2.argv.json"
jq '.argv |= map(if . == "yes" then "no" else . end)' "$argv" > "$TMP/argv.json" && cat "$TMP/argv.json" > "$argv"
out="$(swarm resume "$id2" --no-start)" || fail "the resume was refused: $out"
grep -q 'NOTE: the resumed run keeps the case policy its kickoff recorded; these options say otherwise: more_evidence: recorded "yes", these options "no"' <<<"$out" || fail "the resume did not say it keeps the recorded policy: $out"
[[ "$(sha "$sb2/network/policy.json")" == "$before" ]] || fail "the resume rewrote network/policy.json"
[[ "$(jq -r '.case_policy_sha256' "$sb2.custody-anchor.json")" == "$before" ]] || fail "the anchor's policy changed"
[[ "$(grep -c '^## Case policy and network' "$sb2/SWARM.md")" == 1 ]] || fail "the resume appended a second policy section"
[[ "$(jq -r --arg id "$id2" '.runs[] | select(.id == $id) | .case_policy.more_evidence' "$TMP/runs/registry.json")" == yes ]] || fail "the registry took the resume's options over the recorded policy"
pass "a resume keeps the recorded case policy: the file, its anchor, SWARM.md and the registry, and says what the options would have changed"

echo "# a resume's own --no-netguard cannot open a run its recorded policy keeps closed (review 1)"
out="$(kick --label c3)" || fail "the third kickoff was refused: $out"
id3="$(id_of c3)"; sb3="$(sandbox_of c3)"
[[ "$(jq -r --arg id "$id3" '.runs[] | select(.id == $id) | .netguard' "$TMP/runs/registry.json")" == true ]] || fail "a closed run is not guarded"
out="$(swarm stop "$id3")" || fail "stop failed: $out"
argv="$TMP/runs/resume/$id3.argv.json"
jq '.argv += ["--no-netguard"]' "$argv" > "$TMP/argv3.json" && cat "$TMP/argv3.json" > "$argv"
out="$(swarm resume "$id3" --no-start)" || fail "the resume was refused: $out"
grep -q 'NOTE: --no-netguard is among the resumed run.s options, and its recorded case policy says network closed: the run.s egress stays guarded' <<<"$out" || fail "the resume did not say its egress stays guarded: $out"
[[ "$(jq -r --arg id "$id3" '.runs[] | select(.id == $id) | .netguard' "$TMP/runs/registry.json")" == true ]] || fail "the resumed run's egress was opened under a closed policy: $(jq -c --arg id "$id3" '.runs[] | select(.id == $id) | {netguard, netguard_mode, case_policy: .case_policy.network}' "$TMP/runs/registry.json")"
[[ "$(jq -r '.network' "$sb3/network/policy.json")" == closed ]] || fail "the recorded policy moved"
# The generated specs are held to the policy: an open VM or job spec under a closed policy is refused.
printf '{"open_net": true}\n' > "$TMP/spec.json"
out="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/case-policy.ts" check-spec --policy-json "$(cat "$sb3/network/policy.json")" --spec "$TMP/spec.json" 2>&1)" && fail "an open spec under a closed policy passed: $out"
grep -q 'the VM spec says open_net true, and the case policy.s network is closed' <<<"$out" || fail "$out"
out="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/case-policy.ts" check-spec --policy-json "$(cat "$sb3/network/policy.json")" --spec "$TMP/spec.json" --jobs-json '{"openNet": true}' 2>&1)" && fail "open jobs passed"
grep -q 'openNet true' <<<"$out" || fail "$out"
printf '{"open_net": false}\n' > "$TMP/spec.json"
node --experimental-strip-types --no-warnings "$ROOT/scripts/case-policy.ts" check-spec --policy-json "$(cat "$sb3/network/policy.json")" --spec "$TMP/spec.json" --jobs-json '{"openNet": false}' >/dev/null || fail "a closed spec under a closed policy was refused"
grep -q 'check_spec_network "$spec"' "$ROOT/scripts/swarm.sh" && grep -q 'check_spec_network "$sandbox/vm-spec.json"' "$ROOT/scripts/swarm.sh" || fail "the kickoff does not hold its specs to the policy"
pass "a resume derives its egress from the recorded policy, and the generated specs are held to it"

echo "# mailto: one mailbox, never an option (review 15)"
out="$(kick --notify 'mailto:-X/tmp/notify@example.org' --label c-bad5)" && fail "an option-shaped mailto was accepted: $out"
grep -q 'takes one mail address (local@domain, not beginning with -)' <<<"$out" || fail "$out"
out="$(kick --notify 'mailto:a@example.org,b@example.org' --label c-bad6)" && fail "two recipients were accepted: $out"
: > "$TMP/mail.got"
printf 'mailto:-X/tmp/notify@example.org\n' > "$TMP/runs/notify/$id.targets"
PATH="$FAKE:$PATH" SWARM_NOTIFY_TIMEOUT=5 bash "$ROOT/scripts/notify.sh" "$sb" operator_request '{"request":"R-9","kind":"lead"}'
sleep 2
[[ ! -s "$TMP/mail.got" ]] || fail "an option-shaped recipient reached the mail program: $(cat "$TMP/mail.got")"
grep -q 'not one mail address' "$sb/traces/notify.log" || fail "the refused target is not in the log"
printf 'mailto:examiner@example.org\n' > "$TMP/runs/notify/$id.targets"
PATH="$FAKE:$PATH" SWARM_NOTIFY_TIMEOUT=5 bash "$ROOT/scripts/notify.sh" "$sb" operator_request '{"request":"R-9","kind":"lead"}'
for _ in $(seq 1 50); do [[ -s "$TMP/mail.got" ]] && break; sleep 0.1; done
grep -q -- '-- examiner@example.org' "$TMP/mail.got" || fail "the mail program was not given the address after its option terminator: $(cat "$TMP/mail.got")"
pass "a mailto target is one mailbox, refused when it begins with -, and given after --"

echo "# help"
swarm help requests | grep -q 'requests <id> authorise|collecting|unavailable R-n' || fail "help requests"
swarm help evidence | grep -q 'evidence <id> add PATH --why W \[--for R-n\]' || fail "help evidence"
swarm help material | grep -q 'material <id> add PATH --why W' || fail "help material"
swarm help start | grep -q -- '--more-evidence M' || fail "help start does not document --more-evidence"
pass "requests, evidence and material have their help; start documents the new flags"

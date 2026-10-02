#!/usr/bin/env bash
# The kickoff's run-safety items from the Breadcrumbs run (2026-10-01): the
# derived catalogue's ceiling (--derived-limit), the token marks the
# operator is told of (--token-alert), the operator named before the run
# (--operator, and --as operator on its acts), the model ids asked for and
# a floating one warned of, whose credential each seat uses (an Anthropic
# subscription refused in every run; --customer-case and --key-owner), and
# start --check on a goal that requires a question it does not number.
# Writable evidence in a VM run is tests/microvm-flags.test.sh's. No model,
# no Herdr, no VM: every run is --no-start or --check.
set -uo pipefail
unset SWARM_ISOLATION SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME ANTHROPIC_OAUTH_TOKEN SWARM_DERIVED_LIMIT
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/run-safety.XXXXXX")"
# The VM hubs' directory is the suite's own, and short: a socket path must stay under 104 bytes on macOS.
HUBS_TMP="$(mktemp -d /tmp/dfh.XXXXXX)"
export SWARM_HUBS_DIR="$HUBS_TMP/hubs" MSB_HOME="$HUBS_TMP/msb-home"
export SWARM_SIGNERS_HOME="$TMP/signers"
# Pi's store is the suite's own: each case writes the auth.json it needs.
export PI_CODING_AGENT_DIR="$TMP/pi"
mkdir -p "$PI_CODING_AGENT_DIR"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP" "$HUBS_TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
swarm() { SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
GOAL="$ROOT/prompts/goals/hello.md"
host() { swarm start --isolation host --model solo/model --provider-host solo=api.solo.example --n 2 --cap-usd 1 --no-start --goal-file "$GOAL" --toolbox off "$@"; }
# Small VMs and one worker, so the job service fits on a CI runner (7 GiB): a run with none records no jobs.
vm() { swarm start --isolation microvm --model solo/model --provider-host solo=api.solo.example --n 2 --cap-usd 1 --no-start --goal-file "$GOAL" --toolbox off --vm-memory 512 --workers 1 --worker-memory 512 "$@"; }
sandbox_of() { printf '%s\n' "$1" | sed -n 's/^SANDBOX=//p' | tail -1; }
id_of() { printf '%s\n' "$1" | sed -n 's/^Swarm id: *//p' | tail -1; }
reg() { jq -r --arg l "$1" ".runs[] | select(.[\"label\"] == \$l) | $2" "$TMP/runs/registry.json"; }
none_for() { [[ -z "$(jq -r --arg l "$1" '.runs[]? | select(.label == $l) | .id' "$TMP/runs/registry.json" 2>/dev/null)" ]]; }
store() { printf '%s\n' "$1" > "$PI_CODING_AGENT_DIR/auth.json"; }

# --- the derived catalogue's ceiling ------------------------------------------------
out="$(vm --label dl-default)"; rc=$?
[[ $rc -eq 0 ]] || fail "a VM run exited $rc: $out"
[[ "$(reg dl-default '.isolation.jobs')" != null ]] || fail "the run has no job service on this host: $out"
[[ "$(reg dl-default '.isolation.jobs.derived_limit')" == 50 ]] || fail "the default ceiling is not recorded: $(reg dl-default '.isolation.jobs')"
out="$(vm --derived-limit 120 --label dl-given)"; rc=$?
[[ $rc -eq 0 && "$(reg dl-given '.isolation.jobs.derived_limit')" == 120 ]] || fail "--derived-limit 120 is not recorded ($rc): $out"
out="$(SWARM_DERIVED_LIMIT=80 vm --label dl-env)"; rc=$?
[[ $rc -eq 0 && "$(reg dl-env '.isolation.jobs.derived_limit')" == 80 ]] || fail "SWARM_DERIVED_LIMIT is not the default ($rc): $out"
for bad in 0 -3 1.5 lots; do
  out="$(vm --derived-limit "$bad" --label dl-bad)"; rc=$?
  [[ $rc -eq 2 ]] && grep -q 'BLOCKER: --derived-limit (or SWARM_DERIVED_LIMIT) takes a whole number of generations' <<<"$out" || fail "--derived-limit $bad was not refused ($rc): $out"
done
out="$(vm --derived-limit 10 --no-derived-catalog --label dl-off)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'has none (--no-derived-catalog)' <<<"$out" || fail "a ceiling for a catalogue that is off was not refused ($rc): $out"
out="$(host --derived-limit 10 --label dl-host)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'no job service: a host run' <<<"$out" || fail "a ceiling in a host run was not refused ($rc): $out"
none_for dl-bad && none_for dl-off && none_for dl-host || fail "a refused kickoff left a run"
[[ "$(reg dl-default '.isolation.jobs.derived_catalog')" == true ]] || fail "the derived catalogue is not on by default"
pass "the derived catalogue's ceiling is 50 unless --derived-limit or SWARM_DERIVED_LIMIT says otherwise, recorded; refused when it is not a whole number or there is no catalogue to bound"

# --- writable evidence, as this account's permission bits read ----------------------------
# The owner's bits decide for the owner: a file its group may write and its
# owner (this account) may not is not writable by this account. (Evidence
# another account owns, with its owner's write bit, cannot be made in a
# suite; it is the case os.access reads rightly and -perm -u+w did not.)
mkdir -p "$TMP/ev-group/sub"
printf 'x\n' > "$TMP/ev-group/sub/f.bin"
chmod 0464 "$TMP/ev-group/sub/f.bin"
chmod 0555 "$TMP/ev-group/sub" "$TMP/ev-group"
out="$(vm --inputs "$TMP/ev-group" --label ev-group)"; rc=$?
[[ $rc -eq 0 ]] || fail "evidence only a group may write was refused as this account's ($rc): $out"
chmod u+w "$TMP/ev-group/sub"
out="$(vm --inputs "$TMP/ev-group" --label ev-group-dir)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'is writable by this account, by its permission bits (sub and perhaps more' <<<"$out" || fail "a directory this account may write was not refused, named ($rc): $out"
pass "writable evidence is read as this account's permission bits: a group's write bit is not the owner's; a directory the owner may write is refused, named"

# --- token marks ------------------------------------------------------------------------
out="$(host --stop operator --token-alert 200M,1.6G --token-alert 5000,200M --label ta)"; rc=$?
[[ $rc -eq 0 ]] || fail "--token-alert exited $rc: $out"
sbx="$(sandbox_of "$out")"
[[ "$(jq -c '.token_alerts' "$sbx/budget.json")" == '[5000,200000000,1600000000]' ]] || fail "budget.json does not hold the marks, ascending, each once: $(jq -c '.token_alerts' "$sbx/budget.json")"
[[ "$(reg ta '.token_alerts | join(",")')" == "5000,200000000,1600000000" ]] || fail "the registry does not hold the marks"
grep -q '^Token alerts: 5000 · 200000000 · 1600000000 tokens: as the run crosses each you are told' <<<"$out" || fail "the kickoff does not say the marks: $out"
out="$(host --label ta-none)"
sbx="$(sandbox_of "$out")"
jq -e 'has("token_alerts") | not' "$sbx/budget.json" >/dev/null || fail "a run without marks has token_alerts in budget.json"
[[ "$(reg ta-none '.token_alerts')" == null ]] || fail "a run without marks records some"
for bad in "0" "12x" "1.5" "-3" "2M,,3M"; do
  out="$(host --token-alert "$bad" --label ta-bad)"; rc=$?
  [[ $rc -eq 2 ]] && grep -q 'BLOCKER: --token-alert takes token counts' <<<"$out" || fail "--token-alert $bad was not refused ($rc): $out"
done
none_for ta-bad || fail "a refused kickoff left a run"
# Set again while the run goes on: swarm.sh cap <id> --token-alert.
ta_id="$(reg ta '.id')"
ta_sbx="$(reg ta '.sandbox')"
out="$(swarm cap "$ta_id" --token-alert 1.4G,1.6G)"; rc=$?
[[ $rc -eq 0 ]] || fail "cap --token-alert exited $rc: $out"
[[ "$(jq -c '.token_alerts' "$ta_sbx/budget.json")" == '[1400000000,1600000000]' ]] || fail "cap did not set the marks: $(jq -c '.token_alerts' "$ta_sbx/budget.json")"
[[ "$(jq -c '.token_alert_changes[-1].marks' "$ta_sbx/budget.json")" == '[1400000000,1600000000]' ]] || fail "the change is not kept in budget.json"
[[ "$(reg ta '.token_alerts | join(",")')" == "1400000000,1600000000" ]] || fail "the registry does not follow: $(reg ta '.token_alerts')"
grep -q 'the token alerts from 5,000 · 200,000,000 · 1,600,000,000 to 1,400,000,000 · 1,600,000,000' <<<"$out" || fail "cap does not say what changed: $out"
grep -rq 'the token alerts from 5,000' "$ta_sbx/threads/main" || fail "the change is not said on the board"
out="$(swarm cap "$ta_id" --token-alert soon)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'takes token counts' <<<"$out" || fail "cap --token-alert soon was not refused ($rc): $out"
out="$(swarm cap "$ta_id" --token-alert none)" || fail "cap --token-alert none failed: $out"
jq -e 'has("token_alerts") | not' "$ta_sbx/budget.json" >/dev/null || fail "none did not clear the marks"
pass "--token-alert's marks (k, M, G allowed) are written ascending to budget.json and the registry and said at kickoff; a mark that is not a count is refused; cap --token-alert sets them again (none clears), kept and said"

# --- the operator, named before the run ----------------------------------------------------
enrol() { bash "$ROOT/scripts/swarm.sh" examiner enroll --name "$1" --organisation Lab --competence "case work" --role "$2" --id "$3" --generate-key --passphrase-fd 3 3<<<"correct horse battery" 2>&1; }
e="$(enrol "Opal Operator" examiner opa)" || fail "enrol failed: $e"
e="$(enrol "Oscar Observer" observer obs)" || fail "enrol failed: $e"
out="$(host --operator nobody --label op-nobody)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'BLOCKER: --operator nobody: no one is enrolled on this install under nobody' <<<"$out" && grep -q 'swarm.sh examiner enroll --id nobody' <<<"$out" || fail "an operator nobody enrolled was not refused with the way to enrol ($rc): $out"
out="$(host --operator obs --label op-observer)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'is enrolled as observer' <<<"$out" || fail "an observer as the operator was not refused ($rc): $out"
out="$(host --operator opa --check --label op-check)"; rc=$?
[[ $rc -eq 0 ]] || fail "start --check with an enrolled operator exited $rc: $out"
out="$(host --operator nobody --check --label op-check-nobody)"; rc=$?
[[ $rc -eq 2 ]] || fail "start --check let an operator nobody enrolled through ($rc): $out"
none_for op-nobody && none_for op-observer || fail "a refused kickoff left a run"
out="$(host --operator opa --label op)"; rc=$?
[[ $rc -eq 0 ]] || fail "an enrolled operator was refused ($rc): $out"
[[ "$(reg op '.operator | "\(.id) \(.name) \(.role)"')" == "opa Opal Operator examiner" ]] || fail "the operator is not recorded: $(reg op '.operator')"
[[ "$(reg op '.operator.fingerprint')" == SHA256:* ]] || fail "the operator's key fingerprint is not recorded"
grep -q '^Operator id:  opa (Opal Operator, examiner): --as operator' <<<"$out" || fail "the kickoff does not name the operator: $out"
run_id="$(id_of "$out")"
q="$(swarm question "$run_id" add --text "Was the archive mailed?" --why "the client asks" --as operator)" || fail "a question --as operator was refused on a run that names its operator: $q"
line="$(printf '%s\n' "$q" | tail -1)"
sbx="$(sandbox_of "$out")"
origin="$(jq -c --arg q "$(jq -r '.q' <<<"$line")" 'select(.q == $q and .ev == "open") | .origin' "$sbx/questions/questions.jsonl" | head -1)"
[[ "$(jq -r '"\(.person) \(.enrolled)"' <<<"$origin")" == "opa true" ]] || fail "--as operator was not the run's operator: $origin"
# The Breadcrumbs resume, on a run that names its operator: the question --as operator is admitted, as theirs.
op_run="$run_id"
swarm stop "$op_run" --no-custody >/dev/null || fail "the operator's run would not stop"
out="$(swarm resume "$op_run" --no-start --question "Was the flag's closing brace ever written?" --as operator)" || fail "a resume --as operator on a run that names its operator was refused: $out"
origin="$(jq -c 'select(.ev == "open" and (.act.text // "") == "Was the flag'"'"'s closing brace ever written?") | .origin' "$sbx/questions/questions.jsonl" | head -1)"
[[ "$(jq -r '"\(.person) \(.enrolled)"' <<<"$origin")" == "opa true" ]] || fail "the resumed question is not the run's operator's: $origin"
# A run that names no operator reads --as operator as before: nobody enrolled under it, refused.
out="$(host --label op-none)"
q="$(swarm question "$(id_of "$out")" add --text "Was the archive split?" --why "x" --as operator)" && fail "--as operator on a run that names none was taken: $q"
grep -q 'no one is enrolled on this install under operator' <<<"$q" || fail "the refusal does not say who is unknown: $q"
pass "--operator names an enrolled examiner or analyst, refused otherwise (at --check too), recorded with the run; --as operator is theirs, and on a run that names none it is refused as before"

# --- the model ids asked for ----------------------------------------------------------------
out="$(swarm start --isolation host --models "solo/model-latest=1,solo/model-2026-01-01=1" --provider-host solo=api.solo.example --cap-usd 1 --no-start --goal-file "$GOAL" --toolbox off --label mi)"; rc=$?
[[ $rc -eq 0 ]] || fail "a team with a floating id exited $rc: $out"
grep -q 'WARN: solo/model-latest names no dated model (latest)' <<<"$out" || fail "a -latest id is not warned of: $out"
grep -q 'WARN: solo/model-2026-01-01 names no dated model' <<<"$out" && fail "a dated id was warned of: $out"
[[ "$(reg mi '.model_identity.requested | join(",")')" == "solo/model-latest,solo/model-2026-01-01" ]] || fail "the ids asked for are not recorded: $(reg mi '.model_identity')"
[[ "$(reg mi '.model_identity.floating | join(",")')" == "solo/model-latest" ]] || fail "the floating id is not recorded: $(reg mi '.model_identity')"
[[ "$(reg mi '.model_identity.recorded_at')" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]] || fail "the date is not recorded"
pass "the record keeps the model ids asked for and the date; an id with latest in it is warned of and listed as floating"

# --- whose credential: an Anthropic subscription, a customer's case -------------------------------
store '{"anthropic": {"type": "oauth", "access": "not-real", "refresh": "not-real", "expires": 1}}'
for iso in host microvm; do
  out="$(swarm start --isolation "$iso" --model anthropic/claude-x --n 1 --cap-usd 1 --no-start --goal-file "$GOAL" --toolbox off --label an-oauth-$iso $([[ $iso == microvm ]] && echo --allow-oauth-in-vm))"; rc=$?
  [[ $rc -eq 2 ]] || fail "an anthropic seat on a subscription login exited $rc ($iso), wanted 2: $out"
  grep -q 'BLOCKER: anthropic/claude-x would reach Anthropic on a Claude subscription login' <<<"$out" && grep -q 'does not permit Free, Pro or Max subscription credentials in a third-party client such as Pi' <<<"$out" && grep -q '/login anthropic' <<<"$out" || fail "the refusal does not say why and how ($iso): $out"
  none_for "an-oauth-$iso" || fail "the refused kickoff left a run"
done
store '{"anthropic": {"type": "api_key", "key": "not-real"}}'
out="$(swarm start --isolation host --model anthropic/claude-x --n 1 --cap-usd 1 --no-start --goal-file "$GOAL" --toolbox off --label an-key)"; rc=$?
[[ $rc -eq 0 ]] || fail "an anthropic seat on an API key was refused ($rc): $out"
[[ "$(reg an-key '.credentials[0] | "\(.provider) \(.credential)"')" == "anthropic api_key" ]] || fail "the seat's credential is not recorded: $(reg an-key '.credentials')"
store '{}'
out="$(ANTHROPIC_OAUTH_TOKEN=not-real swarm start --isolation host --model anthropic/claude-x --n 1 --cap-usd 1 --no-start --goal-file "$GOAL" --toolbox off --label an-env)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'ANTHROPIC_OAUTH_TOKEN' <<<"$out" || fail "a subscription token in the environment was not refused ($rc): $out"
# Pi takes ANTHROPIC_AUTH_TOKEN (a bearer) before the API key: refused, from the shell or --env.
out="$(ANTHROPIC_AUTH_TOKEN=not-real ANTHROPIC_API_KEY=not-real swarm start --isolation host --model anthropic/claude-x --n 1 --cap-usd 1 --no-start --goal-file "$GOAL" --toolbox off --label an-bearer)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'with ANTHROPIC_AUTH_TOKEN, a token rather than an API key (a bearer token' <<<"$out" && grep -q 'unset ANTHROPIC_AUTH_TOKEN' <<<"$out" || fail "a bearer token in the environment was not refused ($rc): $out"
out="$(swarm start --isolation host --model anthropic/claude-x --n 1 --cap-usd 1 --no-start --goal-file "$GOAL" --toolbox off --env ANTHROPIC_AUTH_TOKEN=not-real --label an-bearer-env)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'with ANTHROPIC_AUTH_TOKEN' <<<"$out" || fail "a bearer token given with --env was not refused ($rc): $out"
none_for an-env && none_for an-bearer && none_for an-bearer-env || fail "a refused kickoff left a run"
# The API key from the environment: let through, and recorded by the variable's name (never its value).
out="$(ANTHROPIC_API_KEY=not-real-key-value swarm start --isolation host --model anthropic/claude-x --n 1 --cap-usd 1 --no-start --goal-file "$GOAL" --toolbox off --label an-apikey-env)"; rc=$?
[[ $rc -eq 0 ]] || fail "an API key in the environment was refused ($rc): $out"
[[ "$(reg an-apikey-env '.credentials[0] | "\(.credential) \(.variable)"')" == "env ANTHROPIC_API_KEY" ]] || fail "the seat's key is not recorded by its variable: $(reg an-apikey-env '.credentials')"
grep -q 'not-real-key-value' "$TMP/runs/registry.json" && fail "a key's value reached the registry"
pass "an anthropic seat on a Claude subscription login (Pi's store, ANTHROPIC_OAUTH_TOKEN, or ANTHROPIC_AUTH_TOKEN's bearer) is refused in every run, --allow-oauth-in-vm or not, saying why and how; an API key goes through, recorded by where it came from"

store '{"openai-codex": {"type": "oauth", "access": "not-real", "refresh": "not-real", "expires": 1}}'
out="$(swarm start --isolation host --model openai-codex/gpt-x --n 2 --cap-tokens 1000000 --no-start --goal-file "$GOAL" --toolbox off --label codex-ctf)"; rc=$?
[[ $rc -eq 0 ]] || fail "a Codex subscription in a test run was refused ($rc): $out"
[[ "$(reg codex-ctf '[.credentials[] | .plan] | unique | join(",")')" == "consumer plan; not for customer data" ]] || fail "the subscription seats are not recorded as a consumer plan: $(reg codex-ctf '.credentials')"
[[ "$(reg codex-ctf '.customer_case')" == false ]] || fail "a test run is recorded as a customer's case"
# Another provider's subscription is a subscription login, not called a consumer plan.
store '{"solo": {"type": "oauth", "access": "not-real", "refresh": "not-real", "expires": 1}}'
out="$(host --cap-tokens 1000000 --label sub-other)"; rc=$?
[[ $rc -eq 0 ]] || fail "a solo subscription run exited $rc: $out"
[[ "$(reg sub-other '[.credentials[] | .plan] | unique | join(",")')" == "subscription login; not for customer data" ]] || fail "another provider's subscription is not labelled a subscription login: $(reg sub-other '.credentials')"
store '{"openai-codex": {"type": "oauth", "access": "not-real", "refresh": "not-real", "expires": 1}}'
out="$(swarm start --isolation host --model openai-codex/gpt-x --n 2 --cap-tokens 1000000 --no-start --goal-file "$GOAL" --toolbox off --customer-case --key-owner ACME --label cc-codex)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'BLOCKER: --customer-case: openai-codex/gpt-x runs on a subscription (openai-codex is a ChatGPT login by design)' <<<"$out" || fail "a Codex seat in a customer's case was not refused ($rc): $out"
store '{"openai": {"type": "api_key", "key": "not-real"}}'
out="$(swarm start --isolation host --model openai/gpt-x --n 2 --cap-usd 1 --no-start --goal-file "$GOAL" --toolbox off --customer-case --label cc-noowner)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'name whose API key openai uses: --key-owner openai=OWNER' <<<"$out" || fail "a customer's case with no key owner was not refused ($rc): $out"
out="$(swarm start --isolation host --model openai/gpt-x --n 2 --cap-usd 1 --no-start --goal-file "$GOAL" --toolbox off --customer-case --key-owner ACME --policy ctf --label cc-ctf)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'BLOCKER: --customer-case with --policy ctf' <<<"$out" || fail "a customer's case under the ctf policy was not refused ($rc): $out"
none_for cc-codex && none_for cc-noowner && none_for cc-ctf || fail "a refused kickoff left a run"
out="$(swarm start --isolation host --model openai/gpt-x --n 2 --cap-usd 1 --no-start --goal-file "$GOAL" --toolbox off --customer-case --key-owner "Default Owner" --key-owner "openai=ACME Ltd" --label cc)"; rc=$?
[[ $rc -eq 0 ]] || fail "a customer's case on API keys with their owner was refused ($rc): $out"
[[ "$(reg cc '.customer_case')" == true ]] || fail "the customer's case is not recorded"
[[ "$(reg cc '[.credentials[] | "\(.seat|test("^s"))|\(.provider)|\(.credential)|\(.owner)"] | unique | join(";")')" == "true|openai|api_key|ACME Ltd" ]] || fail "each seat's key and its owner are not recorded: $(reg cc '.credentials')"
grep -q '^Customer case: API keys only, no subscription; .*openai ACME Ltd' <<<"$out" || fail "the kickoff does not say whose key: $out"
sbx="$(sandbox_of "$out")"
anchor="$(dirname "$sbx")/$(basename "$sbx").custody-anchor.json"
[[ "$(jq -r '.credentials | "\(.customer_case) \(.seats | length) \(.seats[0].owner)"' "$anchor")" == "true 2 ACME Ltd" ]] || fail "the custody anchor does not hold whose key each seat used: $(jq -c '.credentials' "$anchor")"
out="$(swarm start --isolation host --model openai/gpt-x --n 1 --cap-usd 1 --no-start --goal-file "$GOAL" --toolbox off --key-owner "openai=" --label ko-bad)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'BLOCKER: --key-owner takes OWNER' <<<"$out" || fail "an empty owner was not refused ($rc): $out"
pass "a Codex subscription stays usable for a test run, recorded as a consumer plan; --customer-case refuses it, a key with no owner and the ctf policy, and records whose key each seat used, in the registry and the custody anchor"

# --- start --check on a goal that requires a question it does not number -------------------------
printf '%s\n' "## Goal" "" "Answer two questions." "" "1. Who?" "2. What?" "" "## Must establish" "" "- 1" "- 7" "" "## Definition of done" "" "d" "" "## Checks" "" '- `node "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2`' > "$TMP/goal-must.md"
out="$(swarm start --isolation host --model solo/model --provider-host solo=api.solo.example --n 1 --cap-usd 1 --no-start --goal-file "$TMP/goal-must.md" --toolbox off --check)"; rc=$?
[[ $rc -eq 0 ]] || fail "the check exited $rc: $out"
grep -q 'WARN: the goal says these must be established and numbers no such question, so nothing is required of them: 7\.' <<<"$out" || fail "start --check does not warn of question 7: $out"
grep -q 'nothing is required of them: 1' <<<"$out" && fail "question 1 was called unknown: $out"
[[ ! -e "$TMP/runs/registry.json" ]] || [[ -z "$(jq -r '.runs[] | select(.goal // "" | contains("Answer two questions")) | .id' "$TMP/runs/registry.json")" ]] || fail "the check wrote a run"
pass "start --check warns of a question the goal requires and does not number, as the start's seed does"

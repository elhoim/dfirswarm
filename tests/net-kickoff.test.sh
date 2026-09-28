#!/usr/bin/env bash
# The case policy and the network mode at kickoff, and the operator's
# network commands (docs/adr/0011): a policy that contradicts itself is
# refused before anything is written; a run's policy is recorded in
# network/policy.json, SWARM.md and the registry; the goal's metadata block
# sets it and a flag overrides it; `swarm.sh net` lists and acts, always with
# a reason, and refuses what the policy does not permit; `--allow-host` says
# what it is.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/net-kickoff.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
swarm() { SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
sandbox_of() { printf '%s\n' "$1" | sed -n 's/^SANDBOX=//p' | tail -1; }
start() { swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" "$@"; }

# Refused before anything is written, each with its reason.
out="$(start --network dynamic --label hostdyn)" && fail "a host run with network dynamic was accepted: $out"
grep -q "network: dynamic needs the hub" <<<"$out" || fail "the refusal did not say why: $out"
out="$(start --isolation host --policy ctf --allow-host maps.example.org --label ctfhost)" && fail "--allow-host under ctf was accepted"
grep -q "socket allowance" <<<"$out" || fail "the ctf refusal did not name the socket allowance: $out"
out="$(start --policy nonsense --label bad)" && fail "an unknown preset was accepted"
grep -q "not one of standard, live_adversary, internal, ctf" <<<"$out" || fail "$out"
out="$(start --policy internal --lookups reference --label intl)" && fail "internal with lookups was accepted"
grep -q "nothing leaves the run" <<<"$out" || fail "$out"
out="$(start --network dynamic --no-netguard --label both)" && fail "network dynamic with --no-netguard was accepted"
grep -q -- "--no-netguard opens every public host" <<<"$out" || fail "$out"
[[ -z "$(jq -r '.runs[]? | select(.label == "hostdyn" or .label == "ctfhost" or .label == "bad" or .label == "intl" or .label == "both") | .id' "$TMP/runs/registry.json" 2>/dev/null)" ]] || fail "a refused kickoff left a run in the registry"
# The whole direct egress, not only --allow-host: the package index --allow-install adds.
out="$(start --policy ctf --allow-install --label ctfinstall)" && fail "--allow-install under ctf opened the package index: $out"
grep -q "allow-install would open pypi.org" <<<"$out" || fail "the refusal did not name the package index: $out"
out="$(start --policy internal --allow-install --label intinstall)" && fail "--allow-install under internal was accepted"
out="$(start --policy ctf --allow-install --no-pypi --label ctfnopypi)" || fail "--allow-install --no-pypi under ctf was refused: $out"
out="$(start --policy standard --allow-install --label stdinstall)" || fail "--allow-install under standard was refused: $out"
echo "ok - contradictory case policies are refused at kickoff, each with its reason, the package index --allow-install adds included"

# A run that says nothing: standard, network closed, recorded three ways.
out="$(start --label plain)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" && -f "$sb/network/policy.json" ]] || fail "no network/policy.json: $out"
[[ "$(jq -r '.policy + "/" + .network' "$sb/network/policy.json")" == "standard/closed" ]] || fail "the default is not standard/closed: $(cat "$sb/network/policy.json")"
grep -q '^## Case policy and network' "$sb/SWARM.md" || fail "SWARM.md does not state the case policy"
grep -q 'Case policy: standard (the default); network closed' "$sb/SWARM.md" || fail "SWARM.md's policy line: $(grep -A3 'Case policy and network' "$sb/SWARM.md")"
grep -q 'net_request' "$sb/SWARM.md" && fail "a closed run's contract talks of net_request"
[[ "$(jq -r '.runs[] | select(.label == "plain") | .case_policy.policy' "$TMP/runs/registry.json")" == standard ]] || fail "the registry does not carry the case policy"
echo "ok - a run that says nothing is standard with the network closed: policy.json, SWARM.md and the registry say so"

# The goal's metadata block sets it; the kickoff's flag overrides a field.
printf -- '---\ntitle: internal case\npolicy: internal\nlegal: GDPR or similar laws\n---\n' > "$TMP/goal.md"
cat "$ROOT/prompts/goals/hello.md" >> "$TMP/goal.md"
out="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/goal.md" --label fromgoal)"
sb2="$(sandbox_of "$out")"
[[ "$(jq -r '.policy + "/" + .lookups + "/" + .legal' "$sb2/network/policy.json")" == "internal/none/GDPR or similar laws" ]] || fail "the goal's block did not set the policy: $(cat "$sb2/network/policy.json")"
grep -q '^policy: internal' "$sb2/SWARM.md" && fail "the metadata block leaked into the contract"
grep -q 'Legal: GDPR or similar laws' "$sb2/SWARM.md" || fail "the legal text is not in the contract"
out="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/goal.md" --policy standard --label flagwins)"
sb3="$(sandbox_of "$out")"
[[ "$(jq -r '.policy' "$sb3/network/policy.json")" == standard ]] || fail "the flag did not override the goal"
grep -q 'NOTE: policy: the kickoff' <<<"$out" || fail "the override was not said: $out"
echo "ok - the goal's metadata block sets the case policy, and a kickoff flag overrides it and says so"

# The operator's commands: list, and acts with a reason, refused where the policy permits none.
id2="$(jq -r '.runs[] | select(.label == "fromgoal") | .id' "$TMP/runs/registry.json")"
out="$(swarm net "$id2" list)"
grep -q 'Case policy: internal' <<<"$out" || fail "net list does not show the policy: $out"
grep -q 'No request yet' <<<"$out" || fail "$out"
out="$(swarm net "$id2" grant --socket api.example.org --why "the job's client")" && fail "a socket grant under internal was made: $out"
grep -q 'permits no socket grant' <<<"$out" || fail "$out"
id3="$(jq -r '.runs[] | select(.label == "flagwins") | .id' "$TMP/runs/registry.json")"
out="$(swarm net "$id3" grant --socket api.example.org)" && fail "an act without a reason was accepted"
grep -q 'reason' <<<"$out" || fail "$out"
out="$(swarm net "$id3" revoke N-9 --why "no such grant")" && fail "revoking a grant that is not there succeeded"
grep -q 'not a grant of this run' <<<"$out" || fail "$out"
out="$(swarm net "$id3" frobnicate)" && fail "an unknown net command was accepted"
swarm help net | grep -q 'net <id> grant NR-<n> --why TEXT' || fail "swarm.sh help net does not document grant"
swarm --help | grep -q -- '--network dynamic' || fail "the short help does not name --network"
swarm --help | grep -q 'net <id> list|grant|deny|revoke' || fail "the short help does not name net"
swarm help start | grep -q -- '--policy PRESET' || fail "help start does not document --policy"
echo "ok - swarm.sh net lists the network and acts only with a reason, and refuses what the case policy does not permit"

# --allow-host says what it is.
out="$(start --allow-host api.example.org --label allowhost)"
grep -q 'static socket allowance for the whole run (tier 2): host and port only' <<<"$out" || fail "--allow-host did not say what it is: $out"
[[ "$(jq -r '.runs[] | select(.label == "allowhost") | .case_policy.sockets' "$TMP/runs/registry.json")" == operator ]] || fail "standard's socket rule is not recorded"
echo "ok - --allow-host says it is a static socket allowance, and standard's socket rule is recorded"

# A microVM run with the dynamic network, prepared: the contract tells the
# agents how to ask, and the record says the mode and the preset.
HUBS_TMP="$(mktemp -d /tmp/dfh.XXXXXX)"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP" "$HUBS_TMP"' EXIT
out="$(SWARM_HUBS_DIR="$HUBS_TMP/hubs" MSB_HOME="$HUBS_TMP/msb-home" SWARM_ISOLATION=microvm swarm start --model solo/model --provider-host solo=api.solo.example --n 2 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off --isolation microvm --network dynamic --policy ctf --label vmdyn)" || fail "a prepared microVM run with the dynamic network was refused: $out"
sb4="$(sandbox_of "$out")"
[[ "$(jq -r '.policy + "/" + .network + "/" + .evidence_link' "$sb4/network/policy.json")" == "ctf/dynamic/required" ]] || fail "the ctf policy is not recorded: $(cat "$sb4/network/policy.json")"
grep -q 'net_request' "$sb4/SWARM.md" || fail "the contract of a dynamic run does not say how to ask"
grep -q 'There is no search adapter' "$sb4/SWARM.md" || fail "the contract does not say there is no search"
[[ "$(jq -r '.runs[] | select(.label == "vmdyn") | .case_policy.network' "$TMP/runs/registry.json")" == dynamic ]] || fail "the registry does not say dynamic"
echo "ok - a prepared microVM run with network dynamic and policy ctf: the contract says how to ask, the record says the mode"

# The package carries the network records, each capture, and what was kept
# beside the run and delivered to no seat (a filtered adapter's whole response).
out="$(start --label packnet)" || fail "kickoff failed: $out"
sb5="$(sandbox_of "$out")"
id5="$(jq -r '.runs[] | select(.label == "packnet") | .id' "$TMP/runs/registry.json")"
mkdir -p "$sb5/store/net/1/1" "$sb5.netraw/1/1"
printf '{"ev":"grant"}\n' > "$sb5/network/grants.jsonl"
printf '{"ev":"attempt"}\n{"ev":"result"}\n' > "$sb5/network/fetches.jsonl"
printf '{"title":"A title"}\n' > "$sb5/store/net/1/1/body"
printf '{"ref":"net:1/1"}\n' > "$sb5/store/net/1/1/capture.json"
printf '{"title":"A title","author_name":"someone"}\n' > "$sb5.netraw/1/1/body"
out="$(swarm package "$id5")" || fail "package failed: $out"
for f in network/policy.json network/grants.jsonl network/fetches.jsonl network/captures/1/1/body network/captures/1/1/capture.json network/raw/1/1/body; do
  [[ -f "$sb5/package/$f" ]] || fail "the package lacks $f"
done
grep -q author_name "$sb5/package/network/raw/1/1/body" || fail "the kept whole response is not what was kept"
grep -q 'network/raw/1/1/body' "$sb5/package/MANIFEST.txt" || fail "the manifest does not hash the kept response"
echo "ok - the package carries the network records, the captures and the responses kept beside the run"

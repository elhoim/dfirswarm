#!/usr/bin/env bash
# The kickoff's --isolation microvm, without a VM: every run here is
# `--no-start`, and we read what the kickoff wrote into the sandbox, the
# registry and the contract. What starting VMs does is
# tests/vm-integration.test.ts, which needs a hypervisor.
#
# What must not go wrong: a VM run must be refused before anything is written
# when a flag cannot mean anything in a VM; the evidence must be used in place
# (no copy, no pristine clone) and recorded as held by the VM; every agent's
# writable holes must exist before a VM mounts over them; the record must say
# microvm wherever the host run says which guard it had; the image must follow
# the packs; and the contract must tell the agents what a VM changes for them.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/microvm-flags.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
swarm() { SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
# "solo" is a provider nobody ships: its host is given, as an operator with a
# gateway would give it.
start() { swarm start --model solo/model --provider-host solo=api.solo.example --n 2 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off "$@"; }
bare_start() { swarm start --n 2 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off "$@"; }
sandbox_of() { printf '%s\n' "$1" | sed -n 's/^SANDBOX=//p' | tail -1; }
reg() { jq -r --arg l "$1" ".runs[] | select(.[\"label\"] == \$l) | $2" "$TMP/runs/registry.json"; }
case "$(uname -m)" in arm64|aarch64) ARCH=arm64 ;; *) ARCH=amd64 ;; esac

mkdir -p "$TMP/ev/mail"
printf 'notes\n' > "$TMP/ev/notes.txt"
printf 'attachment' > "$TMP/ev/mail/a.bin"

# --- refusals, before anything is written ---------------------------------------
out="$(start --isolation vmware --label bad-iso)"; rc=$?
[[ $rc -eq 2 ]] || fail "an unknown isolation exited $rc, wanted 2: $out"
printf '%s\n' "$out" | grep -q 'BLOCKER: --isolation must be host or microvm' || fail "no BLOCKER for --isolation vmware: $out"
out="$(start --isolation microvm --probe-violation --label bad-probe)"; rc=$?
[[ $rc -eq 2 ]] || fail "--probe-violation in a VM run exited $rc, wanted 2"
printf '%s\n' "$out" | grep -q 'probe-violation' || fail "the refusal does not name --probe-violation: $out"
out="$(start --isolation microvm --vm-cpus 0 --label bad-cpus)"; rc=$?
[[ $rc -eq 2 ]] || fail "--vm-cpus 0 exited $rc, wanted 2"
out="$(start --isolation microvm --vm-memory 100 --label bad-mem)"; rc=$?
[[ $rc -eq 2 ]] || fail "--vm-memory 100 exited $rc, wanted 2"
out="$(start --isolation microvm --vm-memory 10000000 --label bad-capacity)"; rc=$?
[[ $rc -eq 2 ]] && printf '%s\n' "$out" | grep -q 'lower --vm-memory or --n' || fail "VMs larger than this host were not refused: $out"
for flag in --no-write-guard --no-seal-herdr --key-from-env "--inputs-enforce on"; do
  # shellcheck disable=SC2086
  out="$(start --isolation microvm $flag --label bad-hostflag)"; rc=$?
  [[ $rc -eq 2 ]] && printf '%s\n' "$out" | grep -q 'none of them means anything' || fail "$flag was accepted under microvm: $out"
done
out="$(start --isolation microvm --vm-disk 100 --label bad-disk)"; rc=$?
[[ $rc -eq 2 ]] && printf '%s\n' "$out" | grep -q 'vm-disk is MiB' || fail "--vm-disk 100 was not refused: $out"
[[ ! -f "$TMP/runs/registry.json" ]] || [[ -z "$(jq -r '.runs[] | select(.label | startswith("bad-")) | .id' "$TMP/runs/registry.json")" ]] \
  || fail "a refused kickoff left a run in the registry"
pass "an isolation that does not exist, a probe with no guard to probe, a host guard's flag, and a VM with no CPU, too little memory or more than the host has are refused before anything is written"

# --no-read: what every VM mounts cannot be hidden, and is not claimed hidden.
out="$(start --isolation microvm --no-read "$ROOT/scripts" --label bad-noread)"; rc=$?
[[ $rc -eq 2 ]] && printf '%s\n' "$out" | grep -q 'cannot hide what the VMs are given' || fail "--no-read of a mounted path was accepted under microvm: $out"
mkdir -p "$TMP/private-notes"
out="$(start --isolation microvm --no-read "$TMP/private-notes" --label vm-noread)"; rc=$?
[[ $rc -eq 0 ]] || fail "--no-read of a path no VM mounts was refused: $out"
[[ "$(reg vm-noread '.no_read_applied')" == true ]] || fail "--no-read of an unmounted path was not recorded as applied"
pass "--no-read of a path the VMs mount is refused; of one they do not, recorded as applied"

# No collector: a VM cannot fall back to appending traces/ itself, so the run
# would be all spill. A node that refuses to run the collector stands in for
# one that crashed.
mkdir -p "$TMP/nocollector"
REAL_NODE="$(command -v node)"
cat > "$TMP/nocollector/node" <<EOF
#!/usr/bin/env bash
case "\$*" in *trace-collector.mjs*) exit 1 ;; esac
exec "$REAL_NODE" "\$@"
EOF
chmod +x "$TMP/nocollector/node"
out="$(PATH="$TMP/nocollector:$PATH" start --isolation microvm --label bad-collector)"; rc=$?
[[ $rc -eq 1 ]] || fail "a microvm kickoff with no collector exited $rc, wanted 1: $out"
printf '%s\n' "$out" | grep -q 'BLOCKER: the trace collector did not come up' || fail "no BLOCKER naming the collector: $out"
[[ -z "$(jq -r '.runs[]? | select(.label == "bad-collector") | .id' "$TMP/runs/registry.json" 2>/dev/null)" ]] || fail "the refused kickoff left a run"
out="$(PATH="$TMP/nocollector:$PATH" start --label host-no-collector)"; rc=$?
[[ $rc -eq 0 ]] || fail "a host kickoff with no collector should still start, with a warning: $out"
printf '%s\n' "$out" | grep -q 'appended by the panes themselves' || fail "the host fallback is not said: $out"
pass "a microvm run whose trace collector does not come up is refused; a host run falls back and says so"

# --- the network a VM is given -------------------------------------------------
out="$(bare_start --model mystery/m1 --isolation microvm --label bad-provider)"; rc=$?
[[ $rc -eq 2 ]] || fail "a provider with no known host exited $rc under microvm, wanted 2: $out"
printf '%s\n' "$out" | grep -q -- '--provider-host mystery=<host>' || fail "the refusal does not say how to name the host: $out"
out="$(bare_start --model mystery/m1 --isolation microvm --no-netguard --label bad-provider-open)"; rc=$?
[[ $rc -eq 2 ]] || fail "an open network does not make an unknown provider's key reachable, but it exited $rc: $out"
out="$(bare_start --model amazon-bedrock/anthropic.claude-x --isolation microvm --label bad-bedrock)"; rc=$?
[[ $rc -eq 2 ]] && printf '%s\n' "$out" | grep -q 'signs every request' || fail "bedrock under microvm was not refused with the reason: $out"
out="$(bare_start --model solo/model --provider-host 'solo' --label bad-ph)"; rc=$?
[[ $rc -eq 2 ]] && printf '%s\n' "$out" | grep -q 'provider=host' || fail "a --provider-host without =host was not refused: $out"
out="$(start --isolation microvm --allow-host 'https://mirror.example.org/x' --label bad-allow)"; rc=$?
[[ $rc -eq 2 ]] && printf '%s\n' "$out" | grep -q 'not a URL' || fail "an --allow-host a VM would read as nothing was not refused: $out"
out="$(start --isolation microvm --allow-host '*.com' --label bad-tld)"; rc=$?
[[ $rc -eq 2 ]] && printf '%s\n' "$out" | grep -q 'top-level domain' || fail "*.com was not refused: $out"
[[ -z "$(jq -r '.runs[]? | select(.label | startswith("bad-")) | .id' "$TMP/runs/registry.json" 2>/dev/null)" ]] || fail "a refused network left a run"
# Pi's own model list names the hosts of the providers it ships.
out="$(bare_start --model groq/llama-3.3-70b-versatile --isolation microvm --allow-host '*.blob.core.windows.net' --allow-host '[::1]:11434' --label vm-groq)"; rc=$?
[[ $rc -eq 0 ]] || fail "a Pi provider with a known host was refused: $out"
sbx="$(sandbox_of "$out")"
jq -e '.providers[] | select(.provider == "groq") | .hosts | index("api.groq.com")' "$sbx/vm-spec.json" >/dev/null \
  || fail "the groq host did not come from Pi's model list: $(jq -c .providers "$sbx/vm-spec.json")"
out="$(start --isolation microvm --no-netguard --label vm-open)"; rc=$?
[[ $rc -eq 0 ]] || fail "an open microvm run was refused: $out"
[[ "$(reg vm-open '.netguard_mode')" == "microvm-open" ]] || fail "an open VM network was recorded as $(reg vm-open '.netguard_mode')"
[[ "$(reg vm-ev '.netguard_mode' 2>/dev/null)" != "microvm-open" ]] || fail "a closed VM network was recorded as open"
pass "a provider with no host, a signing provider, a bad --provider-host or --allow-host are refused under microvm; Pi's list names a shipped provider's host; an open VM network is recorded as open"

# A link in the evidence that leads out of it would dangle in every VM.
mkdir -p "$TMP/ev-link" "$TMP/elsewhere"
printf 'image' > "$TMP/elsewhere/case.E01"
printf 'notes\n' > "$TMP/ev-link/notes.txt"
ln -s "$TMP/elsewhere/case.E01" "$TMP/ev-link/case.E01"
ln -s notes.txt "$TMP/ev-link/inside-link.txt"
out="$(start --isolation microvm --inputs "$TMP/ev-link" --label bad-link)"; rc=$?
[[ $rc -eq 2 ]] || fail "evidence with a link out of it exited $rc under microvm, wanted 2: $out"
printf '%s\n' "$out" | grep -q 'case.E01 -> ' || fail "the refusal does not name the link: $out"
printf '%s\n' "$out" | grep -q 'inside-link' && fail "a link that stays inside the evidence was refused: $out"
[[ -z "$(jq -r '.runs[]? | select(.label == "bad-link") | .id' "$TMP/runs/registry.json" 2>/dev/null)" ]] || fail "the refused kickoff left a run"
rm "$TMP/ev-link/case.E01"
out="$(start --isolation microvm --inputs "$TMP/ev-link" --label vm-inside-link)"; rc=$?
[[ $rc -eq 0 ]] || fail "evidence whose only link stays inside it was refused: $out"
pass "evidence with a link leading out of it is refused under microvm, naming the link; a link that stays inside is fine"

# --- the evidence is used in place and held by the VM ----------------------------
out="$(start --isolation microvm --inputs "$TMP/ev" --label vm-ev)"; rc=$?
[[ $rc -eq 0 ]] || fail "a microvm --no-start kickoff exited $rc: $out"
sbx="$(sandbox_of "$out")"
[[ -L "$sbx/inputs" ]] || fail "inputs/ is not a link to the evidence: a VM run copied it"
[[ "$(cd "$sbx/inputs" && pwd -P)" == "$(cd "$TMP/ev" && pwd -P)" ]] || fail "inputs/ links somewhere else"
[[ ! -e "$sbx/.inputs-pristine" ]] || fail "a VM run made a pristine clone it will never heal from"
[[ "$(jq -r '.guard' "$sbx/inputs.json")" == "microvm" ]] || fail "inputs.json does not say the VM holds the evidence"
[[ "$(jq -r '.held' "$sbx/inputs.json")" == "bind" ]] || fail "inputs.json does not say the evidence was used in place"
[[ "$(reg vm-ev '.isolation.disk_mib')" == "8192" ]] || fail "the VM disk size is not recorded"
[[ "$(jq -r '.files | length' "$sbx/inputs.json")" == "2" ]] || fail "the manifest does not list both files"
printf '%s\n' "$out" | grep -q 'kernel guard: microvm' || fail "the kickoff does not say who holds the evidence: $out"
pass "the evidence is used in place, with no copy and no pristine clone, and the manifest says the VM holds it"

for id in $(jq -r '.agents[].id' "$sbx/team.json"); do
  [[ -d "$sbx/tool-output/$id" ]] || fail "no tool-output/$id for its VM to mount writable"
  [[ -d "$sbx/.pi-sessions/$id" ]] || fail "no .pi-sessions/$id for its VM to mount writable"
  for d in "work/$id" "work/extracted/$id" "work/quarantine/$id"; do
    [[ -d "$sbx/$d" ]] || fail "no $d for its VM to mount writable"
  done
done
grep -q 'publish_file' "$sbx/SWARM.md" || fail "the contract does not tell a VM agent how a shared file is written"
grep -q 'the rest of `work/` is read-only there' "$sbx/SWARM.md" || fail "the contract does not say the shared work/ is read-only in a VM"
pass "every agent's writable holes exist before its VM would mount over them"

[[ "$(reg vm-ev '.isolation.mode')" == "microvm" ]] || fail "the registry does not record the isolation"
[[ "$(reg vm-ev '.isolation.image')" == "dfirswarm-base:dev-$ARCH" ]] || fail "a run with no packs should boot the base image, got $(reg vm-ev '.isolation.image')"
[[ "$(reg vm-ev '.isolation.cpus')" == "2" && "$(reg vm-ev '.isolation.memory_mib')" == "2048" ]] || fail "the VM size is not recorded"
[[ "$(reg vm-ev '.isolation.snapshot')" == "true" ]] || fail "a VM run keeps each disk by default"
[[ "$(reg vm-ev '.write_guard')" == "microvm" ]] || fail "write_guard is $(reg vm-ev '.write_guard'), not microvm"
[[ "$(reg vm-ev '.attribution')" == "channel" ]] || fail "attribution is $(reg vm-ev '.attribution'), not channel"
[[ "$(reg vm-ev '.netguard_mode')" == "microvm" ]] || fail "netguard_mode is $(reg vm-ev '.netguard_mode'), not microvm"
[[ "$(reg vm-ev '.herdr_socket')" == "unreachable" ]] || fail "herdr_socket is $(reg vm-ev '.herdr_socket'), not unreachable"
for f in collector.pid nudge.pid hub.pid gate.pid netguard.pid; do
  [[ ! -f "$sbx/$f" ]] || fail "--no-start left $f behind"
done
[[ ! -e "$sbx/.zsh" && ! -e "$sbx/.fsguard" ]] || fail "a VM run wrote the host's pane guard hook"
pass "the record says microvm wherever a host run says which guard it had, and --no-start leaves no daemon"

# --- the contract tells the agents what a VM changes -----------------------------
grep -q 'own microVM' "$sbx/SWARM.md" || fail "SWARM.md does not tell the agents they are in a VM"
grep -q 'up to five seconds' "$sbx/SWARM.md" || fail "SWARM.md does not warn about a peer's file taking a moment to look current"
grep -q 'written for you' "$sbx/SWARM.md" || fail "SWARM.md does not say the board is written by the harness"
grep -q 'no copy, and the host holds the source read-only' "$sbx/SWARM.md" || fail "SWARM.md does not say how the evidence arrived"
! grep -q 'advisory here (a proxy' "$sbx/SWARM.md" || fail "SWARM.md describes the host's proxy to agents that have none"
pass "the contract says the agent is in its own VM, the board is written for it, a peer's file can lag, and how the evidence arrived"

# --- the image follows the packs, and an operator's image wins ------------------
# In a home of our own: whatever packs this machine has installed are not the test's.
export DFIRSWARM_HOME="$TMP/home"
for p in computer-forensics-base memory-forensics; do
  bash "$ROOT/scripts/pack.sh" install "$ROOT/packs/$p" --yes >/dev/null 2>&1 || fail "could not install pack $p into the test's home"
done
out="$(start --isolation microvm --pack memory-forensics --label vm-mem)"; rc=$?
[[ $rc -eq 0 ]] || fail "a microvm run with a pack exited $rc: $out"
[[ "$(reg vm-mem '.isolation.image')" == "dfirswarm-memory:dev-$ARCH" ]] || fail "memory-forensics should boot the memory image, got $(reg vm-mem '.isolation.image')"
out="$(start --isolation microvm --image registry.example/dfirswarm-custom@sha256:abc --label vm-img)"
[[ "$(reg vm-img '.isolation.image')" == "registry.example/dfirswarm-custom@sha256:abc" ]] || fail "--image was not honoured"
out="$(SWARM_ISOLATION=microvm start --label vm-env)"
[[ "$(reg vm-env '.isolation.mode')" == "microvm" ]] || fail "SWARM_ISOLATION=microvm did not set the default"
out="$(start --label host-default)"
[[ "$(reg host-default '.isolation.mode')" == "host" ]] || fail "a run without --isolation is not a host run"
pass "the packs choose the image, --image overrides it, SWARM_ISOLATION sets the default, and host stays the default"

# --- what the VMs would be given: no credential, no host home, the secrets bound ----
# A pack with two secrets: one bound to a host, one with no host to bind to.
mkdir -p "$TMP/psrc/keyed-pack/skills/alpha" "$TMP/psrc/keyed-pack/tools/echo_tool" "$TMP/psrc/keyed-pack/requires"
printf 'Test pack.\n' > "$TMP/psrc/keyed-pack/LICENCE"
cat > "$TMP/psrc/keyed-pack/skills/alpha/first.md" <<'EOF'
---
id: alpha/first
title: The first skill
when: Whenever the suite asks for it.
needs: []
tools: [echo_tool]
requires_host: []
---

A body.
EOF
cat > "$TMP/psrc/keyed-pack/tools/echo_tool/manifest.json" <<'EOF'
{ "name": "echo_tool", "description": "Echo.", "params": { "text": { "type": "string", "description": "What" } }, "runtime": "python3", "entry": "run.py", "timeout_seconds": 10 }
EOF
printf 'import json,sys\nprint(json.dumps({"ok": True}))\n' > "$TMP/psrc/keyed-pack/tools/echo_tool/run.py"
printf '{ "binaries": [] }\n' > "$TMP/psrc/keyed-pack/requires/host.json"
cat > "$TMP/psrc/keyed-pack/pack.json" <<'EOF'
{ "id": "keyed-pack", "name": "keyed-pack", "version": "1.0.0", "description": "A pack for the suite.", "licence": "AGPL-3.0-or-later",
  "depends": [], "requires": { "host": "requires/host.json" },
  "secrets": [
    { "name": "TEST_API_KEY", "title": "A key", "why": "For the suite.", "required": false, "hosts": ["api.example.test"] },
    { "name": "LOOSE_KEY", "title": "A loose key", "why": "For the suite.", "required": false }
  ] }
EOF
bash "$ROOT/scripts/pack.sh" seal "$TMP/psrc/keyed-pack" >/dev/null || fail "seal keyed-pack"
TEST_API_KEY=hunter2-value LOOSE_KEY=loose-value bash "$ROOT/scripts/pack.sh" install "$TMP/psrc/keyed-pack" --yes >/dev/null 2>&1 || fail "install keyed-pack"
mkdir -p "$TMP/home2"
printf 'Summarise the case so far.\n' > "$TMP/home2/prompt.md"
printf '{"not":"a real store"}\n' > "$TMP/home2/auth.json"
out="$(start --isolation microvm --inputs "$TMP/ev" --pack keyed-pack --compact-prompt-file "$TMP/home2/prompt.md" --label vm-spec)"; rc=$?
[[ $rc -eq 0 ]] || fail "a prepared microvm run with a keyed pack exited $rc: $out"
sbx="$(sandbox_of "$out")"
[[ -f "$sbx/vm-spec.json" ]] || fail "a prepared microvm run writes vm-spec.json"
while IFS= read -r h; do
  [[ "$h" == "$TMP/home2" || "$h" == "$HOME" ]] && fail "the prompt's directory (or the home) is mounted into the VMs: $h"
  case "$h" in
    *"/secrets"*|*"/docs/use-cases"*|*"/auth.json"*) fail "a mount carries what no VM may see: $h" ;;
  esac
  [[ "$h" == "$TMP/runs"* && "$h" != *"/vm-prepared/runs" ]] && fail "the operator's registry is mounted: $h"
done < <(jq -r '.mounts[].host' "$sbx/vm-spec.json")
[[ -f "$sbx/compact-prompt.md" ]] || fail "the compaction prompt was not copied into the run"
[[ "$(jq -r '.env.SWARM_COMPACT_PROMPT' "$sbx/vm-spec.json")" == "$sbx/compact-prompt.md" ]] || fail "the VMs are not pointed at the run's copy of the prompt"
jq -e --arg f "$DFIRSWARM_HOME/secrets/keyed-pack.env" '.pack_secrets == [{name: "TEST_API_KEY", value_file: $f, hosts: ["api.example.test"]}]' "$sbx/vm-spec.json" >/dev/null \
  || fail "the bound secret is not in the spec as expected: $(jq -c '.pack_secrets' "$sbx/vm-spec.json")"
printf '%s\n' "$out" | grep -q 'LOOSE_KEY.*withheld' || fail "a secret with no hosts is not said to be withheld: $out"
[[ "$(jq -r '.env.SWARM_PACK_SECRETS | fromjson | ."keyed-pack".names | join(",")' "$sbx/vm-spec.json")" == "TEST_API_KEY" ]] || fail "the VM is told the wrong secret names"
grep -rq 'hunter2-value\|loose-value' "$sbx" && fail "a secret's value is in the run"
[[ "$(reg vm-spec '.pack_secrets."keyed-pack".mode')" == "injected" ]] || fail "the record does not say injected"
pass "a prepared VM run's spec mounts neither the prompt's directory nor a secret, points at the run's own copy of the prompt, and binds each secret to its hosts"

# --- a credential cannot ride in on --env; a subscription needs an explicit yes ---------
out="$(start --isolation microvm --env FOO_API_KEY=abc --label bad-env)"; rc=$?
[[ $rc -eq 2 ]] || fail "--env FOO_API_KEY under microvm exited $rc, wanted 2: $out"
printf '%s\n' "$out" | grep -q 'names a credential' || fail "the refusal does not say why: $out"
mkdir -p "$TMP/pi"
printf '{"openai-codex": {"type": "oauth", "access": "not-real", "refresh": "not-real", "expires": 1}}\n' > "$TMP/pi/auth.json"
out="$(PI_CODING_AGENT_DIR="$TMP/pi" start --isolation microvm --model openai-codex/gpt-5.4 --label bad-oauth)"; rc=$?
[[ $rc -eq 2 ]] || fail "a subscription provider under microvm exited $rc, wanted 2: $out"
printf '%s\n' "$out" | grep -q 'subscription' || fail "the refusal does not name the subscription: $out"
out="$(PI_CODING_AGENT_DIR="$TMP/pi" start --isolation microvm --model openai-codex/gpt-5.4 --allow-oauth-in-vm --label ok-oauth)"; rc=$?
[[ $rc -eq 0 ]] || fail "--allow-oauth-in-vm did not let the run through: $out"
[[ "$(reg ok-oauth '.isolation.oauth_allowed')" == "true" ]] || fail "the record does not say the subscription was let in on purpose"
sbx="$(sandbox_of "$out")"
[[ "$(jq -r '.providers[] | select(.provider == "openai-codex") | .hosts | join(",")' "$sbx/vm-spec.json")" == "chatgpt.com" ]] \
  || fail "the refresh endpoint is bound though the guest never refreshes: $(jq -c '.providers' "$sbx/vm-spec.json")"
pass "a credential in --env is refused, a subscription needs --allow-oauth-in-vm and is recorded, and its refresh endpoint is never bound"

# --- the evidence: links recorded as links, a second layer on request, a warning ------
mkdir -p "$TMP/ev-mixed/sub"
printf 'a\n' > "$TMP/ev-mixed/a.txt"
printf 'b\n' > "$TMP/ev-mixed/sub/b.txt"
ln -s a.txt "$TMP/ev-mixed/a-link.txt"
ln -s sub "$TMP/ev-mixed/sub-link"
chmod -R a-w "$TMP/ev-mixed"/a.txt "$TMP/ev-mixed/sub/b.txt"
out="$(start --isolation microvm --inputs "$TMP/ev-mixed" --label vm-links)"; rc=$?
[[ $rc -eq 0 ]] || fail "evidence with links inside it exited $rc: $out"
sbx="$(sandbox_of "$out")"
jq -e '[.files[] | select(.link)] | map({path, link}) == [{path: "inputs/a-link.txt", link: "a.txt"}, {path: "inputs/sub-link", link: "sub"}]' "$sbx/inputs.json" >/dev/null \
  || fail "the manifest does not record the links as links: $(jq -c '.files' "$sbx/inputs.json")"
[[ "$(jq '[.files[] | select(.link | not)] | length' "$sbx/inputs.json")" == "2" ]] || fail "a directory link was walked into, or a file was lost"
printf '%s\n' "$out" | grep -q 'is writable by this account' && fail "read-only evidence was said to be writable"
node --experimental-strip-types --no-warnings --input-type=module -e "
  const P = await import('$ROOT/extensions/protocol.ts');
  const c = await P.verifyInputs('$sbx');
  if (!c.ok) { console.error(JSON.stringify(c)); process.exit(1); }
" || fail "the agents' own inputs check calls unchanged evidence with links in it changed"
(cd "$sbx" && python3 "$ROOT/packs/computer-forensics-base/tools/check_inputs/run.py" >/dev/null) || fail "the pack's check_inputs calls it changed"
pass "links inside the evidence are recorded as links, and the manifest, the agents' check and check_inputs agree they are unchanged"

chmod u+w "$TMP/ev-mixed/a.txt"
out="$(start --isolation microvm --inputs "$TMP/ev-mixed" --label vm-writable)"
printf '%s\n' "$out" | grep -q 'is writable by this account' || fail "writable evidence used in place is not warned about: $out"
out="$(start --isolation microvm --inputs "$TMP/ev-link" --inputs-copy --label vm-copy)"; rc=$?
[[ $rc -eq 0 ]] || fail "--inputs-copy exited $rc: $out"
sbx="$(sandbox_of "$out")"
[[ -d "$sbx/inputs" && ! -L "$sbx/inputs" ]] || fail "--inputs-copy did not copy the evidence into the run"
[[ "$(jq -r '.held' "$sbx/inputs.json")" == "copy" ]] || fail "the manifest does not say the evidence was copied"
[[ -z "$(find "$sbx/inputs" -type f -perm -u+w)" ]] || fail "the copy is writable"
pass "writable evidence used in place is warned about; --inputs-copy gives the run its own read-only copy"

# --- a reused sandbox starts clean; a prepared VM run touches no host tool ---------------
reuse="$TMP/reused"
out="$(start --isolation microvm --sandbox "$reuse" --label vm-reuse1)"
mkdir -p "$reuse/vm" "$reuse/tools/old_tool" "$reuse/history/x" "$reuse/.pi-sessions/old" "$reuse/tool-output/old"
printf '{}' > "$reuse/vm/old.json"; printf '{"summary":"old"}' > "$reuse/custody.json"; printf 'x' > "$reuse/tools/old_tool/manifest.json"
out="$(start --isolation microvm --sandbox "$reuse" --label vm-reuse2)"; rc=$?
[[ $rc -eq 0 ]] || fail "reusing a sandbox exited $rc: $out"
for gone in vm/old.json custody.json tools/old_tool .pi-sessions/old tool-output/old; do
  [[ ! -e "$reuse/$gone" ]] || fail "a reused sandbox kept the previous run's $gone"
done
# A sandbox a running run still uses is not cleared under it.
reuse_id="$(reg vm-reuse2 '.id')"
jq --arg id "$reuse_id" '.runs = [.runs[] | if .id == $id then .state = "running" else . end]' "$TMP/runs/registry.json" > "$TMP/reg.tmp" && mv "$TMP/reg.tmp" "$TMP/runs/registry.json"
touch "$reuse/work/keep-me"
out="$(start --isolation microvm --sandbox "$reuse" --label vm-reuse3)"; rc=$?
[[ $rc -eq 2 ]] && printf '%s\n' "$out" | grep -q "run $reuse_id is still running in" || fail "a sandbox a running run uses was taken: $out"
[[ -e "$reuse/work/keep-me" ]] || fail "the running run's work was cleared"
jq --arg id "$reuse_id" '.runs = [.runs[] | if .id == $id then .state = "stopped" else . end]' "$TMP/runs/registry.json" > "$TMP/reg.tmp" && mv "$TMP/reg.tmp" "$TMP/runs/registry.json"
pass "a reused sandbox loses the previous run's VM records, custody, tools, sessions and outputs, and one a running run uses is refused"
out="$(start --isolation microvm --inputs "$TMP/ev" --catalog --label vm-prepared)"; rc=$?
[[ $rc -eq 0 ]] || fail "a prepared VM run with --catalog exited $rc: $out"
sbx="$(sandbox_of "$out")"
printf '%s\n' "$out" | grep -q 'built in the run.s image when the VMs start' || fail "a prepared VM run does not say where its catalog will be built: $out"
[[ ! -f "$sbx/catalog/README.md" ]] || fail "a prepared VM run built its catalog with this host's tools"
[[ ! -f "$sbx/toolbox.json" ]] || fail "a prepared VM run checked this host's toolbox"
[[ -f "$TMP/runs/$(basename "$sbx").custody-anchor.json" || -f "$sbx.custody-anchor.json" ]] || fail "no custody anchor outside the run"
pass "a prepared VM run leaves the toolbox and the catalog to the image, and anchors its manifest outside the run"

out="$(start --isolation microvm --no-vm-snapshot --label vm-nosnap)"
[[ "$(reg vm-nosnap '.isolation.snapshot')" == "false" ]] || fail "--no-vm-snapshot is not recorded"
pass "--no-vm-snapshot is recorded for stop to read"

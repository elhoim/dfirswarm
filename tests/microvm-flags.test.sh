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
start() { swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off "$@"; }
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
[[ ! -f "$TMP/runs/registry.json" ]] || [[ -z "$(jq -r '.runs[] | select(.label | startswith("bad-")) | .id' "$TMP/runs/registry.json")" ]] \
  || fail "a refused kickoff left a run in the registry"
pass "an isolation that does not exist, a probe with no guard to probe, and a VM with no CPU or too little memory are refused before anything is written"

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
[[ "$(jq -r '.files | length' "$sbx/inputs.json")" == "2" ]] || fail "the manifest does not list both files"
printf '%s\n' "$out" | grep -q 'kernel guard: microvm' || fail "the kickoff does not say who holds the evidence: $out"
pass "the evidence is used in place, with no copy and no pristine clone, and the manifest says the VM holds it"

for id in $(jq -r '.agents[].id' "$sbx/team.json"); do
  [[ -d "$sbx/tool-output/$id" ]] || fail "no tool-output/$id for its VM to mount writable"
  [[ -d "$sbx/.pi-sessions/$id" ]] || fail "no .pi-sessions/$id for its VM to mount writable"
done
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

out="$(start --isolation microvm --no-vm-snapshot --label vm-nosnap)"
[[ "$(reg vm-nosnap '.isolation.snapshot')" == "false" ]] || fail "--no-vm-snapshot is not recorded"
pass "--no-vm-snapshot is recorded for stop to read"

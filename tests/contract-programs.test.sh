#!/usr/bin/env bash
# The contract's word on programs. A microVM run whose image describes itself
# (/etc/dfirswarm/tools.md, written by images/install.py) is pointed at that
# file and names no program; an image without it, and a host run, keep the
# checked table.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/contract-programs.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
TEMPLATE="$ROOT/prompts/swarm.md.template"
distinct_models() { echo "solo/model"; }
AGENT_MODELS=()
eval "$(sed -n '/^render_contract()/,/^}/p' "$ROOT/scripts/swarm.sh")"
printf 'Find the thing.\n' > "$TMP/goal.md"

render() { # <toolbox.json> <isolation>
  rm -rf "$TMP/sb"; mkdir -p "$TMP/sb"
  printf '%s\n' "$1" > "$TMP/sb/toolbox.json"
  ISOLATION_FOR_CONTRACT="$2" render_contract "$TMP/sb" s1 1 1 10 "$TMP/goal.md" s100
  cat "$TMP/sb/SWARM.md"
}

out="$(render '{"context": "image", "image": "dfirswarm-disk:dev", "tools_md": "/etc/dfirswarm/tools.md", "present": [{"name": "mmls", "version": "4.11", "use": "partition table"}], "missing": []}' microvm)"
grep -q '^## Programs' <<<"$out" || fail "a self-describing image gave no Programs section: $out"
grep -q '/etc/dfirswarm/tools.md' <<<"$out" || fail "the contract does not name tools.md"
grep -q 'mmls' <<<"$out" && fail "the contract names a program the image's own list carries"
grep -q '| Tool | Version |' <<<"$out" && fail "the table is still there beside the pointer"
pass "a VM run whose image has tools.md is pointed at it, and no program is named"

out="$(render '{"context": "image", "image": "dfirswarm-disk:old", "present": [{"name": "mmls", "version": "4.11", "use": "partition table"}], "missing": []}' microvm)"
grep -q '| `mmls` | 4.11 | partition table |' <<<"$out" || fail "an image without tools.md lost the checked table: $out"
out="$(render '{"context": "host", "present": [{"name": "python3", "version": "3.12", "use": "scripts"}], "missing": []}' host)"
grep -q '| `python3` | 3.12 | scripts |' <<<"$out" || fail "a host run lost the checked table: $out"
pass "an image without tools.md, and a host run, keep the checked table"

# The tools in tools/: a pack's are said to be there, in the tool list, and are
# general; only --tools-from copies are listed as another case's, and "baked"
# means an inputs/ path or an offset their example gives, not any big number.
rm -rf "$TMP/sb"; mkdir -p "$TMP/sb/tools/regkv" "$TMP/sb/tools/old_carver"
printf '%s\n' '{"context": "host", "present": [], "missing": []}' > "$TMP/sb/toolbox.json"
printf '%s\n' '{"name": "regkv", "pack": "windows-forensics", "description": "Read a key; limit is at most 20000.", "example": "{\"hive\": \"work/x/SYSTEM\", \"key\": \"Select\"}", "params": {"hive": {}, "key": {}}}' > "$TMP/sb/tools/regkv/manifest.json"
printf '%s\n' '{"name": "old_carver", "description": "Carve from 133502964000000000 onwards.", "example": "{\"image\": \"inputs/disk.E01\", \"offset\": 1048576}", "params": {"image": {}, "offset": {}}}' > "$TMP/sb/tools/old_carver/manifest.json"
ISOLATION_FOR_CONTRACT=host render_contract "$TMP/sb" s1 1 1 10 "$TMP/goal.md" s100
out="$(cat "$TMP/sb/SWARM.md")"
grep -q '^## Pack tools' <<<"$out" || fail "a pack's tools are not said to be there: $out"
grep -q 'packs (windows-forensics) put 1 tools in your tool list' <<<"$out" || fail "the pack tools line does not count them: $out"
grep -q '| `regkv` |' <<<"$out" && fail "a pack's tool is listed as another case's"
grep -q '| `old_carver` | image, offset | Carve from 133502964000000000 onwards. — baked: inputs/disk.E01, offset 1048576 |' <<<"$out" \
  || fail "a seeded tool's baked path and offset are not said, or a number in its prose was taken for one: $out"
grep -q '20000' <<<"$out" && fail "a pack tool's limit reached the contract"
pass "a pack's tools are said to be in the tool list; only seeded tools are another case's, with what their example bakes in"

# The goal's check on the trace for the harness's inputs_check line says who
# writes it, in prose with no backticks, and await-done still runs the check.
rm -rf "$TMP/sb"; mkdir -p "$TMP/sb"
printf '%s\n' '{"context": "host", "present": [], "missing": []}' > "$TMP/sb/toolbox.json"
printf '## Checks\n\n- `test -f work/report.md`\n- `grep -q '"'"'"tool":"inputs_check"'"'"' traces/events.jsonl`\n' > "$TMP/goal-checks.md"
ISOLATION_FOR_CONTRACT=host render_contract "$TMP/sb" s1 1 1 10 "$TMP/goal-checks.md" s100
line="$(grep 'inputs_check' "$TMP/sb/SWARM.md")"
grep -q 'the harness writes this line itself when done verifies the inputs' <<<"$line" || fail "the inputs_check check does not say the harness writes it: $line"
[[ "$(grep -o '`' <<<"$line" | wc -l | tr -d ' ')" == 2 ]] || fail "the note added a code span await-done would run: $line"
grep -q '^- `test -f work/report.md`$' "$TMP/sb/SWARM.md" || fail "another check was changed"
pass "the check on the harness's inputs_check line says the harness writes it, and adds no code span"

# What each job image can do reaches the contract before a seat reads it: the
# kickoff seeds job-capabilities.json (an earlier run's result for the same
# image, said pending) and the contract has a "Job image capabilities" section;
# the probes start as soon as the hub is up, before the seats' VMs are made.
eval "$(sed -n '/^image_capabilities_cache()/p; /^seed_job_capabilities()/,/^}/p' "$ROOT/scripts/swarm.sh")"
export DFIRSWARM_HOME="$TMP/home"
mkdir -p "$DFIRSWARM_HOME/image-capabilities"
# The cache is kept by the image's digest, as the kickoff read it on this host (plan_job_images): a tag names whatever
# was last built under it.
DISK_DIGEST="sha256:$(printf 'd%.0s' $(seq 1 64))"
printf '%s\n' '{"image": "dfirswarm-disk:dev-arm64", "digest": "'"$DISK_DIGEST"'", "profile": "disk", "at": "2026-11-01T10:00:00Z", "capabilities": [{"id": "disasm-x86-64", "what": "disassemble x86-64 code", "ok": false, "said": "objdump here disassembles only elf64-littleaarch64; no r2, no capstone"}]}' \
  > "$DFIRSWARM_HOME/image-capabilities/sha256_$(printf 'd%.0s' $(seq 1 64)).json"
rm -rf "$TMP/sb"; mkdir -p "$TMP/sb"
job_image_digests_json='{"disk": "sha256:'"$(printf 'e%.0s' $(seq 1 64))"'"}' isolation=microvm jobs=1 resume_of="" seed_job_capabilities "$TMP/sb" '{"disk": "dfirswarm-disk:dev-arm64", "re": "dfirswarm-re:dev-arm64"}'
jq -e '.pending == true and (.images | keys) == []' "$TMP/sb/job-capabilities.json" >/dev/null || fail "an image rebuilt under the same tag was seeded with an earlier image's result: $(cat "$TMP/sb/job-capabilities.json")"
rm -rf "$TMP/sb"; mkdir -p "$TMP/sb"
job_image_digests_json='{"disk": "'"$DISK_DIGEST"'"}' isolation=microvm jobs=1 resume_of="" seed_job_capabilities "$TMP/sb" '{"disk": "dfirswarm-disk:dev-arm64", "re": "dfirswarm-re:dev-arm64"}'
jq -e '.pending == true and (.images | keys) == ["disk"] and .cached.disk.image == "dfirswarm-disk:dev-arm64"' "$TMP/sb/job-capabilities.json" >/dev/null || fail "the seed: $(cat "$TMP/sb/job-capabilities.json")"
ISOLATION_FOR_CONTRACT=microvm render_contract "$TMP/sb" s1 1 1 10 "$TMP/goal.md" s100
out="$(cat "$TMP/sb/SWARM.md")"
grep -q '^## Job image capabilities$' <<<"$out" || fail "no capabilities section: $out"
grep -q -- '- disk: WORKS: none of the tested. DOES NOT: disassemble x86-64 code: objdump here disassembles only elf64-littleaarch64' <<<"$out" || fail "the cached line is not in the contract: $out"
grep -q 'As an earlier run of the same image found it (disk 2026-11-01T10:00:00Z); this run tests each image again now' <<<"$out" || fail "the cached line is not said to be an earlier run's: $out"
rm -rf "$TMP/sb"; mkdir -p "$TMP/sb"
isolation=host jobs=1 resume_of="" seed_job_capabilities "$TMP/sb" '{"disk": "dfirswarm-disk:dev-arm64"}'
[[ ! -e "$TMP/sb/job-capabilities.json" ]] || fail "a host run was seeded"
SWARM_IMAGE_CAPABILITIES=off isolation=microvm jobs=1 resume_of="" seed_job_capabilities "$TMP/sb" '{"disk": "dfirswarm-disk:dev-arm64"}'
[[ ! -e "$TMP/sb/job-capabilities.json" ]] || fail "SWARM_IMAGE_CAPABILITIES=off was seeded"
ISOLATION_FOR_CONTRACT=microvm render_contract "$TMP/sb" s1 1 1 10 "$TMP/goal.md" s100
grep -q 'Job image capabilities' "$TMP/sb/SWARM.md" && fail "a run with no seed has a capabilities section"
# In the order a seat needs it: the probe right after the hub, before the seats' VMs.
body="$(sed -n '/^launch_vm_agents()/,/^}/p' "$ROOT/scripts/swarm.sh")"
hub_at="$(grep -n 'start_vm_hub "\$sandbox"' <<<"$body" | head -1 | cut -d: -f1)"
probe_at="$(grep -n 'start_image_capabilities "\$sandbox"' <<<"$body" | head -1 | cut -d: -f1)"
create_at="$(grep -n 'vm_cli create --spec' <<<"$body" | head -1 | cut -d: -f1)"
[[ -n "$hub_at" && -n "$probe_at" && -n "$create_at" && "$hub_at" -lt "$probe_at" && "$probe_at" -lt "$create_at" ]] || fail "the probes do not start between the hub and the seats' VMs ($hub_at, $probe_at, $create_at)"
grep -q 'run_script "\$hub_dir" scripts/image-capabilities.ts' "$ROOT/scripts/swarm.sh" || fail "the probe does not run from the run's frozen copy"
pass "the job images' capabilities are seeded into the contract (an earlier run's, said so), and probed as soon as the hub is up"

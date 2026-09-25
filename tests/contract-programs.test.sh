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

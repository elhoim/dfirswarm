#!/usr/bin/env bash
# SWARM.md as a seat first reads it: Pi's read returns 50 KB, and a contract
# past that once left the seats without "Job images" and "Questions". Rendered
# by the kickoff's own functions with every shipped pack's tools run as jobs
# (one line a tool for every pack is about 36k characters), the largest
# shipped goal, job images and their capabilities, an inputs list past its
# bound and the case policy: it stays under 50 KB, says its size and its
# sections in its first lines, and has the sections in the order a seat needs
# them (Questions and Job images before the programs and the evidence
# catalog). A catalog index too large to quote is left in catalog/README.md.
# No model, no Herdr, no VM.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
TMP="$(mktemp -d "${TMPDIR:-/tmp}/swarm-md-size.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
TEMPLATE="$ROOT/prompts/swarm.md.template"
distinct_models() { echo "solo/model"; }
AGENT_MODELS=()
resume_of=""
eval "$(sed -n '/^render_contract()/,/^}/p; /^pack_tools_contract_section()/,/^}/p; /^finish_contract()/,/^}/p; /^write_case_policy_record()/,/^}/p; /^write_case_policy()/,/^}/p' "$ROOT/scripts/swarm.sh")"

GOAL="$(ls -S "$ROOT"/prompts/goals/*.md | head -1)"
packs="$(cd "$ROOT/packs" && ls -d */ | tr -d / | paste -sd, -)"
[[ "$(tr ',' '\n' <<<"$packs" | wc -l | tr -d ' ')" -ge 13 ]] || fail "fewer than 13 packs: $packs"

build() { # <sandbox> <catalog bytes>
  local sb="$1" bytes="$2" p t
  rm -rf "$sb"; mkdir -p "$sb/tools" "$sb/catalog"
  for p in "$ROOT"/packs/*/; do
    for t in "$p"tools/*/; do
      [[ -f "$t/manifest.json" ]] || continue
      mkdir -p "$sb/tools/$(basename "$t")"
      jq --arg pack "$(basename "$p")" '. + {pack: $pack}' "$t/manifest.json" > "$sb/tools/$(basename "$t")/manifest.json"
    done
  done
  printf '%s\n' '{"context": "image", "image": "dfirswarm-base:dev", "tools_md": "/etc/dfirswarm/tools.md", "present": [], "missing": []}' > "$sb/toolbox.json"
  python3 - "$sb" "$bytes" <<'PY'
import json, sys
sb, n = sys.argv[1], int(sys.argv[2])
files = [{"path": f"inputs/set/item-{i:04d}.bin", "bytes": 4096 * i} for i in range(400)]
json.dump({"source": "/evidence/case", "files": files, "bytes": sum(f["bytes"] for f in files), "guard": "microvm", "held": "bind"}, open(f"{sb}/inputs.json", "w"))
line = "| inputs/set/item-0000.bin | disk image | NTFS, 3 partitions, catalogued in part (listing complete; digests pending) |\n"
open(f"{sb}/catalog/README.md", "w").write("# Evidence catalog\n\n" + line * max(1, n // len(line)))
caps = [{"id": c, "what": w, "ok": i % 2 == 0, **({"by": "a program of the image"} if i % 2 == 0 else {"said": "not in this image: use the pack tool or ask the operator"})}
        for i, (c, w) in enumerate([("disasm-x86-64", "disassemble x86-64 code"), ("qr-decode", "decode a QR symbol from a PNG"), ("video-decode", "write and decode a video clip"), ("image-read", "read a PNG's pixels"), ("ocr", "read text from a picture"), ("brotli", "inflate brotli"), ("numpy", "numpy"), ("compile-c", "compile and run C"), ("crypto-lib", "a Python crypto library")])]
profiles = ["base", "disk", "memory", "mobile", "network", "re", "full"]
json.dump({"at": "2026-11-14T00:00:00Z", "profiles": profiles, "images": {p: caps for p in profiles}}, open(f"{sb}/job-capabilities.json", "w"))
PY
}

jobs_json() {
  jq -nc --arg packs "$packs" '{workers: 4, cpus: 2, memoryMib: 4096, derived: true, allowHosts: [],
    images: {base: "dfirswarm-base:dev", disk: "dfirswarm-disk:dev", memory: "dfirswarm-memory:dev", mobile: "dfirswarm-mobile:dev", network: "dfirswarm-network:dev", re: "dfirswarm-re:dev", full: "dfirswarm-full:dev"},
    packProfiles: ($packs | split(",") | map({key: ., value: "full"}) | from_entries), image: "dfirswarm-full:dev"}'
}

render() { # <sandbox>
  local sb="$1" ids="" i
  for ((i = 0; i < 6; i++)); do ids+=" sw1$(printf '%02d' "$i")"; done
  CASE_POLICY_JSON="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/case-policy.ts" resolve --goal-file "$GOAL" --isolation microvm --allow-hosts "" | jq -c '.policy')"
  pack_tools_as_jobs="$packs" CASE_ID_FOR_CONTRACT="case-1" EXAMINER_FOR_CONTRACT="the examiner" \
    HOST_CAPS_FOR_CONTRACT='{"os": "Darwin"}' WRITE_GUARD_FOR_CONTRACT=microvm ATTRIBUTION_FOR_CONTRACT=channel \
    ISOLATION_FOR_CONTRACT=microvm VM_HOSTS_FOR_CONTRACT="" JOBS_FOR_CONTRACT="$(jobs_json)" \
    render_contract "$sb" sw1 6 250 600 "$GOAL" $ids
  isolation=microvm write_case_policy "$sb"
  finish_contract "$sb"
}

SB="$TMP/sb"
build "$SB" 6000
render "$SB" >/dev/null
md="$SB/SWARM.md"
bytes="$(wc -c < "$md" | tr -d ' ')"
[[ "$bytes" -lt 51200 ]] || fail "SWARM.md with every pack's tools as jobs is $bytes bytes, past 50 KB"
head -3 "$md" | grep -qE '^This file is about [0-9]+ KB\. Its sections, in the order a seat needs them: .*Questions; .*Job images; .*\. One read returns it whole\.$' \
  || fail "the first lines do not say the size and the sections: $(head -3 "$md")"
kb="$(sed -n 's/^This file is about \([0-9]*\) KB\..*/\1/p' "$md")"
[[ "$kb" -ge $(( (bytes + 1023) / 1024 )) && "$kb" -le $(( bytes / 1024 + 2 )) ]] || fail "the first lines say $kb KB of $bytes bytes"
order() { grep -n "^## $1\$" "$md" | head -1 | cut -d: -f1; }
for h in "Team" "Questions" "Inputs (read-only)" "Tool jobs" "Job images" "Job image capabilities" "Pack tools run as jobs" "Programs" "Evidence catalog (read-only)" "Case policy and network"; do
  [[ -n "$(order "$h")" ]] || fail "no section $h"
done
[[ "$(order "Questions")" -lt "$(order "Inputs (read-only)")" && "$(order "Inputs (read-only)")" -lt "$(order "Job images")" && "$(order "Job images")" -lt "$(order "Pack tools run as jobs")" \
   && "$(order "Pack tools run as jobs")" -lt "$(order "Programs")" && "$(order "Programs")" -lt "$(order "Evidence catalog (read-only)")" ]] \
  || fail "the sections are not in the order a seat needs them: $(grep -n '^## ' "$md")"
# What a seat's first read of 50 KB holds: Questions and Job images whole.
first="$(head -c 51200 "$md")"
grep -q '^## Questions$' <<<"$first" && grep -q '^## Job images$' <<<"$first" || fail "the first 50 KB lack Questions or Job images"
section="$(awk '/^## Pack tools run as jobs$/{on=1; print; next} on && /^## /{exit} on' "$md")"
n_tools="$(ls "$SB/tools" | wc -l | tr -d ' ')"
[[ "${#section}" -lt 6000 ]] || fail "the pack tools section is ${#section} characters for $n_tools tools: the catalogue is not in its own file"
grep -c '^- `[a-z0-9_]*` (' "$SB/PACK-TOOLS.md" | { read -r c; [[ "$c" -ge $(( n_tools * 2 )) ]] || fail "PACK-TOOLS.md holds $c tool lines for $n_tools tools (one line, then whole)"; }
grep -q '^## Pack tools$' "$md" && fail "the contract still says the packs run as jobs put their tools in the tool list"
pass "SWARM.md with every pack's $n_tools tools as jobs is $bytes bytes, says its size and sections first, and has Questions and Job images before the programs and the catalog"

# A catalog index that would push it past one read is left in catalog/README.md, and said.
build "$SB" 200000
out="$(render "$SB")"
bytes="$(wc -c < "$md" | tr -d ' ')"
[[ "$bytes" -lt 51200 ]] || fail "with a 200 KB catalog index SWARM.md is $bytes bytes"
grep -q 'The index is in `catalog/README.md` (about [0-9]* KB, too large to quote here' "$md" || fail "the catalog section does not say where its index is"
grep -q "left out to stay within one read: the evidence catalog's quoted index" <<<"$out" || fail "the kickoff does not say what it left out: $out"
pass "a catalog index too large to quote is left in catalog/README.md, and SWARM.md stays under 50 KB"

# Finished twice, it has one first line, of the right size.
node --experimental-strip-types --no-warnings "$ROOT/scripts/render-contract.ts" --finish "$md" >/dev/null
[[ "$(grep -c '^This file is about' "$md")" -eq 1 ]] || fail "the first line is doubled"
[[ "$(sed -n 2p "$md")" == "" && "$(sed -n 3p "$md")" == This\ file\ is\ about* ]] || fail "the first line is not where it was: $(head -4 "$md")"
pass "finishing the contract again leaves one first line"

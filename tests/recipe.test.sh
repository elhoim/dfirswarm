#!/usr/bin/env bash
# Images from packs: which profile a run gets, what a build context holds, and
# how a pinned download is fetched. No container is built here; CI's images
# workflow builds and boots them.
#
# What must not go wrong: a run must get the smallest image that serves its
# packs, never an unbuilt `full` when a smaller one covers them; a build must
# not bake programs their packs mark not redistributable without being told
# to; an image must record which pack versions it was built from; a pinned
# download must be refused when its bytes are not the pinned ones, or when its
# archive reaches outside its directory; a pack must not declare a download
# that could not be checked.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/recipe.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
R="$ROOT/images/recipe.py"

# --- which profile ------------------------------------------------------------
[[ "$(python3 "$R" profile-for)" == base ]] || fail "no packs should be the base image"
[[ "$(python3 "$R" profile-for windows-forensics)" == disk ]] || fail "windows-forensics should be disk"
[[ "$(python3 "$R" profile-for memory-forensics)" == memory ]] || fail "memory-forensics should be memory"
got="$(python3 "$R" profile-for ransomware-response)"
[[ "$got" == re ]] || fail "ransomware-response is in no profile but re covers every program it names and every library it imports; got $got"
[[ "$(python3 "$R" profile-for no-such-pack)" == full ]] || fail "an unknown pack cannot be covered by anything smaller than full"
pass "the smallest profile that holds or covers the packs is chosen, and full only when nothing smaller serves"

# --- a build context ----------------------------------------------------------
out="$(python3 "$R" build memory --out "$TMP/ctx" 2>&1)"; rc=$?
[[ $rc -eq 3 ]] || fail "a build holding programs marked not redistributable should stop without --allow-nonredistributable (rc $rc): $out"
printf '%s\n' "$out" | grep -q 'never publish it' || fail "the refusal should say what the flag is for: $out"
[[ ! -e "$TMP/ctx/spec.json" ]] || fail "a refused build wrote its context"
python3 "$R" build memory --out "$TMP/ctx" --allow-nonredistributable >/dev/null || fail "the build with the flag failed"
for f in spec.json Dockerfile install.py NOTICE; do [[ -f "$TMP/ctx/$f" ]] || fail "the context lacks $f"; done
jq -e '.pack_versions["memory-forensics"].version and (.pack_versions["memory-forensics"].seal | length == 64)' "$TMP/ctx/spec.json" >/dev/null \
  || fail "the spec does not carry each pack's version and seal"
[[ "$(jq -r '.redistributable' "$TMP/ctx/spec.json")" == false ]] || fail "the spec does not say the image is not for redistribution"
jq -e '.downloads[] | select(.name == "memprocfs") | .amd64.sha256 and .arm64.sha256' "$TMP/ctx/spec.json" >/dev/null || fail "memprocfs is not a pinned download"
grep -q 'dev.dfirswarm.redistributable="false"' "$TMP/ctx/Dockerfile" || fail "the image's label does not say so"
grep -q 'COPY install.py spec.json NOTICE' "$TMP/ctx/Dockerfile" || fail "the NOTICE does not go into the image"
grep -q '^vol  (memory-forensics)  Volatility Software License 1.0' "$TMP/ctx/NOTICE" || fail "the NOTICE does not name vol's licence"
seal_py="$(jq -r '.pack_versions["memory-forensics"].seal' "$TMP/ctx/spec.json")"
seal_ts="$(cd "$ROOT" && node --experimental-strip-types -e 'import("./scripts/vm.ts").then(m => console.log(m.packNeeds(["packs/memory-forensics"])[0].seal))')"
[[ "$seal_py" == "$seal_ts" ]] || fail "the recipe's seal ($seal_py) and the kickoff's ($seal_ts) differ"
pass "a build context carries pack versions and seals the kickoff computes alike, a NOTICE, and says it is not for redistribution"

# --- the pinned download ------------------------------------------------------
mkdir -p "$TMP/dl/src/tool-1.0" "$TMP/tools" "$TMP/bin"
printf '#!/bin/sh\necho tool ran\n' > "$TMP/dl/src/tool-1.0/tool"
chmod +x "$TMP/dl/src/tool-1.0/tool"
tar -czf "$TMP/dl/tool.tar.gz" -C "$TMP/dl/src" tool-1.0
sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$TMP/dl/tool.tar.gz")"
# An archive that climbs out of its directory.
python3 - "$TMP/dl/evil.tar.gz" <<'EOF'
import io, sys, tarfile
with tarfile.open(sys.argv[1], "w:gz") as t:
    data = b"#!/bin/sh\necho escaped\n"
    info = tarfile.TarInfo("../../escaped")
    info.size = len(data)
    t.addfile(info, io.BytesIO(data))
EOF
evil_sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$TMP/dl/evil.tar.gz")"
res="$(DFIRSWARM_TOOLS_DIR="$TMP/tools" DFIRSWARM_BIN_DIR="$TMP/bin" python3 - "$ROOT/images" "$TMP/dl" "$sha" "$evil_sha" <<'EOF'
import json, sys
sys.path.insert(0, sys.argv[1])
import install
dl, sha, evil = sys.argv[2], sys.argv[3], sys.argv[4]
a = install.arch()
def pin(url, digest, bin_=None):
    e = {"url": url, "sha256": digest}
    if bin_:
        e["bin"] = bin_
    return {"name": "tool", "version": "1.0", a: e}
out = {}
got, why = install.fetch(pin(f"file://{dl}/tool.tar.gz", sha, "tool-1.0/tool"), [])
out["good"] = [bool(got), why]
got, why = install.fetch(pin(f"file://{dl}/tool.tar.gz", "0" * 64, "tool-1.0/tool"), [])
out["bad_sha"] = [bool(got), why]
got, why = install.fetch(pin(f"file://{dl}/evil.tar.gz", evil, "escaped"), [])
out["escape"] = [bool(got), why]
got, why = install.fetch({"name": "tool", "version": "1.0", "no-such-arch": {}}, [])
out["no_arch"] = [bool(got), why]
print(json.dumps(out))
EOF
)" || fail "install.py could not be driven: $res"
# The installer says what it fetches; the verdicts are its last line.
res="$(tail -1 <<<"$res")"
[[ "$(jq -r '.good[0]' <<<"$res")" == true ]] || fail "a download whose sha256 matches was refused: $res"
[[ "$("$TMP/bin/tool")" == "tool ran" ]] || fail "the program is not linked where PATH finds it"
[[ "$(jq -r '.bad_sha[0]' <<<"$res")" == false ]] && jq -r '.bad_sha[1]' <<<"$res" | grep -q 'is not the pinned' || fail "a download with other bytes was installed: $res"
[[ "$(jq -r '.escape[0]' <<<"$res")" == false ]] && jq -r '.escape[1]' <<<"$res" | grep -q 'leaves the download' || fail "an archive that climbs out of its directory was unpacked: $res"
[[ ! -e "$TMP/escaped" && ! -e "$(dirname "$TMP")/escaped" ]] || fail "the escaping file was written"
[[ "$(jq -r '.no_arch[0]' <<<"$res")" == false ]] && jq -r '.no_arch[1]' <<<"$res" | grep -q 'build pinned' || fail "an architecture with no pin was not recorded as such: $res"
pass "a pinned download is linked onto PATH when its sha256 matches, and refused when its bytes differ, its archive climbs out, or its architecture has no pin"

# --- what a pack may declare ---------------------------------------------------
mk() { # <dir> <download json>
  mkdir -p "$1/requires" "$1/skills/a"
  printf 'Test.\n' > "$1/LICENCE"
  printf -- '---\nid: a/one\ntitle: One\nwhen: Always.\nneeds: []\ntools: []\nrequires_host: []\n---\n\nBody.\n' > "$1/skills/a/one.md"
  printf '{"binaries": [{"name": "tool", "why": "Test.", "licence": "MIT", "redistributable": true, "optional": true, "install": {"apt": "x", "download": %s}}]}\n' "$2" > "$1/requires/host.json"
  printf '{"id": "%s", "name": "t", "version": "1.0.0", "description": "t", "licence": "MIT", "depends": [], "requires": {"host": "requires/host.json"}, "secrets": []}\n' "$(basename "$1")" > "$1/pack.json"
}
mk "$TMP/p/good-pack" '{"version": "1", "amd64": {"url": "https://example.org/t", "sha256": "'"$sha"'"}}'
bash "$ROOT/scripts/pack.sh" seal "$TMP/p/good-pack" >/dev/null 2>&1 || fail "a well-formed download was refused"
for bad in '{"amd64": {"url": "https://example.org/t", "sha256": "'"$sha"'"}}' \
           '{"version": "1", "amd64": {"url": "http://example.org/t", "sha256": "'"$sha"'"}}' \
           '{"version": "1", "amd64": {"url": "https://example.org/t", "sha256": "abc"}}' \
           '{"version": "1", "amd64": {"url": "https://example.org/t", "sha256": "'"$sha"'", "bin": "../x"}}' \
           '{"version": "1"}'; do
  mk "$TMP/p/bad-pack" "$bad"
  bash "$ROOT/scripts/pack.sh" seal "$TMP/p/bad-pack" >/dev/null 2>&1 && fail "a download entry that cannot be checked was sealed: $bad"
done
pass "a pack's download needs a version, an https url, a whole sha256 and a program path inside it"

# --- the tool library's imports are in every image ----------------------------
missing_lib="$(python3 - "$ROOT" <<'EOF'
import re, sys, pathlib
root = pathlib.Path(sys.argv[1])
# A module a tool imports -> the package that provides it.
provides = {"cryptography": "cryptography", "regipy": "regipy", "Evtx": "python-evtx", "dissect": "dissect.util"}
listed = {re.split(r"[<>=!~ ]", l.split("#")[0].strip())[0].lower() for l in (root / "images" / "library-python.txt").read_text().splitlines() if l.split("#")[0].strip()}
stdlib = set(sys.stdlib_module_names) | {"__future__"}
out = set()
for f in root.glob("tool-library/*/*.py"):
    for m in re.finditer(r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)", f.read_text(), re.M):
        mod = m.group(1)
        if mod in stdlib:
            continue
        pkg = provides.get(mod)
        if pkg is None:
            out.add(f"{mod} (in {f.parent.name}: say which package provides it)")
        elif pkg.lower() not in listed:
            out.add(f"{pkg} (imported by {f.parent.name})")
print("\n".join(sorted(out)))
EOF
)"
[[ -z "$missing_lib" ]] || fail "the tool library imports what no image installs: $missing_lib"
grep -q 'COPY library-python.txt' "$ROOT/images/base.Dockerfile" || fail "the base image does not install the tool library's imports"
pass "every third-party module the tool library imports is in images/library-python.txt, which the base image installs"

echo "recipe: all checks passed"

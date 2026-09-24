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
# that could not be checked; an installed pack the repository does not carry
# must be matched by what it names, not sent to `full`; a lock entry must be
# pinned by digest; every image, the base included, must record the package
# lists a VM's inventory is diffed against, a NOTICE and an SBOM.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/recipe.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
R="$ROOT/images/recipe.py"
# profile-for reads installed packs from here; the operator's own must not
# change what this suite sees.
export DFIRSWARM_HOME="$TMP/home"

# --- which profile ------------------------------------------------------------
[[ "$(python3 "$R" profile-for)" == base ]] || fail "no packs should be the base image"
[[ "$(python3 "$R" profile-for windows-forensics)" == disk ]] || fail "windows-forensics should be disk"
[[ "$(python3 "$R" profile-for memory-forensics)" == memory ]] || fail "memory-forensics should be memory"
got="$(python3 "$R" profile-for ransomware-response)"
[[ "$got" == re ]] || fail "ransomware-response is in no profile but re covers every program it names and every library it imports; got $got"
[[ "$(python3 "$R" profile-for no-such-pack)" == full ]] || fail "an unknown pack cannot be covered by anything smaller than full"
pass "the smallest profile that holds or covers the packs is chosen, and full only when nothing smaller serves"

# An installed pack this repository does not carry (a pro or third-party one):
# found where pack.sh installs it, or at the path given, and matched by what it
# names. This one names memory programs only, so memory covers it.
pro="$DFIRSWARM_HOME/packs/pro-memory"
mkdir -p "$pro/requires"
printf '{"id": "pro-memory", "name": "p", "version": "1.0.0", "description": "p", "licence": "MIT", "depends": ["computer-forensics-base>=1.2.0"]}\n' > "$pro/pack.json"
printf '{"binaries": [{"name": "vol", "why": "t", "licence": "t", "redistributable": false}, {"name": "memprocfs", "optional": true, "why": "t", "licence": "t", "redistributable": false}]}\n' > "$pro/requires/host.json"
got="$(python3 "$R" profile-for pro-memory)"
[[ "$got" == memory ]] || fail "an installed pack naming only memory programs should get memory, got $got"
got="$(DFIRSWARM_HOME="$TMP/elsewhere" python3 "$R" profile-for "$pro")"
[[ "$got" == memory ]] || fail "a pack given as a directory should be read there, got $got"
got="$(DFIRSWARM_HOME="$TMP/elsewhere" python3 "$R" profile-for --installed "$DFIRSWARM_HOME/packs" pro-memory)"
[[ "$got" == memory ]] || fail "--installed should name where the packs are, got $got"
[[ "$(DFIRSWARM_HOME="$TMP/elsewhere" python3 "$R" profile-for pro-memory)" == full ]] || fail "a pack found nowhere should still be full"
# One that imports a library no profile installs is covered by none.
printf 'somelib>=1\n' > "$pro/requires/python.txt"
[[ "$(python3 "$R" profile-for pro-memory)" == full ]] || fail "an installed pack importing what no profile installs should be full"
rm "$pro/requires/python.txt"
pass "an installed pack the repository does not carry is found where it is installed and matched by what it names"

# Library tools say which programs they call (manifest `requires`): a profile
# smaller than full that has them all is preferred, and one that lacks some
# never pushes a run to full.
got="$(python3 "$R" profile-for --tools-from "$ROOT/tool-library")"
[[ "$got" == disk ]] || fail "the tool library calls TSK, esedbexport, yara and vol, which disk has; got $got"
got="$(python3 "$R" profile-for --tools-from "$ROOT/tool-library" memory-forensics)"
[[ "$got" == memory ]] || fail "the packs decide when no smaller image serves both; got $got"
mkdir -p "$TMP/tl/only_sql" "$TMP/tl2/odd_one"
printf '{"name": "only_sql", "requires": ["sqlite3"]}\n' > "$TMP/tl/only_sql/manifest.json"
printf '{"name": "odd_one", "requires": ["no-such-program"]}\n' > "$TMP/tl2/odd_one/manifest.json"
[[ "$(python3 "$R" profile-for --tools-from "$TMP/tl")" == base ]] || fail "a program the base image has needs no profile"
[[ "$(python3 "$R" profile-for --tools-from "$TMP/tl2")" == base ]] || fail "a program no image has must not push a run to full"
missing_req="$(python3 - "$ROOT" <<'EOF'
import json, re, sys, pathlib
# A library tool that runs one of these must say so in its manifest. (No
# quote characters in this heredoc: bash 3.2 miscounts them inside $(...).)
progs = "fls|icat|img_stat|img_cat|mmls|istat|esedbexport|yara|vol|ewfexport"
# Python: an argv element or a which(); a shell script: a command at the start of a line or after a pipe.
py_call = re.compile(r"[\x22\x27](" + progs + r")[\x22\x27]\s*[,\])]")
sh_call = re.compile(r"(?:^|\|)\s*(" + progs + r")\s", re.M)
out = []
for mf in sorted(pathlib.Path(sys.argv[1]).glob("tool-library/*/manifest.json")):
    m = json.loads(mf.read_text())
    body = (mf.parent / m["entry"]).read_text()
    used = set((sh_call if m["entry"].endswith(".sh") else py_call).findall(body))
    lacking = used - set(m.get("requires") or [])
    if lacking:
        out.append(f"{mf.parent.name}: {', '.join(sorted(lacking))}")
print("\n".join(out))
EOF
)"
[[ -z "$missing_req" ]] || fail "a library tool runs a program its manifest does not name in requires: $missing_req"
pass "library tools name the programs they call, and those pick an image only when one smaller than full has them"

# --- the images lock ------------------------------------------------------------
digest="$(printf '%064d' 0 | tr 0 a)"
upper="$(tr a-f A-F <<<"$digest")"
printf '{"images": {"disk": {"amd64": "ghcr.io/o/dfirswarm-disk:1.2@sha256:%s", "arm64": "ghcr.io/o/dfirswarm-disk@sha256:%s"}}}\n' "$digest" "$digest" > "$TMP/lock-good.json"
python3 "$R" check-lock "$TMP/lock-good.json" >/dev/null || fail "a lock pinned by digest was refused"
for bad in '{"images": {"disk": {"amd64": "ghcr.io/o/dfirswarm-disk:1.2"}}}' \
           '{"images": {"disk": {"amd64": "ghcr.io/o/dfirswarm-disk@sha256:abc"}}}' \
           '{"images": {"disk": {"amd64": "ghcr.io/o/dfirswarm-disk@sha256:'"$upper"'"}}}' \
           '{"images": {"disk": "ghcr.io/o/dfirswarm-disk@sha256:'"$digest"'"}}' \
           '{"images": {}}' \
           '{"disk": {"amd64": "ghcr.io/o/dfirswarm-disk@sha256:'"$digest"'"}}' \
           'not json'; do
  printf '%s\n' "$bad" > "$TMP/lock-bad.json"
  out="$(python3 "$R" check-lock "$TMP/lock-bad.json" 2>&1)" && fail "a lock entry not pinned by digest was accepted: $bad"
  grep -q 'refused' <<<"$out" || fail "the refusal should say what it refused: $out"
done
printf '{"images": {"no-such-profile": {"amd64": "r@sha256:%s"}}}\n' "$digest" > "$TMP/lock-odd.json"
out="$(python3 "$R" check-lock "$TMP/lock-odd.json" 2>&1)" || fail "an unknown profile is a warning, not a refusal: $out"
grep -q 'no such profile' <<<"$out" || fail "an unknown profile should be named: $out"
pass "a lock entry must name its image by digest; a tag, a short or upper-case digest, or a malformed lock is refused"

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
python3 "$R" build web --out "$TMP/ctx-web" >/dev/null || fail "web holds no pack program and should build without the flag"
grep -q 'dev.dfirswarm.redistributable' "$TMP/ctx-web/Dockerfile" && fail "a profile with nothing held back must inherit the base's label, not claim its own"
grep -q 'dev.dfirswarm.redistributable="${REDISTRIBUTABLE}"' "$ROOT/images/base.Dockerfile" || fail "the base image does not carry the redistributable label"
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

# --- what an image records ------------------------------------------------------
# The base records what a profile does: the venv as `pip list` names it (a VM's
# inventory at stop is diffed against it, so the base's own packages are not
# "installed outside the image"), the whole Debian list, a NOTICE with the npm
# and Python licences, an SBOM, and whether it may be redistributed. A profile
# built on it keeps the base's flag. A fake venv and npm stand in here.
mkdir -p "$TMP/rec/venv/bin" "$TMP/rec/fakebin" "$TMP/rec/npm/@earendil-works/pi-coding-agent/node_modules/left-pad" "$TMP/rec/npm/@earendil-works/pi-coding-agent/dist"
printf '#!/bin/sh\necho %s\n' "'[{\"name\": \"dissect.util\", \"version\": \"3.20\"}, {\"name\": \"pip\", \"version\": \"23.0.1\"}]'" > "$TMP/rec/venv/bin/pip"
printf '#!/bin/sh\necho %s\n' "'[[\"dissect.util\", \"3.20\", \"AGPL-3.0\"], [\"pip\", \"23.0.1\", \"MIT\"]]'" > "$TMP/rec/venv/bin/python"
printf '#!/bin/sh\necho %s\n' "$TMP/rec/npm" > "$TMP/rec/fakebin/npm"
chmod +x "$TMP/rec/venv/bin/pip" "$TMP/rec/venv/bin/python" "$TMP/rec/fakebin/npm"
printf '{"name": "@earendil-works/pi-coding-agent", "version": "0.87.0", "license": "MIT"}\n' > "$TMP/rec/npm/@earendil-works/pi-coding-agent/package.json"
printf '{"name": "left-pad", "version": "1.3.0", "license": "WTFPL"}\n' > "$TMP/rec/npm/@earendil-works/pi-coding-agent/node_modules/left-pad/package.json"
printf '{"type": "module"}\n' > "$TMP/rec/npm/@earendil-works/pi-coding-agent/dist/package.json"
( export PATH="$TMP/rec/fakebin:$PATH" DFIRSWARM_VENV="$TMP/rec/venv" DFIRSWARM_ETC_DIR="$TMP/rec/etc" \
         NONREDISTRIBUTABLE="dissect.util" REDISTRIBUTABLE=false
  python3 "$ROOT/images/install.py" --base >/dev/null ) || fail "install.py --base failed"
rec="$TMP/rec/etc/image.json"
jq -e '.profile == "base" and (.dpkg_all | type == "object") and .pip == {"dissect.util": "3.20", "pip": "23.0.1"}' "$rec" >/dev/null \
  || fail "the base does not record its whole Debian list and its venv as pip lists it: $(cat "$rec")"
jq -e '.redistributable == false and .nonredistributable == ["dissect.util"] and .pi == "0.87.0"' "$rec" >/dev/null \
  || fail "the base does not say it is not for redistribution, or which Pi it holds: $(cat "$rec")"
grep -q '^Not cleared for redistribution: dissect.util' "$TMP/rec/etc/NOTICE" || fail "the base NOTICE does not say what holds it back"
grep -q '^dissect.util 3.20  AGPL-3.0' "$TMP/rec/etc/NOTICE" || fail "the base NOTICE does not give the Python licences"
grep -q '^left-pad 1.3.0  WTFPL' "$TMP/rec/etc/NOTICE" || fail "the base NOTICE does not give the npm licences, nested ones included"
jq -e '.bomFormat == "CycloneDX" and .specVersion == "1.5"
       and ([.components[].purl] | index("pkg:pypi/dissect-util@3.20") != null)
       and ([.components[].purl] | index("pkg:npm/%40earendil-works/pi-coding-agent@0.87.0") != null)
       and ([.components[] | select(.name == "module")] | length == 0)' "$TMP/rec/etc/sbom.json" >/dev/null \
  || fail "the base SBOM is not CycloneDX with the venv's and npm's packages: $(head -c 600 "$TMP/rec/etc/sbom.json")"
( export PATH="$TMP/rec/fakebin:$PATH" DFIRSWARM_VENV="$TMP/rec/venv" DFIRSWARM_ETC_DIR="$TMP/rec/etc"
  python3 - "$ROOT/images" "$sha" <<'EOF'
import json, sys
sys.path.insert(0, sys.argv[1])
import install
spec = {"profile": "web", "packs": [], "redistributable": True, "nonredistributable": [], "apt": {},
        "binaries": [], "manual": []}
record = install.profile_record(json.loads(install.RECORD.read_text()), spec,
                                {"tool": {"version": "1.0", "url": "https://example.org/tool.tar.gz", "sha256": sys.argv[2]}},
                                {"apt": [], "pip": [], "download": []})
install.write_record(record, "dfirswarm-web")
EOF
) || fail "a profile record could not be written over the base's"
jq -e '.profile == "web" and .redistributable == false and .nonredistributable == ["dissect.util"] and .pip["dissect.util"] == "3.20"' "$rec" >/dev/null \
  || fail "a profile over a base not for redistribution claimed it was, or lost the venv: $(cat "$rec")"
jq -e --arg sha "$sha" '[.components[] | select(.name == "tool") | .hashes[0].content == $sha and (.purl | startswith("pkg:generic/tool@1.0?"))] == [true]' \
  "$TMP/rec/etc/sbom.json" >/dev/null || fail "a pinned download is not in the SBOM with its sha256"
pass "every image records its Debian list and venv for the inventory diff, a NOTICE, a CycloneDX SBOM, and the base's redistribution flag carries into a profile"

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

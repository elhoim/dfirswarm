#!/usr/bin/env bash
# The run's copy of the evidence and its manifest (swarm.sh install_inputs,
# write_inputs_manifest), taken from the script itself. No model, no Herdr.
#
# - a link inside the evidence is copied as the link it is, never followed on
#   this host; only a link at the top of --inputs (the operator's) is;
# - a copy that lost a name or a byte against its source is refused, and by
#   default each copied file's source is hashed again (--no-verify-copy:
#   names, kinds and sizes only);
# - every file carries SHA-256, SHA-1 and MD5 from one read;
# - a name that is not UTF-8 is kept exactly (Linux; APFS refuses such names);
# - several sets land each at inputs/<name>/, each checked against its own
#   source, copied or held in place, and the manifest says which is which.
set -euo pipefail
unset SWARM_ISOLATION SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/inputs-copy.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

fn() { sed -n "/^$1() {/,/^}/p" "$ROOT/scripts/swarm.sh"; }
eval "$(fn copy_tree_as_is)"
eval "$(fn copy_evidence_set)"
eval "$(fn install_inputs)"
eval "$(fn write_inputs_manifest)"
type install_inputs >/dev/null 2>&1 || fail "install_inputs was not found in swarm.sh"

echo "# links in the evidence are the evidence's own"
mkdir -p "$TMP/src/etc" "$TMP/host" "$TMP/case"
printf 'operator-only\n' > "$TMP/host/hosts"
printf 'case image\n' > "$TMP/case/disk.E01"
mkdir -p "$TMP/case/dir"
printf 'inside a linked dir\n' > "$TMP/case/dir/a.txt"
ln -s "$TMP/host/hosts" "$TMP/case/dir/escape"
printf 'evidence\n' > "$TMP/src/etc/motd"
# An extracted root's absolute link, and a relative one that climbs out.
ln -s "$TMP/host/hosts" "$TMP/src/etc/hosts"
ln -s ../../host/hosts "$TMP/src/etc/climb"
ln -s motd "$TMP/src/etc/inside"
# The operator's links, at the top of --inputs.
ln -s "$TMP/case/disk.E01" "$TMP/src/disk.E01"
ln -s "$TMP/case/dir" "$TMP/src/linked-dir"
SB="$TMP/sb"
mkdir -p "$SB"
out="$(install_inputs "$SB" "$TMP/src" auto none 2>&1)" || fail "the copy failed: $out"
[[ -L "$SB/inputs/etc/hosts" ]] || fail "a link inside the evidence was followed: etc/hosts is $(ls -l "$SB/inputs/etc/hosts")"
[[ "$(readlink "$SB/inputs/etc/hosts")" == "$TMP/host/hosts" ]] || fail "the link's target changed"
[[ -L "$SB/inputs/etc/climb" && -L "$SB/inputs/etc/inside" ]] || fail "a relative link was followed"
! grep -rqs --exclude-dir=etc 'operator-only' "$SB/inputs" "$SB/.inputs-pristine" || fail "a host file's bytes are in the copy"
[[ -f "$SB/inputs/disk.E01" && ! -L "$SB/inputs/disk.E01" ]] || fail "the operator's top-level link to a file was not followed"
[[ "$(cat "$SB/inputs/disk.E01")" == "case image" ]] || fail "the top-level link's file was not copied"
[[ -d "$SB/inputs/linked-dir" && ! -L "$SB/inputs/linked-dir" && -f "$SB/inputs/linked-dir/a.txt" ]] || fail "the operator's top-level link to a directory was not followed"
[[ -L "$SB/inputs/linked-dir/escape" ]] || fail "a link inside a linked directory was followed"
jq -e '[.files[] | select(.path == "inputs/etc/hosts")][0].link' "$SB/inputs.json" >/dev/null || fail "the manifest does not record etc/hosts as a link"
grep -q 'lead out of it' <<<"$out" || fail "the links that lead out were not said: $out"
grep -q 'etc/hosts' <<<"$out" || fail "the NOTE does not name etc/hosts: $out"
grep -q 'etc/inside' <<<"$out" && fail "a link that stays inside was said to lead out: $out"
[[ "$(jq -c '.source_checked | {by, files, mismatches}' "$SB/inputs.json")" == '{"by":"content","files":3,"mismatches":0}' ]] || fail "the copy was not checked against its source by content: $(jq -c .source_checked "$SB/inputs.json")"
pass "links inside the evidence stay links (said when they lead out), the operator's top-level links are followed, and the copy is checked against the source"

echo "# three digests from one read"
want_md5="$(python3 -c 'import hashlib,sys; print(hashlib.md5(open(sys.argv[1],"rb").read()).hexdigest())' "$TMP/src/etc/motd")"
want_sha1="$(python3 -c 'import hashlib,sys; print(hashlib.sha1(open(sys.argv[1],"rb").read()).hexdigest())' "$TMP/src/etc/motd")"
[[ "$(jq -r '.files[] | select(.path == "inputs/etc/motd") | .md5' "$SB/inputs.json")" == "$want_md5" ]] || fail "the manifest's MD5 is not the file's"
[[ "$(jq -r '.files[] | select(.path == "inputs/etc/motd") | .sha1' "$SB/inputs.json")" == "$want_sha1" ]] || fail "the manifest's SHA-1 is not the file's"
[[ "$(jq -c '.digests' "$SB/inputs.json")" == '["sha256","sha1","md5"]' ]] || fail "the manifest does not say which digests it holds"
pass "each file carries SHA-256, SHA-1 and MD5"

echo "# a copy that lost a name or a byte is refused"
SB2="$TMP/sb2"
mkdir -p "$SB2/inputs" "$TMP/src2"
printf 'one\n' > "$TMP/src2/a.txt"
printf 'two\n' > "$TMP/src2/B.txt"
printf 'three\n' > "$TMP/src2/c.txt"
cp "$TMP/src2/a.txt" "$SB2/inputs/a.txt"
printf 'thr' > "$SB2/inputs/c.txt"
set +e
out="$(write_inputs_manifest "$SB2" "$TMP/src2" auto none copy 2>&1)"
rc=$?
set -e
[[ $rc -eq 4 ]] || fail "a copy missing a name exited $rc, wanted 4: $out"
grep -q 'not in the copy: B.txt' <<<"$out" || fail "the missing name is not said: $out"
grep -q 'differs from its source.*c.txt' <<<"$out" || fail "the short file is not said: $out"
[[ "$(jq -r '.source_checked' "$SB2/inputs.json")" == "MISMATCH" ]] || fail "the manifest does not record the mismatch"
pass "a copy with a name merged away or a short file is refused, naming each"

echo "# the copy against its source by content"
SB4="$TMP/sb4"
mkdir -p "$SB4/inputs" "$TMP/src4"
printf 'same size A\n' > "$TMP/src4/a.txt"
printf 'untouched\n' > "$TMP/src4/b.txt"
# Same name, same size, other bytes: only a content check sees it.
printf 'same size B\n' > "$SB4/inputs/a.txt"
cp "$TMP/src4/b.txt" "$SB4/inputs/b.txt"
set +e
out="$(write_inputs_manifest "$SB4" "$TMP/src4" auto none copy 1 2>&1)"
rc=$?
set -e
[[ $rc -eq 4 ]] || fail "a copy that differs from its source by content exited $rc, wanted 4: $out"
grep -q 'differs from its source by content: inputs/a.txt' <<<"$out" || fail "the file that differs is not named: $out"
grep -q 'b.txt' <<<"$out" && fail "an unchanged file was named: $out"
[[ "$(jq -c '.source_checked | {by, files, mismatches}' "$SB4/inputs.json")" == '{"by":"content","files":2,"mismatches":1}' ]] || fail "the manifest does not record the content check: $(jq -c .source_checked "$SB4/inputs.json")"
# --no-verify-copy: names, kinds and sizes, and the difference goes unseen.
rm -f "$SB4/inputs.json"
out="$(write_inputs_manifest "$SB4" "$TMP/src4" auto none copy 0 2>&1)" || fail "without the content check the copy was refused: $out"
[[ "$(jq -r '.source_checked' "$SB4/inputs.json")" == "names, kinds and sizes" ]] || fail "--no-verify-copy does not say what it checked"
# And through install_inputs, whose default is the content check.
SB5="$TMP/sb5"
mkdir -p "$SB5"
out="$(install_inputs "$SB5" "$TMP/src4" auto none 0 2>&1)" || fail "install_inputs with the check off failed: $out"
[[ "$(jq -r '.source_checked' "$SB5/inputs.json")" == "names, kinds and sizes" ]] || fail "install_inputs did not pass --no-verify-copy on"
pass "each copied file is hashed again from its source and compared; --no-verify-copy checks names, kinds and sizes only"

echo "# a name that is not UTF-8 is kept exactly"
if [[ "$(uname -s)" == "Darwin" ]]; then
  echo "ok - skipped: APFS refuses file names that are not UTF-8"
else
  SB3="$TMP/sb3"
  mkdir -p "$SB3/inputs"
  python3 - "$SB3/inputs" <<'PY'
import os, sys
d = os.fsencode(sys.argv[1])
open(os.path.join(d, b"caf\xe9.txt"), "wb").write(b"latin-1 name\n")
os.symlink(b"caf\xe9.txt", os.path.join(d, b"link-to-caf\xe9"))
PY
  out="$(write_inputs_manifest "$SB3" "$SB3/inputs" auto none bind 2>&1)" || fail "the manifest writer failed on a name that is not UTF-8: $out"
  want="$(python3 -c 'import base64; print(base64.b64encode(b"inputs/caf\xe9.txt").decode())')"
  [[ "$(jq -r --arg w "$want" '[.files[] | select(.path_b64 == $w)] | length' "$SB3/inputs.json")" == "1" ]] || fail "the raw name is not kept as path_b64: $(jq -c '.files' "$SB3/inputs.json")"
  want_link="$(python3 -c 'import base64; print(base64.b64encode(b"caf\xe9.txt").decode())')"
  [[ "$(jq -r --arg w "$want_link" '[.files[] | select(.link_b64 == $w)] | length' "$SB3/inputs.json")" == "1" ]] || fail "the raw link target is not kept as link_b64"
  python3 -c 'import json,sys; json.loads(open(sys.argv[1], encoding="utf-8").read())' "$SB3/inputs.json" || fail "the manifest is not valid UTF-8 JSON"
  pass "a name and a link target that are not UTF-8 are kept as base64 beside a readable name"
fi

echo "# several sets, each at inputs/<name>/"
mkdir -p "$TMP/alpha/sub" "$TMP/beta"
printf 'alpha one\n' > "$TMP/alpha/one.txt"
printf 'alpha two\n' > "$TMP/alpha/sub/two.txt"
ln -s "$TMP/host/hosts" "$TMP/alpha/sub/hosts"
printf 'beta\n' > "$TMP/beta/three.txt"
# The operator's top-level link, in the second set: followed, as in one.
ln -s "$TMP/case/disk.E01" "$TMP/beta/disk.E01"
SB6="$TMP/sb6"
mkdir -p "$SB6"
out="$(install_inputs "$SB6" "" auto none 1 0 alpha "$TMP/alpha" beta "$TMP/beta" 2>&1)" || fail "the copy of two sets failed: $out"
[[ -f "$SB6/inputs/alpha/one.txt" && -f "$SB6/inputs/alpha/sub/two.txt" && -f "$SB6/inputs/beta/three.txt" ]] || fail "a set is not at inputs/<name>/: $(find "$SB6/inputs" | sort)"
[[ -L "$SB6/inputs/alpha/sub/hosts" ]] || fail "a link inside a set was followed"
[[ -f "$SB6/inputs/beta/disk.E01" && ! -L "$SB6/inputs/beta/disk.E01" ]] || fail "the operator's top-level link in the second set was not followed"
[[ -f "$SB6/.inputs-pristine/alpha/one.txt" && -f "$SB6/.inputs-pristine/beta/three.txt" ]] || fail "the pristine clone does not mirror the sets"
[[ ! -e "$SB6/inputs/one.txt" ]] || fail "a set's file landed at the top of inputs/"
python3 -c 'import os, sys; sys.exit(0 if os.stat(sys.argv[1]).st_mode & 0o222 else 1)' "$SB6/inputs/beta/three.txt" && fail "a set kept a write bit"
[[ "$(jq -r '[.files[].path] | sort | join(",")' "$SB6/inputs.json")" == "inputs/alpha/one.txt,inputs/alpha/sub/hosts,inputs/alpha/sub/two.txt,inputs/beta/disk.E01,inputs/beta/three.txt" ]] || fail "the manifest does not list every set's names under inputs/<name>/: $(jq -c '[.files[].path]' "$SB6/inputs.json")"
[[ "$(jq -c '[.sets[] | {name, path, source, files}]' "$SB6/inputs.json")" == "$(jq -nc --arg a "$TMP/alpha" --arg b "$TMP/beta" '[{name: "alpha", path: "inputs/alpha", source: $a, files: 3}, {name: "beta", path: "inputs/beta", source: $b, files: 2}]')" ]] || fail "the manifest's sets are not the two, in order: $(jq -c .sets "$SB6/inputs.json")"
[[ "$(jq -r '[.sets[].bytes] | add == (input | .bytes)' "$SB6/inputs.json" "$SB6/inputs.json")" == "true" ]] || fail "the sets' bytes do not add up to the manifest's"
[[ "$(jq -r '.source' "$SB6/inputs.json")" == "$TMP/alpha, $TMP/beta" ]] || fail "the manifest's source does not name both sets: $(jq -r .source "$SB6/inputs.json")"
[[ "$(jq -c '.source_checked | {by, files, mismatches}' "$SB6/inputs.json")" == '{"by":"content","files":4,"mismatches":0}' ]] || fail "each set was not checked against its source by content: $(jq -c .source_checked "$SB6/inputs.json")"
grep -q 'alpha/sub/hosts' <<<"$out" || fail "the NOTE does not name the link that leads out under its set: $out"
pass "two sets are copied each to inputs/<name>/, cloned, locked, and listed with their sources"

# One set writes the manifest it always did: no `sets`, paths under inputs/.
[[ "$(jq 'has("sets")' "$SB/inputs.json")" == "false" ]] || fail "a one-set manifest grew a sets key"
[[ "$(jq -r 'keys_unsorted | join(",")' "$SB5/inputs.json")" == "source,copied_at,files,bytes,enforce,guard,digests,quarantine,source_checked,held" ]] || fail "a one-set manifest changed shape: $(jq -r 'keys_unsorted | join(",")' "$SB5/inputs.json")"
pass "one set's manifest keeps its shape"

# A set whose copy differs from its source is named under its set.
SB7="$TMP/sb7"
mkdir -p "$SB7/inputs/alpha" "$SB7/inputs/beta"
cp -R "$TMP/alpha/." "$SB7/inputs/alpha/"
printf 'beta, but other\n' > "$SB7/inputs/beta/three.txt"
set +e
out="$(write_inputs_manifest "$SB7" "" auto none copy 1 0 alpha "$TMP/alpha" beta "$TMP/beta" 2>&1)"
rc=$?
set -e
[[ $rc -eq 4 ]] || fail "a set whose copy differs from its source exited $rc, wanted 4: $out"
grep -q 'not in the copy: beta/disk.E01' <<<"$out" || fail "the name missing from the second set is not said under it: $out"
grep -q 'differs from its source.*beta/three.txt' <<<"$out" || fail "the other file is not said under its set: $out"
grep -q 'alpha/' <<<"$(grep -v 'BLOCKER' <<<"$out" | grep -v 'A case-insensitive')" && fail "an intact set was named: $out"
pass "each set's copy is checked against its own source, and a difference is named under its set"

# Held in place: inputs/ is the run's own directory with a link per set.
SB8="$TMP/sb8"
mkdir -p "$SB8/inputs"
ln -s "$TMP/alpha" "$SB8/inputs/alpha"
ln -s "$TMP/beta" "$SB8/inputs/beta"
out="$(write_inputs_manifest "$SB8" "" auto seatbelt bind 0 0 alpha "$TMP/alpha" beta "$TMP/beta" 2>&1)" || fail "the manifest of two sets held in place failed: $out"
[[ "$(jq -r '[.files[].path] | sort | join(",")' "$SB8/inputs.json")" == "inputs/alpha/one.txt,inputs/alpha/sub/hosts,inputs/alpha/sub/two.txt,inputs/beta/disk.E01,inputs/beta/three.txt" ]] || fail "the sets held in place are not walked through their links: $(jq -c '[.files[].path]' "$SB8/inputs.json")"
[[ "$(jq -r '.files[] | select(.path == "inputs/beta/disk.E01") | .link' "$SB8/inputs.json")" == "$TMP/case/disk.E01" ]] || fail "a link inside a set held in place is not recorded as a link"
[[ "$(jq -r '.files[] | select(.path == "inputs/alpha/one.txt") | .mode' "$SB8/inputs.json")" =~ ^[0-7]{3}$ ]] || fail "a set held in place does not record how its files are held"
[[ "$(jq -r '[.held, (.sets | length)] | join(" ")' "$SB8/inputs.json")" == "bind 2" ]] || fail "the manifest does not say bind with two sets"
pass "two sets held in place are walked through their links, and each file's mode is recorded"

echo "inputs-copy.test.sh: all checks passed"

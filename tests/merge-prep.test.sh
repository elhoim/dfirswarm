#!/usr/bin/env bash
# scripts/merge-prep.sh: a branch that has fallen behind main is brought up
# to date by running it, not by hand. In a scratch repository with one pack
# and stand-ins for the goldens and the rule register, two branches change
# the same pack and the same generated files; the merge conflicts, and
# merge-prep resolves the generated ones, seals the pack again, raises a
# version two contents would share, writes the goldens and the register from
# the merged sources, and stops on a conflict a person has to resolve.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
export DFIRSWARM_HOME="$WORK/home" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
R="$WORK/repo"
mkdir -p "$R/scripts" "$R/tests" "$R/docs" "$R/changelog.d" "$R/packs/demo/skills/alpha"
cp "$ROOT/scripts/merge-prep.sh" "$ROOT/scripts/pack.sh" "$ROOT/scripts/changelog.ts" "$R/scripts/"
# Stand-ins: the goldens and the register are written from two one-line source
# files, so a change to each on a different branch merges cleanly in the
# sources and conflicts in what was generated from them.
cat > "$R/tests/kickoff-goldens.test.sh" <<'SH'
set -e
cd "$(dirname "$0")/.."
[ "${GOLDENS:-}" = update ] || exit 1
mkdir -p tests/fixtures/kickoff/hello
cat src/a.txt src/b.txt > tests/fixtures/kickoff/hello/SWARM.md
SH
cat > "$R/scripts/rules.ts" <<'TS'
import { readFileSync, writeFileSync } from "node:fs";
if (process.argv.includes("--write")) writeFileSync("docs/rules.md", readFileSync("src/a.txt", "utf8") + readFileSync("src/b.txt", "utf8"));
TS
mkdir -p "$R/src"
printf 'a\n' > "$R/src/a.txt"; printf 'b\n' > "$R/src/b.txt"
printf 'Test pack.\n' > "$R/packs/demo/LICENCE"
skill() { # <file> <title>
  printf -- '---\nid: alpha/%s\ntitle: %s\nwhen: Whenever the suite asks.\nneeds: []\ntools: []\nrequires_host: []\n---\n\nA body.\n' "$(basename "$1" .md)" "$2" > "$1"
}
skill "$R/packs/demo/skills/alpha/one.md" "One"
skill "$R/packs/demo/skills/alpha/two.md" "Two"
printf '{\n  "id": "demo",\n  "name": "demo",\n  "version": "1.0.0",\n  "description": "A pack for the suite.",\n  "licence": "AGPL-3.0-or-later"\n}\n' > "$R/packs/demo/pack.json"
g() { git -C "$R" -c user.name=t -c user.email=t@example.invalid "$@"; }
mp() { (cd "$R" && bash scripts/merge-prep.sh --base main "$@"); }
seal() { bash "$R/scripts/pack.sh" seal "$R/packs/demo" >/dev/null || fail "the suite's pack does not seal"; }
regen() { (cd "$R" && GOLDENS=update bash tests/kickoff-goldens.test.sh && node --experimental-strip-types --no-warnings scripts/rules.ts --write); }
seal; regen
g init -q -b main && g add -A && g commit -qm base || fail "could not make the scratch repository"

# --- a branch already up to date: nothing is written ----------------------------
g checkout -qb feature
out="$(mp 2>&1)" || fail "merge-prep failed on a branch level with main: $out"
[[ -z "$(g status --porcelain)" ]] || fail "merge-prep wrote something on a branch level with main: $(g status --porcelain)"
pass "on a branch level with main it writes nothing"

# --- both sides change the pack and the generated files ------------------------
set_version() { python3 -c 'import json,sys; p=sys.argv[1]; m=json.load(open(p)); m["version"]=sys.argv[2]; open(p,"w").write(json.dumps(m, indent=2, ensure_ascii=False)+"\n")' "$R/packs/demo/pack.json" "$1"; }
printf 'A body the feature changed.\n' >> "$R/packs/demo/skills/alpha/one.md"
printf 'b (feature)\n' > "$R/src/b.txt"
set_version 1.1.0; seal; regen
g commit -qam "feature" || fail "commit on feature"
g checkout -q main
printf 'A body main changed.\n' >> "$R/packs/demo/skills/alpha/two.md"
printf 'a (main)\n' > "$R/src/a.txt"
set_version 1.1.0; seal; regen
g commit -qam "main" || fail "commit on main"
g checkout -q feature
g merge -q main >/dev/null 2>&1 && fail "the scratch merge was meant to conflict"
conflicted="$(g diff --name-only --diff-filter=U | sort | tr '\n' ' ')"
[[ "$conflicted" == "docs/rules.md packs/demo/pack.json tests/fixtures/kickoff/hello/SWARM.md " ]] \
  || fail "the scratch merge conflicted on something else than meant: $conflicted"

out="$(mp 2>&1)" || fail "merge-prep did not resolve generated conflicts: $out"
[[ -z "$(g diff --name-only --diff-filter=U)" ]] || fail "conflicts are left after merge-prep: $(g diff --name-only --diff-filter=U)"
grep -q '<<<<<<<\|>>>>>>>' "$R/packs/demo/pack.json" "$R/docs/rules.md" "$R/tests/fixtures/kickoff/hello/SWARM.md" && fail "a conflict marker is left"
cp -R "$R/packs/demo" "$WORK/demo-copy"
bash "$R/scripts/pack.sh" seal "$WORK/demo-copy" >/dev/null && diff -r "$R/packs/demo" "$WORK/demo-copy" >/dev/null \
  || fail "the merged pack is not sealed over its merged files"
[[ "$(jq -r .version "$R/packs/demo/pack.json")" == 1.1.1 ]] \
  || fail "both sides released 1.1.0 with different contents; the merge should carry 1.1.1, not $(jq -r .version "$R/packs/demo/pack.json")"
grep -q 'main changed' "$R/packs/demo/skills/alpha/two.md" && grep -q 'feature changed' "$R/packs/demo/skills/alpha/one.md" \
  || fail "the pack's merged files lost a side"
want="$(cat "$R/src/a.txt" "$R/src/b.txt")"
[[ "$(cat "$R/tests/fixtures/kickoff/hello/SWARM.md")" == "$want" ]] || fail "the goldens were not written from the merged sources"
[[ "$(cat "$R/docs/rules.md")" == "$want" ]] || fail "the rule register was not written from the merged sources"
grep -q 'version 1.1.0 -> 1.1.1' <<<"$out" || fail "merge-prep did not say it raised the version: $out"
pass "pack.json, the goldens and the register conflicted; merge-prep resolved them, sealed the pack and raised its version"

g add -A && g commit -qm "merge main" || fail "could not commit the merge"
out="$(mp 2>&1)" || fail "merge-prep failed on its second run: $out"
[[ -z "$(g status --porcelain)" ]] || fail "a second run wrote something: $(g status --porcelain)"
pass "a second run writes nothing"

# --- a conflict a person has to resolve ----------------------------------------
desc() { python3 -c 'import json,sys; p=sys.argv[1]; m=json.load(open(p)); m["description"]=sys.argv[2]; open(p,"w").write(json.dumps(m, indent=2, ensure_ascii=False)+"\n")' "$R/packs/demo/pack.json" "$1"; }
g checkout -qb feature2
desc "The feature's words."; g commit -qam "feature2 description"
g checkout -q main
desc "Main's words."; g commit -qam "main description"
g checkout -q feature2
g merge -q main >/dev/null 2>&1 && fail "the description merge was meant to conflict"
out="$(mp 2>&1)" && fail "merge-prep accepted two descriptions: $out"
grep -q 'both sides changed description differently' <<<"$out" || fail "merge-prep did not name the key: $out"
[[ -n "$(g diff --name-only --diff-filter=U -- packs/demo/pack.json)" ]] || fail "merge-prep marked a conflict it could not resolve as resolved"
pass "a hand-written key both sides changed stops it, named"
g merge --abort

printf 'x\n' > "$R/src/c.txt"; g add -A; g commit -qm "c on feature2"
g checkout -q main; printf 'y\n' > "$R/src/c.txt"; g add -A; g commit -qm "c on main"
g checkout -q feature2
g merge -q main >/dev/null 2>&1 && fail "the source merge was meant to conflict"
before="$(g status --porcelain)"
out="$(mp 2>&1)" && fail "merge-prep ran over a conflict in a source file: $out"
grep -q 'src/c.txt' <<<"$out" || fail "merge-prep did not name the source conflict: $out"
[[ "$(g status --porcelain)" == "$before" ]] || fail "merge-prep wrote something before stopping on a source conflict"
pass "a conflict in a source file stops it before it writes anything"
g merge --abort

# --- the changelog -------------------------------------------------------------
g checkout -q feature
printf 'Not a section.\n' > "$R/changelog.d/feature.md"
out="$(mp 2>&1)" && fail "merge-prep accepted a malformed changelog fragment: $out"
grep -q 'changelog.d/feature.md' <<<"$out" || fail "merge-prep did not name the malformed fragment: $out"
pass "a malformed changelog fragment stops it"

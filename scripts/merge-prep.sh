#!/usr/bin/env bash
# Bring a branch up to date with main: the one step whoever merges runs, so a
# branch that has fallen behind is fixed by running it again, not by hand.
#
#   git fetch origin && git merge origin/main     (a rebase works the same way)
#   bash scripts/merge-prep.sh [--base REF]       (REF defaults to origin/main)
#   git diff                                      (read what it wrote), then commit
#
# 1. A conflict in a file the repository generates is resolved, never edited:
#    - a pack's pack.json is merged key by key from its three sides. What the
#      seal writes (checksums, tools, skills, recipes) and the version are
#      written again below, so either side does for them; any other key both
#      sides changed differently stops it, named, for a person;
#    - a pack's skills/INDEX.md, tests/fixtures/kickoff/** and docs/rules.md
#      take either side and are written again below.
#    Each of these it stages (git add). Any other conflict stops it before it
#    writes anything: resolve those, then run it again.
# 2. Every pack whose files differ from REF's is sealed again (pack.sh seal).
#    A pack whose manifest or files differ from REF's while its version is not
#    above REF's gets REF's version with the patch raised: two different
#    packs never carry one version.
# 3. The kickoff goldens (GOLDENS=update) and the rule register
#    (scripts/rules.ts --write) are written again.
# 4. The changelog fragments are checked (scripts/changelog.ts --check).
# 5. It shows what is staged and what it wrote. It commits nothing.
#
# Safe to run twice: on a branch already up to date it writes nothing.
# CI keeps checking the same things on its own: packs.test.sh verifies every
# shipped pack, kickoff-goldens.test.sh compares the goldens, and
# rules-register.test.ts and changelog.test.ts fail on a stale register or a
# malformed fragment.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
BASE="origin/main"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --base) BASE="${2:?--base wants a ref}"; shift 2 ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) echo "merge-prep: unknown option $1 (see --help)" >&2; exit 2 ;;
  esac
done
git rev-parse --verify -q "$BASE^{commit}" >/dev/null || { echo "merge-prep: $BASE is not a commit here (git fetch origin first?)" >&2; exit 2; }
say() { echo "merge-prep: $*"; }
NODE=(node --experimental-strip-types --no-warnings)

# --- 1. conflicts -------------------------------------------------------------
generated() { # <path>: 0 when the repository writes the file itself
  case "$1" in
    packs/*/pack.json|packs/*/skills/INDEX.md|tests/fixtures/kickoff/*|docs/rules.md) return 0 ;;
    *) return 1 ;;
  esac
}
ours=() others=()
while IFS= read -r p; do
  [[ -n "$p" ]] || continue
  if generated "$p"; then ours+=("$p"); else others+=("$p"); fi
done < <(git diff --name-only --diff-filter=U)
if [[ ${#others[@]} -gt 0 ]]; then
  echo "merge-prep: these conflicts are not in generated files; resolve them (git add), then run merge-prep again:" >&2
  printf '  %s\n' "${others[@]}" >&2
  exit 1
fi

# A side of an unmerged file by its index stage (1 base, 2 and 3 the two sides).
stage() { git show ":$1:$2" 2>/dev/null; }
resealed=()
for p in ${ours[@]+"${ours[@]}"}; do
  case "$p" in
    packs/*/pack.json)
      tmp="$(mktemp -d)"
      stage 1 "$p" > "$tmp/base" || : > "$tmp/base"
      stage 2 "$p" > "$tmp/a" || { rm -rf "$tmp"; echo "merge-prep: $p was deleted on one side; resolve it by hand" >&2; exit 1; }
      stage 3 "$p" > "$tmp/b" || { rm -rf "$tmp"; echo "merge-prep: $p was deleted on one side; resolve it by hand" >&2; exit 1; }
      if ! python3 - "$tmp/base" "$tmp/a" "$tmp/b" "$p" <<'PY'
import json, sys
base_f, a_f, b_f, out_f = sys.argv[1:5]
def load(f):
    t = open(f, encoding="utf-8").read()
    return json.loads(t) if t.strip() else {}
try:
    base, a, b = load(base_f), load(a_f), load(b_f)
except ValueError as e:
    print("merge-prep: %s: a side is not JSON (%s); resolve it by hand" % (out_f, e), file=sys.stderr); sys.exit(1)
SEALED = {"checksums", "tools", "skills", "recipes"}
def ver(v):
    try: return tuple(int(x) for x in str(v).split("."))
    except ValueError: return ()
MISSING = object()
out, clash = {}, []
for k in list(a) + [k for k in b if k not in a]:
    va, vb, v0 = a.get(k, MISSING), b.get(k, MISSING), base.get(k, MISSING)
    if va == vb or vb == v0: v = va
    elif va == v0: v = vb
    elif k == "version": v = max(va, vb, key=ver)
    elif k in SEALED: v = va
    else:
        clash.append(k); continue
    if v is not MISSING: out[k] = v
if clash:
    print("merge-prep: %s: both sides changed %s differently; resolve it by hand" % (out_f, ", ".join(clash)), file=sys.stderr); sys.exit(1)
with open(out_f, "w", encoding="utf-8") as fh:
    json.dump(out, fh, ensure_ascii=False, indent=2); fh.write("\n")
PY
      then rm -rf "$tmp"; exit 1; fi
      rm -rf "$tmp"
      resealed+=("$(dirname "$p")")
      ;;
    *)
      stage 2 "$p" > "$p" 2>/dev/null || stage 3 "$p" > "$p"
      case "$p" in packs/*/skills/INDEX.md) resealed+=("${p%/skills/INDEX.md}") ;; esac
      ;;
  esac
  git add -- "$p"
  say "resolved $p (written again below)"
done

# --- 2. packs -----------------------------------------------------------------
packs=()
while IFS= read -r d; do
  [[ -n "$d" && -f "$d/pack.json" ]] || continue
  case " ${packs[*]-} " in *" $d "*) ;; *) packs+=("$d") ;; esac
done < <( { git diff --name-only "$BASE" -- packs/; git ls-files --others --exclude-standard -- packs/; printf '%s\n' ${resealed[@]+"${resealed[@]}"}; } | sed -n 's#^\(packs/[^/]*\).*#\1#p' | sort -u)
for d in ${packs[@]+"${packs[@]}"}; do
  out="$(bash scripts/pack.sh seal "$d" 2>&1)" || { printf '%s\n' "$out" >&2; echo "merge-prep: $d does not seal" >&2; exit 1; }
  say "sealed $d ($(sed -n 's/^sealed: //p' <<<"$out"))"
  if git cat-file -e "$BASE:$d/pack.json" 2>/dev/null; then
    git show "$BASE:$d/pack.json" | python3 -c '
import json, sys
cur_f, ref, d = sys.argv[1:4]
cur, base = json.load(open(cur_f, encoding="utf-8")), json.load(sys.stdin)
def ver(v): return tuple(int(x) for x in str(v).split("."))
strip = lambda m: {k: v for k, v in m.items() if k != "version"}
if strip(cur) != strip(base) and ver(cur["version"]) <= ver(base["version"]):
    major, minor, patch = ver(base["version"])
    old, cur["version"] = cur["version"], "%d.%d.%d" % (major, minor, patch + 1)
    with open(cur_f, "w", encoding="utf-8") as fh:
        json.dump(cur, fh, ensure_ascii=False, indent=2); fh.write("\n")
    print("merge-prep: %s: version %s -> %s (it differs from %s, which is %s)" % (d, old, cur["version"], ref, base["version"]))
' "$d/pack.json" "$BASE" "$d"
  fi
done
[[ ${#packs[@]} -gt 0 ]] || say "no pack differs from $BASE"

# --- 3. goldens and the rule register -----------------------------------------
out="$(GOLDENS=update bash tests/kickoff-goldens.test.sh 2>&1)" || { printf '%s\n' "$out" >&2; echo "merge-prep: the kickoff goldens could not be written" >&2; exit 1; }
say "kickoff goldens written again (tests/fixtures/kickoff/)"
"${NODE[@]}" scripts/rules.ts --write >/dev/null || { echo "merge-prep: scripts/rules.ts --write failed" >&2; exit 1; }
say "rule register written again (docs/rules.md)"

# --- 4. the changelog ---------------------------------------------------------
"${NODE[@]}" scripts/changelog.ts --check || exit 1
if [[ -n "$(git diff --name-only "$BASE" -- CHANGELOG.md)" ]]; then
  branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo branch)"
  say "note: this branch edits CHANGELOG.md; a pull request's entry goes in changelog.d/${branch//\//-}.md (CONTRIBUTING.md, \"The changelog\")"
fi

# --- 5. what it did -----------------------------------------------------------
echo
echo "Staged (the merge and the conflicts resolved above):"
if git diff --cached --quiet; then echo "  nothing"; else git diff --cached --stat | tail -n 25; fi
echo
echo "Not staged (what this step wrote, and any work not staged before it; git diff reads it):"
if git diff --quiet; then echo "  nothing"; else git diff --stat; fi

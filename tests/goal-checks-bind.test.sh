#!/usr/bin/env bash
# The case presets' inputs checks under --inputs-bind, where inputs/ is a
# symlink to the operator's directory. On run s57e9 the Web Server Case goal
# counted the inputs with `find inputs -type f`, which does not follow a link
# named on the command line: 0 against a manifest of 4, and the coordinator
# abandoned a finished case over it. The count has to be the same through a
# link as through a copy, and no preset may walk inputs/ the bare way again.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

src="$tmp/evidence"; mkdir -p "$src/logs"
printf 'disk\n' > "$src/disk.raw"; printf 'a line\n' > "$src/logs/access.log"
manifest='{"files":[{"path":"disk.raw"},{"path":"logs/access.log"}]}'
copy="$tmp/copy"; mkdir -p "$copy"; cp -R "$src" "$copy/inputs"; printf '%s\n' "$manifest" > "$copy/inputs.json"
bind="$tmp/bind"; mkdir -p "$bind"; ln -s "$src" "$bind/inputs";  printf '%s\n' "$manifest" > "$bind/inputs.json"

goal="$ROOT/docs/use-cases/dfir-web-server-case/goal.md"
check="$(grep -E '^- `.*inputs\.json' "$goal" | head -1 | sed -E 's/^- `(.*)`$/\1/')"
[[ -n "$check" ]] || fail "the Web Server Case goal has no inputs-count check any more"
echo "check: $check"
( cd "$copy" && bash -c "$check" ) || fail "the count check fails on a copied inputs/"
( cd "$bind" && bash -c "$check" ) || fail "the count check fails on a bound (symlinked) inputs/"
# and the bare walk really is the difference, so this test means something
( cd "$bind" && [[ "$(find inputs -type f | wc -l | tr -d ' ')" == 0 ]] ) || fail "a bare find followed the link on this host; the regression this guards cannot show here"

# No goal on any shelf walks inputs/ without following the link named on the
# command line: the published cases, the console's own copies, the library.
if grep -nE 'find +inputs\b' "$ROOT"/docs/use-cases/*/goal.md "$ROOT"/prompts/goals/*.md "$ROOT"/library/*/*.md | grep -v 'find -[HL] inputs'; then
  fail "a goal walks inputs/ with a bare find; under --inputs-bind that counts nothing"
fi
echo "ok - the presets' inputs count is the same through a bound inputs/ as through a copy"

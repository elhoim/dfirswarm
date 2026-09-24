#!/usr/bin/env bash
# A library entry opens with a metadata block between two `---` lines: the
# picker's title, summary and suggestions. The contract starts after it. The
# console strips the block before it sends the text; a file launched from the
# CLI (`--goal-file library/<category>/<slug>.md`) has to be stripped by
# swarm.sh the same way, in the contract and in the registry the checks are
# read from. A goal with no block is left exactly as written.
set -euo pipefail
# A shell with a VM default, an image or a lock file exported, or another pack
# home, would turn this suite's kickoffs into something else (a VM kickoff, another
# image): what the suite checks is the defaults.
unset SWARM_ISOLATION SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/goal-frontmatter.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
swarm() { SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
sandbox_of() { printf '%s\n' "$1" | sed -n 's/^SANDBOX=//p' | tail -1; }

entry="$ROOT/library/windows/host-intrusion.md"
[[ -f "$entry" ]] || fail "the library entry this test launches is missing: $entry"
head -n 1 "$entry" | grep -qx -- '---' || fail "the entry does not open with a metadata block"

out="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$entry" --label fromlib)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" && -f "$sb/SWARM.md" ]] || fail "no sandbox or no contract: $out"
grep -q '^## Goal' "$sb/SWARM.md" || fail "the contract lost the goal"
grep -q '^## Definition of done' "$sb/SWARM.md" || fail "the contract lost the definition of done"
grep -qE '^(title|summary|cap_usd|wall_clock|seats): ' "$sb/SWARM.md" && fail "the metadata block leaked into the contract"
grep -qx -- '---' "$sb/SWARM.md" && fail "a --- line from the metadata block is in the contract"
reg_goal="$(jq -r '.runs[] | select(.label == "fromlib") | .goal' "$TMP/runs/registry.json")"
[[ "$reg_goal" == "## Goal"* ]] || fail "the registry's goal (what the checks are read from) does not start at ## Goal: $(printf '%s' "$reg_goal" | head -c 60)"
echo "ok - a library entry launched from the CLI is stripped of its metadata block, in the contract and in the registry"

# The whole contract still carries the entry's own checks, counted the way await-done.sh counts them.
n_entry="$(sed -n '/^## Checks$/,$p' "$entry" | grep -c '^- `')"
n_contract="$(sed -n '/^## Checks$/,/^## /p' "$sb/SWARM.md" | grep -c '^- `')"
[[ "$n_contract" -eq "$n_entry" ]] || fail "the contract carries $n_contract checks, the entry $n_entry"
echo "ok - the entry's $n_entry checks are in the contract"

# A goal with no block is untouched: hello.md is the reference.
out2="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --label plain)"
sb2="$(sandbox_of "$out2")"
grep -q 'work/hello.txt' "$sb2/SWARM.md" || fail "a plain goal was damaged"
echo "ok - a goal without a metadata block is left as written"

# A block that never closes is not a block: the text is taken as it is, and
# the definition-of-done gate is what refuses it.
printf -- '---\ntitle: never closed\n## Goal\n\nx\n' > "$TMP/open.md"
if swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/open.md" --label open >/dev/null; then
  fail "a goal with an unclosed block and no definition of done was accepted"
fi
echo "ok - an unclosed block is not stripped and the goal is refused for what it lacks"

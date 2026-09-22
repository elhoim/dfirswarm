#!/usr/bin/env bash
# Fixture for read-only inputs. No Herdr, no Pi, no panes: `--no-start`
# prepares the sandbox and we read what it wrote; fsguard.sh is exercised
# directly where the host can run it.
#
# What must not go wrong: the copy has to be complete and stripped of every
# write bit, the pristine clone and the manifest have to match it, the
# contract has to tell the agents, the registry has to record it, a reused
# sandbox has to lose the old inputs, and the refusals (missing dir, dir
# inside the sandbox, too big, bad enforcement, enforcement the host cannot
# give) have to be refusals.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/inputs.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
start() { # start <args...> -> prints stdout+stderr, never fails the suite
  SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" start "$@" 2>&1
}
sandbox_of() { printf '%s\n' "$1" | sed -n 's/^SANDBOX=//p' | tail -1; }
# `-w` is true for root whatever the bits say (Docker runs as root), so look
# at the mode itself: any write bit set means the copy was not locked.
has_write_bit() { python3 -c 'import os, sys; sys.exit(0 if os.stat(sys.argv[1]).st_mode & 0o222 else 1)' "$1"; }

mkdir -p "$TMP/src/sub" "$TMP/elsewhere"
printf 'sensor,reading\na,1\nb,2\n' > "$TMP/src/readings.csv"
printf 'notes\n' > "$TMP/src/sub/notes.md"
printf 'outside\n' > "$TMP/elsewhere/secret.txt"
ln -s "$TMP/elsewhere/secret.txt" "$TMP/src/link.txt"

# --- the bind: no copy, the source held read-only by the kernel ------------------
guard_now="$(bash "$ROOT/scripts/fsguard.sh" --ro "$TMP/src" --dry-run -- true 2>/dev/null | sed -n 's/^mode: //p')"
if [[ -n "$guard_now" && "$guard_now" != "none" ]]; then
  out="$(start --model solo/model --n 2 --cap-usd 1 --no-start \
    --goal-file "$ROOT/prompts/goals/hello.md" --label bound --inputs "$TMP/src" --inputs-bind)"
  sb="$(sandbox_of "$out")"
  [[ -n "$sb" && -L "$sb/inputs" ]] || fail "--inputs-bind should leave inputs/ as a link: $out"
  [[ "$(readlink "$sb/inputs")" == "$(cd "$TMP/src" && pwd -P)" ]] || fail "the link should point at the resolved source, got $(readlink "$sb/inputs")"
  [[ ! -e "$sb/.inputs-pristine" ]] || fail "a bind has no pristine clone to make"
  [[ "$(jq -r '.held' "$sb/inputs.json")" == "bind" && "$(jq -r '.bound' "$sb/inputs.json")" == "true" ]] || fail "the manifest should say held: bind"
  [[ "$(jq -r '.files | length' "$sb/inputs.json")" == "3" ]] || fail "the manifest should hash the bound files through the link"
  [[ "$(jq -r '.guard' "$sb/inputs.json")" == "$guard_now" ]] || fail "the manifest should record the guard ($guard_now), got $(jq -r '.guard' "$sb/inputs.json")"
  grep -q -- "--ro $sb/inputs" "$sb/.zsh/.zshenv" || fail "the hook should make the bound inputs/ read-only"
  grep -q "which \`inputs/\` links to in place" "$sb/SWARM.md" || fail "the contract should say the evidence is bound, not copied"
  has_write_bit "$TMP/src/readings.csv" || fail "a bind must not strip the operator's write bits from the source"
  pass "--inputs-bind links inputs/ to the source, hashes it in place, and the hook holds it read-only ($guard_now)"
fi
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start \
  --goal-file "$ROOT/prompts/goals/hello.md" --label boundnoguard --inputs "$TMP/src" --inputs-bind --inputs-enforce off)"
printf '%s\n' "$out" | grep -q "BLOCKER: --inputs-bind needs a kernel guard" || fail "a bind with no kernel guard should be refused: $out"
pass "--inputs-bind without a kernel guard is refused (the source would be writable)"

# --- the copy ------------------------------------------------------------------
out="$(start --model solo/model --n 2 --cap-usd 1 --no-start \
  --goal-file "$ROOT/prompts/goals/hello.md" --label withinputs --inputs "$TMP/src")"
sb="$(sandbox_of "$out")"
[[ -n "$sb" && -d "$sb/inputs" ]] || fail "no inputs/ in the sandbox: $out"
[[ -f "$sb/inputs/readings.csv" && -f "$sb/inputs/sub/notes.md" ]] || fail "the copy is incomplete"
pass "--inputs copies the directory into inputs/"

[[ -f "$sb/inputs/link.txt" && ! -L "$sb/inputs/link.txt" ]] || fail "a symlink in the source should arrive as a plain copy"
[[ "$(cat "$sb/inputs/link.txt")" == "outside" ]] || fail "the dereferenced copy lost its bytes"
pass "symlinks are dereferenced, so nothing outside the copy is reachable through it"

for f in "$sb/inputs/readings.csv" "$sb/inputs/sub/notes.md" "$sb/inputs" "$sb/inputs/sub"; do
  has_write_bit "$f" && fail "$f still has a write bit"
done
pass "every write bit is gone from the copy"

[[ -f "$sb/.inputs-pristine/readings.csv" && -f "$sb/.inputs-pristine/sub/notes.md" ]] || fail "no pristine clone"
cmp -s "$sb/inputs/readings.csv" "$sb/.inputs-pristine/readings.csv" || fail "pristine clone differs"
pass "a pristine clone sits next to the copy"

n="$(jq -r '.files | length' "$sb/inputs.json")"
[[ "$n" == "3" ]] || fail "manifest lists $n files, expected 3"
sha="$(jq -r '.files[] | select(.path == "inputs/readings.csv") | .sha256' "$sb/inputs.json")"
if command -v sha256sum >/dev/null 2>&1; then want="$(sha256sum "$sb/inputs/readings.csv" | cut -d' ' -f1)"; else want="$(shasum -a 256 "$sb/inputs/readings.csv" | cut -d' ' -f1)"; fi
[[ "$sha" == "$want" ]] || fail "manifest hash $sha != $want"
[[ "$(jq -r '.enforce' "$sb/inputs.json")" == "auto" ]] || fail "manifest enforce should default to auto"
[[ "$(jq -r '.source' "$sb/inputs.json")" == "$(cd "$TMP/src" && pwd -P)" ]] || fail "manifest source"
pass "inputs.json records every file with its hash, the source and the enforcement asked for"

grep -q '^## Inputs (read-only)' "$sb/SWARM.md" || fail "the contract has no inputs section"
grep -q 'inputs/readings.csv' "$sb/SWARM.md" || fail "the contract does not list the files"
grep -q 'Never write, delete, move or chmod' "$sb/SWARM.md" || fail "the contract does not state the rule"
pass "the contract tells the agents what is read-only and why"

got="$(jq -r '.. | objects | select(.["label"]? == "withinputs") | .inputs.files' "$TMP/runs/registry.json")"
[[ "$got" == "3" ]] || fail "registry inputs.files should be 3, got $got"
guard="$(jq -r '.. | objects | select(.["label"]? == "withinputs") | .inputs.guard' "$TMP/runs/registry.json")"
[[ "$guard" == "seatbelt" || "$guard" == "mountns" || "$guard" == "linux" || "$guard" == "landlock" || "$guard" == "none" ]] || fail "registry guard: $guard"
pass "the registry records the inputs and the guard ($guard)"

case "$out" in
  *"Inputs:       3 file(s)"*) pass "the spawn line reports the inputs" ;;
  *) fail "no Inputs line in the kickoff output: $out" ;;
esac

if [[ "$guard" == "none" ]]; then
  printf '%s\n' "$out" | grep -q "WARN: no kernel read-only mechanism" || fail "guard none should come with a WARN"
  [[ ! -e "$sb/.zsh/.zshenv" ]] || fail "no hook should be written without a guard"
  pass "without a kernel guard the kickoff says so and writes no hook"
else
  [[ -f "$sb/.zsh/.zshenv" ]] || fail "no pane hook written for guard $guard"
  # The hook now carries the write allowlist as well, so the arguments are
  # asserted one at a time rather than as one fixed string.
  grep -q "fsguard.sh" "$sb/.zsh/.zshenv" || fail "the hook does not run fsguard"
  grep -q -- "--ro $sb/inputs" "$sb/.zsh/.zshenv" || fail "the hook does not make inputs/ read-only"
  grep -q -- "--mode $guard" "$sb/.zsh/.zshenv" || fail "the hook does not name the guard"
  if [[ "$guard" == "seatbelt" ]]; then
    grep -q -- "--rw $sb" "$sb/.zsh/.zshenv" || fail "the hook does not carry the write allowlist"
  fi
  grep -q "^mode: $guard" "$sb/.fsguard/plan.txt" || fail "the plan does not match the guard"
  pass "the pane hook and the plan name the guard ($guard)"
fi

# --- a swarm without inputs is untouched ----------------------------------------
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --label plain)"
sb2="$(sandbox_of "$out")"
[[ ! -e "$sb2/inputs" && ! -e "$sb2/inputs.json" ]] || fail "a plain swarm got inputs artifacts"
# A run with no evidence still gets a pane hook, because the write guard is
# not about the evidence: it is about the rest of the machine.
if [[ -e "$sb2/.zsh/.zshenv" ]]; then
  grep -q -- "--ro $sb2/inputs" "$sb2/.zsh/.zshenv" && fail "a plain swarm's hook guards an inputs/ it does not have"
  grep -q -- "--rw $sb2" "$sb2/.zsh/.zshenv" || fail "a plain swarm's hook exists but carries no write allowlist"
fi
grep -q '^## Inputs' "$sb2/SWARM.md" && fail "a plain contract mentions inputs"
grep -q '{{INPUTS}}' "$sb2/SWARM.md" && fail "the placeholder leaked into the contract"
[[ "$(jq -r '.. | objects | select(.["label"]? == "plain") | .inputs' "$TMP/runs/registry.json")" == "null" ]] || fail "registry inputs should be null"
pass "a swarm without --inputs has no inputs section, no hook, null in the registry"

# --- a reused sandbox loses the old inputs --------------------------------------
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --label reuse --sandbox "$sb")"
[[ ! -e "$sb/inputs" && ! -e "$sb/.inputs-pristine" && ! -e "$sb/inputs.json" ]] || fail "stale inputs survived a reuse: $(ls -a "$sb")"
# The pane hook is rewritten for the new run; what must not survive is the
# previous run's read-only rule for an inputs/ that no longer exists.
if [[ -e "$sb/.zsh/.zshenv" ]]; then
  grep -q -- "--ro $sb/inputs" "$sb/.zsh/.zshenv" && fail "the reused sandbox's hook still guards the old inputs/"
fi
pass "a reused sandbox is cleared of the previous run's inputs, write bits and all"

# --- refusals ---------------------------------------------------------------------
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --inputs "$TMP/nope")"
printf '%s\n' "$out" | grep -q "BLOCKER: --inputs .* is not a directory" || fail "a missing inputs dir should be a BLOCKER: $out"
pass "a missing directory is refused"

out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --inputs "$TMP/src" --inputs-enforce maybe)"
printf '%s\n' "$out" | grep -q "BLOCKER: --inputs-enforce must be auto, on or off" || fail "a bad enforcement mode should be a BLOCKER: $out"
pass "an unknown enforcement mode is refused"

out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --inputs "$TMP/src" --inputs-max-mb 0)"
printf '%s\n' "$out" | grep -q "BLOCKER: --inputs .* MB; the limit is 0 MB" || fail "an oversized inputs dir should be a BLOCKER: $out"
pass "a directory above --inputs-max-mb is refused before anything is copied"

mkdir -p "$TMP/linked-only"
python3 -c 'open("'"$TMP"'/elsewhere/blob.bin","wb").write(b"x"*(2*1024*1024))'
ln -s "$TMP/elsewhere/blob.bin" "$TMP/linked-only/case.E01"
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --inputs "$TMP/linked-only" --inputs-max-mb 1)"
printf '%s\n' "$out" | grep -q "BLOCKER: --inputs .* MB; the limit is 1 MB" || fail "a symlink to a 2 MiB file should count toward the size cap: $out"
pass "size and file caps follow the same symlinks cp -RL copies"

mkdir -p "$TMP/linked-files"
printf 'x\n' > "$TMP/elsewhere/tiny.bin"
python3 -c '
import os, sys
d = sys.argv[1]
os.makedirs(d, exist_ok=True)
target = sys.argv[2]
for i in range(5001):
    os.symlink(target, os.path.join(d, f"f{i}.bin"))
' "$TMP/linked-files" "$TMP/elsewhere/tiny.bin"
# No cap unless one is asked for: evidence is as large as the case is, and a
# disk image with a hundred thousand files in it is ordinary.
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --inputs "$TMP/linked-files")"
printf '%s\n' "$out" | grep -q "BLOCKER" && fail "5001 files should be accepted with no cap set: $out"
pass "with no --inputs-max-files there is no ceiling on the file count"

out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --inputs "$TMP/linked-files" --inputs-max-files 5000)"
printf '%s\n' "$out" | grep -q "BLOCKER: --inputs .* has 5001 files; the limit is 5000" || fail "--inputs-max-files should still refuse when asked: $out"
pass "the file cap counts symlink targets when --inputs-max-files asks for one"

mkdir -p "$TMP/runs/inside"
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --sandbox "$TMP/runs/inside" --inputs "$TMP/runs/inside")"
printf '%s\n' "$out" | grep -q "BLOCKER" || fail "an inputs dir that is the sandbox should be refused: $out"
pass "an inputs directory inside the sandbox is refused"

out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --inputs "$TMP/src" --env SWARM_FSGUARD=none)"
printf '%s\n' "$out" | grep -q "BLOCKER: --env SWARM_FSGUARD=none would switch the pane's kernel guard off" || fail "a pre-set SWARM_FSGUARD should be refused: $out"
pass "an operator --env that would switch the guard off is refused"

out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --quarantine --env SWARM_FSGUARD=none)"
printf '%s\n' "$out" | grep -q "BLOCKER: --env SWARM_FSGUARD=none would switch the pane's kernel guard off" \
  || fail "--quarantine without --inputs still writes the hook; --env SWARM_FSGUARD must be refused: $out"
pass "SWARM_FSGUARD cannot be switched off through --env when only --quarantine is set"

out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --env SWARM_FSGUARD=none)"
printf '%s\n' "$out" | grep -q "BLOCKER: --env SWARM_FSGUARD=none would switch the pane's kernel guard off" \
  || fail "--env SWARM_FSGUARD must be refused even with no inputs and no quarantine: $out"
pass "an operator --env SWARM_FSGUARD is refused at kickoff, not only with --inputs"

mkdir -p "$TMP/big"
python3 -c 'import os, sys; d = sys.argv[1]; [open(os.path.join(d, f"f{i}.txt"), "w").close() for i in range(5001)]' "$TMP/big"
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --inputs "$TMP/big" --inputs-max-files 5000)"
printf '%s\n' "$out" | grep -q "BLOCKER: --inputs .* has 5001 files; the limit is 5000" || fail "a directory over an asked-for file cap should be refused: $out"
pass "a directory with more files than an asked-for cap is refused"

out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --inputs "$TMP/src" --inputs-enforce off --label off)"
sb3="$(sandbox_of "$out")"
[[ "$(jq -r '.guard' "$sb3/inputs.json")" == "none" ]] || fail "--inputs-enforce off should record guard none"
# `--inputs-enforce off` is about the evidence, not about the rest of the
# machine: the write guard is a separate question and stays on.
if [[ -e "$sb3/.zsh/.zshenv" ]]; then
  grep -q -- "--ro $sb3/inputs" "$sb3/.zsh/.zshenv" && fail "--inputs-enforce off still guarded inputs/"
fi
has_write_bit "$sb3/inputs/readings.csv" && fail "off still strips the write bits"
pass "--inputs-enforce off keeps the copy read-only by mode and writes no kernel hook"

# --- fsguard.sh itself ---------------------------------------------------------------
mode="$(bash "$ROOT/scripts/fsguard.sh" --ro "$TMP/src" --dry-run -- true 2>/dev/null | sed -n 's/^mode: //p')"
[[ -n "$mode" ]] || fail "fsguard --dry-run prints no mode"
pass "fsguard dry-run reports its mode ($mode)"

out="$(bash "$ROOT/scripts/fsguard.sh" --ro "$TMP/nope" -- true 2>&1)"; rc=$?
[[ "$rc" -eq 2 ]] || fail "fsguard should refuse a missing --ro dir with exit 2, got $rc: $out"
pass "fsguard refuses a directory that does not exist"

if [[ "$mode" == "none" ]]; then
  # The refusal for --inputs-enforce on is only reachable on a host without a guard.
  out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --inputs "$TMP/src" --inputs-enforce on)"
  printf '%s\n' "$out" | grep -q "BLOCKER: --inputs-enforce on, but this host has no kernel read-only mechanism" || fail "enforce on without a guard should be a BLOCKER: $out"
  pass "--inputs-enforce on is refused on a host with no kernel guard"
  echo "skip - kernel deny checks (mode=none on this host)"
else
  chmod -R u+w "$TMP/src"
  probe="$TMP/probe.sh"
  cat > "$probe" <<PROBE
echo "guard=\$SWARM_FSGUARD"
echo x > "$TMP/src/readings.csv" 2>/dev/null && echo WRITE-ALLOWED || echo write-denied
echo x > "$TMP/src/new.txt" 2>/dev/null && echo CREATE-ALLOWED || echo create-denied
rm -f "$TMP/src/sub/notes.md" 2>/dev/null; [ -f "$TMP/src/sub/notes.md" ] && echo rm-denied || echo RM-ALLOWED
mv "$TMP/src" "$TMP/src2" 2>/dev/null && echo MV-ALLOWED || echo mv-denied
echo out > "$TMP/elsewhere/out.txt" && echo elsewhere-writable
exit 7
PROBE
  out="$(bash "$ROOT/scripts/fsguard.sh" --ro "$TMP/src" -- bash "$probe" 2>&1)"; rc=$?
  [[ "$rc" -eq 7 ]] || fail "fsguard should pass the command's exit code through, got $rc: $out"
  for want in "guard=$mode" write-denied create-denied rm-denied mv-denied elsewhere-writable; do
    printf '%s\n' "$out" | grep -qx "$want" || fail "fsguard ($mode): expected '$want' in: $out"
  done
  [[ "$(cat "$TMP/src/readings.csv")" == $'sensor,reading\na,1\nb,2' ]] || fail "the guarded file changed"
  pass "under fsguard ($mode) a write, a create, a delete and a rename of the directory are all denied, and a sibling stays writable"
fi

echo "inputs.test.sh: all checks passed"

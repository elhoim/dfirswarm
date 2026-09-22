#!/usr/bin/env bash
# The write guard: a pane writes inside its run and nowhere else.
#
# Phase 1 of docs/sandbox-plan.md. Before this the seatbelt profile was
# `(allow default)` with a deny under inputs/, which protects the evidence
# from the agents and the machine from nobody: measured inside a real guard,
# a pane could list the examiner's home, see every other case, and write
# outside its sandbox — including runs/registry.json, which await-done.sh
# reads the definition of done from and then eval's.
#
# macOS only. On a host without seatbelt the guard cannot apply, and the
# assertions below are skipped rather than quietly passing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FSGUARD="$ROOT/scripts/fsguard.sh"
pass=0

ok() { echo "ok - $1"; pass=$((pass + 1)); }
fail() { echo "not ok - $1" >&2; exit 1; }

# The mode is the host's: seatbelt on macOS; on Linux, `linux` (Landlock
# inside a user namespace) where both exist, `landlock` alone under Docker's
# default profile or Ubuntu's AppArmor restriction, `mountns` where only
# namespaces are there. The assertions are the same; what a mode cannot do
# is asserted as "says so" rather than skipped in silence.
MODE="$(bash "$FSGUARD" --rw "${TMPDIR:-/tmp}" --dry-run -- true 2>/dev/null | sed -n 's/^mode: //p')"
if [[ -z "$MODE" || "$MODE" == "none" ]]; then
  echo "skip - no kernel write guard on this host: seatbelt=$([[ -x /usr/bin/sandbox-exec ]] && echo yes || echo no) userns=$(unshare -rm true 2>/dev/null && echo yes || echo no) landlock=$(python3 "$ROOT/scripts/landlock.py" --dry-run -- true 2>/dev/null | sed -n 's/^abi: //p')"
  echo "write-guard.test.sh: skipped on this host"
  exit 0
fi
if [[ "$MODE" == "mountns" ]] && bash "$FSGUARD" --rw "${TMPDIR:-/tmp}" --mode mountns --dry-run -- true 2>/dev/null | grep -q 'note: --rw needs bubblewrap'; then
  echo "skip - mountns without bubblewrap has no write allowlist (install bubblewrap, or a kernel with Landlock)"
  echo "write-guard.test.sh: skipped on this host"
  exit 0
fi
echo "mode - $MODE"
# Only seatbelt and the namespace modes can carve a read-only directory out
# of a writable one; Landlock grants and does not subtract.
# seatbelt denies beneath a path; the namespace modes bind it read-only on
# top of the writable one; Landlock carves it — its siblings keep the rights,
# its parent becomes listing-only. All three refuse the write.
can_carve() { case "$MODE" in seatbelt|linux|mountns|landlock) return 0 ;; *) return 1 ;; esac; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/write-guard.XXXXXX")"
# The kernel matches on the real path, and /tmp is a symlink on macOS.
TMP="$(cd "$TMP" && pwd -P)"
trap 'rm -rf "$TMP"' EXIT

SANDBOX="$TMP/runs/s0001"
OTHER="$TMP/runs/s0002"
mkdir -p "$SANDBOX/work/.tmp" "$SANDBOX/inputs" "$SANDBOX/traces" "$OTHER/work"
echo evidence > "$SANDBOX/inputs/image.raw"
printf '{"runs":[]}' > "$TMP/runs/registry.json"
: > "$SANDBOX/traces/events.jsonl"

# The kickoff points TMPDIR inside the run, so the per-user temp area can stay
# closed. The guard is tested the way it is used.
run_guarded() {
  TMPDIR="$SANDBOX/work/.tmp" bash "$FSGUARD" --rw "$SANDBOX" --ro "$SANDBOX/inputs" --ro "$SANDBOX/traces" \
    --mode "$MODE" -- bash -c "$1" 2>/dev/null
}

# --- what a pane must still be able to do ---------------------------------
run_guarded "touch '$SANDBOX/work/note.md'" || fail "a pane cannot write its own work/"
ok "a pane writes inside its own run"

run_guarded "python3 -c 'import tempfile; f = tempfile.NamedTemporaryFile(); f.write(b\"x\"); print(\"ok\")' >/dev/null" \
  || fail "python cannot make a temp file under the guard"
ok "python, /dev/null and the temp directory still work"

run_guarded "cd '$SANDBOX/work' && sqlite3 t.db 'create table a(b);'" || fail "sqlite3 cannot write in work/"
ok "a tool that writes its own files in work/ still works"

# --- what it must refuse --------------------------------------------------
if run_guarded "touch '$TMP/runs/escape'"; then fail "a pane wrote outside its sandbox"; fi
ok "a pane cannot write outside its sandbox"

if run_guarded "touch '$OTHER/work/leak'"; then fail "a pane wrote into another run"; fi
ok "a pane cannot write into another case"

if run_guarded "printf x >> '$TMP/runs/registry.json'"; then fail "a pane rewrote the run registry"; fi
ok "a pane cannot rewrite runs/registry.json — the file await-done.sh eval's"

if run_guarded "touch \"\$HOME/.swarm-write-guard-probe\""; then
  rm -f "$HOME/.swarm-write-guard-probe"
  fail "a pane wrote into the examiner's home"
fi
ok "a pane cannot write into the examiner's home"

if run_guarded "printf x > '$SANDBOX/inputs/image.raw'"; then fail "a pane wrote to the evidence"; fi
ok "the evidence is still read-only"

if run_guarded "printf x >> '$SANDBOX/traces/events.jsonl'"; then fail "a pane appended to the trace"; fi
ok "a pane cannot write the trace the collector owns"

# --- the one writable path outside the run, and its limit -----------------
# Pi's agent directory stays writable (a token refresh lands there) and its
# extensions/ does not: code dropped there would load in every later Pi run
# on this machine, which is persistence outside the sandbox.
PIDIR="$TMP/pi/agent"
mkdir -p "$PIDIR/extensions"
guarded_with_pi() {
  TMPDIR="$SANDBOX/work/.tmp" bash "$FSGUARD" --rw "$SANDBOX" --rw "$PIDIR" --ro "$PIDIR/extensions" \
    --mode "$MODE" -- bash -c "$1" 2>/dev/null
}
# The file exists before the pane starts, as Pi's does: a refresh rewrites
# it in place. Under Landlock the agent directory's root is listing-only
# once extensions/ is carved out of it, so creating a *new* file there is
# refused; writing the existing one is not.
: > "$PIDIR/auth.json"
guarded_with_pi "printf '{}' > '$PIDIR/auth.json'" || fail "Pi cannot write its own agent directory"
ok "Pi's agent directory stays writable, so a token refresh still lands"

if can_carve; then
  if guarded_with_pi "touch '$PIDIR/extensions/evil.ts'"; then fail "a pane dropped an extension into Pi's directory"; fi
  ok "and its extensions/ is refused — no persistence into later runs"
else
  # Landlock alone cannot; what matters is that nothing pretends it can.
  guarded_with_pi "touch '$PIDIR/extensions/evil.ts'" || fail "under $MODE the carve is impossible, so this write should succeed and be recorded as such"
  ok "under $MODE extensions/ stays writable, and the kickoff records pi_extensions: writable"
fi

# --- the classic escapes --------------------------------------------------
mkdir -p "$TMP/outside"
echo ORIGINAL > "$TMP/outside/target.txt"
run_guarded "cd '$SANDBOX' && ln -s '$TMP/outside/target.txt' slink && printf TAMPERED > slink" || true
[[ "$(cat "$TMP/outside/target.txt")" == "ORIGINAL" ]] || fail "a symlink out of the sandbox was writable"
ok "a symlink pointing out of the run does not carry a write through it"

run_guarded "cd '$SANDBOX' && ln '$TMP/outside/target.txt' hlink && printf TAMPERED > hlink" || true
[[ "$(cat "$TMP/outside/target.txt")" == "ORIGINAL" ]] || fail "a hard link to an outside file was writable"
ok "a hard link to a file outside the run does not carry a write either"

# --- and the evidence is untouched ----------------------------------------
[[ "$(cat "$SANDBOX/inputs/image.raw")" == "evidence" ]] || fail "the evidence changed"
ok "the evidence bytes are unchanged"

# --- the profile says what it does ----------------------------------------
profile="$(bash "$FSGUARD" --rw "$SANDBOX" --ro "$SANDBOX/inputs" --mode "$MODE" --dry-run -- true)"
if [[ "$MODE" == "seatbelt" ]]; then
  grep -q '(deny file-write\* (subpath "/"))' <<< "$profile" || fail "the profile does not deny writes by default"
  grep -q "(allow file-write\* (subpath \"$SANDBOX\"))" <<< "$profile" || fail "the profile does not allow the sandbox back"
else
  grep -qE '^(landlock abi: [1-9]|namespace: bwrap)' <<< "$profile" || fail "the dry run names neither Landlock nor bubblewrap: $profile"
fi
grep -q 'writable: '"$SANDBOX" <<< "$profile" || fail "the dry run does not name the writable path"
ok "the profile is a write allowlist and the dry run says so"

# --- reads are open, except where the case says they must not be -----------
#
# The allowlist deliberately leaves reads open: a deny-default profile cannot
# start /bin/echo (measured), and an examiner's own tools live outside the
# run. That is right until the thing lying about is the answer. A previous
# run on the same evidence is exactly that, and on a re-run it is the
# difference between a swarm that worked the case and one that read the back
# of the book.
SECRETS="$TMP/prior-run"
mkdir -p "$SECRETS/deep"
printf 'the answer is 42\n' > "$SECRETS/deep/flags.md"
printf 'ordinary\n' > "$TMP/elsewhere.txt"

if bash "$FSGUARD" --rw "$SANDBOX" --mode "$MODE" -- \
    cat "$SECRETS/deep/flags.md" >/dev/null 2>&1; then
  ok "without --no-read a pane can read anything (the behaviour --no-read exists to narrow)"
else
  fail "the baseline is wrong: reads should be open without --no-read"
fi

if bash "$FSGUARD" --rw "$SANDBOX" --no-read "$SECRETS" --mode "$MODE" -- \
    cat "$SECRETS/deep/flags.md" >/dev/null 2>&1; then
  fail "--no-read did not stop the read"
fi
ok "--no-read denies a file under the directory, however deep"

# A directory that cannot be read must not be listable either: the file names
# alone would say what the previous run looked at.
if [[ "$MODE" == "seatbelt" ]]; then
  if bash "$FSGUARD" --rw "$SANDBOX" --no-read "$SECRETS" --mode "$MODE" -- \
      ls "$SECRETS" >/dev/null 2>&1; then
    fail "--no-read left the directory listable"
  fi
  ok "and the directory cannot be listed"
elif [[ "$MODE" != "landlock" ]]; then
  # A namespace mode covers the directory with an empty tmpfs: the listing
  # succeeds and shows nothing, which is the same nothing.
  seen="$(bash "$FSGUARD" --rw "$SANDBOX" --no-read "$SECRETS" --mode "$MODE" -- ls "$SECRETS" 2>/dev/null)"
  [[ -z "$seen" ]] || fail "--no-read left names visible under the mask: $seen"
  ok "and the directory is empty inside the pane (masked)"
else
  # Landlock withholds READ_FILE beneath the directory and leaves READ_DIR on
  # its ancestors so listings elsewhere keep working: the names are visible,
  # the contents are not, and landlock.py's header says exactly that.
  ok "under $MODE the names in the directory stay visible and the contents do not (documented)"
fi

# Narrow on purpose. A rule that took the rest of the disk with it would stop
# the agents using the examiner's tools, which is not what this is for.
bash "$FSGUARD" --rw "$SANDBOX" --no-read "$SECRETS" --mode "$MODE" -- \
  cat "$TMP/elsewhere.txt" >/dev/null 2>&1 || fail "--no-read took an unrelated path with it"
bash "$FSGUARD" --rw "$SANDBOX" --no-read "$SECRETS" --mode "$MODE" -- \
  cat "$SANDBOX/inputs/image.raw" >/dev/null 2>&1 || fail "--no-read blocked the evidence"
ok "everything else stays readable, the evidence included"

profile="$(bash "$FSGUARD" --rw "$SANDBOX" --no-read "$SECRETS" --mode "$MODE" --dry-run -- true)"
if [[ "$MODE" == "seatbelt" ]]; then grep -q '(deny file-read\* (subpath' <<< "$profile" || fail "the profile carries no read deny"; fi
grep -q "no-read: " <<< "$profile" || fail "the dry run does not name the denied path"
ok "the profile and the dry run both say what was denied"

# --- a read-only path that is a symlink: what --inputs-bind makes --------------
#
# `inputs/` is a link to the evidence and the guard's rule is on what it
# resolves to. Landlock only grants, so a carved path is surrounded by rules
# handing its siblings the enclosing region's rights — and a sibling compared
# by its own name never matches a carved path recorded canonically. Measured
# on a Linux server: the link was handed the run's write rights, O_PATH
# followed it, and the evidence directory was writable inside a guard that
# said it was not. The pane's own probe reported "none" and the kickoff said
# the guard was on.
LINKED="$TMP/linked-evidence"
mkdir -p "$LINKED"
printf 'evidence\n' > "$LINKED/file.txt"
ln -sfn "$LINKED" "$SANDBOX/inputs-link"
bash "$FSGUARD" --rw "$SANDBOX" --ro "$SANDBOX/inputs-link" --mode "$MODE" -- \
  bash -c 'touch "$SANDBOX/inputs-link/through-link" 2>/dev/null; touch "$LINKED/at-target" 2>/dev/null' >/dev/null 2>&1 || true
[[ ! -e "$LINKED/through-link" ]] || fail "a write through a --ro symlink was allowed"
[[ ! -e "$LINKED/at-target" ]] || fail "a write to a --ro symlink's target was allowed"
[[ -f "$LINKED/file.txt" ]] || fail "the linked evidence lost a file"
ok "a --ro path that is a symlink is read-only through the link and at its target"

echo "write-guard.test.sh: all $pass checks passed"

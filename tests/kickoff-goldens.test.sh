#!/usr/bin/env bash
# Kickoff goldens: what `swarm.sh start --no-start` writes for a few goals,
# compared with the files checked in under tests/fixtures/kickoff/<case>/.
# A change to the kickoff (the template, a goal, the system prompt, the case
# policy, the budget, the inputs manifest) then shows as a readable diff of
# those files, made in the same pull request:
#
#   GOLDENS=update bash tests/kickoff-goldens.test.sh
#
# What only the machine or the moment decides is written as a placeholder
# before the comparison:
# - the run's id and the paths of the run and the evidence;
# - the times;
# - the host's guard and its facts (the "This host" section, the inputs'
#   guard sentence and inputs.json's guard).
# No model, no Herdr, no VM.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOLD="$ROOT/tests/fixtures/kickoff"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/kickoff-goldens.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
export SWARM_RUNS_DIR="$TMP/runs" SWARM_SIGNERS_HOME="$TMP/signers"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

# The files a kickoff writes that say what the run is, by the name each is kept under.
FILES=("SWARM.md:SWARM.md" ".pi/SYSTEM.md:SYSTEM.md" ".pi/APPEND_SYSTEM.md:APPEND_SYSTEM.md" ".pi/settings.json:settings.json" "budget.json:budget.json" "team.json:team.json" "network/policy.json:policy.json" "inputs.json:inputs.json" "questions/questions.md:questions.md")

# The evidence: small, and the same bytes every time.
EV="$TMP/evidence"
mkdir -p "$EV/logs"
printf 'Jan  1 00:00:01 host sshd[1]: Accepted publickey for alice\n' > "$EV/logs/auth.log"
printf 'disk image bytes\n' > "$EV/disk.img"

normalize() { # <file> <sandbox> <run id>
  python3 - "$@" <<'PY'
import re, sys
path, sandbox, run_id = sys.argv[1:4]
evidence = sys.argv[4] if len(sys.argv) > 4 else ""
t = open(path, encoding="utf-8").read()
import os
def forms(p):
    # A path as given, as the kernel resolves it, without a doubled slash, and macOS's /var under /private.
    out = set()
    for q in {p, os.path.normpath(p), os.path.realpath(p)}:
        out |= {q, q.replace("/private/var/", "/var/"), ("/private" + q) if q.startswith("/var/") else q}
    return sorted(out - {""}, key=len, reverse=True)
for p in forms(sandbox):
    t = t.replace(p, "<SANDBOX>")
for p in (forms(evidence) if evidence else []):
    t = t.replace(p, "<EVIDENCE>")
t = t.replace(run_id, "<RUN>")
t = re.sub(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z", "<TIME>", t)
t = re.sub(r'"(mtime_ms|ctime_ms)": \d+', r'"\1": <MS>', t)
t = re.sub(r'"seconds": [0-9.]+', '"seconds": <S>', t)
t = re.sub(r'"(guard|enforce)": "[^"]*"', r'"\1": "<HOST>"', t)
# SWARM.md: the inputs' guard sentence, and the host's own section.
t = re.sub(r"(`edit`/`write`/`claim_file` refuse it, ).*?(, and every attempt is announced)", r"\1<the host's guard>\2", t, flags=re.S)
t = re.sub(r"## This host\n\n.*?(?=\n## |\Z)", "## This host\n\n<the host's facts>\n", t, flags=re.S)
open(path, "w", encoding="utf-8").write(t)
PY
}

kickoff() { # <case> <args...>
  local name="$1"; shift
  local out sb id
  out="$(bash "$ROOT/scripts/swarm.sh" start --no-start --toolbox off --label "golden-$name" "$@" 2>&1)" || fail "$name: the kickoff failed: $out"
  sb="$(sed -n 's/^SANDBOX=//p' <<<"$out" | tail -1)"
  [[ -n "$sb" && -d "$sb" ]] || fail "$name: no sandbox from the kickoff: $out"
  id="$(basename "$sb")"
  mkdir -p "$TMP/got/$name"
  local f src dst
  for f in "${FILES[@]}"; do
    src="${f%%:*}"; dst="${f##*:}"
    [[ -f "$sb/$src" ]] || continue
    cp "$sb/$src" "$TMP/got/$name/$dst"; chmod u+w "$TMP/got/$name/$dst"
    normalize "$TMP/got/$name/$dst" "$sb" "$id" "$EV"
  done
  # The first seat's own prompt line (its id is the run's id and a number, so it is kept under a fixed name).
  if [[ -f "$sb/.pi/seat-${id}00.md" ]]; then
    cp "$sb/.pi/seat-${id}00.md" "$TMP/got/$name/seat-00.md"; chmod u+w "$TMP/got/$name/seat-00.md"
    normalize "$TMP/got/$name/seat-00.md" "$sb" "$id" "$EV"
  fi
  if [[ "${GOLDENS:-}" == update ]]; then
    rm -rf "$GOLD/$name"; mkdir -p "$GOLD"; cp -R "$TMP/got/$name" "$GOLD/$name"
    pass "$name: goldens written ($(ls "$GOLD/$name" | wc -l | tr -d ' ') files)"
    return
  fi
  [[ -d "$GOLD/$name" ]] || fail "$name: no goldens under tests/fixtures/kickoff/$name (GOLDENS=update writes them)"
  local d
  if ! d="$(diff -r "$GOLD/$name" "$TMP/got/$name")"; then
    printf '%s\n' "$d" | head -40 >&2
    fail "$name: the kickoff writes something else than tests/fixtures/kickoff/$name: if the change is meant, GOLDENS=update bash tests/kickoff-goldens.test.sh, and commit the diff"
  fi
  pass "$name: the kickoff writes what tests/fixtures/kickoff/$name holds"
}

kickoff "hello" --model solo/model --n 2 --cap-usd 1 --goal-file "$ROOT/prompts/goals/hello.md" --inputs "$EV"
kickoff "c10-ctf" --models "solo/a=2,solo/b=1" --cap-usd 250 --goal-file "$ROOT/prompts/goals/dfir-c10-meeting-location.md" --inputs "$EV" \
  --stop operator --policy ctf --more-evidence no --case-id c10 --examiner "the examiner"
kickoff "web-cap-stop" --model solo/model --n 3 --cap-usd 30 --cap-tokens 5000000 --stop cap-stop --goal-file "$ROOT/prompts/goals/dfir-web-server-case.md" --inputs "$EV"

#!/usr/bin/env bash
# What must not go wrong: an agent with something to read is woken quickly, an
# agent with an empty inbox is left alone until the long timer, the nudge says
# what is waiting, and the budget is per silence rather than per run.
#
# The numbers this encodes were measured over seven forensic runs: 34 agents
# had to be woken, and in 32 of those a peer's post had landed a median of 26
# seconds into the silence and then sat unread until the 180-second timer.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/idle-nudge.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

SB="$TMP/sandbox"
mkdir -p "$SB"/{traces,done/agents,threads/main,inbox/a00,inbox/a01,.pi-sessions/a00,.pi-sessions/a01,locks}
cat > "$SB/team.json" <<'JSON'
{"swarm_id": "t", "n": 2, "agents": [{"id": "a00", "role": "worker"}, {"id": "a01", "role": "worker"}]}
JSON
: > "$SB/traces/events.jsonl"

post() { # post <id> <from>
  printf -- '---\nid: %s\nthread: main\nfrom: %s\nto: all\ntag: result\n---\n\nsomething happened\n' "$1" "$2" \
    > "$SB/threads/main/$(printf '%06d' "$1")-$2.md"
}

# a00 has two posts it has not read; a01 has read everything
post 1 a01
post 2 a01
printf '{"main": 0}\n' > "$SB/inbox/a00/cursors.json"
printf '{"main": 2}\n' > "$SB/inbox/a01/cursors.json"

# both have been quiet for about a minute: past the news threshold, short of
# the silence one
# touch -t reads local time, so the stamp has to be local too.
old="$(date -v-70S +%Y%m%d%H%M.%S 2>/dev/null || date -d '70 seconds ago' +%Y%m%d%H%M.%S)"
for id in a00 a01; do
  : > "$SB/.pi-sessions/$id/session.jsonl"
  touch -t "$old" "$SB/.pi-sessions/$id/session.jsonl"
done

# a herdr that always says the pane is idle and records what it was told
mkdir -p "$TMP/bin"
cat > "$TMP/bin/herdr" <<'SH'
#!/usr/bin/env bash
case "$1 $2" in
  "agent get") printf '{"result":{"agent":{"agent_status":"idle"}}}\n' ;;
  "agent prompt") printf '%s\t%s\n' "$3" "$4" >> "$PROMPT_LOG" ;;
  *) : ;;
esac
SH
chmod +x "$TMP/bin/herdr"
export PROMPT_LOG="$TMP/prompts.txt"
: > "$PROMPT_LOG"

run_once() { HERDR_BIN="$TMP/bin/herdr" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$SB" --once "$@" >/dev/null 2>&1; }

run_once --news-sec 45 --idle-sec 180
grep -q '^a00	' "$PROMPT_LOG" || fail "an agent with unread posts should be woken at the news threshold"
grep -q '^a01	' "$PROMPT_LOG" && fail "an agent with nothing to read should wait for the long timer"
pass "unread posts wake an agent early; an empty inbox does not"

grep '^a00	' "$PROMPT_LOG" | grep -q '2 post(s) you have not read' \
  || fail "the nudge should say how much is waiting: $(cat "$PROMPT_LOG")"
pass "the nudge says what is waiting"

# Same silence, run again: the budget counts up rather than starting over.
run_once --news-sec 45 --idle-sec 180
[[ "$(grep -c '^a00	' "$PROMPT_LOG")" -eq 2 ]] || fail "a second pass in the same silence should nudge once more"
grep '^a00	' "$PROMPT_LOG" | tail -1 | grep -q 'Nudge 2 of 3' || fail "the second nudge should be numbered 2"
pass "the budget counts up within one silence"

# The agent works: its idle clock resets, and so does the budget.
run_once --news-sec 45 --idle-sec 180   # nudge 3 of 3
run_once --news-sec 45 --idle-sec 180   # budget spent, no fourth
[[ "$(grep -c '^a00	' "$PROMPT_LOG")" -eq 3 ]] || fail "a spent budget should stop the nudges"
touch "$SB/.pi-sessions/a00/session.jsonl"
touch -t "$old" "$SB/.pi-sessions/a00/session.jsonl"
run_once --news-sec 45 --idle-sec 180
[[ "$(grep -c '^a00	' "$PROMPT_LOG")" -eq 3 ]] || fail "same silence, still spent"
pass "a spent budget stops the nudges for that silence"

# An agent that has finished is left alone whatever its inbox says.
: > "$SB/done/agents/a00.done"
run_once --news-sec 45 --idle-sec 180
[[ "$(grep -c '^a00	' "$PROMPT_LOG")" -eq 3 ]] || fail "a done agent must not be nudged"
pass "an agent with a done marker is left alone"

# Every nudge is on the trace.
[[ "$(grep -c '"tool":"idle_nudge"' "$SB/traces/events.jsonl")" -ge 3 ]] || fail "the nudges are not on the trace"
pass "each nudge is written to the trace"

# --- a provider error is not a silence --------------------------------------
# Both DeepSeek agents on the BelkaCTF #6 run died on `402 Insufficient
# Balance` nine minutes in, and the watchdog spent all three nudges on each of
# them: every retry hit the same 402, and the board never heard about any of
# it. An agent whose last event is agent_error is finished, not idle.
rm -f "$SB/done/agents/a00.done"
: > "$PROMPT_LOG"
: > "$SB/traces/idle-nudge.state"
printf '{"ts":"2026-01-01T00:00:00.000Z","agent":"a00","tool":"agent_error","args":{"model":"deepseek/deepseek-v4-pro"},"result":{"ok":false,"reason":"402 Insufficient Balance"}}\n' \
  >> "$SB/traces/events.jsonl"
run_once --news-sec 45 --idle-sec 180
[[ "$(grep -c '^a00	' "$PROMPT_LOG")" -eq 0 ]] || fail "an agent that died on a provider error must not be nudged"
pass "a turn that ended in a provider error stops the nudges, because no nudge can fix it"

# …and an agent that worked after the error is idle again like any other.
printf '{"ts":"2026-01-01T00:01:00.000Z","agent":"a00","tool":"bash","args":{},"result":{"ok":true}}\n' \
  >> "$SB/traces/events.jsonl"
touch -t "$old" "$SB/.pi-sessions/a00/session.jsonl"
run_once --news-sec 45 --idle-sec 180
[[ "$(grep -c '^a00	' "$PROMPT_LOG")" -eq 1 ]] || fail "an agent that came back after an error is nudged normally"
pass "an agent that works after a provider error is watched like any other"

# --- a local model's first turn ---------------------------------------------
# The LM Studio seat on BelkaCTF #6 took about four minutes to answer its
# first turn on a 10 KB contract and was nudged twice before it had emitted a
# token. Nothing it has done yet, and a model served from this machine: that
# is loading, not stalling.
LOCAL_SB="$TMP/local"
mkdir -p "$LOCAL_SB"/{traces,done/agents,threads/main,inbox/L0,.pi-sessions/L0,locks}
cat > "$LOCAL_SB/team.json" <<'JSON'
{"swarm_id": "L", "n": 1, "agents": [{"id": "L0", "role": "worker", "model": "lmstudio/qwen3.8-27b-uncensored"}]}
JSON
: > "$LOCAL_SB/traces/events.jsonl"
printf '{"ts":"2026-01-01T00:00:00.000Z","agent":"L0","tool":"agent_start","args":{},"result":{"ok":true}}\n' \
  >> "$LOCAL_SB/traces/events.jsonl"
: > "$LOCAL_SB/.pi-sessions/L0/session.jsonl"
touch -t "$old" "$LOCAL_SB/.pi-sessions/L0/session.jsonl"
: > "$PROMPT_LOG"
PATH="$TMP/bin:$PATH" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$LOCAL_SB" --once --news-sec 45 --idle-sec 30 >/dev/null 2>&1 || true
[[ "$(grep -c '^L0	' "$PROMPT_LOG")" -eq 0 ]] || fail "a local seat on its first turn must not be nudged"
pass "a seat on a locally served model gets its first turn before the watchdog counts it idle"

# Once it has worked, the ordinary thresholds apply again.
printf '{"ts":"2026-01-01T00:00:10.000Z","agent":"L0","tool":"bash","args":{},"result":{"ok":true}}\n' \
  >> "$LOCAL_SB/traces/events.jsonl"
touch -t "$old" "$LOCAL_SB/.pi-sessions/L0/session.jsonl"
PATH="$TMP/bin:$PATH" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$LOCAL_SB" --once --news-sec 45 --idle-sec 30 >/dev/null 2>&1 || true
[[ "$(grep -c '^L0	' "$PROMPT_LOG")" -eq 1 ]] || fail "a local seat that has worked is nudged like any other"
pass "the first-turn grace is for the first turn only"

echo "idle-nudge.test.sh: all checks passed"

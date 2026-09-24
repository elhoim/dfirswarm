#!/usr/bin/env bash
# idle-nudge: the watchdog for agents that stop calling tools.
#
# A Pi session that ends its turn sits at the prompt until something prompts
# it again. Nothing in the swarm does, so an agent that posted its intro and
# stopped, or finished a slice and waited for nothing, stays idle until the
# wall clock runs out. This sidecar prompts such an agent through Herdr
# ("you are idle, pick up what you said you would do or call done"), a bounded number of
# times, and writes an `idle_nudge` event to the trace each time.
#
# Activity is measured from the agent's Pi session files (Pi appends to them
# on every message) and from the agent's last trace event, whichever is
# newer; an agent past the limit is then asked of Herdr, which reports a pane
# in a long tool call as `working`, and only an `idle` one is prompted. An
# agent with a done or dead marker is left alone; the loop ends when
# done/SWARM_DONE appears or the sandbox goes away. Plain bash 3.2: macOS
# ships that, so no associative arrays here.
#
# Measured over seven forensic runs: 34 agents had to be woken this way, and
# in 32 of those 34 a peer's post had landed while they slept — a median of 26
# seconds into the silence, then unread until the 180-second timer fired. So
# there are two thresholds. An agent with unread posts is woken after
# --news-sec (45 by default), because there is something to read; an agent that
# is quiet with an empty inbox waits the full --idle-sec, because waking it
# buys nothing. The nudge budget is per silence, not per run: an agent that
# comes back and works starts again with a full budget, since the measurement
# shows every agent that spent its three nudges did come back and keep working.
#
# Usage:
#   idle-nudge.sh --sandbox DIR [--idle-sec 180] [--news-sec 45] [--interval 30]
#                 [--max-nudges 3] [--local-first-turn-sec 600] [--once]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SANDBOX=""
IDLE_SEC="${SWARM_IDLE_SEC:-180}"
NEWS_SEC="${SWARM_NEWS_SEC:-45}"
INTERVAL=30
MAX_NUDGES=3
# How long a seat on a locally served model may take over its first turn
# before the watchdog treats the silence as a stall.
LOCAL_FIRST_TURN_SEC="${SWARM_LOCAL_FIRST_TURN_SEC:-600}"
ONCE=0
HERDR="${HERDR_BIN:-herdr}"
# Agents in microVMs (--isolation microvm): the pane runs `msb exec`, so
# Herdr can neither see Pi's state on the screen nor type a prompt Pi will
# take. The hub has both — each agent's extension reports working/idle up its
# link, and a prompt goes down it as a user message.
HUB_ADMIN="${SWARM_HUB_ADMIN:-}"
HUB_STATUS="${SWARM_HUB_STATUS:-}"
HUB_DIR="${SWARM_HUB_DIR:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sandbox) SANDBOX="$2"; shift 2 ;;
    --idle-sec) IDLE_SEC="$2"; shift 2 ;;
    --news-sec) NEWS_SEC="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --max-nudges) MAX_NUDGES="$2"; shift 2 ;;
    --local-first-turn-sec) LOCAL_FIRST_TURN_SEC="$2"; shift 2 ;;
    --once) ONCE=1; shift ;;
    *) echo "idle-nudge: unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ -n "$SANDBOX" && -d "$SANDBOX" ]] || { echo "idle-nudge: --sandbox DIR is required" >&2; exit 2; }
SANDBOX="$(cd "$SANDBOX" && pwd -P)"

# A seat on a model served from this machine or this network. team.json
# carries the model per agent, and models.json says where a provider lives.
is_local_model() { # <agent id>
  local id="$1" model host
  model="$(jq -r --arg id "$id" '.agents[] | select(.id == $id) | .model // empty' "$SANDBOX/team.json" 2>/dev/null || true)"
  [[ -n "$model" ]] || return 1
  case "${model%%/*}" in
    lmstudio|ollama|vllm|llamacpp|llama.cpp|local) return 0 ;;
  esac
  host="$(jq -r --arg p "${model%%/*}" '.providers[$p].baseUrl // empty' "${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}/models.json" 2>/dev/null || true)"
  case "$host" in
    *127.0.0.1*|*localhost*|*192.168.*|*10.*|*.local*) return 0 ;;
  esac
  return 1
}

# Has this agent completed anything at all? A first turn that has not landed
# yet is not a silence to interrupt.
has_worked() { # <agent id>
  grep -q "\"agent\":\"$1\",\"tool\":\"\(bash\|read\|post\|name\|inbox\|wait\|thinking\)\"" \
    "$SANDBOX/traces/events.jsonl" 2>/dev/null
}

# seconds since the agent last did anything, or -1 when nothing is known
idle_seconds() {
  local id="$1"
  python3 - "$SANDBOX" "$id" <<'PY'
import glob, json, os, sys, time
from datetime import datetime
sandbox, aid = sys.argv[1], sys.argv[2]
last = 0.0
for f in glob.glob(os.path.join(sandbox, ".pi-sessions", aid, "*.jsonl")):
    try:
        last = max(last, os.path.getmtime(f))
    except OSError:
        pass
trace = os.path.join(sandbox, "traces", "events.jsonl")
try:
    with open(trace, "rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        fh.seek(max(0, size - 400000))
        tail = fh.read().decode("utf-8", "replace").splitlines()
    for line in reversed(tail):
        if aid not in line:
            continue
        try:
            event = json.loads(line)
        except Exception:
            continue
        # The event's own agent, not any mention of it: an idle_nudge is
        # written by "system" and names the agent in its arguments.
        if event.get("agent") != aid:
            continue
        # The collector's clock, the host's: a VM's own `ts` is the guest's,
        # and a guest whose clock runs ahead would never look idle.
        try:
            last = max(last, datetime.fromisoformat((event.get("recv_ts") or event["ts"]).replace("Z", "+00:00")).timestamp())
        except Exception:
            pass
        break
except OSError:
    pass
print(int(time.time() - last) if last else -1)
PY
}

# How many posts this agent has not read, across the primary thread and any
# thread it joined. The cursor file is what `inbox` advances; the highest post
# id in a thread is the last line of its directory listing.
unread_for() {
  local id="$1" total=0 thread cursor highest
  for thread in "$SANDBOX"/threads/*/; do
    [[ -d "$thread" ]] || continue
    local name
    name="$(basename "$thread")"
    if [[ "$name" != "main" ]]; then
      jq -e --arg id "$id" '.members // [] | index($id)' "$thread/meta.json" >/dev/null 2>&1 || continue
    fi
    highest="$(ls "$thread" 2>/dev/null | sed -n 's/^\([0-9]\{6\}\)-.*/\1/p' | sort -n | tail -1)"
    [[ -n "$highest" ]] || continue
    cursor="$(jq -r --arg t "$name" '.[$t] // 0' "$SANDBOX/inbox/$id/cursors.json" 2>/dev/null || echo 0)"
    [[ "$cursor" =~ ^[0-9]+$ ]] || cursor=0
    total=$(( total + 10#$highest - cursor ))
  done
  [[ "$total" -lt 0 ]] && total=0
  printf '%s\n' "$total"
}

log_event() { # log_event <agent> <idle> <ok> <count>
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
  local line
  line="$(jq -cn --arg ts "$ts" --arg agent "$1" --argjson idle "$2" --argjson ok "$3" --argjson n "$4" \
    '{ts: $ts, agent: "system", tool: "idle_nudge", args: {agent: $agent, idle_seconds: $idle}, result: {ok: $ok, nudges: $n}}')"
  # Through the collector, so this line is chained like every other. Appending
  # here directly used to break the chain for the *next* line the collector
  # wrote, which with this watchdog on by default meant a run reporting its
  # own record as edited every three minutes.
  if ! printf '%s' "$line" | node "$ROOT/scripts/trace-emit.mjs" "$SANDBOX" 2>/dev/null; then
    # Where the line goes depends on whether there is a chain to protect,
    # which is a property of the file and not of the collector's liveness: a
    # socket can exist and still be unreachable.
    #
    # An unchained record — no collector ran, and the kickoff and the report
    # both say so — takes the append, consistent with every other line in it.
    #
    # A chained one must not. Appending there puts an unchained line into a
    # chained record, and the verifier reports the file as "added by
    # something other than the harness": a corruption alarm the harness
    # raises against itself. The line is kept in the spill file instead,
    # which custody reads, so nothing is lost and nothing is falsified.
    if tail -n 1 "$SANDBOX/traces/events.jsonl" 2>/dev/null | grep -q '"prev":'; then
      # Not work/: an agent on the host writes there, and a line in a file
      # an agent can write is that agent's word, not the harness's. traces/
      # is read-only to every pane and every VM whenever there is a chain.
      printf '%s\n' "$line" >> "$SANDBOX/traces/system-spill.jsonl"
    else
      printf '%s\n' "$line" >> "$SANDBOX/traces/events.jsonl"
    fi
  fi
}

# The stop from outside the panes, for a host run. Each pane's extension
# steers its agent and writes the sentinel itself past a cap or the wall
# clock plus the grace period — from inside the pane, where an agent that
# never ends a turn, or a pane whose extension is wedged, never gets there.
# This watchdog runs for the length of the run outside every pane: past a
# limit it claims the stop clock (and says so on the board) when no pane
# has, and past the grace period it writes the sentinel as the harness. A VM
# run's hub does the same from its own process; this is the host's.
host_backstop() {
  [[ -z "$HUB_DIR" ]] || return 0
  local said
  said="$(node --experimental-strip-types --no-warnings -e '
    const [protocol, S] = process.argv.slice(1);
    import(protocol).then(async (P) => {
      if (await P.swarmDoneExists(S)) return;
      const budget = await P.readBudget(S).catch(() => null);
      if (!budget) return;
      const pressure = P.budgetPressure(budget);
      if (!pressure.reason) return;
      const mark = await P.markStopSteer(S, pressure.reason);
      if (mark.claimed) {
        const text = pressure.reason === "cap" ? P.CAP_STEER : `Swarm wall clock hit (${pressure.elapsed_minutes} of ${budget.wall_clock_minutes} minutes). Call done with reason cannot_complete and stop. Do not start new work.`;
        await P.systemPost(S, { tag: "stop", body: text }).catch(() => undefined);
        console.log(`steered ${pressure.reason}`);
      }
      if (Date.now() - Date.parse(mark.at) < P.STOP_GRACE_MS) return;
      const stop = await P.harnessStop(S, pressure.reason, `The harness watchdog stopped the swarm: ${pressure.reason} passed and the agents did not stop within the grace period.`, { verify: true });
      if (stop.created) console.log(`stopped ${pressure.reason}`);
    }).catch(() => undefined);
  ' "$ROOT/extensions/protocol.ts" "$SANDBOX" 2>/dev/null || true)"
  local what reason ts line
  while read -r what reason; do
    [[ -n "$what" ]] || continue
    ts="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
    line="$(jq -cn --arg ts "$ts" --arg t "$(if [[ "$what" == stopped ]]; then echo harness_stop; elif [[ "$reason" == cap ]]; then echo cap_steer; else echo wall_steer; fi)" --arg r "$reason" \
      '{ts: $ts, agent: "system", tool: $t, args: {via: "idle-nudge", reason: $r}, result: {ok: true}}')"
    printf '%s' "$line" | node "$ROOT/scripts/trace-emit.mjs" "$SANDBOX" >/dev/null 2>&1 || printf '%s\n' "$line" >> "$SANDBOX/traces/system-spill.jsonl"
    echo "idle-nudge: $what the swarm ($reason)" >&2
  done <<< "$said"
}

# "id n idle_at_last_nudge" lines. The count is per silence: if the agent has
# done anything since we last nudged it — its idle clock is shorter than it was
# then — this is a new silence and the budget starts again.
# Words in front of an agent: through the hub for a VM, through Herdr otherwise.
prompt_agent() { # <agent id> <text>
  if [[ -n "$HUB_ADMIN" ]]; then
    node "$ROOT/scripts/vm-hub-send.mjs" "$HUB_ADMIN" \
      "$(jq -nc --arg a "$1" --arg t "$2" '{op: "prompt", agent: $a, text: $t, kind: "idle_nudge"}')" >/dev/null 2>&1
  else
    "$HERDR" agent prompt "$1" "$2" >/dev/null 2>&1
  fi
}

STATE="$SANDBOX/traces/idle-nudge.state"
[[ -f "$STATE" ]] || : > "$STATE"
count_of() { awk -v id="$1" '$1 == id { print $2; found = 1 } END { if (!found) print 0 }' "$STATE"; }
mark_of() { awk -v id="$1" '$1 == id { print ($3 == "" ? 0 : $3); found = 1 } END { if (!found) print 0 }' "$STATE"; }
set_count() {
  local tmp="$STATE.tmp.$$"
  awk -v id="$1" -v n="$2" -v m="$3" 'NF && $1 == id { $2 = n; $3 = m; found = 1 } NF { print } END { if (!found) print id, n, m }' "$STATE" > "$tmp"
  mv "$tmp" "$STATE"
}

# The hub is the VMs' board, trace door and stop: a run whose hub died has
# none of the three until it is back. The hub kept what the kickoff gave it
# in its own directory, so it resumes with the same tokens and the same
# clock; this watchdog, which already runs for the length of the run, is
# what notices.
ensure_hub() {
  [[ -n "$HUB_DIR" && -d "$HUB_DIR" && ! -e "$HUB_DIR/.stop" ]] || return 0
  local pid keeper script
  pid="$(cat "$SANDBOX/hub.pid" 2>/dev/null || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then return 0; fi
  # The hub's own keeper (hub-supervise.sh) brings it back; two restarting
  # it at once would start two hubs.
  keeper="$(cat "$HUB_DIR/supervisor.pid" 2>/dev/null || true)"
  if [[ -n "$keeper" ]] && ps -o command= -p "$keeper" 2>/dev/null | grep -q "hub-supervise.sh"; then return 0; fi
  [[ -f "$HUB_DIR/hub-input.json" ]] || return 0
  script="$ROOT/scripts/vm-hub.ts"
  [[ -f "$HUB_DIR/host/scripts/vm-hub.ts" ]] && script="$HUB_DIR/host/scripts/vm-hub.ts"
  nohup node --experimental-strip-types --no-warnings "$script" --resume "$HUB_DIR" >>"$SANDBOX/traces/vm-hub.log" 2>&1 </dev/null &
  echo $! > "$SANDBOX/hub.pid"
  local i
  for ((i = 0; i < 50; i++)); do
    [[ -S "$HUB_DIR/admin.sock" ]] && break
    sleep 0.1
  done
  local ok=false line
  [[ -S "$HUB_DIR/admin.sock" ]] && ok=true
  line="$(jq -nc --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg d "$HUB_DIR" --argjson ok "$ok" \
    '{ts: $ts, agent: "system", tool: "hub_restarted", args: {dir: $d}, result: {ok: $ok}}')"
  printf '%s' "$line" | node "$ROOT/scripts/trace-emit.mjs" "$SANDBOX" >/dev/null 2>&1 || printf '%s\n' "$line" >> "$HUB_DIR/hub-spill.jsonl"
  echo "idle-nudge: the hub was down; restarted (ok=$ok)" >&2
}

while :; do
  [[ -d "$SANDBOX" ]] || exit 0
  [[ -f "$SANDBOX/done/SWARM_DONE" ]] && exit 0
  ensure_hub
  host_backstop
  for id in $(jq -r '.agents[].id' "$SANDBOX/team.json" 2>/dev/null); do
    [[ -e "$SANDBOX/done/agents/$id.done" || -e "$SANDBOX/done/agents/$id.dead" ]] && continue
    idle="$(idle_seconds "$id")"
    [[ "$idle" -ge 0 ]] || continue
    # Something to read makes a short silence worth interrupting; an empty
    # inbox does not. 32 of the 34 stalls measured had a peer's post waiting.
    unread="$(unread_for "$id")"
    if [[ "$unread" -gt 0 ]]; then
      [[ "$idle" -ge "$NEWS_SEC" ]] || continue
    else
      [[ "$idle" -ge "$IDLE_SEC" ]] || continue
    fi
    # A long tool call writes nothing to the session or the trace until it
    # ends; Herdr knows the pane is still working, so ask it before nudging.
    if [[ -n "$HUB_STATUS" ]]; then
      status="$(jq -r --arg id "$id" '.agents[$id].state // empty' "$HUB_STATUS" 2>/dev/null || true)"
    else
      status="$("$HERDR" agent get "$id" 2>/dev/null | jq -r '.result.agent.agent_status // empty' 2>/dev/null || true)"
    fi
    [[ "$status" == "working" ]] && continue
    # An agent whose last turn ended in a provider error is not idle, it is
    # finished: every nudge buys another identical failure. Both DeepSeek
    # agents on the BelkaCTF #6 run spent all three that way against a 402.
    if grep -q "\"agent\":\"$id\",\"tool\":\"agent_error\"" "$SANDBOX/traces/events.jsonl" 2>/dev/null; then
      last_tool="$(grep "\"agent\":\"$id\"" "$SANDBOX/traces/events.jsonl" 2>/dev/null | tail -1 | jq -r '.tool // empty' 2>/dev/null || true)"
      [[ "$last_tool" == "agent_error" ]] && continue
    fi
    # A model served from this machine can take minutes to answer its first
    # turn on a long contract — the LM Studio seat on BelkaCTF #6 took four,
    # and was nudged twice before it had emitted a token. Nothing it has done
    # yet means it is still loading, not stalling.
    if [[ "$idle" -lt "$LOCAL_FIRST_TURN_SEC" ]] && is_local_model "$id" && ! has_worked "$id"; then
      continue
    fi
    # What this agent is still holding. The ninth case ended with two agents
    # holding work/report.md and work/crypto.md after half an hour of silence,
    # and nobody — including them — was told.
    held=""
    if [[ -d "$SANDBOX/locks" ]]; then
      held="$(jq -r --arg id "$id" --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        'select(.owner == $id and .expires_at > $now) | .path' "$SANDBOX/locks"/*.json 2>/dev/null \
        | paste -sd ', ' - || true)"
    fi
    # A shorter idle clock than when we last nudged means the agent worked in
    # between: this is a new silence, and it gets a fresh budget.
    n="$(count_of "$id")"
    mark="$(mark_of "$id")"
    if [[ "$mark" -gt 0 && "$idle" -lt "$mark" ]]; then
      n=0
    fi
    [[ "$n" -lt "$MAX_NUDGES" ]] || continue
    n=$((n + 1))
    set_count "$id" "$n" "$idle"
    minutes=$((idle / 60))
    # "0 posts you have not read" is worse than saying nothing.
    news_line=""
    [[ "$unread" -gt 0 ]] 2>/dev/null && news_line="You have ${unread} post(s) you have not read. "
    if prompt_agent "$id" "You ended your turn ${minutes} minutes ago and the swarm is not done. Ending a turn is not waiting: nothing prompts you again. ${news_line}Read inbox, see what your peers have taken, and get on with what you said you were doing (name() if that has changed); when there is nothing left to take, call the wait tool and keep it open, and call it again each time it returns. Only done ends your part.${held:+ You still hold: ${held} — release_file what you are not working on, or a peer will take it when the lease runs out.} Nudge ${n} of ${MAX_NUDGES}." >/dev/null 2>&1; then
      log_event "$id" "$idle" true "$n"
      echo "idle-nudge: prompted $id after ${idle}s (nudge $n/$MAX_NUDGES)"
    else
      log_event "$id" "$idle" false "$n"
      echo "idle-nudge: could not prompt $id (pane gone?)" >&2
    fi
  done
  [[ "$ONCE" -eq 1 ]] && exit 0
  sleep "$INTERVAL"
done

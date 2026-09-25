#!/usr/bin/env bash
# Stall / timeout reaper. An agent the harness timed out is shown as "?" —
# not `done`, just dead. What counts as a stall is a local choice
# (SPECULATIVE choices are marked below).
#
# For every id in team.json that has neither done/agents/<id>.done nor
# done/agents/<id>.dead, compute last activity as the newest of:
#   - a post by the agent           threads/*/*-<id>.md         (mtime)
#   - a lock refresh by the agent   locks/*.json owner==<id>    (mtime)
#   - an event by the agent         traces/events.jsonl agent==<id> (ts)
#   - inbox cursor advance          inbox/<id>/cursors.json     (mtime)   SPECULATIVE
#   - Pi session activity           .pi-sessions/<id>/**        (mtime)   SPECULATIVE
#   - fallback: budget.json started_at (swarm start) when none of the above exist
# If now - last_activity > timeout: write done/agents/<id>.dead, release the
# agent's locks, append a `reap` line to traces/events.jsonl (same schema as
# the harness: ts, agent, tool, args, result), and with --stop close the
# agent's Herdr pane. The official CLI reference (herdr.dev/docs/cli-reference)
# has no `herdr agent stop`; the documented path is `herdr agent get <id>` ->
# pane id -> `herdr pane close <pane_id>`. Failure is tolerated.
#
# Idempotent: a reaped agent has a .dead marker and is skipped on later runs.
# Requires: bash 4+, jq, GNU or BSD stat/date (both handled).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/trace.sh
. "$ROOT/scripts/lib/trace.sh"
SANDBOX="${SWARM_SANDBOX:-$ROOT/sandbox}"
TIMEOUT="${REAP_TIMEOUT:-960}"
STOP=0
DRY_RUN=0
QUIET=0
HERDR="${HERDR_BIN:-herdr}"

usage() {
  cat <<EOF
Usage: scripts/reap.sh [--sandbox DIR] [--timeout SECONDS] [--stop] [--dry-run] [--quiet]

  --sandbox   Isolated cwd (default: repo sandbox/ or \$SWARM_SANDBOX)
  --timeout   Seconds of silence before an agent is declared dead (default 960, \$REAP_TIMEOUT).
              A pane Herdr reports as working is never reaped: a long bash call
              writes nothing until it ends.
  --stop      Also close the reaped agent's Herdr pane (agent get -> pane close; best effort)
  --dry-run   Report stalls, change nothing
  --quiet     Only print reaped/skipped lines, no per-agent status

Exit code: 0 always (idempotent housekeeping), 2 on usage / missing deps.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sandbox) SANDBOX="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --stop) STOP=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --quiet) QUIET=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

command -v jq >/dev/null 2>&1 || { echo "reap.sh needs jq" >&2; exit 2; }
[[ -f "$SANDBOX/team.json" ]] || { echo "No team.json in $SANDBOX" >&2; exit 2; }
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || { echo "--timeout must be an integer" >&2; exit 2; }

log() { [[ "$QUIET" -eq 1 ]] || echo "$@"; }

# Portable mtime (epoch seconds): GNU stat first, BSD/macOS second.
mtime() {
  stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || echo 0
}

# ISO-8601 (with or without fractional seconds) -> epoch seconds via jq.
iso_to_epoch() {
  printf '%s' "$1" | jq -Rr 'sub("\\.[0-9]+Z$"; "Z") | try fromdateiso8601 catch 0'
}

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }
NOW="$(date +%s)"

max() { if [[ "$1" -ge "$2" ]]; then echo "$1"; else echo "$2"; fi; }

# >>> table lock: this block is identical in scripts/reap.sh and scripts/swarm.sh
# (tests/table-lock.test.sh checks that). The lock-table mutex protocol.ts
# uses, from bash: an exclusive mkdir of the lock and a 10 s wait. A lock older
# than 15 s has no live holder (protocol.ts refreshes its lock while it holds
# it; holders here hold it for a few seconds at most) unless that holder
# stalled. A stalled holder keeps its lock where its pid can be checked: when
# it recorded the same namespace as ours (table_lock_ns) and its pid is live.
# Elsewhere, as for a holder in another pane's pid namespace, age alone
# decides. A stale lock is broken under <lock>.break and judged again there,
# so two waiters cannot both break it. kill -0 fails on a pid we may not
# signal; the panes of one run share a user, so that is a dead one.
TABLE_LOCK_TOKEN="$$.$RANDOM$RANDOM"
# Where a recorded pid can be checked: this pid namespace and boot on Linux,
# this host and boot on macOS; empty when it cannot be told. protocol.ts
# prints the same string (lockNamespace).
table_lock_ns() {
  local ns boot
  if ns="$(readlink /proc/self/ns/pid 2>/dev/null)" && boot="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"; then
    printf 'linux:%s:%s' "$ns" "$boot"
  elif boot="$(sysctl -n kern.boottime 2>/dev/null)" && [[ "$boot" == *"sec = "* ]]; then
    boot="${boot#*sec = }"
    printf 'darwin:%s:%s' "$(hostname)" "${boot%%,*}"
  fi
}
# Stale: older than 15 s and no live holder we can see. A lock that is gone
# (released between the mkdir and the stat) is not stale.
table_lock_stale() {
  local m b now pid ns probe="${1%/*}/.probe.$TABLE_LOCK_TOKEN"
  m="$(stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null)" || return 1
  # protocol.ts's heartbeat rewrites <lock>/beat.
  if b="$(stat -c %Y "$1/beat" 2>/dev/null || stat -f %m "$1/beat" 2>/dev/null)" && (( b > m )); then m=$b; fi
  # "Now" by the clock that stamped the lock: a probe file touched next to it,
  # so a lock stamped through NFS or a microVM's shared directory is aged on
  # the same clock. Our own clock only when the probe cannot be made.
  if touch "$probe" 2>/dev/null && now="$(stat -c %Y "$probe" 2>/dev/null || stat -f %m "$probe" 2>/dev/null)"; then :; else now="$(date +%s)"; fi
  rm -f "$probe"
  (( now - m >= 15 )) || return 1
  : "${TABLE_LOCK_NS=$(table_lock_ns)}"
  ns="$(cat "$1/ns" 2>/dev/null || true)"
  pid="$(cat "$1/pid" 2>/dev/null || true)"
  if [[ -n "$TABLE_LOCK_NS" && "$ns" == "$TABLE_LOCK_NS" && "$pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$pid" 2>/dev/null; then
    return 1
  fi
  return 0
}
table_lock_stamp() {
  : "${TABLE_LOCK_NS=$(table_lock_ns)}"
  echo $$ > "$1/pid"
  printf '%s' "$TABLE_LOCK_NS" > "$1/ns"
  echo "$TABLE_LOCK_TOKEN" > "$1/owner"
}
table_lock_acquire() {
  local dir="$1" deadline=$((SECONDS + 10))
  while ! mkdir "$dir" 2>/dev/null; do
    if table_lock_stale "$dir"; then
      if mkdir "$dir.break" 2>/dev/null; then
        table_lock_stamp "$dir.break"
        if table_lock_stale "$dir"; then rm -rf "$dir"; fi
        table_lock_release "$dir.break"
        continue
      fi
      if table_lock_stale "$dir.break"; then rm -rf "$dir.break"; fi
    fi
    if (( SECONDS >= deadline )); then
      echo "Timed out waiting for locks/${dir##*/}" >&2
      return 1
    fi
    sleep 0.05
  done
  table_lock_stamp "$dir"
}
# Only our own lock: one broken while we stalled may be someone else's now,
# and that is said rather than ignored. The lock is renamed to a name only we
# use before its owner is read, so what is removed is what was judged ours;
# one taken over in between is put back unless a new lock has appeared.
table_lock_release() {
  local tomb="$1.released.$TABLE_LOCK_TOKEN"
  if [[ "$(cat "$1/owner" 2>/dev/null || true)" == "$TABLE_LOCK_TOKEN" ]] && mv "$1" "$tomb" 2>/dev/null; then
    if [[ "$(cat "$tomb/owner" 2>/dev/null || true)" == "$TABLE_LOCK_TOKEN" ]]; then
      rm -rf "$tomb"
      return 0
    fi
    if [[ -e "$1" ]] || ! mv "$tomb" "$1" 2>/dev/null; then rm -rf "$tomb"; fi
  fi
  echo "warning: ${1##*/} was taken over while this process held it; another process may have been inside with it" >&2
}
# <<< table lock
TABLE_LOCK="$SANDBOX/locks/.table.lock"
table_lock() { mkdir -p "$SANDBOX/locks"; table_lock_acquire "$TABLE_LOCK"; }
table_unlock() { table_lock_release "$TABLE_LOCK"; }

# The hub directory a sandbox names, if it is one the harness made: under
# the hubs' parent, which no pane can write. hub.dir itself is only
# tool-protected, and a pane that wrote it a path to its own status.json
# would never be reaped. The parent is swarm.sh's hubs_parent: one per user,
# whatever this process's TMPDIR, and only a directory of this user's own.
hub_dir_of() { # <sandbox>
  local dir parent
  [[ -f "$1/hub.dir" ]] || return 1
  dir="$(cat "$1/hub.dir" 2>/dev/null || true)"
  parent="${SWARM_HUBS_DIR:-${DFIRSWARM_HOME:-$HOME/.dfirswarm}/hubs}"
  [[ -d "$parent" && ! -L "$parent" && -O "$parent" ]] || return 1
  parent="$(cd "$parent" 2>/dev/null && pwd -P)" || return 1
  [[ -n "$dir" && "$dir" == "$parent"/dfs-* && "$dir" != *..* && -d "$dir" ]] || return 1
  # Made for this sandbox (the kickoff wrote which), not another run's.
  [[ "$(cat "$dir/sandbox" 2>/dev/null)" == "$(cd "$1" 2>/dev/null && pwd -P)" ]] || return 1
  printf '%s\n' "$dir"
}

# A long `vol` / `fls` writes nothing to the session or the trace until it
# returns. Herdr already knows the pane is working; idle-nudge.sh asks it
# before nudging, and the reaper must ask before declaring the seat dead.
agent_working() {
  local id="$1" status hub
  # An agent in a microVM is not a Herdr agent: its pane runs `msb exec`. Its
  # own extension reports working/idle to the hub, which writes status.json.
  if hub="$(hub_dir_of "$SANDBOX")"; then
    status="$(jq -r --arg id "$id" '.agents[$id].state // empty' "$hub/status.json" 2>/dev/null || true)"
    [[ "$status" == "working" ]]
    return
  fi
  status="$("$HERDR" agent get "$id" 2>/dev/null | jq -r '.result.agent.agent_status // empty' 2>/dev/null || true)"
  [[ "$status" == "working" ]]
}

last_activity() {
  local id="$1" last=0 f ts
  shopt -s nullglob
  for f in "$SANDBOX"/threads/*/*-"$id".md; do last="$(max "$last" "$(mtime "$f")")"; done
  for f in "$SANDBOX"/locks/*.json; do
    if [[ "$(jq -r '.owner // empty' "$f" 2>/dev/null)" == "$id" ]]; then
      last="$(max "$last" "$(mtime "$f")")"
    fi
  done
  if [[ -f "$SANDBOX/traces/events.jsonl" ]]; then
    ts="$(jq -r --arg id "$id" 'select(.agent == $id) | .ts' "$SANDBOX/traces/events.jsonl" 2>/dev/null | tail -n 1 || true)"
    [[ -n "$ts" ]] && last="$(max "$last" "$(iso_to_epoch "$ts")")"
  fi
  for f in "$SANDBOX/inbox/$id/cursors.json" "$SANDBOX/inbox/$id/seen"; do
    [[ -f "$f" ]] && last="$(max "$last" "$(mtime "$f")")"
  done
  if [[ -d "$SANDBOX/.pi-sessions/$id" ]]; then
    while IFS= read -r f; do last="$(max "$last" "$(mtime "$f")")"; done \
      < <(find "$SANDBOX/.pi-sessions/$id" -type f 2>/dev/null)
  fi
  shopt -u nullglob
  if [[ "$last" -eq 0 && -f "$SANDBOX/budget.json" ]]; then
    ts="$(jq -r '.started_at // empty' "$SANDBOX/budget.json")"
    [[ -n "$ts" ]] && last="$(iso_to_epoch "$ts")"
  fi
  echo "$last"
}

reap_agent() {
  local id="$1" last="$2" idle="$3" released=0 f lock_path
  local dead="$SANDBOX/done/agents/$id.dead"
  local last_iso; last_iso="$(date -u -d "@$last" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$last" +%Y-%m-%dT%H:%M:%SZ)"

  table_lock
  # Re-check under the lock: another reaper may have won the race.
  if [[ -e "$dead" || -e "$SANDBOX/done/agents/$id.done" ]]; then
    table_unlock
    echo "skip $id: already marked while waiting for the table lock"
    return 0
  fi
  mkdir -p "$SANDBOX/done/agents"
  shopt -s nullglob
  for f in "$SANDBOX"/locks/*.json; do
    if [[ "$(jq -r '.owner // empty' "$f" 2>/dev/null)" == "$id" ]]; then
      lock_path="$(jq -r '.path // "?"' "$f")"
      rm -f "$f"
      released=$((released + 1))
      log "  released lock $lock_path"
    fi
  done
  shopt -u nullglob
  cat > "$dead" <<EOF
---
by: reaper
agent: $id
reason: stall
last_activity: $last_iso
idle_seconds: $idle
timeout_seconds: $TIMEOUT
locks_released: $released
at: $(now_iso)
---

Worker $id showed no post, lock refresh, event, or session activity for ${idle}s (> ${TIMEOUT}s). Marked dead by scripts/reap.sh.
EOF
  mkdir -p "$SANDBOX/traces"
  local reap_line
  reap_line="$(jq -cn --arg ts "$(now_iso)" --arg agent "$id" --arg last "$last_iso" \
    --argjson idle "$idle" --argjson timeout "$TIMEOUT" --argjson released "$released" \
    '{ts: $ts, agent: $agent, tool: "reap",
      args: {timeout_seconds: $timeout, reason: "stall"},
      result: {reaped: true, idle_seconds: $idle, last_activity: $last, locks_released: $released}}')"
  # Through the collector when there is one, so the chain stays unbroken.
  trace_emit "$ROOT" "$SANDBOX" "$reap_line"
  table_unlock

  if [[ "$STOP" -eq 1 ]]; then
    if command -v herdr >/dev/null 2>&1; then
      # Official CLI has no `agent stop`; close the pane that hosts the agent.
      # `agent get` JSON shape is not pinned in the docs, so take the first
      # pane_id anywhere in the result.
      local pane
      pane="$(herdr agent get "$id" 2>/dev/null | jq -r '[.. | objects | .pane_id? // empty] | first // empty' 2>/dev/null || true)"
      # A microVM agent's pane is not known to Herdr as an agent; layout.json
      # says which pane is whose. Closing it ends the `msb exec`, and `stop`
      # puts the VM away.
      if [[ -z "$pane" && -f "$SANDBOX/hub.dir" && -f "$SANDBOX/layout.json" ]]; then
        local idx
        idx="$(jq -r --arg id "$id" '[.agents[].id] | index($id) // empty' "$SANDBOX/team.json" 2>/dev/null || true)"
        [[ -n "$idx" ]] && pane="$(jq -r --argjson i "$idx" '.panes[$i] // empty' "$SANDBOX/layout.json" 2>/dev/null || true)"
      fi
      if [[ -n "$pane" ]] && herdr pane close "$pane" >/dev/null 2>&1; then
        log "  herdr pane close $pane ($id): ok"
      else
        log "  herdr pane close for $id: agent not found or close failed (ignored)"
      fi
    else
      log "  herdr not installed; skipping pane close"
    fi
    # A microVM agent's VM outlives its pane: put it away as stop would (its
    # disk kept), so a reaped seat holds no VM and the hub serves nobody.
    local run_id
    run_id="$(jq -r '.run // empty' "$SANDBOX/vm/$id.json" 2>/dev/null || true)"
    if [[ -n "$run_id" ]] && hub_dir_of "$SANDBOX" >/dev/null; then
      if node --experimental-strip-types --no-warnings "$ROOT/scripts/vm.ts" finish --run "$run_id" --sandbox "$SANDBOX" --agent "$id" \
          ${SWARM_REGISTRY:+--registry "$SWARM_REGISTRY"} >>"$SANDBOX/traces/vm-finish.log" 2>&1; then
        log "  VM of $id put away (disk kept)"
      else
        log "  VM of $id: finish failed; see traces/vm-finish.log"
      fi
    fi
  fi
  echo "reaped $id (idle ${idle}s, released ${released} lock(s)) -> done/agents/$id.dead"
  # The operator's notify command, when the run has one.
  SWARM_RUNS_DIR="${SWARM_RUNS_DIR:-${SWARM_REGISTRY:+$(dirname "$SWARM_REGISTRY")}}" \
    bash "$ROOT/scripts/notify.sh" "$SANDBOX" agent_dead "$(jq -nc --arg a "$id" --argjson idle "$idle" '{agent: $a, idle_seconds: $idle, reason: "stall"}')" >/dev/null 2>&1 </dev/null || true
}

reaped=0
while IFS= read -r id; do
  [[ -z "$id" ]] && continue
  if [[ -e "$SANDBOX/done/agents/$id.done" ]]; then
    log "ok   $id: done"
    continue
  fi
  if [[ -e "$SANDBOX/done/agents/$id.dead" ]]; then
    log "dead $id: already reaped"
    continue
  fi
  last="$(last_activity "$id")"
  idle=$((NOW - last))
  if [[ "$last" -eq 0 ]]; then
    log "??   $id: no activity signal and no budget.json baseline; leaving alone"
    continue
  fi
  if (( idle > TIMEOUT )); then
    if agent_working "$id"; then
      log "work $id: idle ${idle}s but $(hub_dir_of "$SANDBOX" >/dev/null && echo "its VM's extension" || echo herdr) says working; leaving alone"
      continue
    fi
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "would reap $id (idle ${idle}s > ${TIMEOUT}s)"
    else
      reap_agent "$id" "$last" "$idle"
      reaped=$((reaped + 1))
    fi
  else
    log "live $id: idle ${idle}s"
  fi
done < <(jq -r '.agents[].id' "$SANDBOX/team.json")

log "reaped $reaped agent(s)"
exit 0

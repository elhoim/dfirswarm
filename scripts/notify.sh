#!/usr/bin/env bash
# notify: tell the operator that something happened to a run.
#
# `swarm.sh start --notify TARGET` (repeatable) keeps its targets outside the
# run, in $SWARM_RUNS_DIR/notify/ (0600): a webhook's URL or an ntfy topic
# is often its secret, and nothing an agent can write may name what the host
# runs or where it sends. This script finds the run by its sandbox in the
# registry, never by anything in the sandbox, and hands the event to each
# target, detached:
#
#   <run>.cmd      the operator's own command, run with one JSON line on its
#                  stdin: {"event": "...", "run": "<id>", "at": "<UTC>",
#                  "event_id": "n-...", "detail": {...identifiers only...}}
#   <run>.targets  one typed target a line:
#                    desktop:          a desktop notification (osascript on
#                                      macOS, notify-send elsewhere)
#                    ntfy:<topic>      a push through ntfy.sh (ntfy:https://host/topic
#                                      for a server of your own)
#                    mailto:<address>  a mail through this host's mail or sendmail
#
# Every target gets an identifier-only envelope: the event, the run, the
# event's id and, of its details, identifiers, enumerations, numbers and the
# counts of lists (an operator request's R-n and kind, the lead's or
# question's id; an agent's id; how many evidence files changed), never what
# was asked, found or printed: it leaves the host. The details themselves are
# kept in the run, traces/notify-events.jsonl, under the event id.
#
# Events: finished, finish_failed, stop_incomplete, budget_cap, wall_clock,
# paused (a cap-pause run held at a cap, or any run held by the model
# provider's limit on every seat: reason provider_limit, with the time the
# provider named, `until`, when it named one), extended (the operator gave it
# room), operator_request (the operator requests' outbox: a lead needs the
# operator, an acquisition, a clarification, a network item, a stop proposed
# when nothing yields), evidence_changed, chain_broken, agent_dead,
# collector_unreachable, hub_down. Each target gets 30 seconds. What one
# said on failure goes to <sandbox>/traces/notify.log. This script never
# blocks its caller and never fails it: a notification is a courtesy, not a
# step of the run.
#
# Usage: notify.sh <sandbox> <event> [<detail json>]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SANDBOX="${1:-}"
EVENT="${2:-}"
DETAIL="${3:-}"
[[ -n "$DETAIL" ]] || DETAIL='{}'
[[ -n "$SANDBOX" && -n "$EVENT" && -d "$SANDBOX" ]] || exit 0
[[ "$EVENT" =~ ^[a-z_]+$ ]] || exit 0
RUNS_DIR="${SWARM_RUNS_DIR:-$ROOT/runs}"
REGISTRY="$RUNS_DIR/registry.json"
[[ -f "$REGISTRY" ]] || exit 0
command -v jq >/dev/null 2>&1 || exit 0

sandbox_real="$(cd "$SANDBOX" && pwd -P)"
# The run whose sandbox this is, by the resolved path (a record may name it
# through a link); the latest such record wins.
run="" r_id="" r_sb=""
while IFS=$'\t' read -r r_id r_sb; do
  [[ -n "$r_id" && -n "$r_sb" ]] || continue
  if [[ "$r_sb" == "$SANDBOX" || "$r_sb" == "$sandbox_real" ]] || { [[ -d "$r_sb" ]] && [[ "$(cd "$r_sb" && pwd -P)" == "$sandbox_real" ]]; }; then
    run="$r_id"
  fi
done < <(jq -r '.runs[]? | [.id, (.sandbox // "")] | @tsv' "$REGISTRY" 2>/dev/null)
[[ -n "$run" && "$run" =~ ^[A-Za-z0-9_-]+$ ]] || exit 0
# Only regular files the operator's own kickoff wrote.
kept() { [[ -f "$1" && ! -L "$1" && -O "$1" ]]; }
cmd_file="$RUNS_DIR/notify/$run.cmd"
targets_file="$RUNS_DIR/notify/$run.targets"
cmd=""
kept "$cmd_file" && cmd="$(cat "$cmd_file" 2>/dev/null || true)"
targets=()
if kept "$targets_file"; then
  while IFS= read -r t; do [[ -n "$t" ]] && targets+=("$t"); done < "$targets_file"
fi
[[ -n "$cmd" || ${#targets[@]} -gt 0 ]] || exit 0

jq -e . >/dev/null 2>&1 <<<"$DETAIL" || DETAIL="$(jq -nc --arg d "$DETAIL" '{text: $d}')"
at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Every event leaves the host as an identifier-only envelope, whoever it
# goes to (docs/adr/0014): the event, the run, an event id, and of the
# details only identifiers and enumerations (a request's R-n and kind, a
# lead's or question's id, an agent's id, a state, a reason), numbers, and
# for a list the count of what it named. What an evidence change named, a
# failed finish's output, an operator request's words: case content, kept
# here, in the run (traces/notify-events.jsonl), under the event id the
# envelope carries. Nothing of it is in the line a command reads, in its
# environment or in a typed target's message.
event_id="n-$(date -u +%Y%m%dT%H%M%SZ)-$(od -An -N4 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n' || echo $$)"
if [[ -d "$sandbox_real/traces" ]]; then
  jq -nc --arg id "$event_id" --arg e "$EVENT" --arg r "$run" --arg at "$at" --argjson d "$DETAIL" \
    '{id: $id, event: $e, run: $r, at: $at, detail: $d}' >> "$sandbox_real/traces/notify-events.jsonl" 2>/dev/null || true
fi
ENVELOPE="$(jq -c '
  def idlike: type == "string" and test("^[A-Za-z0-9_.:@-]{1,64}$");
  ["request", "kind", "run", "lead", "question", "id", "item", "questions", "urgency", "agent", "scope", "reason", "state", "by", "event", "until"] as $keys
  | if type == "object" then . else {} end
  | to_entries
  | map(
      if (.key | IN($keys[])) then
        (if (.value | idlike) or (.value | type) == "number" or (.value | type) == "boolean" then .
         elif (.value | type) == "array" and (.value | all(idlike)) then .
         else empty end)
      elif (.value | type) == "array" then {key: (.key + "_count"), value: (.value | length)}
      elif (.value | type) == "number" or (.value | type) == "boolean" then .
      else empty end)
  | from_entries' <<<"$DETAIL" 2>/dev/null || echo '{}')"
line="$(jq -nc --arg e "$EVENT" --arg r "$run" --arg at "$at" --arg id "$event_id" --argjson d "$ENVELOPE" \
  '{event: $e, run: $r, at: $at, event_id: $id, detail: $d, details: "traces/notify-events.jsonl in the run, under event_id"}')" || exit 0
# What a typed target is told: the event and the run, an operator request's
# ids, and for a pause at the provider's limit when it lifts and what frees
# the machine meanwhile.
words="$(jq -r --arg r "$run" '
  if .event == "operator_request" then
    "operator request \(.detail.request // "?") (\(.detail.kind // "request")\(if .detail.lead then "; lead \(.detail.lead)" else "" end)\(if .detail.question then "; question \(.detail.question)" else "" end)\(if .detail.item then "; item \(.detail.item)" else "" end)\(if .detail.urgency and .detail.urgency != "normal" then "; \(.detail.urgency)" else "" end)): swarm.sh requests \($r) show \(.detail.request // "")"
  elif .event == "paused" and .detail.reason == "provider_limit" then
    "paused: the model provider refused every seat\(if .detail.until then " until \(.detail.until)" else "" end). Every VM is held while it waits; to free the machine, swarm.sh stop \($r) now and swarm.sh resume \($r) after the limit lifts"
  else (.event | gsub("_"; " ")) end' <<<"$line")"
title="DFIR Swarm $run"
log="$sandbox_real/traces/notify.log"
# 30 seconds; a test sets less.
LIMIT="${SWARM_NOTIFY_TIMEOUT:-30}"
[[ "$LIMIT" =~ ^[1-9][0-9]*$ ]] || LIMIT=30
[[ -d "$sandbox_real/traces" ]] || log=/dev/null

# One target, bounded: its own output kept, and said in the log when it fails.
deliver() { # <what> <command...>
  local what="$1" out rc=0 pid waited=0
  shift
  out="$(mktemp "${TMPDIR:-/tmp}/dfs-notify.XXXXXX")"
  "$@" >"$out" 2>&1 &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    if [[ "$waited" -ge "$LIMIT" ]]; then
      kill -TERM "$pid" 2>/dev/null || true
      sleep 1
      kill -KILL "$pid" 2>/dev/null || true
      rc=124
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done
  [[ "$rc" -eq 124 ]] || { wait "$pid"; rc=$?; }
  if [[ "$rc" -ne 0 ]]; then
    {
      printf '%s %s: %s %s (exit %s)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$EVENT" "$what" "$([[ "$rc" -eq 124 ]] && echo "took more than $LIMIT seconds and was stopped" || echo failed)" "$rc"
      sed 's/^/  /' "$out"
    } >>"$log" 2>/dev/null
  fi
  rm -f "$out"
}
run_command() { printf '%s\n' "$line" | bash -c "$cmd"; }
desktop() {
  if command -v osascript >/dev/null 2>&1; then
    osascript -e "display notification \"${words//\"/\\\"}\" with title \"${title//\"/\\\"}\""
  elif command -v notify-send >/dev/null 2>&1; then
    notify-send "$title" "$words"
  else
    echo "no osascript and no notify-send on this host"
    return 3
  fi
}
ntfy() { # <topic or https://host/topic>
  local to="$1" url
  if [[ "$to" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9_-]{1,64}$ ]]; then url="$to"
  elif [[ "$to" =~ ^[A-Za-z0-9_-]{1,64}$ ]]; then url="https://ntfy.sh/$to"
  else echo "not an ntfy topic: $to"; return 3; fi
  command -v curl >/dev/null 2>&1 || { echo "no curl on this host"; return 3; }
  curl -fsS -m "$LIMIT" -H "Title: $title" -d "$words" "$url"
}
# One mailbox, never an option: a leading "-" is refused, and the transport
# is given the address after its option terminator.
MAILBOX_RE='^[A-Za-z0-9_%+][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+$'
mailto() { # <address>
  local to="$1"
  [[ "$to" =~ $MAILBOX_RE ]] || { echo "not one mail address: the notify target is refused"; return 3; }
  if command -v mail >/dev/null 2>&1; then
    printf '%s\n' "$words" | mail -s "$title: $EVENT" -- "$to"
  elif command -v sendmail >/dev/null 2>&1; then
    printf 'To: %s\nSubject: %s: %s\n\n%s\n' "$to" "$title" "$EVENT" "$words" | sendmail -i -- "$to"
  else
    echo "no mail and no sendmail on this host"
    return 3
  fi
}

# Every target, each on its own; detached from the caller.
runner() {
  [[ -n "$cmd" ]] && deliver "the notify command" run_command &
  local t
  for t in "${targets[@]+"${targets[@]}"}"; do
    case "$t" in
      desktop|desktop:*) deliver "the desktop notification" desktop & ;;
      ntfy:*) deliver "the ntfy notification" ntfy "${t#ntfy:}" & ;;
      mailto:*) deliver "the mail notification" mailto "${t#mailto:}" & ;;
      *) printf '%s %s: an unknown notify target was skipped\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$EVENT" >>"$log" 2>/dev/null ;;
    esac
  done
  wait
}
if command -v setsid >/dev/null 2>&1; then
  export -f runner deliver run_command desktop ntfy mailto
  export line cmd log EVENT LIMIT words title MAILBOX_RE
  export TARGETS_LINES="$(printf '%s\n' "${targets[@]+"${targets[@]}"}")"
  setsid bash -c 'targets=(); while IFS= read -r t; do [[ -n "$t" ]] && targets+=("$t"); done <<<"$TARGETS_LINES"; runner' </dev/null >/dev/null 2>&1 &
else
  runner </dev/null >/dev/null 2>&1 &
fi
exit 0

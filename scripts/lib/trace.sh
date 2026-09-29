# Sourced by scripts/swarm.sh, scripts/reap.sh and scripts/idle-nudge.sh. Functions only.

# trace_emit <root> <sandbox> <json-line>: append one harness line to the run's
# trace through the collector; when the collector does not take it, for any
# reason, keep it in traces/system-spill.jsonl.
trace_emit() {
  local root="$1" sandbox="$2" line="$3"
  if ! printf '%s' "$line" | node "$root/scripts/trace-emit.mjs" "$sandbox" 2>/dev/null; then
    # Never appended to events.jsonl. Only the collector writes there, and a
    # line it did not write is one nobody can vouch for: in a chained record
    # the verifier reports it as appended by something other than the
    # harness, and in a record not chained yet it stands before the chain
    # with nothing to say who wrote it. Nor does looking first help: the
    # collector can chain the file between the look and the append. The
    # spill is the harness's own (traces/ is read-only to every pane and
    # every VM whenever there is a chain; not work/, which an agent on the
    # host writes), custody reads it as the harness's, and the package
    # carries it, so nothing is lost and nothing is falsified.
    printf '%s\n' "$line" >> "$sandbox/traces/system-spill.jsonl"
  fi
}

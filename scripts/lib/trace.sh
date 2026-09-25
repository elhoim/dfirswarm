# Sourced by scripts/reap.sh and scripts/idle-nudge.sh. Functions only.

# trace_emit <root> <sandbox> <json-line>: append one harness line to the run's
# trace, through the collector when it answers.
trace_emit() {
  local root="$1" sandbox="$2" line="$3"
  if ! printf '%s' "$line" | node "$root/scripts/trace-emit.mjs" "$sandbox" 2>/dev/null; then
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
    #
    # A file that ends partway through a line spills too, as the collector
    # refuses it: a line appended there fuses into the fragment. The fragment
    # is usually a chained line cut short, and `prev` is its last key, so the
    # `prev` check alone misses it.
    if [[ -s "$sandbox/traces/events.jsonl" && "$(tail -c 1 "$sandbox/traces/events.jsonl" | wc -l | tr -d ' ')" -eq 0 ]] \
      || tail -n 1 "$sandbox/traces/events.jsonl" 2>/dev/null | grep -q '"prev":'; then
      # Not work/: an agent on the host writes there, and a line in a file
      # an agent can write is that agent's word, not the harness's. traces/
      # is read-only to every pane and every VM whenever there is a chain.
      printf '%s\n' "$line" >> "$sandbox/traces/system-spill.jsonl"
    else
      printf '%s\n' "$line" >> "$sandbox/traces/events.jsonl"
    fi
  fi
}

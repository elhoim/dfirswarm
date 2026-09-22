#!/usr/bin/env bash
# What the gate and the collector are handed on stdin, on any host.
#
# One schema, `{tokens, gate}`, built once when the tokens are minted. The
# gate is always given the key; the collector is given it only when the gate
# is up, and an empty key otherwise. The kickoff once started the gate with
# the flat map (the shape was keyed off a variable start_trace_gate clears
# first), so the gate had no key while the collector expected one, and every
# forwarded line was written unverified under `attribution: ancestry`.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

for fn in mint_trace_tokens trace_token_for trace_stdin_json inputs_guard_label; do
  eval "$(sed -n "/^$fn()/,/^}/p" "$ROOT/scripts/swarm.sh")"
done

mint_trace_tokens alpha beta
[[ ${#TRACE_GATE_KEY} -eq 48 ]] || fail "the gate key should be 48 hex characters, got ${#TRACE_GATE_KEY}"
[[ "$(jq -r '.tokens | length' <<<"$TRACE_STDIN_JSON")" == "3" ]] || fail "three tokens (two panes and system): $TRACE_STDIN_JSON"
[[ "$(jq -r '.tokens["'"$(trace_token_for beta)"'"]' <<<"$TRACE_STDIN_JSON")" == "beta" ]] || fail "beta's token should map to beta"
pass "minting builds {tokens, gate} once, with a token per pane and one for the harness"

gated="$(trace_stdin_json gated)"
[[ "$(jq -r .gate <<<"$gated")" == "$TRACE_GATE_KEY" ]] || fail "the gated shape should carry the key: $gated"
[[ "$(jq -r '.tokens | length' <<<"$gated")" == "3" ]] || fail "the gated shape should carry every token"
pass "trace_stdin_json gated carries the key (what the gate, and a collector behind a gate, read)"

open="$(trace_stdin_json open)"
[[ "$(jq -r .gate <<<"$open")" == "" ]] || fail "the open shape should carry an empty key: $open"
[[ "$(jq -r '.tokens | length' <<<"$open")" == "3" ]] || fail "the open shape should still carry every token"
[[ "$(trace_stdin_json)" == "$open" ]] || fail "no argument means open"
pass "trace_stdin_json open carries an empty key (what a collector with no gate reads)"

# The two processes accept exactly that line, and say what they were given.
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trace-stdin.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/sb/traces"
printf '%s' "$gated" | node "$ROOT/scripts/trace-collector.mjs" "$TMP/sb" --tokens --anchor "$TMP/anchor.json" --quiet >"$TMP/coll.log" 2>&1 &
cpid=$!
for _ in $(seq 1 60); do [[ -S "$TMP/sb/traces/.collector.sock" ]] && break; sleep 0.05; done
kill "$cpid" 2>/dev/null || true; wait "$cpid" 2>/dev/null || true
grep -q 'trace-collector: up, 3 token(s), gate key: yes' "$TMP/coll.log" || fail "the collector should log the key it was given: $(cat "$TMP/coll.log")"
printf '%s' '{"alpha-token":"alpha"}' | node "$ROOT/scripts/trace-collector.mjs" "$TMP/sb" --tokens --anchor "$TMP/anchor.json" --quiet >"$TMP/coll2.log" 2>&1 &
cpid=$!
sleep 0.4; kill "$cpid" 2>/dev/null || true; wait "$cpid" 2>/dev/null || true
grep -q 'expected one line of JSON on stdin, {tokens, gate}' "$TMP/coll2.log" || fail "the flat map is no longer a shape the collector reads: $(cat "$TMP/coll2.log")"
pass "the collector reads {tokens, gate} and logs whether it holds the key; the flat map is refused"

[[ "$(inputs_guard_label linux)" == linux* ]] || fail "inputs_guard_label linux: $(inputs_guard_label linux)"
[[ "$(inputs_guard_label landlock)" == landlock* ]] || fail "inputs_guard_label landlock: $(inputs_guard_label landlock)"
[[ "$(inputs_guard_label none)" == none* ]] || fail "inputs_guard_label none: $(inputs_guard_label none)"
pass "every guard mode fsguard has is named on the kickoff line, none of them as 'none'"

echo "trace-stdin: all checks passed"

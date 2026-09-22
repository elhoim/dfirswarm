#!/usr/bin/env bash
# Fixture for scripts/reap.sh. No model, no Herdr. Three fake agents:
#   agent00  posted recently                          -> live
#   agent01  lock refreshed 10 min ago, nothing since -> reaped, lock released
#   agent02  already done                             -> skipped
# Then a second run must change nothing (idempotent).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SB="$(mktemp -d "${TMPDIR:-/tmp}/slice2-reap.XXXXXX")"
trap 'rm -rf "$SB"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

mkdir -p "$SB/threads/main" "$SB/locks" "$SB/done/agents" "$SB/inbox/agent00" "$SB/inbox/agent01" "$SB/inbox/agent02" "$SB/work" "$SB/traces"
cat > "$SB/team.json" <<'EOF'
{ "swarm_id": "reap-test", "n": 3, "agents": [
  { "id": "agent00", "role": "worker" },
  { "id": "agent01", "role": "worker" },
  { "id": "agent02", "role": "worker" } ] }
EOF
old_iso="$(date -u -d '@'$(( $(date +%s) - 1200 )) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r $(( $(date +%s) - 1200 )) +%Y-%m-%dT%H:%M:%SZ)"
cat > "$SB/budget.json" <<EOF
{ "cap_usd": 1, "spent_usd": 0, "wall_clock_minutes": 15, "started_at": "$old_iso" }
EOF

# agent00: fresh post
printf -- '---\nid: 1\nthread: main\nfrom: agent00\nto: all\ntag: intro\n---\n\nhi\n' > "$SB/threads/main/000001-agent00.md"

# agent01: stale lock (mtime 10 minutes ago) + stale post; the lock TTL is
# irrelevant to the reaper, only silence matters.
cat > "$SB/locks/deadbeef.json" <<'EOF'
{ "path": "work/hello.txt", "owner": "agent01", "claimed_at": "2026-01-01T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z" }
EOF
printf -- '---\nid: 2\nthread: main\nfrom: agent01\nto: all\ntag: claim\n---\n\nclaiming\n' > "$SB/threads/main/000002-agent01.md"
touch -d '10 minutes ago' "$SB/locks/deadbeef.json" "$SB/threads/main/000002-agent01.md" "$SB/inbox/agent01/seen" 2>/dev/null \
  || touch -t "$(date -v-10M +%Y%m%d%H%M.%S)" "$SB/locks/deadbeef.json" "$SB/threads/main/000002-agent01.md" "$SB/inbox/agent01/seen"
printf '0\n' > "$SB/inbox/agent00/seen"
# (touch above created inbox/agent01/seen with the old mtime; leave it stale.)

# agent00 also has a fresh event line; agent01 has an old one.
printf '{"ts":"%s","agent":"agent01","tool":"claim_file","args":{"path":"work/hello.txt"},"result":{"ok":true}}\n' "$old_iso" >> "$SB/traces/events.jsonl"
printf '{"ts":"%s","agent":"agent00","tool":"post","args":{"tag":"intro"},"result":{"id":1}}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$SB/traces/events.jsonl"

# agent02: done
printf -- '---\nby: agent02\nreason: finished\n---\n' > "$SB/done/agents/agent02.done"

echo "# dry run"
out="$(bash "$ROOT/scripts/reap.sh" --sandbox "$SB" --timeout 300 --dry-run)"
echo "$out"
grep -q "would reap agent01" <<< "$out" || fail "dry-run should flag agent01"
grep -q "live agent00" <<< "$out" || fail "dry-run should keep agent00 live"
grep -q "ok   agent02: done" <<< "$out" || fail "dry-run should skip done agent02"
[[ -e "$SB/done/agents/agent01.dead" ]] && fail "dry-run must not write .dead"
[[ -f "$SB/locks/deadbeef.json" ]] || fail "dry-run must not release locks"
pass "dry-run reports without changes"

echo "# first run"
out="$(bash "$ROOT/scripts/reap.sh" --sandbox "$SB" --timeout 300 --stop)"
echo "$out"
grep -q "^reaped agent01" <<< "$out" || fail "agent01 should be reaped"
[[ -f "$SB/done/agents/agent01.dead" ]] || fail "missing done/agents/agent01.dead"
grep -q "^reason: stall" "$SB/done/agents/agent01.dead" || fail ".dead frontmatter missing reason"
grep -q "^locks_released: 1" "$SB/done/agents/agent01.dead" || fail ".dead should record 1 released lock"
[[ -e "$SB/locks/deadbeef.json" ]] && fail "agent01's lock should be released"
[[ -e "$SB/done/agents/agent00.dead" ]] && fail "agent00 must stay alive"
[[ -e "$SB/done/agents/agent02.dead" ]] && fail "done agent02 must not be reaped"
[[ -d "$SB/locks/.table.lock" ]] && fail "table lock left behind"
reaped_lines="$(jq -c 'select(.tool == "reap")' "$SB/traces/events.jsonl")"
[[ "$(wc -l <<< "$reaped_lines")" -eq 1 ]] || fail "expected exactly one reaped event"
jq -e 'select(.tool == "reap")
  | (.agent == "agent01")
  and (keys == ["agent","args","result","tool","ts"])
  and (.args.reason == "stall") and (.args.timeout_seconds == 300)
  and (.result.reaped == true) and (.result.locks_released == 1) and (.result.idle_seconds >= 600)' \
  "$SB/traces/events.jsonl" >/dev/null || fail "reap event schema mismatch (expect ts, agent, tool, args, result)"
pass "stale agent reaped, lock released, event appended"

echo "# second run (idempotent)"
before="$(cat "$SB/traces/events.jsonl")"
out="$(bash "$ROOT/scripts/reap.sh" --sandbox "$SB" --timeout 300)"
echo "$out"
grep -q "dead agent01: already reaped" <<< "$out" || fail "second run should skip agent01"
[[ "$(cat "$SB/traces/events.jsonl")" == "$before" ]] || fail "second run appended events"
pass "second run is a no-op"

echo "# tiny timeout reaps the live agent too, exactly once"
sleep 1.1
bash "$ROOT/scripts/reap.sh" --sandbox "$SB" --timeout 0 --quiet >/dev/null
[[ -f "$SB/done/agents/agent00.dead" ]] || fail "agent00 should be reaped at timeout 0"
[[ "$(jq -c 'select(.tool == "reap")' "$SB/traces/events.jsonl" | wc -l)" -eq 2 ]] || fail "expected two reaped events total"
pass "timeout 0 reaps remaining agent once"

echo "# default timeout is above a 10-minute forensic tool"
SB2="$(mktemp -d "${TMPDIR:-/tmp}/slice2-reap-default.XXXXXX")"
mkdir -p "$SB2/threads/main" "$SB2/locks" "$SB2/done/agents" "$SB2/inbox/agent01" "$SB2/work" "$SB2/traces"
cat > "$SB2/team.json" <<'EOF'
{ "swarm_id": "reap-default", "n": 1, "agents": [ { "id": "agent01", "role": "worker" } ] }
EOF
printf -- '---\nid: 1\nthread: main\nfrom: agent01\nto: all\ntag: claim\n---\n\nclaiming\n' > "$SB2/threads/main/000001-agent01.md"
touch -d '10 minutes ago' "$SB2/threads/main/000001-agent01.md" 2>/dev/null \
  || touch -t "$(date -v-10M +%Y%m%d%H%M.%S)" "$SB2/threads/main/000001-agent01.md"
out="$(bash "$ROOT/scripts/reap.sh" --sandbox "$SB2" --dry-run)"
echo "$out"
grep -q "would reap agent01" <<< "$out" && fail "default 960s timeout must not reap a 10-minute silence"
grep -q "live agent01" <<< "$out" || fail "a 10-minute silence should still be live at the default timeout"
rm -rf "$SB2"
pass "default timeout leaves a 10-minute silence alone"

echo "# herdr working is not a stall"
SB3="$(mktemp -d "${TMPDIR:-/tmp}/slice2-reap-working.XXXXXX")"
mkdir -p "$SB3/threads/main" "$SB3/locks" "$SB3/done/agents" "$SB3/inbox/agent01" "$SB3/work" "$SB3/traces" "$SB3/bin"
cat > "$SB3/team.json" <<'EOF'
{ "swarm_id": "reap-working", "n": 1, "agents": [ { "id": "agent01", "role": "worker" } ] }
EOF
cat > "$SB3/locks/deadbeef.json" <<'EOF'
{ "path": "work/hello.txt", "owner": "agent01", "claimed_at": "2026-01-01T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z" }
EOF
printf -- '---\nid: 1\nthread: main\nfrom: agent01\nto: all\ntag: claim\n---\n\nclaiming\n' > "$SB3/threads/main/000001-agent01.md"
touch -d '10 minutes ago' "$SB3/locks/deadbeef.json" "$SB3/threads/main/000001-agent01.md" 2>/dev/null \
  || touch -t "$(date -v-10M +%Y%m%d%H%M.%S)" "$SB3/locks/deadbeef.json" "$SB3/threads/main/000001-agent01.md"
cat > "$SB3/bin/herdr" <<'SH'
#!/usr/bin/env bash
printf '{"result":{"agent":{"agent_status":"working"}}}\n'
SH
chmod +x "$SB3/bin/herdr"
out="$(HERDR_BIN="$SB3/bin/herdr" bash "$ROOT/scripts/reap.sh" --sandbox "$SB3" --timeout 300)"
echo "$out"
grep -q "herdr says working" <<< "$out" || fail "a working pane should be skipped: $out"
[[ -e "$SB3/done/agents/agent01.dead" ]] && fail "a working pane must not be reaped"
[[ -f "$SB3/locks/deadbeef.json" ]] || fail "a working pane must keep its locks"
cat > "$SB3/bin/herdr" <<'SH'
#!/usr/bin/env bash
printf '{"result":{"agent":{"agent_status":"idle"}}}\n'
SH
chmod +x "$SB3/bin/herdr"
out="$(HERDR_BIN="$SB3/bin/herdr" bash "$ROOT/scripts/reap.sh" --sandbox "$SB3" --timeout 300)"
grep -q "^reaped agent01" <<< "$out" || fail "an idle stale pane should still be reaped: $out"
[[ -f "$SB3/done/agents/agent01.dead" ]] || fail "idle stale pane should be marked dead"
rm -rf "$SB3"
pass "herdr working skips the reaper; idle still reaps"

echo "# status must not reap"
grep -A 30 '^cmd_status()' "$ROOT/scripts/swarm.sh" | grep -q 'reap.sh' \
  && fail "swarm.sh status must not run reap.sh"
pass "status does not reap"

echo "reap.test.sh: all checks passed"

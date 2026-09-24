#!/usr/bin/env bash
# The shell copies of the lock-table mutex, in scripts/reap.sh and
# scripts/swarm.sh, against the same rules as protocol.ts (tests/table-lock.test.ts):
#   * a lock older than 15 s is broken whatever pid it records, because a
#     pane's pid belongs to its own pid namespace and says nothing here;
#   * it is not broken while another waiter is breaking it;
#   * a holder does not remove a lock that is no longer its own.
# The functions are lifted out of the scripts rather than re-implemented.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/table-lock.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

# From the first line matching $2 to the end of table_unlock, one-line or not.
lift() {
  awk -v start="$2" '
    $0 ~ start { on = 1 }
    on { print }
    on && /^table_unlock\(\)/ { if ($0 ~ /}[[:space:]]*$/) exit; last = 1; next }
    on && last && /^}/ { exit }
  ' "$1"
}

backdate() {
  touch -d '20 seconds ago' "$1" 2>/dev/null || touch -t "$(date -v-20S +%Y%m%d%H%M.%S)" "$1"
}

check_copy() {
  local name="$1" lock="$2" start
  # Each case in its own subshell, so one copy's globals never reach the other.
  (
    eval "$3"
    mkdir -p "$lock"
    echo $$ > "$lock/pid"            # live here, but not the holder
    backdate "$lock"
    start=$SECONDS
    lock_call || fail "$name: a stale lock recording a live pid was not broken"
    (( SECONDS - start < 5 )) || fail "$name: took $((SECONDS - start)) s to break a stale lock"
    unlock_call
    [[ -d "$lock" ]] && fail "$name: its own lock was left behind"
    pass "$name: a stale lock is broken whatever pid it records"
  )
  (
    eval "$3"
    mkdir -p "$lock" "$lock.break"
    echo 999999999 > "$lock/pid"
    backdate "$lock"
    lock_call &
    local waiter=$!
    sleep 0.5
    [[ "$(cat "$lock/pid" 2>/dev/null || true)" == "999999999" ]] \
      || fail "$name: the lock was broken while another waiter was breaking it"
    rm -rf "$lock.break"
    wait "$waiter" || fail "$name: the waiter did not get the lock once the break was done"
    rm -rf "$lock"
    pass "$name: one waiter breaks a stale lock at a time"
  )
  (
    eval "$3"
    lock_call || fail "$name: could not take a free lock"
    echo someone-else > "$lock/owner"   # ours was broken and taken meanwhile
    unlock_call
    [[ "$(cat "$lock/owner" 2>/dev/null || true)" == "someone-else" ]] \
      || fail "$name: released a lock someone else holds"
    rm -rf "$lock"
    pass "$name: a holder removes only its own lock"
  )
  (
    eval "$3"
    # Released between the waiter's look at it and its stat: the stat fails,
    # which must not read as infinitely old. A stat that fails stands in for
    # the lock vanishing in that gap.
    mkdir -p "$lock"
    stat() { return 1; }
    if stale_call "$lock"; then fail "$name: a lock that is gone was judged stale"; fi
    unset -f stat
    rm -rf "$lock"
    pass "$name: a lock that is gone is not stale"
  )
}

SB="$TMP/reap"; mkdir -p "$SB/locks"
reap_fns="SANDBOX='$SB'
$(sed -n '/^mtime() {/,/^}/p' "$ROOT/scripts/reap.sh")
$(lift "$ROOT/scripts/reap.sh" '^TABLE_LOCK=')
lock_call() { table_lock; }
unlock_call() { table_unlock; }
stale_call() { lock_stale \"\$1\"; }"
check_copy reap.sh "$SB/locks/.table.lock" "$reap_fns"

SB2="$TMP/swarm"; mkdir -p "$SB2/locks"
swarm_fns="$(lift "$ROOT/scripts/swarm.sh" '^# The lock-table mutex protocol.ts and reap.sh use')
lock_call() { table_lock '$SB2'; }
unlock_call() { table_unlock '$SB2'; }
stale_call() { table_lock_stale \"\$1\"; }"
check_copy swarm.sh "$SB2/locks/.table.lock" "$swarm_fns"

echo "table-lock: all passed"

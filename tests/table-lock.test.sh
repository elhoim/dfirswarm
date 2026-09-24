#!/usr/bin/env bash
# The shell copies of the lock-table mutex, in scripts/reap.sh and
# scripts/swarm.sh, against the same rules as protocol.ts (tests/table-lock.test.ts):
#   * a lock older than 15 s is broken whatever pid it records, unless it
#     recorded our own namespace and that pid is live here: a pane's pid
#     belongs to its own pid namespace and says nothing elsewhere, but where it
#     can be checked it keeps a stalled holder's lock;
#   * it is not broken while another waiter is breaking it;
#   * a holder does not remove a lock that is no longer its own, and says so;
#   * a lock whose stat fails is not stale.
# The functions are lifted out of the scripts rather than re-implemented, and
# the two copies must be the same text.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/table-lock.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

block() { sed -n '/^# >>> table lock/,/^# <<< table lock/p' "$1"; }
wrappers() { grep -E '^(TABLE_LOCK=|table_lock\(\)|table_unlock\(\))' "$1"; }

[[ -n "$(block "$ROOT/scripts/reap.sh")" ]] || fail "no table lock block in reap.sh"
[[ "$(block "$ROOT/scripts/reap.sh")" == "$(block "$ROOT/scripts/swarm.sh")" ]] \
  || fail "the table lock blocks in reap.sh and swarm.sh differ"
pass "reap.sh and swarm.sh carry the same table lock"

backdate() {
  touch -d '20 seconds ago' "$1" 2>/dev/null || touch -t "$(date -v-20S +%Y%m%d%H%M.%S)" "$1"
}

dead_pid() { local p; sleep 0 & p=$!; wait "$p" 2>/dev/null || true; echo "$p"; }

check_copy() {
  local name="$1" lock="$2" start
  # Each case in its own subshell, so one copy's globals never reach the other.
  (
    eval "$3"
    mkdir -p "$lock"
    echo $$ > "$lock/pid"            # live here, but not the holder
    printf 'linux:pid:[1]:another-boot' > "$lock/ns"   # recorded somewhere else
    backdate "$lock"
    start=$SECONDS
    lock_call || fail "$name: a stale lock recording a live pid in another namespace was not broken"
    (( SECONDS - start < 5 )) || fail "$name: took $((SECONDS - start)) s to break a stale lock"
    unlock_call
    [[ -d "$lock" ]] && fail "$name: its own lock was left behind"
    pass "$name: a stale lock from another namespace is broken whatever pid it records"
  )
  (
    eval "$3"
    mkdir -p "$lock"
    echo $$ > "$lock/pid"            # no ns: an older lock, judged by age alone
    backdate "$lock"
    stale_call "$lock" || fail "$name: a stale lock with no namespace was kept"
    rm -rf "$lock"
    pass "$name: a stale lock with no namespace is judged by age alone"
  )
  (
    eval "$3"
    local ns; ns="$(table_lock_ns)"
    if [[ -z "$ns" ]]; then pass "$name: SKIP namespace cases (no namespace on this host)"; exit 0; fi
    mkdir -p "$lock"
    echo $$ > "$lock/pid"
    printf '%s' "$ns" > "$lock/ns"
    backdate "$lock"
    # The holder stalled past the stale age but is alive where we can see it.
    if stale_call "$lock"; then fail "$name: a stalled holder's lock was judged stale although its pid is live here"; fi
    dead_pid > "$lock/pid"
    backdate "$lock"
    stale_call "$lock" || fail "$name: a stale lock whose holder is dead here was kept"
    rm -rf "$lock"
    pass "$name: a stalled holder keeps its lock where its pid can be checked"
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
    local said; said="$(unlock_call 2>&1)"
    [[ "$(cat "$lock/owner" 2>/dev/null || true)" == "someone-else" ]] \
      || fail "$name: released a lock someone else holds"
    [[ "$said" == *"taken over"* ]] || fail "$name: a lost lock went unreported at release"
    rm -rf "$lock"
    pass "$name: a holder removes only its own lock, and says when it is not"
  )
  (
    eval "$3"
    lock_call || fail "$name: could not take a free lock"
    unlock_call
    [[ -z "$(ls -A "${lock%/*}")" ]] || fail "$name: release left $(ls -A "${lock%/*}") behind"
    lock_call || fail "$name: could not take a free lock"
    # Taken over between the owner check and the rename: the rename moves
    # someone else's lock, which must be put back, not removed.
    # shellcheck disable=SC2329  # called by table_lock_release
    mv() { echo someone-else > "$1/owner"; unset -f mv; command mv "$@"; }
    local said; said="$(unlock_call 2>&1)"
    [[ "$(cat "$lock/owner" 2>/dev/null || true)" == "someone-else" ]] \
      || fail "$name: a lock taken over during release was not put back"
    [[ "$(ls -A "${lock%/*}")" == "${lock##*/}" ]] || fail "$name: release left $(ls -A "${lock%/*}") behind"
    [[ "$said" == *"taken over"* ]] || fail "$name: a lock taken over during release went unreported"
    rm -rf "$lock"
    pass "$name: release renames before it judges, and puts back a lock that is not its own"
  )
  (
    eval "$3"
    # Released between the waiter's look at it and its stat: the stat fails,
    # which must not read as infinitely old. A stat that fails stands in for
    # the lock vanishing in that gap.
    mkdir -p "$lock"
    # shellcheck disable=SC2329  # called by table_lock_stale
    stat() { return 1; }
    if stale_call "$lock"; then fail "$name: a lock that is gone was judged stale"; fi
    unset -f stat
    rm -rf "$lock"
    pass "$name: a lock that is gone is not stale"
  )
}

SB="$TMP/reap"; mkdir -p "$SB/locks"
reap_fns="SANDBOX='$SB'
$(block "$ROOT/scripts/reap.sh")
$(wrappers "$ROOT/scripts/reap.sh")
lock_call() { table_lock; }
unlock_call() { table_unlock; }
stale_call() { table_lock_stale \"\$1\"; }"
check_copy reap.sh "$SB/locks/.table.lock" "$reap_fns"

SB2="$TMP/swarm"; mkdir -p "$SB2/locks"
swarm_fns="$(block "$ROOT/scripts/swarm.sh")
$(wrappers "$ROOT/scripts/swarm.sh")
lock_call() { table_lock '$SB2'; }
unlock_call() { table_unlock '$SB2'; }
stale_call() { table_lock_stale \"\$1\"; }"
check_copy swarm.sh "$SB2/locks/.table.lock" "$swarm_fns"

echo "table-lock: all passed"

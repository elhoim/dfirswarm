#!/usr/bin/env bash
# Run every shell suite and report each one, then fail if any failed.
#
# `npm run test:bash` used to be one `&&` chain, so the first suite that
# failed hid every suite after it: a fix could not be judged against the
# whole set without re-running by hand. Here every suite runs, the verdict is
# printed per suite, and the exit code says whether all of them passed.
#
#   scripts/test-bash.sh            every suite
#   scripts/test-bash.sh reap inputs   only these (by file stem)
#   scripts/test-bash.sh --shard 1/2   the first of two shards of every suite
#   scripts/test-bash.sh --shard 2/2 --list   the stems of the second, run nothing
#
# A shard is for a CI job that runs part of the suites: they are dealt out by
# the time each takes (tests/shell-suites.weights, longest first onto the
# shard with the least so far), so the same suites land in the same shard on
# every host, and the shards together hold every suite exactly once
# (tests/ci-shards.test.ts checks it).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The suites choose where their runs are: an operator's exported isolation,
# image, lock file or pack home would have pointed their kickoffs somewhere
# else. A run is in microVMs unless it says otherwise, so each suite that
# tests host runs exports SWARM_ISOLATION=host itself (and holds for a run of
# one), and microvm-flags checks the default with nothing set.
unset SWARM_ISOLATION SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
# Nor do they reach the operator's own msb database (a finish that removes a
# stand-in VM scrubs it) or the VM hubs' directory: both are the suite run's.
# Under /tmp, not the per-user TMPDIR: a hub's socket path must stay under
# the 104 bytes macOS allows, and /var/folders/… leaves no room for it.
SUITE_HOME="$(mktemp -d /tmp/dfh.XXXXXX)"
trap 'rm -rf "$SUITE_HOME"' EXIT
export MSB_HOME="$SUITE_HOME/msb-home" SWARM_HUBS_DIR="$SUITE_HOME/dfirswarm-hubs"
# A stop seals a draft release with the install's machine key: the suites'
# is made in their own home, never in the operator's.
export SWARM_SIGNERS_HOME="$SUITE_HOME/dfirswarm-signers"
mkdir -p "$MSB_HOME"
# Every tests/*.test.sh, so adding a suite needs no edit here.
ALL=()
for f in "$ROOT"/tests/*.test.sh; do
  [[ -f "$f" ]] || continue
  name="${f##*/}"
  ALL+=("${name%.test.sh}")
done
SHARD="" LIST_ONLY=0 NAMED=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --shard) SHARD="${2:-}"; shift; [[ $# -gt 0 ]] && shift ;;
    --shard=*) SHARD="${1#--shard=}"; shift ;;
    --list) LIST_ONLY=1; shift ;;
    -*) echo "test-bash: unknown option: $1" >&2; exit 2 ;;
    *) NAMED+=("$1"); shift ;;
  esac
done

# The suites of shard I of N: every suite weighed (seconds on the hosted macOS
# runner, 20 for one the weights file does not know), longest first, each onto
# the shard with the least load so far, a tie to the lowest number.
shard_suites() {
  local i="${1%%/*}" n="${1##*/}"
  printf '%s\n' ${ALL[@]+"${ALL[@]}"} \
    | awk -v wf="$ROOT/tests/shell-suites.weights" -v def=20 '
        BEGIN { while ((getline l < wf) > 0) { sub(/#.*/, "", l); split(l, a, " "); if (a[1] != "") w[a[1]] = a[2] } }
        { print (($1 in w) ? w[$1] : def), $1 }' \
    | LC_ALL=C sort -k1,1nr -k2,2 \
    | awk -v n="$n" -v i="$i" '
        { b = 1; for (k = 2; k <= n; k++) if (load[k] < load[b]) b = k; load[b] += $1; if (b == i) print $2 }' \
    | LC_ALL=C sort
}

if [[ -n "$SHARD" ]]; then
  if ! [[ "$SHARD" =~ ^[1-9][0-9]*/[1-9][0-9]*$ ]] || (( ${SHARD%%/*} > ${SHARD##*/} )); then
    echo "test-bash: --shard wants I/N with 1 <= I <= N, got '$SHARD'" >&2
    exit 2
  fi
  if [[ ${#NAMED[@]} -gt 0 ]]; then
    echo "test-bash: --shard takes every suite, not named ones" >&2
    exit 2
  fi
  SUITES=()
  while IFS= read -r s; do SUITES+=("$s"); done < <(shard_suites "$SHARD")
elif [[ ${#NAMED[@]} -gt 0 ]]; then
  SUITES=("${NAMED[@]}")
else
  SUITES=(${ALL[@]+"${ALL[@]}"})
fi
if [[ $LIST_ONLY -eq 1 ]]; then
  printf '%s\n' ${SUITES[@]+"${SUITES[@]}"}
  exit 0
fi
if [[ ${#SUITES[@]} -eq 0 ]]; then
  echo "test-bash: no suites found under $ROOT/tests" >&2
  exit 2
fi
[[ -z "$SHARD" ]] || echo "test-bash: shard $SHARD: ${#SUITES[@]} of ${#ALL[@]} suites"

failed=()
started=$SECONDS
for suite in "${SUITES[@]}"; do
  file="$ROOT/tests/$suite.test.sh"
  if [[ ! -f "$file" ]]; then
    echo "test-bash: no such suite: $suite (tests/$suite.test.sh)" >&2
    failed+=("$suite")
    continue
  fi
  echo "=== tests/$suite.test.sh"
  at=$SECONDS
  if bash "$file"; then
    echo "=== ok   $suite ($((SECONDS - at))s)"
  else
    echo "=== FAIL $suite ($((SECONDS - at))s)"
    failed+=("$suite")
  fi
done

echo
if [[ ${#failed[@]} -gt 0 ]]; then
  echo "shell suites: ${#failed[@]} of ${#SUITES[@]} failed: ${failed[*]} ($((SECONDS - started))s)" >&2
  exit 1
fi
echo "shell suites: ${#SUITES[@]} of ${#SUITES[@]} passed ($((SECONDS - started))s)"

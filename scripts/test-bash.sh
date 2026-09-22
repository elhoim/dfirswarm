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
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Every tests/*.test.sh, so adding a suite needs no edit here.
ALL=()
for f in "$ROOT"/tests/*.test.sh; do
  [[ -f "$f" ]] || continue
  name="$(basename "$f")"
  ALL+=("${name%.test.sh}")
done
SUITES=("$@")
[[ ${#SUITES[@]} -gt 0 ]] || SUITES=(${ALL[@]+"${ALL[@]}"})
if [[ ${#SUITES[@]} -eq 0 ]]; then
  echo "test-bash: no suites found under $ROOT/tests" >&2
  exit 2
fi

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

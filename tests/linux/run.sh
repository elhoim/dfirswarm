#!/usr/bin/env bash
# Run the test suites on Linux, in Docker, twice: once with user namespaces
# (a host, or a container started with seccomp/apparmor unconfined) and once
# under Docker's default profile, where only Landlock is left. Both are real
# hosts the harness meets.
#
#   tests/linux/run.sh [--build] [ns|landlock|both] [suite...]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="dfirswarm-linux-test"
build=0; which="both"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --build) build=1; shift ;;
    ns|landlock|both) which="$1"; shift ;;
    *) break ;;
  esac
done
if [[ "$build" -eq 1 ]] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -q -t "$IMAGE" "$ROOT/tests/linux" >/dev/null
fi
# The tree is copied into the user's home, node_modules excluded: a macOS
# node_modules carries macOS binaries. npm ci runs once per container start
# against the lockfile.
inner='set -e; mkdir -p "$HOME/work"; (cd /src && tar --exclude=node_modules --exclude=.git --exclude=ui/dist -cf - .) | (cd "$HOME/work" && tar -xf -); cd "$HOME/work";
  npm ci --ignore-scripts --no-audit --no-fund --loglevel=error 2>&1 | tail -3;
  echo "host: $(uname -r) · userns: $(unshare -rm true 2>/dev/null && echo yes || echo no) · landlock: $(python3 -c "import ctypes;print(ctypes.CDLL(None).syscall(444,None,0,1))" 2>/dev/null)";
  bash scripts/test-bash.sh "$@"'
run() {
  local label="$1"; shift
  echo "=== linux · $label ==="
  docker run --rm "$@" -v "$ROOT:/src:ro" "$IMAGE" bash -c "$inner" bash ${SUITES[@]+"${SUITES[@]}"}
}
SUITES=("$@")
# `;;&` would be neater and is bash 4; macOS ships bash 3.2 and this runs there.
rc=0
if [[ "$which" == "ns" || "$which" == "both" ]]; then
  run "user namespaces available" --security-opt seccomp=unconfined --security-opt apparmor=unconfined || rc=1
fi
if [[ "$which" == "landlock" || "$which" == "both" ]]; then
  run "Docker default profile (Landlock only)" || rc=1
fi
exit "$rc"

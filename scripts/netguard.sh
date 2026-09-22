#!/usr/bin/env bash
# netguard: run a command with egress limited to a provider-host allowlist.
#
# The safe default is no network at all. A swarm still needs
# exactly one thing on the network: the model provider API. This wrapper
# gives the command *no* network, then punches one hole through a local
# allowlisting HTTP proxy.
#
# How (Linux, unprivileged, no root, no iptables):
#   1. Host namespace: start scripts/netguard-proxy.mjs (Node) on a Unix
#      socket. It is the only thing that does DNS or opens outbound TCP, and
#      only to hosts on the allowlist (CONNECT for HTTPS, absolute-form HTTP).
#   2. `unshare -rn`  -> new user+network namespace with only `lo` (down).
#      Bring `lo` up (iproute2 `ip`, or a python3 ioctl when `ip` is absent).
#   3. `unshare -U --map-user=<real uid>` inside -> the command sees its real
#      uid again instead of the mapped root.
#   4. Inside the namespace, a TCP->Unix bridge listens on 127.0.0.1:PORT and
#      forwards to the proxy socket (Unix sockets are filesystem objects, so
#      they cross network namespaces). HTTP(S)_PROXY point at the bridge.
#   Direct connections from inside fail with ENETUNREACH / "Could not resolve
#   host" — fail-closed even if the command ignores the proxy variables.
#
# Fallback `--mode proxy-only` (no namespaces): sets the proxy env only.
# That is ADVISORY — a process that ignores HTTP(S)_PROXY has full egress.
# This is also the only mode on macOS (no `unshare`): macOS is UNKNOWN /
# untested here; pf rules would be the equivalent and need root.
#
# Client caveat: Node's global fetch ignores HTTP(S)_PROXY unless
# NODE_USE_ENV_PROXY=1 is honoured (Node 24+, backported to 22.21+). We export
# it. Bun's fetch honours the variables natively. Whether the installed Pi
# binary honours them is UNVERIFIED without a provider key — inside netns the
# failure mode is "no network", never "unfiltered network".
#
# Usage:
#   scripts/netguard.sh [--allow h1,h2] [--allow-file F] [--port N]
#                       [--mode auto|netns|proxy-only] [--log FILE] [--dry-run]
#                       -- CMD [ARGS...]
#   NETGUARD_ALLOW="host1,host2" adds to the default list.
#   Default allowlist: api.openai.com api.deepseek.com api.x.ai
#                      generativelanguage.googleapis.com api.anthropic.com
#                      platform.claude.com chatgpt.com auth.openai.com
#   The last four are the subscription paths: Claude and ChatGPT/Codex plans
#   each need their API host plus the endpoint Pi refreshes the OAuth token on.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROXY_JS="$ROOT/scripts/netguard-proxy.mjs"
DEFAULT_ALLOW="api.openai.com,api.deepseek.com,api.x.ai,generativelanguage.googleapis.com,api.anthropic.com,platform.claude.com,chatgpt.com,auth.openai.com"
ALLOW="$DEFAULT_ALLOW"
ALLOW_FILE=""
PORT="${NETGUARD_PORT:-3128}"
MODE="${NETGUARD_MODE:-auto}"
LOG="${NETGUARD_LOG:-}"
DRY_RUN=0

usage() {
  cat <<EOF
Usage: scripts/netguard.sh [options] -- CMD [ARGS...]

  --allow LIST      Comma-separated hosts added to the default provider list
                    (exact host, .suffix / *.suffix for subdomains, host:port).
                    A host with no port means 443 and nothing else: a bare
                    127.0.0.1 would otherwise open every port on the box,
                    including this console's. Name the port for anything else.
  --allow-file F    One allowlist entry per line (# comments ok)
  --only LIST       Replace the default list instead of adding to it
  --port N          Proxy port visible to CMD (default 3128)
  --mode M          auto | netns | proxy-only (default auto)
  --log FILE        Append ALLOW/DENY lines here (also printed to stderr)
  --dry-run         Print the plan and exit
  -h, --help

Env: NETGUARD_ALLOW (added to the list), NETGUARD_PORT, NETGUARD_MODE, NETGUARD_LOG
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --allow) ALLOW="$ALLOW,$2"; shift 2 ;;
    --only) ALLOW="$2"; shift 2 ;;
    --allow-file) ALLOW_FILE="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --log) LOG="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ $# -eq 0 ]]; then
  echo "netguard: no command given (use -- CMD ...)" >&2
  usage
  exit 2
fi

command -v node >/dev/null 2>&1 || { echo "netguard: node is required" >&2; exit 2; }
[[ -f "$PROXY_JS" ]] || { echo "netguard: missing $PROXY_JS" >&2; exit 2; }

if [[ -n "${NETGUARD_ALLOW:-}" ]]; then ALLOW="$ALLOW,$NETGUARD_ALLOW"; fi
if [[ -n "$ALLOW_FILE" ]]; then
  [[ -f "$ALLOW_FILE" ]] || { echo "netguard: allow file not found: $ALLOW_FILE" >&2; exit 2; }
  while IFS= read -r line; do
    line="${line%%#*}"; line="${line// /}"
    [[ -n "$line" ]] && ALLOW="$ALLOW,$line"
  done < "$ALLOW_FILE"
fi
# normalise: lowercase, dedupe, drop empties
ALLOW="$(tr ',' '\n' <<< "$ALLOW" | tr '[:upper:]' '[:lower:]' | sed '/^$/d' | awk '!seen[$0]++' | paste -sd, -)"

lo_up_method() {
  if command -v ip >/dev/null 2>&1; then echo "ip"; return; fi
  if command -v python3 >/dev/null 2>&1; then echo "python3"; return; fi
  echo "none"
}

netns_supported() {
  command -v unshare >/dev/null 2>&1 || return 1
  unshare -rn true 2>/dev/null || return 1
  [[ "$(lo_up_method)" != "none" ]] || return 1
  return 0
}

case "$MODE" in
  auto)
    if netns_supported; then MODE="netns"; else
      MODE="proxy-only"
      echo "netguard: WARNING unprivileged network namespace unavailable; falling back to proxy-only (advisory, not enforced)" >&2
    fi ;;
  netns)
    netns_supported || { echo "netguard: --mode netns requested but 'unshare -rn' or lo-up is unavailable here" >&2; exit 3; } ;;
  proxy-only) ;;
  *) echo "netguard: unknown --mode $MODE" >&2; exit 2 ;;
esac

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "mode:      $MODE"
  echo "allowlist: $ALLOW"
  echo "proxy:     http://127.0.0.1:$PORT (inside the guarded command)"
  echo "lo-up:     $(lo_up_method)"
  printf 'command:  '; printf ' %q' "$@"; echo
  exit 0
fi

RUNDIR="$(mktemp -d "${TMPDIR:-/tmp}/netguard.XXXXXX")"
SOCK="$RUNDIR/proxy.sock"
PROXY_PID=""
CHILD_PID=""
cleanup() {
  if [[ -n "$CHILD_PID" ]] && kill -0 "$CHILD_PID" 2>/dev/null; then
    # The child may be a shell whose TERM trap waits for its own foreground
    # command (the sidecar's is `sleep 3600`): kill what it is running too,
    # and never wait on it without a bound.
    # Order matters. A shell child runs its TERM trap only once its foreground
    # command returns, so the TERM goes to the shell first (the trap is now
    # pending) and its command second (the shell returns and runs the trap).
    # The other way round, the shell starts the next command before the TERM
    # lands and defers it for as long as that one runs.
    kill -TERM "$CHILD_PID" 2>/dev/null || true
    sleep 0.05
    pkill -TERM -P "$CHILD_PID" 2>/dev/null || true
    # Reap it, so it is gone rather than a zombie kill -0 still sees; a child
    # that will not die within two seconds is killed outright.
    ( sleep 2; kill -KILL "$CHILD_PID" 2>/dev/null ) &
    local killer=$!
    wait "$CHILD_PID" 2>/dev/null || true
    kill "$killer" 2>/dev/null || true
  fi
  if [[ -n "$PROXY_PID" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  rm -rf "$RUNDIR"
}
trap cleanup EXIT
# A stop is a TERM to this shell. Handle it here rather than letting bash
# wait for whatever foreground command is running: the supervision loop
# below sleeps, and a stop that waits out a sleep is a stop that swarm.sh
# times out on.
trap 'cleanup; trap - TERM; kill -TERM $$' TERM
trap 'cleanup; trap - INT; kill -INT $$' INT

# bash 3.2 (macOS) treats "${arr[@]}" on an empty array as unbound under set -u,
# so without --log the proxy never started at all.
PROXY_LOG_ARGS=()
[[ -n "$LOG" ]] && PROXY_LOG_ARGS=(--log "$LOG")

wait_for() { # wait_for <test-command...> ; up to ~5s
  local i
  for i in $(seq 1 100); do
    if "$@" 2>/dev/null; then return 0; fi
    sleep 0.05
  done
  return 1
}

if [[ "$MODE" == "proxy-only" ]]; then
  start_proxy() {
    node "$PROXY_JS" proxy --listen "tcp:127.0.0.1:$PORT" --allow "$ALLOW" ${PROXY_LOG_ARGS[@]+"${PROXY_LOG_ARGS[@]}"} &
    PROXY_PID=$!
  }
  start_proxy
  wait_for bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT" || { echo "netguard: proxy did not start" >&2; exit 3; }
  echo "netguard: proxy-only mode (advisory). allow=[$ALLOW]" >&2
  set +e
  env HTTP_PROXY="http://127.0.0.1:$PORT" HTTPS_PROXY="http://127.0.0.1:$PORT" \
      http_proxy="http://127.0.0.1:$PORT" https_proxy="http://127.0.0.1:$PORT" \
      NO_PROXY="" no_proxy="" NODE_USE_ENV_PROXY=1 NETGUARD_MODE=proxy-only \
      "$@" &
  CHILD_PID=$!
  # Every agent's road to its provider is this proxy. If it dies while the
  # command runs (run sfeb5: an unhandled socket error after a DENY), bring it
  # back on the same port, which the panes' HTTPS_PROXY still names, and say
  # so in the log so the record shows the gap.
  while kill -0 "$CHILD_PID" 2>/dev/null; do
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
      wait "$PROXY_PID" 2>/dev/null
      echo "netguard: proxy exited; restarting on 127.0.0.1:$PORT" >&2
      [[ -n "$LOG" ]] && printf '%s RESTART proxy on 127.0.0.1:%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PORT" >> "$LOG"
      start_proxy
      wait_for bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT" || echo "netguard: proxy did not come back" >&2
    fi
    # A background sleep is interruptible: a TERM lands in the trap at once
    # instead of after the second is up.
    sleep 1 & wait $! || true
  done
  wait "$CHILD_PID"
  code=$?
  CHILD_PID=""
  set -e
  exit "$code"
fi

# ---- netns mode -----------------------------------------------------------
node "$PROXY_JS" proxy --listen "unix:$SOCK" --allow "$ALLOW" ${PROXY_LOG_ARGS[@]+"${PROXY_LOG_ARGS[@]}"} &
PROXY_PID=$!
wait_for test -S "$SOCK" || { echo "netguard: proxy socket did not appear" >&2; exit 3; }

# Stage 1 (mapped root inside the new user+net namespace): bring lo up, then
# drop back to the real uid in a nested user namespace.
cat > "$RUNDIR/stage1.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$NETGUARD_LO_METHOD" in
  ip) ip link set lo up ;;
  python3) python3 - <<'PY'
import socket, struct, fcntl
SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ifr = struct.pack("16sH14s", b"lo", 0, b"\x00" * 14)
flags = struct.unpack("16sH14s", fcntl.ioctl(s, SIOCGIFFLAGS, ifr))[1]
fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH14s", b"lo", flags | IFF_UP, b"\x00" * 14))
PY
  ;;
  *) echo "netguard: cannot bring lo up (need ip or python3)" >&2; exit 3 ;;
esac
exec unshare -U --map-user="$NETGUARD_UID" --map-group="$NETGUARD_GID" -- bash "$NETGUARD_RUNDIR/stage2.sh" "$@"
EOF

# Stage 2 (real uid, empty network namespace): bridge 127.0.0.1:PORT -> proxy
# socket, export proxy variables, run the command, propagate its exit code.
cat > "$RUNDIR/stage2.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
node "$NETGUARD_PROXY_JS" bridge --unix "$NETGUARD_SOCK" --port "$NETGUARD_PORT" 2>/dev/null &
BRIDGE_PID=$!
for _ in $(seq 1 100); do
  if bash -c "exec 3<>/dev/tcp/127.0.0.1/$NETGUARD_PORT" 2>/dev/null; then break; fi
  sleep 0.05
done
export HTTP_PROXY="http://127.0.0.1:$NETGUARD_PORT" HTTPS_PROXY="http://127.0.0.1:$NETGUARD_PORT"
export http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY"
export NO_PROXY="" no_proxy="" NODE_USE_ENV_PROXY=1 NETGUARD_MODE=netns
set +e
"$@"
code=$?
set -e
kill "$BRIDGE_PID" 2>/dev/null || true
exit "$code"
EOF

echo "netguard: netns mode. allow=[$ALLOW] proxy=127.0.0.1:$PORT" >&2
set +e
NETGUARD_LO_METHOD="$(lo_up_method)" NETGUARD_UID="$(id -u)" NETGUARD_GID="$(id -g)" \
NETGUARD_RUNDIR="$RUNDIR" NETGUARD_SOCK="$SOCK" NETGUARD_PORT="$PORT" NETGUARD_PROXY_JS="$PROXY_JS" \
  unshare -rn -- bash "$RUNDIR/stage1.sh" "$@"
code=$?
set -e
exit "$code"

#!/usr/bin/env bash
# One agent, end to end, living in a microVM.
#
#   bash agent-in-vm.sh RUNDIR [MODEL]        (IMAGE=dfirswarm-re:dev-arm64 by default)
#   MODE=herdr bash agent-in-vm.sh RUNDIR     the interactive agent in a Herdr pane
#
# The host keeps what the agent must not reach: the run registry, the trace
# collector and its anchor, the provider key, the evidence's own bytes. The
# VM gets Pi, the harness code read-only, the sandbox, the evidence
# read-only, one allowed host, and a placeholder where the key would be.
#
#   host                                   VM (Pi + extensions)
#   swarm.sh --no-start  -> sandbox   ->   /swarm            (rw)
#   evidence copy        -> inputs/   ->   /swarm/inputs     (ro, noexec)
#   trace collector      <- vsock 5000 <-  socat <- /run/dfirswarm/collector.sock
#   Pi's key (host env)  -> injected on the way to api.openai.com only
#   repo                 ->               /opt/dfirswarm     (ro)
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
RUN=${1:?usage: agent-in-vm.sh RUNDIR [MODEL]}
MODEL=${2:-openai/gpt-5.4-mini}
IMAGE=${IMAGE:-dfirswarm-re:dev-arm64}
MODE=${MODE:-print}
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) PLAT=darwin-arm64 ;;
  Linux-x86_64) PLAT=linux-x64-gnu ;;
  *) echo "unsupported host"; exit 2 ;;
esac
export PATH="$HERE/node_modules/@superradcompany/microsandbox-$PLAT/bin:$PATH"
TOOLS="read,bash,edit,write,post,inbox,wait,claim_file,release_file,claims,list_team,budget,file_history,file_restore,file_diff,thread_open,thread_join,inputs,name,record,ledger,done"
say() { printf '\n== %s\n' "$*"; }

mkdir -p "$RUN"
RUN=$(cd "$RUN" && pwd -P)

say "evidence (synthetic)"
EV="$RUN/evidence"
rm -rf "$EV" && mkdir -p "$EV/mail"
printf 'case notes: laptop seized 2026-09-23, examiner HO\n' > "$EV/notes.txt"
{ head -c 4096 /dev/urandom; printf 'suspect wire transfer to account 4471'; head -c 4096 /dev/urandom; } > "$EV/mail/attachment.bin"
head -c 8192 /dev/urandom > "$EV/mail/clean.bin"
ls -la "$EV" "$EV/mail"

say "goal"
cat > "$RUN/goal.md" <<'EOF'
## Goal

Examine the evidence under `inputs/`. It is read-only; work in `work/`.

1. Write `work/hashes.txt`: one line per file under `inputs/`, `<sha256>  <path>`,
   the path relative to the sandbox (for example `inputs/notes.txt`).
2. Find every evidence file that contains the ASCII string `suspect` (`yara` and
   `strings` are installed). Write their paths, one per line, to
   `work/suspects.txt`.
3. Record each suspect file as a finding with the `record` tool, citing its sha256.

## Definition of done

`work/hashes.txt` lists every file under `inputs/` with its correct sha256, and
`work/suspects.txt` names exactly the files that contain `suspect`.

## Checks

- `for f in $(find inputs -type f); do grep -q "$(sha256sum "$f" | cut -d' ' -f1)" work/hashes.txt || exit 1; done`
- `grep -q 'inputs/mail/attachment.bin' work/suspects.txt && ! grep -q clean.bin work/suspects.txt`

## How to divide the work

You are alone. Name yourself, do the three steps, verify the checks, call `done`.
EOF

say "sandbox (swarm.sh start --no-start)"
SBX="$RUN/sbx"
# The harness makes inputs/ and its pristine clone read-only; undo that to clear a previous run.
if [[ -d "$SBX" ]]; then
  for f in collector.pid nudge.pid idle-nudge.pid; do
    [[ -f "$SBX/$f" ]] && kill "$(cat "$SBX/$f")" 2>/dev/null || true
  done
  chmod -R u+w "$SBX"
fi
rm -rf "$SBX" "$RUN"/sbx.*
bash "$REPO/scripts/swarm.sh" start --no-start --n 1 --model "$MODEL" --cap-usd 1 \
  --goal-file "$RUN/goal.md" --inputs "$EV" --inputs-enforce off --no-netguard --toolbox off \
  --sandbox "$SBX" --label vm-e2e 2>&1 | grep -E '^(Sandbox|SANDBOX|Inputs|Net|WARN|BLOCKER)' || true
AGENT=$(jq -r '.agents[0].id' "$SBX/team.json")
SWARM_ID=$(jq -r '.swarm_id' "$SBX/team.json")
echo "agent $AGENT, swarm $SWARM_ID"

say "trace collector on the host, socket outside the sandbox"
if [[ -f "$SBX/collector.pid" ]]; then kill "$(cat "$SBX/collector.pid")" 2>/dev/null || true; fi
rm -f "$SBX/traces/.collector.sock" "$SBX/collector.pid"
TOKEN=$(openssl rand -hex 16)
# A Unix socket path must fit in sun_path (104 bytes on macOS, 108 on Linux);
# msb refuses a longer one with ENAMETOOLONG. The run directory can be deep,
# so the socket lives in a short per-user temp directory.
SOCKDIR=$(mktemp -d "${TMPDIR:-/tmp}/dfs.XXXXXX")
# Whatever happens, leave nothing running: the collector, the helpers
# swarm.sh started for this sandbox, the VM, the socket directory.
cleanup() {
  [[ -n "${COLLECTOR:-}" ]] && kill "$COLLECTOR" 2>/dev/null
  for f in nudge.pid idle-nudge.pid; do
    [[ -f "$SBX/$f" ]] && kill "$(cat "$SBX/$f")" 2>/dev/null
  done
  [[ -n "${WS:-}" ]] && herdr workspace close "$WS" >/dev/null 2>&1
  if [[ -n "${VM:-}" ]]; then msb stop "$VM" >/dev/null 2>&1; msb rm "$VM" >/dev/null 2>&1; fi
  rm -rf "$SOCKDIR"
  return 0
}
trap cleanup EXIT
SOCK="$SOCKDIR/collector.sock"
printf '{"tokens":{"%s":"%s"},"gate":""}' "$TOKEN" "$AGENT" |
  node "$REPO/scripts/trace-collector.mjs" "$SBX" --socket "$SOCK" --tokens \
    --anchor "$RUN/sbx.trace-anchor.json" --quiet > "$RUN/collector.log" 2>&1 &
COLLECTOR=$!
for _ in $(seq 40); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
[[ -S "$SOCK" ]] || { echo "collector did not come up"; cat "$RUN/collector.log"; exit 1; }
echo "collector pid $COLLECTOR on $SOCK"

say "microVM with Pi inside"
VM="vm-e2e-$AGENT"
msb rm "$VM" >/dev/null 2>&1 || true
# The key is read from Pi's own store on the host and handed to msb's
# environment only; the guest sees $MSB_OPENAI_API_KEY and never the value.
OPENAI_API_KEY="$(jq -r '.openai.key' "$HOME/.pi/agent/auth.json")" \
msb create "$IMAGE" --name "$VM" --cpus 2 --memory 2G \
  --no-net --net-rule "allow@api.openai.com:tcp:443" \
  --secret "OPENAI_API_KEY@api.openai.com" \
  --mount-dir "$SBX:/swarm" \
  --mount-dir "$SBX/inputs:/swarm/inputs:ro,noexec" \
  --mount-dir "$SBX/.inputs-pristine:/swarm/.inputs-pristine:ro" \
  --mount-dir "$SBX/traces:/swarm/traces:ro" \
  --mount-dir "$REPO:/opt/dfirswarm:ro" \
  --vsock "$SOCK:5000" \
  -e "AGENT_ID=$AGENT" -e "SWARM_ID=$SWARM_ID" -e "SWARM_TRACE_TOKEN=$TOKEN" \
  -e "SWARM_TRACE_SOCKET=/run/dfirswarm/collector.sock" -e "TMPDIR=/swarm/work/.tmp" \
  -w /swarm > "$RUN/create.log" 2>&1
# Not piped: the VM's runtime keeps the creating process's stdout open, and a
# pipe to tail would never see EOF.
tail -1 "$RUN/create.log"
msb exec "$VM" -- sh -c 'mkdir -p /run/dfirswarm /swarm/work/.tmp &&
  setsid socat UNIX-LISTEN:/run/dfirswarm/collector.sock,fork VSOCK-CONNECT:2:5000 </dev/null >/tmp/socat.log 2>&1 &
  for i in 1 2 3 4 5 6 7 8 9 10; do [ -S /run/dfirswarm/collector.sock ] && break; sleep 0.2; done
  ls -la /run/dfirswarm/collector.sock; echo "OPENAI_API_KEY in the guest: $OPENAI_API_KEY"; pi --version'

KICKOFF="Join swarm ${SWARM_ID}. Read SWARM.md, team.json, threads/main, and done/SWARM_DONE.
If the done file exists, terminate.
Otherwise: nobody has been given a job here. Read the goal, see on the board
what your peers have taken, decide what you are going to do, and call
name(name, doing) to say what to call you and what you are taking on. Then
post it and start."
PI_ARGS=(--approve --name "$AGENT" --session-dir "/swarm/.pi-sessions/$AGENT"
  -e /opt/dfirswarm/extensions/agent-swarm.ts --tools "$TOOLS" --model "$MODEL")
START=$(date +%s)
if [[ "$MODE" == herdr ]]; then
  say "the agent works (interactive Pi inside the VM, in a Herdr pane)"
  # The pane runs msb, not pi, so Herdr cannot detect the agent by process;
  # the harness, which sees the trace, reports its lifecycle instead.
  printf '%s\n' "$KICKOFF" > "$SBX/.kickoff"
  {
    printf 'exec %q exec -t %q -- sh -c %q sh' "$(command -v msb)" "$VM" 'cd /swarm && exec pi "$@" "$(cat /swarm/.kickoff)"'
    printf ' %q' "${PI_ARGS[@]}"
    printf '\n'
  } > "$SOCKDIR/launch.sh"
  WS=$(herdr workspace create --cwd "$SBX" --label "vm-$AGENT" --no-focus | jq -r '.result.workspace.workspace_id // .result.workspace.id')
  PANE=$(herdr pane list --workspace "$WS" 2>/dev/null | jq -r '[.. | .pane_id? // empty][0]')
  [[ -n "$PANE" && "$PANE" != null ]] || PANE="$WS:p1"
  sleep 2
  herdr pane run "$PANE" "sh $SOCKDIR/launch.sh" >/dev/null
  herdr pane report-agent "$PANE" --source dfirswarm-vm --agent pi --state working --message "in microVM $VM" >/dev/null
  echo "Herdr workspace $WS, pane $PANE: $(herdr agent list | jq -c --arg p "$PANE" '[.. | objects | select(.pane_id? == $p) | {agent, agent_status}][0]')"
  for _ in $(seq 180); do [[ -f "$SBX/done/SWARM_DONE" ]] && break; sleep 5; done
  herdr pane report-agent "$PANE" --source dfirswarm-vm --agent pi --state idle --message "done" >/dev/null
  herdr pane process-info --pane "$PANE" | jq -c '[.result.process_info.foreground_processes[] | {name, argv0}]'
  herdr pane read "$PANE" | grep -v '^\s*$' | tail -12 > "$RUN/pi.out"
  herdr workspace close "$WS" >/dev/null 2>&1; WS=""
  [[ -f "$SBX/done/SWARM_DONE" ]] && echo "done file written" || echo "no done file after 15 min"
else
  say "the agent works (pi -p, inside the VM)"
  msb exec --timeout 15m "$VM" -- sh -c 'cd /swarm && exec pi "$@"' sh -p "${PI_ARGS[@]}" "$KICKOFF" \
    > "$RUN/pi.out" 2>&1 || echo "pi exited with $?"
fi
tail -12 "$RUN/pi.out"
echo "agent ran for $(( $(date +%s) - START ))s"

say "snapshot, then remove the VM"
msb stop "$VM" >/dev/null 2>&1 || true
msb snapshot create --from-sandbox "$VM" --integrity --label "run=$SWARM_ID" --label "agent=$AGENT" \
  -o "$RUN/$VM.msb" 2>&1 | tail -2
ls -la "$RUN/$VM.msb" 2>/dev/null && shasum -a 256 "$RUN/$VM.msb" | tee "$RUN/$VM.msb.sha256"
echo "SANDBOX=$SBX"

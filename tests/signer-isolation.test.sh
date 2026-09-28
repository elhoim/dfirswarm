#!/usr/bin/env bash
# The signers' keys, kept from a host run's panes.
#
# The machine key seals a draft release at stop, unattended, so it has no
# passphrase; an examiner's key may have none either, or sit in an ssh-agent.
# A host run's panes read the whole machine but what the kernel denies, so:
#
# - the no-read list: each home's machine/ and examiners/ (made 0700 first),
#   SWARM_SIGNERS_HOME, each enrolled examiner's key file as its record names
#   it (the key itself is never opened), the custody key;
# - the ssh-agent: SSH_AUTH_SOCK is dropped from a pane's environment and the
#   hook, and its socket denied (launchd's by its directory);
# - a guard that cannot deny one of them refuses the run; no guard at all
#   refuses it while a signing key exists, unless --accept-signer-exposure,
#   which the run records (signer_keys_hidden: false, and what was exposed);
# - every earlier run's sandbox in registry.json, and reviews/, are denied;
#   this run's own is not, and neither is the registry;
# - where the host has a guard, the kernel itself refuses the reads and the
#   connect (seatbelt on macOS; a mount namespace and Landlock on Linux);
# - machine rotate retires the key into machine/retired/<id>/, never deletes
#   it, makes the next one and prints both fingerprints.
#
# No model, no Herdr, no VM. Every home is a temporary one: never the
# operator's ~/.dfirswarm. The keys here are made for the test, in it.
set -euo pipefail
unset SWARM_ISOLATION SWARM_VM_IMAGE SWARM_IMAGES_LOCK SWARM_SIGNERS_HOME

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d /tmp/sgnr.XXXXXX)"
TMP="$(cd "$TMP" && pwd -P)"
PIDS=()
cleanup() {
  local p
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  chmod -R u+rwx "$TMP" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT
export DFIRSWARM_HOME="$TMP/home" SWARM_HUBS_DIR="$TMP/hubs" SWARM_RUNS_DIR="$TMP/runs"
H="$DFIRSWARM_HOME"

pass=0
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok - $*"; pass=$((pass + 1)); }
has_line() { grep -qxF -- "$2" <<<"$1"; }
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

fn() { sed -n "/^$1() {/,/^}/p" "$ROOT/scripts/swarm.sh"; }
for f in signers_home signer_homes real_paths path_covers examiner_key_paths signer_paths signer_keys_present \
  agent_socket_rules signer_guard earlier_run_sandboxes fsguard_can_mask pane_env_for; do
  eval "$(fn "$f")"
  type "$f" >/dev/null 2>&1 || fail "$f was not found in swarm.sh"
done

# A listening Unix socket, as an ssh-agent's is.
listen() { # <path>
  mkdir -p "$(dirname "$1")"
  python3 -c '
import os, socket, sys, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1]); s.listen(8)
while True:
    try:
        c, _ = s.accept(); c.close()
    except Exception:
        time.sleep(0.1)
' "$1" >/dev/null 2>&1 &
  PIDS+=("$!")
  disown "$!" 2>/dev/null || true
  local i
  for i in $(seq 1 50); do [[ -S "$1" ]] && return 0; sleep 0.1; done
  fail "the test socket $1 did not come up"
}
# Whether a connect to a socket gets through (prints REACHABLE, or the error).
probe_connect='
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect(sys.argv[1]); print("REACHABLE")
except Exception as e:
    print(type(e).__name__)
'

swarm() { bash "$ROOT/scripts/swarm.sh" "$@"; }
BASE=(--isolation host --model solo/model --provider-host solo=api.solo.example --n 1 --cap-usd 1
  --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off --no-start)
start_run() { # <args...> -> out, rc
  set +e
  out="$(swarm start "${BASE[@]}" "$@" 2>&1)"
  rc=$?
  set -e
}
reg() { jq -r "$1" "$SWARM_RUNS_DIR/registry.json"; }

# The keys: the machine's, made as a seal makes it, and an examiner's, given
# at enrolment from outside the home (the record names its path).
mkdir -p "$TMP/keys"
node --experimental-strip-types --no-warnings --input-type=module -e '
import { machineSigner } from "'"$ROOT"'/scripts/signers.ts";
const m = machineSigner();
if ("why" in m) { console.error(m.why); process.exit(1); }' || fail "the machine key was not made"
[[ -f "$H/machine/release_ed25519" ]] || fail "the machine key is not where signers.ts keeps it"
ssh-keygen -q -t ed25519 -N "" -C examiner-test -f "$TMP/keys/examiner_ed25519" </dev/null
# A key with no passphrase is taken only as the documented trade (--no-passphrase).
swarm examiner enroll --name "Test Examiner" --organisation "Test Lab" --competence "a test" \
  --key "$TMP/keys/examiner_ed25519" --no-passphrase --id test-examiner >/dev/null || fail "the examiner was not enrolled"
EXKEY="$TMP/keys/examiner_ed25519"

echo "# the no-read list"
# The key's own bytes are never needed: it is listed while nobody may read it.
chmod 000 "$EXKEY"
paths="$(signer_paths)"
chmod 600 "$EXKEY"
has_line "$paths" "$H/machine" || fail "the machine directory is not on the list: $paths"
has_line "$paths" "$H/examiners" || fail "the examiners' directory is not on the list: $paths"
has_line "$paths" "$EXKEY" || fail "the examiner's key file, as the record names it, is not on the list: $paths"
paths="$(SWARM_SIGNERS_HOME="$TMP/signers" signer_paths "$TMP/keys/custody_ed25519")"
for p in "$H/machine" "$H/examiners" "$TMP/signers/machine" "$TMP/signers/examiners" "$TMP/signers" "$TMP/keys/custody_ed25519"; do
  has_line "$paths" "$p" || fail "$p is not on the list with SWARM_SIGNERS_HOME and a custody key: $paths"
done
# A record naming a public key (the private half in an agent or beside it):
# the private file beside it is listed too.
ssh-keygen -q -t ed25519 -N "" -C agent-held -f "$TMP/keys/held_ed25519" </dev/null
jq --arg p "$TMP/keys/held_ed25519.pub" '.id = "held" | .key.path = $p' "$H/examiners/test-examiner.json" > "$H/examiners/held.json"
paths="$(signer_paths)"
has_line "$paths" "$TMP/keys/held_ed25519.pub" && has_line "$paths" "$TMP/keys/held_ed25519" \
  || fail "a public key's record does not put its private half on the list: $paths"
rm -f "$H/examiners/held.json"
# A link is followed: the kernel rules match what a path really is.
mkdir -p "$TMP/real-home"
ln -s "$TMP/real-home" "$TMP/linked-home"
paths="$(DFIRSWARM_HOME="$TMP/linked-home" signer_paths)"
has_line "$paths" "$TMP/real-home/machine" || fail "a linked home is not resolved: $paths"
paths="$(cd "$TMP" && DFIRSWARM_HOME=./home signer_paths)"
has_line "$paths" "$H/machine" || fail "a relative DFIRSWARM_HOME was dropped rather than resolved: $paths"
ok "the list names each home's machine/ and examiners/, SWARM_SIGNERS_HOME, the examiner's key from its record (unread), the custody key, resolved (a link, a relative home)"

echo "# the ssh-agent"
unset SSH_AUTH_SOCK
listen "$TMP/agent/agent.sock"
launchd_dir="$TMP/com.apple.launchd.TEST"
listen "$launchd_dir/Listeners"
rules="$(SSH_AUTH_SOCK="$TMP/agent/agent.sock" agent_socket_rules)"
has_line "$rules" "path	$TMP/agent/agent.sock" || fail "the agent socket SSH_AUTH_SOCK names is not denied: $rules"
rules="$(SSH_AUTH_SOCK="$launchd_dir/Listeners" agent_socket_rules)"
has_line "$rules" "tree	$launchd_dir" || fail "launchd's agent socket is not denied by its directory: $rules"
: > "$TMP/not-a-socket"
rules="$(launchctl() { :; }; SSH_AUTH_SOCK="$TMP/not-a-socket" agent_socket_rules)"
[[ -z "$rules" ]] || fail "a path that is not a socket was taken for an agent: $rules"
# The pane's environment: set empty (ssh reads that as no agent), in a host
# pane and in a VM run's pane alike.
trace_token_for() { echo token; }
swarm_id=s0 hard=0 provider_env=() VM_PANE_ZDOTDIR=""
pane_env_for s000
printf '%s\n' "${PANE_ENV_ARGS[@]}" | grep -qx 'SSH_AUTH_SOCK=' || fail "a host pane still gets the operator's SSH_AUTH_SOCK: ${PANE_ENV_ARGS[*]}"
VM_PANE_ZDOTDIR="$TMP/zdot"
pane_env_for s000
printf '%s\n' "${PANE_ENV_ARGS[@]}" | grep -qx 'SSH_AUTH_SOCK=' || fail "a VM run's pane still gets SSH_AUTH_SOCK: ${PANE_ENV_ARGS[*]}"
VM_PANE_ZDOTDIR=""
# An operator's --env cannot hand it back.
start_run --env "SSH_AUTH_SOCK=$TMP/agent/agent.sock" --label env-agent
[[ $rc -eq 2 ]] && grep -q 'BLOCKER: --env SSH_AUTH_SOCK would hand the agents an ssh-agent' <<<"$out" \
  || fail "--env SSH_AUTH_SOCK was not refused (rc $rc): $out"
ok "the agent's socket is denied (launchd's by its directory), a pane starts without SSH_AUTH_SOCK, and --env cannot put it back"

echo "# signer_guard: what each guard can do"
launchctl() { :; }  # launchd's own agent stays out of these unit checks
unset SSH_AUTH_SOCK
set +e
msg="$(signer_guard none 0 "" 2>&1)"; r=$?
set -e
[[ $r -eq 2 ]] || fail "no guard with a machine key present was not refused (rc $r)"
grep -q "BLOCKER: no kernel guard holds this run's panes" <<<"$msg" && grep -q -- "--accept-signer-exposure" <<<"$msg" \
  && grep -qF "$H/machine/release_ed25519" <<<"$msg" && grep -qF "$EXKEY" <<<"$msg" \
  || fail "the refusal does not name the keys and the way on: $msg"
signer_guard none 1 "" >/dev/null 2>&1 || fail "--accept-signer-exposure did not let the run start"
[[ "$SIGNER_KEYS_HIDDEN" == false && "$SIGNER_ACCEPTED" -eq 1 && ${#SIGNER_NO_READ[@]} -eq 0 ]] || fail "the accepted exposure is not recorded as such"
printf '%s\n' "${SIGNER_EXPOSED[@]}" | grep -qF "the machine key ($H/machine/release_ed25519)" || fail "the exposed keys do not name the machine key: ${SIGNER_EXPOSED[*]}"
printf '%s\n' "${SIGNER_EXPOSED[@]}" | grep -qF "examiner test-examiner's key ($EXKEY)" || fail "the exposed keys do not name the examiner's: ${SIGNER_EXPOSED[*]}"
# With no key anywhere there is nothing to refuse over, and the record says why.
(DFIRSWARM_HOME="$TMP/empty-home" signer_guard none 0 "" >/dev/null 2>&1 && [[ "$SIGNER_KEYS_HIDDEN" == false && "$SIGNER_WHY" == *"no signing key existed"* ]]) \
  || fail "no guard and no key was refused, or recorded as hidden"
# An agent holding an examiner's key counts as that key.
jq --arg p "$TMP/keys/agent-only.pub" '.id = "agent-only" | .key.path = $p' "$H/examiners/test-examiner.json" > "$TMP/agent-only.json"
mkdir -p "$TMP/agent-home/examiners" && cp "$TMP/agent-only.json" "$TMP/agent-home/examiners/"
set +e
msg="$(DFIRSWARM_HOME="$TMP/agent-home" SSH_AUTH_SOCK="$TMP/agent/agent.sock" signer_guard none 0 "" 2>&1)"; r=$?
set -e
[[ $r -eq 2 ]] && grep -qF "the ssh-agent at $TMP/agent/agent.sock" <<<"$msg" || fail "an agent holding an examiner's key was not counted (rc $r): $msg"
# A guard that denies: every path and the socket are to be denied.
signer_guard seatbelt 0 "" "rw:$TMP/runs/sx" "keep:$ROOT" >/dev/null 2>&1 || fail "a guard that can deny was refused"
[[ "$SIGNER_KEYS_HIDDEN" == true ]] || fail "a guard that denies is not recorded as hiding the keys"
has_line "$(printf '%s\n' "${SIGNER_NO_READ[@]}")" "$EXKEY" || fail "the guard's list lacks the examiner's key"
SSH_AUTH_SOCK="$TMP/agent/agent.sock" signer_guard linux 0 "" "rw:$TMP/runs/sx" >/dev/null 2>&1 || fail "a namespace guard with an agent was refused"
has_line "$(printf '%s\n' "${SIGNER_SOCKETS[@]}")" "path	$TMP/agent/agent.sock" || fail "the agent's socket is not among what the guard denies"
# Landlock cannot refuse a socket: with an agent reachable, the run is refused.
set +e
msg="$(SSH_AUTH_SOCK="$TMP/agent/agent.sock" signer_guard landlock 0 "" "rw:$TMP/runs/sx" 2>&1)"; r=$?
set -e
[[ $r -eq 2 ]] && grep -q "cannot refuse a socket" <<<"$msg" || fail "Landlock with an agent reachable was not refused (rc $r): $msg"
signer_guard landlock 0 "" "rw:$TMP/runs/sx" >/dev/null 2>&1 && [[ "$SIGNER_KEYS_HIDDEN" == true ]] || fail "Landlock with no agent could not hide the key paths"
# A denied path may not take what the panes need, and a key may not be in the run.
set +e
msg="$(SWARM_SIGNERS_HOME="$TMP" signer_guard seatbelt 0 "" "rw:$TMP/runs/sx" 2>&1)"; r=$?
set -e
[[ $r -eq 2 ]] && grep -q "holds $TMP/runs/sx, which the panes need" <<<"$msg" || fail "a signers' home holding the sandbox was not refused (rc $r): $msg"
mkdir -p "$TMP/runs/sx"
set +e
msg="$(signer_guard seatbelt 0 "$TMP/runs/sx/custody_ed25519" "rw:$TMP/runs/sx" 2>&1)"; r=$?
set -e
[[ $r -eq 2 ]] && grep -q "is inside $TMP/runs/sx" <<<"$msg" || fail "a key inside the sandbox was not refused (rc $r): $msg"
# A VM mounts none of it, unless a key lies in something every VM mounts.
signer_guard microvm 0 "" "mount:$ROOT/scripts" "mount:$TMP/runs/sx" >/dev/null 2>&1 && [[ "$SIGNER_KEYS_HIDDEN" == true ]] || fail "a VM run was not recorded as keeping the keys out"
set +e
msg="$(SWARM_SIGNERS_HOME="$TMP/runs/sx/signers" signer_guard microvm 0 "" "mount:$TMP/runs/sx" 2>&1)"; r=$?
set -e
[[ $r -eq 2 ]] && grep -q "which every VM mounts" <<<"$msg" || fail "a signers' home inside the mounted run was not refused (rc $r): $msg"
unset -f launchctl
ok "no guard: refused while a key exists, or accepted and recorded; a guard: everything denied, or refused where it cannot be (Landlock and a socket, a path the panes need, a key in the run); a VM: out unless mounted"

echo "# earlier runs, from registry.json"
E="$TMP/er"
mkdir -p "$E/runs/cur" "$E/runs/old" "$E/runs/cur/nested" "$E/evidence-run/ev" "$E/runs/linkme"
ln -s "$E/runs/old" "$E/runs/old-link"
jq -n --arg r "$E/runs" --arg e "$E/evidence-run" '{runs: [
  {id: "cur", sandbox: ($r + "/cur")},
  {id: "old", sandbox: ($r + "/old")},
  {id: "old-again", sandbox: ($r + "/old-link")},
  {id: "gone", sandbox: ($r + "/gone")},
  {id: "parent", sandbox: $r},
  {id: "nested", sandbox: ($r + "/cur/nested")},
  {id: "holds-evidence", sandbox: $e},
  {id: "relative", sandbox: "runs/x"}
]}' > "$E/registry.json"
got="$(earlier_run_sandboxes "$E/registry.json" "$E/runs/cur" "$ROOT" "$E/evidence-run/ev")"
[[ "$(grep -c '^hide' <<<"$got")" -eq 1 ]] && has_line "$got" "hide	$E/runs/old" \
  || fail "the earlier run was not hidden once (a link to it is the same run): $got"
grep -q "^hide	$E/runs/cur\$" <<<"$got" && fail "this run's own sandbox is hidden: $got"
grep -q "gone" <<<"$got" && fail "a sandbox that is not there was named: $got"
grep -q "^skip	$E/runs	it holds this run's sandbox" <<<"$got" || fail "a sandbox holding this run's was not left out: $got"
grep -q "^skip	$E/runs/cur/nested	it is inside this run's sandbox" <<<"$got" || fail "a sandbox inside this run's was not left out: $got"
grep -q "^skip	$E/evidence-run	it holds $E/evidence-run/ev" <<<"$got" || fail "a sandbox holding the evidence was not left out: $got"
ok "each earlier sandbox that is there is hidden once, this run's own is not, and one that holds what the panes need is left out and said"

echo "# kickoffs"
# No guard (--no-write-guard) with a key present: refused, --check the same,
# nothing registered.
start_run --no-write-guard --label noguard
[[ $rc -eq 2 ]] && grep -q "BLOCKER: no kernel guard holds this run's panes" <<<"$out" || fail "an unguarded host run with a key present was started (rc $rc): $out"
blocker="$(grep '^BLOCKER' <<<"$out")"
set +e
check_out="$(swarm start --check "${BASE[@]}" --no-write-guard --label noguard 2>&1)"; check_rc=$?
set -e
[[ $check_rc -eq 2 ]] && grep -qxF -- "$blocker" <<<"$check_out" || fail "--check does not refuse it in the start's words (rc $check_rc): $check_out"
[[ ! -f "$SWARM_RUNS_DIR/registry.json" ]] || [[ "$(reg '[.runs[] | select(.label == "noguard")] | length')" == 0 ]] || fail "a refused run was registered"
# The operator's word: started, recorded, told to rotate.
start_run --no-write-guard --accept-signer-exposure --label exposed
[[ $rc -eq 0 ]] || fail "--accept-signer-exposure did not start the run (rc $rc): $out"
grep -q "swarm.sh machine rotate" <<<"$out" || fail "the kickoff does not say to rotate: $out"
[[ "$(reg '.runs[-1].signer_keys_hidden')" == false ]] || fail "an exposed run is recorded as hiding the keys"
jq -e --arg k "$H/machine/release_ed25519" '.runs[-1].signer_isolation | .isolation == "host" and .guard == "none" and .exposure_accepted == true and .keys_hidden == false
  and (.exposed | map(select(contains($k))) | length == 1)' "$SWARM_RUNS_DIR/registry.json" >/dev/null \
  || fail "the exposure is not recorded: $(reg '.runs[-1].signer_isolation')"
jq -e '.runs[-1].earlier_runs_hidden | .by == null and .sandboxes == 0' "$SWARM_RUNS_DIR/registry.json" >/dev/null || fail "an unguarded run claims earlier runs hidden"
# A host guard flag means nothing in a VM, and is refused there.
set +e
out="$(swarm start --model solo/model --provider-host solo=api.solo.example --n 1 --cap-usd 1 --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off --no-start --accept-signer-exposure 2>&1)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q -- "--accept-signer-exposure set a guard of a host run" <<<"$out" || fail "--accept-signer-exposure was accepted for a VM run (rc $rc): $out"
ok "no guard: refused with a key present (and by --check alike), or started on --accept-signer-exposure, recorded and told to rotate; not a VM run's flag"

# The write guard this host gives a host run's panes, as the kickoff decides
# it: none where there is no mechanism, or no write allowlist (a namespace
# without bubblewrap).
MODE="$(bash "$ROOT/scripts/fsguard.sh" --rw "$TMP" --dry-run -- true 2>/dev/null | sed -n 's/^mode: //p')"
if [[ "$MODE" == mountns ]] && bash "$ROOT/scripts/fsguard.sh" --rw "$TMP" --mode mountns --dry-run -- true 2>/dev/null | grep -q 'note: --rw needs bubblewrap'; then
  MODE=none
fi
if [[ -z "$MODE" || "$MODE" == none ]]; then
  echo "skip - no kernel write guard here (mode: ${MODE:-none}): what a guarded pane is denied is not measured"
else
  echo "mode - $MODE"
  # Material a pane must not find, beside the keys.
  echo canary > "$H/machine/canary"
  echo canary > "$H/examiners/canary"
  first_sb="$(reg '[.runs[] | select(.label == "exposed")][0].sandbox')"
  echo "an earlier finding" > "$first_sb/work/finding.md"
  sock_args=()
  fsguard_can_mask "$MODE" && sock_args=(env SSH_AUTH_SOCK="$TMP/agent/agent.sock")
  if [[ "$MODE" == landlock ]]; then
    # The one thing Landlock cannot deny: an agent's socket. Refused.
    set +e
    out="$(SSH_AUTH_SOCK="$TMP/agent/agent.sock" swarm start "${BASE[@]}" --label ll-agent 2>&1)"; rc=$?
    set -e
    [[ $rc -eq 2 ]] && grep -q "cannot refuse a socket" <<<"$out" || fail "a Landlock-only run with an agent reachable was started (rc $rc): $out"
  fi
  set +e
  out="$(${sock_args[@]+"${sock_args[@]}"} bash "$ROOT/scripts/swarm.sh" start "${BASE[@]}" --label guarded 2>&1)"; rc=$?
  set -e
  [[ $rc -eq 0 ]] || fail "a guarded host run was refused (rc $rc): $out"
  sb="$(reg '.runs[-1].sandbox')"
  [[ "$(mode_of "$H/machine")" == 700 && "$(mode_of "$H/examiners")" == 700 ]] || fail "the signers' directories are not 0700"
  [[ "$(reg '.runs[-1].signer_keys_hidden')" == true ]] || fail "a guarded run does not record the keys hidden: $(reg '.runs[-1].signer_isolation')"
  jq -e --arg m "$MODE" --arg h "$H" --arg k "$EXKEY" '.runs[-1].signer_isolation | .isolation == "host" and .guard == $m and .keys_hidden == true
    and (.hidden | index($h + "/machine") != null and index($h + "/examiners") != null and index($k) != null) and .exposure_accepted == false' \
    "$SWARM_RUNS_DIR/registry.json" >/dev/null || fail "the record does not name what was denied: $(reg '.runs[-1].signer_isolation')"
  plan="$(cat "$sb/.fsguard/plan.txt")"
  for p in "$H/machine" "$H/examiners" "$EXKEY"; do
    grep -qxF "no-read: $p" <<<"$plan" || fail "the pane plan does not deny $p: $plan"
  done
  if fsguard_can_mask "$MODE"; then
    grep -qxF "no-socket: $TMP/agent/agent.sock" <<<"$plan" || fail "the pane plan does not deny the agent's socket: $plan"
    jq -e --arg s "$TMP/agent/agent.sock" '.runs[-1].signer_isolation.agent_sockets | index($s) != null' "$SWARM_RUNS_DIR/registry.json" >/dev/null \
      || fail "the record does not name the agent's socket"
    grep -qxF "no-read: $first_sb" <<<"$plan" || fail "the earlier run's sandbox is not denied: $plan"
    grep -qxF "no-read: $SWARM_RUNS_DIR/reviews" <<<"$plan" || fail "the reviews are not denied: $plan"
    grep -qxF "no-read: $sb" <<<"$plan" && fail "this run's own sandbox is denied to its panes"
    grep -qxF "no-read: $SWARM_RUNS_DIR" <<<"$plan" && fail "the whole runs directory is denied"
    jq -e --arg m "$MODE" --arg rv "$SWARM_RUNS_DIR/reviews" '.runs[-1].earlier_runs_hidden | .by == $m and .sandboxes >= 1 and .reviews == $rv' \
      "$SWARM_RUNS_DIR/registry.json" >/dev/null || fail "the record does not say the earlier runs are hidden: $(reg '.runs[-1].earlier_runs_hidden')"
  else
    jq -e '.runs[-1].earlier_runs_hidden | .by == null and (.why | contains("Landlock"))' "$SWARM_RUNS_DIR/registry.json" >/dev/null \
      || fail "a Landlock-only run does not say why the earlier runs stay readable: $(reg '.runs[-1].earlier_runs_hidden')"
  fi
  # The hook drops the agent before the guarded shell starts.
  for hook in "$sb/.zsh/.zshenv" "$sb/.bash/.bashrc"; do
    u="$(grep -n '^unset SSH_AUTH_SOCK$' "$hook" | cut -d: -f1 | head -1)"
    x="$(grep -n 'exec bash .*scripts/fsguard.sh' "$hook" | cut -d: -f1 | head -1)"
    [[ -n "$u" && -n "$x" && "$u" -lt "$x" ]] || fail "$hook does not unset SSH_AUTH_SOCK before the guard"
  done
  # And the kernel: the pane's own guard, as its hook runs it.
  line="$(grep -m1 '^  exec bash .*scripts/fsguard.sh' "$sb/.zsh/.zshenv")"
  prefix="${line%% --in-place -- *}"
  eval "guard=(${prefix#*exec })"
  # Both ways the guard is run: in place, as the pane's shell runs it (on
  # Linux, `unshare` with no fork), and as a child (bubblewrap, where it is).
  mkdir -p "$SWARM_RUNS_DIR/reviews"
  echo "an examiner's review" > "$SWARM_RUNS_DIR/reviews/earlier.jsonl"
  for inplace in "" --in-place; do
    guarded() { TMPDIR="$sb/work/.tmp" "${guard[@]}" ${inplace:+"$inplace"} -- "$@" 2>/dev/null; }
    for f in "$H/machine/canary" "$H/examiners/canary" "$EXKEY"; do
      if guarded cat "$f" | grep -q .; then fail "a guarded pane${inplace:+ ($inplace)} read $f"; fi
    done
    guarded cat "$SWARM_RUNS_DIR/registry.json" | grep -q '"runs"' || fail "a guarded pane${inplace:+ ($inplace)} cannot read the registry the finish line reads"
    guarded cat "$sb/SWARM.md" | grep -q . || fail "a guarded pane${inplace:+ ($inplace)} cannot read its own contract"
    if fsguard_can_mask "$MODE"; then
      if guarded cat "$first_sb/work/finding.md" | grep -q .; then fail "a guarded pane${inplace:+ ($inplace)} read an earlier run's finding"; fi
      if guarded cat "$SWARM_RUNS_DIR/reviews/earlier.jsonl" | grep -q .; then fail "a guarded pane${inplace:+ ($inplace)} read the examiners' reviews"; fi
      got="$(guarded python3 -c "$probe_connect" "$TMP/agent/agent.sock" || true)"
      [[ "$got" != REACHABLE ]] || fail "a guarded pane${inplace:+ ($inplace)} connected to the ssh-agent's socket"
    fi
  done
  # The registry is rewritten by rename while the panes run (a new inode). A
  # pane started before must still read it: a Landlock carve beneath runs/
  # would freeze that directory, and the finish line would fall back to
  # SWARM.md, which it does not trust; so the earlier runs and the reviews
  # are the mount layer's, not Landlock's. (Landlock alone already carves
  # beneath runs/ for the read-only traces/, and has that fault; it is not
  # asserted here.)
  if fsguard_can_mask "$MODE"; then
    inplace=--in-place
    guarded sh -c 'sleep 3; cat "$1"' _ "$SWARM_RUNS_DIR/registry.json" > "$TMP/late-read" &
    late=$!
    sleep 1
    jq . "$SWARM_RUNS_DIR/registry.json" > "$SWARM_RUNS_DIR/registry.json.tmp" && mv "$SWARM_RUNS_DIR/registry.json.tmp" "$SWARM_RUNS_DIR/registry.json"
    wait "$late" || true
    grep -q '"runs"' "$TMP/late-read" || fail "a pane started before the registry was rewritten cannot read it after ($MODE)"
  fi
  if fsguard_can_mask "$MODE"; then
    [[ "$(python3 -c "$probe_connect" "$TMP/agent/agent.sock")" == REACHABLE ]] || fail "the control: the socket is not reachable even unguarded, so the check above proves nothing"
    guarded() { cat "$@"; }
    guarded "$first_sb/work/finding.md" | grep -q . || fail "the control: the earlier finding is not readable unguarded"
  fi
  ok "a guarded run ($MODE) records the keys hidden, and its panes cannot read them$(fsguard_can_mask "$MODE" && printf ', an earlier run or the reviews, or reach the agent, while the registry, rewritten under it, stays readable'); the run itself stays readable"
fi

echo "# machine rotate"
old_fp="$(jq -r .fingerprint "$H/machine/machine.json")"
old_id="$(jq -r .id "$H/machine/machine.json")"
out="$(swarm machine rotate)" || fail "machine rotate failed: $out"
new_fp="$(jq -r .fingerprint "$H/machine/machine.json")"
new_id="$(jq -r .id "$H/machine/machine.json")"
[[ "$new_id" != "$old_id" && "$new_fp" != "$old_fp" ]] || fail "rotate did not make a new key"
grep -qF "Retired:      $old_fp (machine key $old_id)" <<<"$out" && grep -qF "New:          $new_fp (machine key $new_id)" <<<"$out" \
  || fail "rotate does not print both fingerprints: $out"
R="$H/machine/retired/$old_id"
for f in release_ed25519 release_ed25519.pub machine.json retired.json; do
  [[ -f "$R/$f" ]] || fail "the retired key's $f is not kept in $R"
done
[[ "$(jq -r .fingerprint "$R/machine.json")" == "$old_fp" ]] || fail "the retired record is not the old key's"
[[ "$(mode_of "$R")" == 700 && "$(mode_of "$H/machine/retired")" == 700 && "$(mode_of "$R/release_ed25519")" == 600 ]] || fail "the retired key is not kept 0700/0600"
out="$(swarm machine rotate)" || fail "a second rotate failed: $out"
[[ -f "$R/release_ed25519" && -f "$H/machine/retired/$new_id/release_ed25519" ]] || fail "a second rotate lost a retired key"
[[ "$(find "$H/machine" -name release_ed25519 -type f | wc -l | tr -d ' ')" == 3 ]] || fail "rotating twice should leave three keys (two retired, one live)"
out="$(DFIRSWARM_HOME="$TMP/fresh" swarm machine rotate)" || fail "rotate with no key failed"
grep -q "No machine key" <<<"$out" || fail "rotate with no key does not say so: $out"
mkdir -p "$TMP/half/machine" && echo '{}' > "$TMP/half/machine/machine.json"
set +e
out="$(DFIRSWARM_HOME="$TMP/half" swarm machine rotate 2>&1)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q "half a machine key" <<<"$out" || fail "rotate moved half a key (rc $rc): $out"
# A signing key that exists only retired still counts.
set +e
out="$(DFIRSWARM_HOME="$H" bash -c "$(declare -f signers_home signer_homes signer_keys_present); signer_keys_present" 2>&1)"
set -e
grep -qF "a retired machine key	$R/release_ed25519" <<<"$out" || fail "a retired machine key is not counted as a signing key: $out"
ok "rotate retires the key into machine/retired/<id>/ (0700/0600, never deleted), makes the next, prints both fingerprints; refuses half a key"

echo "signer-isolation.test.sh: all $pass checks passed"

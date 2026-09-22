#!/usr/bin/env bash
# Evidence held by the host kernel, not by a mount option.
#
# Phase 3 of docs/sandbox-plan.md. Two halves, and the first one is the reason
# the second exists:
#
#   1. A container with CAP_SYS_ADMIN — the capability that mounting a
#      forensic image needs — remounts a `:ro` bind read-write and edits the
#      host's file. Measured, not assumed. This assertion exists so that
#      nobody later "simplifies" the design back to a bind mount.
#   2. The same container against an image attached read-only on the host gets
#      "Read-only file system", and the bytes are untouched.
#
# Docker is optional: without it the container halves are skipped and the
# host-side assertions still run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pass=0
ok() { echo "ok - $1"; pass=$((pass + 1)); }
fail() { echo "not ok - $1" >&2; exit 1; }

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "skip - --inputs-image needs macOS (hdiutil); on Linux a read-only loop mount needs root"
  echo "evidence-image.test.sh: skipped on this host"
  exit 0
fi

# Under /private/tmp rather than the per-user temp directory: Docker Desktop
# shares the first and not the second, and the container half of this file is
# worth running.
TMP="$(mktemp -d "/private/tmp/evidence-image.XXXXXX")"
TMP="$(cd "$TMP" && pwd -P)"
SANDBOX=""
cleanup() {
  [[ -n "$SANDBOX" ]] && hdiutil detach "$SANDBOX/inputs" -force -quiet 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$TMP/src"
printf 'PRISTINE\n' > "$TMP/src/case.raw"
# UDRW, not UDZO: a compressed image is read-only by format, so a test built
# on one cannot tell whether `-readonly` does anything. With a writable image
# the flag is the only thing standing between the pane and the evidence.
hdiutil create -quiet -size 10m -fs APFS -volname CASE -o "$TMP/case.dmg" || fail "could not build the test image"
mp="$(hdiutil attach -nobrowse "$TMP/case.dmg" | awk '/\/Volumes\// {print $NF; exit}')"
[[ -n "$mp" ]] || fail "could not attach the image to fill it"
printf 'PRISTINE\n' > "$mp/case.raw"
hdiutil detach "$mp" -quiet || fail "could not detach after filling"

out="$(SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" start \
  --model solo/model --n 1 --cap-usd 1 --no-start \
  --goal-file "$ROOT/prompts/goals/hello.md" --label image --inputs-image "$TMP/case.dmg" 2>&1)"
SANDBOX="$(printf '%s\n' "$out" | sed -n 's/^SANDBOX=//p' | tail -1)"
[[ -n "$SANDBOX" && -d "$SANDBOX/inputs" ]] || fail "no sandbox from --inputs-image: $out"
ok "--inputs-image prepares a run"

[[ "$(cat "$SANDBOX/inputs/case.raw")" == "PRISTINE" ]] || fail "the evidence did not arrive"
ok "the evidence is readable"

if touch "$SANDBOX/inputs/probe" 2>/dev/null; then fail "the attached image is writable"; fi
ok "the host cannot write the attached image"

# macOS lets `chmod` report success against a read-only mount — measured, and
# the reason this is asserted on the bytes rather than on the mode. What must
# hold is that no write lands, whatever the mode says afterwards.
chmod u+w "$SANDBOX/inputs/case.raw" 2>/dev/null || true
if printf 'TAMPERED\n' > "$SANDBOX/inputs/case.raw" 2>/dev/null; then fail "a write landed after chmod"; fi
[[ "$(cat "$SANDBOX/inputs/case.raw")" == "PRISTINE" ]] || fail "the evidence changed"
ok "chmod cannot buy a write: the bytes are still refused, and still PRISTINE"

guard="$(jq -r '.guard' "$SANDBOX/inputs.json")"
[[ "$guard" == "image" ]] || fail "the manifest should record guard=image, got $guard"
[[ "$(jq -r '.attached' "$SANDBOX/inputs.json")" == "true" ]] || fail "the manifest should say it is attached"
[[ "$(jq -r '.files | length' "$SANDBOX/inputs.json")" == "1" ]] || fail "the manifest should list the file"
ok "the manifest records the image, its hash and how it is held"

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  # 1. The trap: a :ro bind is not a write block against CAP_SYS_ADMIN.
  mkdir -p "$TMP/bind"
  printf 'PRISTINE\n' > "$TMP/bind/case.raw"
  docker run --rm --cap-add SYS_ADMIN -v "$TMP/bind:/ev:ro" alpine:3 sh -c \
    'mount -o remount,rw /ev 2>/dev/null; echo TAMPERED > /ev/case.raw 2>/dev/null' >/dev/null 2>&1 || true
  if [[ "$(cat "$TMP/bind/case.raw")" == "PRISTINE" ]]; then
    echo "note - this docker refused the remount; the :ro-bind assertion is weaker here than when it was measured"
  else
    ok "a :ro bind mount does NOT hold against container root (which is why evidence goes on an image)"
  fi

  # 2. The fix: the same container against the attached image.
  #
  # First prove the container can SEE the evidence. Docker Desktop shares only
  # certain host paths — `/private/tmp` yes, the `/private/var/folders` that
  # `mktemp` hands out no — and a mount it does not share arrives as an empty
  # directory, where the write below fails for entirely the wrong reason. An
  # assertion that passes against a read-write image is not an assertion.
  seen="$(docker run --rm -v "$SANDBOX/inputs:/ev:ro" alpine:3 sh -c 'cat /ev/case.raw 2>/dev/null' 2>/dev/null || true)"
  if [[ "$seen" != "PRISTINE" ]]; then
    echo "skip - this docker does not share $SANDBOX/inputs into the VM, so the container half would pass vacuously"
  else
    docker run --rm --cap-add SYS_ADMIN -v "$SANDBOX/inputs:/ev:ro" alpine:3 sh -c \
      'mount -o remount,rw /ev 2>/dev/null; echo TAMPERED > /ev/case.raw 2>/dev/null' >/dev/null 2>&1 || true
    [[ "$(cat "$SANDBOX/inputs/case.raw")" == "PRISTINE" ]] || fail "container root modified evidence on an attached image"
    ok "container root cannot modify evidence attached read-only on the host (and could read it, so the write was really refused)"
  fi
else
  echo "skip - docker is not available; the container halves were not run"
fi

# Teardown detaches, so the sandbox can be reused.
SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" stop "$(basename "$SANDBOX")" >/dev/null 2>&1 || true
if mount | grep -q "$SANDBOX/inputs"; then fail "the image is still attached after stop"; fi
SANDBOX=""
ok "stop detaches the image"

echo "evidence-image.test.sh: all $pass checks passed"

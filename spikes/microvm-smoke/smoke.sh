#!/usr/bin/env bash
# microsandbox smoke test for a DFIR swarm, on macOS arm64 or Linux x86_64/arm64.
#
#   bash smoke.sh WORKDIR [BLOB_GIB]
#
# Builds synthetic evidence under WORKDIR (never real case data), then checks:
#   1. tamper   guest root cannot change evidence mounted read-only (host verdict)
#   2. network  --no-net is closed; a domain allowlist opens only that domain
#   3. speed    evidence read and sha256 inside the VM vs on the host, same hash
#   4. stream   lossless output, concurrency, timeout, kill, reattach (stream.mjs)
#   5. offline  save / remove / load an image, boot with --pull never --no-net
# Run `npm install` in this directory first.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
W=${1:?usage: smoke.sh WORKDIR [BLOB_GIB]}
GIB=${2:-8}
IMG=python:3.12-slim-bookworm
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) PLAT=darwin-arm64 ;;
  Linux-x86_64) PLAT=linux-x64-gnu ;;
  Linux-aarch64) PLAT=linux-arm64-gnu ;;
  *) echo "unsupported host $(uname -sm)"; exit 2 ;;
esac
export PATH="$HERE/node_modules/@superradcompany/microsandbox-$PLAT/bin:$PATH"
CPUS=$(( $(getconf _NPROCESSORS_ONLN) < 4 ? $(getconf _NPROCESSORS_ONLN) : 4 ))
FAILED=0
verdict() { if [[ "$1" == 0 ]]; then echo "PASS  $2"; else echo "FAIL  $2"; FAILED=$((FAILED + 1)); fi; }

echo "== host: $(uname -srm), msb $(msb --version | awk '{print $2}'), $CPUS vCPU for the VM"
msb doctor 2>&1 | tail -1
msb pull "$IMG" 2>&1 | tail -1

# -- synthetic evidence ------------------------------------------------------
mkdir -p "$W/evidence/sub" "$W/work"
E="$W/evidence"
if [[ ! -f "$E/blob.bin" ]]; then
  printf 'case notes: original evidence, do not alter\n' > "$E/notes.txt"
  head -c 1048576 /dev/urandom > "$E/sub/a.bin"
  printf '#!/bin/sh\necho executed-from-evidence\n' > "$E/tool.sh"; chmod 755 "$E/tool.sh"
  head -c $((GIB * 1024 * 1024 * 1024)) /dev/urandom > "$E/blob.bin"
  msb run -q --no-net --mount-dir "$W/work:/work" "$IMG" -- sh -c '
    mkdir -p /tmp/img/docs && echo "suspect ledger entry 42" > /tmp/img/docs/ledger.txt &&
    head -c 262144 /dev/urandom > /tmp/img/docs/payload.bin &&
    truncate -s 64M /work/disk.ext4 && mkfs.ext4 -q -F -L EVIDENCE -d /tmp/img /work/disk.ext4'
  mv "$W/work/disk.ext4" "$E/disk.ext4"
fi
python3 "$HERE/manifest.py" take "$E" "$W/before.json" >/dev/null

# -- 1. tamper -----------------------------------------------------------------
echo; echo "== 1. tamper"
msb run -q --no-net --mount-dir "$E:/evidence:ro,noexec" --mount-disk "$E/disk.ext4:/ev2:ro" \
  --script-path "tamper:$HERE/guest-tamper.sh" "$IMG" -- sh -c tamper 2>&1 | tee "$W/tamper.log" | grep -E 'SUCCEEDED|remount|mount tag'
python3 "$HERE/manifest.py" take "$E" "$W/after.json" >/dev/null
python3 "$HERE/manifest.py" diff "$W/before.json" "$W/after.json"
verdict $? "evidence unchanged on the host after every tamper attempt"
grep -q '^SUCCEEDED  execute tool.sh directly' "$W/tamper.log"; verdict $(( $? == 0 )) "noexec refuses direct execution"

# -- 2. network ----------------------------------------------------------------
echo; echo "== 2. network"
probe() { msb run -q "$@" --mount-file "$HERE/guest-net.py:/opt/guest-net.py:ro" "$IMG" -- python3 /opt/guest-net.py 2>&1; }
probe --no-net > "$W/net-none.log"
grep -c '^OPEN' "$W/net-none.log" | xargs -I{} echo "--no-net: {} probe(s) answered (the local NXDOMAIN counts as one)"
! grep -E '^OPEN' "$W/net-none.log" | grep -v 'udp 8.8.8.8:53 direct DNS: .* rcode NXDOMAIN, 0 answer' | grep -q .
verdict $? "--no-net: nothing reaches out"
probe --no-net --net-rule "allow@deb.debian.org:tcp:80" --net-rule "allow@deb.debian.org:tcp:443" > "$W/net-allow.log"
cat "$W/net-allow.log"
opened=$(grep '^OPEN' "$W/net-allow.log" | sed -E 's/^OPEN +//; s/:.*//' | sort | tr '\n' '|')
[[ "$opened" == "http deb.debian.org Release|resolve deb.debian.org|tcp deb.debian.org|udp 8.8.8.8|" ]] &&
  grep -q '^OPEN     udp 8.8.8.8:53 direct DNS: .* rcode NXDOMAIN, 0 answer' "$W/net-allow.log"
verdict $? "allowlist opens deb.debian.org and nothing else (got: $opened)"

# -- 3. speed and integrity ----------------------------------------------------
echo; echo "== 3. speed and integrity ($GIB GiB)"
READ='
import hashlib, sys, time
p = sys.argv[1]; t = time.time(); n = 0
with open(p, "rb") as f:
    while b := f.read(16 << 20): n += len(b)
r = time.time() - t; t = time.time(); h = hashlib.sha256()
with open(p, "rb") as f:
    while b := f.read(16 << 20): h.update(b)
s = time.time() - t
print(f"read {n/2**20/r:,.0f} MiB/s  sha256 {n/2**20/s:,.0f} MiB/s  {h.hexdigest()}")'
host=$(python3 -c "$READ" "$E/blob.bin"); echo "host  $host"
vm=$(msb run -q --no-net --cpus "$CPUS" --memory 1G --mount-dir "$E:/evidence:ro,noexec" "$IMG" -- python3 -c "$READ" /evidence/blob.bin 2>&1); echo "VM    $vm"
[[ "${host##* }" == "${vm##* }" ]]; verdict $? "sha256 inside the VM equals the host's"

# -- 4. stream -----------------------------------------------------------------
echo; echo "== 4. stream (SDK)"
( cd "$HERE" && node stream.mjs ) | tee "$W/stream.log" | grep -E '^(PASS|FAIL)'
passes=$(grep -c '^PASS' "$W/stream.log")
others=$(grep '^FAIL' "$W/stream.log" | grep -vc 'known gap in 0.7.2')
[[ $passes -ge 8 && $others -eq 0 ]]
verdict $? "every stream check passes except the known SDK timeout gap ($passes passed)"

# -- 5. offline ----------------------------------------------------------------
echo; echo "== 5. offline"
msb save --output "$W/image.tar" "$IMG" >/dev/null 2>&1
msb image rm "$IMG" >/dev/null 2>&1
msb run -q --pull never --no-net "$IMG" -- true >/dev/null 2>&1; refused=$?
msb load --input "$W/image.tar" --tag dfir-offline:smoke >/dev/null 2>&1
msb run -q --pull never --no-net dfir-offline:smoke -- sh -c 'echo offline-ready' 2>&1 | grep -q offline-ready
booted=$?
[[ $refused != 0 && $booted == 0 ]]; verdict $? "pull never refuses an uncached image, a loaded archive boots offline"

echo; echo "== $([[ $FAILED == 0 ]] && echo ALL PASSED || echo "$FAILED FAILED")"
exit $FAILED

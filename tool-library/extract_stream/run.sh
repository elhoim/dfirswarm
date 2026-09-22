#!/bin/bash
# Extract a data stream by inode from an E01 image; the bytes come back
# base64-encoded.
#
# It used to end `icat -o "$OFFSET" "$IMAGE" "$INODE" 2>&1 | base64`, which
# had two faults a caller could not see. The `2>&1` put icat's error text into
# the base64 payload, so "inode not found" decoded as forty-odd bytes of file
# content. The pipe then made the exit status base64's, which is always 0, so
# a failed extraction reported success. Errors now go back as JSON with
# icat's own status.
set -uo pipefail
ARGS=$(cat)
FIELDS=$(printf '%s' "$ARGS" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except ValueError as exc:
    print(json.dumps({"error": "arguments are not valid JSON", "reason": str(exc)}))
    raise SystemExit(2)
image = d.get("image")
if not isinstance(image, str) or not image or "\n" in image:
    print(json.dumps({"error": "image must be a single-line path", "image": image}))
    raise SystemExit(2)
inode = d.get("inode")
if isinstance(inode, int) and not isinstance(inode, bool):
    inode = str(inode)
if not isinstance(inode, str) or not inode or "\n" in inode:
    print(json.dumps({"error": "inode must be a string like 168-128-4, or an integer", "inode": d.get("inode")}))
    raise SystemExit(2)
offset = d.get("offset", 0)
if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
    print(json.dumps({"error": "offset must be a non-negative sector count", "offset": d.get("offset")}))
    raise SystemExit(2)
print(image)
print(inode)
print(offset)
')
rc=$?
# A refusal is JSON the caller has to see; command substitution would
# otherwise swallow it and leave an empty stdout with no reason.
if [ "$rc" -ne 0 ]; then
  printf '%s\n' "$FIELDS"
  exit "$rc"
fi
IMAGE=$(printf '%s\n' "$FIELDS" | sed -n 1p)
INODE=$(printf '%s\n' "$FIELDS" | sed -n 2p)
OFFSET=$(printf '%s\n' "$FIELDS" | sed -n 3p)

RAW=$(mktemp) || { echo '{"error":"cannot create a temporary file"}'; exit 1; }
ERR=$(mktemp) || { rm -f "$RAW"; echo '{"error":"cannot create a temporary file"}'; exit 1; }
trap 'rm -f "$RAW" "$ERR"' EXIT
icat -o "$OFFSET" "$IMAGE" "$INODE" > "$RAW" 2> "$ERR"
rc=$?
if [ "$rc" -ne 0 ]; then
  python3 -c '
import json, sys
print(json.dumps({
    "error": "icat failed",
    "status": int(sys.argv[1]),
    "image": sys.argv[2],
    "inode": sys.argv[3],
    "stderr": sys.stdin.read().strip()[:2000],
}))
' "$rc" "$IMAGE" "$INODE" < "$ERR"
  exit "$rc"
fi
base64 < "$RAW"

#!/bin/bash
# Extract a file by inode from an E01. The HDFS master image and sector
# offset 2048 are the defaults, because that is the case this was written for.
# stdin is a pipe and can only be read once: parsing it twice left the
# second reader with EOF, so under `set -e` every call died before icat ran.
set -euo pipefail
ARGS=$(cat)
set +e
FIELDS=$(printf '%s' "$ARGS" | python3 -c '
import json, sys
from pathlib import Path
try:
    d = json.load(sys.stdin)
except ValueError as exc:
    print(json.dumps({"error": "arguments are not valid JSON", "reason": str(exc)}))
    raise SystemExit(1)
inode = d.get("inode")
if not isinstance(inode, int) or isinstance(inode, bool) or inode < 0:
    print(json.dumps({"error": "inode must be a non-negative integer", "inode": inode}))
    raise SystemExit(1)
out = d.get("output") or ""
if not isinstance(out, str) or "\n" in out:
    print(json.dumps({"error": "output must be a single-line path"}))
    raise SystemExit(1)
# The image this was written for stays the default, so the calls that exist
# still work; naming another one makes it a tool about extracting an inode
# rather than a tool about one cluster.
image = d.get("image") or "inputs/HDFS-Master.E01"
if not isinstance(image, str) or not image or "\n" in image:
    print(json.dumps({"error": "image must be a single-line path"}))
    raise SystemExit(1)
offset = d.get("offset", 2048)
if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
    print(json.dumps({"error": "offset must be a non-negative sector count"}))
    raise SystemExit(1)
dest = ""
if out:
    # Same rule as aescrypt_v2_decrypt: resolve first. A prefix check on the
    # string the caller typed misses work/../inputs/x and an absolute path.
    root = Path.cwd().resolve()
    dest_path = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest_path != root and root not in dest_path.parents:
        print(json.dumps({"error": "output must stay inside the run directory", "output": out}))
        raise SystemExit(1)
    inputs = root / "inputs"
    if dest_path == inputs or inputs in dest_path.parents:
        print(json.dumps({"error": "output cannot be under inputs/", "output": out}))
        raise SystemExit(1)
    dest = str(dest_path)
print(inode)
print(out)
print(image)
print(offset)
print(dest)
')
rc=$?
set -e
# A refusal is JSON the caller has to see, and command substitution had
# swallowed it: the script exited with an empty stdout and no reason.
if [ "$rc" -ne 0 ]; then
  printf '%s\n' "$FIELDS"
  exit "$rc"
fi
INODE=$(printf '%s\n' "$FIELDS" | sed -n 1p)
OUTPUT=$(printf '%s\n' "$FIELDS" | sed -n 2p)
IMAGE=$(printf '%s\n' "$FIELDS" | sed -n 3p)
OFFSET=$(printf '%s\n' "$FIELDS" | sed -n 4p)
DEST=$(printf '%s\n' "$FIELDS" | sed -n 5p)
if [ -n "$OUTPUT" ]; then
  mkdir -p "$(dirname "$DEST")"
  icat -o "$OFFSET" "$IMAGE" "$INODE" > "$DEST"
  echo "{\"inode\":$INODE,\"image\":\"$IMAGE\",\"offset\":$OFFSET,\"output\":\"$OUTPUT\",\"size\":$(wc -c < "$DEST" | tr -d ' ')}"
else
  icat -o "$OFFSET" "$IMAGE" "$INODE"
fi

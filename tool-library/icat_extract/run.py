#!/usr/bin/env python3
"""Extract an inode from an E01 image to a path. Args come from JSON stdin."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def fail(msg, **extra):
    print(json.dumps({"error": msg, **extra}))
    sys.exit(1)


def resolve_output(out):
    """Where `out` really lands, refusing anything outside the run directory.

    A string check is not enough: `work/../inputs/x` and an absolute path
    both name a file the tool must not write, and neither starts with
    "inputs/". Resolving first and comparing directories is what actually
    holds, and the read-only inputs are the one place extracted bytes must
    never appear -- a later integrity check would report the evidence as
    modified.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest != root and root not in dest.parents:
        fail("output must stay inside the run directory", output=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("output cannot be under inputs/", output=str(out))
    return dest


d = json.load(sys.stdin)
inode = d.get("inode")
output = d.get("output")
image = d.get("image") or "inputs/AF-Case2.E01"
offset = d.get("offset", 0)
if inode is None or not isinstance(output, str) or not output:
    fail("need inode and output")
dest = resolve_output(output)
if not os.path.isfile(image):
    fail(f"image not found: {image}")
r = subprocess.run(
    ["icat", "-o", str(offset), image, str(inode)],
    capture_output=True,
)
if r.returncode != 0:
    err = r.stderr.decode("utf-8", "replace").strip() or f"icat exit {r.returncode}"
    fail(err, image=image, inode=inode)
dest.parent.mkdir(parents=True, exist_ok=True)
dest.write_bytes(r.stdout)
digest = hashlib.sha256(r.stdout).hexdigest()
print(json.dumps({"path": output, "size": len(r.stdout), "sha256": digest, "image": image}))

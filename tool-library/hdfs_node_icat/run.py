#!/usr/bin/env python3
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
node = str(d.get("node", "master")).lower()
inode = str(d.get("inode", "")).strip()
output = d.get("output", "")
# The three images of the cluster this was written for, kept as defaults.
# `image` names any other one, so the tool is about extracting an inode from
# a node rather than about that one cluster.
imgs = {
    "master": "inputs/HDFS-Master.E01",
    "m": "inputs/HDFS-Master.E01",
    "slave1": "inputs/HDFS-Slave1.E01",
    "s1": "inputs/HDFS-Slave1.E01",
    "slave2": "inputs/HDFS-Slave2.E01",
    "s2": "inputs/HDFS-Slave2.E01",
}
img = d.get("image") or imgs.get(node)
offset = str(d.get("offset", 2048))
if not img or not inode or not output:
    fail("need inode, output, and either node=master|slave1|slave2 or image")
if not isinstance(output, str):
    fail("output must be a path")
dest = resolve_output(output)
if not os.path.isfile(img):
    fail("image not found", image=img)
r = subprocess.run(["icat", "-o", offset, img, inode], capture_output=True)
if r.returncode != 0:
    fail(r.stderr.decode("utf-8", "replace"), inode=inode, node=node)
dest.parent.mkdir(parents=True, exist_ok=True)
dest.write_bytes(r.stdout)
h = hashlib.sha256(r.stdout).hexdigest()
print(json.dumps({"node": node, "image": img, "inode": inode, "output": output, "size": len(r.stdout), "sha256": h, "offset": int(offset)}))

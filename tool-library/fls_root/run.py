#!/usr/bin/env python3
"""List a directory inode on an EXT4 volume. Args come from JSON stdin."""
import json
import os
import subprocess
import sys

d = json.load(sys.stdin)
image = d.get("image") or "inputs/Webserver.E01"
offset = d.get("offset", 503808)
inode = d.get("inode", 2)
recursive = bool(d.get("recursive"))
if not os.path.isfile(image):
    print(json.dumps({"error": f"image not found: {image}"}))
    sys.exit(1)
cmd = ["fls", "-o", str(offset)]
if recursive:
    cmd.append("-r")
cmd += [image, str(inode)]
r = subprocess.run(cmd, capture_output=True)
if r.returncode != 0:
    err = r.stderr.decode("utf-8", "replace").strip() or f"fls exit {r.returncode}"
    print(json.dumps({"error": err, "image": image, "inode": inode}))
    sys.exit(r.returncode or 1)
sys.stdout.buffer.write(r.stdout)

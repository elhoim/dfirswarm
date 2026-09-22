#!/usr/bin/env python3
"""Run a Volatility 3 plugin. Args are an argv list, never joined for a shell."""
import json
import os
import subprocess
import sys

d = json.load(sys.stdin)
image = d.get("image") or ""
plugin = d.get("plugin") or ""
args = d.get("args") or []
if not image or not plugin:
    print(json.dumps({"error": "image and plugin required"}))
    sys.exit(1)
if not os.path.isfile(image):
    print(json.dumps({"error": f"image not found: {image}"}))
    sys.exit(1)
if not isinstance(args, list) or not all(isinstance(a, (str, int, float)) for a in args):
    print(json.dumps({"error": "args must be a list of strings"}))
    sys.exit(1)
cmd = ["vol", "-f", image, str(plugin), *[str(a) for a in args]]
r = subprocess.run(cmd, capture_output=True)
sys.stdout.buffer.write(r.stdout)
sys.stderr.buffer.write(r.stderr)
sys.exit(r.returncode)

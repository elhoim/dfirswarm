#!/usr/bin/env python3
"""Diff inputs/ against inputs.json. Always-OK hashing is a false negative."""
import hashlib
import json
import os
import sys

MANIFEST = "inputs.json"
if not os.path.isfile(MANIFEST):
    print(json.dumps({"status": "FAIL", "error": "inputs.json not found"}))
    sys.exit(1)
try:
    man = json.load(open(MANIFEST, encoding="utf-8"))
except json.JSONDecodeError as err:
    print(json.dumps({"status": "FAIL", "error": f"inputs.json is not JSON: {err}"}))
    sys.exit(1)
files = man.get("files") if isinstance(man, dict) else None
if not isinstance(files, list):
    print(json.dumps({"status": "FAIL", "error": "inputs.json has no files list"}))
    sys.exit(1)

modified = []
missing = []
known = {}
for entry in files:
    if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
        continue
    rel = entry["path"]
    known[rel] = entry
    if not os.path.isfile(rel):
        missing.append(rel)
        continue
    data = open(rel, "rb").read()
    digest = hashlib.sha256(data).hexdigest()
    size = len(data)
    want_hash = entry.get("sha256")
    want_bytes = entry.get("bytes")
    if want_hash and digest != want_hash:
        modified.append(rel)
    elif want_bytes is not None and int(want_bytes) != size:
        modified.append(rel)

added = []
if os.path.isdir("inputs"):
    for root, _dirs, names in os.walk("inputs"):
        for name in names:
            rel = os.path.join(root, name).replace("\\", "/")
            if rel not in known:
                added.append(rel)

ok = not modified and not missing and not added
print(json.dumps({
    "status": "OK" if ok else "FAIL",
    "ok": ok,
    "modified": modified,
    "missing": missing,
    "added": added,
    "checked": len(known),
}))
sys.exit(0 if ok else 1)

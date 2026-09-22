#!/usr/bin/env python3
import json, re, sys
from pathlib import Path
args = json.load(sys.stdin)
pattern = args.get("pattern", "")
ignore_case = bool(args.get("ignore_case", True))
limit = int(args.get("limit", 200))
path = args.get("path", "catalog/AF-Case2.E01/p0/filelist.txt")
flags = re.I if ignore_case else 0
rx = re.compile(pattern, flags)
out = []
with open(path, "r", errors="replace") as f:
    for line in f:
        if rx.search(line):
            out.append(line.rstrip("\n"))
            if len(out) >= limit:
                break
print(json.dumps({"count": len(out), "truncated": len(out) >= limit, "lines": out}))

#!/usr/bin/env python3
import json, re, sys
from pathlib import Path
args = json.load(sys.stdin)
path = Path(args["path"])
pattern = args["pattern"]
flags = re.I if args.get("ignore_case", True) else 0
limit = int(args.get("limit", 80))
context = int(args.get("context", 0))
rx = re.compile(pattern, flags)
text = path.read_text(errors="replace")
lines = text.splitlines()
hits = []
seen = set()
for i, line in enumerate(lines):
    if rx.search(line):
        start = max(0, i-context)
        end = min(len(lines), i+1+context)
        for j in range(start, end):
            if j in seen:
                continue
            seen.add(j)
            hits.append({"n": j+1, "line": lines[j][:500]})
        if len(hits) >= limit:
            break
print(json.dumps({"path": str(path), "count_shown": len(hits), "hits": hits}, ensure_ascii=True))

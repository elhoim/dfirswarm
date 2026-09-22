#!/usr/bin/env python3
import json, re, sys, os
args = json.load(sys.stdin)
pattern = args.get("pattern") or ""
which = args.get("which") or "filelist"
flags = re.IGNORECASE if args.get("ignore_case", True) else 0
limit = int(args.get("limit") or 200)
exclude = args.get("exclude") or ""
try:
    rx = re.compile(pattern, flags)
except re.error as e:
    print(json.dumps({"error": str(e)}))
    sys.exit(1)
ex = re.compile(exclude, flags) if exclude else None
base = "catalog/SysInternalsCase.E01"
paths = {
    "filelist": os.path.join(base, "p0/filelist.txt"),
    "timeline": os.path.join(base, "p0/timeline.csv"),
    "bodyfile": os.path.join(base, "p0/bodyfile.txt"),
    "fsstat": os.path.join(base, "p0/fsstat.txt"),
    "partitions": os.path.join(base, "partitions.txt"),
}
path = paths.get(which)
if not path:
    print(json.dumps({"error": "which must be filelist|timeline|bodyfile|fsstat|partitions"}))
    sys.exit(1)
hits = []
total = 0
with open(path, "r", errors="replace") as f:
    for i, line in enumerate(f, 1):
        if rx.search(line):
            if ex and ex.search(line):
                continue
            total += 1
            if len(hits) < limit:
                hits.append({"n": i, "line": line.rstrip("\n")})
print(json.dumps({"which": which, "pattern": pattern, "matched": total, "returned": len(hits), "hits": hits}))

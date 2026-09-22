#!/usr/bin/env python3
import json, sys, sqlite3, re
args = json.load(sys.stdin)
path = args["path"]
sql = args["sql"]
minlen = int(args.get("minlen", 6))
con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
rows = []
pat = re.compile(rb"[\x20-\x7e]{%d,400}" % minlen)
for rec in con.execute(sql):
    item = {"key": str(rec[0]) if rec else None, "strings": []}
    for col in rec[1:]:
        if col is None:
            continue
        if isinstance(col, str):
            item["strings"].append(col)
            continue
        if isinstance(col, bytes):
            for m in pat.findall(col):
                item["strings"].append(m.decode("ascii"))
    rows.append(item)
print(json.dumps({"n": len(rows), "rows": rows}, indent=1))

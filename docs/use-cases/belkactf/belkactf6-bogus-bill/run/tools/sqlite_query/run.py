import json, sqlite3, sys
args = json.load(sys.stdin)
path = args["path"]
sql = args["sql"]
limit = int(args.get("limit", 200))
con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
con.row_factory = sqlite3.Row
cur = con.execute(sql)
rows = []
for i, r in enumerate(cur):
    if i >= limit:
        break
    d = {}
    for k in r.keys():
        v = r[k]
        if isinstance(v, bytes):
            d[k] = {"_bytes": len(v)}
        else:
            d[k] = v
    rows.append(d)
print(json.dumps({"n": len(rows), "rows": rows}, default=str))

import json, sqlite3, gzip, sys, re
args = json.load(sys.stdin)
path = args["path"]
con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
con.row_factory = sqlite3.Row
out = []
for r in con.execute("SELECT o.Z_PK pk, o.ZTITLE1 title, o.ZSNIPPET snippet, d.ZDATA data FROM ZICCLOUDSYNCINGOBJECT o LEFT JOIN ZICNOTEDATA d ON d.ZNOTE=o.Z_PK OR d.Z_PK=o.ZNOTEDATA"):
    data = r["data"]
    text = None
    if data:
        try:
            u = gzip.decompress(data)
            m = re.findall(rb"[\x09\x0a\x0d\x20-\x7e\xc0-\xff]{8,}", u)
            text = "\n".join(x.decode("utf-8", "replace") for x in m)
        except Exception as e:
            text = f"decompress_error:{e}"
    if r["title"] or text:
        out.append({"pk": r["pk"], "title": r["title"], "snippet": r["snippet"], "text": text[:4000] if text else None})
print(json.dumps(out, ensure_ascii=False))

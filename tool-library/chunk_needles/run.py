#!/usr/bin/env python3
import io, json, sys, subprocess, os
args = json.load(sys.stdin)
needles = args.get("needles") or ""
path = args.get("path") or ""
inode = args.get("inode")
context = int(args.get("context") or 60)
max_hits = int(args.get("max_hits") or 20)
chunk = int(args.get("chunk") or 8 * 1024 * 1024)
need_list = [n for n in needles.split("|") if n]
if not need_list:
    print(json.dumps({"error": "needles required, pipe-separated"}))
    sys.exit(1)
variants = []
for n in need_list:
    b = n.encode("utf-8")
    variants.append((n, "ascii", b))
    variants.append((n, "utf16le", n.encode("utf-16le")))

def scan_fh(fh):
    hits = {n: {"ascii": 0, "utf16le": 0, "snippets": []} for n in need_list}
    overlap = 1024
    prev = b""
    offset = 0
    while True:
        buf = fh.read(chunk)
        if not buf:
            break
        data = prev + buf
        base = offset - len(prev)
        for n, enc, pat in variants:
            start = 0
            while True:
                i = data.find(pat, start)
                if i < 0:
                    break
                hits[n][enc] += 1
                if len(hits[n]["snippets"]) < max_hits:
                    a = max(0, i - context)
                    b = min(len(data), i + len(pat) + context)
                    snip = data[a:b]
                    txt = "".join(chr(c) if 32 <= c < 127 else "." for c in snip)
                    hits[n]["snippets"].append({"off": base + i, "enc": enc, "text": txt})
                start = i + 1
        prev = data[-overlap:]
        offset += len(buf)
        if not buf:
            break
    return hits, offset

if path:
    if not os.path.isfile(path):
        print(json.dumps({"error": f"path not found: {path}"}))
        sys.exit(1)
    with open(path, "rb") as f:
        hits, scanned = scan_fh(f)
    src = path
else:
    if inode is None:
        print(json.dumps({"error": "path or inode required"}))
        sys.exit(1)
    image = args.get("image") or "inputs/SysInternalsCase.E01"
    offset = args.get("offset")
    if not os.path.isfile(image):
        print(json.dumps({"error": f"image not found: {image}"}))
        sys.exit(1)
    cmd = ["icat"]
    if offset is not None:
        cmd += ["-o", str(offset)]
    cmd += [image, str(inode)]
    r = subprocess.run(cmd, capture_output=True)
    if r.returncode != 0:
        err = r.stderr.decode("utf-8", "replace").strip() or f"icat exit {r.returncode}"
        print(json.dumps({"error": err, "image": image, "inode": inode}))
        sys.exit(1)
    hits, scanned = scan_fh(io.BytesIO(r.stdout))
    src = f"icat:{inode}"
print(json.dumps({"source": src, "scanned_bytes": scanned, "hits": hits}))

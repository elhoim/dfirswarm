#!/usr/bin/env python3
import io, json, sys, subprocess, os

def _catalogue_slug(path):
    """The directory name the kickoff's catalogue gives an input: its path under
    inputs/ with every byte outside [A-Za-z0-9._-] made "_" (evidence-catalog.sh)."""
    import os, re
    rel = os.fsencode(os.path.relpath(path, "inputs"))
    return os.fsdecode(re.sub(rb"[^A-Za-z0-9._-]", b"_", rel))


def _resolve_image(explicit=None):
    """A pack tool belongs to no case: find the image under inputs/ instead of
    baking one in. One candidate is used; several mean the caller must say which.
    An image is known by its extension or, lacking one (a raw `dd` of a web
    server named after the host), by the catalogue: the kickoff writes
    catalog/<input>/partitions.txt for every input it read as a disk."""
    import glob, os
    if explicit:
        return explicit
    cands = []
    for ext in ("*.E01", "*.e01", "*.raw", "*.dd", "*.001", "*.img", "*.vhd", "*.vhdx"):
        cands += glob.glob(os.path.join("inputs", ext))
    for base, _dirs, files in os.walk("inputs", followlinks=True):
        for f in files:
            p = os.path.join(base, f)
            if os.path.isfile(os.path.join("catalog", _catalogue_slug(p), "partitions.txt")):
                cands.append(p)
    cands = sorted(set(cands))
    if len(cands) == 1:
        return cands[0]
    if not cands:
        raise SystemExit('{"ok": false, "error": "no disk image under inputs/; pass image="}')
    raise SystemExit('{"ok": false, "error": "several images under inputs/; pass image=", "candidates": %s}' % json.dumps(cands))


def _resolve_offset(image, explicit=None):
    """The volume's start sector for icat -o. Given, it is used as is; not
    given, the catalogue says: one filesystem catalogued (catalog/<input>/p<start>/)
    is that start, several mean the caller must say which, none is sector 0."""
    import os, re
    if explicit is not None:
        return explicit
    root = os.path.join("catalog", _catalogue_slug(image))
    starts = sorted(int(d[1:]) for d in (os.listdir(root) if os.path.isdir(root) else [])
                    if re.fullmatch(r"p\d+", d) and os.path.isdir(os.path.join(root, d)))
    if len(starts) == 1:
        return starts[0]
    if not starts:
        return 0
    raise SystemExit('{"ok": false, "error": "several filesystems in %s; pass offset= (a start sector, see %s/partitions.txt)", "candidates": %s}' % (image, root, json.dumps(starts)))


def _resolve_catalog(explicit=None):
    """The catalogue directory for the one image the kickoff catalogued, or
    the one named: by its name under catalog/, as the index lists it
    (catalog=Case4.E01 was a traceback), or by its path."""
    import os
    root = "catalog"
    subs = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))) if os.path.isdir(root) else []
    if explicit:
        for cand in (explicit, os.path.join(root, explicit)):
            if os.path.isdir(cand):
                return cand
        raise SystemExit(json.dumps({"ok": False, "error": "no catalogue %s" % explicit, "candidates": subs}))
    if not os.path.isdir(root):
        raise SystemExit('{"ok": false, "error": "no catalog/ in this run; pass catalog="}')
    if len(subs) == 1:
        return os.path.join(root, subs[0])
    if not subs:
        raise SystemExit('{"ok": false, "error": "catalog/ is empty; pass catalog="}')
    raise SystemExit('{"ok": false, "error": "several catalogues; pass catalog=", "candidates": %s}' % json.dumps(subs))

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
    image = _resolve_image(args.get("image"))
    if not os.path.isfile(image):
        print(json.dumps({"error": f"image not found: {image}"}))
        sys.exit(1)
    offset = _resolve_offset(image, args.get("offset"))
    r = subprocess.run(["icat", "-o", str(offset), image, str(inode)], capture_output=True)
    if r.returncode != 0:
        err = r.stderr.decode("utf-8", "replace").strip() or f"icat exit {r.returncode}"
        print(json.dumps({"error": err, "image": image, "inode": inode, "offset": offset}))
        sys.exit(1)
    hits, scanned = scan_fh(io.BytesIO(r.stdout))
    src = f"icat:{inode}@{offset}"
print(json.dumps({"source": src, "scanned_bytes": scanned, "hits": hits}))

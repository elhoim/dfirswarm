#!/usr/bin/env python3
import json, re, sys, os

def _resolve_image(explicit=None):
    """A pack tool belongs to no case: find the image under inputs/ instead of
    baking one in. One candidate is used; several mean the caller must say which."""
    import glob, os
    if explicit:
        return explicit
    cands = []
    for ext in ("*.E01", "*.e01", "*.raw", "*.dd", "*.001", "*.img", "*.vhd", "*.vhdx"):
        cands += glob.glob(os.path.join("inputs", ext))
    cands = sorted(set(cands))
    if len(cands) == 1:
        return cands[0]
    if not cands:
        raise SystemExit('{"ok": false, "error": "no disk image under inputs/; pass image="}')
    raise SystemExit('{"ok": false, "error": "several images under inputs/; pass image=", "candidates": %s}' % cands)


def _resolve_catalog(explicit=None):
    """The catalogue directory for the one image the kickoff catalogued."""
    import os
    if explicit:
        return explicit
    root = "catalog"
    if not os.path.isdir(root):
        raise SystemExit('{"ok": false, "error": "no catalog/ in this run; pass catalog="}')
    subs = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d)))
    if len(subs) == 1:
        return os.path.join(root, subs[0])
    if not subs:
        raise SystemExit('{"ok": false, "error": "catalog/ is empty; pass catalog="}')
    raise SystemExit('{"ok": false, "error": "several catalogues; pass catalog=", "candidates": %s}' % subs)

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
base = _resolve_catalog(args.get("catalog") if isinstance(args, dict) else None)
# The catalog keeps one directory per filesystem, named by its first sector
# (p0 for an image with no partition table, p2048 for a usual first
# partition): the one there is, or the one the caller names.
parts = sorted(n for n in os.listdir(base) if re.fullmatch(r"p\d+", n) and os.path.isdir(os.path.join(base, n)))
want = str(args.get("partition") or "").strip()
if want and not want.startswith("p"):
    want = "p" + want
if which == "partitions":
    part = None
elif want:
    if want not in parts:
        print(json.dumps({"ok": False, "error": "no filesystem at %s in %s; pass partition= one of these" % (want, base), "partitions": parts}))
        sys.exit(1)
    part = want
elif len(parts) == 1:
    part = parts[0]
elif not parts:
    print(json.dumps({"ok": False, "error": "the catalogue %s holds no filesystem listing (see its partitions.txt and README.md)" % base}))
    sys.exit(1)
else:
    print(json.dumps({"ok": False, "error": "several filesystems in %s; pass partition= one of these" % base, "partitions": parts}))
    sys.exit(1)
files = {"filelist": "filelist.txt", "timeline": "timeline.csv", "bodyfile": "bodyfile.txt", "fsstat": "fsstat.txt"}
if which == "partitions":
    path = os.path.join(base, "partitions.txt")
elif which in files:
    path = os.path.join(base, part, files[which])
else:
    print(json.dumps({"error": "which must be filelist|timeline|bodyfile|fsstat|partitions"}))
    sys.exit(1)
if not os.path.isfile(path):
    have = sorted(os.listdir(os.path.dirname(path))) if os.path.isdir(os.path.dirname(path)) else []
    print(json.dumps({"ok": False, "error": "%s is not in the catalogue" % path, "there": have}))
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
print(json.dumps({"which": which, "partition": part, "file": path, "pattern": pattern, "matched": total, "returned": len(hits), "hits": hits}))

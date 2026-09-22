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
base = _resolve_catalog(d.get("catalog") if isinstance(d, dict) else None)
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

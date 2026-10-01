#!/usr/bin/env python3
"""A pack whose content differs from a base's carries a version above the base's.

    python3 scripts/pack-versions.py --base REF [--bump]

Every packs/*/pack.json in this checkout is compared with REF's: when the
manifest without its version differs (its checksums cover every file, so any
change to the pack does), the version must be above REF's. Without --bump an
offending pack is named and the exit is 1: CI's pack-versions job runs it on a
pull request against its base, where two branches that changed one pack can
merge cleanly and land two different packs under one number. With --bump it
gets REF's version with the patch raised (scripts/merge-prep.sh). A pack REF
does not have is new and passes. The rule: docs/packs.md, "Versions".
"""
import json, os, subprocess, sys

def ver(v):
    return tuple(int(x) for x in str(v).split("."))

def main(argv):
    if "--base" not in argv or argv.index("--base") + 1 >= len(argv):
        print("usage: pack-versions.py --base REF [--bump]", file=sys.stderr)
        return 2
    ref, bump = argv[argv.index("--base") + 1], "--bump" in argv
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    packs = os.path.join(root, "packs")
    bad = []
    for pid in sorted(os.listdir(packs)) if os.path.isdir(packs) else []:
        path = os.path.join(packs, pid, "pack.json")
        if not os.path.isfile(path):
            continue
        r = subprocess.run(["git", "show", "%s:packs/%s/pack.json" % (ref, pid)], cwd=root, capture_output=True, text=True)
        if r.returncode != 0:
            continue
        cur, base = json.load(open(path, encoding="utf-8")), json.loads(r.stdout)
        strip = lambda m: {k: v for k, v in m.items() if k != "version"}
        if strip(cur) == strip(base) or ver(cur["version"]) > ver(base["version"]):
            continue
        if not bump:
            bad.append("packs/%s: its content differs from %s's while its version %s is not above %s's %s" % (pid, ref, cur["version"], ref, base["version"]))
            continue
        major, minor, patch = ver(base["version"])
        old, cur["version"] = cur["version"], "%d.%d.%d" % (major, minor, patch + 1)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(cur, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print("pack-versions: packs/%s: version %s -> %s (it differs from %s, which is %s)" % (pid, old, cur["version"], ref, base["version"]))
    for b in bad:
        print("pack-versions: %s; raise it (bash scripts/merge-prep.sh does)" % b, file=sys.stderr)
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

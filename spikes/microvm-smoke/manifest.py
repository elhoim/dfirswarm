#!/usr/bin/env python3
"""Fingerprint an evidence tree on the host, or compare two fingerprints.

  manifest.py take DIR OUT.json   record every file: sha256, size, mode, mtime, ctime, inode
  manifest.py diff A.json B.json  print every difference; exit 1 if there is one

The fingerprint is taken on the host, outside the VM, so nothing the guest
does can reach the record it is judged against.
"""
import hashlib
import json
import os
import sys


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(16 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def take(root: str) -> dict:
    files = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            st = os.lstat(full)
            entry = {
                "size": st.st_size,
                "mode": oct(st.st_mode),
                "mtime_ns": st.st_mtime_ns,
                "ctime_ns": st.st_ctime_ns,
                "ino": st.st_ino,
                "nlink": st.st_nlink,
            }
            if os.path.isfile(full) and not os.path.islink(full):
                entry["sha256"] = sha256(full)
            files[rel] = entry
    return {"root": os.path.abspath(root), "count": len(files), "files": files}


def diff(a: dict, b: dict) -> list[str]:
    out = []
    for rel in sorted(set(a["files"]) | set(b["files"])):
        x, y = a["files"].get(rel), b["files"].get(rel)
        if x is None:
            out.append(f"added   {rel}")
        elif y is None:
            out.append(f"removed {rel}")
        else:
            for key in sorted(set(x) | set(y)):
                if x.get(key) != y.get(key):
                    out.append(f"changed {rel}: {key} {x.get(key)} -> {y.get(key)}")
    return out


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "take":
        with open(sys.argv[3], "w") as f:
            json.dump(take(sys.argv[2]), f, indent=1)
        print(f"fingerprinted {sys.argv[2]}")
    elif len(sys.argv) == 4 and sys.argv[1] == "diff":
        with open(sys.argv[2]) as f:
            a = json.load(f)
        with open(sys.argv[3]) as f:
            b = json.load(f)
        changes = diff(a, b)
        for line in changes:
            print(line)
        print(f"{a['count']} entries compared, {len(changes)} differences")
        sys.exit(1 if changes else 0)
    else:
        print(__doc__)
        sys.exit(2)

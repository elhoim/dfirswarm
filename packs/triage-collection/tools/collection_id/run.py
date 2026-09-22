#!/usr/bin/env python3
"""Name the collector, and read the log it wrote about itself.

Every collector leaves a recognisable shape and its own record of what it did.
That record is the fastest route to the two things that matter before any
analysis: what was in scope, and what failed. The files that failed are usually
the ones that were locked, which is to say in use, which is to say the
interesting ones — and they are in a log almost nobody opens.

The shapes:

    KAPE          a tree mirroring C:\\, with *_CopyLog.csv and *_SkipLog.csv
    UAC           [root], [bodyfile], [live_response] directories, and uac.log
    Velociraptor  uploads/ with uploads.json, and results per artefact
    CyLR          a zip mirroring the source paths, no manifest of its own
    none          a hand-made copy, with no manifest and no way to know what was
                  left out — which is itself the finding

It also reports which artefact families are present, so that a question can be
matched against the collection before an hour is spent on it.
"""
import csv
import json
import os
import sys

MARKERS = [
    ("KAPE", ["*_CopyLog.csv", "*_SkipLog.csv", "*_ConsoleLog.txt"],
     lambda names: any(n.endswith("_CopyLog.csv") or n.endswith("_SkipLog.csv") for n in names)),
    ("UAC", ["uac.log", "[root]", "[bodyfile]", "[live_response]"],
     lambda names: "uac.log" in names or "[bodyfile]" in names or "[root]" in names),
    ("Velociraptor", ["uploads.json", "uploads/"],
     lambda names: "uploads.json" in names),
]
FAMILIES = {
    "$MFT": "the NTFS master file table",
    "$J": "the USN change journal",
    "$LogFile": "the NTFS transaction log",
    "SYSTEM": "the SYSTEM hive", "SOFTWARE": "the SOFTWARE hive",
    "SAM": "the SAM hive", "SECURITY": "the SECURITY hive",
    "NTUSER.DAT": "a user hive", "UsrClass.dat": "shell bags",
    "Amcache.hve": "Amcache",
    "SRUDB.dat": "SRUM",
    "ConsoleHost_history.txt": "PowerShell history",
    "auth.log": "Linux authentication log", "secure": "Linux authentication log",
    "wtmp": "Linux login records", "btmp": "Linux failed logins",
    "packages.xml": "the Android package list",
    "Manifest.db": "an iOS backup manifest",
}
MISSING = [
    "unallocated space, so no carving",
    "file slack",
    "a volume, so no partition table, no inode and no -o offset",
    "shadow copies, unless the collector was told to take them",
    "memory, unless it was captured separately",
]


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def read_kape_logs(root, names_by_dir, limit):
    copied, skipped, meta = 0, [], {}
    for dirpath, names in names_by_dir:
        for name in names:
            full = os.path.join(dirpath, name)
            if name.endswith("_SkipLog.csv") or name.endswith("_CopyLog.csv"):
                try:
                    with open(full, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
                        rows = list(csv.DictReader(fh))
                except OSError:
                    continue
                if name.endswith("_CopyLog.csv"):
                    copied += len(rows)
                    if rows:
                        meta["copy_log"] = full
                else:
                    meta["skip_log"] = full
                    for row in rows[:limit]:
                        skipped.append({"file": row.get("SourceFile") or row.get("Source"),
                                        "why": row.get("Reason") or row.get("Message")})
    return copied, skipped, meta


def read_uac_log(path, limit):
    failed, meta = [], {"log": path}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                low = line.lower()
                if "start date" in low or "end date" in low or "hostname" in low:
                    meta.setdefault("header", []).append(line.strip()[:200])
                if "error" in low or "cannot" in low or "permission denied" in low:
                    if len(failed) < limit:
                        failed.append({"line": line.strip()[:300]})
    except OSError as exc:
        meta["error"] = str(exc)
    return failed, meta


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    root = args.get("root")
    if not isinstance(root, str) or not root:
        fail("root is required: the collection directory")
    if not os.path.isdir(root):
        fail("no such directory", root=root)
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")

    top = set(os.listdir(root))
    names_by_dir, files, families = [], 0, {}
    for dirpath, dirs, names in os.walk(root):
        names_by_dir.append((dirpath, names))
        files += len(names)
        for name in names:
            for marker, meaning in FAMILIES.items():
                if name == marker or name.endswith(marker):
                    families.setdefault(meaning, 0)
                    families[meaning] += 1

    collector, evidence = "unknown", []
    for name, hints, test in MARKERS:
        if test(top) or any(test(set(n)) for _d, n in names_by_dir[:200]):
            collector, evidence = name, hints
            break
    if collector == "unknown" and any(n.lower() in ("c", "c$", "windows") for n in top):
        collector = "CyLR or a plain copy"

    detail, failures = {}, []
    if collector == "KAPE":
        copied, failures, detail = read_kape_logs(root, names_by_dir, limit)
        detail["files_in_copy_log"] = copied
    elif collector == "UAC":
        for dirpath, names in names_by_dir:
            if "uac.log" in names:
                failures, detail = read_uac_log(os.path.join(dirpath, "uac.log"), limit)
                break
    elif collector == "Velociraptor":
        for dirpath, names in names_by_dir:
            if "uploads.json" in names:
                path = os.path.join(dirpath, "uploads.json")
                detail["uploads_json"] = path
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        rows = [json.loads(l) for l in fh if l.strip()]
                    detail["uploads"] = len(rows)
                    detail["artefacts"] = sorted({r.get("_Source") for r in rows
                                                  if isinstance(r, dict) and r.get("_Source")})[:40]
                except (OSError, ValueError) as exc:
                    detail["uploads_json_error"] = str(exc)
                break

    print(json.dumps({
        "root": root,
        "collector": collector,
        "recognised_by": evidence,
        "files": files,
        "artefact_families_present": dict(sorted(families.items(), key=lambda kv: -kv[1])),
        "collector_detail": detail,
        "failed_targets": failures[:limit],
        "failed_target_count": len(failures),
        "cannot_contain": MISSING,
        "note": "The failed targets are usually the files that were locked, which is to say in "
                "use, which is to say the interesting ones — put them in the report rather than "
                "in an appendix nobody reads. Where the collector is unknown there is no manifest "
                "and no way to know what was left out, and that is itself a finding about the "
                "evidence. Before citing anything by path, run collection_index: the paths in "
                "this tree are not the paths that were on the machine.",
    }, indent=2))


if __name__ == "__main__":
    main()

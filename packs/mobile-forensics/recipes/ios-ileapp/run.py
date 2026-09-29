#!/usr/bin/env python3
"""A broad extraction of an iOS full file-system acquisition with iLEAPP.

The ios-filesystem recipe only inventories the tar: it reads headers and
parses no artefact content. This one hands the whole acquisition (a tar,
plain or compressed, or a zip) to iLEAPP, which runs every one of its
artefact modules over it and writes a report per artefact: TSV files, a
timeline database and an HTML report. The TSVs and databases are the
searchable form; they are listed in index.tsv, and every file iLEAPP wrote is
kept under ileapp/.

    run.py detect --target T [--probe-out DIR]   exit 0 applies, 1 does not
    run.py run --target T --out DIR

A run that is stopped before its end leaves coverage.json saying partial, so
what it wrote is read as partial and never as complete.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile

IOS_MARKERS = (
    "private/var/mobile/",
    "private/var/containers/",
    "system/library/coreservices/systemversion.plist",
)
NOT_COVERED = ("artefacts no module of the pinned iLEAPP release parses; deleted records beyond what a module reads "
               "itself (no carving); protected data that needs a key it does not have; archives nested inside the acquisition")


def target_of(value):
    text = open(value, encoding="utf-8").read() if os.path.isfile(value) else value
    target = json.loads(text)
    paths = target.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


def tar_mode(path):
    """A compressed tar by its magic, in stream mode; a plain one header to
    header (tarfile's "r:*" tries every decompressor and the LZMA one reads a
    run of zeros as a stream)."""
    with open(path, "rb") as fh:
        head = fh.read(6)
    if head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00":
        return "r|*"
    return "r:"


def ios_name(name):
    low = name.lower().lstrip("./")
    return any(marker in low for marker in IOS_MARKERS)


def detect(path):
    """(applies, why, kind): kind is iLEAPP's input type, tar or zip."""
    if not os.path.isfile(path):
        return False, "not a readable file", None
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as archive:
                for name in archive.namelist():
                    if ios_name(name):
                        return True, "zip members have an iOS full file-system root", "zip"
        except (zipfile.BadZipFile, OSError) as exc:
            return False, "not a readable zip: %s" % exc, None
        return False, "zip has no iOS full file-system marker", None
    try:
        with tarfile.open(path, tar_mode(path)) as archive:
            for member in archive:
                if ios_name(member.name):
                    return True, "tar members have an iOS full file-system root", "tar"
                archive.members = []
    except (tarfile.TarError, OSError, EOFError) as exc:
        return False, "not a readable tar or zip: %s" % exc, None
    return False, "tar has no iOS full file-system marker", None


def write_coverage(out, status, covered, errors, limits=()):
    with open(os.path.join(out, "coverage.json"), "w", encoding="utf-8") as handle:
        json.dump({"recipe": "ios-ileapp", "status": status, "covered": covered, "not_covered": NOT_COVERED,
                   "limits_hit": list(limits), "errors": list(errors)}, handle, indent=2, sort_keys=True)
        handle.write("\n")


def program():
    for name in ("ileapp", "ileapp.py"):
        found = shutil.which(name)
        if found:
            return found
    return None


def index(out, report):
    """Every TSV and database iLEAPP wrote, one row each, relative to out/."""
    rows = []
    for dirpath, dirs, files in os.walk(report):
        dirs.sort()
        for name in sorted(files):
            low = name.lower()
            rel = os.path.relpath(os.path.join(dirpath, name), out)
            if low.endswith(".tsv"):
                rows.append((rel, "iLEAPP artefact report %s (TSV, one row per record)" % name[:-4]))
            elif low.endswith((".db", ".sqlite")):
                rows.append((rel, "iLEAPP database %s (SQLite: the timeline, or every artefact's rows)" % name))
            elif low.endswith(".kml"):
                rows.append((rel, "iLEAPP locations %s (KML)" % name))
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        for rel, what in rows:
            handle.write("%s\t%s\n" % (rel.replace("\t", " "), what))
    return rows


def run(path, kind, out):
    os.makedirs(out, exist_ok=True)
    # Said before iLEAPP starts: a run stopped at its limit leaves this, and is read as partial.
    write_coverage(out, "partial", "started; iLEAPP did not finish (stopped before its end)", ["the run ended before iLEAPP did"])
    prog = program()
    if not prog:
        write_coverage(out, "failed", "nothing: iLEAPP is not in this image", ["ileapp is not on PATH in this job image"])
        return 1
    scratch = os.path.join(out, "ileapp-run")
    os.makedirs(scratch, exist_ok=True)
    with open(os.path.join(out, "ileapp.stdout"), "wb") as so, open(os.path.join(out, "ileapp.stderr"), "wb") as se:
        rc = subprocess.run([prog, "-t", kind, "-i", path, "-o", scratch], stdout=so, stderr=se).returncode
    made = [d for d in sorted(os.listdir(scratch)) if os.path.isdir(os.path.join(scratch, d))]
    report = os.path.join(out, "ileapp")
    if len(made) == 1:
        os.rename(os.path.join(scratch, made[0]), report)
        shutil.rmtree(scratch, ignore_errors=True)
    else:
        os.rename(scratch, report)
    rows = index(out, report)
    tsvs = sum(1 for rel, _ in rows if rel.lower().endswith(".tsv"))
    errors = [] if rc == 0 else ["iLEAPP exited %d; its output is kept whole in ileapp.stdout and ileapp.stderr" % rc]
    if rc == 0 and tsvs:
        write_coverage(out, "complete", "iLEAPP ran every module over the %s: %d artefact report(s) with records" % (kind, tsvs), errors)
    elif rows:
        write_coverage(out, "partial", "iLEAPP wrote %d report(s) before it ended" % len(rows), errors or ["iLEAPP wrote no TSV report"])
    else:
        write_coverage(out, "failed", "nothing parsed", errors or ["iLEAPP wrote no report"])
    return 0 if rc == 0 else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    # The census asks every detect step with --probe-out DIR; detect keeps nothing there.
    parser.add_argument("--probe-out")
    args = parser.parse_args()
    try:
        _, path = target_of(args.target)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    applies, why, kind = detect(path)
    if args.command == "detect":
        print(json.dumps({"applies": applies, "why": why}))
        return 0 if applies else 1
    if not args.out:
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    if not applies:
        print(json.dumps({"ok": False, "status": "unsupported", "why": why}))
        return 2
    rc = run(path, kind, args.out)
    status = json.load(open(os.path.join(args.out, "coverage.json"), encoding="utf-8")).get("status")
    print(json.dumps({"ok": rc == 0, "status": status}))
    return rc


if __name__ == "__main__":
    sys.exit(main())

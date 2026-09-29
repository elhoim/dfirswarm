#!/usr/bin/env python3
"""A broad extraction of a disk image: Plaso's super timeline.

disk-volumes lists every file entry and its MAC times, and reads no file's
contents. This one runs log2timeline over the whole image (every partition
and volume it finds, every parser it carries) into one storage file, then
psort writes it out as a CSV timeline: the searchable form of what the
image's artefacts say happened when. It takes hours on a large image, so its
pack does not run it by itself: the harness offers it as a lead, and a seat
runs it (catalog_request recipe=computer-forensics-base/disk-timeline) or
declines it with why.

    run.py detect --target T [--probe-out DIR]   exit 0 a disk image, 1 not
    run.py run --target T --out DIR

Detect reads signatures only (an EWF, VMDK, VHD(X) or QCOW container, a
partition table, a filesystem's boot sector), so it answers the same on any
host. A run stopped before its end leaves coverage.json saying partial.
"""
import argparse
import json
import os
import shutil
import struct
import subprocess
import sys

NOT_COVERED = ("volume shadow copies (run with --no_vss); encrypted volumes without their key; unallocated space and "
               "deleted file contents (nothing is carved); formats no parser of the pinned Plaso handles, and the text inside documents")


def target_of(value):
    text = open(value, encoding="utf-8").read() if os.path.isfile(value) else value
    target = json.loads(text)
    paths = target.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


def mbr_partitions(head):
    """Whether bytes 446..509 hold at least one partition entry with a type and a size."""
    for i in range(4):
        entry = head[446 + 16 * i: 462 + 16 * i]
        if len(entry) < 16:
            return False
        ptype = entry[4]
        sectors = struct.unpack("<I", entry[12:16])[0]
        if ptype and sectors:
            return True
    return False


def detect(path):
    if not os.path.isfile(path):
        return False, "not a readable file"
    try:
        with open(path, "rb") as fh:
            head = fh.read(65536)
            size = os.path.getsize(path)
            tail = b""
            if size >= 512:
                fh.seek(size - 512)
                tail = fh.read(512)
    except OSError as exc:
        return False, str(exc)
    containers = [
        (0, b"EVF\x09\x0d\x0a\xff\x00", "an EWF image (Plaso reads it through libewf)"),
        (0, b"EVF2\x0d\x0a\x81\x00", "an EWF2 image (Plaso reads it through libewf)"),
        (0, b"KDMV", "a VMDK sparse extent"),
        (0, b"# Disk DescriptorFile", "a VMDK descriptor"),
        (0, b"vhdxfile", "a VHDX disk"),
        (0, b"conectix", "a dynamic VHD disk"),
        (0, b"QFI\xfb", "a QCOW disk"),
        (512, b"EFI PART", "a GPT partition table"),
        (3, b"NTFS    ", "an NTFS volume at sector 0"),
        (3, b"EXFAT   ", "an exFAT volume at sector 0"),
        (54, b"FAT", "a FAT volume at sector 0"),
        (82, b"FAT32", "a FAT32 volume at sector 0"),
        (1080, b"\x53\xef", "an ext volume at sector 0"),
        (1024, b"H+", "an HFS+ volume at sector 0"),
        (1024, b"HX", "an HFSX volume at sector 0"),
        (32, b"NXSB", "an APFS container at sector 0"),
    ]
    for offset, magic, why in containers:
        if head[offset:offset + len(magic)] == magic:
            return True, why
    if tail[:8] == b"conectix":
        return True, "a fixed VHD disk"
    if head[510:512] == b"\x55\xaa" and mbr_partitions(head):
        return True, "an MBR partition table with at least one partition"
    return False, "no disk image, partition table or filesystem signature"


def program(*names):
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def write_coverage(out, status, covered, errors):
    with open(os.path.join(out, "coverage.json"), "w", encoding="utf-8") as handle:
        json.dump({"recipe": "disk-timeline", "status": status, "covered": covered, "not_covered": NOT_COVERED,
                   "limits_hit": [], "errors": list(errors)}, handle, indent=2, sort_keys=True)
        handle.write("\n")


def step(out, name, argv):
    with open(os.path.join(out, name + ".stdout"), "wb") as so, open(os.path.join(out, name + ".stderr"), "wb") as se:
        return subprocess.run(argv, stdout=so, stderr=se).returncode


def run(image, out):
    os.makedirs(out, exist_ok=True)
    write_coverage(out, "partial", "started; log2timeline or psort did not finish (stopped before its end)", ["the run ended before Plaso did"])
    l2t = program("log2timeline", "log2timeline.py")
    psort = program("psort", "psort.py")
    if not l2t or not psort:
        missing = [n for n, p in (("log2timeline", l2t), ("psort", psort)) if not p]
        write_coverage(out, "failed", "nothing: Plaso is not in this image", ["%s not on PATH in this job image" % " and ".join(missing)])
        return 1
    storage = os.path.join(out, "timeline.plaso")
    rc = step(out, "log2timeline", [l2t, "--unattended", "--partitions", "all", "--volumes", "all", "--no_vss", "--storage-file", storage, image])
    errors = []
    if rc != 0:
        errors.append("log2timeline exited %d; its output is kept whole in log2timeline.stdout and log2timeline.stderr" % rc)
    rows = []
    if os.path.isfile(storage):
        rows.append(("timeline.plaso", "Plaso storage file of the whole image (psort, pinfo)"))
        prc = step(out, "psort", [psort, "-o", "dynamic", "-w", os.path.join(out, "timeline.csv"), storage])
        if prc != 0:
            errors.append("psort exited %d; its output is kept whole in psort.stdout and psort.stderr" % prc)
        if os.path.isfile(os.path.join(out, "timeline.csv")):
            rows.append(("timeline.csv", "super timeline (psort -o dynamic): one event per row, every parser's, in time order"))
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        for rel, what in rows:
            handle.write("%s\t%s\n" % (rel, what))
    if not errors and len(rows) == 2:
        write_coverage(out, "complete", "log2timeline over every partition and volume of the image, and psort's timeline of it", [])
        return 0
    if rows:
        write_coverage(out, "partial", "Plaso wrote %s before it ended" % " and ".join(r for r, _ in rows), errors)
    else:
        write_coverage(out, "failed", "nothing parsed", errors or ["log2timeline wrote no storage file"])
    return 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    # The census asks every detect step with --probe-out DIR; detect keeps nothing there.
    parser.add_argument("--probe-out")
    args = parser.parse_args()
    try:
        _, image = target_of(args.target)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    applies, why = detect(image)
    if args.command == "detect":
        print(json.dumps({"applies": applies, "why": why}))
        return 0 if applies else 1
    if not args.out:
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    if not applies:
        print(json.dumps({"ok": False, "status": "unsupported", "why": why}))
        return 2
    rc = run(image, args.out)
    status = json.load(open(os.path.join(args.out, "coverage.json"), encoding="utf-8")).get("status")
    print(json.dumps({"ok": rc == 0, "status": status}))
    return rc


if __name__ == "__main__":
    sys.exit(main())

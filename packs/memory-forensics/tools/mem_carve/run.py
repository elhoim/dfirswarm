#!/usr/bin/env python3
"""Find the structures inside a memory image that other parsers already read.

A framework needs a symbol profile that matches the build, and on an unusual
build there may not be one. Meanwhile the image is a large blob with recognisable
structures in it, and every one of those structures has a parser in this
project already: a hive carved out of memory goes to regkv exactly as one taken
off a disk would, a chunk goes to evtx_carve, a prefetch record to mam_scan.

That is the whole idea here. This tool finds and cuts; it does not parse. The
offset it returns is the entire provenance of whatever comes out — there is no
path and no file name — so the offset belongs in the report beside anything the
downstream parser says.

Sizes are the amount cut out per hit, chosen to be large enough to hold a
typical instance of that structure. A cut that ends mid-record is truncated, not
corrupt, and the parser that reads it will say so.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

SIGNATURES = [
    (b"regf", "registry hive", 1 << 20),
    (b"ElfChnk\x00", "event log chunk", 65536),
    (b"ElfFile\x00", "event log file", 1 << 20),
    (b"MAM\x04", "compressed prefetch record", 1 << 17),
    (b"SCCA", "prefetch record", 1 << 17),
    (b"MZ\x90\x00\x03", "PE header", 1 << 20),
    (b"SQLite format 3\x00", "SQLite database", 1 << 21),
    (b"FILE0", "MFT record", 1024),
    (b"INDX(", "NTFS index block", 4096),
    (b"\x50\x4b\x03\x04", "zip or office document", 1 << 20),
    (b"%PDF-", "PDF", 1 << 20),
    (b"bplist00", "binary property list", 1 << 16),
]
WINDOW = 1 << 22


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def resolve_output(out):
    """Where `out` really lands, refusing anything outside the run directory.

    A string check is not enough: `work/../inputs/x` and an absolute path
    both name a file the tool must not write, and neither starts with
    "inputs/". Resolving first and comparing directories is what actually
    holds, and the read-only inputs are the one place extracted bytes must
    never appear -- a later integrity check would report the evidence as
    modified.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest != root and root not in dest.parents:
        fail("output must stay inside the run directory", output=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("output cannot be under inputs/", output=str(out))
    return dest


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a memory image, page file or blob")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    limit = args.get("limit", 2000)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    max_extract = args.get("max_extract", 25)
    if not isinstance(max_extract, int) or isinstance(max_extract, bool) or max_extract < 0:
        fail("max_extract must be a non-negative integer")
    wanted = {str(k) for k in (args.get("kinds") or [])}
    known = {name for _sig, name, _size in SIGNATURES}
    unknown = wanted - known
    if unknown:
        fail("no signature by that name", unknown=sorted(unknown), kinds=sorted(known))
    signatures = [(s, n, z) for s, n, z in SIGNATURES if not wanted or n in wanted]

    size = os.path.getsize(path)
    start = args.get("start", 0) or 0
    end = min(size, start + args["max_bytes"]) if args.get("max_bytes") else size
    extract_to = args.get("extract_to")
    if extract_to:
        resolve_output(extract_to)
        os.makedirs(extract_to, exist_ok=True)

    longest = max(len(s) for s, _n, _z in signatures)
    hits, truncated, extracted = [], False, 0
    with open(path, "rb") as fh:
        position, tail, tail_at = start, b"", start
        while position < end and not truncated:
            fh.seek(position)
            block = fh.read(min(WINDOW, end - position))
            if not block:
                break
            buf = tail + block
            base = tail_at
            for signature, name, cut in signatures:
                at = 0
                while True:
                    found = buf.find(signature, at)
                    if found < 0:
                        break
                    at = found + 1
                    absolute = base + found
                    if len(hits) >= limit:
                        truncated = True
                        break
                    entry = {"kind": name, "offset": absolute,
                             "page_aligned": absolute % 4096 == 0}
                    if extract_to and extracted < max_extract:
                        fh.seek(absolute)
                        piece = fh.read(min(cut, size - absolute))
                        fh.seek(position + len(block))
                        safe = "%012x-%s.bin" % (absolute, name.replace(" ", "_"))
                        target = os.path.join(extract_to, safe)
                        with open(target, "wb") as out:
                            out.write(piece)
                        entry["extracted_to"] = target
                        entry["extracted_bytes"] = len(piece)
                        entry["sha256"] = hashlib.sha256(piece).hexdigest()
                        extracted += 1
                    hits.append(entry)
                if truncated:
                    break
            tail = buf[-(longest - 1):] if len(buf) >= longest else buf
            tail_at = base + len(buf) - len(tail)
            position += len(block)

    counts = {}
    for hit in hits:
        counts[hit["kind"]] = counts.get(hit["kind"], 0) + 1
    hits.sort(key=lambda h: h["offset"])
    print(json.dumps({
        "path": path,
        "bytes_swept": max(0, end - start),
        "hits": hits[:limit],
        "hit_count": len(hits),
        "by_kind": counts,
        "extracted": extracted,
        "truncated": truncated,
        "note": "The offset is the whole provenance: a structure carved from memory has no path "
                "and no file name, so the offset belongs in the report beside whatever the parser "
                "says about it. Hand each extract to the tool that reads that format — a hive to "
                "regkv, a chunk to evtx_carve, a prefetch record to mam_scan. A cut that ends "
                "mid-record is truncated, not corrupt.",
    }, indent=2))


if __name__ == "__main__":
    main()

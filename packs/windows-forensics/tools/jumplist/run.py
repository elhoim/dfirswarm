#!/usr/bin/env python3
"""Read a jump list, and hand the link structures inside it to lnk_parse.

A jump list outlives the Recent folder and outlives the file it points at, which
is why it answers "what did this user open, and from where" when nothing else
does. Two formats:

  *.automaticDestinations-ms  an OLE compound file. Each numbered stream is a
                              link structure; the DestList stream is the index,
                              holding the entry number, the host the file was
                              on, an access count and the last access time.
  *.customDestinations-ms     no container at all: link structures one after
                              another, found by their own 20-byte header.

The design here is deliberate. The DestList's fixed fields have moved between
Windows versions and a parser that guesses at them quietly returns wrong times,
so this reads the fields that are stable, validates each entry before trusting
it, and stops and says so when the layout stops making sense. The substance —
target path, volume serial, the three target timestamps — comes from the link
structures themselves, which are written out for `lnk_parse`, a parser that
already handles them properly.

The file name's leading hex is the application id. It identifies the
application, and published lists map the common ones; quote the id and the
source you resolved it with rather than asserting the application from memory.
"""
import binascii
import datetime
import json
import os
import re
import struct
import sys

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
LNK_MAGIC = bytes([0x4C, 0x00, 0x00, 0x00]) + binascii.unhexlify("0114020000000000c000000000000046")
DESTLIST_HEADER = 32


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def filetime(value):
    if not value:
        return None
    try:
        return (FILETIME_EPOCH + datetime.timedelta(microseconds=value // 10)).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError):
        return None


def parse_destlist(data):
    """Entry layout per Joachim Metz's jump list documentation; version aware."""
    out = {"entries": [], "problems": []}
    if len(data) < DESTLIST_HEADER:
        out["problems"].append("the DestList stream is shorter than its header")
        return out
    version, count, pinned = struct.unpack_from("<III", data, 0)
    out["destlist_version"] = version
    out["entries_claimed"] = count
    out["pinned_claimed"] = pinned
    if version not in (1, 3, 4):
        out["problems"].append("DestList version %d is not one this parser knows; entries are not read" % version)
        return out
    trailer = 0 if version == 1 else 4
    offset = DESTLIST_HEADER
    while offset + 118 <= len(data):
        chars = struct.unpack_from("<H", data, 0x74 + offset)[0]
        end = offset + 118 + chars * 2 + trailer
        if chars > 2048 or end > len(data):
            out["problems"].append(
                "entry %d claims a %d-character path, which does not fit; stopped here"
                % (len(out["entries"]) + 1, chars))
            break
        host = data[offset + 0x48:offset + 0x58].split(b"\x00", 1)[0].decode("ascii", "replace")
        number, = struct.unpack_from("<I", data, offset + 0x58)
        access_count, = struct.unpack_from("<I", data, offset + 0x64)
        modified, = struct.unpack_from("<Q", data, offset + 0x68)
        pin, = struct.unpack_from("<i", data, offset + 0x70)
        path = data[offset + 118:offset + 118 + chars * 2].decode("utf-16-le", "replace")
        out["entries"].append({
            "entry_number": number,
            "stream": "%x" % number,
            "path": path,
            "hostname": host,
            "access_count": access_count,
            "last_access": filetime(modified),
            "pinned": pin != -1,
        })
        offset = end
    if count and len(out["entries"]) != count:
        out["problems"].append(
            "the header claims %d entries and %d were read" % (count, len(out["entries"])))
    return out


def split_lnks(data):
    """Find every link structure by its own header, wherever it sits."""
    found, at = [], 0
    while True:
        hit = data.find(LNK_MAGIC, at)
        if hit < 0:
            break
        found.append(hit)
        at = hit + 4
    out = []
    for i, start in enumerate(found):
        end = found[i + 1] if i + 1 < len(found) else len(data)
        out.append((start, data[start:end]))
    return out


def write_stream(out_dir, name, payload):
    os.makedirs(out_dir, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80] or "stream"
    target = os.path.join(out_dir, safe + ".lnk")
    with open(target, "wb") as fh:
        fh.write(payload)
    return target


def read_automatic(path, out_dir, limit):
    try:
        import olefile
    except ImportError as exc:
        return {"file": path, "error": "olefile is not installed: python3 -m pip install olefile",
                "reason": str(exc)}
    if not olefile.isOleFile(path):
        return {"file": path, "error": "not an OLE compound file; is it a customDestinations-ms?"}
    ole = olefile.OleFileIO(path)
    result = {"file": path, "format": "automaticDestinations-ms", "streams": [], "links": []}
    try:
        names = ["/".join(p) for p in ole.listdir()]
        result["stream_names"] = names
        if "DestList" in names:
            result.update(parse_destlist(ole.openstream("DestList").read()))
        else:
            result["problems"] = ["there is no DestList stream in this file"]
        by_stream = {e["stream"]: e for e in result.get("entries", [])}
        for name in names:
            if name == "DestList":
                continue
            payload = ole.openstream(name).read()
            entry = {"stream": name, "bytes": len(payload), "is_link": payload[:4] == LNK_MAGIC[:4]}
            known = by_stream.get(name.lower())
            if known:
                entry["path"] = known["path"]
                entry["last_access"] = known["last_access"]
            if out_dir and entry["is_link"]:
                entry["written_to"] = write_stream(out_dir, os.path.basename(path) + "-" + name, payload)
            result["links"].append(entry)
            if len(result["links"]) >= limit:
                result["links_truncated"] = True
                break
    finally:
        ole.close()
    return result


def read_custom(path, out_dir, limit):
    with open(path, "rb") as fh:
        data = fh.read()
    result = {"file": path, "format": "customDestinations-ms", "links": []}
    for i, (offset, payload) in enumerate(split_lnks(data)):
        entry = {"offset": offset, "bytes": len(payload), "is_link": True}
        if out_dir:
            entry["written_to"] = write_stream(out_dir, "%s-%04d" % (os.path.basename(path), i), payload)
        result["links"].append(entry)
        if len(result["links"]) >= limit:
            result["links_truncated"] = True
            break
    if not result["links"]:
        result["problems"] = ["no link structure header found in this file"]
    return result


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a jump list file or a directory of them")

    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))

    out_dir = args.get("out_dir")
    if out_dir is not None and (not isinstance(out_dir, str) or not out_dir):
        fail("out_dir must be a directory path under work/")

    targets = []
    if os.path.isdir(path):
        for root, _dirs, names in os.walk(path):
            for name in sorted(names):
                if name.lower().endswith(("destinations-ms",)):
                    targets.append(os.path.join(root, name))
    elif os.path.isfile(path):
        targets = [path]
    else:
        fail("no such file or directory", path=path)
    if not targets:
        fail("no jump list files under that directory", path=path)

    files = []
    for target in targets:
        try:
            if target.lower().endswith("customdestinations-ms"):
                files.append(read_custom(target, out_dir, limit))
            else:
                files.append(read_automatic(target, out_dir, limit))
        except Exception as exc:                              # one bad file must not end the sweep
            files.append({"file": target, "error": "%s: %s" % (type(exc).__name__, exc)})
        app_id = os.path.basename(target).split(".")[0]
        if re.fullmatch(r"[0-9a-f]{16}", app_id):
            files[-1]["application_id"] = app_id

    print(json.dumps({
        "files": files,
        "file_count": len(files),
        "note": "The DestList gives the index and the access counts; the target path, the volume "
                "serial and the three target timestamps come from the link structures, so run "
                "lnk_parse over what was written to out_dir before citing any of them.",
    }, indent=2))


if __name__ == "__main__":
    main()

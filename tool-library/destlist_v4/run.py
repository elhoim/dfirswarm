#!/usr/bin/env python3
"""destlist_v4: read the DestList stream of a Windows jump list, version 4.

An automaticDestinations-ms file is an OLE compound file; its DestList stream
is the index of the jump list: one entry for each target the user opened with
the application, in the order of use. This reads that stream once it is out of
the compound file, and says for every entry where it lies in the stream, its
entry number, the host's NetBIOS name it records, the last time the target was
accessed (a FILETIME, shown in UTC and as the raw number), whether it is
pinned, and the target's path.

It reads version 4 (a 32-byte header, then entries with a 130-byte fixed part,
the path as UTF-16LE and four bytes after it). Another version is laid out
differently and is refused by name, not guessed at; so is a compound file
given whole, which has to be opened first for its DestList stream. Fields it
does not read it does not report. A stream that is cut short or claims more
entries than it holds is read as far as it goes, and says so under `problems`.

Args, JSON on stdin:
  path       the DestList stream, as a file
  offset     where it starts in that file (default 0)
  limit      entries in the answer (default 200); when there are more the whole
             list is written as JSON Lines and named in all_results
  max_bytes  the largest stream read (default 64 MiB)
"""
import datetime
import json
import struct
import sys
from pathlib import Path

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self._out = None
        self._tmp: Path | None = None
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(
                r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
            )
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row: object) -> None:
        assert self._out is not None
        self._out.write(json.dumps(row, ensure_ascii=False, default=str))
        self._out.write("\n")

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(
                dir=self.path.parent, prefix=f".{self.path.name}-"
            )
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            assert self._tmp is not None
            os.replace(self._tmp, self.path)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
HEADER = 32
FIXED = 130          # an entry's fixed part; its path follows, then 4 bytes
TRAILER = 4
MAX_PATH_CHARS = 32767


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def filetime(value):
    if not value:
        return None
    try:
        return (FILETIME_EPOCH + datetime.timedelta(microseconds=value // 10)).isoformat().replace("+00:00", "Z")
    except OverflowError:
        return None


def whole(args, name, default, low, high):
    v = args.get(name)
    if v is None:
        v = default
    if isinstance(v, bool) or not isinstance(v, int) or not low <= v <= high:
        fail("%s must be a whole number from %d to %d" % (name, low, high), got=v)
    return v


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as e:
        fail("the arguments are not JSON", reason=str(e))
    if not isinstance(args, dict):
        fail("the arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the DestList stream, as a file")
    limit = whole(args, "limit", 200, 1, 1_000_000)
    offset = whole(args, "offset", 0, 0, 1 << 62)
    max_bytes = whole(args, "max_bytes", 64 * 1024 * 1024, HEADER, 1 << 32)
    try:
        size = Path(path).stat().st_size
        if offset > size:
            fail("offset is past the end of the file", offset=offset, size=size)
        if size - offset > max_bytes:
            fail("the stream is %d bytes, over max_bytes (%d)" % (size - offset, max_bytes), size=size - offset)
        with open(path, "rb") as fh:
            fh.seek(offset)
            data = fh.read()
    except OSError as e:
        fail("cannot read %s" % path, reason=str(e.strerror or e))

    out = {"path": path, "stream_offset": offset, "bytes": len(data), "problems": []}
    if data.startswith(OLE_MAGIC):
        fail("this is an OLE compound file, a jump list as it lies on disk; open it and give its DestList stream", path=path)
    entries = LosslessPage("destlist_v4", [path, offset, len(data)], limit)
    if not data:
        out["empty"] = True
    elif len(data) < HEADER:
        fail("the stream is %d bytes, shorter than its %d-byte header" % (len(data), HEADER), path=path)
    else:
        version, claimed, pinned = struct.unpack_from("<III", data, 0)
        out.update(version=version, entries_claimed=claimed, pinned_claimed=pinned)
        if version != 4:
            fail("DestList version %d is not one this reads; it reads version 4, whose entries are laid out differently from the others" % version, version=version, path=path)
        pos = HEADER
        read = 0
        while read < claimed:
            if pos + FIXED > len(data):
                out["problems"].append("entry %d is cut short: %d byte(s) left of its %d-byte fixed part; stopped here" % (read + 1, len(data) - pos, FIXED))
                break
            chars = struct.unpack_from("<H", data, pos + 128)[0]
            end = pos + FIXED + chars * 2
            if chars > MAX_PATH_CHARS or end + TRAILER > len(data):
                out["problems"].append("entry %d claims a path of %d characters, which does not fit in the stream; stopped here" % (read + 1, chars))
                break
            ft = struct.unpack_from("<Q", data, pos + 100)[0]
            pin = struct.unpack_from("<i", data, pos + 108)[0]
            entries.add({
                "n": read + 1,
                "offset": offset + pos,
                "entry_id": struct.unpack_from("<Q", data, pos + 88)[0],
                "hostname": data[pos + 72:pos + 88].split(b"\x00", 1)[0].decode("ascii", "replace"),
                "last_access": filetime(ft),
                "filetime": ft,
                "pin": pin,
                "pinned": pin != -1,
                "path": data[pos + FIXED:end].decode("utf-16-le", "replace"),
                "path_offset": offset + pos + FIXED,
            })
            pos = end + TRAILER
            read += 1
        out["entries_read"] = read
        out["end_offset"] = offset + pos
        out["trailing_bytes"] = len(data) - pos
        if read == claimed and len(data) > pos:
            out["problems"].append("%d byte(s) follow the last entry the header counts; they are not read" % (len(data) - pos))
    page = entries.finish()
    out.update(page)
    out["entries"] = entries.page
    out["fields_not_read"] = "the checksum, the volume and file identifiers, and the header and entry fields whose meaning is not settled"
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

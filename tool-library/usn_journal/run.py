#!/usr/bin/env python3
"""Parse an NTFS change journal ($UsnJrnl:$J) into records.

Asked for in two of the measured cases and forged badly in one. The journal
is the closest thing NTFS has to an audit log of file names: every create,
rename, write and delete, with a timestamp and the reason bits that say which.

$J is sparse. Extracted with icat, its front is a run of zeros as long as
everything the journal has already let go (tens of megabytes, or gigabytes on
a volume that has lived), and the live records sit at the end. So the file is
mapped, never read whole; zeros are skipped in steps of up to a megabyte, at
the front and wherever they pad a page inside the live part; and the output
says where the first record was and how many zero bytes it passed.

Every record is read. `name` narrows what is returned, never what is read:
records_read says how many records the journal holds, so a filter that
matched nothing reads as that and not as an empty journal. `name` is a
case-insensitive regex over the file name, as in mft_records and indx_carve
(a|b for either); a run passed an alternation to the substring match this
tool used to do, and read "0 records" as "the journal is empty".

USN_RECORD_V2 (the usual one):
  0x00  4  RecordLength
  0x04  2  MajorVersion (2)
  0x06  2  MinorVersion
  0x08  8  FileReferenceNumber
  0x10  8  ParentFileReferenceNumber
  0x18  8  Usn
  0x20  8  TimeStamp (FILETIME)
  0x28  4  Reason
  0x2C  4  SourceInfo
  0x30  4  SecurityId
  0x34  4  FileAttributes
  0x38  2  FileNameLength
  0x3A  2  FileNameOffset

USN_RECORD_V3 (ReFS, and NTFS with 128-bit file ids): the two references are
16 bytes each, so everything after them is 0x10 further on (Usn at 0x28, the
name's length and offset at 0x48 and 0x4A).

USN_RECORD_V4 (range tracking, written after a v3 record): the two 16-byte
references, Usn at 0x28, Reason 0x30, SourceInfo 0x34, RemainingExtents 0x38,
NumberOfExtents 0x3C, ExtentSize 0x3E, then the extents (offset and length,
8 bytes each). It has no name and no timestamp.

A record's length is a multiple of 8 and records start on 8-byte boundaries.
"""
import datetime
import json
import mmap
import os
import re
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

REASONS = [
    (0x00000001, "DATA_OVERWRITE"), (0x00000002, "DATA_EXTEND"), (0x00000004, "DATA_TRUNCATION"),
    (0x00000010, "NAMED_DATA_OVERWRITE"), (0x00000020, "NAMED_DATA_EXTEND"), (0x00000040, "NAMED_DATA_TRUNCATION"),
    (0x00000100, "FILE_CREATE"), (0x00000200, "FILE_DELETE"), (0x00000400, "EA_CHANGE"),
    (0x00000800, "SECURITY_CHANGE"), (0x00001000, "RENAME_OLD_NAME"), (0x00002000, "RENAME_NEW_NAME"),
    (0x00004000, "INDEXABLE_CHANGE"), (0x00008000, "BASIC_INFO_CHANGE"), (0x00010000, "HARD_LINK_CHANGE"),
    (0x00020000, "COMPRESSION_CHANGE"), (0x00040000, "ENCRYPTION_CHANGE"), (0x00080000, "OBJECT_ID_CHANGE"),
    (0x00100000, "REPARSE_POINT_CHANGE"), (0x00200000, "STREAM_CHANGE"), (0x00400000, "TRANSACTED_CHANGE"),
    (0x00800000, "INTEGRITY_CHANGE"), (0x80000000, "CLOSE"),
]

ATTRIBUTES = [
    (0x00000001, "READONLY"), (0x00000002, "HIDDEN"), (0x00000004, "SYSTEM"), (0x00000010, "DIRECTORY"),
    (0x00000020, "ARCHIVE"), (0x00000080, "NORMAL"), (0x00000100, "TEMPORARY"), (0x00000200, "SPARSE_FILE"),
    (0x00000400, "REPARSE_POINT"), (0x00000800, "COMPRESSED"), (0x00001000, "OFFLINE"),
    (0x00004000, "ENCRYPTED"),
]


# The fixed part of each version: a record shorter than this is not one.
HEAD = {2: 0x3C, 3: 0x4C, 4: 0x40}
# Where each version keeps the name's length and offset.
NAME_AT = {2: 0x38, 3: 0x48}
MAX_RECORD = 0x10000
ZERO_STEP = 1 << 20


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def flags(value, table):
    return [name for bit, name in table if value & bit]


def filetime(value):
    if value <= 0:
        return None
    try:
        return (FILETIME_EPOCH + datetime.timedelta(microseconds=value // 10)).isoformat().replace("+00:00", "Z")
    except OverflowError:
        return None


def next_nonzero(data, offset, end):
    """The first 8-byte boundary at or after `offset` whose 8 bytes are not all
    zero, or `end`. The look ahead doubles up to a megabyte: a record starts
    within the first few bytes, and the sparse front of $J, which can be
    gigabytes, would take minutes 8 bytes at a time."""
    step = 64
    while offset < end:
        chunk = data[offset:min(offset + step, end)]
        rest = chunk.lstrip(b"\0")
        if rest:
            return offset + ((len(chunk) - len(rest)) & ~7)
        offset += len(chunk)
        step = min(step * 2, ZERO_STEP)
    return end


def reference(raw):
    """A 128-bit file id: the NTFS reference (entry and sequence) when the high
    half is zero, as it is on NTFS; the whole id, in hex, either way."""
    low, high = struct.unpack("<QQ", raw)
    out = {"id": "%016x%016x" % (high, low)}
    if high == 0:
        out["entry"] = low & 0x0000FFFFFFFFFFFF
        out["sequence"] = low >> 48
    return out


def record_at(data, offset, end):
    """The record at `offset` as a dict with its length, or None when the bytes
    there are not a plausible v2, v3 or v4 record."""
    if offset + 8 > end:
        return None
    length, major = struct.unpack_from("<IH", data, offset)
    head = HEAD.get(major)
    if head is None or not (head <= length <= MAX_RECORD) or length % 8 or offset + length > end:
        return None
    if major == 4:
        ref, parent = reference(data[offset + 0x08:offset + 0x18]), reference(data[offset + 0x18:offset + 0x28])
        usn, reason, source, remaining, count, size = struct.unpack_from("<QIIIHH", data, offset + 0x28)
        if size != 16 or 0x40 + count * size > length:
            return None
        extents = [dict(zip(("offset", "length"), struct.unpack_from("<qq", data, offset + 0x40 + i * 16)))
                   for i in range(count)]
        return {"length": length, "row": {
            "version": 4, "usn": usn, "name": None,
            "file_reference": ref.get("entry"), "file_sequence": ref.get("sequence"), "file_id": ref["id"],
            "parent_reference": parent.get("entry"), "parent_id": parent["id"],
            "reason": flags(reason, REASONS), "reason_raw": reason, "source_info": source,
            "extents": extents, "remaining_extents": remaining, "offset": offset,
        }}
    name_len, name_off = struct.unpack_from("<HH", data, offset + NAME_AT[major])
    if name_off < head or name_off + name_len > length or name_len % 2:
        return None
    name = data[offset + name_off:offset + name_off + name_len].decode("utf-16-le", "replace")
    if major == 2:
        ref, parent, usn, stamp, reason, source, sec, attrs = struct.unpack_from("<QQQqIIII", data, offset + 0x08)
        row = {"version": 2, "usn": usn, "timestamp": filetime(stamp), "name": name,
               "file_reference": ref & 0x0000FFFFFFFFFFFF, "file_sequence": ref >> 48,
               "parent_reference": parent & 0x0000FFFFFFFFFFFF}
    else:
        ref, parent = reference(data[offset + 0x08:offset + 0x18]), reference(data[offset + 0x18:offset + 0x28])
        usn, stamp, reason, source, sec, attrs = struct.unpack_from("<QqIIII", data, offset + 0x28)
        row = {"version": 3, "usn": usn, "timestamp": filetime(stamp), "name": name,
               "file_reference": ref.get("entry"), "file_sequence": ref.get("sequence"), "file_id": ref["id"],
               "parent_reference": parent.get("entry"), "parent_id": parent["id"]}
    row.update({"reason": flags(reason, REASONS), "reason_raw": reason,
                "attributes": flags(attrs, ATTRIBUTES), "offset": offset})
    return {"length": length, "row": row}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the $J stream, extracted with icat")
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))
    limit = min(limit, 100000)
    name_filter = args.get("name")
    if name_filter is not None and not isinstance(name_filter, str):
        fail("name must be a string: a case-insensitive regex over the file name")
    pattern = None
    if name_filter:
        try:
            pattern = re.compile(name_filter, re.I)
        except re.error as exc:
            fail("name is not a valid regex", name=name_filter, reason=str(exc))

    try:
        fh = open(path, "rb")
        size = os.fstat(fh.fileno()).st_size
    except OSError as exc:
        fail("could not read the journal", path=path, reason=str(exc))
    if size < HEAD[2]:
        fail("too short to hold a record", bytes=size)
    try:
        data = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
    except (OSError, ValueError) as exc:
        fail("could not map the journal", path=path, reason=str(exc))

    records = LosslessPage("usn_journal", [path, name_filter], limit)
    versions = {}
    start = None
    read = skipped = zeros = 0
    offset = 0
    while offset < size:
        # The sparse front, and the zeros that pad the end of each page.
        ahead = next_nonzero(data, offset, size)
        zeros += ahead - offset
        offset = ahead
        if offset >= size:
            break
        found = record_at(data, offset, size)
        if found is None:
            # Before the first record this is the search for it; after it, a
            # stretch that is not a record, counted and stepped over.
            if start is not None:
                skipped += 1
            offset += 8
            continue
        if start is None:
            start = offset
        row = found["row"]
        read += 1
        versions[str(row["version"])] = versions.get(str(row["version"]), 0) + 1
        if pattern is None or (row["name"] is not None and pattern.search(row["name"])):
            records.add(row)
        offset += found["length"]
    data.close()
    fh.close()

    if start is None:
        fail("no USN record (v2, v3 or v4) found", bytes=size, zero_bytes=zeros,
             hint="is this the $J stream rather than $Max?")

    page = records.finish()
    result = {
        "path": path,
        "bytes": size,
        "first_record_offset": start,
        "zero_bytes_skipped": zeros,
        "records_read": read,
        "records_by_version": versions,
        "name_filter": name_filter,
        "records": records.page,
        "record_count": page["matched"],
        "malformed_skipped": skipped,
        **page,
    }
    if pattern is not None and not page["matched"]:
        result["note"] = ("%d records were read and none has a file name matching %r "
                          "(a case-insensitive regex); the journal is not empty" % (read, name_filter))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

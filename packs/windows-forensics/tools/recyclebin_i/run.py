#!/usr/bin/env python3
"""Parse a Windows $Recycle.Bin $I metadata file.

Three of the measured cases did this by hand with `xxd` and arithmetic, which
is exactly the kind of work a tool should absorb: the format is fixed and
small, and getting the FILETIME conversion wrong by an hour is easy and
invisible.

$I layout (Vista and later), little-endian, unsigned:
  0x00  8  header: 1 (Vista/7) or 2 (8 and later)
  0x08  8  original file size
  0x10  8  deletion time, FILETIME (100 ns since 1601-01-01 UTC)
  0x18     header 1: 520 bytes, UTF-16LE path, NUL padded (544 bytes in all)
           header 2: 4-byte character count (the terminating NUL included), then
           that many UTF-16LE characters (0x1C plus twice the count in all)

Every length is checked against the bytes the file has. A file shorter than its layout needs is
reported `truncated: true` with the bytes it has and the path decoded from them as far as it goes,
never as a complete record; one longer than its layout says carries `trailing_bytes`. The whole file is
read (a $I is a few hundred bytes; one over 1 MiB is not a $I and is reported as such). An unknown
header is not guessed at.

The directory a $I sits in is a per-user bin named by a SID (`bin_directory_sid`): the account whose
bin received the item. The record does not say who deleted the file, or from where the deletion was
asked, and a $R file of the same name (reported as `r_file`) holds the content only while it lasts.
"""
import datetime
import json
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

    def _cannot_write(self, exc: BaseException) -> None:
        """The whole result cannot be kept: say so as JSON and stop, never a traceback."""
        import sys as _sys
        _sys.stdout.write(json.dumps({
            "error": "the whole result (%d rows so far) cannot be written to %s: %s. Outside a job the place is your own "
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, exc),
            "status": "failed",
        }) + "\n")
        _sys.exit(1)

    def _write(self, row: object) -> None:
        assert self._out is not None
        text = json.dumps(row, ensure_ascii=False, default=str)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate (a file name that is not UTF-8): escape it, lose nothing.
            text = json.dumps(row, ensure_ascii=True, default=str)
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            self._cannot_write(exc)

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(
                    dir=self.path.parent, prefix=f".{self.path.name}-"
                )
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
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
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                os.replace(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
V1_SIZE = 0x18 + 520
MAX_I_BYTES = 1024 * 1024
SID = re.compile(r"^S-\d+(?:-\d+)+$", re.I)
PARSER = "recyclebin_i/2"


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def filetime(value):
    """ISO 8601 UTC with seven fractional digits, by integer arithmetic; None for 0 or past year 9999."""
    if value <= 0:
        return None
    try:
        whole, ticks = divmod(value, 10_000_000)
        return (FILETIME_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError):
        return None


def text_of(raw):
    """A UTF-16LE path up to its first NUL; an odd byte at the end is not a character and is said so by the caller."""
    return raw[:len(raw) - (len(raw) % 2)].decode("utf-16-le", "replace").split("\x00", 1)[0]


def parse(data, name, file_bytes):
    if len(data) < 0x18:
        return {"file": name, "file_bytes": file_bytes, "truncated": True, "error": f"too short: {len(data)} bytes, need at least 24"}
    header, size, deleted = struct.unpack_from("<QQQ", data, 0)
    entry = {
        "file": name,
        "file_bytes": file_bytes,
        "header_version": header,
        "original_size": size,
        "deleted_at": filetime(deleted),
        "deleted_filetime": str(deleted),
        "truncated": False,
    }
    if header == 1:
        raw = data[0x18:V1_SIZE]
        entry["original_path"] = text_of(raw)
        if len(data) < V1_SIZE:
            entry["truncated"] = True
            entry["note"] = "a version 1 record is %d bytes and this file has %d; the path is what those bytes hold" % (V1_SIZE, len(data))
        elif len(data) > V1_SIZE:
            entry["trailing_bytes"] = len(data) - V1_SIZE
    elif header == 2:
        if len(data) < 0x1C:
            entry["truncated"] = True
            entry["error"] = "header 2 with no path length"
            return entry
        chars = struct.unpack_from("<I", data, 0x18)[0]
        entry["path_characters_declared"] = chars
        need = 0x1C + chars * 2
        raw = data[0x1C:need]
        entry["original_path"] = text_of(raw)
        if len(data) < need:
            entry["truncated"] = True
            entry["note"] = "the record declares %d path characters (%d bytes in all) and this file has %d bytes; the path is what they hold" % (chars, need, len(data))
        elif len(data) > need:
            entry["trailing_bytes"] = len(data) - need
        if len(data) >= need and chars and raw[-2:] != b"\x00\x00":
            entry["note"] = "the declared path is not NUL-terminated"
    else:
        # An unknown header is not a reason to guess: say so and stop, rather
        # than decoding whatever happens to be at 0x18.
        entry["error"] = f"unknown header version {header}; the path was not decoded"
    return entry


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a $I file, or a directory holding them")

    targets = []
    if os.path.isdir(path):
        for root, dirs, names in os.walk(path):
            dirs.sort()
            for name in sorted(names):
                if name.upper().startswith("$I"):
                    targets.append(os.path.join(root, name))
    elif os.path.isfile(path):
        targets = [path]
    else:
        fail("no such file or directory", path=path)

    if not targets:
        fail("no $I files under that directory", path=path)

    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))

    entries = LosslessPage("recyclebin_i", [path], limit)
    counts = {"parsed": 0, "truncated": 0, "unknown_header": 0, "unreadable": 0}
    for target in targets:
        base = os.path.basename(target)
        directory = os.path.dirname(os.path.abspath(target))
        entry = None
        try:
            if os.path.islink(target):
                entry = {"file": target, "error": "a link, not followed"}
            else:
                size = os.path.getsize(target)
                if size > MAX_I_BYTES:
                    entry = {"file": target, "file_bytes": size, "error": "%d bytes: a $I file is a few hundred bytes, and this one is not read" % size}
                else:
                    with open(target, "rb") as fh:
                        data = fh.read(MAX_I_BYTES + 1)
                    entry = parse(data, target, size)
        except OSError as exc:
            entry = {"file": target, "error": str(exc)}
        # The $R file of the same name holds the content while it lasts; the bin directory is named for a SID.
        counterpart = "$R" + base[2:]
        entry["r_file"] = counterpart if os.path.isfile(os.path.join(directory, counterpart)) else None
        sid = os.path.basename(directory)
        if SID.match(sid):
            entry["bin_directory_sid"] = sid
        if entry.get("error") and "unknown header" in str(entry["error"]):
            counts["unknown_header"] += 1
        elif entry.get("error"):
            counts["unreadable"] += 1
        else:
            counts["parsed"] += 1
        if entry.get("truncated"):
            counts["truncated"] += 1
        entries.add(entry)

    page = entries.finish()
    problems = counts["truncated"] + counts["unknown_header"] + counts["unreadable"]
    print(json.dumps({
        "parser": PARSER,
        "status": "partial" if problems else "complete",
        "entries": entries.page,
        "entry_count": page["matched"],
        "found": len(targets),
        "parsed": counts["parsed"],
        "records_truncated": counts["truncated"],
        "unknown_header": counts["unknown_header"],
        "unreadable": counts["unreadable"],
        "note": "A $I record names the original path, size and deletion time of an item the Recycle Bin took. "
                "The directory SID is the account whose bin received it; it does not say who deleted the file or from where.",
        **page,
    }, indent=2))


if __name__ == "__main__":
    main()

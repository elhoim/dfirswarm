#!/usr/bin/env python3
"""Read knowledgeC.db: the application and device-state records macOS keeps for its own features.

CoreDuet records what the machine was doing (Apple's features use it: it is not an
audit log) in one SQLite file per user and one for the system. Streams an examiner
meets:

    /app/inFocus        which application was in front, and for how long
    /app/usage          application use, with the bundle id
    /display/isBacklit  the screen on or off (the state is in ZVALUEINTEGER)
    /device/isLocked    locked or unlocked (the state is in ZVALUEINTEGER)
    /safari/history     browsing
    /app/webUsage       per-application web use, with a domain

Which streams exist, and what they carry, vary by build and by device. This tool
inventories every stream in the file and reads what it finds; it does not assume a
stream is there.

**Every time in the file is Apple absolute: seconds since 2001-01-01 UTC.** Read as
Unix time it lands in 1970; add the wrong constant and it lands somewhere plausible
and wrong. The conversion is +978307200 and is applied here, with the raw value kept
beside the converted one.

What one entry carries (parser knowledgec_query/3): the ZOBJECT row it came from
(`z_pk`, `source_table`), the typed values (`value_string`, `value_integer`,
`value_double`, `value_type_code`), the raw and converted start, end and creation
times, the UUID, every other non-null ZOBJECT column, and, joined on the row's own
foreign keys, every non-null column of its ZSTRUCTUREDMETADATA and ZSOURCE rows under
their own names. The joins are made from the schema the file has (PRAGMA table_info),
not from a fixed column list, and the answer says which tables joined and a
fingerprint of the three tables' columns.

The database is never opened where it lies unless it has no sidecars. A write-ahead
log (or a hot rollback journal) beside it holds committed rows the main file does
not, so with one the database and its sidecars are copied into a private directory,
SQLite applies them there, the frames applied are counted, and the copy is removed;
the evidence directory is not written to (a read-only open of a WAL database creates
a -shm file beside it). With no sidecar the file is opened read-only and immutable.
"""
import base64
import datetime
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import struct
import sys
import tempfile
import urllib.parse
from pathlib import Path

PARSER = "knowledgec_query/3"
APPLE_EPOCH = 978307200
DEFAULT_MAX_STAGE = 2 << 30
BLOB_MAX = 4096
STANDARD = {"Z_PK", "ZSTREAMNAME", "ZVALUESTRING", "ZVALUEINTEGER", "ZVALUEDOUBLE", "ZVALUETYPECODE", "ZSTARTDATE",
            "ZENDDATE", "ZCREATIONDATE", "ZSECONDSFROMGMT", "ZUUID"}


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place
    outside it, the run directory itself, or anything under inputs/ is refused.

    A string check is not enough: `work/../inputs/x`, an absolute path and a
    symlink that points out all name a place the tool must not write, and none
    of them starts with "inputs/". Resolving first and comparing directories
    is what actually holds, and the read-only inputs are the one place
    extracted bytes must never appear -- a later integrity check would report
    the evidence as modified. In a job $OUT is inside the run directory.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    return str(dest.relative_to(root))


# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output (in a job, $OUT/tool-output)
# and named. The file name is a digest of the page's key (a path), never of a value.
class LosslessPage:
    def __init__(self, tool, key, limit):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page = []
        self.total = 0
        self._out = None
        self._tmp = None
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        name = "%s-%s.jsonl" % (self.tool, digest)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row):
        self._out.write(json.dumps(row, ensure_ascii=False, default=str))
        self._out.write("\n")

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            os.replace(self._tmp, self.path)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


def when(value):
    if value is None:
        return None
    try:
        return datetime.datetime.fromtimestamp(
            float(value) + APPLE_EPOCH, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError, TypeError):
        return None


def to_apple(text, name):
    try:
        parsed = datetime.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        fail("since and until must be ISO 8601, e.g. 2026-02-14T00:00:00Z", **{name: text})
    if not parsed.tzinfo:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.timestamp() - APPLE_EPOCH


def quote(name):
    return '"%s"' % name.replace('"', '""')


def cell(value):
    """A SQLite value as JSON: a BLOB as base64 (up to BLOB_MAX bytes, with its whole length), an infinite
    REAL as its name (JSON has none), text as it is."""
    if isinstance(value, (bytes, bytearray)):
        head = bytes(value[:BLOB_MAX])
        return {"_blob_bytes": len(value), "_base64": base64.b64encode(head).decode("ascii"), "_truncated": len(value) > len(head)}
    if isinstance(value, float) and not math.isfinite(value):
        return {"_float": repr(value)}
    return value


def sha256_copy(src, dst):
    digest = hashlib.sha256()
    with open(src, "rb") as read, open(dst, "wb") as write:
        for block in iter(lambda: read.read(1 << 20), b""):
            digest.update(block)
            write.write(block)
    return digest.hexdigest()


def wal_inventory(path):
    """What the WAL says about itself, from its header and its frame headers: the frames of its current
    generation (their salts match the header's) and the last commit among them. Checksums are not verified."""
    size = os.path.getsize(path)
    info = {"bytes": size}
    if size < 32:
        info.update(state="empty or shorter than its 32-byte header", frames_valid=0, frames_committed=0)
        return info
    with open(path, "rb") as fh:
        head = fh.read(32)
        magic, _version, page, seq, salt1, salt2 = struct.unpack(">IIIIII", head[:24])
        if magic not in (0x377F0682, 0x377F0683) or not 512 <= page <= 65536 or page & (page - 1):
            info.update(state="not a WAL header (magic %08x, page size %d)" % (magic, page), frames_valid=0, frames_committed=0)
            return info
        stride = 24 + page
        total = (size - 32) // stride
        valid, committed = 0, 0
        for i in range(total):
            fh.seek(32 + i * stride)
            frame = fh.read(24)
            if len(frame) < 24:
                break
            pgno, commit, s1, s2 = struct.unpack(">IIII", frame[:16])
            if s1 != salt1 or s2 != salt2 or pgno == 0:
                break
            valid += 1
            if commit:
                committed = valid
    info.update(page_size=page, checkpoint_sequence=seq, frames_in_file=total, frames_valid=valid, frames_committed=committed,
                state="frames of the current generation counted from their salts; checksums not verified")
    return info


def stage_parent():
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out:
        return Path(out) / "knowledgec-stage"
    agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
    return Path("work") / agent


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    db = args.get("db")
    if not isinstance(db, str) or not db:
        fail("db is required: a knowledgeC.db")
    if not os.path.isfile(db):
        fail("no such database", db=db)
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    max_stage = args.get("max_stage_bytes", DEFAULT_MAX_STAGE)
    if not isinstance(max_stage, int) or isinstance(max_stage, bool) or max_stage < 1:
        fail("max_stage_bytes must be a positive integer")
    out_name = args.get("out_file")
    if out_name is not None and (not isinstance(out_name, str) or not out_name):
        fail("out_file must be a non-empty string")
    if out_name is not None:
        resolve_output(out_name, "out_file")   # refuses a place outside the run, or under inputs/
    since = to_apple(args["since"], "since") if args.get("since") else None
    until = to_apple(args["until"], "until") if args.get("until") else None

    # The sidecars decide how the file is opened. A WAL or a hot journal holds committed work the main file lacks.
    sidecars = {}
    for suffix in ("-wal", "-shm", "-journal"):
        beside = db + suffix
        if os.path.isfile(beside):
            sidecars[suffix] = {"bytes": os.path.getsize(beside)}
    stage = None
    source = {"database": db, "staged": False, "sidecars": sidecars}
    try:
        if "-wal" in sidecars or "-journal" in sidecars:
            total = os.path.getsize(db) + sum(v["bytes"] for v in sidecars.values())
            if total > max_stage:
                fail("the database and its sidecars (%d bytes) are over max_stage_bytes (%d): nothing was read; raise it, or query the "
                     "files with a tool that applies the WAL" % (total, max_stage), db=db, sidecars=sidecars)
            parent = stage_parent()
            parent.mkdir(parents=True, exist_ok=True)
            stage = tempfile.mkdtemp(prefix="knowledgec-", dir=str(parent))
            name = os.path.basename(db)
            staged_db = os.path.join(stage, name)
            source["database_sha256"] = sha256_copy(db, staged_db)
            source["database_bytes"] = os.path.getsize(db)
            for suffix in sidecars:
                sidecars[suffix]["sha256"] = sha256_copy(db + suffix, staged_db + suffix)
            if "-wal" in sidecars:
                source["wal"] = wal_inventory(db + "-wal")
            source["staged"] = True
            source["open_mode"] = "a private copy of the database and its sidecars, read-write so SQLite applies them, removed at the end"
            connection = sqlite3.connect(staged_db)
        else:
            source["open_mode"] = "read-only and immutable, in place (no WAL or journal beside it)"
            connection = sqlite3.connect("file:%s?mode=ro&immutable=1" % urllib.parse.quote(os.path.abspath(db)), uri=True)
        connection.row_factory = sqlite3.Row
        # Text that is not UTF-8 comes back with its bytes escaped, every byte still said.
        connection.text_factory = lambda b: b.decode("utf-8", "backslashreplace")
        try:
            tables = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        except sqlite3.DatabaseError as exc:
            fail("this file is not a SQLite database", db=db, reason=str(exc))
        if "ZOBJECT" not in tables:
            fail("this is not a knowledgeC database: there is no ZOBJECT table", db=db, tables=tables)
        if source["staged"] and "-wal" in sidecars:
            try:
                busy, log, done = connection.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
                source["wal_checkpoint"] = {"busy": busy, "log": log, "checkpointed": done}
            except sqlite3.Error as exc:
                source["wal_checkpoint"] = {"error": str(exc)}
        try:
            connection.execute("PRAGMA query_only=ON")
        except sqlite3.Error:
            pass

        def info(table):
            return [(r["name"], r["type"]) for r in connection.execute("PRAGMA table_info(%s)" % quote(table))]

        zobject = info("ZOBJECT")
        columns = {n for n, _t in zobject}
        meta_cols = info("ZSTRUCTUREDMETADATA") if "ZSTRUCTUREDMETADATA" in tables else []
        src_cols = info("ZSOURCE") if "ZSOURCE" in tables else []
        joins = {"ZSTRUCTUREDMETADATA": bool(meta_cols) and "ZSTRUCTUREDMETADATA" in columns and any(n == "Z_PK" for n, _ in meta_cols),
                 "ZSOURCE": bool(src_cols) and "ZSOURCE" in columns and any(n == "Z_PK" for n, _ in src_cols)}
        fingerprint = hashlib.sha256("\n".join(
            "%s|%s|%s" % (t, n, ty) for t, cols in (("ZOBJECT", zobject), ("ZSOURCE", src_cols), ("ZSTRUCTUREDMETADATA", meta_cols))
            for n, ty in sorted(cols)).encode("utf-8")).hexdigest()

        select = ["o.%s AS %s" % (quote(n), quote("o|" + n)) for n, _t in zobject]
        if joins["ZSTRUCTUREDMETADATA"]:
            select += ["m.%s AS %s" % (quote(n), quote("m|" + n)) for n, _t in meta_cols]
        if joins["ZSOURCE"]:
            select += ["s.%s AS %s" % (quote(n), quote("s|" + n)) for n, _t in src_cols]
        sql = "SELECT %s FROM ZOBJECT AS o" % ", ".join(select)
        if joins["ZSTRUCTUREDMETADATA"]:
            sql += " LEFT JOIN ZSTRUCTUREDMETADATA AS m ON o.ZSTRUCTUREDMETADATA = m.Z_PK"
        if joins["ZSOURCE"]:
            sql += " LEFT JOIN ZSOURCE AS s ON o.ZSOURCE = s.Z_PK"
        where, params = [], []
        applied, unapplied = [], []
        if args.get("stream"):
            where.append("o.ZSTREAMNAME LIKE ?")
            params.append(args["stream"])
        for name, value, op in (("since", since, ">="), ("until", until, "<=")):
            if value is None:
                continue
            if "ZSTARTDATE" in columns:
                where.append("o.ZSTARTDATE %s ?" % op)
                params.append(value)
                applied.append(name)
            else:
                unapplied.append(name)
        if where:
            sql += " WHERE " + " AND ".join(where)
        order = "o.ZSTARTDATE, o.Z_PK" if "ZSTARTDATE" in columns and "Z_PK" in columns else (
            "o.ZSTARTDATE" if "ZSTARTDATE" in columns else ("o.Z_PK" if "Z_PK" in columns else "o.rowid"))
        sql += " ORDER BY " + order

        sink = None
        if out_name:
            try:
                Path(out_name).parent.mkdir(parents=True, exist_ok=True)
                # The name as the caller gave it: O_EXCL refuses a name that exists, a link (a dangling one included) as much as a file.
                fd = os.open(out_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
            except FileExistsError:
                fail("out_file already exists; the tool does not overwrite: use a new name", out_file=out_name)
            except OSError as exc:
                fail("out_file could not be created", out_file=out_name, reason="%s: %s" % (type(exc).__name__, exc))
            sink = os.fdopen(fd, "w", encoding="utf-8", newline="\n")
        paging = None if sink else LosslessPage("knowledgec_query", [db, args.get("stream"), args.get("since"), args.get("until")], limit)
        inline = []
        count = 0
        unconverted = 0
        try:
            cursor = connection.execute(sql, params)
        except sqlite3.Error as exc:
            fail("the query failed", reason=str(exc), sql=" ".join(sql.split())[:2000])
        names = [d[0] for d in cursor.description]
        for raw in cursor:
            row = dict(zip(names, raw))
            o = {n[2:]: v for n, v in row.items() if n.startswith("o|")}
            start_raw, end_raw, created_raw = o.get("ZSTARTDATE"), o.get("ZENDDATE"), o.get("ZCREATIONDATE")
            duration = None
            if (isinstance(start_raw, (int, float)) and isinstance(end_raw, (int, float))
                    and math.isfinite(start_raw) and math.isfinite(end_raw)):
                duration = round(float(end_raw) - float(start_raw), 3)
            for r in (start_raw, end_raw, created_raw):
                if r is not None and when(r) is None:
                    unconverted += 1
            uuid = o.get("ZUUID")
            entry = {
                "parser": PARSER, "source_table": "ZOBJECT", "z_pk": o.get("Z_PK"), "stream": o.get("ZSTREAMNAME"),
                "value_string": cell(o.get("ZVALUESTRING")), "value_integer": cell(o.get("ZVALUEINTEGER")),
                "value_double": cell(o.get("ZVALUEDOUBLE")), "value_type_code": cell(o.get("ZVALUETYPECODE")),
                "start_raw": cell(start_raw), "end_raw": cell(end_raw), "created_raw": cell(created_raw),
                "start": when(start_raw), "end": when(end_raw), "created": when(created_raw),
                "duration_seconds": duration, "utc_offset_seconds": o.get("ZSECONDSFROMGMT"),
                "uuid": uuid.hex() if isinstance(uuid, (bytes, bytearray)) else uuid,
            }
            other = {n: cell(v) for n, v in o.items() if n not in STANDARD and v is not None}
            if other:
                entry["zobject_other"] = other
            for key, prefix in (("metadata", "m|"), ("source", "s|")):
                got = {n[2:]: cell(v) for n, v in row.items() if n.startswith(prefix) and v is not None}
                if got:
                    entry[key] = got
            count += 1
            if sink:
                sink.write(json.dumps(entry, default=str, sort_keys=True) + "\n")
                if len(inline) < limit:
                    inline.append(entry)
            else:
                paging.add(entry)

        streams = LosslessPage("knowledgec_streams", [db], 200)
        start_col = "ZSTARTDATE" if "ZSTARTDATE" in columns else "NULL"
        for name, n, first, last in connection.execute(
                "SELECT ZSTREAMNAME, COUNT(*), MIN(%s), MAX(%s) FROM ZOBJECT GROUP BY 1 ORDER BY 2 DESC, 1" % (start_col, start_col)):
            streams.add({"stream": name, "count": n, "first_start_raw": cell(first), "last_start_raw": cell(last),
                         "first_start": when(first), "last_start": when(last)})
        streams_page = streams.finish()
        connection.close()
    finally:
        if stage:
            shutil.rmtree(stage, ignore_errors=True)
    if source["staged"]:
        source["staged_copy"] = "removed"

    if sink:
        sink.flush()
        os.fsync(sink.fileno())
        sink.close()
        shown, complete, limited = inline, out_name, count > len(inline)
    else:
        page = paging.finish()
        shown, complete, limited = paging.page, page.get("all_results"), page["truncated"]

    problems = []
    if unapplied:
        problems.append("%s could not be applied: this database has no ZSTARTDATE column, so the rows are not filtered by time" % " and ".join(unapplied))
    wal = source.get("wal")
    if wal and not wal.get("frames_valid"):
        problems.append("a -wal file is beside the database and holds no frame of its current generation (%s): it added nothing" % wal.get("state"))
    cp = source.get("wal_checkpoint")
    if wal and wal.get("frames_valid") and cp and (cp.get("error") or cp.get("log", 0) < 1 or cp.get("busy")):
        problems.append("the WAL has frames of its current generation but SQLite did not apply them (checkpoint %s): rows committed only "
                        "in the WAL are not in this result" % json.dumps(cp))
    if unconverted:
        problems.append("%d time value(s) could not be converted from the Apple epoch; their raw values are in the entries" % unconverted)
    print(json.dumps({
        "db": db,
        "parser": PARSER,
        "status": "partial" if problems else "complete",
        "problems": problems,
        "entries": shown,
        "entry_count": count,
        "entries_inline": len(shown),
        "complete_entries": complete,
        "inline_limited": bool(limited),
        "filters_applied": applied,
        **({"filters_unapplied": unapplied} if unapplied else {}),
        "schema": {"tables": tables, "joins": joins, "fingerprint": fingerprint,
                   "zobject_columns": [n for n, _t in zobject]},
        "source_used": source,
        "streams": streams.page,
        "streams_total": streams_page["matched"],
        "streams_pages": streams_page,
        "note": "Times are converted from the Apple epoch (2001-01-01 UTC) and returned as UTC, with the raw value beside each. "
                "The streams list is every stream in the database, whatever the filters. since and until select rows by start time, "
                "so a record that began before the window and overlapped it is not in it. A write-ahead log beside the database is "
                "applied in a private copy and counted in source_used; a -shm file is a derived index and adds nothing. These are "
                "records of application and device state the machine kept for its own features: foreground application and screen "
                "or lock state do not show a person at the keyboard, and retention varies by OS version and device, so scope an "
                "absence to the earliest and latest rows of the stream in this database.",
    }, indent=2, default=str))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Read wtmp, btmp, utmp and lastlog: Linux's binary login records, in the layouts this tool names.

wtmp holds sessions that started and ended with the source address, btmp the failed attempts (its user
field is what was typed, which may be no account), utmp the sessions now, lastlog the last login per UID.
They are written by login programs and PAM modules, and only by those that were configured to: a record
that is missing does not show that no login happened. They are not a log a root user cannot edit.

Three layouts are read, and the answer names the one it used and how it chose:

  utmp-384    glibc `struct utmp`, 384 bytes (wtmp, btmp, utmp):
                0x000 int16 ut_type    0x004 int32 ut_pid       0x008 char ut_line[32]   0x028 char ut_id[4]
                0x02c char ut_user[32] 0x04c char ut_host[256]  0x14c ut_exit (2 x int16) 0x150 int32 ut_session
                0x154 int32 tv_sec     0x158 int32 tv_usec      0x15c int32 ut_addr_v6[4] 0x16c unused[20]
              tv_sec is a signed 32-bit value. This is the layout of the glibc ABIs that store 32-bit times
              in it; a file in which the records are some other size is not read as this.
  lastlog-292 `struct lastlog` with a 32-bit ll_time, ll_line[32], ll_host[256], indexed by UID
  lastlog-296 the same with a 64-bit ll_time

The byte order of a utmp file is decided from the records: in the right order every non-empty record's
ut_type is 0 to 9, and in the wrong one it almost never is. Where that cannot decide (every record empty) the
answer says `undetermined`, and `byte_order` names it. A lastlog file's layout is decided by its size where
only one width divides it, by structure (every non-empty slot's two text fields are printable, NUL-padded
strings) where both do and the slots can tell, and is refused as ambiguous where nothing can tell: pass
`layout`. A lastlog byte order is the little-endian default unless `byte_order` says otherwise, and the answer
says it was not tested.

A microsecond field outside 0 to 999999 is not a time: the record keeps its raw seconds and microseconds, has
no `time` and says why. Nothing is reduced modulo anything to look plausible. An address whose first word is
the only non-zero one is shown as IPv4 and is also kept as raw hex, because an IPv6 address can look like one.

A file of SQLite (wtmpdb, lastlog2) is refused with a pointer to the SQLite tools. A lastlog file is read slot
by slot by UID, skipping holes of a sparse file, within `max_slots` and `max_seconds`; what is left unread is
named (`next_uid`), and `uids` reads only the slots named.
"""
import datetime
import hashlib
import json
import os
import re
import socket
import struct
import sys
import tempfile
import time
from pathlib import Path

TOOL = "utmp_parse"
PARSER = "utmp_parse/4"
DEFAULT_LIMIT = 200
RECORD = 384
LASTLOG = {"lastlog-292": (292, 4, 4), "lastlog-296": (296, 8, 8)}   # slot width, bytes of ll_time, offset of ll_line
STRUCTURE_SLOTS = 20000        # non-empty slots examined per layout when structure has to decide
DEFAULT_SECONDS = 40.0
CHUNK = 4 << 20
TYPES = {0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME",
         5: "INIT_PROCESS", 6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS",
         9: "ACCOUNTING"}
EPOCH = datetime.datetime(1970, 1, 1)
SQLITE_MAGIC = b"SQLite format 3\x00"


# ---- The parts every tool of this pack that pages or keeps text copies (a tool is standalone; none imports another) ----


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def describe(exc):
    return "%s: %s" % (type(exc).__name__, exc)


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def want_flag(args, key):
    value = args.get(key, False)
    if not isinstance(value, bool):
        fail("%s must be true or false" % key)
    return value


def want_limit(args):
    limit = args.get("limit", DEFAULT_LIMIT)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        fail("limit must be a positive integer")
    return limit


# Lossless paging (the same in every library tool that pages): the page an agent reads stays small, and when
# there are more rows the whole result is written as JSON Lines under work/<agent>/tool-output (in a job,
# $OUT/tool-output) and named. The file name is a digest of the page's key (a path), never of a value.
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
            # In a job only $OUT is written, and it is sealed as the job's output: the whole result is cited from there.
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


def text(raw):
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def address(raw):
    """ut_addr_v6 holds an IPv4 address in its first word, or a whole IPv6 one."""
    words = struct.unpack("<4I", raw)
    if not any(words):
        return None
    if not any(words[1:]):
        return socket.inet_ntop(socket.AF_INET, raw[:4])
    try:
        return socket.inet_ntop(socket.AF_INET6, raw)
    except (OSError, ValueError):
        return raw.hex()


def when(sec, usec=0):
    """(ISO 8601 UTC, error): a time only from a valid seconds and microseconds, the fraction kept."""
    if not sec and not usec:
        return None, None
    if usec < 0 or usec > 999999:
        return None, "tv_usec %d is outside 0..999999: the stored value is not a microsecond count" % usec
    try:
        return (EPOCH + datetime.timedelta(seconds=sec, microseconds=usec)).isoformat() + "Z", None
    except OverflowError:
        return None, "seconds %d are outside the range of a date" % sec


def passwd_users(path):
    users = {}
    if not path:
        return users
    if os.path.islink(path):
        fail("refusing a symlink passwd file", path=path, target=os.readlink(path))
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                fields = line.rstrip("\n").split(":")
                if len(fields) >= 3:
                    try:
                        users[int(fields[2])] = fields[0]
                    except ValueError:
                        continue
    except OSError as exc:
        fail("could not read passwd file", path=path, reason=describe(exc))
    return users


def printable_field(raw):
    """A strncpy'd text field: printable ASCII up to the first NUL, and NUL after it."""
    head, nul, tail = raw.partition(b"\x00")
    return all(0x20 <= b <= 0x7E for b in head) and not any(tail)


def slot_is_text(raw, width, line_at):
    return printable_field(raw[line_at:line_at + 32]) and printable_field(raw[line_at + 32:line_at + 288])


# --- utmp ------------------------------------------------------------------------------------------

def utmp_records(path, size):
    with open(path, "rb") as fh:
        index, offset = 0, 0
        while offset + RECORD <= size:
            raw = fh.read(RECORD)
            if len(raw) < RECORD:
                return
            yield index, offset, raw
            index += 1
            offset += RECORD


def decide_byte_order(path, size):
    """(order, basis): which byte order makes the non-empty records' ut_type a value from 0 to 9."""
    ok = {"little": 0, "big": 0}
    nonempty = 0
    for _i, _o, raw in utmp_records(path, size):
        if not any(raw):
            continue
        nonempty += 1
        for order, fmt in (("little", "<h"), ("big", ">h")):
            if 0 <= struct.unpack_from(fmt, raw, 0)[0] <= 9:
                ok[order] += 1
    if nonempty == 0:
        return "undetermined", "structure cannot decide: every record is empty"
    if ok["little"] > ok["big"]:
        return "little", "structure: ut_type is 0-9 in %d of %d non-empty records read little-endian, %d read big-endian" % (ok["little"], nonempty, ok["big"])
    if ok["big"] > ok["little"]:
        return "big", "structure: ut_type is 0-9 in %d of %d non-empty records read big-endian, %d read little-endian" % (ok["big"], nonempty, ok["little"])
    if ok["little"] == 0:
        return "neither", "structure: no non-empty record (of %d) has a ut_type of 0-9 in either byte order" % nonempty
    return "ambiguous", "structure cannot decide: ut_type is 0-9 in %d of %d non-empty records in either order" % (ok["little"], nonempty)


def parse_utmp(path, size, order, args, pattern, wanted, page, stats):
    e = "<" if order != "big" else ">"
    for index, offset, raw in utmp_records(path, size):
        stats["records"] += 1
        ut_type, pid = struct.unpack_from(e + "hxxi", raw, 0)
        session = struct.unpack_from(e + "i", raw, 0x150)[0]
        sec, usec = struct.unpack_from(e + "ii", raw, 0x154)
        name = TYPES.get(ut_type)
        kind = name or "UNKNOWN"
        user, line, host = text(raw[0x02C:0x04C]), text(raw[0x008:0x028]), text(raw[0x04C:0x14C])
        stats["by_type"][kind] = stats["by_type"].get(kind, 0) + 1
        if kind == "BOOT_TIME":
            stats["boots"] += 1
        if kind == "EMPTY" and not user and not sec and not usec and not line and not host:
            stats["empty"] += 1
            continue
        if wanted and kind not in wanted:
            continue
        if pattern and not pattern.search(user):
            continue
        shown, error = when(sec, usec)
        addr = raw[0x15C:0x16C]
        row = {"id": "U%06d" % (stats["matched"] + 1), "parser": PARSER, "record_index": index, "byte_offset": offset,
               "type": kind, "type_raw": ut_type, "user": user, "line": line, "id_field": text(raw[0x028:0x02C]),
               "host": host, "address": address(addr), "address_raw": addr.hex(), "pid": pid, "session": session,
               "epoch": sec, "usec": usec, "time": shown}
        if error:
            row["time_error"] = error
        stats["matched"] += 1
        page.add(row)


# --- lastlog ---------------------------------------------------------------------------------------

def data_regions(fd, size, begin, end, state):
    """(start, stop) byte ranges of [begin, end) that are not a hole. A file with no hole support is one range."""
    seek_data = getattr(os, "SEEK_DATA", None)
    seek_hole = getattr(os, "SEEK_HOLE", None)
    if seek_data is None or seek_hole is None:
        state["holes"] = False
        yield begin, end
        return
    pos = begin
    try:
        while pos < end:
            start = os.lseek(fd, pos, seek_data)
            if start >= end:
                return
            stop = os.lseek(fd, start, seek_hole)
            yield max(start, pos), min(stop, end)
            pos = stop
    except OSError as exc:
        import errno
        if exc.errno == errno.ENXIO:
            return        # no data after pos: the rest is a hole
        state["holes"] = False
        yield pos, end


def nonempty_slots(path, size, width, begin_uid, end_uid, state, deadline=None):
    """(uid, offset, raw) for each slot in [begin_uid, end_uid) that holds a non-zero byte, skipping holes.

    A chunk that is all zero is passed over whole. If `deadline` passes, the walk stops and
    state["stopped_at_uid"] is the first UID not examined."""
    fd = os.open(path, os.O_RDONLY)
    last = begin_uid - 1
    try:
        lo, hi = begin_uid * width, end_uid * width
        for start, stop in data_regions(fd, size, lo, hi, state):
            pos = (start // width) * width
            while pos < stop:
                if deadline is not None and time.monotonic() > deadline:
                    state["stopped_at_uid"] = max(pos // width, begin_uid)
                    return
                length = min(CHUNK - CHUNK % width, stop - pos + width - 1, size - pos)
                data = os.pread(fd, length, pos)
                if len(data) < width:
                    return
                whole = (len(data) // width) * width
                if data.count(0) != len(data):
                    for k in range(0, whole, width):
                        slot = data[k:k + width]
                        if slot.count(0) != width:
                            uid = (pos + k) // width
                            if begin_uid <= uid < end_uid and uid > last:
                                last = uid
                                yield uid, pos + k, slot
                pos += whole
    finally:
        os.close(fd)


def lastlog_structure(path, size, width, text_at, budget_seconds):
    """(non-empty slots examined, those whose text fields are not text) under one width."""
    seen = bad = 0
    deadline = time.monotonic() + budget_seconds
    for _uid, _off, slot in nonempty_slots(path, size, width, 0, size // width, {"holes": True}, deadline):
        seen += 1
        if not slot_is_text(slot, width, text_at):
            bad += 1
        if seen >= STRUCTURE_SLOTS or time.monotonic() > deadline:
            break
    return seen, bad


def choose_lastlog_layout(path, size, requested):
    if requested in LASTLOG:
        return requested, "argument"
    fits = [name for name, (width, _t, _a) in LASTLOG.items() if size % width == 0]
    if not fits:
        fail("a lastlog file's size is not a whole number of 292-byte or 296-byte slots; pass layout to read whole slots anyway "
             "and have the short tail named", path=path, bytes=size, candidates=sorted(LASTLOG))
    if len(fits) == 1:
        return fits[0], "size: %d bytes is a whole number of %d-byte slots and not of the other width" % (size, LASTLOG[fits[0]][0])
    results = {}
    for name in fits:
        width, _t, text_at = LASTLOG[name]
        results[name] = lastlog_structure(path, size, width, text_at, 10.0)
    clean = [n for n, (seen, bad) in results.items() if seen > 0 and bad == 0]
    broken = [n for n, (seen, bad) in results.items() if bad > 0]
    if len(clean) == 1 and len(broken) == len(fits) - 1:
        n = clean[0]
        return n, "structure: all %d non-empty slots read as %s have printable, NUL-padded line and host fields; %s" % (
            results[n][0], n, "; ".join("%s: %d of %d slots do not" % (b, results[b][1], results[b][0]) for b in broken))
    fail("the lastlog layout is ambiguous: the size divides by both 292 and 296 and the slots cannot tell them apart "
         "(%s). Pass layout: lastlog-292 or lastlog-296" % "; ".join("%s: %d non-empty slots, %d not text" % (n, s, b) for n, (s, b) in results.items()),
         ambiguous=True, candidates=sorted(fits), path=path, bytes=size)


def parse_lastlog(path, size, layout, order, args, pattern, wanted, page, stats, deadline):
    width, time_bytes, text_at = LASTLOG[layout]
    e = "<" if order != "big" else ">"
    fmt = e + ("i" if time_bytes == 4 else "q")
    users = passwd_users(args.get("passwd"))
    total = size // width
    selected = args.get("uids")
    state = {"holes": True}
    if selected is not None:
        if not isinstance(selected, list) or not all(isinstance(u, int) and not isinstance(u, bool) and u >= 0 for u in selected):
            fail("uids must be a list of whole numbers (UIDs)")
        stats["scope"] = "selected UIDs"
        fd = os.open(path, os.O_RDONLY)
        try:
            for uid in sorted(set(selected)):
                if uid >= total:
                    stats["uids_beyond_file"].append(uid)
                    continue
                slot = os.pread(fd, width, uid * width)
                stats["slots_read"] += 1
                emit_slot(uid, uid * width, slot, width, fmt, time_bytes, text_at, users, pattern, wanted, page, stats, layout)
        finally:
            os.close(fd)
        stats["next_uid"] = None
        return
    start = args.get("start_uid", 0)
    cap = args.get("max_slots")
    if isinstance(start, bool) or not isinstance(start, int) or start < 0:
        fail("start_uid must be a whole number")
    if cap is not None and (isinstance(cap, bool) or not isinstance(cap, int) or cap < 1):
        fail("max_slots must be a positive whole number")
    end = total if cap is None else min(total, start + cap)
    stats["scope"] = "whole file" if start == 0 and end == total else "uid %d to %d" % (start, end - 1)
    for uid, offset, slot in nonempty_slots(path, size, width, start, end, state, deadline):
        stats["nonempty"] += 1
        emit_slot(uid, offset, slot, width, fmt, time_bytes, text_at, users, pattern, wanted, page, stats, layout)
    if "stopped_at_uid" in state:
        stats["slots_read"] = state["stopped_at_uid"] - start
        stats["next_uid"] = state["stopped_at_uid"]
        stats["stopped"] = "max_seconds"
    else:
        stats["slots_read"] = end - start
        stats["next_uid"] = end if end < total else None
    stats["holes_skipped"] = state["holes"]


def emit_slot(uid, offset, slot, width, fmt, time_bytes, text_at, users, pattern, wanted, page, stats, layout):
    if slot.count(0) == width:
        return
    sec = struct.unpack_from(fmt, slot, 0)[0]
    line, host = text(slot[text_at:text_at + 32]), text(slot[text_at + 32:text_at + 288])
    user = users.get(uid)
    if wanted and "LASTLOG" not in wanted:
        return
    if pattern and not pattern.search(user or str(uid)):
        return
    shown, error = when(sec, 0)
    row = {"id": "U%06d" % (stats["matched"] + 1), "parser": PARSER, "type": "LASTLOG", "uid": uid, "slot": uid,
           "byte_offset": offset, "layout": layout, "user": user, "line": line, "host": host, "epoch": sec, "time": shown}
    if error:
        row["time_error"] = error
    if not slot_is_text(slot, width, text_at):
        row["text_fields_valid"] = False
    stats["matched"] += 1
    page.add(row)


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a wtmp, btmp, utmp or lastlog file")
    if os.path.islink(path):
        fail("refusing a symlink: pass the binary log inside the evidence", path=path, target=os.readlink(path))
    if not os.path.isfile(path):
        fail("no such file", path=path)
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(16)
    if head.startswith(SQLITE_MAGIC):
        fail("this is a SQLite database (wtmpdb and lastlog2 write one), not a utmp or lastlog file, and this tool does not read "
             "it. Copy it with its -wal and -shm files and open the copy read-only with sqlite_query from the "
             "computer-forensics-base pack.", path=path, format="sqlite", bytes=size)
    limit = want_limit(args)
    wanted = {str(t).upper() for t in (args.get("types") or [])}
    pattern = None
    if args.get("user"):
        try:
            pattern = re.compile(args["user"], re.I)
        except re.error as exc:
            fail("user is not a valid regex", reason=str(exc))
    requested_format = args.get("format")
    if requested_format not in (None, "utmp", "lastlog"):
        fail("format must be utmp or lastlog")
    layout_arg = args.get("layout", "auto")
    if layout_arg not in ("auto", "utmp-384", "lastlog-292", "lastlog-296"):
        fail("layout must be auto, utmp-384, lastlog-292 or lastlog-296")
    order_arg = args.get("byte_order", "auto")
    if order_arg not in ("auto", "little", "big"):
        fail("byte_order must be auto, little or big")
    seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds <= 0:
        fail("max_seconds must be a positive number")
    is_lastlog = (requested_format == "lastlog" or layout_arg.startswith("lastlog")
                  or (requested_format is None and layout_arg == "auto" and os.path.basename(path).lower() == "lastlog"))
    if requested_format == "utmp" and layout_arg.startswith("lastlog") or requested_format == "lastlog" and layout_arg == "utmp-384":
        fail("format and layout disagree", format=requested_format, layout=layout_arg)
    page = LosslessPage(TOOL, [path, sorted(wanted), str(pattern.pattern if pattern else ""), layout_arg, order_arg, args.get("uids"), args.get("start_uid")], limit)
    stats = {"records": 0, "empty": 0, "matched": 0, "boots": 0, "by_type": {}, "slots_read": 0, "nonempty": 0,
             "scope": "whole file", "next_uid": None, "uids_beyond_file": []}
    deadline = time.monotonic() + seconds
    out = {"parser": PARSER, "path": path, "bytes": size}
    if is_lastlog and size == 0:
        out["layout"] = {"name": None, "basis": "the file is empty: it holds no slot, so no layout is needed"}
        pages = {"records": page.finish()}
        out.update({"slots_total": 0, "slots_read": 0, "nonempty_slots": 0, "scope": "whole file", "next_uid": None,
                    "trailing_bytes": 0, "all_records_read": True, "record_count": 0, "records": [], "pages": pages, "truncated": False,
                    "note": "An empty lastlog file holds no slot."})
        print(json.dumps(out, indent=2))
        return
    if is_lastlog:
        layout, basis = choose_lastlog_layout(path, size, layout_arg)
        width = LASTLOG[layout][0]
        order = "big" if order_arg == "big" else "little"
        order_basis = "argument" if order_arg != "auto" else "default assumption, not tested: a lastlog slot has no field to test it by"
        out["layout"] = {"name": layout, "slot_bytes": width, "basis": basis, "byte_order": order, "byte_order_basis": order_basis}
        parse_lastlog(path, size, layout, order, args, pattern, wanted, page, stats, deadline)
        out.update({
            "slots_total": size // width,
            "slots_read": stats["slots_read"],
            "nonempty_slots": stats["nonempty"] if args.get("uids") is None else stats["matched"],
            "scope": stats["scope"],
            "next_uid": stats["next_uid"],
            "stopped": stats.get("stopped"),
            "uids_beyond_file": stats["uids_beyond_file"],
            "trailing_bytes": size % width,
            "trailing_offset": (size // width) * width if size % width else None,
            "all_records_read": stats["scope"] == "whole file" and stats["next_uid"] is None and stats.get("stopped") is None and size % width == 0,
            "note": "Each LASTLOG record is the most recent login stored for one UID: the file is indexed by UID, an empty slot is "
                    "not evidence the account never logged in, and a program that does not update lastlog leaves it unchanged. Pass "
                    "passwd (the evidence's own) to name the accounts.",
        })
    else:
        if order_arg == "auto":
            order, order_basis = decide_byte_order(path, size)
            if order == "neither":
                fail("this does not read as a utmp file: %s. If it is a wtmp, btmp or utmp from a C library whose records are not "
                     "384 bytes, this tool does not read it" % order_basis, path=path, bytes=size)
            if order == "ambiguous":
                fail("the byte order is ambiguous: the records read as utmp in either order. Pass byte_order: little or big",
                     ambiguous=True, candidates=["big", "little"], path=path, basis=order_basis)
        else:
            order, order_basis = order_arg, "argument"
        out["layout"] = {"name": "utmp-384", "record_bytes": RECORD,
                         "basis": "argument" if layout_arg != "auto" else "assumed: the only utmp layout this tool reads, 384-byte records",
                         "abi": "glibc struct utmp with 32-bit session and time fields",
                         "byte_order": order, "byte_order_basis": order_basis}
        parse_utmp(path, size, order, args, pattern, wanted, page, stats)
        out.update({
            "records_in_file": stats["records"],
            "empty_records": stats["empty"],
            "by_type": stats["by_type"],
            "boots": stats["boots"],
            "trailing_bytes": size % RECORD,
            "trailing_offset": (size // RECORD) * RECORD if size % RECORD else None,
            "all_records_read": size % RECORD == 0,
            "note": "A USER_PROCESS record is a session that started; the matching DEAD_PROCESS on the same line is when it ended, and a "
                    "session with no end is not shown to be still open. btmp holds failures and its user field is what was typed, which "
                    "may be no account. Records exist only for programs that wrote them: a missing record is not a login that did not "
                    "happen. A type outside 0-9 is UNKNOWN, kept raw. Compare these records with auth.log and the journal; a "
                    "disagreement has more than one explanation (rotation, a program that does not write wtmp, a damaged or edited file).",
        })
    pages = {"records": page.finish()}
    out.update({"record_count": pages["records"]["matched"], "records": page.page, "pages": pages,
                "truncated": pages["records"]["truncated"]})
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()

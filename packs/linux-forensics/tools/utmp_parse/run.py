#!/usr/bin/env python3
"""Read wtmp, btmp and utmp: the login record Linux keeps in binary.

Text logs are edited; these are not, as often. An operator who cleans
/var/log/auth.log frequently leaves wtmp alone, and the two disagreeing is
itself evidence. wtmp holds successful sessions with the source address, btmp
holds the failures, and both keep going back as far as rotation allowed.

struct utmp on 64-bit Linux, 384 bytes, little-endian:

  0x000 int16  ut_type          0x004 int32  ut_pid
  0x008 char   ut_line[32]      0x028 char   ut_id[4]
  0x02c char   ut_user[32]      0x04c char   ut_host[256]
  0x14c int32  ut_exit          0x150 int32  ut_session
  0x154 int32  tv_sec           0x158 int32  tv_usec
  0x15c int32  ut_addr_v6[4]    0x16c char   unused[20]

tv_sec is a 32-bit signed value even on 64-bit systems, which is a real
year-2038 problem sitting inside the format and worth knowing before a date
comes back negative.
"""
import datetime
import json
import os
import re
import socket
import struct
import sys

RECORD = 384
TYPES = {0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME",
         5: "INIT_PROCESS", 6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS",
         9: "ACCOUNTING"}


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


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


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a wtmp, btmp or utmp file")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    size = os.path.getsize(path)
    if size % RECORD:
        note = "the file is not a whole number of %d-byte records; the tail is reported as short" % RECORD
    else:
        note = None
    limit = args.get("limit", 1000)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    wanted = {str(t).upper() for t in (args.get("types") or [])}
    pattern = None
    if args.get("user"):
        try:
            pattern = re.compile(args["user"], re.I)
        except re.error as exc:
            fail("user is not a valid regex", reason=str(exc))

    records, seen, truncated = [], 0, False
    with open(path, "rb") as fh:
        while True:
            raw = fh.read(RECORD)
            if len(raw) < RECORD:
                break
            seen += 1
            ut_type, pid = struct.unpack_from("<hxxi", raw, 0)
            sec, usec = struct.unpack_from("<ii", raw, 0x154)
            when = None
            if sec:
                try:
                    when = datetime.datetime.fromtimestamp(
                        sec, datetime.timezone.utc).replace(microsecond=usec % 1000000)
                    when = when.isoformat().replace("+00:00", "Z")
                except (OverflowError, OSError, ValueError):
                    when = None
            entry = {
                "type": TYPES.get(ut_type, str(ut_type)),
                "user": text(raw[0x02C:0x04C]),
                "line": text(raw[0x008:0x028]),
                "id": text(raw[0x028:0x02C]),
                "host": text(raw[0x04C:0x14C]),
                "address": address(raw[0x15C:0x16C]),
                "pid": pid,
                "session": struct.unpack_from("<i", raw, 0x150)[0],
                "time": when,
                "epoch": sec,
            }
            if entry["type"] == "EMPTY" and not entry["user"] and not sec:
                continue
            if wanted and entry["type"] not in wanted:
                continue
            if pattern and not pattern.search(entry["user"]):
                continue
            if len(records) >= limit:
                truncated = True
                break
            records.append(entry)

    boots = [r for r in records if r["type"] == "BOOT_TIME"]
    print(json.dumps({
        "path": path,
        "records_in_file": seen,
        "records": records,
        "record_count": len(records),
        "boots": len(boots),
        "truncated": truncated,
        "file_note": note,
        "note": "A USER_PROCESS record is a session that started; the matching DEAD_PROCESS on the "
                "same line is when it ended. btmp holds failures and its user field is what was "
                "typed, which may be a user name that does not exist. Compare these against "
                "/var/log/auth.log: where the two disagree, the text log was edited.",
    }, indent=2))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Put every scheduled job on the machine in one list.

Scheduling on Linux is scattered across six places and two subsystems, and an
agent that checks the obvious one has checked a sixth of it. The @reboot entry
in a user's spool file is persistence with no schedule at all and is the one
most often missed.

    /etc/crontab                     system table, with a user field
    /etc/cron.d/*                    drop-ins, also with a user field
    /etc/cron.{hourly,daily,weekly,monthly}/   scripts, run by run-parts
    /var/spool/cron/crontabs/<user>  per-user tables, no user field
    /var/spool/cron/<user>           the same, on Red Hat family
    *.timer + *.service              systemd, the modern route

Each entry comes back with the file it was in and that file's modification
time, because the question is almost never "what is scheduled" but "what was
added, and when".
"""
import datetime
import json
import os
import re
import sys

SPECIALS = {"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily",
            "@midnight", "@hourly"}
SYSTEM_TABLES = ["etc/crontab"]
SYSTEM_DIRS = ["etc/cron.d"]
RUN_PARTS = ["etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly"]
SPOOLS = ["var/spool/cron/crontabs", "var/spool/cron"]
UNIT_DIRS = ["etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system",
             "run/systemd/system"]


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def mtime_of(path):
    try:
        return datetime.datetime.fromtimestamp(
            os.path.getmtime(path), datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except OSError:
        return None


def parse_table(path, has_user):
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        return [{"file": path, "error": str(exc)}]
    stamp = mtime_of(path)
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"^[A-Z_]+\s*=", line):          # MAILTO=, PATH=, SHELL=
            continue
        parts = line.split()
        if parts[0] in SPECIALS:
            schedule, rest = parts[0], parts[1:]
        elif len(parts) >= 6:
            schedule, rest = " ".join(parts[:5]), parts[5:]
        else:
            continue
        user = None
        if has_user and rest:
            user, rest = rest[0], rest[1:]
        out.append({"source": "cron", "file": path, "file_modified": stamp,
                    "schedule": schedule, "user": user, "command": " ".join(rest),
                    "at_reboot": schedule == "@reboot"})
    return out


def parse_unit(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return {"file": path, "error": str(exc)}
    def field(name):
        found = re.search(r"^\s*%s\s*=\s*(.+?)\s*$" % name, text, re.M)
        return found.group(1) if found else None
    return {"source": "systemd", "file": path, "file_modified": mtime_of(path),
            "schedule": field("OnCalendar") or field("OnBootSec") or field("OnUnitActiveSec"),
            "unit": field("Unit") or os.path.basename(path).replace(".timer", ".service"),
            "persistent": field("Persistent"), "command": None,
            "at_reboot": bool(field("OnBootSec"))}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    root = args.get("root")
    if not isinstance(root, str) or not root:
        fail("root is required: an extracted file system root")
    if not os.path.isdir(root):
        fail("no such directory", root=root)
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    pattern = None
    if args.get("contains"):
        try:
            pattern = re.compile(args["contains"], re.I)
        except re.error as exc:
            fail("contains is not a valid regex", reason=str(exc))

    entries, looked = [], []
    def note(rel):
        looked.append(rel)

    for rel in SYSTEM_TABLES:
        full = os.path.join(root, rel); note(rel)
        if os.path.isfile(full):
            entries += parse_table(full, has_user=True)
    for rel in SYSTEM_DIRS:
        full = os.path.join(root, rel); note(rel)
        if os.path.isdir(full):
            for name in sorted(os.listdir(full)):
                target = os.path.join(full, name)
                if os.path.isfile(target):
                    entries += parse_table(target, has_user=True)
    for rel in RUN_PARTS:
        full = os.path.join(root, rel); note(rel)
        if os.path.isdir(full):
            for name in sorted(os.listdir(full)):
                target = os.path.join(full, name)
                if os.path.isfile(target):
                    entries.append({"source": "run-parts", "file": target,
                                    "file_modified": mtime_of(target),
                                    "schedule": os.path.basename(rel).replace("cron.", "@"),
                                    "user": "root", "command": target, "at_reboot": False})
    for rel in SPOOLS:
        full = os.path.join(root, rel); note(rel)
        if os.path.isdir(full):
            for name in sorted(os.listdir(full)):
                target = os.path.join(full, name)
                if os.path.isfile(target):
                    for entry in parse_table(target, has_user=False):
                        entry["user"] = entry.get("user") or name
                        entries.append(entry)
    for rel in UNIT_DIRS:
        full = os.path.join(root, rel); note(rel)
        if os.path.isdir(full):
            for dirpath, _dirs, names in os.walk(full):
                for name in sorted(names):
                    if name.endswith(".timer"):
                        entries.append(parse_unit(os.path.join(dirpath, name)))

    if pattern:
        entries = [e for e in entries
                   if pattern.search((e.get("command") or "") + " " + (e.get("unit") or ""))]
    truncated = len(entries) > limit
    kept = entries[:limit]
    print(json.dumps({
        "root": root,
        "locations_checked": looked,
        "entries": kept,
        "entry_count": len(kept),
        "at_reboot": sum(1 for e in kept if e.get("at_reboot")),
        "truncated": truncated,
        "note": "file_modified is the thing to read first: a cron directory where every file "
                "dates from the build and one dates from last month answers the question on its "
                "own. An @reboot entry is persistence with no schedule. A systemd timer only says "
                "when; read the unit it names for what runs.",
    }, indent=2))


if __name__ == "__main__":
    main()

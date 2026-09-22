#!/usr/bin/env python3
"""Read the unified log, on a Mac or off one.

macOS stopped writing text logs years ago; /var/log/system.log is nearly empty
and the real record is a compressed binary format under /var/db/diagnostics,
whose entries hold references into /var/db/uuidtext rather than message text.
Both directories are needed. A collection that took one and left the other
produces entries whose message is a placeholder, and that is a limit on the
evidence rather than on the analysis — so it is reported as one.

Two readers exist and this uses whichever is present:

    log        Apple's own, macOS only, and the only one that resolves the
               format strings exactly as the system would have
    UnifiedLogReader.py   for an examination host that is not a Mac

`--info --debug` are always passed. Without them the default level hides most of
what an investigation wants and says nothing about having done so.
"""
import json
import os
import shutil
import subprocess
import sys

DEFAULT_TIMEOUT = 900
KEEP = ["timestamp", "processImagePath", "process", "subsystem", "category",
        "senderImagePath", "eventMessage", "messageType", "processID", "threadID",
        "activityIdentifier", "eventType"]


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a .logarchive or a directory holding diagnostics and uuidtext")
    if not os.path.exists(path):
        fail("no such file or directory", path=path)
    out_dir = args.get("out_dir")
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: a directory under work/ for the reader's own output")
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 10:
        fail("timeout_seconds must be an integer of at least 10")

    apple = shutil.which("log")
    reader = shutil.which("UnifiedLogReader.py") or shutil.which("UnifiedLogReader")
    if not apple and not reader:
        fail("no unified log reader on PATH",
             looked_for=["log", "UnifiedLogReader.py"],
             install={"log": "part of macOS", "UnifiedLogReader": "python3 -m pip install UnifiedLogReader"},
             note="Off a Mac, Apple's log command does not exist and UnifiedLogReader is the route.")

    os.makedirs(out_dir, exist_ok=True)
    missing_uuidtext = None
    if os.path.isdir(path):
        has = {n.lower() for n in os.listdir(path)}
        if "diagnostics" in has and "uuidtext" not in has:
            missing_uuidtext = ("diagnostics is present and uuidtext is not: entries will carry "
                                "placeholders instead of messages")

    if apple:
        engine = "log"
        argv = [apple, "show", "--archive", path, "--style", "ndjson", "--info", "--debug"]
        for flag, key in (("--predicate", "predicate"), ("--start", "start"), ("--end", "end")):
            if args.get(key):
                argv += [flag, str(args[key])]
    else:
        engine = "UnifiedLogReader"
        argv = [reader, path, os.path.join(path, "uuidtext") if os.path.isdir(path) else path,
                out_dir, "-f", "SQLITE"]

    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        fail("%s did not finish in time" % engine, after_seconds=timeout, command=" ".join(argv))

    entries, unparsed = [], 0
    if engine == "log":
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue
            try:
                row = json.loads(line)
            except ValueError:
                unparsed += 1
                continue
            entries.append({k: row.get(k) for k in KEEP if row.get(k) is not None})
            if len(entries) >= limit:
                break
        if not entries and proc.returncode != 0:
            fail("log refused this archive", exit_code=proc.returncode,
                 stderr=(proc.stderr or "").strip()[-600:], command=" ".join(argv))
    else:
        found = [os.path.join(out_dir, n) for n in sorted(os.listdir(out_dir))]
        if not found:
            fail("UnifiedLogReader wrote nothing", exit_code=proc.returncode,
                 stderr=(proc.stderr or "").strip()[-600:], command=" ".join(argv))

    print(json.dumps({
        "path": path,
        "engine": engine,
        "command": " ".join(argv),
        "out_dir": out_dir,
        "entries": entries,
        "entry_count": len(entries),
        "unparsed_lines": unparsed,
        "warning": missing_uuidtext,
        "reader_said": (proc.stderr or "").strip()[-400:] or None,
        "note": "Retention is days on a busy machine, not months, and it is not usefully "
                "configurable: an event three weeks before acquisition is usually gone, and its "
                "absence means nothing. Quote the predicate with any line you cite so a reviewer "
                "can re-run it. Where the engine is UnifiedLogReader the entries are in out_dir, "
                "not inline.",
    }, indent=2, default=str))


if __name__ == "__main__":
    main()

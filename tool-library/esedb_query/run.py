#!/usr/bin/env python3
"""Read an ESE (Extensible Storage Engine) database as tables.

The gap this closes is recorded in a delivered report's own words: "No
`esedbexport`: WebCacheV01.dat and spartan.edb could not be parsed as
tables". That file appears in four of the fifteen measured runs across 144
trace events and was never once read as tables. The same wrapper opens
SRUDB.dat (the System Resource Usage Monitor) and Edge's database, so one
tool covers three artefacts that a Windows case asks for every time.

Backed by `esedbexport` (libesedb), which writes one TSV per table into a
directory. This wraps it: list the tables, or read one with a row cap, and
return JSON either way. It never leaves its export behind in a place the
caller did not ask for.
"""
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile


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
        fail("path is required: the .dat or .edb file to read", path=args.get("path"))
    if not os.path.isfile(path):
        fail("no such file", path=path)

    table = args.get("table")
    if table is not None and not isinstance(table, str):
        fail("table must be a string", table=table)
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))
    limit = min(limit, 20000)

    if shutil.which("esedbexport") is None:
        fail(
            "esedbexport is not on PATH",
            hint="brew install libesedb, or apt-get install libesedb-utils; "
            "scripts/toolbox.sh reports it with the dfir set",
        )

    out = tempfile.mkdtemp(prefix="esedb-")
    try:
        # -t names the export root; libesedb appends ".export". No -q: the
        # esedbexport Debian ships (20181229) has none, and refused the call.
        target = os.path.join(out, "db")
        proc = subprocess.run(
            ["esedbexport", "-t", target, path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        export = target + ".export"
        if not os.path.isdir(export):
            fail(
                "esedbexport produced no tables",
                status=proc.returncode,
                stderr=proc.stderr.decode("utf-8", "replace").strip()[:2000],
            )

        names = sorted(
            f[: -len(".csv")] if f.endswith(".csv") else f
            for f in os.listdir(export)
            if os.path.isfile(os.path.join(export, f))
        )
        if table is None:
            sizes = {}
            for f in os.listdir(export):
                abs_f = os.path.join(export, f)
                if os.path.isfile(abs_f):
                    sizes[f.rsplit(".", 1)[0]] = os.path.getsize(abs_f)
            print(json.dumps({
                "path": path,
                "tables": names,
                "table_count": len(names),
                "bytes_per_table": sizes,
                "hint": "call again with table=<name> to read one",
            }, indent=2))
            return

        matches = [n for n in names if n.lower() == table.lower()]
        if not matches:
            fail("no such table", table=table, tables=names)
        chosen = matches[0]
        # libesedb writes <name>.csv, tab-separated despite the extension.
        candidates = [
            os.path.join(export, chosen + ".csv"),
            os.path.join(export, chosen),
        ]
        src = next((c for c in candidates if os.path.isfile(c)), None)
        if src is None:
            fail("the table exported no file", table=chosen)

        rows = []
        truncated = False
        with open(src, "r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.reader(fh, delimiter="\t")
            header = next(reader, [])
            for row in reader:
                if len(rows) >= limit:
                    truncated = True
                    break
                rows.append({header[i] if i < len(header) else f"col{i}": v for i, v in enumerate(row)})
        print(json.dumps({
            "path": path,
            "table": chosen,
            "columns": header,
            "rows": rows,
            "row_count": len(rows),
            "truncated": truncated,
        }, indent=2))
    finally:
        shutil.rmtree(out, ignore_errors=True)


if __name__ == "__main__":
    main()

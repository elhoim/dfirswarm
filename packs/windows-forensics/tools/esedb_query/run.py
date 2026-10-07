#!/usr/bin/env python3
"""Read an ESE (Extensible Storage Engine) database as tables.

The gap this closes is recorded in a delivered report's own words: "No
`esedbexport`: WebCacheV01.dat and spartan.edb could not be parsed as
tables". That file appears in four of the fifteen measured runs across 144
trace events and was never once read as tables. The same wrapper opens
SRUDB.dat (the System Resource Usage Monitor) and Edge's database, so one
tool covers three artefacts that a Windows case asks for every time.

Backed by `esedbexport` (libesedb), which writes one TSV per table into a
directory. This wraps it: list the tables, or read one, and return JSON either
way. It exports TABLES, as text: it does not decode what a table means (a SRUM
table is not joined to the application or user it names, a WebCache container
is not resolved to a browser), and it does not read an ESE log.

The export is made once per database, into `esedb-export/<sha256 of the database,
first 16 hex>/` under the job's $OUT (or the agent's own work directory), with the
exporter's whole standard output and standard error in files beside it and an
`export-manifest.json` that records the database's digest, the exporter's version, argv
and exit status and every table file. A later call with the same database reuses a
complete export. An exporter that exits non-zero, or is stopped by its time limit, leaves a
PARTIAL export: the answer says status: partial, never lists it as the database's tables,
and keeps the logs. A table name that matches more than one export file is refused with
the candidates, never resolved by taking the first.
"""
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
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


PARSER = "esedb_query/4"


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def work_root():
    """Where exports live, and the name they are cited by: $OUT/esedb-export in a job, else the agent's own directory."""
    out, job = os.environ.get("OUT"), os.environ.get("JOB_ID")
    if job and out:
        return Path(out) / "esedb-export", "store/jobs/%s/out/esedb-export" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)
    d = Path("work") / re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool") / "esedb-export"
    return d, str(d)


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def exporter_version():
    try:
        p = subprocess.run(["esedbexport", "-V"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        lines = p.stdout.decode("utf-8", "replace").strip().splitlines()
        return lines[0].strip() if p.returncode == 0 and lines else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def table_files(export):
    """The export's files, by table name. libesedb names each export file <table>.<its index>
    (Containers.4, Container_1.6): the table is the part before the index, the name an agent
    knows it by."""
    files = {}
    for f in sorted(os.listdir(export)):
        if os.path.isfile(os.path.join(export, f)):
            base = f[: -len(".csv")] if f.endswith(".csv") else f
            m = re.fullmatch(r"(.+)\.(\d+)", base)
            files[f] = m.group(1) if m else base
    return files


def make_export(path, digest, timeout, root):
    """Run esedbexport once into root/<digest[:16]>/, or reuse a complete export of the same bytes.
    Returns (record, reused). The record is the export-manifest.json content."""
    base = root / digest[:16]
    manifest_path = base / "export-manifest.json"
    if manifest_path.is_file():
        try:
            record = json.loads(manifest_path.read_text(encoding="utf-8"))
            if record.get("db_sha256") == digest and record.get("exporter_exit_status") == 0 and not record.get("timed_out") \
                    and os.path.isdir(str(base / "db.export")):
                return record, True
        except (OSError, ValueError):
            pass
        shutil.rmtree(base, ignore_errors=True)       # a partial or unreadable earlier export is made again
    base.mkdir(parents=True, exist_ok=True)
    target = str(base / "db")
    out_file, err_file = base / "esedbexport.stdout.txt", base / "esedbexport.stderr.txt"
    # -t names the export root; libesedb appends ".export". No -q: the esedbexport Debian
    # ships (20181229) has none, and refused the call.
    argv = ["esedbexport", "-t", target, path]
    timed_out = False
    with open(out_file, "wb") as so, open(err_file, "wb") as se:
        proc = subprocess.Popen(argv, stdout=so, stderr=se, stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, 9)
            except (OSError, ProcessLookupError):
                pass
            rc = proc.wait()
    export = target + ".export"
    files = {}
    if os.path.isdir(export):
        files = {f: {"table": t, "bytes": os.path.getsize(os.path.join(export, f))} for f, t in table_files(export).items()}
    record = {
        "parser": PARSER,
        "db": path,
        "db_bytes": os.path.getsize(path),
        "db_sha256": digest,
        "exporter_argv": argv,
        "exporter_version": exporter_version(),
        "exporter_exit_status": rc,
        "timed_out": timed_out,
        "export_dir": "db.export" if os.path.isdir(export) else None,
        "stdout_file": out_file.name,
        "stderr_file": err_file.name,
        "files": files,
    }
    manifest_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record, False


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
    timeout = args.get("export_timeout_seconds", 240)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
        fail("export_timeout_seconds must be a positive integer", export_timeout_seconds=args.get("export_timeout_seconds"))

    if shutil.which("esedbexport") is None:
        fail(
            "esedbexport is not on PATH",
            hint="brew install libesedb, or apt-get install libesedb-utils; "
            "scripts/toolbox.sh reports it with the dfir set",
        )

    root, shown_root = work_root()
    full = sha256_of(path)
    digest = full[:16]
    # The directory is named by the first 16 hex digits; the manifest holds the whole digest.
    record, reused = make_export(path, full, timeout, root)
    base = root / digest
    export = base / "db.export"
    shown = "%s/%s" % (shown_root, digest)
    complete = record["exporter_exit_status"] == 0 and not record["timed_out"]
    logs = {"stdout_file": "%s/%s" % (shown, record["stdout_file"]), "stderr_file": "%s/%s" % (shown, record["stderr_file"])}
    stderr_text = (base / record["stderr_file"]).read_text(encoding="utf-8", errors="replace")
    common = {
        "parser": PARSER,
        "path": path,
        "db_sha256": full,
        "exporter_version": record["exporter_version"],
        "exporter_exit_status": record["exporter_exit_status"],
        "timed_out": record["timed_out"],
        "export_reused": reused,
        "export_manifest": "%s/export-manifest.json" % shown,
        "export_dir": "%s/db.export" % shown,
        **logs,
    }
    if not os.path.isdir(str(export)) or not record["files"]:
        fail("esedbexport produced no tables",
             **{**common, "status": "failed", "stderr_first_lines": stderr_text.strip().splitlines()[:10]})

    files = {f: v["table"] for f, v in record["files"].items()}
    names = sorted(set(files.values()))
    if not complete:
        common.update({
            "status": "partial",
            "complete": False,
            "warning": "esedbexport %s: this is a PARTIAL export, and a table missing from it, or short, is not absent from the database; "
                       "the exporter's own output is in stdout_file and stderr_file" % ("was stopped by its time limit" if record["timed_out"] else "exited with status %s" % record["exporter_exit_status"]),
            "stderr_first_lines": stderr_text.strip().splitlines()[:10],
        })
    else:
        common.update({"status": "complete", "complete": True})

    if table is None:
        sizes = {}
        for f, name in files.items():
            sizes[name] = sizes.get(name, 0) + record["files"][f]["bytes"]
        listing = {"tables_in_partial_export" if not complete else "tables": names}
        print(json.dumps({
            **common,
            **listing,
            "table_count": len(names),
            "bytes_per_table": sizes,
            "files": {f: v["bytes"] for f, v in record["files"].items()},
            "hint": "call again with table=<name> to read one; the export is kept and reused",
        }, indent=2))
        return

    # By its name, or by the export file's own name (index and all).
    wanted = table.lower()
    exact = sorted(f for f in files if wanted in (f.lower(), f.lower().removesuffix(".csv")))
    hits = exact or sorted(f for f, name in files.items() if name.lower() == wanted)
    if not hits:
        fail("no such table", table=table, tables=names, **{k: common[k] for k in ("status", "complete")})
    if len(hits) > 1:
        fail("the table name matches more than one export file; name one of them", table=table, candidates=hits)
    chosen = files[hits[0]]
    # Tab-separated, whatever the extension says.
    src = str(export / hits[0])

    # A cell can be megabytes (a SRUM or WebCache blob): the reader's default field limit would stop on it.
    csv.field_size_limit(min(sys.maxsize, 2 ** 31 - 1))
    rows = LosslessPage("esedb_query", [path, table, hits[0], full], limit)
    with open(src, "r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.reader(fh, delimiter="\t")
        header = next(reader, [])
        # Two columns of one name would overwrite each other in a row; the later ones are numbered.
        names_seen, columns = {}, []
        for h in header:
            names_seen[h] = names_seen.get(h, 0) + 1
            columns.append(h if names_seen[h] == 1 else "%s_%d" % (h, names_seen[h]))
        renamed = [c for c, h in zip(columns, header) if c != h]
        ordinal = 0
        for row in reader:
            ordinal += 1
            cells = {columns[i] if i < len(columns) else "col%d" % i: v for i, v in enumerate(row)}
            rows.add({"_row": ordinal, **cells})
    page = rows.finish()
    print(json.dumps({
        **common,
        "table": chosen,
        "export_file": hits[0],
        "columns": header,
        "duplicate_columns_renamed": renamed,
        "rows": rows.page,
        "row_count": page["matched"],
        "row_ordinals": "_row is the 1-based position of the row in the exported table file",
        **page,
    }, indent=2))


if __name__ == "__main__":
    main()

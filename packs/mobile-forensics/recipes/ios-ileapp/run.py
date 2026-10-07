#!/usr/bin/env python3
"""A broad extraction of an iOS full file-system acquisition with iLEAPP.

The ios-filesystem recipe only inventories the tar: it reads headers and
parses no artefact content. This one hands the whole acquisition (a tar,
plain or compressed, or a zip) to iLEAPP, which runs its artefact modules
over it and writes a report per artefact: TSV files, a timeline database and
an HTML report. The TSVs and databases are the searchable form; they are
listed in index.tsv, and every file iLEAPP wrote is kept under ileapp/.

    run.py detect --target T [--probe-out DIR]   exit 0 applies, 1 does not
    run.py run --target T --out DIR

WHAT `complete` MEANS. iLEAPP exiting 0 with a TSV in its output says the
program ran and wrote something; it does not say that every module ran, and a
module that failed while others wrote their reports leaves the same trace. So
the run reads iLEAPP's own log (the stdout and stderr it keeps whole) for one
outcome per module, and writes them to modules.tsv (the text of a log line is
not copied into any of the run's files except as the kept log itself):

    completed      started, completed, and does not say it found nothing
    no_record      started, completed, and said "No file found" or "No data
                   found": it is never read as "the artefact is absent from the
                   phone", only as what that module found in this acquisition
    errored        the log says the module failed ("artifact failed after", or
                   "Reading <artefact> artifact had errors!")
    errors_logged  completed, and wrote lines that speak of an error (a module
                   that cannot read a table says so and completes)
    unknown        started, and the log does not say how it ended

The status is `complete` only when iLEAPP exited 0, wrote at least one TSV, the
log was recognised (at least one module started), every module is completed or
no_record, nothing printed a traceback on stderr, the number of modules started
is the number the log says it will parse, and the log ends with "Processes
completed.". An `unsupported` outcome is not something the log lines read here
show: a module that skips itself appears as completed or no_record. The log
shape is that of a real iLEAPP v2026.4.1 run; a release that logs differently
leaves every module unknown and the run partial, and the receipt says so.

A run that is stopped before its end leaves coverage.json saying partial, so
what it wrote is read as partial and never as complete. A run never writes over
an earlier run's output: if the output directory already holds ileapp/ or a
coverage.json, it refuses and leaves them as they are.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile

IOS_MARKERS = (
    "private/var/mobile/",
    "private/var/containers/",
    "system/library/coreservices/systemversion.plist",
)
NOT_COVERED = ("artefacts no module of the pinned iLEAPP release parses; deleted records beyond what a module reads "
               "itself (no carving); protected data that needs a key it does not have; archives nested inside the acquisition; "
               "a module the log does not account for as completed")

# --- the module receipt: held equal to the one in the Android recipe by a test ----------------------------
# The log lines a LEAPP program prints for each artefact module, as iLEAPP v2026.4.1 prints them:
#   [12/1139] name [module] artifact started at 09:29:44 UTC
#   Found 3 records for X | No file found | No data found for X     (what the module says it did)
#   name [module] artifact completed in 0.0s   |   name [module] artifact failed after 0.0s
#   Reading name artifact had errors!          (before a failure, with the module's own error text)
#   Artifact to parse: 1139   ...   Processes completed.
# A release that prints other lines leaves its modules unknown, and the run partial.
LOG_START = re.compile(r"^(?:\[\d+/(?P<total>\d+)\] )?(?P<name>.+?) \[(?P<module>[^\[\]]+)\] artifact started(?: at .+)?\s*$")
LOG_DONE = re.compile(r"^(?P<name>.+?) \[(?P<module>[^\[\]]+)\] artifact completed(?: in .+)?\s*$")
LOG_FAILED = re.compile(r"^(?P<name>.+?) \[(?P<module>[^\[\]]+)\] artifact failed(?: after .+)?\s*$")
LOG_ERROR = re.compile(r"^Reading (?P<name>.+?) artifact had errors!\s*$")
LOG_FOUND = re.compile(r"^Found (?P<n>\d+) records? for ")
LOG_NO_FILE = re.compile(r"^No files? found\s*$")
LOG_NO_DATA = re.compile(r"^No data found for ")
LOG_EXPECTED = re.compile(r"^Artifact to parse: (?P<n>\d+)\s*$")
LOG_PROBLEM = re.compile(r"\b(error|errors|exception|traceback|unable to|failed)\b", re.I)
LOG_LINE_BOUND = 4000
FIRST_UNATTRIBUTED = 20
STATUSES = ("completed", "no_record", "errored", "errors_logged", "unknown")


def tsv_escape(value):
    """One line, one field, nothing hidden: backslash, tab, newline, return and other controls escaped."""
    out = []
    for ch in str(value):
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


def read_log(path, source, events, facts):
    """Append (kind, artefact, module, source, line number, extra) for each module line of a kept log, and
    note what the log says about the run itself; count tracebacks. The text of a log line is never kept."""
    tracebacks = 0
    try:
        with open(path, "rb") as fh:
            for number, raw in enumerate(fh, 1):
                line = raw[:LOG_LINE_BOUND].decode("utf-8", "replace").rstrip("\r\n")
                found = LOG_START.match(line)
                if found:
                    events.append(("start", found.group("name"), found.group("module"), source, number, None))
                    if found.group("total"):
                        facts["total"] = int(found.group("total"))
                    continue
                found = LOG_DONE.match(line)
                if found:
                    events.append(("done", found.group("name"), found.group("module"), source, number, None))
                    continue
                found = LOG_FAILED.match(line)
                if found:
                    events.append(("failed", found.group("name"), found.group("module"), source, number, None))
                    continue
                found = LOG_ERROR.match(line)
                if found:
                    events.append(("error", found.group("name"), None, source, number, None))
                    continue
                found = LOG_FOUND.match(line)
                if found:
                    events.append(("found", None, None, source, number, int(found.group("n"))))
                    continue
                if LOG_NO_FILE.match(line):
                    events.append(("nofile", None, None, source, number, None))
                    continue
                if LOG_NO_DATA.match(line):
                    events.append(("nodata", None, None, source, number, None))
                    continue
                found = LOG_EXPECTED.match(line)
                if found:
                    facts["expected"] = int(found.group("n"))
                    continue
                if line.startswith("Processes completed."):
                    facts["end"] = True
                    continue
                if line.startswith("Traceback (most recent call last):"):
                    tracebacks += 1
                if LOG_PROBLEM.search(line):
                    events.append(("problem", None, None, source, number, None))
    except OSError:
        pass
    return tracebacks


def receipt(events):
    """One row per module the log names, in the order they started, and what could not be attributed.

    A module's lines are those between its start and its completed or failed line. errored: the log says
    it failed. errors_logged: it completed, and wrote lines that speak of an error (a module that could
    not read a table says so and completes). no_record: it completed and said it found no file, or no
    data. completed: it completed and does not say it found nothing. unknown: it started and the log
    does not say how it ended.
    """
    order, modules, current, unattributed = [], {}, None, []
    for kind, name, module, source, line, extra in events:
        if kind == "start":
            key = (module, name)
            if key not in modules:
                modules[key] = {"artefact": name, "module": module, "state": "started", "log": source, "line": line,
                                "records": 0, "nofile": False, "nodata": False, "notes": 0, "errored": False}
                order.append(key)
            elif modules[key]["state"] in ("done", "failed"):
                modules[key]["state"] = "started"        # started again: an error already seen stays
            current = key
        elif kind in ("done", "failed"):
            row = modules.get((module, name))
            if row is None:
                unattributed.append({"what": "a %s line with no start" % ("completed" if kind == "done" else "failed"), "artefact": name, "log": source, "line": line})
                continue
            row["state"] = "done" if kind == "done" else "failed"
            if kind == "failed":
                row["errored"] = True
            current = None
        elif kind == "error":
            key = current if current is not None and modules[current]["artefact"] == name else None
            if key is None:
                for candidate in reversed(order):
                    if modules[candidate]["artefact"] == name:
                        key = candidate
                        break
            if key is None:
                unattributed.append({"what": "an error line for an artefact that never started", "artefact": name, "log": source, "line": line})
            else:
                modules[key]["errored"] = True
                modules[key]["error_log"], modules[key]["error_line"] = source, line
        elif current is not None:
            row = modules[current]
            if kind == "found":
                row["records"] += extra
            elif kind == "nofile":
                row["nofile"] = True
            elif kind == "nodata":
                row["nodata"] = True
            elif kind == "problem":
                row["notes"] += 1
    rows = []
    for key in order:
        row = modules[key]
        if row["errored"]:
            status = "errored"
        elif row["state"] != "done":
            status = "unknown"
        elif row["notes"]:
            status = "errors_logged"
        elif row["records"] == 0 and (row["nofile"] or row["nodata"]):
            status = "no_record"
        else:
            status = "completed"
        rows.append({**row, "status": status, "reason": ("no source file" if row["nofile"] else "no data") if status == "no_record" else None})
    counts = {name: 0 for name in STATUSES}
    for row in rows:
        counts[row["status"]] += 1
    return rows, counts, unattributed


def write_modules(out, rows):
    with open(os.path.join(out, "modules.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write("n\tstatus\tartefact\tmodule\trecords\tlogged_error_lines\tlog\tline\n")
        for n, row in enumerate(rows):
            handle.write("%d\t%s\t%s\t%s\t%d\t%d\t%s\t%d\n" % (n, row["status"], tsv_escape(row["artefact"]), tsv_escape(row["module"]),
                                                              row["records"], row["notes"], row["log"], row["line"]))
# --- end of the module receipt -------------------------------------------------------------------------


def target_of(value):
    text = open(value, encoding="utf-8").read() if os.path.isfile(value) else value
    target = json.loads(text)
    paths = target.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


def tar_mode(path):
    """A compressed tar by its magic, in stream mode; a plain one header to
    header (tarfile's "r:*" tries every decompressor and the LZMA one reads a
    run of zeros as a stream)."""
    with open(path, "rb") as fh:
        head = fh.read(6)
    if head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00":
        return "r|*"
    return "r:"


def ios_name(name):
    low = name.lower()
    return any(marker in low for marker in IOS_MARKERS)


def zip_signature(path):
    """A zip by its own signature (a local file header, or the end record of an empty one), not by
    zipfile.is_zipfile, whose answer changed between Python 3.11 and 3.14 for an archive whose
    end-of-central-directory record is damaged: dispatch does not depend on a library's verdict. A file
    that does not start so is still a zip when zipfile opens it (data before the first header, as in a
    self-extracting archive); that can only add a zip, never refuse one."""
    with open(path, "rb") as fh:
        if fh.read(4) in (b"PK\x03\x04", b"PK\x05\x06"):
            return True
    try:
        with zipfile.ZipFile(path):
            return True
    except (zipfile.BadZipFile, OSError):
        return False


def detect(path):
    """(applies, why, kind): kind is iLEAPP's input type, tar or zip."""
    if not os.path.isfile(path):
        return False, "not a readable file", None
    try:
        is_zip = zip_signature(path)
    except OSError as exc:
        return False, "not a readable file: %s" % (exc.strerror or exc), None
    if is_zip:
        try:
            with zipfile.ZipFile(path) as archive:
                for name in archive.namelist():
                    if ios_name(name):
                        return True, "zip members have an iOS full file-system root", "zip"
        except (zipfile.BadZipFile, OSError) as exc:
            return False, "not a readable zip: %s" % exc, None
        return False, "zip has no iOS full file-system marker", None
    try:
        with tarfile.open(path, tar_mode(path)) as archive:
            for member in archive:
                if ios_name(member.name):
                    return True, "tar members have an iOS full file-system root", "tar"
                archive.members = []
    except (tarfile.TarError, OSError, EOFError) as exc:
        return False, "not a readable tar or zip: %s" % exc, None
    return False, "tar has no iOS full file-system marker", None


def write_coverage(out, status, covered, errors, limits=(), **more):
    with open(os.path.join(out, "coverage.json"), "w", encoding="utf-8") as handle:
        json.dump({"recipe": "ios-ileapp", "status": status, "covered": covered, "not_covered": NOT_COVERED,
                   "limits_hit": list(limits), "errors": list(errors), **more}, handle, indent=2, sort_keys=True)
        handle.write("\n")


def program():
    for name in ("ileapp", "ileapp.py"):
        found = shutil.which(name)
        if found:
            return os.path.abspath(found)
    return None


def index(out, report):
    """Every TSV and database iLEAPP wrote, one row each, relative to out/."""
    rows = []
    for dirpath, dirs, files in os.walk(report):
        dirs.sort()
        for name in sorted(files):
            low = name.lower()
            rel = os.path.relpath(os.path.join(dirpath, name), out)
            if low.endswith(".tsv"):
                rows.append((rel, "iLEAPP artefact report %s (TSV, one row per record)" % name[:-4]))
            elif low.endswith((".db", ".sqlite")):
                rows.append((rel, "iLEAPP database %s (SQLite: the timeline, or every artefact's rows)" % name))
            elif low.endswith(".kml"):
                rows.append((rel, "iLEAPP locations %s (KML)" % name))
    return rows


def write_index(out, rows):
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        for rel, what in rows:
            handle.write("%s\t%s\n" % (rel.replace("\t", " "), what))
        handle.write("modules.tsv\tone row per module the iLEAPP log names: completed, no_record, errored, errors_logged or unknown, with the records it reports and the log line\n")


def child_files(directory):
    """How many files and links a program left in a directory this recipe gave it: kept, never deleted."""
    count = 0
    for _dirpath, dirs, files in os.walk(directory):
        count += len(files) + sum(1 for d in dirs if os.path.islink(os.path.join(_dirpath, d)))
    return count


def run(path, kind, out):
    out = os.path.abspath(out)       # the program runs from a directory under out: nothing here may be relative
    report = os.path.join(out, "ileapp")
    if os.path.lexists(report) or os.path.lexists(os.path.join(out, "coverage.json")):
        # Before anything is written: an earlier run's coverage and report stay as they are.
        print(json.dumps({"ok": False, "status": "refused", "why": "the output directory already holds ileapp/ or coverage.json: the recipe does not write over an earlier run"}))
        return 2
    os.makedirs(out, exist_ok=True)
    # Said before iLEAPP starts: a run stopped at its limit leaves this, and is read as partial.
    write_coverage(out, "partial", "started; iLEAPP did not finish (stopped before its end)", ["the run ended before iLEAPP did"])
    prog = program()
    if not prog:
        write_coverage(out, "failed", "nothing: iLEAPP is not in this image", ["ileapp is not on PATH in this job image"])
        return 1
    path = os.path.abspath(path)
    scratch = os.path.join(out, "ileapp-run")
    # The run directory is read-only in a job: the program's working directory and its temporary files
    # are under the output, and every file it leaves there is kept and counted.
    cwd = os.path.join(out, "ileapp-cwd")
    temp = os.path.join(out, "ileapp-tmp")
    for directory in (scratch, cwd, temp):
        os.makedirs(directory, exist_ok=True)
    env = dict(os.environ, TMPDIR=temp)
    with open(os.path.join(out, "ileapp.stdout"), "wb") as so, open(os.path.join(out, "ileapp.stderr"), "wb") as se:
        rc = subprocess.run([prog, "-t", kind, "-i", path, "-o", scratch], stdout=so, stderr=se, cwd=cwd, env=env).returncode
    made = [d for d in sorted(os.listdir(scratch)) if os.path.isdir(os.path.join(scratch, d)) and not os.path.islink(os.path.join(scratch, d))]
    layout, siblings = "whole output directory", False
    if len(made) == 1:
        os.rename(os.path.join(scratch, made[0]), report)
        left = sorted(os.listdir(scratch))
        if left:
            # Files the program wrote beside its report folder are kept, whole, in a directory of their own.
            os.rename(scratch, os.path.join(out, "ileapp-run-files"))
            siblings = True
            layout = "one report folder; %d file(s) beside it kept in ileapp-run-files/" % len(left)
        else:
            os.rmdir(scratch)
            layout = "one report folder"
    else:
        os.rename(scratch, report)
    kept = {}
    for name, directory in (("ileapp-cwd", cwd), ("ileapp-tmp", temp)):
        files = child_files(directory)
        if files:
            kept[name] = files
        else:
            for dirpath, _dirs, _files in os.walk(directory, topdown=False):
                try:
                    os.rmdir(dirpath)
                except OSError:
                    pass
    rows = index(out, report)
    tsvs = sum(1 for rel, _ in rows if rel.lower().endswith(".tsv"))

    events, facts = [], {}
    read_log(os.path.join(out, "ileapp.stdout"), "ileapp.stdout", events, facts)
    tracebacks = read_log(os.path.join(out, "ileapp.stderr"), "ileapp.stderr", events, {})
    modules, counts, unattributed = receipt(events)
    write_modules(out, modules)
    write_index(out, rows)
    recognised = bool(modules)
    receipt_json = {"log_format_recognised": recognised, "counts": counts, "modules_listed_in": "modules.tsv",
                    "records_reported_by_modules": sum(m["records"] for m in modules),
                    "modules_the_log_says_it_will_parse": facts.get("expected", facts.get("total")),
                    "log_says_processing_completed": bool(facts.get("end")),
                    "unsupported": "not observable in the log lines read: a module that skipped itself appears as completed or no_record",
                    "tracebacks_on_stderr": tracebacks, "unattributed_log_lines": unattributed[:FIRST_UNATTRIBUTED],
                    "report_layout": layout, **({"files_beside_the_report": "ileapp-run-files/"} if siblings else {}),
                    **({"files_left_in_program_directories": kept} if kept else {})}
    errors = [] if rc == 0 else ["iLEAPP exited %d; its output is kept whole in ileapp.stdout and ileapp.stderr" % rc]
    problems = []
    named = lambda status: [m["artefact"] for m in modules if m["status"] == status][:5]
    if counts["errored"]:
        problems.append("%d module(s) errored: %s%s; see modules.tsv and ileapp.stdout" % (counts["errored"], ", ".join(named("errored")), " and others" if counts["errored"] > 5 else ""))
    if counts["errors_logged"]:
        problems.append("%d module(s) completed but logged error lines: %s%s; see modules.tsv and ileapp.stdout" % (counts["errors_logged"], ", ".join(named("errors_logged")), " and others" if counts["errors_logged"] > 5 else ""))
    if counts["unknown"]:
        problems.append("%d module(s) started and the log says nothing more about them" % counts["unknown"])
    if tracebacks:
        problems.append("%d traceback(s) on stderr" % tracebacks)
    if unattributed:
        problems.append("%d log line(s) about a module that did not start" % len(unattributed))
    expected = facts.get("expected", facts.get("total"))
    if recognised and expected is not None and len(modules) != expected:
        problems.append("the log says %d modules would be parsed and %d started" % (expected, len(modules)))
    if recognised and expected is not None and not facts.get("end"):
        problems.append("the log does not end with its processing-completed line")
    if rc == 0 and tsvs and not recognised:
        problems.append("the log has no module lines this recipe reads: per-module outcome is unknown for all of them")
    if rc == 0 and tsvs and not problems:
        write_coverage(out, "complete", "iLEAPP exited 0 over the %s and its log accounts for %d module(s): %d completed, %d with no record (no source file or no data); %d TSV report(s)"
                       % (kind, len(modules), counts["completed"], counts["no_record"], tsvs), errors, modules=receipt_json)
    elif rows:
        write_coverage(out, "partial", "iLEAPP wrote %d report(s); %d module(s) in its log: %d completed, %d no_record, %d errored, %d errors_logged, %d unknown"
                       % (len(rows), len(modules), counts["completed"], counts["no_record"], counts["errored"], counts["errors_logged"], counts["unknown"]),
                       (errors + problems) or ["iLEAPP wrote no TSV report"], modules=receipt_json)
    else:
        write_coverage(out, "failed", "nothing parsed", (errors + problems) or ["iLEAPP wrote no report"], modules=receipt_json)
    return 0 if rc == 0 else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    # The census asks every detect step with --probe-out DIR; detect keeps nothing there.
    parser.add_argument("--probe-out")
    args = parser.parse_args()
    try:
        _, path = target_of(args.target)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    applies, why, kind = detect(path)
    if args.command == "detect":
        print(json.dumps({"applies": applies, "why": why}))
        return 0 if applies else 1
    if not args.out:
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    if not applies:
        print(json.dumps({"ok": False, "status": "unsupported", "why": why}))
        return 2
    rc = run(path, kind, args.out)
    if rc == 2:
        return rc
    status = json.load(open(os.path.join(os.path.abspath(args.out), "coverage.json"), encoding="utf-8")).get("status")
    print(json.dumps({"ok": rc == 0, "status": status}))
    return rc


if __name__ == "__main__":
    sys.exit(main())

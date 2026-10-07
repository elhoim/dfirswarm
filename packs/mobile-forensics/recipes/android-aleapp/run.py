#!/usr/bin/env python3
"""A broad extraction of an Android full file-system acquisition with ALEAPP.

The pack's other Android recipe reads an adb backup's header and member list;
nothing parses a full file-system acquisition's artefacts until an agent
does. This one hands the whole acquisition (a tar, plain or compressed, or a
zip, whose members hold an Android userdata root) to ALEAPP, which runs its
artefact modules over it and writes a report per artefact: TSV files, a
timeline database and an HTML report. The TSVs and databases are the
searchable form; they are listed in index.tsv, and every file ALEAPP wrote is
kept under aleapp/.

    run.py detect --target T [--probe-out DIR]   exit 0 applies, 1 does not
    run.py run --target T --out DIR

WHAT `complete` MEANS. ALEAPP exiting 0 with a TSV in its output says the
program ran and wrote something; it does not say that every module ran, and a
module that failed while others wrote their reports leaves the same trace. So
the run reads ALEAPP's own log (the stdout and stderr it keeps whole) for one
outcome per module, and writes them to modules.tsv:

    completed   the log says the module started and completed, and a TSV named
                for the artefact was written
    no_record   it started and completed and no TSV named for the artefact was
                written: no records parsed, or a report named otherwise. It is
                never read as "the artefact is absent from the phone"
    errored     the log says "Reading <artefact> artifact had errors!"
    unknown     it started and the log says nothing more (the program ended, or
                printed something this reader does not know)

The status is `complete` only when ALEAPP exited 0, wrote at least one TSV, the
log was recognised (at least one module started) and no module is errored or
unknown and nothing printed a traceback on stderr. An `unsupported` outcome (a
module that skips a release or an acquisition it cannot read) is not something
the log lines read here show: it is not counted, and a module that skipped
itself appears as completed or no_record. A release that logs differently
leaves every module unknown and the run partial, and the receipt says so.

A run that is stopped before its end leaves coverage.json saying partial, so
what it wrote is read as partial and never as complete.
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

ANDROID_MARKERS = (
    "data/system/packages.xml",
    "data/system/packages.list",
    "data/data/com.android.providers.",
    "data/user_de/0/com.android.",
)
NOT_COVERED = ("artefacts no module of the pinned ALEAPP release parses; deleted records beyond what a module reads "
               "itself (no carving); protected data that needs a key it does not have (file-based encryption without "
               "its keys); archives nested inside the acquisition; a module the log does not account for as completed")

# --- the module receipt: held equal to the one in the iOS recipe by a test ----------------------------
# The log lines a LEAPP program is expected to print for each artefact module; a release that prints other lines leaves its modules unknown.
LOG_START = re.compile(r"^(?P<name>.+?) \[(?P<module>[^\[\]]+)\] artifact started\s*$")
LOG_DONE = re.compile(r"^(?P<name>.+?) \[(?P<module>[^\[\]]+)\] artifact completed\s*$")
LOG_ERROR = re.compile(r"^Reading (?P<name>.+?) artifact had errors!\s*$")
LOG_LINE_BOUND = 4000
FIRST_UNATTRIBUTED = 20


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


def normal(name):
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def read_log(path, source, events):
    """Append (kind, artefact, module, source, line number) for each module line of a kept log; count tracebacks."""
    tracebacks = 0
    try:
        with open(path, "rb") as fh:
            for number, raw in enumerate(fh, 1):
                line = raw[:LOG_LINE_BOUND].decode("utf-8", "replace").rstrip("\r\n")
                found = LOG_START.match(line)
                if found:
                    events.append(("start", found.group("name"), found.group("module"), source, number))
                    continue
                found = LOG_DONE.match(line)
                if found:
                    events.append(("done", found.group("name"), found.group("module"), source, number))
                    continue
                found = LOG_ERROR.match(line)
                if found:
                    events.append(("error", found.group("name"), None, source, number))
                    continue
                if line.startswith("Traceback (most recent call last):"):
                    tracebacks += 1
    except OSError:
        pass
    return tracebacks


def receipt(events, reports):
    """One row per module the log names, in the order they started, and what could not be attributed.

    `reports` is the list of TSV file names written (relative paths): a module is `completed` only when one
    of them is named for its artefact.
    """
    order, modules, last, unattributed = [], {}, None, []
    for kind, name, module, source, line in events:
        if kind == "start":
            key = (module, name)
            if key not in modules:
                modules[key] = {"artefact": name, "module": module, "state": "started", "log": source, "line": line}
                order.append(key)
            else:
                modules[key]["state"] = "started"
            last = key
        elif kind == "done":
            row = modules.get((module, name))
            if row is None:
                unattributed.append({"what": "a completion line with no start", "artefact": name, "log": source, "line": line})
            elif row["state"] != "errored":
                row["state"] = "done"
        else:
            key = last if last is not None and modules[last]["artefact"] == name else None
            if key is None:
                for candidate in reversed(order):
                    if modules[candidate]["artefact"] == name:
                        key = candidate
                        break
            if key is None:
                unattributed.append({"what": "an error line for an artefact that never started", "artefact": name, "log": source, "line": line})
            else:
                modules[key]["state"] = "errored"
                modules[key]["error_log"], modules[key]["error_line"] = source, line
    names = [(normal(os.path.splitext(os.path.basename(r))[0]), r) for r in reports]
    rows = []
    for key in order:
        row = modules[key]
        wanted = normal(row["artefact"])
        report = next((r for n, r in names if wanted and (n == wanted or n.startswith(wanted))), None)
        if row["state"] == "errored":
            status = "errored"
        elif row["state"] == "done":
            status = "completed" if report else "no_record"
        else:
            status = "unknown"
        rows.append({**row, "status": status, "report": report if status == "completed" else None})
    counts = {"completed": 0, "no_record": 0, "errored": 0, "unknown": 0}
    for row in rows:
        counts[row["status"]] += 1
    return rows, counts, unattributed


def write_modules(out, rows):
    with open(os.path.join(out, "modules.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write("n\tstatus\tartefact\tmodule\treport\tlog\tline\n")
        for n, row in enumerate(rows):
            handle.write("%d\t%s\t%s\t%s\t%s\t%s\t%d\n" % (n, row["status"], tsv_escape(row["artefact"]), tsv_escape(row["module"]),
                                                          tsv_escape(row["report"] or ""), row["log"], row["line"]))
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


def android_name(name):
    low = name.lower()
    return any(marker in low for marker in ANDROID_MARKERS)


def zip_signature(path):
    """A zip by its own signature (a local file header, or the end record of an empty one), not by
    zipfile.is_zipfile, whose answer changed between Python 3.11 and 3.14 for an archive whose
    end-of-central-directory record is damaged: dispatch does not depend on a library's verdict."""
    with open(path, "rb") as fh:
        return fh.read(4) in (b"PK\x03\x04", b"PK\x05\x06")


def detect(path):
    """(applies, why, kind): kind is ALEAPP's input type, tar or zip."""
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
                    if android_name(name):
                        return True, "zip members have an Android userdata root", "zip"
        except (zipfile.BadZipFile, OSError) as exc:
            return False, "not a readable zip: %s" % exc, None
        return False, "zip has no Android userdata marker", None
    try:
        with tarfile.open(path, tar_mode(path)) as archive:
            for member in archive:
                if android_name(member.name):
                    return True, "tar members have an Android userdata root", "tar"
                archive.members = []
    except (tarfile.TarError, OSError, EOFError) as exc:
        return False, "not a readable tar or zip: %s" % exc, None
    return False, "tar has no Android userdata marker", None


def write_coverage(out, status, covered, errors, limits=(), **more):
    with open(os.path.join(out, "coverage.json"), "w", encoding="utf-8") as handle:
        json.dump({"recipe": "android-aleapp", "status": status, "covered": covered, "not_covered": NOT_COVERED,
                   "limits_hit": list(limits), "errors": list(errors), **more}, handle, indent=2, sort_keys=True)
        handle.write("\n")


def program():
    for name in ("aleapp", "aleapp.py"):
        found = shutil.which(name)
        if found:
            return os.path.abspath(found)
    return None


def index(out, report):
    """Every TSV and database ALEAPP wrote, one row each, relative to out/."""
    rows = []
    for dirpath, dirs, files in os.walk(report):
        dirs.sort()
        for name in sorted(files):
            low = name.lower()
            rel = os.path.relpath(os.path.join(dirpath, name), out)
            if low.endswith(".tsv"):
                rows.append((rel, "ALEAPP artefact report %s (TSV, one row per record)" % name[:-4]))
            elif low.endswith((".db", ".sqlite")):
                rows.append((rel, "ALEAPP database %s (SQLite: the timeline, or every artefact's rows)" % name))
            elif low.endswith(".kml"):
                rows.append((rel, "ALEAPP locations %s (KML)" % name))
    return rows


def write_index(out, rows):
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        for rel, what in rows:
            handle.write("%s\t%s\n" % (rel.replace("\t", " "), what))
        handle.write("modules.tsv\tone row per module the ALEAPP log names: completed, no_record, errored or unknown, with the log line\n")


def child_files(directory):
    """How many files a program left in a directory this recipe gave it: kept, never deleted."""
    return sum(len(files) for _dirpath, _dirs, files in os.walk(directory))


def run(path, kind, out):
    os.makedirs(out, exist_ok=True)
    # Said before ALEAPP starts: a run stopped at its limit leaves this, and is read as partial.
    write_coverage(out, "partial", "started; ALEAPP did not finish (stopped before its end)", ["the run ended before ALEAPP did"])
    prog = program()
    if not prog:
        write_coverage(out, "failed", "nothing: ALEAPP is not in this image", ["aleapp is not on PATH in this job image"])
        return 1
    report = os.path.join(out, "aleapp")
    if os.path.lexists(report):
        write_coverage(out, "failed", "nothing: the output directory already holds aleapp/",
                       ["aleapp/ exists: the recipe does not write over an earlier run's report"])
        return 1
    path = os.path.abspath(path)
    scratch = os.path.join(out, "aleapp-run")
    # The run directory is read-only in a job: the program's working directory and its temporary files
    # are under the output, and every file it leaves there is kept and counted.
    cwd = os.path.join(out, "aleapp-cwd")
    temp = os.path.join(out, "aleapp-tmp")
    for directory in (scratch, cwd, temp):
        os.makedirs(directory, exist_ok=True)
    env = dict(os.environ, TMPDIR=temp)
    with open(os.path.join(out, "aleapp.stdout"), "wb") as so, open(os.path.join(out, "aleapp.stderr"), "wb") as se:
        rc = subprocess.run([prog, "-t", kind, "-i", path, "-o", scratch], stdout=so, stderr=se, cwd=cwd, env=env).returncode
    made = [d for d in sorted(os.listdir(scratch)) if os.path.isdir(os.path.join(scratch, d))]
    layout, siblings = "whole output directory", False
    if len(made) == 1:
        os.rename(os.path.join(scratch, made[0]), report)
        left = sorted(os.listdir(scratch))
        if left:
            # Files the program wrote beside its report folder are kept, whole, in a directory of their own.
            os.rename(scratch, os.path.join(out, "aleapp-run-files"))
            siblings = True
            layout = "one report folder; %d file(s) beside it kept in aleapp-run-files/" % len(left)
        else:
            os.rmdir(scratch)
            layout = "one report folder"
    else:
        os.rename(scratch, report)
    kept = {}
    for name, directory in (("aleapp-cwd", cwd), ("aleapp-tmp", temp)):
        files = child_files(directory)
        if files:
            kept[name] = files
        else:
            for dirpath, _dirs, _files in os.walk(directory, topdown=False):
                os.rmdir(dirpath)
    rows = index(out, report)
    tsv_names = [rel for rel, _ in rows if rel.lower().endswith(".tsv")]
    tsvs = len(tsv_names)

    events = []
    read_log(os.path.join(out, "aleapp.stdout"), "aleapp.stdout", events)
    tracebacks = read_log(os.path.join(out, "aleapp.stderr"), "aleapp.stderr", events)
    modules, counts, unattributed = receipt(events, tsv_names)
    write_modules(out, modules)
    write_index(out, rows)
    recognised = bool(modules)
    receipt_json = {"log_format_recognised": recognised, "counts": counts, "modules_listed_in": "modules.tsv",
                    "unsupported": "not observable in the log lines read: a module that skipped itself appears as completed or no_record",
                    "tracebacks_on_stderr": tracebacks, "unattributed_log_lines": unattributed[:FIRST_UNATTRIBUTED],
                    "report_layout": layout, **({"files_beside_the_report": "aleapp-run-files/"} if siblings else {}),
                    **({"files_left_in_program_directories": kept} if kept else {})}
    errors = [] if rc == 0 else ["ALEAPP exited %d; its output is kept whole in aleapp.stdout and aleapp.stderr" % rc]
    problems = []
    if counts["errored"]:
        first = [m["artefact"] for m in modules if m["status"] == "errored"][:5]
        problems.append("%d module(s) errored: %s%s; see modules.tsv and aleapp.stdout" % (counts["errored"], ", ".join(first), " and others" if counts["errored"] > 5 else ""))
    if counts["unknown"]:
        problems.append("%d module(s) started and the log says nothing more about them" % counts["unknown"])
    if tracebacks:
        problems.append("%d traceback(s) on stderr" % tracebacks)
    if unattributed:
        problems.append("%d log line(s) about a module that did not start" % len(unattributed))
    if rc == 0 and tsvs and not recognised:
        problems.append("the log has no module lines this recipe reads: per-module outcome is unknown for all of them")
    if rc == 0 and tsvs and not problems:
        write_coverage(out, "complete", "ALEAPP exited 0 over the %s and its log accounts for %d module(s): %d completed with a report, %d completed with no report named for them; %d TSV report(s)"
                       % (kind, len(modules), counts["completed"], counts["no_record"], tsvs), errors, modules=receipt_json)
    elif rows:
        write_coverage(out, "partial", "ALEAPP wrote %d report(s); %d module(s) in its log: %d completed, %d no_record, %d errored, %d unknown"
                       % (len(rows), len(modules), counts["completed"], counts["no_record"], counts["errored"], counts["unknown"]),
                       (errors + problems) or ["ALEAPP wrote no TSV report"], modules=receipt_json)
    else:
        write_coverage(out, "failed", "nothing parsed", errors or ["ALEAPP wrote no report"], modules=receipt_json)
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
    status = json.load(open(os.path.join(args.out, "coverage.json"), encoding="utf-8")).get("status")
    print(json.dumps({"ok": rc == 0, "status": status}))
    return rc


if __name__ == "__main__":
    sys.exit(main())

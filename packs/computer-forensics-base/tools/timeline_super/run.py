#!/usr/bin/env python3
"""Build a super timeline with Plaso, and hand back something a swarm can read.

Our own timeline is the ledger: facts an agent decided were worth recording,
each with a citation. Plaso's is the opposite and the two are complementary:
what the enabled parsers produced from the sources they could read, with no
judgement applied. An examiner wants both: the machine timeline to find the
window, the ledger to say what happened in it. It is not every timestamp on the
volume: a parser that is not enabled, a source it could not open and a record
it could not read add no row.

Two things this wrapper exists to enforce.

The first is the parser filter. A default log2timeline run over a 60 GB image
takes hours and returns tens of millions of events, most of them filestat
noise. Naming the parsers you actually need turns that into minutes, and the
output says which filter produced it so a reviewer can repeat it.

The second is the timezone. Plaso writes UTC, but it needs the evidence
machine's own zone to interpret the formats that store local time. Getting it
wrong shifts a whole class of artefacts and nothing in the output says so,
which is why the zone given is returned with the result.

What it reports, so that a failed run cannot look like a normal one: each
stage's exit code, a status (complete: both programs exited 0 and wrote their
files and every line parsed; partial: something ran and something did not;
failed: nothing usable), the versions the programs print, how many output lines
parsed and how many did not (with where), and that `complete` says the programs
finished, not that every parser read every source (the storage file's own
processing report, read with Plaso's pinfo, says what each parser did).

`mode: export` runs only psort, over a storage file that already exists, so a
new filter does not collect the evidence again. The default, `full`, runs
log2timeline then psort and refuses an out_dir that already holds files unless
`resume` is true, in which case only files written after the run began count.
Each program writes its log to out_dir (--logfile), its stdout and stderr to
files there, and runs from out_dir: the run's own directory is read-only in an
agent's VM and in a job's worker.
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

TOOL = {"name": "timeline_super", "version": 4}
DEFAULT_TIMEOUT = 1800
VERSION_TIMEOUT = 20
LINE_MAX = 8 * 1024 * 1024        # a line past this is counted invalid, its tail skipped; the file keeps it whole
MESSAGE_PREVIEW = 2000
INVALID_LISTED = 1000


def emit(obj, code=0):
    print(json.dumps(obj, indent=2))
    raise SystemExit(code)


def fail(message, **extra):
    print(json.dumps({"error": message, "tool": TOOL, **extra}))
    raise SystemExit(1)


def resolve_output(out):
    """Where `out` really lands, refusing anything outside the run directory.

    A string check is not enough: `work/../inputs/x` and an absolute path
    both name a file the tool must not write, and neither starts with
    "inputs/". Resolving first and comparing directories is what actually
    holds, and the read-only inputs are the one place extracted bytes must
    never appear -- a later integrity check would report the evidence as
    modified.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest != root and root not in dest.parents:
        fail("output must stay inside the run directory", output=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("output cannot be under inputs/", output=str(out))
    return dest


def readable(stamp):
    """Plaso writes microseconds since the epoch; an examiner reads ISO 8601 UTC."""
    if stamp is None:
        return None
    if isinstance(stamp, str):
        return stamp
    try:
        micro = int(stamp)
        whole, frac = divmod(micro, 1_000_000)
        text = datetime.fromtimestamp(whole, timezone.utc).isoformat().replace("+00:00", "")
        return text + ("." + "%06d" % frac if frac else "") + "Z"
    except (ValueError, OverflowError, OSError, TypeError):
        return str(stamp)


class Stage:
    """One program run: its command, its exit, how long, and where its words went."""

    def __init__(self, name, argv, out_dir):
        self.name, self.argv, self.out_dir = name, argv, out_dir
        self.exit = None
        self.timed_out = False
        self.seconds = None
        self.stdout_file = os.path.join(out_dir, name + ".stdout")
        self.stderr_file = os.path.join(out_dir, name + ".stderr")

    def run(self, deadline):
        started = time.monotonic()
        budget = deadline - started
        if budget <= 0:
            self.exit, self.timed_out, self.seconds = None, True, 0
            return self
        with open(self.stdout_file, "wb") as so, open(self.stderr_file, "wb") as se:
            proc = subprocess.Popen(self.argv, stdout=so, stderr=se, cwd=self.out_dir, start_new_session=True)
            try:
                self.exit = proc.wait(timeout=budget)
            except subprocess.TimeoutExpired:
                self.timed_out = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    proc.kill()
                proc.wait()
                self.exit = None
        self.seconds = round(time.monotonic() - started, 1)
        return self

    def record(self):
        rec = {"command": " ".join(self.argv), "exit": self.exit, "seconds": self.seconds,
               "stdout": self.stdout_file, "stderr": self.stderr_file}
        if self.timed_out:
            rec["timed_out"] = True
        return rec


def version_of(program, out_dir):
    try:
        p = subprocess.run([program, "--version"], capture_output=True, text=True, timeout=VERSION_TIMEOUT, cwd=out_dir)
    except (subprocess.TimeoutExpired, OSError):
        return None
    text = ((p.stdout or "") + (p.stderr or "")).strip().splitlines()
    return text[0][:200] if text else None


def summarise(output, sample, out_dir):
    """Valid and invalid lines of psort's JSON Lines, read line by line with a cap on
    a line's size, so a hostile line cannot fill memory and a bad one is not a count."""
    events = invalid = oversized = 0
    first_event = last_event = None
    parsers_seen, head, bad = {}, [], []
    invalid_path = os.path.join(out_dir, "timeline.invalid_lines.txt")
    with open(output, "rb") as fh:
        number, offset = 0, 0
        while True:
            line = fh.readline(LINE_MAX + 1)
            if not line:
                break
            start = offset
            number += 1
            if len(line) > LINE_MAX and not line.endswith(b"\n"):
                rest = 0
                while True:
                    chunk = fh.readline(LINE_MAX)
                    rest += len(chunk)
                    if not chunk or chunk.endswith(b"\n"):
                        break
                offset += len(line) + rest
                oversized += 1
                invalid += 1
                if len(bad) < INVALID_LISTED:
                    bad.append((number, start, len(line) + rest, "longer than %d bytes: not parsed" % LINE_MAX, line[:200]))
                continue
            offset += len(line)
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text.decode("utf-8", "replace"))
                if not isinstance(row, dict):
                    raise ValueError("not a JSON object")
            except ValueError as exc:
                invalid += 1
                if len(bad) < INVALID_LISTED:
                    bad.append((number, start, len(line), str(exc), text[:200]))
                continue
            events += 1
            stamp = readable(row.get("datetime") or row.get("timestamp"))
            if stamp is not None:
                if first_event is None:
                    first_event = stamp
                last_event = stamp
            name = row.get("parser") or row.get("data_type") or "unknown"
            parsers_seen[name] = parsers_seen.get(name, 0) + 1
            if len(head) < sample:
                entry = {k: row.get(k) for k in ("timestamp_desc", "parser", "data_type", "display_name") if row.get(k) is not None}
                entry["datetime"] = stamp
                msg = str(row.get("message") or "")
                entry["message"] = msg[:MESSAGE_PREVIEW]
                if len(msg) > MESSAGE_PREVIEW:
                    entry["message_length"] = len(msg)
                    entry["message_note"] = "a preview: the whole line is line %d of the output file" % number
                head.append(entry)
    if bad:
        with open(invalid_path, "w", encoding="utf-8") as fh:
            fh.write("line\tbyte_offset\tbytes\treason\tfirst 200 bytes (the whole line stays in the output file)\n")
            for n, off, size, why, snippet in bad:
                fh.write("%d\t%d\t%d\t%s\t%s\n" % (n, off, size, why.replace("\t", " ").replace("\n", " "),
                                                   snippet.decode("utf-8", "replace").replace("\t", " ").replace("\n", " ")))
    return {"events": events, "invalid_lines": invalid, "oversized_lines": oversized, "first_event": first_event,
            "last_event": last_event, "parsers_seen": parsers_seen, "head": head,
            "invalid_lines_file": invalid_path if bad else None,
            "invalid_lines_listed": len(bad), "invalid_lines_listing_complete": len(bad) == invalid}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments are a JSON object")

    mode = args.get("mode", "full")
    if mode not in ("full", "export"):
        fail("mode is full (log2timeline then psort) or export (psort over an existing storage file)", mode=mode)
    resume = args.get("resume", False)
    if not isinstance(resume, bool):
        fail("resume is true or false")

    out_dir = args.get("out_dir")
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: a directory under work/ for the storage file and the output")
    dest = resolve_output(out_dir)

    source = args.get("source")
    storage_arg = args.get("storage_file")
    if mode == "full":
        if not isinstance(source, str) or not source:
            fail("source is required: an image, a partition or a collection directory")
        if not os.path.exists(source):
            fail("no such source", source=source)
        if storage_arg is not None:
            fail("storage_file is for mode export; mode full makes timeline.plaso in out_dir")
    else:
        if not isinstance(storage_arg, str) or not storage_arg:
            fail("mode export needs storage_file: the .plaso file psort should read")
        if not os.path.isfile(storage_arg):
            fail("no such storage file", storage_file=storage_arg)

    l2t = shutil.which("log2timeline.py") or shutil.which("log2timeline")
    psort = shutil.which("psort.py") or shutil.which("psort")
    needed = [("psort.py", psort)] + ([("log2timeline.py", l2t)] if mode == "full" else [])
    if any(not p for _, p in needed):
        fail("Plaso is not on PATH", missing=[n for n, p in needed if not p],
             install="python3 -m pip install plaso, or apt-get install -y plaso-tools")

    timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 30:
        fail("timeout_seconds must be an integer of at least 30")
    sample = args.get("sample", 20)
    if not isinstance(sample, int) or isinstance(sample, bool) or sample < 0:
        fail("sample must be a non-negative integer")

    began = time.time()
    deadline = time.monotonic() + timeout            # one budget for every stage
    preexisting = []
    if dest.exists():
        if not dest.is_dir():
            fail("out_dir is not a directory", out_dir=out_dir)
        preexisting = sorted(os.listdir(dest))
        if preexisting and not resume:
            fail("out_dir already holds files, and a file left by an earlier run would be taken for this one's: "
                 "give a new directory, or resume: true to write beside them (only files written after this run began count)",
                 out_dir=out_dir, holds=preexisting[:20])
    os.makedirs(dest, exist_ok=True)
    out_abs = str(dest)
    store = os.path.join(out_abs, "timeline.plaso") if mode == "full" else os.path.abspath(storage_arg)
    output = os.path.join(out_abs, "timeline.jsonl")
    for path in (output, os.path.join(out_abs, "timeline.plaso"), os.path.join(out_abs, "log2timeline.log.gz"), os.path.join(out_abs, "psort.log.gz")):
        if os.path.islink(path):
            fail("a link stands where this tool writes; it will not write through it", path=path)

    def fresh(path):
        try:
            return os.path.isfile(path) and os.stat(path).st_mtime >= began - 1
        except OSError:
            return False

    result = {"tool": TOOL, "mode": mode, "out_dir": out_abs, "storage_file": store, "output": output,
              "versions": {}, "stages": {}, "problems": []}
    if preexisting:
        result["preexisting"] = preexisting
    result["versions"]["psort"] = version_of(psort, out_abs)
    if mode == "full":
        result["source"] = source
        result["versions"]["log2timeline"] = version_of(l2t, out_abs)
        collect_log = os.path.join(out_abs, "log2timeline.log.gz")
        collect = [l2t, "--status_view", "none", "--logfile", collect_log, "--partitions", "all", "--volumes", "all", "--unattended", "--quiet"]
        if args.get("parsers"):
            collect += ["--parsers", str(args["parsers"])]
        if args.get("timezone"):
            collect += ["--timezone", str(args["timezone"])]
        collect += ["--storage_file", store, os.path.abspath(source)]
        stage = Stage("log2timeline", collect, out_abs).run(deadline)
        result["stages"]["collect"] = stage.record()
        result["collect_exit"] = stage.exit
        if stage.timed_out:
            result["problems"].append("log2timeline did not finish within the %ds budget; narrow it with parsers" % timeout)
        elif stage.exit != 0:
            result["problems"].append("log2timeline exited %s; its output is in %s and %s, its log in %s" % (stage.exit, stage.stdout_file, stage.stderr_file, collect_log))
        storage_ok = fresh(store)
        if not storage_ok:
            result["problems"].append("log2timeline wrote no storage file (or none newer than this run's start)")
    else:
        storage_ok = os.path.isfile(store)
        result["collect_exit"] = None
        result["stages"]["collect"] = {"skipped": "mode export: log2timeline was not run; the storage file is the one given"}

    export_log = os.path.join(out_abs, "psort.log.gz")
    export = [psort, "--status_view", "none", "--logfile", export_log, "-o", "json_line", "-w", output]
    if args.get("psort_filter"):
        export += ["--filter", str(args["psort_filter"])]
    export += [store]
    result["export_exit"] = None
    output_ok = False
    # psort reads a storage file, so it is run when there is one even after a nonzero collect (a partial
    # storage can still be read), and its status then says what each stage did.
    if storage_ok and time.monotonic() < deadline:
        stage = Stage("psort", export, out_abs).run(deadline)
        result["stages"]["export"] = stage.record()
        result["export_exit"] = stage.exit
        if stage.timed_out:
            result["problems"].append("psort did not finish within the %ds budget" % timeout)
        elif stage.exit != 0:
            result["problems"].append("psort exited %s; its output is in %s and %s, its log in %s" % (stage.exit, stage.stdout_file, stage.stderr_file, export_log))
        output_ok = fresh(output)
        if not output_ok:
            result["problems"].append("psort wrote no output file (or none newer than this run's start)")
    elif storage_ok:
        result["problems"].append("the time budget was used before psort could run")

    result["logs"] = [p for p in (os.path.join(out_abs, "log2timeline.log.gz"), export_log) if os.path.isfile(p)]
    result["captured_output"] = [str(p) for p in sorted(Path(out_abs).glob("*.std*"))]
    result["parsers_filter"] = args.get("parsers") or ("all (the default, and usually the wrong choice)" if mode == "full" else "as in the storage file given")
    result["timezone_given"] = args.get("timezone") or None
    result["timezone_note"] = ("the zone given to log2timeline for the formats that store local time" if args.get("timezone")
                               else "none given: for the formats that store local time Plaso used its own default, which this tool does not read back; "
                                    "the storage file records what it used (pinfo)")
    result["psort_filter"] = args.get("psort_filter")

    if output_ok:
        try:
            summary = summarise(output, sample, out_abs)
        except OSError as exc:
            summary = None
            result["problems"].append("psort's output could not be read: %s" % (exc.strerror or exc))
        if summary:
            result["events"] = summary["events"]
            result["invalid_lines"] = summary["invalid_lines"]
            result["oversized_lines"] = summary["oversized_lines"]
            if summary["invalid_lines_file"]:
                result["invalid_lines_file"] = summary["invalid_lines_file"]
                result["invalid_lines_listing_complete"] = summary["invalid_lines_listing_complete"]
            result["first_event"], result["last_event"] = summary["first_event"], summary["last_event"]
            top = sorted(summary["parsers_seen"].items(), key=lambda kv: -kv[1])[:15]
            result["by_parser"] = [{"parser": n, "events": c} for n, c in top]
            result["sample"] = summary["head"]
            result["sample_note"] = "a preview; the whole timeline is the output file, one JSON object per line"
            if summary["invalid_lines"]:
                result["problems"].append("%d line(s) of the output are not valid JSON events and are not in the count; see %s"
                                          % (summary["invalid_lines"], summary["invalid_lines_file"] or "the output file"))

    clean = (not result["problems"] and result["export_exit"] == 0 and (mode == "export" or result["collect_exit"] == 0))
    if clean and output_ok:
        result["status"] = "complete"
    elif output_ok:
        result["status"] = "partial"
    else:
        result["status"] = "failed"
        result["error"] = result["problems"][0] if result["problems"] else "no timeline was produced"
    result["coverage_note"] = ("complete here means the programs exited 0, wrote their files and every output line parsed. It does not say every "
                               "parser read every source: read the storage file's processing report (Plaso's pinfo) before a negative rests on it. "
                               "A timestamp in this timeline is what a parser read, in UTC; it is a pointer to an artefact, which the artefact's own "
                               "skill then examines.")
    emit(result, 0 if result["status"] == "complete" else 1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Recipe protocol for a lossless dissect.target Linux catalogue.

    run.py detect --target T [--probe-out DIR]   exit 0 applies, 1 does not, 2 could not tell
    run.py run --target T --out DIR

detect keeps three answers apart. Exit 0 says dissect.target named a Linux target. Exit 1 says it ran, named
something that is not Linux, and so the route is closed. Exit 2 says it could not tell (the reader is not in
this image, it timed out, it failed, it printed nothing, or it printed that it could not identify the system)
and the route is NOT closed: the census records a detect step that failed, with why, rather than "does not
apply". A reader that is not in the image, or that timed out, is a missing observation and never a negative.

run builds the linux_triage artefact files and a coverage receipt that follows what each selected function
produced, read from the wrapper's own durable summary (which the wrapper rewrites after every function), so a
run that is killed or times out still leaves a receipt of what had been done. The receipt is written as
`incomplete` before the wrapper starts, and again if this process is terminated.
"""

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

DETECT_SECONDS = int(os.environ.get("LINUX_TARGET_DETECT_SECONDS", "300"))
# What dissect.target prints for a system it could not identify, rather than for one it identified.
UNIDENTIFIED = {"default", "unknown", "none", "null", "unidentified", "n/a"}
NOT_COVERED = "deleted/unallocated carving, arbitrary application files, memory, encrypted content without a key"


def answer(value, code=0):
    print(json.dumps(value))
    raise SystemExit(code)


def target_value(raw):
    try:
        value = json.load(open(raw, encoding="utf-8")) if os.path.isfile(raw) else json.loads(raw)
    except (OSError, ValueError) as exc:
        answer({"ok": False, "error": f"target is not readable JSON: {exc}"}, 2)
    paths = value.get("paths") if isinstance(value, dict) else None
    if not isinstance(paths, list) or not paths or not isinstance(paths[0], str):
        answer({"ok": False, "error": "target has no paths"}, 2)
    name = value.get("name")
    return paths[0], name if isinstance(name, str) and name else paths[0]


def detect(image):
    """Any failure to read the OS is exit 2 and `applies: unknown`: only a typed answer naming another system closes the route."""
    try:
        detect_os(image)
    except SystemExit:
        raise
    except Exception as exc:    # an unreadable reader, an answer that is not text: not a negative
        answer({"applies": "unknown", "why": f"the OS probe failed ({type(exc).__name__}: {exc}): the OS was not identified, "
                                             "so this route is not closed"}, 2)


def detect_os(image):
    binary = shutil.which("target-query")
    if not binary:
        answer({"applies": "unknown", "why": "target-query is not in this image: the OS of the target was not identified, "
                                             "so this route is not closed"}, 2)
    try:
        proc = subprocess.run([binary, "--no-cache", "-s", "-f", "os", image],
                              capture_output=True, text=True, errors="replace", timeout=DETECT_SECONDS)
    except subprocess.TimeoutExpired:
        answer({"applies": "unknown", "why": f"target-query did not identify the OS within {DETECT_SECONDS} seconds: "
                                             "not known to be Linux or not, so this route is not closed"}, 2)
    text = proc.stdout.strip()
    tokens = re.findall(r"[A-Za-z0-9_.-]+", text.lower())
    if proc.returncode == 0 and "linux" in tokens:
        answer({"applies": True, "why": "dissect.target identified a Linux target"})
    if proc.returncode == 0 and tokens and not set(tokens) <= UNIDENTIFIED:
        answer({"applies": False, "why": f"dissect.target identified the target as {text.splitlines()[0][:80]!r}, not Linux"}, 1)
    why = (proc.stderr or proc.stdout).strip()
    if proc.returncode == 0 and not why:
        why = "target-query exited 0 and printed nothing: the OS was not identified"
    elif proc.returncode == 0 and tokens:
        why = f"target-query reported that it could not identify the system ({text.splitlines()[0][:80]!r})"
    elif not why:
        why = f"target-query exited {proc.returncode} without identifying the OS"
    answer({"applies": "unknown", "why": why[-400:] + " (the OS was not identified: this route is not closed)"}, 2)


FUNCTION_STATUSES = ("parsed", "empty", "unsupported", "failed", "not_attempted", "unknown")


def coverage_from(summary, proc_code, shown, state):
    """The receipt: what each selected function produced, from the wrapper's own summary."""
    counts = {k: 0 for k in FUNCTION_STATUSES}
    errors, limits = [], []
    for group in (summary or {}).get("groups") or []:
        for fn in group.get("functions") or []:
            status = fn.get("status")
            if status in counts:
                counts[status] += 1
            if status in ("unsupported", "failed", "not_attempted", "unknown"):
                why = {"unsupported": "the stderr says the function is not available for this target",
                       "failed": f"exit {fn.get('exit_code')}, timed_out={fn.get('timed_out')}",
                       "not_attempted": fn.get("reason", "not started"),
                       "unknown": "its output or stderr could not be read as parsed or empty: read the files"}[status]
                errors.append(f"{group.get('group')}: {fn.get('name')} {status}: {why}")
            if fn.get("timed_out"):
                limits.append(f"{fn.get('name')} timed out ({fn.get('deadline', 'function')} deadline)")
            if status in ("running", "pending"):
                counts["not_attempted"] += 1
                errors.append(f"{group.get('group')}: {fn.get('name')} was {status} when the receipt was written")
    wrapper = (summary or {}).get("state", "missing")
    done = wrapper == "finished" and proc_code == 0 and (summary or {}).get("execution_complete") is True
    clean = done and not any(counts[k] for k in ("unsupported", "failed", "not_attempted", "unknown"))
    if summary is None:
        status = "unknown"
    else:
        status = "complete" if clean else "partial"
    return {
        "recipe": "linux-target",
        "status": status,
        "covered": "the dissect.target functions selected for this recipe (counted under functions, named in artefacts/summary.json) over "
                   + shown + "; `complete` says every selected function ran and produced records or nothing, not that the artefacts exist or were all read",
        "not_covered": NOT_COVERED,
        "functions": counts,
        "limits_hit": limits,
        "errors": errors,
        "wrapper": {"state": wrapper, "exit_code": proc_code, "execution_complete": (summary or {}).get("execution_complete")},
        "receipt_written": state,
    }


def read_summary(out, since):
    """The wrapper's summary, if it is this run's: one that started before this process did is an earlier run's."""
    try:
        summary = json.loads((out / "artefacts" / "summary.json").read_text())
    except (OSError, ValueError):
        return None
    started = summary.get("started") if isinstance(summary, dict) else None
    if not isinstance(started, (int, float)) or started < since:
        return None
    return summary


def write_index(out):
    with (out / "index.tsv").open("w", encoding="utf-8") as index:
        index.write("summary.json\tlinux_triage's answer: per function status, exit code, records, paths, sizes and hashes\n")
        for path in sorted((out / "artefacts").glob("*")) if (out / "artefacts").is_dir() else []:
            if not path.is_file():
                continue
            if path.name == "summary.json":
                kind = "durable summary the wrapper rewrote after every function (state running or finished)"
            elif path.suffix in (".jsonl", ".txt"):
                kind = "complete target-query output of a family's functions, in order"
            else:
                kind = "complete target-query stderr of one function"
            index.write(f"artefacts/{path.name}\t{kind}\n")
        if (out / "runner.stderr").exists():
            index.write("runner.stderr\tcomplete stderr from the linux_triage runner\n")


def run(image, shown, out):
    out.mkdir(parents=True, exist_ok=True)
    tool = Path(__file__).resolve().parents[2] / "tools" / "linux_triage" / "run.py"
    request = {"source": image, "out_dir": str(out / "artefacts")}
    state = {"proc": None}
    began = time.time()

    def receipt(proc_code, written):
        summary = read_summary(out, began)
        coverage = coverage_from(summary, proc_code, shown, written)
        (out / "coverage.json").write_text(json.dumps(coverage, indent=2) + "\n")
        write_index(out)
        return coverage

    # A receipt exists before the wrapper starts, and again if this process is told to stop.
    (out / "coverage.json").write_text(json.dumps({
        "recipe": "linux-target", "status": "unknown", "covered": "nothing yet: the wrapper had not finished",
        "not_covered": NOT_COVERED, "errors": ["the wrapper was running when this receipt was written; see artefacts/summary.json"],
        "receipt_written": "before the wrapper started"}, indent=2) + "\n")

    def terminated(signum, _frame):
        child = state["proc"]
        if child is not None and child.poll() is None:
            # The wrapper runs in a session of its own, with the dissect.target it started: end the whole group.
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                child.terminate()
            try:
                child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    child.kill()
        receipt(None, "after this process was terminated")
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, terminated)
    proc = subprocess.Popen([sys.executable, str(tool)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            start_new_session=True)
    state["proc"] = proc
    stdout, stderr = proc.communicate(json.dumps(request))
    (out / "summary.json").write_text(stdout or json.dumps({"error": "linux_triage wrote no result"}) + "\n")
    if stderr:
        (out / "runner.stderr").write_text(stderr)
    coverage = receipt(proc.returncode, "after the wrapper finished")
    if proc.returncode != 0:
        coverage["errors"].append(f"linux_triage exited {proc.returncode}")
        (out / "coverage.json").write_text(json.dumps(coverage, indent=2) + "\n")
    answer({"ok": proc.returncode == 0, "status": coverage["status"], "functions": coverage["functions"]},
           0 if proc.returncode == 0 else 2)


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    target = None
    out = None
    args = iter(sys.argv[2:])
    for arg in args:
        if arg == "--target":
            target = next(args, None)
        elif arg == "--out":
            out = next(args, None)
        elif arg == "--probe-out":
            next(args, None)
        else:
            answer({"ok": False, "error": f"unknown argument: {arg}"}, 2)
    if not target:
        answer({"ok": False, "error": "--target is required"}, 2)
    image, shown = target_value(target)
    if not os.path.exists(image):
        answer({"ok": False, "error": "target path does not exist"}, 2)
    if command == "detect":
        detect(image)
    if command == "run" and out:
        run(image, shown, Path(out))
    answer({"ok": False, "error": "usage: run.py detect --target T | run --target T --out DIR"}, 2)


if __name__ == "__main__":
    main()

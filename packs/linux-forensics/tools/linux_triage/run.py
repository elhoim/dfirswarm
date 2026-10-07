#!/usr/bin/env python3
"""Lossless Linux triage through dissect.target, one function at a time, with a status for each.

Each artefact family is written to its own complete file (JSON Lines, or text for the identity family),
every selected dissect.target function appended to it in turn, and its stderr kept whole in a file of its
own. Stdout is a small manifest: for each function the exit code, the records it produced, the lines that
were not JSON, its time, and a status; for each file its size, hash and line count.

The status is what was observed, never a promise about the evidence:

    parsed         the function exited 0 and produced records (every line JSON)
    empty          it exited 0, produced nothing and wrote nothing to stderr
    unsupported    it exited 0, produced nothing, and its stderr says the plugin or function is not available
                   for this target (the patterns are in UNSUPPORTED_STDERR; which messages dissect.target
                   writes for which causes is not validated here, so a message not matched is `unknown`)
    failed         a non-zero exit, or it ran past its deadline
    not_attempted  the total deadline had passed or was too near to start it
    unknown        it exited 0 and the output or the stderr cannot be read as one of the above (a line that is
                   not JSON, or a stderr that names no cause for an empty result): read the files

`execution_complete` says that every function was started and exited 0 within its deadline. It is not
artefact coverage: an exit code does not say which artefacts the target had, which of them the function reads,
or whether it read them. Coverage is the counts of statuses, and even `parsed` means only that the function
produced records. A family's name is not what it covers: each family says its functions and what they do not
cover. Empty output is a parser's result, not proof that the artefact is absent.

Time. Each function runs for at most `timeout_seconds`, and all of them within `total_timeout_seconds`
(default 13800, under the manifest's 14400): the tool starts no function with less than a second left,
marks what it did not start `not_attempted`, and rewrites `summary.json` in the output directory after every
function, so a run that is killed from outside still leaves what it had done.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

TOOL = "linux_triage"
PARSER = "linux_triage/3"
DEFAULT_FUNCTION_SECONDS = 1800
DEFAULT_TOTAL_SECONDS = 13800
FIRST_FAILURES = 20

# family -> its dissect.target functions, what it covers and what it does not
GROUPS = {
    "identity": {"functions": ["os", "hostname", "version", "ips"], "strings": True,
                 "covers": "the OS name, hostname, version and IP addresses as dissect.target reports them, as text",
                 "does_not_cover": "the timezone, the machine id, the install date or the installed packages"},
    "users": {"functions": ["users"],
              "covers": "the accounts dissect.target's users function reports",
              "does_not_cover": "shadow verifiers, group membership, sudoers, SSH policy or accounts of a central identity source"},
    "sessions": {"functions": ["wtmp", "btmp", "lastlog"],
                 "covers": "classic wtmp, btmp and lastlog records",
                 "does_not_cover": "wtmpdb or lastlog2 (SQLite) databases, utmp, audit login records or the journal"},
    "authentication": {"functions": ["authlog"],
                       "covers": "auth.log or secure lines as dissect.target's authlog function parses them",
                       "does_not_cover": "the journal, the audit log, or a log kept under another name or place"},
    "history": {"functions": ["bashhistory"],
                "covers": "bash history files only",
                "does_not_cover": "zsh, fish or client histories, a custom HISTFILE, or what a shell did not save"},
    "persistence": {"functions": ["cronjobs", "services"],
                    "covers": "cron jobs and services as the two functions report them",
                    "does_not_cover": "per-user systemd units, drop-ins, enablement, at jobs or the other persistence mechanisms"},
    "packages": {"functions": ["dpkg.status", "packagemanager.logs"],
                 "covers": "the Debian-family package status file and package-manager logs",
                 "does_not_cover": "an RPM database or any package verification"},
    "ssh": {"functions": ["ssh.authorized_keys", "ssh.known_hosts", "ssh.public_keys"],
            "covers": "authorized_keys, known_hosts and public keys as the functions read them",
            "does_not_cover": "sshd_config, certificates' authorities or private keys"},
    "logs": {"functions": ["journal", "syslog"],
             "covers": "the journal and syslog as the two functions parse them",
             "does_not_cover": "the audit log, application logs, or entries the journal reader does not decode"},
    "web": {"functions": ["webserver.logs"],
            "covers": "access and error logs of the web servers dissect.target knows",
            "does_not_cover": "a proxy, application or database log, or a server it does not recognise"},
    "containers": {"functions": ["container.logs"],
                   "covers": "container logs only",
                   "does_not_cover": "container configuration, layers, volumes, environment or runtime state"},
}
UNSUPPORTED_STDERR = re.compile(
    r"(unsupported|not\s+(?:available|supported|applicable|implemented)|no\s+such\s+(?:function|plugin)|"
    r"unknown\s+(?:function|plugin)|unrecogni[sz]ed\s+(?:function|plugin)|failed\s+to\s+find\s+(?:function|plugin))", re.I)

def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place
    outside it, the run directory itself, or anything under inputs/ is refused.

    A string check is not enough: `work/../inputs/x`, an absolute path and a
    symlink that points out all name a place the tool must not write, and none
    of them starts with "inputs/". Resolving first and comparing directories
    is what actually holds, and the read-only inputs are the one place
    extracted bytes must never appear -- a later integrity check would report
    the evidence as modified. In a job $OUT is inside the run directory.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    return str(dest.relative_to(root))


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def count_region(path, start, end, as_json):
    """(records, invalid lines, first invalid line numbers) of one function's bytes in its family's file."""
    records = invalid = 0
    first = []
    line_no = 0
    with path.open("rb") as fh:
        fh.seek(start)
        remaining = end - start
        for raw in fh:
            remaining -= len(raw)
            if raw.strip():
                line_no += 1
                if as_json:
                    try:
                        json.loads(raw)
                        records += 1
                    except ValueError:
                        invalid += 1
                        if len(first) < FIRST_FAILURES:
                            first.append(line_no)
                else:
                    records += 1
            if remaining <= 0:
                break
    return records, invalid, first


def classify(function, exit_code, timed_out, records, invalid, stderr_text):
    if timed_out or exit_code != 0:
        return "failed"
    if invalid:
        return "unknown"
    if records == 0 and stderr_text and UNSUPPORTED_STDERR.search(stderr_text):
        return "unsupported"
    if records > 0:
        return "parsed"
    return "unknown" if stderr_text.strip() else "empty"


def group_status(functions):
    statuses = [f["status"] for f in functions]
    if all(s == "not_attempted" for s in statuses):
        return "not_attempted"
    if "failed" in statuses:
        return "failed"
    if all(s == "unsupported" for s in statuses):
        return "unsupported"
    if "unsupported" in statuses:
        return "partial_unsupported"
    if "not_attempted" in statuses or "pending" in statuses or "running" in statuses:
        return "partial_not_attempted"
    if any(f.get("records", 0) > 0 for f in functions):
        return "produced_records"
    return "unknown" if "unknown" in statuses else "empty"


def coverage_of(groups):
    counts = {"parsed": 0, "empty": 0, "unsupported": 0, "failed": 0, "not_attempted": 0, "unknown": 0}
    for g in groups:
        for f in g["functions"]:
            if f["status"] in counts:
                counts[f["status"]] += 1
    counts["note"] = ("These count the selected functions by what each produced. Artefact coverage of the host is not established by "
                      "this tool: `parsed` means a function produced records, `empty` that it produced none and wrote nothing, and "
                      "neither says which artefacts the target had or which of them the function reads.")
    return counts


def write_summary(out, state):
    tmp = out / ".summary.json.tmp"
    tmp.write_text(json.dumps(state, indent=2) + "\n")
    os.replace(tmp, out / "summary.json")


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    source = args.get("source")
    out_arg = args.get("out_dir")
    if not isinstance(source, str) or not source or not os.path.exists(source):
        fail("source is required and must exist", source=source)
    if not isinstance(out_arg, str) or not out_arg:
        fail("out_dir is required")
    out = Path(resolve_output(out_arg, "out_dir"))
    if out.exists():
        fail("out_dir already exists; refusing to overwrite an earlier result", out_dir=str(out))
    binary = shutil.which("target-query")
    if not binary:
        fail("target-query is not on PATH", install="the computer-forensics-base image requirement 'dissect'")
    if "groups" in args and args["groups"] is not None:
        selected = args["groups"]
        if not isinstance(selected, list):
            fail("groups must be a list of family names, or omitted to run every family", known=list(GROUPS))
        if not selected:
            fail("groups is empty: omit it to run every family, or name the families to run", known=list(GROUPS))
        unknown = [g for g in selected if not isinstance(g, str) or g not in GROUPS]
        if unknown:
            fail("groups must name known families", unknown=[str(u) for u in unknown], known=list(GROUPS))
        repeated = sorted({g for g in selected if selected.count(g) > 1})
        if repeated:
            fail("groups names a family more than once, which would write its file twice", repeated=repeated)
    else:
        selected = list(GROUPS)
    per_function = args.get("timeout_seconds", DEFAULT_FUNCTION_SECONDS)
    total = args.get("total_timeout_seconds", DEFAULT_TOTAL_SECONDS)
    for name, value in (("timeout_seconds", per_function), ("total_timeout_seconds", total)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            fail("%s must be a positive integer" % name)

    out.mkdir(parents=True)
    started_at = time.time()
    deadline = time.monotonic() + total
    groups = [{"group": g, "functions": [{"name": f, "status": "pending"} for f in GROUPS[g]["functions"]],
               "covers": GROUPS[g]["covers"], "does_not_cover": GROUPS[g]["does_not_cover"], "status": "pending"} for g in selected]

    def state(kind):
        return {"state": kind, "parser": PARSER, "source": source, "out_dir": str(out), "started": started_at, "updated": time.time(),
                "total_timeout_seconds": total, "timeout_seconds": per_function, "groups": groups, "coverage": coverage_of(groups)}

    write_summary(out, state("running"))
    stop = False
    for group in groups:
        spec = GROUPS[group["group"]]
        result_path = out / (group["group"] + (".txt" if spec.get("strings") else ".jsonl"))
        group["file"] = str(result_path)
        with result_path.open("wb") as stdout:
            for entry in group["functions"]:
                name = entry["name"]
                remaining = deadline - time.monotonic()
                if stop or remaining < 1:
                    entry.update({"status": "not_attempted", "reason": "the total deadline (%d s) had passed or was too near to start it" % total})
                    stop = True
                    write_summary(out, state("running"))
                    continue
                entry["status"] = "running"
                write_summary(out, state("running"))
                limit = min(per_function, remaining)
                err_path = out / ("%s.%s.stderr" % (group["group"], re.sub(r"[^A-Za-z0-9_.-]", "_", name)))
                argv = [binary, "--no-cache", "-f", name] + (["-s"] if spec.get("strings") else ["-j"]) + [source]
                begin = stdout.tell()
                began = time.monotonic()
                timed_out = False
                with err_path.open("wb") as stderr:
                    try:
                        proc = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=limit)
                        code = proc.returncode
                    except subprocess.TimeoutExpired:
                        timed_out, code = True, 124
                stdout.flush()
                end = stdout.tell()
                err_text = err_path.read_text(errors="replace") if err_path.exists() else ""
                records, invalid, first_bad = count_region(result_path, begin, end, not spec.get("strings"))
                entry.update({"exit_code": code, "timed_out": timed_out, "seconds": round(time.monotonic() - began, 3),
                              "bytes": end - begin, "byte_offset": begin, "records": records, "invalid_lines": invalid,
                              "argv": argv[1:]})
                if timed_out:
                    entry["deadline"] = "total" if limit < per_function else "function"
                    if entry["deadline"] == "total":
                        stop = True
                if first_bad:
                    entry["first_invalid_lines"] = first_bad
                if err_path.stat().st_size:
                    entry.update({"stderr": str(err_path), "stderr_bytes": err_path.stat().st_size, "stderr_sha256": digest(err_path)})
                else:
                    err_path.unlink()
                entry["status"] = classify(name, code, timed_out, records, invalid, err_text)
                write_summary(out, state("running"))
        group["status"] = group_status(group["functions"])
        if result_path.exists():
            group.update({"bytes": result_path.stat().st_size, "sha256": digest(result_path)})
            with result_path.open("rb") as fh:
                group["lines"] = sum(1 for _ in fh)
    final = state("finished")
    final["execution_complete"] = all(f.get("exit_code") == 0 and not f.get("timed_out") and f["status"] != "not_attempted"
                                      for g in groups for f in g["functions"])
    final["source"], final["note"] = source, (
        "Every byte a function wrote is in its family's file, and its stderr is in its own file. execution_complete says every function was "
        "started and exited 0 within its deadline: it is not artefact coverage (see coverage). Empty output is a parser's result, not proof "
        "that the artefact is absent; read the paired stderr and confirm the source scope before recording an absence. dissect.target is "
        "run on the source as given; whether an extracted root is read as well as an image is shown by the statuses, not assumed.")
    write_summary(out, final)
    print(json.dumps(final, indent=2))


if __name__ == "__main__":
    main()

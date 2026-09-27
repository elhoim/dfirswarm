#!/usr/bin/env python3
"""Run a Sigma ruleset over event logs, with whichever engine the host carries.

Querying by event id answers a question you already knew to ask. A ruleset
answers the ones you did not: several thousand community rules, each one a
pattern somebody saw in a real intrusion, run over every record in the channel.
On a case where the first pass found nothing, this is the cheapest way to find
the thing you were not looking for.

Two engines do the same job and neither is shipped here:

    Zircolite   LGPL-3.0, Python, loads the records into SQLite and runs the
                rules as queries. Fastest, lightest on memory.
    Hayabusa    GPL-3.0, one Rust binary, and it also builds a timeline.

Both are invoked as executables, so neither licence combines with this one.

The output is normalised to the same shape whichever ran, because an agent
should not have to learn two formats — and because the thing that goes in the
report is not the detection anyway. A rule firing is a hypothesis with a name.
The evidence is the record it matched, which you then read with evtx_query and
cite by its record id and channel.

Nothing is cut. Every field of a matched record is kept, every rule that fired
is counted, and the engine's own stdout and stderr are kept whole beside its
result. Past `limit` the detections are a page, and all of them, normalised,
are in detections.jsonl in out_dir; each file is named with its path, size and
sha256.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_TIMEOUT = 900
LEVELS = ["informational", "low", "medium", "high", "critical"]


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


def kept_file(path, text=None, rows=None):
    """Write the whole of something to `path` (text, or rows as JSON Lines) and
    name it: path, bytes, sha256, and rows when it holds rows."""
    body = text if rows is None else "".join(json.dumps(r, ensure_ascii=False, default=str) + "\n" for r in rows)
    data = body.encode("utf-8", "surrogateescape")
    with open(path, "wb") as fh:
        fh.write(data)
    named = {"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if rows is not None:
        named["rows"] = len(rows)
    return named


def rank(level):
    try:
        return LEVELS.index(str(level).lower())
    except ValueError:
        return 0


def from_zircolite(path):
    """Zircolite writes a list of rules, each with the events that matched it."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    out = []
    for rule in data if isinstance(data, list) else []:
        title = rule.get("title") or rule.get("rule_title") or "unnamed rule"
        level = rule.get("rule_level") or rule.get("level") or "medium"
        for match in rule.get("matches") or []:
            out.append({
                "rule": title,
                "level": level,
                "rule_id": rule.get("id"),
                "time": match.get("SystemTime") or match.get("UtcTime") or match.get("timestamp"),
                "event_id": match.get("EventID"),
                "channel": match.get("Channel"),
                "computer": match.get("Computer"),
                "record_id": match.get("EventRecordID"),
                "detail": match,
            })
    return out


def from_hayabusa(path):
    """Hayabusa's JSON timeline is one detection per object, or one per line."""
    rows = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read().strip()
    if not text:
        return rows
    try:
        loaded = json.loads(text)
        rows = loaded if isinstance(loaded, list) else [loaded]
    except ValueError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    out = []
    for row in rows:
        details = row.get("Details")
        out.append({
            "rule": row.get("RuleTitle") or row.get("RuleFile") or "unnamed rule",
            "level": row.get("Level") or "medium",
            "rule_id": row.get("RuleID"),
            "time": row.get("Timestamp") or row.get("timestamp"),
            "event_id": row.get("EventID"),
            "channel": row.get("Channel"),
            "computer": row.get("Computer"),
            "record_id": row.get("RecordID"),
            "detail": details if isinstance(details, dict) else {"details": details},
        })
    return out


def _text(value):
    if value is None:
        return ""
    return value.decode("utf-8", "surrogateescape") if isinstance(value, bytes) else value


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an .evtx file or a directory of them")
    if not os.path.exists(path):
        fail("no such file or directory", path=path)

    out_dir = args.get("out_dir")
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: a directory under work/ for the engine's own output")
    out_dir = resolve_output(out_dir, "out_dir")

    min_level = str(args.get("min_level") or "medium").lower()
    if min_level not in LEVELS:
        fail("min_level must be one of %s" % ", ".join(LEVELS), min_level=args.get("min_level"))
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 10:
        fail("timeout_seconds must be an integer of at least 10")

    wanted = str(args.get("engine") or "auto").lower()
    if wanted not in ("auto", "zircolite", "hayabusa"):
        fail("engine must be auto, zircolite or hayabusa", engine=args.get("engine"))

    zircolite = shutil.which("zircolite") or shutil.which("zircolite.py")
    hayabusa = shutil.which("hayabusa")
    engine = None
    if wanted in ("auto", "zircolite") and zircolite:
        engine, binary = "zircolite", zircolite
    elif wanted in ("auto", "hayabusa") and hayabusa:
        engine, binary = "hayabusa", hayabusa
    if engine is None:
        fail("no Sigma engine on PATH",
             looked_for=["zircolite", "hayabusa"],
             install={"zircolite": "https://github.com/wagga40/Zircolite/releases",
                      "hayabusa": "https://github.com/Yamato-Security/hayabusa/releases"},
             note="Both are invoked as executables, so neither licence combines with this project's.")

    os.makedirs(out_dir, exist_ok=True)
    result = resolve_output(os.path.join(out_dir, "%s.json" % engine), "out_dir")

    if engine == "zircolite":
        # No --noexternal: Zircolite 3 removed it (it reads EVTX through its
        # Python bindings only) and refuses the flag; 2.x without it uses its
        # own bundled evtx_dump.
        argv = [binary, "--evtx", path, "--outfile", result]
        if args.get("rules"):
            argv += ["--ruleset", str(args["rules"])]
    else:
        argv = [binary, "json-timeline", "-d" if os.path.isdir(path) else "-f", path,
                "-o", result, "-w", "-q"]
        if args.get("rules"):
            argv += ["-r", str(args["rules"])]

    # The engine's own words, whole, beside its result: they used to be
    # dropped when it succeeded and cut to their last few hundred characters
    # when it did not.
    stdout_path = resolve_output(os.path.join(out_dir, "%s.stdout" % engine), "out_dir")
    stderr_path = resolve_output(os.path.join(out_dir, "%s.stderr" % engine), "out_dir")
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, errors="surrogateescape", timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        said = {"stdout": kept_file(stdout_path, text=_text(exc.stdout)),
                "stderr": kept_file(stderr_path, text=_text(exc.stderr))}
        fail("%s did not finish in time" % engine, after_seconds=timeout, command=" ".join(argv), **said)
    said = {"stdout": kept_file(stdout_path, text=proc.stdout or ""),
            "stderr": kept_file(stderr_path, text=proc.stderr or "")}

    if not os.path.isfile(result):
        fail("%s wrote no result file" % engine, exit_code=proc.returncode,
             command=" ".join(argv), **said,
             note="Engine command lines change between versions; the exact invocation is above "
                  "so it can be corrected by hand and re-run. Its whole stdout and stderr are "
                  "the files named here.")

    try:
        detections = from_zircolite(result) if engine == "zircolite" else from_hayabusa(result)
    except (ValueError, OSError) as exc:
        fail("%s wrote a result this tool could not read" % engine, result=result, reason=str(exc))

    floor = rank(min_level)
    kept = [d for d in detections if rank(d.get("level")) >= floor]
    kept.sort(key=lambda d: (-rank(d.get("level")), str(d.get("time") or "")))
    by_rule = {}
    for d in kept:
        by_rule[d["rule"]] = by_rule.get(d["rule"], 0) + 1
    all_detections = kept_file(resolve_output(os.path.join(out_dir, "detections.jsonl"), "out_dir"), rows=kept)

    print(json.dumps({
        "path": path,
        "engine": engine,
        "exit_code": proc.returncode,
        "command": " ".join(argv),
        "result_file": result,
        "detections": kept[:limit],
        "detection_count": len(kept),
        "returned": min(len(kept), limit),
        "truncated": len(kept) > limit,
        "all_detections": all_detections,
        "below_min_level": len(detections) - len(kept),
        "min_level": min_level,
        "rules_that_fired": sorted(({"rule": r, "count": c} for r, c in by_rule.items()),
                                   key=lambda x: (-x["count"], str(x["rule"]))),
        "rules_fired": len(by_rule),
        "engine_stdout": said["stdout"],
        "engine_stderr": said["stderr"],
        "note": "A rule firing is a hypothesis with a name, not a finding. Take its record id and "
                "channel to evtx_query, read the record, and cite the record. Community rulesets "
                "are tuned for live estates and produce false positives on a forensic image: an "
                "administrator doing their job trips a dozen of them.",
    }, indent=2))


if __name__ == "__main__":
    main()

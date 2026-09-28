#!/usr/bin/env python3
"""A run's dated ledger entries as one timeline, in time order, written to a file.

Reads ledger/entries.jsonl (or the one named) as the harness writes it, with
ledger/attestations.jsonl and ledger/disputes.jsonl beside it when they are
there, and writes the standing dated entries as a Markdown table, CSV or JSON
Lines. What is left out is chosen by parameters and counted in the answer,
never assumed: corrected entries (superseded by a later one), entries that
duplicate another (rel duplicates), seqs named in exclude, kinds not asked
for, times outside since/until, entries a match does not find. An entry marked
sensitive is withheld by default, and redact takes patterns to withhold
inside the rest. Args come from JSON stdin.
"""
import csv
import hashlib
import io
import json
import os
import re
import sys
from pathlib import Path

# The ledger's kinds (extensions/protocol.ts LEDGER_KINDS): coverage records
# and external material (a capture the harness recorded) as well.
KINDS = ("event", "ioc", "finding", "absence", "hypothesis", "limitation", "answer", "coverage", "external")
COLUMNS = ("time", "event", "kind", "source", "evidence", "clock", "precision", "confidence", "refs", "by", "entry")
DEFAULT_COLUMNS = ["time", "event", "clock", "entry"]
HEADINGS = {
    "time": "Time (UTC)",
    "event": "Event",
    "kind": "Kind",
    "source": "Source",
    "evidence": "Evidence",
    "clock": "Clock",
    "precision": "Precision",
    "confidence": "Confidence",
    "refs": "Refs",
    "by": "By",
    "entry": "Entry",
}


def fail(msg, **extra):
    print(json.dumps({"ok": False, "error": msg, **extra}))
    sys.exit(1)


def resolve_output(out):
    """Where `out` lands, refusing anything outside the run directory and the
    places a tool must not write: the read-only inputs, and ledger/ and
    tools/, which the harness owns (a write there is a claim violation)."""
    root = Path.cwd().resolve()
    dest = Path(out).resolve() if Path(out).is_absolute() else (root / out).resolve()
    if dest != root and root not in dest.parents:
        fail("output must stay inside the run directory", output=str(out))
    for owned in ("inputs", "ledger", "tools"):
        place = root / owned
        if dest == place or place in dest.parents:
            fail("output cannot be under %s/" % owned, output=str(out))
    return dest


def read_jsonl(path):
    """Every JSON object in a JSON Lines file, and how many lines were not one."""
    rows, torn = [], []
    if not path.is_file():
        return rows, torn
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                torn.append(n)
                continue
            if isinstance(obj, dict):
                rows.append(obj)
            else:
                torn.append(n)
    return rows, torn


def whole_number(value, what):
    """A seq as the ledger takes one: 7, "7" or "#7"."""
    if isinstance(value, bool):
        fail("%s must be entry numbers" % what, got=value)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"#?\d+", value.strip()):
        return int(value.strip().lstrip("#"))
    fail("%s must be entry numbers (7, \"7\" or \"#7\")" % what, got=value)


def string_list(value, what):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        fail("%s must be a list of strings" % what, got=value)
    return value


def bound(value, what):
    """since/until: an ISO 8601 UTC time or a date, compared as the ledger
    stores times (UTC, ISO text)."""
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}([T ][0-9:.]+Z?)?", value.strip()):
        fail("%s must be an ISO 8601 UTC time or a date (2026-01-31 or 2026-01-31T12:00:00Z)" % what, got=value)
    return value.strip().replace(" ", "T").rstrip("Z")


def cell(text):
    return str(text if text is not None else "").replace("|", "\\|").replace("\r\n", " ").replace("\n", " ")


args = json.load(sys.stdin)
if not isinstance(args, dict):
    fail("arguments must be a JSON object")
ledger = Path(args.get("ledger") or "ledger/entries.jsonl")
output = args.get("output")
if not isinstance(output, str) or not output.strip():
    fail("need output: the file to write the timeline to (under your work directory)")
dest = resolve_output(output)
fmt = args.get("format") or ("csv" if dest.suffix.lower() == ".csv" else "jsonl" if dest.suffix.lower() in (".jsonl", ".ndjson") else "markdown")
if fmt not in ("markdown", "csv", "jsonl"):
    fail("format must be markdown, csv or jsonl", got=fmt)
kinds = string_list(args.get("kinds"), "kinds") or ["event"]
unknown = [k for k in kinds if k not in KINDS]
if unknown:
    fail("unknown kinds", unknown=unknown, kinds=list(KINDS))
raw_exclude = args.get("exclude")
if raw_exclude is None or raw_exclude == "":
    excluded = set()
elif isinstance(raw_exclude, list):
    excluded = {whole_number(v, "exclude") for v in raw_exclude}
else:
    excluded = {whole_number(raw_exclude, "exclude")}
keep_duplicates = bool(args.get("keep_duplicates", False))
include_superseded = bool(args.get("include_superseded", False))
since = bound(args.get("since"), "since")
until = bound(args.get("until"), "until")
sensitive_mode = args.get("sensitive") or "withhold"
if sensitive_mode not in ("withhold", "keep", "drop"):
    fail("sensitive must be withhold, keep or drop", got=sensitive_mode)
try:
    match = re.compile(args["match"], re.IGNORECASE) if args.get("match") else None
    redact = [re.compile(p) for p in string_list(args.get("redact"), "redact")]
except re.error as e:
    fail("not a valid regex: %s" % e)
columns = string_list(args.get("columns"), "columns") or list(DEFAULT_COLUMNS)
bad_cols = [c for c in columns if c not in COLUMNS]
if bad_cols:
    fail("unknown columns", unknown=bad_cols, columns=list(COLUMNS))
title = args.get("title") or "Timeline"
note = args.get("note") or ""

if not ledger.is_file():
    fail("no ledger at %s" % ledger, hint="a run's ledger is ledger/entries.jsonl; pass ledger= for another")
entries, torn = read_jsonl(ledger)
entries = [e for e in entries if isinstance(e.get("seq"), int)]
if not entries:
    fail("the ledger holds no entries", ledger=str(ledger), unreadable_lines=torn)
here = ledger.parent
attestations, torn_att = read_jsonl(here / "attestations.jsonl")
disputes, torn_disp = read_jsonl(here / "disputes.jsonl")
# Where the rows' E-<seq> links point: the rendered ledger beside the
# entries, as seen from the output, unless the caller says otherwise.
link = args.get("link")
if link is None:
    link = os.path.relpath((here / "ledger.md").resolve(), dest.parent)

# A correction names the entry it corrects; the corrected one stays in the
# file, and the correction is what stands.
superseded_by = {}
for e in entries:
    s = e.get("supersedes")
    if isinstance(s, int):
        superseded_by[s] = e["seq"]
# The same content recorded by a second author is folded into authors; an
# explicit attest (v2) names who re-derived an entry, by the entry's hash.
more_authors, attested_by = {}, {}
for a in attestations:
    if a.get("v") == 2 and a.get("act") == "attest":
        attested_by.setdefault(a.get("target"), []).append(str(a.get("by")))
    elif isinstance(a.get("seq"), int):
        more_authors.setdefault(a["seq"], []).append(str(a.get("by")))
# A dispute stands until the same author withdraws it.
open_disputes = {}
for d in disputes:
    key = (d.get("target"), d.get("by"))
    if d.get("act") == "dispute":
        open_disputes[key] = d
    else:
        open_disputes.pop(key, None)
disputed = {}
for (target, by), d in open_disputes.items():
    disputed.setdefault(target, []).append("%s: %s" % (by, d.get("why") or ""))

left_out = {"not_asked_kind": 0, "undated": 0, "superseded": 0, "duplicate": 0, "excluded": 0, "outside_range": 0, "not_matched": 0, "sensitive": 0}
rows = []
withheld = 0
for e in entries:
    seq = e["seq"]
    if e.get("kind") not in kinds:
        left_out["not_asked_kind"] += 1
        continue
    ts = e.get("ts")
    if not isinstance(ts, str) or not ts:
        left_out["undated"] += 1
        continue
    if seq in superseded_by and not include_superseded:
        left_out["superseded"] += 1
        continue
    dup_of = [r.get("to") for r in (e.get("rel") or []) if isinstance(r, dict) and r.get("kind") == "duplicates"]
    if dup_of and not keep_duplicates:
        left_out["duplicate"] += 1
        continue
    if seq in excluded:
        left_out["excluded"] += 1
        continue
    key = ts.rstrip("Z")
    if (since and key < since) or (until and key[: len(until)] > until):
        left_out["outside_range"] += 1
        continue
    if match and not any(match.search(str(e.get(f) or "")) for f in ("value", "source", "evidence", "clock")):
        left_out["not_matched"] += 1
        continue
    is_sensitive = bool(e.get("sensitive"))
    if is_sensitive and sensitive_mode == "drop":
        left_out["sensitive"] += 1
        continue
    value = str(e.get("value") or "")
    source = str(e.get("source") or "")
    evidence = str(e.get("evidence") or "")
    if is_sensitive and sensitive_mode == "withhold":
        value = "[sensitive: withheld; see E-%d in the ledger]" % seq
        source = evidence = "[withheld]"
        withheld += 1
    for rx in redact:
        value, source, evidence = (rx.sub("[withheld]", x) for x in (value, source, evidence))
    marks = []
    if isinstance(e.get("supersedes"), int):
        marks.append("corrects E-%d%s" % (e["supersedes"], (": " + str(e["because"])) if e.get("because") else ""))
    if seq in superseded_by:
        marks.append("superseded by E-%d" % superseded_by[seq])
    if dup_of:
        marks.append("duplicates " + ", ".join("E-%s" % t for t in dup_of))
    if e.get("hash") in attested_by:
        marks.append("attested by " + ", ".join(sorted(set(attested_by[e["hash"]]))))
    if e.get("hash") in disputed:
        marks.append("disputed by " + "; ".join(disputed[e["hash"]]))
    precision = e.get("precision") or ""
    when = ts[:10] if precision == "date" else ts
    raw = e.get("ts_raw")
    if isinstance(raw, str) and raw and not raw.upper().endswith("Z") and not (precision == "date" and raw == ts[:10]):
        when += " (as written: %s)" % raw
    authors = list(e.get("authors") or ([e["by"]] if e.get("by") else []))
    authors += [a for a in more_authors.get(seq, []) if a not in authors]
    rows.append({
        "seq": seq,
        "ts": ts,
        "time": when,
        "kind": e.get("kind"),
        "event": value + ("" if not marks else " (" + "; ".join(marks) + ")"),
        "value": value,
        "marks": marks,
        "source": source,
        "evidence": evidence,
        "clock": e.get("clock") or "",
        "precision": precision,
        "confidence": e.get("confidence") or "",
        "refs": ", ".join(e.get("refs") or []),
        "by": ", ".join(authors),
        "sensitive": is_sensitive,
    })
rows.sort(key=lambda r: (r["ts"], r["seq"]))

buf = io.StringIO()
if fmt == "markdown":
    buf.write("# %s\n\n" % title)
    if note:
        buf.write("%s\n\n" % note)
    buf.write("%d entries from `%s`, in time order (UTC). `E-n` is the entry's number in the ledger.\n\n" % (len(rows), ledger))
    buf.write("| %s |\n" % " | ".join(HEADINGS[c] for c in columns))
    buf.write("| %s |\n" % " | ".join("---" for _ in columns))
    for r in rows:
        cells = []
        for c in columns:
            if c == "entry":
                cells.append("[E-%d](%s)" % (r["seq"], link) if link else "E-%d" % r["seq"])
            else:
                cells.append(cell(r[c]))
        buf.write("| %s |\n" % " | ".join(cells))
elif fmt == "csv":
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(columns)
    for r in rows:
        w.writerow(["E-%d" % r["seq"] if c == "entry" else r[c] for c in columns])
else:
    for r in rows:
        buf.write(json.dumps({"entry": "E-%d" % r["seq"], **{k: r[k] for k in ("seq", "ts", "time", "kind", "value", "marks", "source", "evidence", "clock", "precision", "confidence", "refs", "by", "sensitive")}}, ensure_ascii=False) + "\n")
data = buf.getvalue().encode("utf-8")
dest.parent.mkdir(parents=True, exist_ok=True)
tmp = dest.with_name(".%s.tmp" % dest.name)
tmp.write_bytes(data)
os.replace(tmp, dest)
result = {
    "ok": True,
    "output": output,
    "format": fmt,
    "sha256": hashlib.sha256(data).hexdigest(),
    "bytes": len(data),
    "ledger": str(ledger),
    "entries_read": len(entries),
    "rows": len(rows),
    "left_out": left_out,
    "sensitive_withheld": withheld,
    "first": rows[0]["time"] if rows else None,
    "last": rows[-1]["time"] if rows else None,
}
if torn or torn_att or torn_disp:
    result["unreadable_lines"] = {"entries": torn, "attestations": torn_att, "disputes": torn_disp}
if not rows:
    result["note"] = "no entry was kept: %d read, left out as counted in left_out" % len(entries)
print(json.dumps(result, ensure_ascii=False))

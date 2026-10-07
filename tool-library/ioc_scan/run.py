#!/usr/bin/env python3
"""Stream a binary for ASCII and UTF-16LE needles and say where each one is.

The answer is a list of locators: for every occurrence, an id, the offset it starts at,
the needle and encoding that matched and how many bytes of context lie around it.
No context bytes come back by default. Context around a hit in a memory image, a
pagefile or unallocated space is where a password, a token or a card number sits, so
the bytes are written only when the caller asks (`write_values: true`), only in a job,
and only to a file under $OUT (JSON Lines, mode 0600, created new), which the skill
says to run with `secret_output: true`. The answer then says where that file is and
that it holds secret values, not what they are. Never put a secret in `needles`: the
arguments of a call are recorded in the trace.

What it finds, exactly: every occurrence of each needle, by the offset it starts at,
overlapping occurrences included, so the count does not depend on `chunk`. Matching is
case-sensitive and on the needle's bytes: ASCII/UTF-8 as given, and the same text as
UTF-16LE. Each read keeps back the bytes a needle or its context could still need, so a
match or its context cut by a read boundary is found once, whole. `scanned_*` and
`bytes_scanned` are the bytes actually read, not the range asked for.
"""
import hashlib
import json
import os
import re
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

TOOL = {"name": "ioc_scan", "version": 4}
CHUNK_DEFAULT = 8 * 1024 * 1024
CHUNK_MIN, CHUNK_MAX = 16, 256 * 1024 * 1024
CONTEXT_MAX = 65536
BEFORE = 16                        # bytes of context before a match
HITS_MAX = 1_000_000
NEEDLES_MAX = 1000
NEEDLE_BYTES_MAX = 4096
SEEN_CAP = 100_000                 # distinct contexts remembered for the inline view
ROW_CAP = 20_000_000               # rows in the whole-result file; counting goes on past it
SLICE = 256 * 1024                 # positions searched, sorted and emitted together: hits come out in offset order, whatever chunk is


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The reference implementation of the secret-safe output pattern (docs/packs.md, "Writing a
    pack that holds up"), copied as a standalone tool copies LosslessPage: call `add` once per
    finding with the finding's id, its locator and the value. With `enabled` false it writes
    nothing and `summary()` says so.
    """

    NAME = "ioc-scan-values.jsonl"

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.written = 0
        self._fh = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        if enabled and not (self.job and self.out):
            raise SecretValuesRefused(
                "write_values is refused outside a job: a value written here would be an ordinary "
                "file, not a sealed secret output. Run this as job_run tool=ioc_scan with "
                "secret_output: true, and ask again there. Nothing was written."
            )
        self.path = Path(self.out) / self.NAME if enabled else None
        self.shown = ("store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), self.NAME)) if enabled else None

    def add(self, finding_id: str, locator: dict, value: str) -> None:
        if not self.enabled:
            return
        if self._fh is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Exclusively and private: a second run never overwrites a first's file.
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            self._fh = os.fdopen(fd, "w", encoding="utf-8")
        self._fh.write(json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=False))
        self._fh.write("\n")
        self.written += 1

    def close(self) -> None:
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self) -> dict:
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.written else None,
            "contains_secret_values": self.written > 0,
            "format": "JSON Lines, mode 0600: finding_id, file, offset, needle, encoding, value (the printable context around the match)" if self.written else None,
        }


class Locators:
    """Every locator goes to a file as it is found; the inline page is the view of them the caller asked for.
    The file is published when the page is not the whole (more rows than the page, or repeats hidden from it)."""

    def __init__(self, key, page_limit):
        self.limit, self.page, self.total, self.hidden = page_limit, [], 0, 0
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        name = "ioc_scan-%s.jsonl" % digest
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        self.tmp = self.fh = self.error = None
        self.written = 0
        self.stopped_at = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".ioc_scan-")
            self.tmp, self.fh = Path(tmp), os.fdopen(fd, "w", encoding="utf-8")
        except OSError as exc:
            self.error = "the whole result could not be kept (%s: %s)" % (self.path.parent, exc.strerror or exc)

    def add(self, row, show):
        self.total += 1
        if self.fh:
            if self.written < ROW_CAP:
                self.fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                self.written += 1
            elif self.stopped_at is None:
                self.stopped_at = row["offset"]
        if show and len(self.page) < self.limit:
            self.page.append(row)
        elif show is False:
            self.hidden += 1

    def finish(self):
        info = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self.fh:
            self.fh.flush()
            os.fsync(self.fh.fileno())
            self.fh.close()
            if self.total > len(self.page):
                os.replace(self.tmp, self.path)
                info["all_results"] = self.shown
                info["all_results_format"] = "JSON Lines, one locator per occurrence: finding_id, offset, needle, enc, context_length"
                if self.stopped_at is not None:
                    info["all_results_stopped_at_offset"] = self.stopped_at
                    info["all_results_cap_rows"] = ROW_CAP
            else:
                os.unlink(self.tmp)
        if self.error:
            info["all_results_error"] = self.error
        return info


def fail(message, **extra):
    print(json.dumps({"error": message, "tool": TOOL, **extra}))
    sys.exit(1)


def whole(args, key, default, low, high):
    value = args.get(key)
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        fail("%s is a whole number from %d to %d" % (key, low, high), **{key: value})
    return value


DEFAULT_NEEDLES = [
    "http://", "https://", "ftp://",
    "powershell", "cmd.exe", "rundll32", "mshta", "wscript", "cscript",
    "schtasks", "bitsadmin", "certutil", "regsvr32",
    "Invoke-", "IEX(", "-enc ", "FromBase64",
    "HKEY_", "CurrentVersion\\Run", "UserInit",
    "mimikatz", "meterpreter", "cobalt", "beacon",
    ".onion", "bitcoin", "ransom", "wallet",
    "psexec", "procexp", "sysinternals", "tcpview", "autoruns",
    "IEUser", "@gmail", "@yahoo", "@hotmail",
    "password", "Password", "C2", "user-agent", "User-Agent",
    ".exe", ".ps1", ".bat", ".vbs", ".js",
    "AppData\\", "\\Temp\\", "Downloads\\",
    "From:", "Subject:", "mailto:",
    "192.168.", "10.0.", "172.16.",
]


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments are a JSON object")
    path = args.get("path") or "inputs/[UNALLOCATED]"
    needles = args.get("needles")  # a list of strings, or a pipe-separated string
    if isinstance(needles, str):
        needles = [n for n in needles.split("|") if n]
    if needles is not None and (not isinstance(needles, list) or not all(isinstance(n, str) for n in needles)):
        fail("needles is a pipe-separated string or a list of strings")
    if not needles:
        needles = DEFAULT_NEEDLES
    needles = list(dict.fromkeys(needles))          # a needle given twice is one needle
    if len(needles) > NEEDLES_MAX:
        fail("at most %d needles" % NEEDLES_MAX, given=len(needles))
    max_hits = whole(args, "max_hits", 80, 1, HITS_MAX)
    context = whole(args, "context", 96, 0, CONTEXT_MAX)
    start = whole(args, "start", 0, 0, 1 << 62)
    length = args.get("length")
    if length is not None:
        length = whole(args, "length", None, 0, 1 << 62)
    chunk = whole(args, "chunk", CHUNK_DEFAULT, CHUNK_MIN, CHUNK_MAX)
    if args.get("skip_zeros", False):
        fail("skip_zeros would make the scan lossy and is not supported", hint="omit skip_zeros or pass false")
    unique_only = bool(args.get("unique_only", True))
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values is true or false")

    variants = []
    for n in needles:
        try:
            raw = n.encode("utf-8")
            wide = n.encode("utf-16le")
        except UnicodeEncodeError:
            fail("a needle is not text that can be encoded", needle_index=needles.index(n))
        if not raw:
            continue
        if len(raw) > NEEDLE_BYTES_MAX:
            fail("a needle is longer than %d bytes" % NEEDLE_BYTES_MAX, needle_index=needles.index(n))
        variants.append(("ascii", n, raw))
        variants.append(("utf16", n, wide))
    if not variants:
        fail("no needle to look for")
    longest = max(len(v[2]) for v in variants)

    if os.path.isdir(path):
        fail("a directory, not a file: scan one file at a time", path=path)
    if not os.path.isfile(path):
        fail("no such file", path=path)
    size = os.path.getsize(path)
    if start > size:
        fail("start is past the end of the file", start=start, size=size)
    end = size if length is None else min(size, start + length)

    try:
        secret = SecretValues(write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused")
    locators = Locators([path, needles, start, end, context, unique_only, size], max_hits)
    counts = defaultdict(int)
    seen = set()
    next_id = [0]

    def emit(at, kind, name, nb, buf, base):
        i = at - base
        s = max(0, i - BEFORE)
        e = min(len(buf), i + len(nb) + context)
        raw = buf[s:e]
        next_id[0] += 1
        fid = "F%06d" % next_id[0]
        counts[name] += 1
        row = {"finding_id": fid, "offset": at, "needle": name, "enc": kind, "context_length": len(raw)}
        show = True
        if unique_only:
            key = (name, kind, raw[:80])
            if key in seen:
                show = False
            elif len(seen) < SEEN_CAP:
                seen.add(key)
        locators.add(row, show)
        if write_values:
            text = "".join(chr(c) if 32 <= c < 127 else "." for c in raw)
            secret.add(fid, {"file": path, "offset": at, "needle": name, "encoding": kind}, text)

    # buf holds bytes [base, base + len(buf)); positions below `done` have been searched.
    # A position is searched once the context after a match there is in buf (or the range ended).
    scanned = start
    with open(path, "rb") as fh:
        fh.seek(start)
        buf, base, done = b"", start, start
        while True:
            data = fh.read(min(chunk, end - scanned)) if scanned < end else b""
            at_end = not data
            buf += data
            scanned += len(data)
            have = base + len(buf)
            process_end = have if at_end else have - (longest + context)
            if process_end > done:
                lo, hi = done - base, process_end - base
                a = lo
                while a < hi:
                    b = min(hi, a + SLICE)
                    found = []
                    for vi, (kind, name, nb) in enumerate(variants):
                        stop = min(len(buf), b + len(nb) - 1)
                        j = buf.find(nb, a, stop)
                        while j >= 0:
                            found.append((j, vi))
                            j = buf.find(nb, j + 1, stop)
                    found.sort()                      # by offset, then by needle order: the same list for any chunk
                    for j, vi in found:
                        kind, name, nb = variants[vi]
                        emit(base + j, kind, name, nb, buf, base)
                    a = b
                done = process_end
            if at_end:
                break
            keep_from = max(0, (done - BEFORE) - base)
            buf, base = buf[keep_from:], base + keep_from
    secret.close()
    page = locators.finish()
    result = {
        "tool": TOOL,
        "path": path,
        "source": {"path": path, "bytes": size, "address_space": "the bytes of this file as given; a container (E01, VMDK) is not decoded"},
        "scanned_start": start,
        "scanned_end": scanned,
        "bytes_scanned": scanned - start,
        "requested": {"start": start, "length": length, "end": end},
        "complete": scanned >= end,
        "size": size,
        "case_sensitive": True,
        "match_policy": "every occurrence by its start offset, overlapping ones included; a needle is searched as given (UTF-8) and as UTF-16LE",
        "context": {"after_bytes": context, "before_bytes": BEFORE, "returned_inline": False,
                    "note": "context bytes are not returned: they are where a secret sits. write_values: true, in a job run with secret_output: true, writes them to a file under $OUT."},
        "hit_count_returned": page["returned"],
        "counts": dict(sorted(counts.items(), key=lambda kv: -kv[1])),
        "hits": locators.page,
        **page,
        "secret_values": secret.summary(),
    }
    if unique_only and locators.hidden:
        result["repeats_hidden_inline"] = locators.hidden
        result["repeats_note"] = "occurrences whose context repeats one already listed are not in the inline page; every one is in all_results"
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

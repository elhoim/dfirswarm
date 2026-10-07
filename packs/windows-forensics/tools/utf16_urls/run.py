#!/usr/bin/env python3
"""String candidates for URLs, `file:` and `Visited:` entries and 192.168.x.x addresses in a file.

This is a STRING SCANNER, not a browser parser. It says where a URL-shaped or history-shaped run of
characters is in the bytes of a file, in two encodings:

  ascii     `http://` or `https://` followed by at least six URL characters, to the first byte that is not
            one. No length is cut off: a URL of any length is returned whole.
  utf16le   a run of at least eight printable ASCII characters, each stored in two bytes (the second 0),
            that contains `http`, `file:`, `visited:` or `192.168`. A character outside printable ASCII
            ends the run, so a URL with a non-ASCII character in it is found only up to it; the run is
            everything printable around the anchor, not a parsed URL.

Every occurrence is kept, with its byte offset and its encoding: an offset is where the run starts, and
the same text twice is two candidates. A `groups` view lists each distinct text once with its occurrence
count and first offset (bounded: past `max_distinct` distinct texts the view stops growing and says so; every
occurrence is still in the candidates). A string is a candidate: nothing here says it was visited, typed,
downloaded or opened by anyone.

The file is read in windows of `chunk` bytes with a carry, never whole, so a match that straddles a window
is found once. A run that touches the end of a window and is longer than the carry is cut there and goes on in
the next window as a piece (`continued: true` on every piece but the last), so the memory is bounded and no
character is lost.
"""
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

PARSER = "utf16_urls/2"
DEFAULT_CHUNK = 8 * 1024 * 1024
CARRY = 64 * 1024
URL_CHARS = rb"[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]"
ASCII_START = re.compile(rb"https?://" + URL_CHARS + rb"{6,}")
ASCII_CONT = re.compile(URL_CHARS + rb"+")
UTF16_START = re.compile(rb"(?:[\x20-\x7e]\x00){8,}")
UTF16_CONT = re.compile(rb"(?:[\x20-\x7e]\x00)+")
UTF16_ANCHORS = ("http", "file:", "visited:", "192.168")


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

    def _cannot_write(self, exc: BaseException) -> None:
        """The whole result cannot be kept: say so as JSON and stop, never a traceback."""
        import sys as _sys
        _sys.stdout.write(json.dumps({
            "error": "the whole result (%d rows so far) cannot be written to %s: %s. Outside a job the place is your own "
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, exc),
            "status": "failed",
        }) + "\n")
        _sys.exit(1)

    def _write(self, row: object) -> None:
        assert self._out is not None
        text = json.dumps(row, ensure_ascii=False, default=str)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate (a file name that is not UTF-8): escape it, lose nothing.
            text = json.dumps(row, ensure_ascii=True, default=str)
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            self._cannot_write(exc)

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(
                    dir=self.path.parent, prefix=f".{self.path.name}-"
                )
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
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
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                os.replace(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result



def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


class Spec:
    """One encoding's scanner state: where its first undecided byte is, and whether a run was cut at a window's end."""

    def __init__(self, name, start, cont, width):
        self.name = name
        self.start = start
        self.cont = cont
        self.width = width            # bytes per character
        self.done_to = 0              # absolute offset: everything before it is decided
        self.continuing = False
        self.run_start = None
        self.anchor_ok = False


def window(spec, buf, base, eof, emit):
    """Decide the candidates of `spec` in buf (absolute offset base)."""
    n = len(buf)
    pos = max(spec.done_to - base, 0)
    if spec.continuing and spec.done_to >= base:
        m = spec.cont.match(buf, pos)
        if m and m.end() > pos:
            more = m.end() >= n - (spec.width - 1) and not eof
            emit(spec, base + pos, buf[pos:m.end()], more, True)
            spec.done_to = base + m.end()
            pos = m.end()
            spec.continuing = more
            if more:
                return
        else:
            spec.continuing = False
    while True:
        m = spec.start.search(buf, pos)
        if not m:
            break
        touches = m.end() >= n - (spec.width - 1) and not eof     # a half character at the end is part of the run
        if touches:
            if m.start() >= n - CARRY:
                break                      # undecided: the next window starts at the carry and sees all of it
            emit(spec, base + m.start(), buf[m.start():m.end()], True, False)
            spec.continuing = True
            spec.done_to = base + m.end()
            return
        emit(spec, base + m.start(), buf[m.start():m.end()], False, False)
        spec.done_to = base + m.end()
        pos = m.end()


def main():
    try:
        d = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(d, dict):
        fail("the arguments must be a JSON object")
    path = d.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the file to scan")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    contains = d.get("contains") or ""
    if not isinstance(contains, str):
        fail("contains must be a string")
    contains = contains.lower()
    limit = d.get("limit", 200)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        fail("limit must be a positive integer", limit=d.get("limit"))
    chunk = d.get("chunk", DEFAULT_CHUNK)
    if isinstance(chunk, bool) or not isinstance(chunk, int) or not 2 * CARRY <= chunk <= 256 * 1024 * 1024:
        fail("chunk must be a whole number of bytes from %d to 268435456" % (2 * CARRY), chunk=d.get("chunk"))
    max_distinct = d.get("max_distinct", 100000)
    if isinstance(max_distinct, bool) or not isinstance(max_distinct, int) or max_distinct < 1:
        fail("max_distinct must be a positive integer", max_distinct=d.get("max_distinct"))

    out = LosslessPage("utf16_urls", [path, contains], limit)
    groups = {}
    totals = {"ascii": 0, "utf16le": 0, "filtered_out": 0, "pieces": 0}
    state = {"groups_complete": True}

    def emit(spec, offset, raw, more, is_cont):
        text = raw.decode("ascii", "replace") if spec.width == 1 else raw[::2].decode("ascii", "replace")
        if spec.name == "utf16le":
            if not is_cont and not any(a in text.lower() for a in UTF16_ANCHORS):
                return
            if not is_cont:
                spec.anchor_ok = True
            elif not spec.anchor_ok and not any(a in text.lower() for a in UTF16_ANCHORS):
                return
        if contains and contains not in text.lower():
            totals["filtered_out"] += 1
            return
        row = {"encoding": spec.name, "offset": offset, "length_bytes": len(raw), "text": text}
        if more or is_cont:
            row["continued"] = bool(more)
            row["piece_of_a_longer_run"] = True
            totals["pieces"] += 1
        out.add(row)
        totals[spec.name] += 1
        key = (spec.name, text)
        g = groups.get(key)
        if g is not None:
            g[0] += 1
        elif len(groups) < max_distinct:
            groups[key] = [1, offset]
        else:
            state["groups_complete"] = False

    ascii_spec = Spec("ascii", ASCII_START, ASCII_CONT, 1)
    utf16_spec = Spec("utf16le", UTF16_START, UTF16_CONT, 2)
    size = os.path.getsize(path)
    scanned = 0
    with open(path, "rb") as fh:
        carry = b""
        base = 0
        nxt = fh.read(chunk)
        while True:
            data, nxt = nxt, fh.read(chunk) if nxt else b""
            eof = not nxt
            buf = carry + data
            scanned += len(data)
            window(ascii_spec, buf, base, eof, emit)
            window(utf16_spec, buf, base, eof, emit)
            if eof:
                break
            keep = min(CARRY, len(buf))
            base += len(buf) - keep
            carry = buf[len(buf) - keep:]

    page = out.finish()
    distinct = LosslessPage("utf16_urls-groups", [path, contains, "groups"], limit)
    for (enc, text), (count, first) in sorted(groups.items(), key=lambda kv: kv[1][1]):
        distinct.add({"text": text, "encoding": enc, "occurrences": count, "first_offset": first})
    group_page = distinct.finish()
    answer = {
        "parser": PARSER,
        "status": "complete",
        "path": path,
        "file_bytes": size,
        "bytes_scanned": scanned,
        "candidates": out.page,
        "candidate_count": page["matched"],
        "by_encoding": {"ascii": totals["ascii"], "utf16le": totals["utf16le"]},
        "filtered_out_by_contains": totals["filtered_out"],
        "pieces": totals["pieces"],
        "groups": distinct.page,
        "distinct_count": group_page["matched"],
        "groups_complete": state["groups_complete"],
        "groups_page": group_page,
        **page,
        "note": "These are string candidates: where a URL-shaped or history-shaped run of characters is in the bytes, not "
                "a parsed browser record. A string does not say it was visited, typed, downloaded or opened, or by whom. "
                "UTF-16LE runs are matched only where every character is printable ASCII.",
    }
    print(json.dumps(answer, ensure_ascii=False))


if __name__ == "__main__":
    main()

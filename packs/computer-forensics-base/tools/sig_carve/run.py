#!/usr/bin/env python3
"""Scan one file for known file signatures, in one pass, and list every offset.

A signature scan, not a carver: it finds where a header's bytes occur and returns the
offsets with a short preview, and it estimates no sizes. A hit is where the bytes
occur: it may be inside a file, a string or an unrelated blob, so a decisive hit is
cut with `file_carver` (or read in place) and checked with a parser of that format.
Every signature is looked for in the same single read of the file, with a carry of
the longest header less one byte between reads, so a header cut by a read boundary
is found once, at its true offset. The result says what file and what range were
scanned. It reads the file as given: an E01 or another container is its container
bytes, not the disk inside.
"""
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

TOOL = {"name": "sig_carve", "version": 2}
WINDOW = 8 * 1024 * 1024
CONTEXT_MAX = 4096
HITS_MAX = 1_000_000
ROWS_PER_SIGNATURE = 2_000_000       # rows kept in the whole-result file per signature; counting goes on past it

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


class SafePage(LosslessPage):
    """The pager, with a whole-result file that may not be writable (a read-only run directory, a full disk).

    The count and the page stay whole; the answer says the file was not written (all_results_error) and no
    half file is left. LosslessPage itself is the pager every library tool carries, byte for byte.
    """

    error = None

    def _give_up(self, exc):
        self.error = "%s: %s" % (self.path.parent, exc.strerror or exc)
        if self._out is not None:
            try:
                self._out.close()
            except OSError:
                pass
            self._out = None
        if self._tmp is not None:
            try:
                self._tmp.unlink()
            except OSError:
                pass
            self._tmp = None

    def add(self, row):
        if self.error is not None:
            self.total += 1
            if len(self.page) < self.limit:
                self.page.append(row)
            return
        try:
            super().add(row)
        except OSError as exc:
            self._give_up(exc)

    def finish(self):
        if self.error is None:
            try:
                return super().finish()
            except OSError as exc:
                self._give_up(exc)
        return {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
            "all_results_error": (
                "the whole result could not be written (%s); the hits past the page are counted, not listed: "
                "run again with a larger max_hits, or in a place that can be written" % self.error
            ),
        }


# File signatures: name -> (header_hex, where the candidate file starts relative to the hit, note)
SIGS = {
    "MZ":    ("4D5A", 0, "PE or DOS executable: two bytes, so many hits are not executables"),
    "PK":    ("504B0304", 0, "a ZIP local file header (also docx, xlsx, jar, apk)"),
    "regf":  ("72656766", 0, "a registry hive base block"),
    "MAM":   ("4D414D", 0, "three bytes: also inside text; MAM prefetch is PCH"),
    "SCCA":  ("53434341", -4, "an uncompressed prefetch file's signature, which sits 4 bytes after its start (after the version)"),
    "EVTX":  ("456C6646696C6500", 0, "an event log file header (ElfFile)"),
    "OLE":   ("D0CF11E0A1B11AE1", 0, "an OLE2 compound file (Office 97-2003, MSI, Jump Lists)"),
    "LNK":   ("4C0000000114020000000000C000000000000046", 0, "a Windows shortcut header"),
    "SQLite":("53514C69746520666F726D6174203300", 0, "a SQLite database header"),
    "RAR":   ("526172211A0700", 0, "a RAR (version 4) archive"),
    "7z":    ("377ABCAF271C", 0, "a 7-Zip archive"),
    "GZ":    ("1F8B08", 0, "a gzip stream"),
    "BZ2":   ("425A68", 0, "three bytes: a bzip2 stream, or text"),
    "PDF":   ("255044462D", 0, "a PDF header"),
    "PNG":   ("89504E470D0A1A0A", 0, "a PNG header"),
    "JFIF":  ("FFD8FFE0", 0, "a JPEG (JFIF) start"),
    "PCH":   ("4D414D04", 0, "a compressed (MAM) prefetch file"),
}


def fail(message, **extra):
    print(json.dumps({"ok": False, "error": message, "tool": TOOL, **extra}))
    raise SystemExit(1)


def whole_number(args, key, default, low, high):
    value = args.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        fail("%s is a whole number from %d to %d" % (key, low, high), **{key: value})
    return value


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments are a JSON object")
    path = args.get("path", "")
    sig_name = args.get("sig") or "all"
    context = whole_number(args, "context", 64, 0, CONTEXT_MAX)
    max_hits = whole_number(args, "max_hits", 500, 1, HITS_MAX)
    window = whole_number(args, "window_bytes", WINDOW, 16, 256 * 1024 * 1024)
    if not isinstance(path, str) or not path:
        fail("path is required: the binary file to scan")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    if not isinstance(sig_name, str):
        fail("sig is a signature name or all", sig=sig_name, signatures=sorted(SIGS))
    if sig_name != "all" and sig_name not in SIGS:
        fail("no such signature", sig=sig_name, signatures=sorted(SIGS), hint="sig is one of these names, or all")
    chosen = SIGS if sig_name == "all" else {sig_name: SIGS[sig_name]}
    headers = {name: bytes.fromhex(h) for name, (h, _a, _n) in chosen.items()}
    carry_len = max(len(h) for h in headers.values()) - 1
    size = os.path.getsize(path)
    pages = {name: SafePage("sig_carve-" + name, [path, name, size, context], max_hits) for name in chosen}
    totals = {name: 0 for name in chosen}
    capped = {}

    def preview(fh, window, base, at):
        """The bytes from a hit to `context` bytes on, from the window when it holds them, else from the file."""
        i = at - base
        if i + context <= len(window):
            return window[i:i + context]
        fh.seek(at)
        return fh.read(context)

    scanned = 0
    with open(path, "rb") as fh:
        carry = b""
        pos = 0
        while pos < size:
            block = fh.read(min(window, size - pos))
            if not block:
                break
            buf = carry + block
            base = pos - len(carry)
            for name, header in headers.items():
                i = buf.find(header)
                while i >= 0:
                    # A hit wholly inside the carry was found in the window before: it is counted once.
                    if i + len(header) > len(carry):
                        at = base + i
                        totals[name] += 1
                        if totals[name] <= ROWS_PER_SIGNATURE:
                            snippet = preview(fh, buf, base, at) if context else b""
                            row = {"offset": at, "hex_preview": snippet[:32].hex(" "),
                                   "ascii_preview": "".join(chr(b) if 32 <= b < 127 else "." for b in snippet[:64])}
                            adjust = chosen[name][1]
                            if adjust and at + adjust >= 0:
                                row["candidate_start"] = at + adjust
                            pages[name].add(row)
                        elif name not in capped:
                            capped[name] = at
                    i = buf.find(header, i + 1)
            fh.seek(pos + len(block))          # a preview may have moved the file position
            carry = buf[-carry_len:] if carry_len else b""
            pos += len(block)
            scanned = pos
    results = {}
    for name in chosen:
        page = pages[name].finish()
        entry = {"count": totals[name], "hits": pages[name].page, **page, "matched": totals[name], "note": chosen[name][2]}
        entry["truncated"] = totals[name] > len(pages[name].page)
        if name in capped:
            entry["rows_file_stopped_at_offset"] = capped[name]
            entry["rows_file_cap"] = ROWS_PER_SIGNATURE
        results[name] = entry
    print(json.dumps({
        "tool": TOOL,
        "source": {"path": path, "bytes": size, "address_space": "the bytes of this file as given; a container (E01, VMDK) is not decoded"},
        "scanned": {"start": 0, "end": scanned, "bytes": scanned, "complete": scanned == size, "passes": 1,
                    "window_bytes": window, "carry_bytes": carry_len},
        "context_bytes": context,
        "signatures": results,
        "note": "A hit is where a header's bytes occur, not a file: cut it with file_carver or read it in place and check it with a parser of that format. "
                "A signature that is not listed here, an encrypted or compressed region and a file split across the scan's source are not found by this scan.",
    }, indent=2))


if __name__ == "__main__":
    main()

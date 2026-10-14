#!/usr/bin/env python3
"""Read the structure of a document from its bytes, and never as an application would open it.

doc_probe says what a byte search finds; this tool reads the container. Four containers, each read to the depth
its format lets a standard-library reader go, and for each structure the answer says whether it was read whole:

    OLE compound file   the header, the FAT and mini FAT, the directory (every entry, with the entries no storage
                        reaches), stream sizes and times; the VBA project (the `dir` stream is decompressed, each
                        module's stream and the size of its compressed source are listed; source is written out
                        only when asked for); the encryption structures that the Office formats record (the
                        EncryptionInfo stream, the Word FIB flags, the Excel FILEPASS record, the PowerPoint
                        header token); Excel sheet kinds from the BOUNDSHEET records
    OOXML / ZIP         the central directory, [Content_Types].xml, the document and workbook protection
                        elements, and each vbaProject.bin read as an OLE compound file
    PDF                 the cross-reference chain (tables and streams, hybrid files, every revision), the objects
                        with their stream filters, object streams, the trailer's encryption dictionary read, the
                        catalog's actions and the way they are triggered, embedded files, the page tree
    RTF                 group structure and nesting, control words, the object groups with their class names and
                        the decoded start of their data, fields and templates

Nothing here executes a document, a macro, a script or an embedded object, and nothing is fetched. A password
verifier, a salt, a hash or an encrypted value that a structure holds is reported as present and by length, never as
bytes. Streams are decoded only under budgets (a stream, all streams together, an expansion ratio, a depth, a
count of objects and a clock), and a budget that is reached is a limit in the answer, not a clean result.
"""
import array
import base64
import errno
import hashlib
import io
import json
import mmap
import os
import re
import struct
import sys
import time
import xml.parsers.expat
import zipfile
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

TOOL = {"name": "doc_structure", "version": 1}
PARSER = "doc_structure/1"
NOTE = ("Static structure only. A structure shows what the file holds, not what an application would do with it: an action, a macro, "
        "a field or an external target does not show that anything ran or was fetched. Record what was read and what was not before "
        "drawing an absence conclusion. A string out of the file is shown with each backslash written twice and each control character as \\xNN.")

DEFAULT_STREAM = 16 << 20           # bytes one stream may be read or expand to
DEFAULT_TOTAL = 128 << 20           # bytes all streams may be read or expand to, together
DEFAULT_ENTRIES = 10000             # OLE directory entries and ZIP members read
DEFAULT_OBJECTS = 200000            # PDF objects indexed
DEFAULT_DEPTH = 256                 # nesting followed: RTF groups, PDF structures, OLE storages
DEFAULT_RATIO = 1000                # expanded bytes per compressed byte
DEFAULT_LIMIT = 1000                # rows of one table in the answer; the whole of a longer one is in a file
MAX_ENTRIES = 100000
MAX_OBJECTS = 2000000
MAX_DEPTH = 10000
DEFAULT_SECONDS = 100               # the tool's own clock: below the manifest's 120 s, so a slow file is a partial answer, not a kill
MAX_SECONDS = 110
RATIO_FLOOR = 1 << 20
MAX_DIRECTORY_ENTRIES = 100000
MAX_DIRECTORY_BYTES = 64 << 20
MIN_ENTRY = 46
METHODS_READ = (0, 8)
HEAD_BYTES = 1024
MAX_PROBLEMS = 100
PAGE = 1 << 16
MAX_EXTRACT = 64

# BEGIN SHARED WITHHOLDING
# The same text is in pcap_extract, zeek_run, suricata_run and network_log_summary, so that the four tools withhold
# the same strings; tests/pack-network-withholding.test.ts holds the copies equal. An identifier-shaped string is
# withheld wherever the tool would print one: a name, a path component, a URL, a message that quotes either.
COUNTS = {"names": 0, "urls": 0, "text": 0}
# A run of name characters long enough to be a token. `=` is only a padding at the end (so a key= prefix stays);
# `/` joins pieces of a base64 token and is handled apart, below.
_RUN = re.compile(r"[A-Za-z0-9_+%-]{20,}={0,2}|[A-Za-z0-9_+%-]{14,}={2}")
_SLASHED = re.compile(r"[A-Za-z0-9_+/%-]{30,}={0,2}")
_HEX = re.compile(r"[0-9a-fA-F]{32,}")
_PREFIXED = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                       r"|xox[abeprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}"
                       r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"
                       r"|(?i:basic|bearer)\s+[A-Za-z0-9+/=._~-]{8,}")
# User-info: after `//` (a URL, or a scheme-relative one), or bare as name:password@host. A mailto: address is not one.
_USERINFO = re.compile(r"(?<=//)[^/?#\s@]+(?=@)")
_BARE_USERINFO = re.compile(r"(?<![\w.%+:/-])(?!mailto:)[\w.%+-]{1,64}:[^\s/@:]{1,128}(?=@[\w\[])")


def _withheld(what, length, kind):
    COUNTS[kind] = COUNTS.get(kind, 0) + 1
    return ("<%s withheld %d characters>" % (what, length)) if what else ("<withheld %d characters>" % length)


def _token_run(run):
    """Is this run of name characters shaped like a token, and not like words, dates or versions?"""
    if _HEX.search(run):
        return True
    chunks = [(m.group()[0].isdigit(), m.start(), m.end()) for m in re.finditer(r"[A-Za-z]+|[0-9]+", run)]
    # digits packed between letters ("a9b2c7"), which words, dates and versions do not do
    packed = 0
    for i, (is_digit, start, end) in enumerate(chunks):
        if not is_digit or end - start > 3:
            continue
        before = i > 0 and not chunks[i - 1][0] and chunks[i - 1][2] == start
        after = i + 1 < len(chunks) and not chunks[i + 1][0] and chunks[i + 1][1] == end
        packed += 1 if before or after else 0
    if packed >= 3:
        return True
    letters = [c for c in run if c.isalpha()]
    case_flips = sum(1 for a, b in zip(letters, letters[1:]) if a.islower() != b.islower())
    if len(letters) >= 20 and case_flips >= max(8, 0.4 * len(letters)):
        return True
    if run.endswith("==") and len(run) >= 16:
        return True
    if run.endswith("=") and len(run) >= 24:
        return True
    return len(run) >= 40 and run.isalnum() and any(c.isdigit() for c in run) and any(c.isalpha() for c in run)


def _randomish(piece):
    """A piece of a path that is not a plain word: digits among letters, or capitals inside a word."""
    if len(piece) < 4 or "." in piece or re.fullmatch(r"[A-Z][a-z]+", piece):
        return False
    letters = [c for c in piece if c.isalpha()]
    mixed = any(c.islower() for c in letters) and any(c.isupper() for c in letters)
    return (any(c.isdigit() for c in piece) and bool(letters)) or mixed


def token_spans(text):
    spans = [m.span() for m in _PREFIXED.finditer(text)]
    for m in _RUN.finditer(text):
        if _token_run(m.group()):
            spans.append(m.span())
    # A base64 token holds `/`: pieces too short to be one alone (an AWS-style secret has two) are caught as a whole.
    for m in _SLASHED.finditer(text):
        run = m.group()
        if "/" in run and sum(1 for p in run.split("/") if _randomish(p)) >= 3 and re.search(r"[0-9+]", run):
            spans.append(m.span())
    # A flagged piece takes the random-looking pieces next to it across a `/`: the head of a token is not printed.
    grown = []
    for start, end in spans:
        while start > 1 and text[start - 1] == "/":
            m = re.search(r"[A-Za-z0-9_+%-]+$", text[:start - 1])
            if not m or not _randomish(m.group()):
                break
            start = m.start()
        while end < len(text) - 1 and text[end] == "/":
            m = re.match(r"[A-Za-z0-9_+%-]+={0,2}", text[end + 1:])
            if not m or not _randomish(m.group()):
                break
            end = end + 1 + m.end()
        grown.append((start, end))
    grown.sort()
    merged = []
    for start, end in grown:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def token_shaped(text):
    return bool(token_spans(text))


def scrub(text, kind="text"):
    """The text with every token-shaped run and every user-info withheld."""
    text = _USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), text)
    text = _BARE_USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), text)
    out, last = [], 0
    for start, end in token_spans(text):
        out.append(text[last:start])
        out.append(_withheld("token-shaped text", end - start, kind))
        last = end
    out.append(text[last:])
    return "".join(out)


def redact_url(url):
    """A URL or request target without its user-info, its token-shaped path text, its query values or its fragment."""
    rest, fragment = (url.split("#", 1) + [None])[:2]
    rest, query = (rest.split("?", 1) + [None])[:2]
    scheme = authority = ""
    m = re.match(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)([^/]*)(.*)$", rest, re.S)
    if m:
        scheme, authority, rest = m.group(1), m.group(2), m.group(3)
        if "@" in authority:
            userinfo, authority = authority.rsplit("@", 1)
            authority = _withheld("userinfo", len(userinfo), "urls") + "@" + authority
    out = scheme + authority + scrub(rest, "urls")
    if query is not None:
        pairs = []
        for pair in query.split("&"):
            name, eq, value = pair.partition("=")
            pairs.append(scrub(name, "urls") + (eq + _withheld("", len(value), "urls") if eq else ""))
        out += "?" + "&".join(pairs)
    if fragment is not None:
        out += "#" + _withheld("", len(fragment), "urls")
    return out


def cell(value):
    """Text for one tab-separated cell or one printed path: no tab or line break, and a byte that was not UTF-8
    (a lone surrogate) written as \\xNN, so that no writer raises on it."""
    text = value if isinstance(value, str) else str(value)
    out = []
    for ch in text:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)
# END SHARED WITHHOLDING


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)), "text")


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


VALUES = [None]    # the values file of this call, once it exists: an answer that fails after it was created names it


def shown_path(text):
    """A path as it may be printed: each component with anything token-shaped, or with user-info, withheld. A path is
    tested component by component, as an OPC part name or a file name is a path and not one token."""
    if not isinstance(text, str):
        return text
    return "/".join(scrub(part, "names") for part in text.split("/"))


def shown_deep(value, key=""):
    if key in ("head_hex", "tool"):
        return value
    if isinstance(value, str):
        return shown_path(value)
    if isinstance(value, list):
        return [shown_deep(v) for v in value]
    if isinstance(value, dict):
        return {k: shown_deep(v, k) for k, v in value.items()}
    return value


def fail(message, **extra):
    status = extra.pop("status", "failed")
    answer = {"error": scrub(message), "status": status, "tool": TOOL, **shown_deep(extra)}
    if VALUES[0] is not None:
        answer["secret_values"] = VALUES[0].summary()
    print(json.dumps(answer))
    raise SystemExit(1)


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place outside it, the run directory itself,
    or anything under inputs/ is refused, and in a job so is anything outside $OUT, the one place a job writes.

    A string check is not enough: `work/../inputs/x`, an absolute path and a symlink that points out all name a
    place the tool must not write, and none of them starts with "inputs/". Resolving first and comparing
    directories is what actually holds, and the read-only inputs are the one place extracted bytes must never
    appear -- a later integrity check would report the evidence as modified.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    if in_job():
        job_out = Path(os.environ["OUT"]).resolve()
        if dest != job_out and job_out not in dest.parents:
            fail("in a job %s is a directory under $OUT, the one place a job writes" % what, **{what: str(out), "out": str(job_out)})
    return str(dest.relative_to(root))


# --- lossless paging ------------------------------------------------------------------------------------------------

class LosslessPage:
    """The first `limit` rows of a table in the answer; when there are more, the whole table as JSON Lines in a
    file that is created exclusively (under a new name when the name is taken) and named in the answer. A table
    that cannot be written whole says so."""

    def __init__(self, tool, key, limit):
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page = []
        self.total = 0
        self._out = None
        self.shown = None
        self.not_written = None
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8", "surrogatepass")).hexdigest()[:16]
        self.stem = "%s-%s" % (self.tool, digest)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if out:
            self.dir = Path(out) / "tool-output"
            self.prefix = ("store/jobs/%s/out/tool-output/" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)) if job else str(self.dir) + "/"
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.dir = Path("work") / agent / "tool-output"
            self.prefix = str(self.dir) + "/"

    def _open(self):
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            for n in range(1, 100):
                name = "%s.jsonl" % self.stem if n == 1 else "%s-%d.jsonl" % (self.stem, n)
                try:
                    fd = os.open(str(self.dir / name), flags, 0o600)
                except FileExistsError:
                    continue
                self.shown = self.prefix + name
                self._out = os.fdopen(fd, "w", encoding="utf-8")
                for kept in self.page:
                    self._write(kept)
                return
            self.not_written = "ninety-nine files of this name already exist in %s" % self.dir
        except OSError as exc:
            self.not_written = "the file could not be created in %s (%s)" % (self.dir, describe(exc))

    def _write(self, row):
        self._out.write(json.dumps(row, default=str))
        self._out.write("\n")

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None and self.not_written is None:
            self._open()
        if self._out is not None:
            try:
                self._write(row)
            except OSError as exc:
                self.not_written = "writing the file failed (%s)" % describe(exc)
                self._out = None

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
            except OSError as exc:
                self.not_written = "writing the file failed (%s)" % describe(exc)
            else:
                result["all_results"] = self.shown
                result["all_results_format"] = "JSON Lines, one complete row per line"
        if self.not_written:
            result["not_written"] = self.not_written
        return result


# --- values the answer does not carry ----------------------------------------------------------------------------------

class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The secret-safe output pattern (recovery_key_scan is the reference implementation), with one change: a row is
    written as JSON escapes, so that a name that is not UTF-8 cannot raise. Call `add` once per finding with its id,
    its locator and the value. With `enabled` false it writes nothing and `summary()` says so.
    """

    NAME = "doc-structure-values.jsonl"

    def __init__(self, enabled):
        self.enabled = enabled
        self.written = 0
        self._fh = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        self.path = None
        self.shown = None
        if not enabled:
            return
        if not (self.job and self.out):
            raise SecretValuesRefused(
                "write_values is refused outside a job: a value written here would be an ordinary "
                "file, not a sealed secret output. Run this as job_run tool=doc_structure with "
                "secret_output: true, and ask again there. Nothing was written."
            )
        self.path = Path(self.out) / self.NAME
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), self.NAME)
        # Created now, before anything is read: a file or a link already at that name is refused by name at once
        # (O_EXCL does not follow a link, a dangling one included), instead of failing, or writing through it,
        # after the read. With nothing withheld it stays an empty file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id, locator, value):
        if not self.enabled or self._fh is None:
            return
        self._fh.write(json.dumps({"finding_id": finding_id, **locator, "value": value}))
        self._fh.write("\n")
        self.written += 1

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self):
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            "format": ("JSON Lines, mode 0600: finding_id, the locator of the finding, value (the whole, unredacted text: a target, an instruction, "
                       "the real name behind a withheld one)") if self.enabled else None,
        }


class Names:
    """The real name behind every name withheld from the answer: a private file (mode 0600, created exclusively, in the
    tool-output directory) written at the moment a name is withheld, whether or not write_values was given, so that no name
    is lost; with write_values the values file holds them as well. The answer names the file."""

    NAME = "doc-structure-withheld-names"

    def __init__(self, values):
        self.values = values
        self.count = 0
        self._fh = None
        self.shown = None
        self.error = None
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if out:
            self.dir = Path(out) / "tool-output"
            self.prefix = ("store/jobs/%s/out/tool-output/" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)) if job else str(self.dir) + "/"
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.dir = Path("work") / agent / "tool-output"
            self.prefix = str(self.dir) + "/"

    def add(self, real, shown, kind="part_name"):
        self.count += 1
        finding_id = "N%06d" % self.count
        self.values.add(finding_id, {"kind": kind}, real)
        if self._fh is None and self.error is None:
            try:
                self.dir.mkdir(parents=True, exist_ok=True)
                for n in range(1, 100):
                    name = "%s.jsonl" % self.NAME if n == 1 else "%s-%d.jsonl" % (self.NAME, n)
                    try:
                        fd = os.open(str(self.dir / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                    except FileExistsError:
                        continue
                    self._fh = os.fdopen(fd, "w", encoding="utf-8")
                    self.shown = self.prefix + name
                    break
                else:
                    self.error = "ninety-nine files of this name already exist"
            except OSError as exc:
                self.error = "the file could not be created in %s (%s)" % (self.dir, describe(exc))
        if self._fh is not None:
            self._fh.write(json.dumps({"finding_id": finding_id, "kind": kind, "name": real, "shown": shown}) + "\n")
            self._fh.flush()
        return finding_id

    def close(self):
        if self._fh is not None:
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._fh.close()
            except OSError:
                pass
            self._fh = None


# --- ZIP reading: the end record, then members under budgets ----------------------------------------------------

class Budget:
    def __init__(self, member, total, ratio):
        self.member, self.total, self.ratio, self.used = member, total, ratio, 0


class Unreadable(Exception):
    def __init__(self, kind, reason):
        Exception.__init__(self, reason)
        self.kind, self.reason = kind, reason


# --- ZIP: the end record, then members under budgets ------------------------------------------------------------------------

class ZipProblem(Exception):
    pass


def zip_directory(fh, size):
    """The end record the tool chooses, and what it names: {total, cd_size, cd_off, eocd_at, others}. The choice is the last end
    record in the last 64 KiB whose comment fits the file; `others` lists every other signature there, because a reader that
    chooses differently lists another directory. The zip64 record is read when the end record holds its sentinels. Nothing here
    depends on the standard library's validators."""
    tail_len = min(size, 65557)
    fh.seek(size - tail_len)
    tail = fh.read(tail_len)
    found, pos = [], tail.find(b"PK\x05\x06")
    while pos >= 0:
        found.append(pos)
        pos = tail.find(b"PK\x05\x06", pos + 1)
    plausible = [p for p in found if p + 22 <= len(tail) and p + 22 + struct.unpack_from("<H", tail, p + 20)[0] <= len(tail)]
    if not plausible:
        raise ZipProblem("no end of central directory record in the last %d bytes of the file" % tail_len)
    pos = plausible[-1]
    _sig, _disk, _cd_disk, _n_disk, total, cd_size, cd_off, _clen = struct.unpack_from("<IHHHHIIH", tail, pos)
    eocd_at = size - tail_len + pos
    others = [size - tail_len + p for p in found if p != pos]
    if total == 0xFFFF or cd_size == 0xFFFFFFFF or cd_off == 0xFFFFFFFF:
        if eocd_at < 20:
            raise ZipProblem("the end record holds zip64 values and there is no room for the zip64 locator")
        fh.seek(eocd_at - 20)
        locator = fh.read(20)
        if locator[:4] != b"PK\x06\x07":
            raise ZipProblem("the end record holds zip64 values and no zip64 locator precedes it")
        _s, _d, record_at, _n = struct.unpack("<IIQI", locator)
        fh.seek(record_at)
        record = fh.read(56)
        if len(record) < 56 or record[:4] != b"PK\x06\x06":
            raise ZipProblem("the zip64 end of central directory record is not where its locator says")
        total, cd_size, cd_off = struct.unpack_from("<QQQ", record, 32)
    if cd_off + cd_size > size:
        raise ZipProblem("the central directory (offset %d, %d bytes) lies outside the %d-byte file" % (cd_off, cd_size, size))
    return {"total": total, "cd_size": cd_size, "cd_off": cd_off, "eocd_at": eocd_at, "others": others}


class Window(io.RawIOBase):
    """The first `limit` bytes of a file, with the end record's comment length read as 0: the ZIP reader sees the archive up to
    the end record the tool chose, so that it lists the directory the tool counted and not one hidden in a comment."""

    def __init__(self, fh, limit, zero_at):
        self._fh, self._limit, self._zero_at, self._pos = fh, limit, zero_at, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self._pos

    def seek(self, offset, whence=0):
        base = {0: 0, 1: self._pos, 2: self._limit}[whence]
        self._pos = max(0, base + offset)
        return self._pos

    def readinto(self, buffer):
        n = max(0, min(len(buffer), self._limit - self._pos))
        if not n:
            return 0
        self._fh.seek(self._pos)
        data = bytearray(self._fh.read(n))
        for at in (self._zero_at, self._zero_at + 1):
            if self._pos <= at < self._pos + len(data):
                data[at - self._pos] = 0
        buffer[:len(data)] = data
        self._pos += len(data)
        return len(data)


def stream_member(archive, info, budget):
    """Yield the bytes of one member in chunks, under the budgets. Raises Unreadable (kind: encrypted, unsupported,
    failed, over_budget, not_attempted) and never returns a truncated member as a whole one."""
    if info.flag_bits & 0x1 or info.compress_type == 99:
        raise Unreadable("encrypted", "the member is marked encrypted (general purpose flag bit 0%s)" % (" or AES method 99" if info.compress_type == 99 else ""))
    if info.compress_type not in METHODS_READ:
        raise Unreadable("unsupported", ("compression method %d is not read: OOXML parts are stored (0) or deflated (8), and the standard library "
                                         "decompresses any other method whole, with no limit on its output, so it cannot be held to a budget") % info.compress_type)
    declared = info.file_size
    if declared > budget.member:
        raise Unreadable("over_budget", "the member declares %d bytes, over max_stream_bytes (%d)" % (declared, budget.member))
    if declared > RATIO_FLOOR and declared > budget.ratio * max(info.compress_size, 1):
        raise Unreadable("over_budget", "the member declares %d bytes from %d compressed: an expansion ratio over max_ratio (%d)"
                         % (declared, info.compress_size, budget.ratio))
    if budget.used + declared > budget.total:
        raise Unreadable("not_attempted", "the member declares %d bytes and %d of the total budget of %d are left"
                         % (declared, budget.total - budget.used, budget.total))
    try:
        fh = archive.open(info)
    except RuntimeError as exc:
        raise Unreadable("encrypted", "the member needs a password (%s)" % type(exc).__name__)
    except NotImplementedError:
        raise Unreadable("unsupported", "compression method %d is not read" % info.compress_type)
    except Exception as exc:
        raise Unreadable("failed", "the member could not be opened (%s)" % type(exc).__name__)
    read = 0
    with fh:
        while True:
            try:
                chunk = fh.read(PAGE)
            except Exception as exc:
                raise Unreadable("failed", "the member could not be read to its end (%s: %s)" % (type(exc).__name__, scrub(str(exc))))
            if not chunk:
                return
            read += len(chunk)
            budget.used += len(chunk)
            if read > budget.member:
                raise Unreadable("over_budget", "the member expanded past max_stream_bytes (%d)" % budget.member)
            if read > RATIO_FLOOR and read > budget.ratio * max(info.compress_size, 1):
                raise Unreadable("over_budget", "the member expanded past max_ratio (%d) of its compressed size" % budget.ratio)
            if budget.used > budget.total:
                raise Unreadable("over_budget", "the members together expanded past max_total_bytes (%d)" % budget.total)
            yield chunk


# --- the call's bookkeeping ----------------------------------------------------------------------------------------------

class Over(Exception):
    """A budget was reached. The message says which, in words that go straight into `limits_hit`."""


class Stop(Exception):
    def __init__(self, message, partial=None):
        Exception.__init__(self, message)
        self.message, self.partial = message, partial or {}


def member_name(name, ctx):
    """A name as it may be printed: tested one component at a time. The real name behind a withheld one is kept."""
    shown = shown_path(name)
    if shown != name:
        ctx.names.add(name, shown)
    return shown


def text_of(value, ctx=None, kind="text"):
    """A string out of a document, as it may be printed: control characters escaped, anything token-shaped withheld."""
    return scrub(cell(value), kind)


class Ctx:
    def __init__(self, key, cfg, values, seconds):
        self.key = key
        self.cfg = cfg
        self.limit = cfg["limit"]
        self.values = values
        self.deadline = time.monotonic() + seconds
        self.seconds = seconds
        self.problems = []
        self.problems_dropped = 0
        self.limits = []
        self.pages = {}
        self.names = Names(values)
        self.budget = Budget(cfg["max_stream_bytes"], cfg["max_total_bytes"], cfg["max_ratio"])
        self.extracted = []
        self.counter = [0]
        self.finding = [0]

    def expired(self, where):
        if time.monotonic() <= self.deadline:
            return False
        self.limit_hit("time: %s stopped at max_seconds (%d); what was read is reported, and the counts are lower bounds" % (where, self.seconds))
        return True

    def problem(self, text):
        text = scrub(text)
        if text in self.problems:
            return
        if len(self.problems) >= MAX_PROBLEMS:
            self.problems_dropped += 1
            return
        self.problems.append(text)

    def limit_hit(self, text):
        text = scrub(text)
        if text not in self.limits:
            self.limits.append(text)

    def page(self, name, limit=None):
        if name not in self.pages:
            self.pages[name] = LosslessPage("doc_structure-" + name, [self.key, name], limit or self.limit)
        return self.pages[name]

    def next_finding(self, letter):
        self.finding[0] += 1
        return "%s%06d" % (letter, self.finding[0])

    def spend(self, n, what):
        """Count `n` bytes read or expanded against the total budget."""
        self.budget.used += n
        if self.budget.used > self.budget.total:
            raise Over("%s: the streams read together passed max_total_bytes (%d); the rest of this call reads no more stream content" % (what, self.budget.total))


def iso_filetime(value):
    """A Windows FILETIME (100 ns ticks since 1601-01-01 UTC) as ISO 8601 UTC with its fraction, or None for zero and for a value
    outside the calendar."""
    if not value:
        return None
    try:
        moment = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value // 10)
    except OverflowError:
        return None
    return "%s.%07dZ" % (moment.strftime("%Y-%m-%dT%H:%M:%S"), value % 10_000_000)


def guid(raw):
    if len(raw) != 16 or not any(raw):
        return None
    d1, d2, d3 = struct.unpack_from("<IHH", raw)
    return "%08X-%04X-%04X-%s-%s" % (d1, d2, d3, raw[8:10].hex().upper(), raw[10:16].hex().upper())


# --- extraction: byte-exact, in a file, only what was asked for -----------------------------------------------------------

class Extractor:
    """Writes the objects the caller named (selectors) into `extract_to`: each file is created exclusively, mode 0600, under a name
    made of a counter and nothing from the document. A selector that matches nothing is a problem. Every object is written
    under the stream budget or not at all: a cut copy would pass for the object."""

    KINDS = ("vba", "javascript", "ole", "zip", "pdf", "pdf-raw", "rtf")

    def __init__(self, ctx, extract_to, selectors):
        self.ctx = ctx
        self.dir = extract_to
        self.selectors = []
        for text in selectors:
            kind, _sep, rest = text.partition(":")
            if kind not in self.KINDS or (kind in ("vba", "javascript")) == bool(rest) or (kind in ("pdf", "pdf-raw", "rtf") and not rest.isdigit()):
                fail("extract: %r is not a selector (vba, javascript, ole:<stream path>, zip:<member name>, pdf:<object number>, pdf-raw:<object number>, rtf:<object number>)" % text[:80])
            self.selectors.append({"kind": kind, "arg": rest, "matched": 0, "text": text})

    def wants(self, kind, arg=None):
        found = False
        for sel in self.selectors:
            if sel["kind"] == kind and (arg is None or sel["arg"] == str(arg) or (kind in ("ole", "zip") and sel["arg"].lower() == str(arg).lower())):
                found = True
        return found

    def wanted_args(self, kind):
        return [s["arg"] for s in self.selectors if s["kind"] == kind]

    def write(self, kind, arg, locator, chunks, source):
        """Write `chunks` (bytes or an iterable of bytes) for the selector (kind, arg); returns the row."""
        for sel in self.selectors:
            if sel["kind"] == kind and (not sel["arg"] or sel["arg"] == str(arg) or sel["arg"].lower() == str(arg).lower()):
                sel["matched"] += 1
        self.ctx.counter[0] += 1
        index = self.ctx.counter[0]
        shown = shown_path(locator)
        row = {"locator": shown, "source": source}
        if shown != locator:
            row["locator_withheld"] = True
            self.ctx.names.add(locator, shown, "extraction_locator")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = target = None
        for n in range(1, 100):
            name = "extract-%04d.bin" % index if n == 1 else "extract-%04d-%d.bin" % (index, n)
            target = resolve_output(os.path.join(self.dir, name), "extract_to")
            try:
                fd = os.open(target, flags, 0o600)
                break
            except FileExistsError:
                continue
            except OSError as exc:
                self.ctx.problem("%s: the file could not be created in extract_to (%s)" % (shown, describe(exc)))
                row["status"] = "failed"
                self.ctx.extracted.append(row)
                return row
        if fd is None:
            self.ctx.problem("%s: ninety-nine files of this name already exist in extract_to" % shown)
            row["status"] = "failed"
            self.ctx.extracted.append(row)
            return row
        written, kept = 0, False
        try:
            with os.fdopen(fd, "wb") as out_fh:
                fd = None
                if isinstance(chunks, (bytes, bytearray)):
                    chunks = [bytes(chunks)]
                for chunk in chunks:
                    out_fh.write(chunk)
                    written += len(chunk)
            kept = True
        except Over as exc:
            row["status"] = "over_budget"
            self.ctx.limit_hit("%s: %s" % (shown, exc))
        except Unreadable as exc:
            row["status"] = exc.kind
            (self.ctx.limit_hit if exc.kind in ("over_budget", "not_attempted") else self.ctx.problem)("%s: %s" % (shown, exc.reason))
        except OSError as exc:
            row["status"] = "failed"
            self.ctx.problem("%s: writing failed (%s)" % (shown, describe(exc)))
        finally:
            if fd is not None:
                os.close(fd)
            if not kept:
                try:
                    os.unlink(target)
                except OSError:
                    pass
        if kept:
            row["status"] = "written"
            row["file"] = shown_path(target)
            row["bytes"] = written
        self.ctx.extracted.append(row)
        return row

    def unmatched(self):
        return [s["text"] for s in self.selectors if not s["matched"]]


# --- XML: namespace-aware, no DOCTYPE, nothing expanded --------------------------------------------------------------------

class DoctypeRefused(Exception):
    pass


def xml_elements(chunks, on_element):
    """Hand every element to `on_element(local_name, namespace, attrs)` as it is read; attribute names are local names. A DOCTYPE is
    refused, so no entity is ever expanded. Raises DoctypeRefused or xml.parsers.expat.ExpatError."""
    parser = xml.parsers.expat.ParserCreate(namespace_separator=" ")
    parser.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)

    def start(name, attrs):
        ns, _sp, local = name.rpartition(" ")
        on_element(local, ns, {k.rpartition(" ")[2]: v for k, v in attrs.items()})

    def doctype(*_args):
        raise DoctypeRefused()

    parser.StartElementHandler = start
    parser.StartDoctypeDeclHandler = doctype
    for chunk in chunks:
        parser.Parse(chunk, False)
    parser.Parse(b"", True)


# --- OLE compound file (MS-CFB) --------------------------------------------------------------------------------------------

FREESECT, ENDOFCHAIN, FATSECT, DIFSECT, MAXREGSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFC, 0xFFFFFFFA
NOSTREAM = 0xFFFFFFFF
CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ENTRY_TYPES = {0: "unallocated", 1: "storage", 2: "stream", 5: "root"}
# name (lower case) -> (kinds it applies to: 1 storage, 2 stream, what it is)
NOTABLE_STREAMS = {
    "\x01ole10native": ((2,), "OLE 1.0 native data: an embedded file, package or other object's bytes"),
    "\x01compobj": ((2,), "the compound object's class and format names"),
    "\x05summaryinformation": ((2,), "the summary property set (title, author, times)"),
    "\x05documentsummaryinformation": ((2,), "the document summary property set"),
    "encryptioninfo": ((2,), "the encryption descriptor of an OOXML package in an OLE wrapper"),
    "encryptedpackage": ((2,), "the encrypted OOXML package"),
    "worddocument": ((2,), "the Word binary document stream"),
    "workbook": ((2,), "the Excel workbook stream (BIFF8)"),
    "book": ((2,), "the Excel workbook stream (BIFF5 and earlier)"),
    "powerpoint document": ((2,), "the PowerPoint document stream"),
    "current user": ((2,), "the PowerPoint current-user stream"),
    "_vba_project_cur": ((1,), "an Excel VBA project storage"),
    "macros": ((1,), "the Word VBA storage"),
    "vba": ((1,), "a VBA storage"),
    "_vba_project": ((2,), "the VBA project header and performance cache"),
    "project": ((2,), "the VBA project properties stream (text)"),
    "projectwm": ((2,), "the VBA module-name map"),
    "dir": ((2,), "in a VBA storage: the compressed project information stream"),
    "objectpool": ((1,), "the storage of embedded objects"),
    "\x01ole": ((2,), "the OLE link or embedding stream"),
    "\x06dataspaces": ((1,), "how the package is transformed (encryption, rights management)"),
}


class CfbError(Exception):
    pass


class Entry:
    __slots__ = ("sid", "name", "kind", "left", "right", "child", "clsid", "start", "size", "created", "modified", "reachable", "parts", "name_bad")


class Cfb:
    """A compound file read from a bytes-like source (a memory map or bytes): header, FAT, mini FAT, directory. Sector chains are
    walked with cycle detection and a step budget, and every offset is checked against the source before it is read. Whatever is
    wrong is a problem on the context, with the label of this file ("" for the document itself, a path for a nested one)."""

    def __init__(self, src, ctx, label=""):
        self.src, self.ctx, self.label = src, ctx, label
        self.size = len(src)
        self.entries = []
        self.by_path = {}
        self.orphans = 0
        head = src[:512]
        if len(head) < 512:
            raise CfbError("the file is shorter than the 512-byte compound file header")
        if head[:8] != CFB_MAGIC:
            raise CfbError("the compound file signature is not at offset 0")
        self.minor, self.major, order, shift, mini_shift = struct.unpack_from("<HHHHH", head, 24)
        if order != 0xFFFE:
            raise CfbError("the byte-order mark is 0x%04X, not 0xFFFE" % order)
        if (self.major, shift) not in ((3, 9), (4, 12)):
            raise CfbError("major version %d with sector shift %d is not a layout this tool reads (3 with 9, 4 with 12)" % (self.major, shift))
        if mini_shift != 6:
            raise CfbError("the mini sector shift is %d, not 6" % mini_shift)
        self.ss = 1 << shift
        (self.n_dir_sectors, self.n_fat, self.first_dir, _tx, self.cutoff, self.first_minifat, self.n_minifat,
         self.first_difat, self.n_difat) = struct.unpack_from("<IIIIIIIII", head, 40)
        self.nsect = max(0, (self.size - self.ss + self.ss - 1) // self.ss)
        self.steps = max(1_000_000, 20 * self.nsect)
        if self.cutoff != 4096:
            self.warn("the mini stream cutoff is %d, not 4096" % self.cutoff)
        self.fat = self._read_fat(head)
        self.minifat = self._read_minifat()
        self.mini_chain = None

    def warn(self, text):
        self.ctx.problem(("%s: " % self.label if self.label else "") + text)

    # sectors and chains ---------------------------------------------------------------------------------------------

    def sector(self, n):
        at = (n + 1) * self.ss
        if n >= self.nsect or at >= self.size:
            return None
        return self.src[at:at + self.ss]

    def _u32s(self, raw):
        a = array.array("I")
        a.frombytes(raw[:len(raw) // 4 * 4])
        if sys.byteorder == "big":
            a.byteswap()
        return a

    def _read_fat(self, head):
        difat = list(struct.unpack_from("<109I", head, 76))
        sectors, seen = [], set()
        for n in difat:
            if n == FREESECT:
                continue
            sectors.append(n)
        nxt, hops = self.first_difat, 0
        per = self.ss // 4 - 1
        while nxt not in (ENDOFCHAIN, FREESECT) and hops < min(self.n_difat, self.nsect + 1):
            if nxt in seen:
                self.warn("the DIFAT chain loops back to sector %d" % nxt)
                break
            seen.add(nxt)
            raw = self.sector(nxt)
            if raw is None or len(raw) < self.ss:
                self.warn("DIFAT sector %d lies outside the file" % nxt)
                break
            vals = struct.unpack("<%dI" % (self.ss // 4), raw)
            sectors += [v for v in vals[:per] if v != FREESECT]
            nxt = vals[per]
            hops += 1
        if len(sectors) != self.n_fat:
            self.warn("the header declares %d FAT sector(s) and the DIFAT lists %d" % (self.n_fat, len(sectors)))
        fat = array.array("I")
        for n in sectors:
            raw = self.sector(n)
            if raw is None:
                self.warn("FAT sector %d lies outside the file (the file may be truncated)" % n)
                continue
            if len(raw) < self.ss:
                self.warn("FAT sector %d is cut short by the end of the file" % n)
            fat.extend(self._u32s(raw))
        return fat

    def chain(self, start, fat=None, label="chain"):
        """The sectors of a chain, and what ended it: 'end' (ENDOFCHAIN), 'loop', 'outside' (a sector number past the FAT or the
        file), 'free' (a free sector inside a chain), 'budget'."""
        fat = self.fat if fat is None else fat
        out, seen, n = array.array("I"), set(), start
        while True:
            if n == ENDOFCHAIN:
                return out, "end"
            if n >= len(fat) or n > MAXREGSECT:
                return out, ("free" if n == FREESECT else "outside")
            if n in seen:
                return out, "loop"
            self.steps -= 1
            if self.steps < 0:
                return out, "budget"
            seen.add(n)
            out.append(n)
            n = fat[n]

    def _read_minifat(self):
        if self.n_minifat == 0 or self.first_minifat == ENDOFCHAIN:
            return array.array("I")
        chain, why = self.chain(self.first_minifat)
        if why != "end":
            self.warn("the mini FAT chain ends with %s, not at an end-of-chain marker" % why)
        mf = array.array("I")
        for n in chain:
            raw = self.sector(n)
            if raw is None:
                self.warn("mini FAT sector %d lies outside the file" % n)
                continue
            mf.extend(self._u32s(raw))
        return mf

    # directory ------------------------------------------------------------------------------------------------------

    def read_directory(self, max_entries):
        chain, why = self.chain(self.first_dir)
        if why != "end":
            self.warn("the directory chain ends with %s, not at an end-of-chain marker" % why)
        per = self.ss // 128
        total = len(chain) * per
        if total > max_entries:
            self.ctx.limit_hit("%sthe directory holds %d entries: the first %d were read" % ("%s: " % self.label if self.label else "", total, max_entries))
        raws = []
        for n in chain:
            raw = self.sector(n)
            if raw is None:
                self.warn("directory sector %d lies outside the file" % n)
                break
            raws.append(raw)
            if len(raws) * per >= max_entries:
                break
        data = b"".join(raws)
        for i in range(min(len(data) // 128, max_entries)):
            row = data[i * 128:(i + 1) * 128]
            e = Entry()
            e.sid, e.reachable, e.parts = i, False, None
            namelen = struct.unpack_from("<H", row, 64)[0]
            e.name_bad = namelen > 64 or namelen % 2 == 1 or (namelen == 0 and row[66] != 0)
            take = max(0, min(namelen, 64) - 2) if namelen >= 2 else 0
            e.name = row[:take].decode("utf-16-le", "surrogatepass")
            e.kind = row[66]
            e.left, e.right, e.child = struct.unpack_from("<III", row, 68)
            e.clsid = guid(row[80:96])
            e.created, e.modified = struct.unpack_from("<QQ", row, 100)
            e.start = struct.unpack_from("<I", row, 116)[0]
            e.size = struct.unpack_from("<Q", row, 120)[0]
            if self.major == 3:
                e.size &= 0xFFFFFFFF
            self.entries.append(e)
        if not self.entries or self.entries[0].kind != 5:
            raise CfbError("the first directory entry is not the root storage")
        return len(self.entries)

    def walk(self, max_depth):
        """Mark the entries the red-black trees reach from the root; build each reachable entry's path. Cycles and shared entries are
        problems, and an allocated entry no tree reaches is an orphan."""
        root = self.entries[0]
        root.reachable, root.parts = True, ()
        stack = [(root.child, (), 1)]
        n = len(self.entries)
        while stack:
            sid, parent, depth = stack.pop()
            if sid == NOSTREAM:
                continue
            if sid >= n:
                self.warn("a directory link names entry %d and the directory has %d entries read" % (sid, n))
                continue
            e = self.entries[sid]
            if e.reachable:
                self.warn("directory entry %d is reached twice: the trees loop or share an entry" % sid)
                continue
            e.reachable = True
            e.parts = parent + (e.name,)
            stack.append((e.left, parent, depth))
            stack.append((e.right, parent, depth))
            if e.kind in (1, 5):
                if depth >= max_depth:
                    self.ctx.limit_hit("%sstorages nest past max_depth (%d): the entries below %s are listed without a path" % ("%s: " % self.label if self.label else "", max_depth, shown_path("/".join(e.parts))))
                else:
                    stack.append((e.child, e.parts, depth + 1))
        self.orphans = sum(1 for e in self.entries if e.kind != 0 and not e.reachable)
        for e in self.entries:
            if e.reachable and e.parts is not None and e.kind in (1, 2):
                self.by_path.setdefault(tuple(p.lower() for p in e.parts), e)

    def find(self, *parts):
        return self.by_path.get(tuple(p.lower() for p in parts))

    def children(self, parts):
        low = tuple(p.lower() for p in parts)
        return [e for e in self.entries if e.reachable and e.parts is not None and len(e.parts) == len(low) + 1 and tuple(p.lower() for p in e.parts[:-1]) == low]

    # streams --------------------------------------------------------------------------------------------------------

    def mini_sectors(self):
        if self.mini_chain is None:
            root = self.entries[0]
            self.mini_chain, why = self.chain(root.start) if root.size else (array.array("I"), "end")
            if why != "end":
                self.warn("the mini stream's chain ends with %s" % why)
        return self.mini_chain

    def chunks(self, e, limit=None, take=None):
        """The bytes of a stream, in pieces: all of it, or its first `take` bytes. A stream (or the part asked for) past `limit`
        (default the stream budget) raises Unreadable('over_budget'); a chain that ends early or leaves the file raises
        Unreadable('failed'). Nothing wrong is yielded."""
        limit = self.ctx.budget.member if limit is None else limit
        size = e.size
        want = size if take is None else min(size, take)
        if want > limit:
            raise Unreadable("over_budget", "the stream declares %d bytes, over max_stream_bytes (%d)" % (want, limit))
        if want > self.size:
            raise Unreadable("failed", "the stream declares %d bytes in a %d-byte file" % (want, self.size))
        self.ctx.spend(want, "a stream")
        if want <= 0:
            return
        if size < self.cutoff and e.kind == 2:
            yield from self._mini(e, want)
            return
        chain, why = self.chain(e.start)
        need = (want + self.ss - 1) // self.ss
        if len(chain) < need:
            raise Unreadable("failed", "the stream declares %d bytes (%d sectors) and its chain ends after %d sector(s) (%s)" % (want, need, len(chain), why))
        left = want
        for n in chain[:need]:
            raw = self.sector(n)
            if raw is None or (len(raw) < min(self.ss, left)):
                raise Unreadable("failed", "sector %d of the stream is cut off by the end of the file" % n)
            piece = raw[:min(self.ss, left)]
            left -= len(piece)
            yield bytes(piece)

    def _mini(self, e, want):
        need = (want + 63) // 64
        chain, why = self.chain(e.start, self.minifat)
        if len(chain) < need:
            raise Unreadable("failed", "the stream declares %d bytes (%d mini sectors) and its mini chain ends after %d (%s)" % (want, need, len(chain), why))
        base = self.mini_sectors()
        left = want
        for m in chain[:need]:
            off = m * 64
            holder = off // self.ss
            if holder >= len(base):
                raise Unreadable("failed", "mini sector %d lies beyond the mini stream" % m)
            raw = self.sector(base[holder])
            if raw is None:
                raise Unreadable("failed", "the sector holding mini sector %d lies outside the file" % m)
            piece = raw[off % self.ss:off % self.ss + min(64, left)]
            if len(piece) < min(64, left):
                raise Unreadable("failed", "mini sector %d is cut off by the end of the file" % m)
            left -= len(piece)
            yield bytes(piece)

    def verify_stream(self, e):
        """None when the stream's chain is whole and inside the file, else why not. Walks the chain; reads no data."""
        size = e.size
        if size == 0:
            return None
        if size > self.size:
            return "it declares %d bytes in a %d-byte file" % (size, self.size)
        if self.steps <= 0:
            return "not checked: the chain-walk budget of this file is spent"
        if size < self.cutoff and e.kind == 2:
            need = (size + 63) // 64
            chain, why = self.chain(e.start, self.minifat)
            if len(chain) < need:
                return "its mini chain ends after %d of %d mini sectors (%s)" % (len(chain), need, why)
            base = self.mini_sectors()
            if (max(chain[:need]) * 64 + 63) // self.ss >= len(base):
                return "a mini sector lies beyond the mini stream"
            return None
        chain, why = self.chain(e.start)
        need = (size + self.ss - 1) // self.ss
        if len(chain) < need:
            return "its chain ends after %d of %d sectors (%s)" % (len(chain), need, why)
        rem = size - (need - 1) * self.ss
        if need > 1 and (max(chain[:need - 1]) + 2) * self.ss > self.size:
            return "a sector of the stream is cut off by the end of the file"
        if (chain[need - 1] + 1) * self.ss + rem > self.size:
            return "its last sector is cut off by the end of the file"
        return None

    def head(self, e, n):
        return b"".join(self.chunks(e, take=n))

    def read(self, e, limit=None):
        return b"".join(self.chunks(e, limit))


def ole_entry_rows(cfb, ctx, page, extractor):
    kinds = {"storage": 0, "stream": 0, "root": 0, "unallocated": 0, "other": 0}
    chains = {"checked": 0, "broken": 0, "not_checked": 0}
    for e in cfb.entries:
        name = ENTRY_TYPES.get(e.kind, "other")
        kinds[name] += 1
        if e.kind == 0:
            continue
        path = "/".join(e.parts) if e.parts is not None else e.name
        shown = shown_path(path) if e.parts is not None else shown_path(e.name)
        row = {"sid": e.sid, "path": cell(shown), "type": name, "size": e.size, "start_sector": e.start, "reachable": e.reachable}
        if shown != path:
            row["name_withheld"] = True
            ctx.names.add(path, shown)
        if e.clsid:
            row["clsid"] = e.clsid
        if e.created:
            row["created"] = {"raw": e.created, "utc": iso_filetime(e.created)}
        if e.modified:
            row["modified"] = {"raw": e.modified, "utc": iso_filetime(e.modified)}
        known = NOTABLE_STREAMS.get(e.name.lower()) if e.parts is not None else None
        if known and e.kind in known[0]:
            row["note"] = known[1]
        if e.name_bad:
            row["name_length_inconsistent"] = True
        if e.kind == 2:
            why = cfb.verify_stream(e)
            if why is None:
                chains["checked"] += 1
            elif why.startswith("not checked"):
                chains["not_checked"] += 1
                row["chain"] = why
            else:
                chains["checked"] += 1
                chains["broken"] += 1
                row["chain"] = "broken: " + why
                ctx.problem("stream %s: %s" % (cell(shown), why))
        page.add(row)
    if chains["not_checked"]:
        ctx.limit_hit("%sthe chain-walk budget of this file was spent: %d stream chain(s) were not checked" % ("%s: " % cfb.label if cfb.label else "", chains["not_checked"]))
    kinds["stream_chains"] = chains
    return kinds


# --- VBA project (MS-OVBA) -------------------------------------------------------------------------------------------------

def ovba_decompress(data, limit, ctx=None):
    """MS-OVBA 2.4.1 decompression of a compressed container. Returns (bytes, problem or None). Output past `limit` raises Over."""
    if not data:
        return b"", "the compressed container is empty"
    if data[0] != 1:
        return b"", "the compressed container does not begin with the signature byte 0x01"
    out, pos, n, chunks = bytearray(), 1, len(data), 0
    while pos < n:
        chunks += 1
        if ctx is not None and chunks % 64 == 0 and ctx.expired("a VBA decompression"):
            return bytes(out), "the clock ran out while decompressing"
        if pos + 2 > n:
            return bytes(out), "a chunk header is cut off"
        header = data[pos] | data[pos + 1] << 8
        size, sig, flag = (header & 0x0FFF) + 3, (header >> 12) & 7, header >> 15
        if sig != 3:
            return bytes(out), "a chunk header carries the signature bits %d, not 3" % sig
        end, start_out = pos + size, len(out)
        if end > n:
            return bytes(out), "a chunk of %d bytes is cut off after %d" % (size, n - pos)
        p = pos + 2
        if not flag:
            out += data[p:p + 4096]
        else:
            while p < end:
                flags = data[p]
                p += 1
                for bit in range(8):
                    if p >= end:
                        break
                    if not (flags >> bit) & 1:
                        out.append(data[p])
                        p += 1
                    else:
                        if p + 2 > end:
                            return bytes(out), "a copy token is cut off by the end of its chunk"
                        token = data[p] | data[p + 1] << 8
                        p += 2
                        done = len(out) - start_out
                        if done < 1:
                            return bytes(out), "a copy token at the start of a chunk has nothing to copy"
                        bits = max((done - 1).bit_length(), 4)
                        length = (token & (0xFFFF >> bits)) + 3
                        offset = (token >> (16 - bits)) + 1
                        if offset > done:
                            return bytes(out), "a copy token reaches %d bytes back in a chunk that has %d" % (offset, done)
                        for _i in range(length):
                            out.append(out[-offset])
                if len(out) - start_out > 4096:
                    return bytes(out), "a chunk expands past 4096 bytes"
        pos = end
        if len(out) > limit:
            raise Over("a VBA module's source expands past max_stream_bytes (%d)" % limit)
    return bytes(out), None


DIR_NO_SIZE = {0x0009}


def parse_vba_dir(data, ctx, where):
    """Walk the decompressed `dir` stream's records (an id, a size, that many bytes; PROJECTVERSION is the one exception)."""
    info = {"modules": [], "references": 0, "codepage": None, "project_name": None, "module_count_declared": None, "cookie": None}
    pos, n, current = 0, len(data), None
    while pos + 6 <= n:
        rid, size = struct.unpack_from("<HI", data, pos)
        pos += 6
        if rid in DIR_NO_SIZE:
            body = data[pos:pos + 4]
            pos += 4 + 2
        else:
            if pos + size > n:
                ctx.problem("%s: a dir record (id 0x%04X) of %d bytes is cut off by the end of the stream" % (where, rid, size))
                break
            body = data[pos:pos + size]
            pos += size
        if rid == 0x0003 and len(body) == 2:
            info["codepage"] = struct.unpack("<H", body)[0]
        elif rid == 0x0004:
            info["project_name"] = body
        elif rid in (0x000D, 0x000E, 0x002F, 0x0033):
            info["references"] += 1
        elif rid == 0x000F and len(body) == 2:
            info["module_count_declared"] = struct.unpack("<H", body)[0]
        elif rid == 0x0019:
            current = {"name": body, "unicode_name": None, "stream_name": None, "text_offset": None, "type": None, "read_only": False, "private": False}
            info["modules"].append(current)
        elif current is not None:
            if rid == 0x0047:
                current["unicode_name"] = body
            elif rid == 0x001A:
                current["stream_name"] = body
            elif rid == 0x0032:
                current["unicode_stream_name"] = body
            elif rid == 0x0031 and len(body) == 4:
                current["text_offset"] = struct.unpack("<I", body)[0]
            elif rid == 0x0021:
                current["type"] = "procedural"
            elif rid == 0x0022:
                current["type"] = "document, class or designer"
            elif rid == 0x0025:
                current["read_only"] = True
            elif rid == 0x0028:
                current["private"] = True
            elif rid == 0x002B:
                current = None
    return info


def codec(info):
    page = info.get("codepage")
    return ("cp%d" % page) if isinstance(page, int) else "latin-1"


def decode_text(raw, encoding):
    try:
        return raw.decode(encoding, "replace")
    except LookupError:
        return raw.decode("latin-1", "replace")


def vba_projects(cfb, ctx, extractor, where):
    """Every storage named VBA that holds a `dir` stream, read as a VBA project."""
    found = []
    for e in cfb.entries:
        if e.reachable and e.kind == 1 and e.parts and e.parts[-1].lower() == "vba" and cfb.find(*e.parts, "dir") is not None:
            found.append(e)
    projects = []
    for store in found:
        base = store.parts
        label = shown_path("/".join(base))
        project = {"storage": cell(label), "modules": [], "status": "read"}
        if label != "/".join(base):
            ctx.names.add("/".join(base), label)
        projects.append(project)
        try:
            raw = cfb.read(cfb.find(*base, "dir"), ctx.budget.member)
        except (Unreadable, Over) as exc:
            project["status"] = "dir_unreadable"
            ctx.problem("%s: the dir stream could not be read: %s" % (label, getattr(exc, "reason", None) or exc))
            continue
        try:
            data, why = ovba_decompress(raw, ctx.budget.member, ctx)
        except Over as exc:
            project["status"] = "dir_over_budget"
            ctx.limit_hit("%s: %s" % (label, exc))
            continue
        if why:
            ctx.problem("%s: the dir stream does not decompress cleanly: %s" % (label, why))
            project["status"] = "dir_partial"
        info = parse_vba_dir(data, ctx, label)
        enc = codec(info)
        project["codepage"] = info["codepage"]
        if info["project_name"] is not None:
            project["project_name"] = text_of(decode_text(info["project_name"], enc), ctx, "names")
        project["references"] = info["references"]
        project["modules_declared"] = info["module_count_declared"]
        if info["module_count_declared"] is not None and info["module_count_declared"] != len(info["modules"]):
            ctx.problem("%s: the dir stream declares %d module(s) and lists %d" % (label, info["module_count_declared"], len(info["modules"])))
        vp = cfb.find(*base, "_VBA_PROJECT")
        if vp is not None:
            project["performance_cache_stream"] = {"bytes": vp.size, "note": "the _VBA_PROJECT stream: a header and the compiled (p-code) cache; this tool does not read it"}
            try:
                head = cfb.head(vp, 7)
            except Unreadable:
                head = b""
            if len(head) >= 4:
                project["performance_cache_stream"]["version_field"] = struct.unpack_from("<H", head, 2)[0]
        else:
            ctx.problem("%s: no _VBA_PROJECT stream beside the dir stream" % label)
        proj_stream = cfb.find(*base[:-1], "PROJECT") if len(base) > 1 else cfb.find("PROJECT")
        if proj_stream is not None and proj_stream.size <= 1 << 20:
            try:
                text = cfb.read(proj_stream, 1 << 20)
            except (Unreadable, Over):
                text = b""
            keys = []
            for line in text.split(b"\n"):
                key = line.split(b"=", 1)[0].strip().decode("latin-1", "replace")
                if re.fullmatch(r"[A-Za-z]{1,32}", key) and key not in keys:
                    keys.append(key)
            protected = [k for k in ("ID", "CMG", "DPB", "GC") if k in keys]
            project["project_properties"] = {"keys": keys[:50], "protection_fields_present": [k for k in protected if k != "ID"],
                                             "note": "CMG, DPB and GC hold the project's protection data (a password verifier among it): their presence is reported, their values never are"}
        for mod in info["modules"]:
            name_raw = mod["unicode_name"].decode("utf-16-le", "replace") if mod["unicode_name"] else decode_text(mod["name"], enc)
            stream_name = (mod["unicode_stream_name"].decode("utf-16-le", "replace") if mod.get("unicode_stream_name")
                           else decode_text(mod["stream_name"] or b"", enc))
            shown = shown_path(name_raw)
            if shown != name_raw:
                ctx.names.add(name_raw, shown, "vba_module_name")
            row = {"name": cell(shown), "type": mod["type"], "read_only": mod["read_only"], "private": mod["private"], "text_offset": mod["text_offset"]}
            stream = cfb.find(*base, stream_name) if stream_name else None
            if stream is None:
                row["stream"] = "missing"
                ctx.problem("%s: module %s names a stream that the directory does not hold" % (label, cell(shown)))
            else:
                row["stream_bytes"] = stream.size
                off = mod["text_offset"]
                if off is None or off > stream.size:
                    row["source"] = "text offset missing or past the stream"
                    ctx.problem("%s: module %s has a text offset (%s) outside its %d-byte stream" % (label, cell(shown), off, stream.size))
                else:
                    row["compressed_source_bytes"] = stream.size - off
                    row["compiled_cache_bytes_before_source"] = off
                    try:
                        blob = cfb.read(stream, ctx.budget.member)
                        source, why = ovba_decompress(blob[off:], ctx.budget.member, ctx)
                    except (Unreadable, Over) as exc:
                        row["source"] = "unreadable"
                        (ctx.limit_hit if isinstance(exc, Over) or getattr(exc, "kind", "") == "over_budget" else ctx.problem)(
                            "%s: module %s: %s" % (label, cell(shown), getattr(exc, "reason", None) or exc))
                    else:
                        row["source_bytes"] = len(source)
                        row["source"] = "decompressed" if not why else "decompressed in part (%s)" % why
                        if why:
                            ctx.problem("%s: module %s: the source does not decompress cleanly: %s" % (label, cell(shown), why))
                        if extractor is not None and extractor.wants("vba"):
                            r = extractor.write("vba", "", "%s%s/%s" % (where, "/".join(base), name_raw), source, "decompressed VBA module source")
                            row["extracted"] = r.get("file") or r.get("status")
            project["modules"].append(row)
    return projects


# --- encryption structures an Office file records -------------------------------------------------------------------------

STD_ALG = {0x6801: "RC4", 0x660E: "AES-128", 0x660F: "AES-192", 0x6610: "AES-256", 0x0000: "not set (the flags decide)"}
STD_HASH = {0x8004: "SHA-1", 0x0000: "not set (SHA-1)"}
AGILE_SAFE = ("saltSize", "blockSize", "keyBits", "hashSize", "cipherAlgorithm", "cipherChaining", "hashAlgorithm", "spinCount")
KEY_ENCRYPTOR_KINDS = {"http://schemas.microsoft.com/office/2006/keyEncryptor/password": "password",
                       "http://schemas.microsoft.com/office/2006/keyEncryptor/certificate": "certificate"}


def num(text):
    return int(text) if re.fullmatch(r"[0-9]{1,12}", text) else text_of(text, None, "names")


def encryption_info(cfb, ctx, entry):
    """MS-OFFCRYPTO EncryptionInfo. Algorithms, key sizes and counts are reported; salts, verifiers and encrypted keys are not."""
    out = {"stream_bytes": entry.size}
    try:
        data = cfb.read(entry, min(entry.size, 1 << 20))
    except (Unreadable, Over) as exc:
        ctx.problem("EncryptionInfo could not be read: %s" % (getattr(exc, "reason", None) or exc))
        out["scheme"] = "unreadable"
        return out
    if len(data) < 8:
        out["scheme"] = "too short to hold a version"
        ctx.problem("EncryptionInfo is %d bytes: shorter than its version and flags" % len(data))
        return out
    major, minor, flags = struct.unpack_from("<HHI", data, 0)
    out["version"] = "%d.%d" % (major, minor)
    if (major, minor) == (4, 4):
        out["scheme"] = "agile"
        summary = {"key_encryptors": []}

        def element(local, _ns, attrs):
            if local == "keyData":
                summary["data"] = {k: num(attrs[k]) for k in AGILE_SAFE if k in attrs}
            elif local == "keyEncryptor":
                kind = KEY_ENCRYPTOR_KINDS.get(attrs.get("uri", ""), "other")
                summary["key_encryptors"].append({"kind": kind})
                summary["current"] = summary["key_encryptors"][-1]
            elif local == "encryptedKey" and summary.get("current") is not None:
                summary["current"].update({k: num(attrs[k]) for k in AGILE_SAFE if k in attrs})
            elif local == "dataIntegrity":
                summary["data_integrity_present"] = True

        try:
            xml_elements([data[8:]], element)
        except DoctypeRefused:
            ctx.problem("EncryptionInfo: the XML descriptor contains a DOCTYPE, which is refused: it was not parsed")
            out["descriptor"] = "doctype_refused"
        except xml.parsers.expat.ExpatError as exc:
            ctx.problem("EncryptionInfo: the XML descriptor is not well-formed (%s)" % xml.parsers.expat.ErrorString(exc.code))
            out["descriptor"] = "not_well_formed"
        summary.pop("current", None)
        out.update(summary)
        out["not_reported"] = "salts, encrypted verifier values and the encrypted key are present in the descriptor and are not reported"
    elif minor == 2 and major in (2, 3, 4):
        out["scheme"] = "standard"
        out["header_flags"] = flags
        if len(data) >= 12:
            hsize = struct.unpack_from("<I", data, 8)[0]
            if 32 <= hsize <= len(data) - 12:
                f, _extra, alg, hashalg, keysize, provider = struct.unpack_from("<IIIIII", data, 12)
                out["flags"] = {"crypto_api": bool(f & 0x04), "doc_props_not_encrypted": bool(f & 0x08), "external": bool(f & 0x10), "aes": bool(f & 0x20)}
                out["algorithm"] = STD_ALG.get(alg, "unrecognised (0x%04X)" % alg)
                out["hash"] = STD_HASH.get(hashalg, "unrecognised (0x%04X)" % hashalg)
                out["key_bits"] = keysize
                out["provider_type"] = provider
            else:
                ctx.problem("EncryptionInfo: the standard header declares %d bytes in a %d-byte stream" % (hsize, len(data)))
        out["not_reported"] = "the salt, the encrypted verifier and its hash are present in the stream and are not reported"
    elif minor == 3 and major in (3, 4):
        out["scheme"] = "extensible (a provider-defined descriptor; not read)"
    else:
        out["scheme"] = "version %d.%d is not one this tool reads" % (major, minor)
        ctx.problem("EncryptionInfo: version %d.%d is not one this tool reads" % (major, minor))
    return out


def biff_records(data, limit):
    """(type, body) for each BIFF record until the first EOF record (0x000A) after the first BOF, or the data ends."""
    pos, n, count = 0, len(data), 0
    seen_bof = False
    while pos + 4 <= n and count < limit:
        rtype, size = struct.unpack_from("<HH", data, pos)
        body = data[pos + 4:pos + 4 + size]
        pos += 4 + size
        count += 1
        yield rtype, body, pos > n
        if rtype == 0x0809:
            seen_bof = True
        elif rtype == 0x000A and seen_bof:
            return


def excel_findings(cfb, ctx, entry, out):
    try:
        data = cfb.read(entry, ctx.budget.member)
    except (Unreadable, Over) as exc:
        (ctx.limit_hit if isinstance(exc, Over) or getattr(exc, "kind", "") == "over_budget" else ctx.problem)("the Excel workbook stream was not read: %s" % (getattr(exc, "reason", None) or exc))
        out["status"] = "unreadable"
        return
    sheets, filepass, bof_version, ended = [], None, None, False
    for rtype, body, cut in biff_records(data, 2_000_000):
        if rtype == 0x0809 and len(body) >= 2 and bof_version is None:
            bof_version = struct.unpack_from("<H", body, 0)[0]
        elif rtype == 0x002F and len(body) >= 2:
            etype = struct.unpack_from("<H", body, 0)[0]
            if etype == 0:
                filepass = {"scheme": "XOR obfuscation", "note": "a weak obfuscation, not encryption; the key check value is not reported"}
            elif etype == 1 and len(body) >= 6:
                vmaj, vmin = struct.unpack_from("<HH", body, 2)
                filepass = {"scheme": "RC4 (Office 97-2003)" if (vmaj, vmin) == (1, 1) else ("RC4 CryptoAPI" if vmin == 2 and vmaj in (2, 3, 4) else "RC4 variant %d.%d" % (vmaj, vmin)),
                            "version": "%d.%d" % (vmaj, vmin)}
            else:
                filepass = {"scheme": "encryption type %d" % etype}
        elif rtype == 0x0085 and len(body) >= 8:
            state, kind = body[4], body[5]
            if bof_version == 0x0500:
                cch, flag, at = body[6], 0, 7
            else:
                cch, flag, at = body[6], body[7], 8
            raw = body[at:at + (cch * 2 if flag & 1 else cch)]
            name = raw.decode("utf-16-le" if flag & 1 else "latin-1", "replace")
            if len(sheets) >= 1000:
                if len(sheets) == 1000:
                    ctx.limit_hit("the Excel globals substream lists more than 1000 sheets: the first 1000 are listed")
                    sheets.append(None)
                continue
            sheets.append({"name": text_of(name, ctx, "names"), "state": {0: "visible", 1: "hidden", 2: "very hidden"}.get(state & 3, "state %d" % state),
                           "kind": {0: "worksheet", 1: "Excel 4.0 macro sheet", 2: "chart", 6: "VBA module"}.get(kind, "type %d" % kind)})
        elif rtype == 0x000A:
            ended = True
    out["biff_version_field"] = bof_version
    out["sheets"] = [x for x in sheets if x is not None]
    out["globals_substream_ended"] = ended
    if not ended:
        ctx.problem("the Excel globals substream did not end with an EOF record in the bytes read: the sheet list may be incomplete")
    if filepass is not None:
        out["filepass"] = filepass


def word_findings(cfb, ctx, entry, out):
    try:
        head = cfb.head(entry, 64)
    except (Unreadable, Over) as exc:
        ctx.problem("the WordDocument stream was not read: %s" % (getattr(exc, "reason", None) or exc))
        return
    if len(head) < 12:
        ctx.problem("the WordDocument stream is %d bytes: shorter than the FIB base" % len(head))
        return
    ident, nfib, _u, _lid, _pn, flags = struct.unpack_from("<HHHHHH", head, 0)
    out["fib"] = {"ident": "0x%04X" % ident, "nFib": nfib}
    if ident != 0xA5EC:
        ctx.problem("the WordDocument stream does not begin with the FIB identifier 0xA5EC")
        return
    out["fib"]["fEncrypted"] = bool(flags & 0x0100)
    out["fib"]["fObfuscated"] = bool(flags & 0x8000)
    out["fib"]["fWhichTblStm"] = bool(flags & 0x0200)
    if flags & 0x0100:
        table = cfb.find("1Table" if flags & 0x0200 else "0Table")
        if table is None:
            ctx.problem("the FIB says the document is encrypted and the table stream it names is not in the directory")
        elif flags & 0x8000:
            out["scheme"] = "XOR obfuscation (fObfuscated)"
        else:
            try:
                t = cfb.head(table, 4)
            except (Unreadable, Over):
                t = b""
            if len(t) >= 4:
                vmaj, vmin = struct.unpack_from("<HH", t, 0)
                out["scheme"] = "RC4 (Office 97-2003)" if (vmaj, vmin) == (1, 1) else ("RC4 CryptoAPI" if vmin == 2 and vmaj in (2, 3, 4) else "encryption header version %d.%d" % (vmaj, vmin))
                out["version"] = "%d.%d" % (vmaj, vmin)


def powerpoint_findings(cfb, ctx, out):
    cu = cfb.find("Current User")
    if cu is None:
        return
    try:
        head = cfb.head(cu, 16)
    except (Unreadable, Over):
        return
    if len(head) >= 16:
        token = struct.unpack_from("<I", head, 12)[0]
        out["current_user_header_token"] = "0x%08X" % token
        if token == 0xF3D1C4DF:
            out["scheme"] = "encrypted (the Current User header token for an encrypted presentation)"
        elif token == 0xE391C05F:
            out["scheme"] = "not encrypted (the header token for an unencrypted presentation)"
        else:
            ctx.problem("the Current User header token 0x%08X is neither of the two defined values" % token)


def probe_ole_blob(src, ctx, extractor, label="", nested=0):
    """Read a compound file and return the answer's body: directory, applications, VBA projects, encryption. Raises CfbError."""
    cfb = Cfb(src, ctx, label)
    cfb.read_directory(ctx.cfg["max_entries"])
    cfb.walk(ctx.cfg["max_depth"])
    out = {"cfb": {"major_version": cfb.major, "minor_version": cfb.minor, "sector_bytes": cfb.ss, "mini_stream_cutoff": cfb.cutoff,
                   "fat_sectors": cfb.n_fat, "file_bytes": cfb.size, "entries_read": len(cfb.entries)}}
    root = cfb.entries[0]
    if root.clsid:
        out["root_clsid"] = root.clsid
    if root.modified:
        out["root_modified"] = {"raw": root.modified, "utc": iso_filetime(root.modified), "note": "a FILETIME in UTC; the root storage's time is a claim, not an editing history"}
    page = ctx.page("ole_directory" if not label else "ole_directory_" + re.sub(r"[^A-Za-z0-9]", "_", label)[:40])
    out["entry_counts"] = ole_entry_rows(cfb, ctx, page, extractor)
    if cfb.orphans:
        ctx.problem("%s%d allocated directory entr%s no storage reaches: listed with reachable false" % ("%s: " % label if label else "", cfb.orphans, "y is one" if cfb.orphans == 1 else "ies are ones"))
    out["orphan_entries"] = cfb.orphans
    apps, enc, protection = [], {"items": []}, []
    names = {e.name.lower() for e in cfb.entries if e.reachable and e.parts is not None and len(e.parts) == 1}
    if "worddocument" in names:
        apps.append("Word binary document")
        w = {"container": "Word"}
        word_findings(cfb, ctx, cfb.find("WordDocument"), w)
        if w.get("scheme"):
            enc["items"].append({"where": "WordDocument FIB", **{k: w[k] for k in ("scheme", "version", "fib") if k in w}})
        out["word"] = w
    for key in ("workbook", "book"):
        if key in names:
            apps.append("Excel workbook (BIFF)")
            x = {"stream": cell(key), "container": "Excel"}
            excel_findings(cfb, ctx, cfb.find("Workbook" if key == "workbook" else "Book"), x)
            if x.get("filepass"):
                enc["items"].append({"where": "Excel FILEPASS record", **x["filepass"]})
            out["excel"] = x
            macro = [s for s in x.get("sheets", []) if s["kind"] == "Excel 4.0 macro sheet"]
            if macro:
                protection.append({"kind": "macro_sheets", "count": len(macro), "note": "Excel 4.0 macro sheets are formula-language macros: not VBA, not read by a VBA reader"})
            break
    if "powerpoint document" in names:
        apps.append("PowerPoint binary presentation")
        p = {"container": "PowerPoint"}
        powerpoint_findings(cfb, ctx, p)
        if "encrypted" in p.get("scheme", "") and not p["scheme"].startswith("not"):
            enc["items"].append({"where": "PowerPoint Current User stream", "scheme": p["scheme"], "header_token": p.get("current_user_header_token")})
        out["powerpoint"] = p
    if "encryptioninfo" in names and "encryptedpackage" in names:
        apps.append("encrypted OOXML package in an OLE wrapper")
        info = encryption_info(cfb, ctx, cfb.find("EncryptionInfo"))
        pkg = cfb.find("EncryptedPackage")
        if pkg is not None and pkg.size >= 8:
            try:
                declared = struct.unpack("<Q", cfb.head(pkg, 8))[0]
                info["encrypted_package_declared_size"] = declared
                info["encrypted_package_stream_bytes"] = pkg.size
            except (Unreadable, Over):
                pass
        enc["items"].append({"where": "EncryptionInfo and EncryptedPackage streams", **info})
    elif "encryptedpackage" in names or "encryptioninfo" in names:
        ctx.problem("only one of EncryptionInfo and EncryptedPackage is in the root: an encrypted OOXML package needs both")
    ds = [e for e in cfb.entries if e.reachable and e.parts and e.parts[0] == "\x06DataSpaces" and len(e.parts) > 1]
    if ds:
        transforms = sorted({e.parts[-1] for e in ds if len(e.parts) >= 3 and e.parts[1].lower() == "transforminfo" and e.kind == 1})
        protection.append({"kind": "data_spaces", "entries": len(ds), "transforms": [text_of(t, ctx, "names") for t in transforms[:20]],
                           "note": "the \\x06DataSpaces storage records how the package is transformed (strong encryption, rights management); the names are directory entries, not a reading of the transform"})
    vba = vba_projects(cfb, ctx, extractor, label + "/" if label else "")
    if vba:
        out["vba_projects"] = vba
        apps.append("VBA project")
    # Streams the caller named.
    if extractor is not None:
        for sel_path in extractor.wanted_args("ole"):
            parts = [p for p in sel_path.split("/") if p != ""]
            entry = cfb.find(*parts) if parts else None
            if entry is None or entry.kind != 2:
                continue
            extractor.write("ole", sel_path, label + ("/" if label else "") + "/".join(entry.parts), cfb.chunks(entry), "OLE stream, byte for byte")
    out["applications"] = apps
    out["encryption_items"] = enc["items"]
    out["protection_items"] = protection
    # Embedded OLE 1.0 / Package payloads are listed, not opened.
    return out, cfb


# --- OOXML / ZIP ----------------------------------------------------------------------------------------------------------

ZIP_READ = ["the ZIP central directory: member names, sizes, DOS times, flags",
            "[Content_Types].xml: the content types the package declares",
            "the document, workbook and presentation protection elements, by attribute name (a hash, salt or password attribute is reported by length only)",
            "every vbaProject.bin member, read as an OLE compound file (see the VBA project and OLE entries)"]
ZIP_NOT_READ = ["the contents of any other part (document.xml, shared strings, sheets, embedded objects under embeddings/)",
                "relationship targets (doc_probe reads *.rels parts)", "compiled VBA (p-code), Excel 4.0 macro sheet formulas and ActiveX binaries",
                "digital-signature parts", "encryption of the whole package: an encrypted OOXML package is an OLE compound file, not a ZIP"]
OLE_READ = ["the compound file header, FAT, mini FAT and directory (every entry, reachable or not), stream sizes and times",
            "the VBA project: the dir stream, each module's stream and the size of its compressed source (source is written only with extract)",
            "the encryption structures: EncryptionInfo, the Word FIB flags and table-stream header, the Excel FILEPASS record, the PowerPoint Current User token",
            "Excel BOUNDSHEET records: sheet names, kinds and visibility"]
OLE_NOT_READ = ["stream contents other than those named above (document text, workbook cells, presentation slides, embedded objects)",
                "property sets (SummaryInformation, DocumentSummaryInformation)", "compiled VBA (p-code) in the _VBA_PROJECT stream and the module streams' cache",
                "OLE 1.0 and Package payloads in \\x01Ole10Native streams: listed, not opened", "whether any password, empty or otherwise, opens the file: no key is tried"]
PROTECTION_ELEMENTS = {"documentProtection", "writeProtection", "workbookProtection", "fileSharing", "modifyVerifier"}
SECRETISH = re.compile(r"hash|salt|password|digest|verifier", re.I)
NOTABLE_CONTENT_TYPES = ("vbaProject", "macroEnabled", "macrosheet", "activeX", "oleObject", "vbaProjectSignature", "vbaData")


def read_member(archive, info, ctx):
    return b"".join(stream_member(archive, info, ctx.budget))


def zip_unreadable(ctx, members, shown, exc):
    kind = exc.kind
    members[kind] = members.get(kind, 0) + 1
    (ctx.limit_hit if kind in ("over_budget", "not_attempted") else ctx.problem)("%s: %s" % (shown, exc.reason))


def protection_row(local, attrs):
    row = {"element": local, "attributes": {}, "secret_bearing_attributes": []}
    for key, value in attrs.items():
        if SECRETISH.search(key):
            row["secret_bearing_attributes"].append({"name": text_of(key, None, "names"), "length": len(value)})
        else:
            row["attributes"][text_of(key, None, "names")] = text_of(value, None, "names") if len(value) <= 64 else "<%d characters>" % len(value)
    return row


def probe_zip(path, size, ctx, extractor):
    out = {"container": "OOXML or ZIP", "timestamps_note": "ZIP member times are DOS local times with no zone recorded and a resolution of two seconds: they are claims, not UTC."}
    members = {"declared": 0, "listed": 0, "read": 0, "flagged_encrypted": 0, "encrypted": 0, "unsupported": 0, "failed": 0, "over_budget": 0, "not_attempted": 0}
    out["members"] = members
    parts = ctx.page("parts")
    cfg = ctx.cfg
    out["protection_items"] = []
    out["encryption_items"] = []
    with open(path, "rb") as fh:
        try:
            end = zip_directory(fh, size)
        except ZipProblem as exc:
            raise Stop("the archive's directory cannot be read: %s" % exc, out)
        total, cd_size = end["total"], end["cd_size"]
        members["declared"] = total
        if end["others"]:
            ctx.problem("the last 64 KiB of the file hold more than one end of central directory signature (at offsets %s besides the one chosen, at %d): "
                        "a reader that chooses another lists another directory. This tool lists the directory of the chosen one"
                        % (", ".join(str(o) for o in end["others"][:5]), end["eocd_at"]))
        if total > MAX_DIRECTORY_ENTRIES or cd_size > MAX_DIRECTORY_BYTES or cd_size // MIN_ENTRY > MAX_DIRECTORY_ENTRIES:
            ctx.limit_hit("the central directory declares %d members in %d bytes (it can hold up to %d): over the %d-member and %d-byte limits for opening it; "
                          "no member was listed or read" % (total, cd_size, cd_size // MIN_ENTRY, MAX_DIRECTORY_ENTRIES, MAX_DIRECTORY_BYTES))
            members["not_attempted"] = total
            out["coverage"] = {"structures_read": ["the end of central directory record"], "structures_not_read": ZIP_READ + ZIP_NOT_READ}
            return out
        window = Window(fh, end["eocd_at"] + 22, end["eocd_at"] + 20)
        try:
            archive = zipfile.ZipFile(io.BufferedReader(window))
        except Exception as exc:
            raise Stop("the archive will not open (%s: %s)" % (type(exc).__name__, scrub(str(exc))), out)
        by_name, seen = {}, {}
        with archive:
            infos = archive.infolist()
            if len(infos) != total:
                ctx.problem("the end record declares %d member%s and the central directory holds %d" % (total, "" if total == 1 else "s", len(infos)))
            for index, info in enumerate(infos):
                if index >= cfg["max_entries"]:
                    members["not_attempted"] = len(infos) - index
                    ctx.limit_hit("%d members are past max_entries (%d): not listed, not read" % (len(infos) - index, cfg["max_entries"]))
                    break
                if ctx.expired("the member loop"):
                    members["not_attempted"] = len(infos) - index
                    break
                members["listed"] += 1
                name = info.filename
                by_name.setdefault(name.lower(), info)
                seen[name] = seen.get(name, 0) + 1
                shown = member_name(name, ctx)
                row = {"name": shown, "bytes": info.file_size, "compressed": info.compress_size, "method": info.compress_type,
                       "modified": "%04d-%02d-%02dT%02d:%02d:%02d" % info.date_time}
                if shown != name:
                    row["name_withheld"] = True
                if info.flag_bits & 0x1:
                    row["encrypted"] = True
                    members["flagged_encrypted"] += 1
                parts.add(row)
            for name, count in seen.items():
                if count > 1:
                    ctx.problem("the member name %s appears %d times: an OPC package has one part of each name, and readers resolve a repeated one differently" % (shown_path(name), count))
            if members["flagged_encrypted"]:
                ctx.problem("%d member%s marked encrypted in the directory: its content is not examined" % (members["flagged_encrypted"], "" if members["flagged_encrypted"] == 1 else "s"))
                out["encryption_items"].append({"where": "ZIP central directory", "scheme": "member-level ZIP encryption (general purpose flag bit 0 or AES method 99)", "members": members["flagged_encrypted"]})
            names = set(by_name)
            out["kind"] = ("Word" if "word/document.xml" in names else "Excel" if any(n.startswith("xl/") for n in names)
                           else "PowerPoint" if any(n.startswith("ppt/") for n in names) else "a ZIP with no word/, xl/ or ppt/ part names")
            out["opc_markers"] = {"[Content_Types].xml": "[content_types].xml" in names, "_rels/.rels": "_rels/.rels" in names}
            # [Content_Types].xml
            ct = by_name.get("[content_types].xml")
            if ct is not None:
                overrides, defaults, notable = ctx.page("content_types"), 0, []

                def element(local, _ns, attrs):
                    nonlocal defaults
                    if local == "Default":
                        defaults += 1
                        kind = attrs.get("ContentType", "")
                        row = {"extension": text_of(attrs.get("Extension", ""), None, "names"), "content_type": text_of(kind, None, "names")}
                    elif local == "Override":
                        kind = attrs.get("ContentType", "")
                        row = {"part": shown_path(attrs.get("PartName", "")), "content_type": text_of(kind, None, "names")}
                    else:
                        return
                    overrides.add(row)
                    if any(k in kind for k in NOTABLE_CONTENT_TYPES) and len(notable) < 50 and row not in notable:
                        notable.append(row)

                try:
                    xml_elements(stream_member(archive, ct, ctx.budget), element)
                    members["read"] += 1
                    out["content_types"] = {"read": True, "notable": notable, "table": "content_types"}
                except Unreadable as exc:
                    zip_unreadable(ctx, members, "[Content_Types].xml", exc)
                except DoctypeRefused:
                    ctx.problem("[Content_Types].xml contains a DOCTYPE, which is refused: it was not parsed")
                except xml.parsers.expat.ExpatError as exc:
                    ctx.problem("[Content_Types].xml is not well-formed XML (%s): the entries before the error are listed" % xml.parsers.expat.ErrorString(exc.code))
            else:
                ctx.problem("no [Content_Types].xml member: an OPC package needs one")
            # protection elements
            for part in ("word/settings.xml", "xl/workbook.xml", "ppt/presentation.xml"):
                info = by_name.get(part)
                if info is None:
                    continue
                found = []

                def element2(local, _ns, attrs, found=found):
                    if local in PROTECTION_ELEMENTS and len(found) < 20:
                        found.append(protection_row(local, attrs))

                try:
                    xml_elements(stream_member(archive, info, ctx.budget), element2)
                    members["read"] += 1
                except Unreadable as exc:
                    zip_unreadable(ctx, members, part, exc)
                except DoctypeRefused:
                    ctx.problem("%s contains a DOCTYPE, which is refused: it was not parsed" % part)
                except xml.parsers.expat.ExpatError as exc:
                    ctx.problem("%s is not well-formed XML (%s): the elements before the error are listed" % (part, xml.parsers.expat.ErrorString(exc.code)))
                for row in found:
                    out["protection_items"].append({"where": part, **row, "note": "an editing restriction, not encryption: the content is readable without a password"})
            # embedded VBA projects
            projects = []
            for lowered, info in by_name.items():
                if lowered.endswith("vbaproject.bin"):
                    shown = shown_path(info.filename)
                    try:
                        blob = read_member(archive, info, ctx)
                    except Unreadable as exc:
                        zip_unreadable(ctx, members, shown, exc)
                        continue
                    members["read"] += 1
                    try:
                        body, _cfb = probe_ole_blob(blob, ctx, extractor, label=info.filename)
                    except CfbError as exc:
                        ctx.problem("%s is not read as a compound file: %s" % (shown, exc))
                        continue
                    projects.append({"part": shown, "vba_projects": body.get("vba_projects", []), "orphan_entries": body["orphan_entries"], "cfb": body["cfb"]})
            if projects:
                out["vbaproject_parts"] = projects
            if extractor is not None:
                for want in extractor.wanted_args("zip"):
                    info = by_name.get(want.lower())
                    if info is None:
                        continue
                    extractor.write("zip", want, info.filename, stream_member(archive, info, ctx.budget), "ZIP member, byte for byte")
    out["coverage"] = {"structures_read": ZIP_READ, "structures_not_read": ZIP_NOT_READ}
    return out


# --- PDF (ISO 32000) -------------------------------------------------------------------------------------------------------

PDF_READ = ["the header line, the cross-reference chain (tables, streams, hybrid files; every revision) and the trailers",
            "every indexed object's header and dictionary (not stream contents), and the objects held in object streams",
            "stream filters, named; stream lengths declared and measured",
            "the encryption dictionary named by the current trailer: handler, version, revision, crypt filters, permission bits",
            "actions (OpenAction, additional-actions, link and widget annotations, form fields, outlines, the JavaScript name tree) and the way each is reached",
            "embedded files named by file specifications, and the page tree's counts"]
PDF_NOT_READ = ["page content streams, fonts, images and metadata", "the content of JavaScript, embedded files and object streams unless extract asks for it",
                "the plaintext of an encrypted file: no key is tried (not even the empty password), so objects inside encrypted object streams are not parsed",
                "filters other than FlateDecode, ASCIIHexDecode, ASCII85Decode and RunLengthDecode (LZW, JBIG2, JPX, DCT and CCITT streams are listed with their filter, not decoded)",
                "whether an action would run: that depends on the reader, its version and its settings"]
WS_BYTES = b"\x00\t\n\x0c\r "
WS_SET = frozenset(WS_BYTES)
REGULAR_END = re.compile(rb"[\x00\t\n\x0c\r ()<>\[\]{}/%]")
NUM_RE = re.compile(rb"[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)")
REF_RE = re.compile(rb"([0-9]{1,10})[\x00\t\n\x0c\r ]+([0-9]{1,5})[\x00\t\n\x0c\r ]+R(?![^\x00\t\n\x0c\r ()<>\[\]{}/%])")
OBJ_RE = re.compile(rb"[\x00\t\n\x0c\r ]*([0-9]{1,10})[\x00\t\n\x0c\r ]+([0-9]{1,5})[\x00\t\n\x0c\r ]+obj(?![A-Za-z0-9])")
SCAN_OBJ = re.compile(rb"(?<![0-9])([0-9]{1,10})[ \t\r\n\x00\x0c]+([0-9]{1,5})[ \t\r\n\x00\x0c]+obj(?![A-Za-z0-9])")
XREF_ENTRY = re.compile(rb"[\x00\t\n\x0c\r ]*([0-9]{1,10})[\x00\t\n\x0c\r ]+([0-9]{1,5})[\x00\t\n\x0c\r ]+([nf])")
EOL_RE = re.compile(rb"[\r\n]")
STRING_SPECIAL = re.compile(rb"[()\\]")
HEX_NAME = re.compile(rb"#([0-9A-Fa-f]{2})")
MAX_OBJECT_WINDOW = 32 << 20
MAX_ITEMS = 1_000_000
ACTION_SUBTYPES = {"JavaScript", "Launch", "URI", "SubmitForm", "GoToR", "GoToE", "ImportData", "Named", "Rendition", "Movie", "Sound", "GoTo", "Thread",
                   "ResetForm", "Hide", "SetOCGState", "Trans", "GoTo3DView", "RichMediaExecute", "SetState", "NoOp"}
SUPPORTED_FILTERS = {"FlateDecode": "FlateDecode", "Fl": "FlateDecode", "ASCIIHexDecode": "ASCIIHexDecode", "AHx": "ASCIIHexDecode",
                     "ASCII85Decode": "ASCII85Decode", "A85": "ASCII85Decode", "RunLengthDecode": "RunLengthDecode", "RL": "RunLengthDecode"}
PREDICTOR_MAX = 4 << 20
MAX_FILTERS = 8
MAX_REVISIONS = 1000
MAX_HEADER_PAIRS = 1_000_000


class PdfError(Exception):
    pass


class NeedMore(PdfError):
    pass


class Name(str):
    __slots__ = ()


class PStr(bytes):
    __slots__ = ()


class Ref:
    __slots__ = ("num", "gen")

    def __init__(self, num, gen):
        self.num, self.gen = num, gen


class _Null:
    def __bool__(self):
        return False


NULL = _Null()


def unescape_name(raw):
    return HEX_NAME.sub(lambda m: bytes([int(m.group(1), 16)]), raw).decode("utf-8", "surrogateescape")


class Lexer:
    """PDF syntax over a window of bytes. `final` says that the window ends at the end of the file: running off the end is then
    an error, and otherwise a request for a longer window (NeedMore)."""

    def __init__(self, buf, pos, final, max_depth):
        self.buf, self.pos, self.final, self.max_depth = buf, pos, final, max_depth

    def eof(self):
        if self.final:
            raise PdfError("unexpected end of the data")
        raise NeedMore()

    def skip(self):
        buf, n = self.buf, len(self.buf)
        while self.pos < n:
            c = buf[self.pos]
            if c in WS_SET:
                self.pos += 1
            elif c == 0x25:
                m = EOL_RE.search(buf, self.pos)
                self.pos = m.end() if m else n
            else:
                break

    def token_end(self, start):
        m = REGULAR_END.search(self.buf, start)
        if m:
            return m.start()
        if not self.final:
            raise NeedMore()
        return len(self.buf)

    def parse(self, depth=0):
        if depth > self.max_depth:
            raise PdfError("objects nest deeper than max_depth (%d)" % self.max_depth)
        self.skip()
        buf = self.buf
        if self.pos >= len(buf):
            self.eof()
        c = buf[self.pos]
        if c == 0x2F:
            end = self.token_end(self.pos + 1)
            name = Name(unescape_name(buf[self.pos + 1:end]))
            self.pos = end
            return name
        if c == 0x3C:
            if buf[self.pos:self.pos + 2] == b"<<":
                return self.dictionary(depth)
            if len(buf) - self.pos < 2:
                self.eof()
            return self.hex_string()
        if c == 0x5B:
            return self.array(depth)
        if c == 0x28:
            return self.literal()
        if c in b"+-.0123456789":
            if not self.final and len(buf) - self.pos < 64:
                raise NeedMore()
            m = REF_RE.match(buf, self.pos)
            if m:
                self.pos = m.end()
                return Ref(int(m.group(1)), int(m.group(2)))
            m = NUM_RE.match(buf, self.pos)
            if not m:
                raise PdfError("a malformed number at %d" % self.pos)
            self.pos = m.end()
            text = m.group()
            if b"." in text:
                try:
                    return float(text)
                except ValueError:
                    raise PdfError("a malformed number")
            return int(text)
        end = self.token_end(self.pos)
        word = buf[self.pos:end]
        if word == b"true":
            self.pos = end
            return True
        if word == b"false":
            self.pos = end
            return False
        if word == b"null":
            self.pos = end
            return NULL
        raise PdfError("an unexpected token %r at %d" % (word[:20], self.pos))

    def dictionary(self, depth):
        self.pos += 2
        out = {}
        while True:
            self.skip()
            if self.pos + 1 >= len(self.buf):
                self.eof()
            if self.buf[self.pos:self.pos + 2] == b">>":
                self.pos += 2
                return out
            key = self.parse(depth + 1)
            if not isinstance(key, Name):
                raise PdfError("a dictionary key that is not a name, at %d" % self.pos)
            out[str(key)] = self.parse(depth + 1)
            if len(out) > MAX_ITEMS:
                raise PdfError("a dictionary of more than %d entries" % MAX_ITEMS)

    def array(self, depth):
        self.pos += 1
        out = []
        while True:
            self.skip()
            if self.pos >= len(self.buf):
                self.eof()
            if self.buf[self.pos] == 0x5D:
                self.pos += 1
                return out
            out.append(self.parse(depth + 1))
            if len(out) > MAX_ITEMS:
                raise PdfError("an array of more than %d items" % MAX_ITEMS)

    def hex_string(self):
        end = self.buf.find(b">", self.pos)
        if end < 0:
            self.eof()
        digits = re.sub(rb"[^0-9A-Fa-f]", b"", self.buf[self.pos + 1:end])
        if len(digits) % 2:
            digits += b"0"
        self.pos = end + 1
        return PStr(bytes.fromhex(digits.decode("ascii")))

    def literal(self):
        buf, pos, depth, out = self.buf, self.pos + 1, 1, bytearray()
        while True:
            m = STRING_SPECIAL.search(buf, pos)
            if not m:
                self.pos = len(buf)
                self.eof()
                raise PdfError("an unterminated string")
            out += buf[pos:m.start()]
            c, pos = buf[m.start()], m.start() + 1
            if c == 0x28:
                depth += 1
                out.append(c)
            elif c == 0x29:
                depth -= 1
                if depth == 0:
                    self.pos = pos
                    return PStr(bytes(out))
                out.append(c)
            else:
                if pos >= len(buf):
                    self.pos = len(buf)
                    self.eof()
                e = buf[pos]
                pos += 1
                if e in b"nrtbf":
                    out.append({0x6E: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x66: 12}[e])
                elif 0x30 <= e <= 0x37:
                    digits = bytes([e])
                    while len(digits) < 3 and pos < len(buf) and 0x30 <= buf[pos] <= 0x37:
                        digits += bytes([buf[pos]])
                        pos += 1
                    out.append(int(digits, 8) & 0xFF)
                elif e == 0x0D:
                    if pos < len(buf) and buf[pos] == 0x0A:
                        pos += 1
                elif e == 0x0A:
                    pass
                else:
                    out.append(e)


def text_string(raw):
    """A PDF text string as text: UTF-16 with a byte-order mark, UTF-8 with a mark, or the single-byte PDFDocEncoding read as Latin-1."""
    if raw[:2] == b"\xfe\xff":
        return raw[2:].decode("utf-16-be", "replace")
    if raw[:2] == b"\xff\xfe":
        return raw[2:].decode("utf-16-le", "replace")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", "replace")
    return raw.decode("latin-1")


def png_unpredict(data, columns, colors, bpc):
    rowlen = (columns * colors * bpc + 7) // 8
    bpp = max(1, (colors * bpc + 7) // 8)
    if rowlen < 1 or len(data) < rowlen + 1:
        return b""
    prev = bytearray(rowlen)
    out = bytearray()
    for start in range(0, len(data) - rowlen, rowlen + 1):
        ft = data[start]
        row = bytearray(data[start + 1:start + 1 + rowlen])
        if ft == 1:
            for i in range(bpp, rowlen):
                row[i] = (row[i] + row[i - bpp]) & 0xFF
        elif ft == 2:
            for i in range(rowlen):
                row[i] = (row[i] + prev[i]) & 0xFF
        elif ft == 3:
            for i in range(rowlen):
                left = row[i - bpp] if i >= bpp else 0
                row[i] = (row[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ft == 4:
            for i in range(rowlen):
                a = row[i - bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i - bpp] if i >= bpp else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pred = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                row[i] = (row[i] + pred) & 0xFF
        elif ft != 0:
            raise PdfError("a PNG predictor row of type %d" % ft)
        out += row
        prev = row
    return bytes(out)


class Obj:
    __slots__ = ("num", "gen", "value", "offset", "stream", "header_offset")


class Pdf:
    def __init__(self, blob, ctx):
        self.blob, self.size, self.ctx = blob, len(blob), ctx
        self.cfg = ctx.cfg
        self.entries = {}
        self.cache = {}
        self.objstm_cache = {}
        self.trailers = []
        self.revisions = []
        self.base = 0
        self.resolving = False
        self.scan_budget = 4 * self.size + (64 << 20)
        self.unreadable_compressed = 0
        self.encrypted = False
        self.length_problems = 0

    def problem(self, text):
        self.ctx.problem(text)

    # parsing at an offset, with a window that grows ---------------------------------------------------------------------

    def parse_at(self, off, fn):
        window = 1 << 16
        while True:
            end = min(self.size, off + window)
            buf = self.blob[off:end]
            lx = Lexer(buf, 0, end >= self.size, min(self.cfg["max_depth"], 150))
            try:
                return fn(lx), off
            except NeedMore:
                if end >= self.size or window >= MAX_OBJECT_WINDOW:
                    raise PdfError("an object longer than the %d-byte window, or cut off by the end of the file" % MAX_OBJECT_WINDOW)
                window *= 4

    def read_indirect(self, off, expect=None):
        """The object whose 'N G obj' header is at `off` (relative to the file; the header's own offset shift is tried when it is not
        there). Parses the value; for a stream, locates the data and checks its length against the 'endstream' keyword."""
        last = None
        for shift in ((0, self.base) if self.base else (0,)):
            at = off + shift
            if at < 0 or at >= self.size:
                continue

            def fn(lx):
                m = OBJ_RE.match(lx.buf, 0)
                if not m:
                    raise PdfError("no 'N G obj' header at offset %d" % at)
                lx.pos = m.end()
                value = lx.parse()
                lx.skip()
                stream_at = None
                if isinstance(value, dict) and lx.buf.startswith(b"stream", lx.pos):
                    if not lx.final and len(lx.buf) - lx.pos < 12:
                        raise NeedMore()
                    p = lx.pos + 6
                    if lx.buf[p:p + 2] == b"\r\n":
                        p += 2
                    elif lx.buf[p:p + 1] in (b"\n", b"\r"):
                        p += 1
                    stream_at = p
                return int(m.group(1)), int(m.group(2)), value, stream_at

            try:
                (num, gen, value, stream_at), _ = self.parse_at(at, fn)
            except PdfError as exc:
                last = last or exc
                continue
            if expect is not None and num != expect:
                self.problem("the cross-reference entry for object %d points at the header of object %d (offset %d)" % (expect, num, at))
            o = Obj()
            o.num, o.gen, o.value, o.offset, o.stream, o.header_offset = num, gen, value, at, None, shift
            if stream_at is not None:
                o.stream = self.locate_stream(value, at, stream_at)
            return o
        raise last or PdfError("no object header at offset %d" % off)

    def locate_stream(self, value, base_off, rel_stream_at):
        """Where a stream's bytes are: {start, declared, measured, length, consistent}. `rel_stream_at` is relative to the window start."""
        start = base_off + rel_stream_at
        declared = value.get("Length")
        if isinstance(declared, Ref):
            declared = self.int_of(declared)
        if isinstance(declared, bool) or not isinstance(declared, int) or declared < 0:
            declared = None
        ok = False
        if declared is not None and start + declared <= self.size:
            tail = self.blob[start + declared:start + declared + 24]
            ok = re.match(rb"[\x00\t\n\x0c\r ]*endstream", tail) is not None
        measured = None
        if not ok:
            if self.scan_budget > 0:
                idx = self.blob.find(b"endstream", start)
                self.scan_budget -= max(1, (idx if idx >= 0 else self.size) - start)
                if idx >= 0:
                    end = idx
                    if self.blob[end - 2:end] == b"\r\n":
                        end -= 2
                    elif self.blob[end - 1:end] in (b"\n", b"\r"):
                        end -= 1
                    measured = max(0, end - start)
            else:
                self.ctx.limit_hit("stream lengths: the search for 'endstream' used its budget; later streams with a wrong /Length are listed without a measured length")
        length = declared if ok else measured
        return {"start": start, "declared": declared, "measured": measured, "length": length, "consistent": ok}

    def int_of(self, ref):
        if self.resolving:
            return None
        self.resolving = True
        try:
            o = self.get(ref.num)
        finally:
            self.resolving = False
        return o.value if o is not None and isinstance(o.value, int) and not isinstance(o.value, bool) else None

    # objects ----------------------------------------------------------------------------------------------------------

    def get(self, num):
        if num in self.cache:
            return self.cache[num]
        entry = self.entries.get(num)
        o = None
        if entry is not None:
            try:
                if entry[0] == 1:
                    o = self.read_indirect(entry[1], num)
                elif entry[0] == 2:
                    o = self.from_objstm(entry[1], entry[2], num)
            except (PdfError, Over) as exc:
                if isinstance(exc, Over):
                    raise
                self.problem("object %d could not be read: %s" % (num, exc))
        if len(self.cache) > 4000:
            self.cache.clear()
        self.cache[num] = o
        return o

    def deref(self, x, hops=8):
        num = None
        while isinstance(x, Ref) and hops > 0:
            o = self.get(x.num)
            if o is None:
                return None, x.num
            num, x, hops = x.num, o.value, hops - 1
        if isinstance(x, (Ref, _Null)):
            return None, num
        return x, num

    # stream decoding --------------------------------------------------------------------------------------------------

    def filters_of(self, value):
        raw, _ = self.deref(value.get("Filter"))
        parms, _ = self.deref(value.get("DecodeParms", value.get("DP")))
        names = [raw] if isinstance(raw, Name) else [self.deref(x)[0] for x in raw] if isinstance(raw, list) else []
        plist = [parms] if isinstance(parms, dict) else [self.deref(x)[0] for x in parms] if isinstance(parms, list) else []
        out = []
        for i, name in enumerate(names[:MAX_FILTERS + 1]):
            p = plist[i] if i < len(plist) and isinstance(plist[i], dict) else {}
            out.append((str(name) if isinstance(name, Name) else "?", p))
        return out

    def decode(self, o, cap=None):
        """The decoded bytes of a stream object under the budgets. Raises PdfError (a filter this tool does not decode, a corrupt stream)
        or Over. A stream is never returned cut."""
        info = o.stream
        if info is None or info["length"] is None:
            raise PdfError("the stream's length cannot be established")
        cap = self.ctx.budget.member if cap is None else min(cap, self.ctx.budget.member)
        if info["length"] > 2 * cap:
            raise Over("a stream of %d bytes is over twice max_stream_bytes (%d): not read" % (info["length"], cap))
        data = self.blob[info["start"]:info["start"] + info["length"]]
        chain = self.filters_of(o.value)
        if len(chain) > MAX_FILTERS:
            raise PdfError("a chain of more than %d filters" % MAX_FILTERS)
        for name, parms in chain:
            canon = SUPPORTED_FILTERS.get(name)
            if name == "Crypt":
                if str(parms.get("Name", "Identity")) != "Identity":
                    raise PdfError("a Crypt filter that is not the identity")
                continue
            if canon is None:
                raise PdfError("the %s filter is not decoded by this tool" % text_of(name, None, "names"))
            if canon == "FlateDecode":
                d = zlib.decompressobj()
                out = bytearray()
                pos = 0
                try:
                    while pos < len(data) and not d.eof:
                        chunk = data[pos:pos + PAGE]
                        pos += len(chunk)
                        piece = d.decompress(chunk, cap + 1 - len(out))
                        out += piece
                        while d.unconsumed_tail and len(out) <= cap:
                            piece = d.decompress(d.unconsumed_tail, cap + 1 - len(out))
                            out += piece
                        if len(out) > cap:
                            raise Over("a stream expanded past max_stream_bytes (%d)" % cap)
                        if len(out) > RATIO_FLOOR and len(out) > self.ctx.budget.ratio * max(len(data), 1):
                            raise Over("a stream expanded past max_ratio (%d) of its compressed size" % self.ctx.budget.ratio)
                except zlib.error as exc:
                    raise PdfError("the Flate data is corrupt (%s)" % exc)
                if not d.eof:
                    raise PdfError("the Flate data ends before its end marker")
                data = bytes(out)
            elif canon == "ASCIIHexDecode":
                end = data.find(b">")
                digits = re.sub(rb"[^0-9A-Fa-f]", b"", data if end < 0 else data[:end])
                data = bytes.fromhex((digits + (b"0" if len(digits) % 2 else b"")).decode("ascii"))
            elif canon == "ASCII85Decode":
                body = data.strip()
                if body.startswith(b"<~"):
                    body = body[2:]
                end = body.find(b"~>")
                body = body if end < 0 else body[:end]
                try:
                    data = base64.a85decode(body, adobe=False, ignorechars=b" \t\n\r\x0b\x00\x0c")
                except ValueError as exc:
                    raise PdfError("the ASCII85 data is corrupt (%s)" % exc)
            elif canon == "RunLengthDecode":
                out, i = bytearray(), 0
                while i < len(data):
                    n = data[i]
                    i += 1
                    if n == 128:
                        break
                    if n < 128:
                        out += data[i:i + n + 1]
                        i += n + 1
                    else:
                        out += data[i:i + 1] * (257 - n)
                        i += 1
                    if len(out) > cap:
                        raise Over("a stream expanded past max_stream_bytes (%d)" % cap)
                data = bytes(out)
            predictor = parms.get("Predictor", 1) if isinstance(parms, dict) else 1
            if canon == "FlateDecode" and isinstance(predictor, int) and predictor > 1:
                if predictor == 2:
                    raise PdfError("a TIFF predictor is not decoded by this tool")
                if len(data) > PREDICTOR_MAX:
                    raise Over("a predictor-coded stream of %d bytes is over the %d-byte limit for undoing a predictor" % (len(data), PREDICTOR_MAX))
                get = lambda k, d: parms.get(k) if isinstance(parms.get(k), int) and not isinstance(parms.get(k), bool) else d
                data = png_unpredict(data, get("Columns", 1), get("Colors", 1), get("BitsPerComponent", 8))
        self.ctx.spend(len(data), "a stream")
        return data

    # object streams ---------------------------------------------------------------------------------------------------

    def objstm(self, num):
        if num in self.objstm_cache:
            return self.objstm_cache[num]
        entry = self.entries.get(num)
        o = self.get(num) if entry is not None and entry[0] == 1 else None
        res = None
        if o is None or o.stream is None or not isinstance(o.value, dict) or o.value.get("Type") != "ObjStm":
            raise PdfError("object %d is not an object stream" % num)
        n, first = o.value.get("N"), o.value.get("First")
        if not (isinstance(n, int) and isinstance(first, int)) or n < 0 or first < 0 or n > MAX_HEADER_PAIRS:
            raise PdfError("object stream %d has no usable /N and /First" % num)
        data = self.decode(o)
        nums = [int(x) for x in re.findall(rb"[0-9]+", data[:first])[:2 * n]]
        if len(nums) < 2 * n:
            raise PdfError("object stream %d lists %d of the %d objects it declares" % (num, len(nums) // 2, n))
        res = (data, first, [(nums[2 * i], nums[2 * i + 1]) for i in range(n)])
        if len(self.objstm_cache) >= 6:
            self.objstm_cache.pop(next(iter(self.objstm_cache)))
        self.objstm_cache[num] = res
        return res

    def from_objstm(self, stm, index, num):
        try:
            data, first, pairs = self.objstm(stm)
        except PdfError as exc:
            self.unreadable_compressed += 1
            raise PdfError("object %d lives in object stream %d, which cannot be read: %s" % (num, stm, exc))
        if not (0 <= index < len(pairs)) or pairs[index][0] != num:
            idx = next((i for i, p in enumerate(pairs) if p[0] == num), None)
            if idx is None:
                raise PdfError("object %d is not in object stream %d" % (num, stm))
            index = idx
        at = first + pairs[index][1]
        if at >= len(data):
            raise PdfError("object %d's offset is outside object stream %d" % (num, stm))
        lx = Lexer(data, at, True, min(self.cfg["max_depth"], 150))
        value = lx.parse()
        o = Obj()
        o.num, o.gen, o.value, o.offset, o.stream, o.header_offset = num, 0, value, None, None, 0
        return o

    # cross-reference chain --------------------------------------------------------------------------------------------

    def find_startxref(self):
        tail = self.blob[max(0, self.size - 4096):]
        i = tail.rfind(b"startxref")
        if i < 0:
            return None
        m = re.match(rb"startxref[\x00\t\n\x0c\r ]+([0-9]{1,15})", tail[i:])
        return int(m.group(1)) if m else None

    def read_xref_chain(self, start):
        seen, off = set(), start
        pending = [("startxref", off)]
        while pending and len(self.revisions) < MAX_REVISIONS:
            how, off = pending.pop(0)
            if off in seen:
                self.problem("the cross-reference chain returns to offset %d: a /Prev loop" % off)
                break
            seen.add(off)
            if self.ctx.expired("the cross-reference chain"):
                return False
            try:
                nxt = self.read_xref_section(off, how)
            except PdfError as exc:
                self.problem("the cross-reference section at offset %d cannot be read: %s" % (off, exc))
                return False
            pending.extend(nxt)
        if pending:
            self.ctx.limit_hit("the cross-reference chain has more than %d sections: the rest were not followed" % MAX_REVISIONS)
        return True

    def read_xref_section(self, off, how):
        for shift in ((0, self.base) if self.base else (0,)):
            at = off + shift
            if at < 0 or at >= self.size:
                continue
            head = self.blob[at:at + 64].lstrip(WS_BYTES)
            if head.startswith(b"xref"):
                return self.read_xref_table(at, off, how)
            if OBJ_RE.match(self.blob[at:at + 64]):
                return self.read_xref_stream(at, off, how)
        raise PdfError("neither an 'xref' keyword nor an object header is there")

    def add_entry(self, num, kind, a, b, over_free=False):
        if num in self.entries:
            # A hybrid file lists, as free in its table, the objects its cross-reference stream defines: the stream's entry takes the free one's place.
            if over_free and self.entries[num][0] == 0 and kind != 0:
                self.entries[num] = (kind, a, b)
            return
        if len(self.entries) >= self.cfg["max_objects"]:
            if not self.ctx.cfg.get("_objects_capped"):
                self.ctx.cfg["_objects_capped"] = True
                self.ctx.limit_hit("the cross-reference sections list more than max_objects (%d) objects: the rest are not indexed" % self.cfg["max_objects"])
            return
        self.entries[num] = (kind, a, b)

    def read_xref_table(self, at, off, how):
        pos = at + (len(self.blob[at:at + 64]) - len(self.blob[at:at + 64].lstrip(WS_BYTES))) + 4
        count_entries = 0
        while True:
            window = self.blob[pos:pos + 64]
            m = re.match(rb"[\x00\t\n\x0c\r ]*([0-9]{1,10})[\x00\t\n\x0c\r ]+([0-9]{1,10})", window)
            if not m:
                break
            first, count = int(m.group(1)), int(m.group(2))
            pos += m.end()
            if count > (self.size - pos) // 18 + 1:
                raise PdfError("a subsection declares %d entries and the file cannot hold them" % count)
            body = self.blob[pos:pos + count * 20 + 40]
            ent = XREF_ENTRY
            p = 0
            for i in range(count):
                em = ent.match(body, p)
                if not em:
                    raise PdfError("entry %d of a subsection that starts at object %d is malformed" % (i, first))
                p = em.end()
                if em.group(3) == b"n":
                    self.add_entry(first + i, 1, int(em.group(1)), int(em.group(2)))
                else:
                    self.add_entry(first + i, 0, 0, int(em.group(2)))
                count_entries += 1
                if i % 4096 == 0 and self.ctx.expired("a cross-reference table"):
                    raise PdfError("the clock ran out inside a cross-reference table")
            pos += p
        rest = self.blob[pos:pos + 16].lstrip(WS_BYTES)
        if not rest.startswith(b"trailer"):
            raise PdfError("no 'trailer' keyword after the table")
        tpos = pos + (len(self.blob[pos:pos + 16]) - len(rest)) + 7
        trailer, _ = self.parse_at(tpos, lambda lx: lx.parse())
        if not isinstance(trailer, dict):
            raise PdfError("the trailer is not a dictionary")
        self.trailers.append(trailer)
        rev = {"index": len(self.revisions), "kind": "table", "startxref": off, "entries": count_entries, "size": trailer.get("Size") if isinstance(trailer.get("Size"), int) else None,
               "prev": trailer.get("Prev") if isinstance(trailer.get("Prev"), int) else None, "encrypt_in_trailer": "Encrypt" in trailer}
        self.revisions.append(rev)
        nxt = []
        xs = trailer.get("XRefStm")
        if isinstance(xs, int) and not isinstance(xs, bool):
            rev["hybrid_xrefstm"] = xs
            nxt.append(("XRefStm", xs))
        if isinstance(trailer.get("Prev"), int):
            nxt.append(("Prev", trailer["Prev"]))
        return nxt

    def read_xref_stream(self, at, off, how):
        o = self.read_indirect(off, None)
        v = o.value
        if not isinstance(v, dict) or v.get("Type") != "XRef" or o.stream is None:
            raise PdfError("the object at offset %d is not a cross-reference stream" % off)
        w = v.get("W")
        if not (isinstance(w, list) and len(w) == 3 and all(isinstance(x, int) and 0 <= x <= 8 for x in w)) or sum(w) == 0:
            raise PdfError("the cross-reference stream has no usable /W")
        size = v.get("Size")
        if not isinstance(size, int):
            raise PdfError("the cross-reference stream has no /Size")
        index = v.get("Index") if isinstance(v.get("Index"), list) else [0, size]
        if len(index) % 2 or not all(isinstance(x, int) and x >= 0 for x in index):
            raise PdfError("the cross-reference stream's /Index is not a list of pairs")
        data = self.decode(o)
        width = sum(w)
        total = len(data) // width
        entries, pos = 0, 0
        for k in range(0, len(index), 2):
            first, count = index[k], index[k + 1]
            for i in range(count):
                if pos + width > len(data):
                    self.problem("the cross-reference stream holds %d entries and its /Index declares more" % (pos // width))
                    break
                f1 = int.from_bytes(data[pos:pos + w[0]], "big") if w[0] else 1
                f2 = int.from_bytes(data[pos + w[0]:pos + w[0] + w[1]], "big")
                f3 = int.from_bytes(data[pos + w[0] + w[1]:pos + width], "big") if w[2] else 0
                pos += width
                entries += 1
                hybrid = how == "XRefStm"
                if f1 == 1:
                    self.add_entry(first + i, 1, f2, f3, hybrid)
                elif f1 == 2:
                    self.add_entry(first + i, 2, f2, f3, hybrid)
                elif f1 == 0:
                    self.add_entry(first + i, 0, 0, f3)
                if entries % 8192 == 0 and self.ctx.expired("a cross-reference stream"):
                    raise PdfError("the clock ran out inside a cross-reference stream")
        self.trailers.append(v)
        rev = {"index": len(self.revisions), "kind": "stream", "startxref": off, "entries": entries, "size": size,
               "prev": v.get("Prev") if isinstance(v.get("Prev"), int) else None, "encrypt_in_trailer": "Encrypt" in v}
        self.revisions.append(rev)
        return [("Prev", v["Prev"])] if isinstance(v.get("Prev"), int) else []


def is_action(d):
    if not isinstance(d, dict):
        return False
    s = d.get("S")
    return (isinstance(s, Name) and str(s) in ACTION_SUBTYPES and d.get("Type") in (None, "Action")) or ("JS" in d and d.get("Type") in (None, "Action"))


def pdf_encryption(pdf, ctx):
    """The encryption dictionary the newest trailer names, read as structure: handler, version, revision, crypt filters, permission
    bits; the owner and user verifiers and their companions are reported by length and never as bytes."""
    if not pdf.trailers:
        return None
    holder = next((t for t in pdf.trailers if "Encrypt" in t), None)
    if holder is None:
        return {"present": False}
    current = pdf.trailers[0]
    entry = {"present": "Encrypt" in current, "in_current_trailer": "Encrypt" in current}
    if not entry["in_current_trailer"]:
        entry["in_an_earlier_revision_only"] = True
        entry["note"] = "an earlier revision's trailer names an encryption dictionary and the current one does not: the current trailer is what a reader follows, and the file's objects may still be encrypted"
        return entry
    d, num = pdf.deref(holder["Encrypt"])
    if not isinstance(d, dict):
        ctx.problem("the trailer's /Encrypt does not lead to a dictionary")
        entry["dictionary"] = "unreadable"
        return entry
    out = {"object": num}
    for key, name in (("Filter", "filter"), ("SubFilter", "sub_filter"), ("StmF", "stm_f"), ("StrF", "str_f"), ("EFF", "eff")):
        if isinstance(d.get(key), Name):
            out[name] = text_of(str(d[key]), None, "names")
    for key, name in (("V", "v"), ("R", "r"), ("Length", "length_bits")):
        if isinstance(d.get(key), int) and not isinstance(d.get(key), bool):
            out[name] = d[key]
    p = d.get("P")
    if isinstance(p, int) and not isinstance(p, bool):
        u = p & 0xFFFFFFFF
        out["permissions"] = {"signed": u - (1 << 32) if u & 0x80000000 else u, "hex": "0x%08X" % u, "note": "permission flags: what a conforming reader is asked to allow, not a protection"}
    if isinstance(d.get("EncryptMetadata"), bool):
        out["encrypt_metadata"] = d["EncryptMetadata"]
    cf, _ = pdf.deref(d.get("CF"))
    if isinstance(cf, dict):
        filters = {}
        for name, f in list(cf.items())[:20]:
            f, _n = pdf.deref(f)
            if isinstance(f, dict):
                filters[text_of(name, None, "names")] = {"cfm": text_of(str(f.get("CFM")), None, "names") if isinstance(f.get("CFM"), Name) else None,
                                                         "length": f.get("Length") if isinstance(f.get("Length"), int) else None,
                                                         "auth_event": text_of(str(f.get("AuthEvent")), None, "names") if isinstance(f.get("AuthEvent"), Name) else None}
        out["crypt_filters"] = filters
    out["verifier_fields_present"] = [{"name": k, "length": len(d[k])} for k in ("O", "U", "OE", "UE", "Perms") if isinstance(d.get(k), PStr)]
    out["not_reported"] = "the owner and user password verifiers (/O, /U, /OE, /UE) and /Perms are in the dictionary and are reported by length only"
    out["not_determined"] = "whether an opening password is needed: no password, empty or otherwise, was tried"
    entry["dictionary"] = out
    return entry


def probe_pdf(blob, ctx, extractor):
    out = {"container": "PDF"}
    cfg = ctx.cfg
    size = len(blob)
    pdf = Pdf(blob, ctx)
    head = blob[:HEAD_BYTES]
    m = re.search(rb"%PDF-(\d\.\d)", head)
    anomalies = []
    if m:
        out["pdf_header"] = {"version": m.group(1).decode("ascii"), "offset": m.start()}
        pdf.base = m.start()
        if m.start():
            anomalies.append("%d byte(s) before the %%PDF- header: offsets in the file are relative to the header in a strict reader and absolute in many others" % m.start())
    else:
        ctx.problem("no %%PDF- header line in the first %d bytes" % HEAD_BYTES)
    eofs = [x.start() for x in re.finditer(rb"%%EOF", blob[max(0, size - (4 << 20)):])]
    out["eof_markers"] = len(eofs) if size <= 4 << 20 else "%d in the last 4 MiB" % len(eofs)
    trail = blob[max(0, size - 4096):].rfind(b"%%EOF")
    if trail >= 0:
        after = blob[max(0, size - 4096) + trail + 5:]
        if after.strip(WS_BYTES):
            anomalies.append("%d non-whitespace byte(s) after the last %%%%EOF marker" % len(after.strip(WS_BYTES)))
    else:
        anomalies.append("no %%EOF marker in the last 4096 bytes")
    structure = "xref"
    start = pdf.find_startxref()
    if start is None:
        ctx.problem("no startxref in the last 4096 bytes: the cross-reference chain is rebuilt by scanning the file")
        structure = "scan"
    else:
        out["startxref"] = start
        try:
            ok = pdf.read_xref_chain(start)
        except Over as exc:
            ctx.limit_hit(str(exc))
            ok = False
        if not ok or not pdf.entries:
            structure = "scan"
    # A scan of the whole file for 'N G obj' headers: the objects a reader that ignores the table would find.
    scanned, scan_total, numbers, truncated_scan = {}, 0, {}, False
    for hit in SCAN_OBJ.finditer(blob):
        scan_total += 1
        n = int(hit.group(1))
        numbers[n] = numbers.get(n, 0) + 1
        scanned[n] = hit.start()
        if scan_total % 8192 == 0 and ctx.expired("the object scan"):
            truncated_scan = True
            break
        if scan_total >= cfg["max_objects"] * 4:
            ctx.limit_hit("the object scan stopped after %d headers (max_objects x 4)" % scan_total)
            truncated_scan = True
            break
    if structure == "scan":
        for n, at in scanned.items():
            pdf.add_entry(n, 1, at, 0)
        if not pdf.trailers:
            # Trailers by scan: every 'trailer' keyword with a dictionary, and cross-reference stream dictionaries found below.
            for t in re.finditer(rb"trailer[\x00\t\n\x0c\r ]*<<", blob):
                try:
                    d, _ = pdf.parse_at(t.end() - 2, lambda lx: lx.parse())
                except PdfError:
                    continue
                if isinstance(d, dict):
                    pdf.trailers.insert(0, d)
        anomalies.append("the cross-reference chain could not be used; the object index comes from scanning the file for object headers, and the newest definition of a number wins")
    out["structure_source"] = "cross-reference chain" if structure == "xref" else "scan of the file for object headers"
    revisions = pdf.revisions
    out["revisions"] = revisions
    out["objects_scan"] = {"object_headers_found": scan_total, "distinct_numbers": len(numbers), "complete": not truncated_scan,
                           "numbers_defined_more_than_once": sum(1 for c in numbers.values() if c > 1)}
    in_table = {n for n, e in pdf.entries.items() if e[0] == 1}
    if structure == "xref":
        extra = [n for n in numbers if n not in in_table and not (n in pdf.entries)]
        out["objects_scan"]["headers_not_in_the_cross_reference_chain"] = len(extra)
        if extra:
            anomalies.append("%d object number(s) have an 'N G obj' header in the file and no entry of kind 'in use' in the cross-reference chain" % len(extra))
    # The census: each indexed object's dictionary, never its stream.
    objects = ctx.page("objects")
    types, filters_seen, streams = {}, {}, {"count": 0, "declared_bytes": 0, "length_inconsistent": 0, "undecodable_filter": 0}
    interesting = {}
    embedded = []
    compressed_total = sum(1 for e in pdf.entries.values() if e[0] == 2)
    unreadable = 0
    census_done = 0
    stop_census = False
    def census(order):
        nonlocal census_done, stop_census, unreadable
        for num in order:
            if stop_census:
                break
            entry = pdf.entries[num]
            if entry[0] == 0:
                continue
            if census_done % 2048 == 0 and ctx.expired("the object census"):
                stop_census = True
                break
            try:
                o = pdf.get(num)
            except Over as exc:
                ctx.limit_hit(str(exc))
                stop_census = True
                break
            census_done += 1
            if o is None:
                unreadable += 1
                continue
            v = o.value
            row = {"object": num, "generation": o.gen}
            if entry[0] == 1:
                row["offset"] = o.offset
            else:
                row["in_object_stream"] = entry[1]
                row["index_in_stream"] = entry[2]
            kind = "dictionary" if isinstance(v, dict) else "array" if isinstance(v, list) else type(v).__name__
            if o.stream is not None:
                kind = "stream"
            row["kind"] = kind
            if isinstance(v, dict):
                t = v.get("Type")
                if isinstance(t, Name):
                    row["type"] = text_of(str(t), None, "names")
                    types[row["type"]] = types.get(row["type"], 0) + 1
                st = v.get("Subtype")
                if isinstance(st, Name):
                    row["subtype"] = text_of(str(st), None, "names")
                if t in ("Catalog", "ObjStm", "XRef", "EmbeddedFile", "Filespec") or "JS" in v or is_action(v) or "EF" in v:
                    interesting[num] = o
            if o.stream is not None:
                info = o.stream
                streams["count"] += 1
                streams["declared_bytes"] += info["declared"] or 0
                chain = [n for n, _p in pdf.filters_of(v)]
                names = [text_of(n, None, "names") for n in chain]
                row["stream"] = {"declared_length": info["declared"], "measured_length": info["measured"], "length_consistent": info["consistent"], "filters": names}
                key = "+".join(names) if names else "none"
                if key in filters_seen or len(filters_seen) < 100:
                    filters_seen[key] = filters_seen.get(key, 0) + 1
                if not info["consistent"]:
                    streams["length_inconsistent"] += 1
                if any(SUPPORTED_FILTERS.get(n) is None and n != "Crypt" for n in chain):
                    streams["undecodable_filter"] += 1
                if len(chain) > 3:
                    row["note"] = "a chain of %d filters" % len(chain)
            objects.add(row)

    census(sorted(pdf.entries))
    if structure == "scan":
        # Objects inside object streams are not listed by any table here: read each object stream found and index what it holds.
        for onum, oo in list(interesting.items()):
            if stop_census:
                break
            if isinstance(oo.value, dict) and oo.value.get("Type") == "ObjStm" and oo.stream is not None:
                try:
                    _data, _first, pairs = pdf.objstm(onum)
                except (PdfError, Over) as exc:
                    (ctx.limit_hit if isinstance(exc, Over) else ctx.problem)("object stream %d was not read: %s" % (onum, exc))
                    continue
                new = []
                for i, (n, _off) in enumerate(pairs):
                    if n not in pdf.entries:
                        pdf.add_entry(n, 2, onum, i)
                        new.append(n)
                census(new)
        if not pdf.trailers:
            pdf.trailers.extend(oo.value for oo in interesting.values() if isinstance(oo.value, dict) and oo.value.get("Type") == "XRef")
    compressed_total = sum(1 for e in pdf.entries.values() if e[0] == 2)
    out["census"] = {"objects_listed": census_done, "objects_in_table_of_kind_free": sum(1 for e in pdf.entries.values() if e[0] == 0), "compressed_objects_indexed": compressed_total,
                     "objects_unreadable": unreadable, "complete": not stop_census}
    if stop_census:
        ctx.limit_hit("the object census stopped early: the counts and the actions found are lower bounds")
    out["streams"] = {**streams, "by_filter_chain": filters_seen}
    out["object_types"] = dict(sorted(types.items(), key=lambda kv: -kv[1])[:50])
    # Trailer and encryption
    trailer = pdf.trailers[0] if pdf.trailers else {}
    out["trailer"] = {"size": trailer.get("Size") if isinstance(trailer.get("Size"), int) else None, "root": isinstance(trailer.get("Root"), Ref),
                      "info": "Info" in trailer, "id": "ID" in trailer, "encrypt": "Encrypt" in trailer, "newest_of": len(pdf.trailers)}
    enc = pdf_encryption(pdf, ctx)
    out["encryption"] = enc
    pdf.encrypted = bool(enc and enc.get("in_current_trailer"))
    if pdf.encrypted and pdf.unreadable_compressed:
        ctx.problem("%d object(s) live in object streams that could not be read; in an encrypted file the streams are encrypted and no key is tried" % pdf.unreadable_compressed)
    # Catalog
    catalog, cnum = (pdf.deref(trailer.get("Root")) if trailer else (None, None))
    if not isinstance(catalog, dict):
        cat = next(((n, o) for n, o in interesting.items() if isinstance(o.value, dict) and o.value.get("Type") == "Catalog"), None)
        if cat:
            catalog, cnum = cat[1].value, cat[0]
            anomalies.append("the trailer's /Root does not lead to a catalog; the catalog found is object %d" % cnum)
    findings = trace_catalog(pdf, ctx, catalog, cnum, interesting, extractor)
    out.update(findings)
    out["anomalies"] = anomalies
    if extractor is not None:
        for kind in ("pdf", "pdf-raw"):
            for arg in extractor.wanted_args(kind):
                o = pdf.get(int(arg))
                if o is None or o.stream is None:
                    ctx.problem("extract %s:%s: the object is not there or is not a stream" % (kind, arg))
                    continue
                if kind == "pdf-raw":
                    info = o.stream
                    if info["length"] is None:
                        ctx.problem("extract pdf-raw:%s: the stream's length cannot be established" % arg)
                        continue
                    extractor.write(kind, arg, "object %s" % arg, pdf_slices(blob, info["start"], info["length"], ctx), "PDF stream bytes, still encoded")
                else:
                    try:
                        data = pdf.decode(o)
                    except (PdfError, Over) as exc:
                        (ctx.limit_hit if isinstance(exc, Over) else ctx.problem)("extract pdf:%s: %s" % (arg, exc))
                        continue
                    extractor.write(kind, arg, "object %s" % arg, data, "PDF stream, filters undone")
    out["coverage"] = {"structures_read": PDF_READ, "structures_not_read": PDF_NOT_READ}
    return out


def pdf_slices(blob, start, length, ctx):
    ctx.spend(length, "a stream")
    pos = start
    end = start + length
    while pos < end:
        yield bytes(blob[pos:min(end, pos + PAGE)])
        pos += PAGE


def filespec_info(pdf, ctx, spec):
    """Name and embedded stream of a file specification dictionary (or a bare file name string)."""
    d, _n = pdf.deref(spec)
    info = {}
    if isinstance(d, PStr):
        info["name"] = d
        return info
    if not isinstance(d, dict):
        return info
    for key in ("UF", "F", "DOS", "Mac", "Unix"):
        v, _ = pdf.deref(d.get(key))
        if isinstance(v, PStr):
            info["name"] = v
            break
    ef, _ = pdf.deref(d.get("EF"))
    if isinstance(ef, dict):
        for key in ("F", "UF"):
            if isinstance(ef.get(key), Ref):
                info["stream_object"] = ef[key].num
                break
    return info


def trace_catalog(pdf, ctx, catalog, cnum, interesting, extractor):
    out = {"catalog": None}
    actions, embedded, seen_actions, scripts = [], [], set(), []
    values = ctx.values
    page = ctx.page("pdf_actions")
    if not isinstance(catalog, dict):
        ctx.problem("no catalog could be found: actions, pages and embedded files were not traced")
        out["actions"] = {"count": 0, "table": "pdf_actions", "traced": False}
        return out
    out["catalog"] = {"object": cnum, "keys": sorted(text_of(k, None, "names") for k in catalog)[:40]}
    visited = set()
    budget = [pdf.cfg["max_objects"]]

    def tick():
        budget[0] -= 1
        if budget[0] < 0:
            raise Over("the traversal of the document's structures visited max_objects (%d) objects: the rest is not traced" % pdf.cfg["max_objects"])
        if budget[0] % 4096 == 0 and ctx.expired("the structure trace"):
            raise Over("the structure trace stopped at max_seconds")

    def describe_action(value, num, trigger, reached=True):
        s = value.get("S")
        subtype = text_of(str(s), None, "names") if isinstance(s, Name) else None
        finding = ctx.next_finding("A")
        row = {"finding_id": finding, "object": num, "action": subtype, "trigger": trigger, "reached_from_catalog": reached}
        if subtype == "JavaScript" or "JS" in value:
            js, jnum = pdf.deref(value.get("JS"))
            o = pdf.get(value["JS"].num) if isinstance(value.get("JS"), Ref) else None
            if o is not None and o.stream is not None:
                row["script"] = {"form": "stream", "object": value["JS"].num, "stream_bytes": o.stream["length"]}
                scripts.append(("stream", o, value["JS"].num))
            elif isinstance(js, PStr):
                row["script"] = {"form": "string", "bytes": len(js)}
                scripts.append(("string", js, num))
            else:
                row["script"] = {"form": "not found"}
        target_value = None
        if subtype == "URI":
            u, _ = pdf.deref(value.get("URI"))
            if isinstance(u, PStr):
                text = text_string(u)
                row["target"] = redact_url(text)
                row["target_length"] = len(text)
                target_value = text
        elif subtype in ("Launch", "GoToR", "GoToE", "SubmitForm", "ImportData"):
            fs = filespec_info(pdf, ctx, value.get("F"))
            if "name" in fs:
                text = text_string(fs["name"])
                shown = redact_url(text) if re.match(r"[A-Za-z][A-Za-z0-9+.-]*://", text) else shown_path(text)
                row["target"] = cell(shown)
                row["target_length"] = len(text)
                target_value = text
            win, _ = pdf.deref(value.get("Win"))
            if isinstance(win, dict):
                row["windows_launch"] = {k: (len(win[k]) if isinstance(win.get(k), PStr) else None) for k in ("F", "D", "O", "P") if k in win}
                row["windows_launch_note"] = "the lengths of the file, directory, operation and parameter strings of a Launch action's Win dictionary; their text is not reported"
        elif subtype == "Named":
            n = value.get("N")
            if isinstance(n, Name):
                row["name"] = text_of(str(n), None, "names")
        nxt, _ = pdf.deref(value.get("Next"))
        if nxt is not None:
            row["has_next"] = True
        if target_value is not None:
            values.add(finding, {"object": num, "trigger": trigger}, target_value)
        page.add(row)
        actions.append(row)
        return row

    def act(x, trigger, depth=0):
        """x is an action dictionary, a reference to one, or a destination (an array / a name / a string); /Next actions follow."""
        if depth > 32:
            return
        tick()
        num = x.num if isinstance(x, Ref) else None
        d, n2 = pdf.deref(x)
        if isinstance(d, dict) and (is_action(d) or "S" in d or "JS" in d):
            key = (num or n2, trigger)
            if key in seen_actions:
                return
            seen_actions.add(key)
            describe_action(d, num or n2, trigger)
            nxt = d.get("Next")
            if isinstance(nxt, list):
                for item in nxt[:32]:
                    act(item, trigger + "/Next", depth + 1)
            elif nxt is not None:
                act(nxt, trigger + "/Next", depth + 1)
        elif isinstance(d, (list, Name, PStr)):
            out.setdefault("destinations_seen", 0)
            out["destinations_seen"] += 1

    def aa(x, trigger):
        d, _ = pdf.deref(x)
        if isinstance(d, dict):
            for k, v in list(d.items())[:40]:
                act(v, "%s/AA/%s" % (trigger, text_of(k, None, "names")))

    def walk_name_tree(root, label, visit_leaf, depth=0):
        seen = set()
        stack = [(root, 0)]
        while stack:
            node, dp = stack.pop()
            tick()
            d, n = pdf.deref(node)
            if not isinstance(d, dict) or (n is not None and n in seen) or dp > pdf.cfg["max_depth"]:
                continue
            if n is not None:
                seen.add(n)
            names, _ = pdf.deref(d.get("Names"))
            if isinstance(names, list):
                for i in range(0, len(names) - 1, 2):
                    key, _k = pdf.deref(names[i])
                    visit_leaf(key if isinstance(key, PStr) else None, names[i + 1])
            kids, _ = pdf.deref(d.get("Kids"))
            if isinstance(kids, list):
                for kid in kids[:10000]:
                    stack.append((kid, dp + 1))

    try:
        # Catalog level: OpenAction, AA, names, form.
        if "OpenAction" in catalog:
            act(catalog["OpenAction"], "Catalog/OpenAction")
        if "AA" in catalog:
            aa(catalog["AA"], "Catalog")
        names, _ = pdf.deref(catalog.get("Names"))
        if isinstance(names, dict):
            if "JavaScript" in names:
                walk_name_tree(names["JavaScript"], "JavaScript", lambda key, val: act(val, "Catalog/Names/JavaScript[%s]" % (cell(shown_path(text_string(key))) if key is not None else "?")))
            if "EmbeddedFiles" in names:
                def leaf(key, val):
                    fs = filespec_info(pdf, ctx, val)
                    row = {"source": "Catalog/Names/EmbeddedFiles"}
                    if "name" in fs:
                        row["name"] = cell(shown_path(text_string(fs["name"])))
                        if shown_path(text_string(fs["name"])) != text_string(fs["name"]):
                            ctx.names.add(text_string(fs["name"]), row["name"])
                    if "stream_object" in fs:
                        o = pdf.get(fs["stream_object"])
                        row["stream_object"] = fs["stream_object"]
                        if o is not None and o.stream is not None:
                            row["stream_bytes"] = o.stream["length"]
                            row["filters"] = [text_of(n, None, "names") for n, _p in pdf.filters_of(o.value)]
                    embedded.append(row)
                walk_name_tree(names["EmbeddedFiles"], "EmbeddedFiles", leaf)
        form, _ = pdf.deref(catalog.get("AcroForm"))
        if isinstance(form, dict):
            out["acroform"] = {"fields_root": isinstance(form.get("Fields"), (Ref, list)), "xfa_present": "XFA" in form, "need_appearances": form.get("NeedAppearances") if isinstance(form.get("NeedAppearances"), bool) else None}
            fields, _ = pdf.deref(form.get("Fields"))
            stack = [(f, 0) for f in (fields if isinstance(fields, list) else [])]
            fseen, nfields = set(), 0
            while stack:
                f, dp = stack.pop()
                tick()
                d, n = pdf.deref(f)
                if not isinstance(d, dict) or (n is not None and n in fseen) or dp > pdf.cfg["max_depth"]:
                    continue
                if n is not None:
                    fseen.add(n)
                nfields += 1
                if "A" in d:
                    act(d["A"], "AcroForm/Field/A")
                if "AA" in d:
                    aa(d["AA"], "AcroForm/Field")
                kids, _ = pdf.deref(d.get("Kids"))
                if isinstance(kids, list):
                    stack.extend((k, dp + 1) for k in kids[:10000])
            out["acroform"]["fields_traversed"] = nfields
        # Outlines
        outl, _ = pdf.deref(catalog.get("Outlines"))
        if isinstance(outl, dict):
            stack, oseen, n_items = [outl.get("First")], set(), 0
            while stack:
                item = stack.pop()
                tick()
                d, n = pdf.deref(item)
                if not isinstance(d, dict) or (n is not None and n in oseen):
                    continue
                if n is not None:
                    oseen.add(n)
                n_items += 1
                if "A" in d:
                    act(d["A"], "Outlines/Item/A")
                stack.append(d.get("Next"))
                stack.append(d.get("First"))
            out["outline_items"] = n_items
        # Pages
        pages, _ = pdf.deref(catalog.get("Pages"))
        leaves, declared, pseen = 0, None, set()
        annot_types = {}
        if isinstance(pages, dict):
            declared = pages.get("Count") if isinstance(pages.get("Count"), int) else None
            stack = [(catalog.get("Pages"), 0)]
            while stack:
                node, dp = stack.pop()
                tick()
                d, n = pdf.deref(node)
                if not isinstance(d, dict) or (n is not None and n in pseen) or dp > pdf.cfg["max_depth"]:
                    if isinstance(d, dict) and n in pseen:
                        ctx.problem("the page tree returns to object %d: a cycle" % n)
                    continue
                if n is not None:
                    pseen.add(n)
                kids, _ = pdf.deref(d.get("Kids"))
                if isinstance(kids, list) and d.get("Type") != "Page":
                    stack.extend((k, dp + 1) for k in kids[:100000])
                    continue
                leaves += 1
                if "AA" in d:
                    aa(d["AA"], "Page")
                an, _ = pdf.deref(d.get("Annots"))
                if isinstance(an, list):
                    for a in an[:10000]:
                        ad, anum = pdf.deref(a)
                        if not isinstance(ad, dict):
                            continue
                        tick()
                        st = ad.get("Subtype")
                        key = text_of(str(st), None, "names") if isinstance(st, Name) else "?"
                        annot_types[key] = annot_types.get(key, 0) + 1
                        if "A" in ad:
                            act(ad["A"], "Page/Annot[%s]/A" % key)
                        if "AA" in ad:
                            aa(ad["AA"], "Page/Annot[%s]" % key)
        out["pages"] = {"declared_count_in_root_pages_node": declared, "leaf_nodes_traversed": leaves,
                        "note": "the declared count is what the root node says; the traversed count is the leaves reached from it. Neither is a verified page count"}
        out["annotation_subtypes"] = annot_types
    except Over as exc:
        ctx.limit_hit(str(exc))
    # Objects that are actions or hold scripts and were not reached from the catalog.
    reached_nums = {a["object"] for a in actions}
    unreached = 0
    for num, o in interesting.items():
        if isinstance(o.value, dict) and is_action(o.value) and num not in reached_nums:
            unreached += 1
            describe_action(o.value, num, None, reached=False)
        elif isinstance(o.value, dict) and o.value.get("Type") == "EmbeddedFile":
            if not any(e.get("stream_object") == num for e in embedded):
                embedded.append({"source": "an EmbeddedFile stream no file specification reached", "stream_object": num, "stream_bytes": o.stream["length"] if o.stream else None,
                                 "filters": [text_of(n, None, "names") for n, _p in pdf.filters_of(o.value)]})
    # File specifications that name an embedded stream but sit outside the name tree.
    for num, o in interesting.items():
        if isinstance(o.value, dict) and "EF" in o.value:
            fs = filespec_info(pdf, ctx, Ref(num, 0))
            if "stream_object" in fs and not any(e.get("stream_object") == fs["stream_object"] for e in embedded):
                emb = {"source": "a file specification (object %d)" % num, "stream_object": fs["stream_object"]}
                if "name" in fs:
                    emb["name"] = cell(shown_path(text_string(fs["name"])))
                embedded.append(emb)
    counts = {}
    for a in actions:
        counts[a["action"] or "?"] = counts.get(a["action"] or "?", 0) + 1
    out["actions"] = {"count": len(actions), "by_type": counts, "unreached_from_catalog": unreached, "table": "pdf_actions",
                      "note": "an action dictionary and the key that reaches it are different facts: a trigger is where the reader is asked to run it, and whether it runs depends on the reader"}
    out["embedded_files"] = embedded[:200]
    if len(embedded) > 200:
        ctx.limit_hit("%d embedded files were found: the first 200 are listed" % len(embedded))
    if extractor is not None and extractor.wants("javascript"):
        for i, (form, src, ref) in enumerate(scripts, 1):
            if form == "string":
                extractor.write("javascript", "", "script %d (string, action object %s)" % (i, ref), bytes(src), "PDF JavaScript string")
            else:
                try:
                    data = pdf.decode(src)
                except (PdfError, Over) as exc:
                    ctx.problem("script %d (stream object %s) was not extracted: %s" % (i, ref, exc))
                    continue
                extractor.write("javascript", "", "script %d (stream object %s)" % (i, ref), data, "PDF JavaScript stream, filters undone")
        if not scripts:
            for sel in extractor.selectors:
                if sel["kind"] == "javascript":
                    sel["matched"] += 1
    return out


# --- RTF -------------------------------------------------------------------------------------------------------------------

RTF_READ = ["group structure: nesting depth, brace balance, the bytes after the last group", "control words and destinations, counted",
            "object groups: the object kind, class name, the length of the hex-encoded data and the decoded start of it (the OLE 1.0 object header)",
            "fields (the first word of the instruction), templates and data stores, by length; a nested compound file inside object data is read as one"]
RTF_NOT_READ = ["text, formatting, tables, styles and pictures", "the meaning of an embedded object: its payload is listed, not opened",
                "fields' instruction text and template paths, beyond their first word and length (the whole is in the values file only when write_values is asked for in a secret_output job)"]
RTF_TOKEN = re.compile(rb"\\([A-Za-z]{1,32})(-?[0-9]{1,10})? ?|\\'[0-9A-Fa-f]{2}|\\[^A-Za-z]|[{}]")
RTF_OBJECT_KINDS = ("objemb", "objlink", "objautlink", "objsub", "objpub", "objicemb", "objhtml", "objocx")
RTF_WATCH = ("objupdate", "objautlink", "objlink", "objemb", "objhtml", "objocx", "objsetsize", "datastore", "template", "fldinst", "field", "pict", "bin", "objdata", "objclass", "objname",
             "result", "listoverridetable", "mmath", "stylesheet", "fonttbl", "colortbl", "info", "rsidtbl", "falt", "upr", "ud", "ansicpg", "mac", "pc", "pca", "ansi")
MAX_WORDS = 5000
MAX_RTF_OBJECTS = 20000
MAX_FIELDS = 20000
MAX_TEMPLATES = 2000
HEXDIGITS = b"0123456789abcdefABCDEF"
CAPTURE_LIMIT = 4096


def hex_decode_range(blob, start, end, limit):
    """The bytes encoded as hex digits in blob[start:end], white space ignored, read in pieces. Returns (bytes, non_hex_count, truncated):
    at most `limit` bytes are kept, and `truncated` says the range held more."""
    out, nonhex, pos, truncated, carry = bytearray(), 0, start, False, b""
    while pos < end:
        piece = carry + blob[pos:min(end, pos + (1 << 20))].translate(None, b" \t\r\n")
        pos += 1 << 20
        bad = piece.translate(None, HEXDIGITS)
        if bad:
            nonhex += len(bad)
            piece = piece.translate(None, bytes(set(bad)))
        usable = len(piece) // 2 * 2
        out += bytes.fromhex(piece[:usable].decode("ascii"))
        carry = piece[usable:]
        if len(out) > limit:
            truncated = True
            del out[limit:]
            break
    return bytes(out), nonhex, truncated


def count_hex(blob, start, end):
    """(hex digits, other bytes) in blob[start:end], white space ignored, counted in pieces."""
    digits = other = pos = 0
    pos = start
    while pos < end:
        piece = blob[pos:min(end, pos + (1 << 20))].translate(None, b" \t\r\n")
        pos += 1 << 20
        good = len(piece.translate(None, bytes(set(piece.translate(None, HEXDIGITS)))))
        digits += good
        other += len(piece) - good
    return digits, other


def ole1_header(raw):
    """MS-OLEDS 2.2.4 ObjectHeader: version, format, then three length-prefixed ANSI strings and the native data size."""
    if len(raw) < 12:
        return None
    version, fmt = struct.unpack_from("<II", raw, 0)
    if version != 0x00000501:
        return None
    pos, names = 8, []
    for _ in range(3):
        if pos + 4 > len(raw):
            return {"ole_version": "0x%08X" % version, "format_id": fmt, "header_truncated": True}
        n = struct.unpack_from("<I", raw, pos)[0]
        pos += 4
        if n > 4096 or pos + n > len(raw):
            return {"ole_version": "0x%08X" % version, "format_id": fmt, "header_truncated": True}
        names.append(raw[pos:pos + n].rstrip(b"\x00").decode("latin-1"))
        pos += n
    native = struct.unpack_from("<I", raw, pos)[0] if pos + 4 <= len(raw) else None
    return {"ole_version": "0x%08X" % version, "format_id": fmt, "format": {1: "linked", 2: "embedded"}.get(fmt, "other"), "class_name": names[0],
            "native_data_bytes": native, "native_data_offset": pos + 4}


def probe_rtf(blob, ctx, extractor):
    out = {"container": "RTF"}
    cfg = ctx.cfg
    max_depth = cfg["max_depth"]
    size = len(blob)
    head = blob[:HEAD_BYTES]
    start = head.find(b"{\\rtf")
    out["rtf_header_offset"] = start
    m = re.match(rb"\{\\rtf(-?[0-9]*)", head[start:])
    out["rtf_version_word"] = ("rtf" + m.group(1).decode("ascii")) if m else None
    if start > 0:
        ctx.problem("the {\\rtf header starts at offset %d, after %d byte(s) a reader may skip" % (start, start))
    words, other_words, symbols, destinations = {}, 0, 0, {}
    stack = []                      # (destination name, ignorable, start offset) of each open group
    over = 0
    depth = max_depth_seen = groups = 0
    skip_until = 0
    unbalanced_close = 0
    objects, fields, templates, stores = [], [], [], 0
    fields_over = [0, 0]
    capture = None                  # [kind, buffer bytearray, group depth at start, owner index]
    cur_obj_stack = []              # indexes into objects of the open \object groups
    last_end = 0
    pos_after_last_close = None
    tokens = 0
    expired = False
    bin_blocks, bin_bytes = 0, 0
    nonhex_total = 0

    def finish_capture():
        nonlocal capture
        kind, buf, _d, owner = capture
        text = bytes(buf)
        if kind == "objclass" and owner is not None:
            objects[owner]["class_name_raw"] = text.strip().decode("latin-1")[:200]
        elif kind == "objname" and owner is not None:
            objects[owner]["name_raw"] = text.strip().decode("latin-1")[:200]
        elif kind == "fldinst":
            if len(fields) < MAX_FIELDS:
                fields.append(text)
            else:
                fields_over[0] += 1
        elif kind == "template":
            if len(templates) < MAX_TEMPLATES:
                templates.append(text)
            else:
                fields_over[1] += 1
        capture = None

    for tok in RTF_TOKEN.finditer(blob):
        tokens += 1
        if tokens % 8192 == 0 and ctx.expired("the RTF scan"):
            expired = True
            break
        s = tok.start()
        if s < skip_until:
            continue
        gap_start, last_end = last_end, tok.end()
        if capture is not None and capture[0] != "objdata" and s > gap_start and len(capture[1]) < CAPTURE_LIMIT:
            capture[1] += blob[gap_start:min(s, gap_start + CAPTURE_LIMIT)]
        lead = tok.group()[:1]
        if lead == b"{":
            groups += 1
            depth += 1
            max_depth_seen = max(max_depth_seen, depth)
            if len(stack) < max_depth:
                stack.append([None, False, s])
            else:
                over += 1
            continue
        if lead == b"}":
            if depth == 0:
                unbalanced_close += 1
                continue
            depth -= 1
            if over:
                over -= 1
            else:
                dest, _ign, gs = stack.pop()
                if capture is not None and capture[2] == len(stack) + 1:
                    if capture[0] == "objdata":
                        o = objects[capture[3]]
                        o["data_end"] = s
                    finish_capture()
                if dest == "object" and cur_obj_stack:
                    cur_obj_stack.pop()
            if depth == 0:
                pos_after_last_close = tok.end()
            continue
        word = tok.group(1)
        if word is None:
            symbols += 1
            if capture is not None and capture[0] != "objdata" and len(capture[1]) < CAPTURE_LIMIT:
                sym = tok.group()
                if sym in (b"\\\\", b"\\{", b"\\}"):
                    capture[1] += sym[1:2]
                elif sym[:2] == b"\\'":
                    capture[1] += bytes.fromhex(sym[2:4].decode("ascii"))
            if tok.group()[:2] == b"\\*" and stack:
                stack[-1][1] = True
            continue
        name = word.decode("ascii")
        param = int(tok.group(2)) if tok.group(2) else None
        if name in words or len(words) < MAX_WORDS:
            words[name] = words.get(name, 0) + 1
        else:
            other_words += 1
        if stack and stack[-1][0] is None and not over:
            stack[-1][0] = name
            if name in destinations or len(destinations) < MAX_WORDS:
                destinations[name] = destinations.get(name, 0) + 1
            if name == "object" and len(objects) < MAX_RTF_OBJECTS:
                objects.append({"index": len(objects) + 1, "offset": s, "depth": depth, "kind": None, "flags": []})
                cur_obj_stack.append(len(objects) - 1)
            elif name == "datastore":
                stores += 1
            elif name in ("objclass", "objname", "fldinst", "template") and capture is None:
                owner = cur_obj_stack[-1] if cur_obj_stack and name in ("objclass", "objname") else None
                capture = [name, bytearray(), len(stack), owner]
            elif name == "objdata" and cur_obj_stack and capture is None:
                o = objects[cur_obj_stack[-1]]
                o["data_start"] = tok.end()
                capture = ["objdata", bytearray(), len(stack), cur_obj_stack[-1]]
        if cur_obj_stack:
            o = objects[cur_obj_stack[-1]]
            if name in RTF_OBJECT_KINDS and o["kind"] is None:
                o["kind"] = name
            elif name in ("objupdate", "objlock", "objsetsize", "objscalex", "objscaley", "objw", "objh", "objcropt", "objcropb", "objcropl", "objcropr") and name not in o["flags"]:
                o["flags"].append(name)
        if name == "bin" and param is not None and param > 0:
            bin_blocks += 1
            bin_bytes += param
            skip_until = tok.end() + param
            if skip_until > size:
                ctx.problem("a \\bin%d control word at offset %d declares more bytes than the file holds" % (param, s))
    # Close any capture still open, and the bookkeeping at the end of the data.
    if capture is not None:
        if capture[0] == "objdata":
            objects[capture[3]]["data_end"] = size
        finish_capture()
    out["structure"] = {"groups": groups, "max_depth_seen": max_depth_seen, "open_groups_at_end": depth, "close_without_open": unbalanced_close,
                        "depth_over_limit": over > 0 or max_depth_seen > max_depth, "binary_blocks": bin_blocks, "binary_bytes": bin_bytes}
    if depth:
        ctx.problem("the file ends with %d group(s) still open" % depth)
    if unbalanced_close:
        ctx.problem("%d closing brace(s) with no open group" % unbalanced_close)
    if max_depth_seen > max_depth:
        ctx.limit_hit("groups nest to %d, past max_depth (%d): destinations of the groups below that depth were not tracked" % (max_depth_seen, max_depth))
    if expired:
        ctx.limit_hit("the RTF scan stopped at max_seconds: the counts and objects found are lower bounds")
    if pos_after_last_close is not None and size - pos_after_last_close > 0:
        tail = blob[pos_after_last_close:]
        stripped = tail.strip(b" \t\r\n\x00")
        if stripped:
            ctx.problem("%d non-whitespace byte(s) follow the last group's closing brace" % len(stripped))
            out["bytes_after_last_group"] = len(stripped)
    top = sorted(words.items(), key=lambda kv: -kv[1])[:40]
    out["control_words"] = {"distinct": len(words), "not_counted_past_limit": other_words, "top": [{"word": w, "count": c} for w, c in top],
                            "watched": {w: words[w] for w in RTF_WATCH if w in words}, "control_symbols": symbols}
    out["destinations"] = dict(sorted(destinations.items(), key=lambda kv: -kv[1])[:40])
    # Objects
    table = ctx.page("rtf_objects")
    rows = []
    for o in objects:
        row = {"index": o["index"], "offset": o["offset"], "kind": o["kind"], "flags": o["flags"]}
        if "class_name_raw" in o:
            row["class_name"] = text_of(o["class_name_raw"], None, "names")
        if "name_raw" in o:
            row["object_name"] = text_of(o["name_raw"], None, "names")
        if "data_start" in o and "data_end" in o:
            digits, other = count_hex(blob, o["data_start"], o["data_end"])
            row["data"] = {"offset": o["data_start"], "end_offset": o["data_end"], "hex_digits": digits, "non_hex_bytes": other}
            if other:
                ctx.problem("RTF object %d: %d byte(s) of its data are not hex digits or white space" % (o["index"], other))
            raw, nonhex, trunc = hex_decode_range(blob, o["data_start"], min(o["data_end"], o["data_start"] + 4096 * 4), 4096)
            row["data"]["decoded_start"] = {"bytes_read": len(raw), "first_bytes_hex": raw[:16].hex()}
            hdr = ole1_header(raw)
            if hdr:
                row["ole1_header"] = {k: (text_of(v, None, "names") if isinstance(v, str) and k == "class_name" else v) for k, v in hdr.items()}
            if digits % 2:
                ctx.problem("RTF object %d: an odd number of hex digits in its data" % o["index"])
            need = digits // 2
            if need <= cfg["max_stream_bytes"] and (raw[:8] == CFB_MAGIC or (hdr and hdr.get("native_data_offset") is not None)):
                try:
                    full, nonhex2, trunc2 = hex_decode_range(blob, o["data_start"], o["data_end"], cfg["max_stream_bytes"])
                    ctx.spend(len(full), "an RTF object")
                    payload = full
                    base = 0
                    if hdr and hdr.get("native_data_offset") is not None:
                        base = hdr["native_data_offset"]
                        payload = full[base:base + (hdr["native_data_bytes"] or 0)]
                    if payload[:8] == CFB_MAGIC:
                        label = "rtf-object-%d" % o["index"]
                        try:
                            inner, _cfb = probe_ole_blob(payload, ctx, extractor, label=label)
                            row["nested_compound_file"] = {"bytes": len(payload), "cfb": inner["cfb"], "applications": inner["applications"], "orphan_entries": inner["orphan_entries"],
                                                           "vba_projects": inner.get("vba_projects", []), "encryption_items": inner["encryption_items"]}
                        except CfbError as exc:
                            ctx.problem("RTF object %d: its payload begins like a compound file and is not read as one: %s" % (o["index"], exc))
                    if extractor is not None and extractor.wants("rtf", o["index"]):
                        extractor.write("rtf", o["index"], "rtf object %d" % o["index"], full, "RTF object data, hex decoded")
                except Over as exc:
                    ctx.limit_hit("RTF object %d: %s" % (o["index"], exc))
            elif extractor is not None and extractor.wants("rtf", o["index"]):
                try:
                    full, _n, trunc2 = hex_decode_range(blob, o["data_start"], o["data_end"], cfg["max_stream_bytes"])
                    if trunc2:
                        ctx.limit_hit("RTF object %d: the data is over max_stream_bytes (%d): not extracted" % (o["index"], cfg["max_stream_bytes"]))
                    else:
                        ctx.spend(len(full), "an RTF object")
                        extractor.write("rtf", o["index"], "rtf object %d" % o["index"], full, "RTF object data, hex decoded")
                except Over as exc:
                    ctx.limit_hit("RTF object %d: %s" % (o["index"], exc))
        elif o["kind"] or "data_start" in o:
            ctx.problem("RTF object %d: its data group has no end in the bytes read" % o["index"])
        rows.append(row)
        table.add(row)
    out["objects"] = {"count": len(objects), "table": "rtf_objects", "capped": len(objects) >= MAX_RTF_OBJECTS}
    if len(objects) >= MAX_RTF_OBJECTS:
        ctx.limit_hit("the file holds at least %d object groups: the first %d are listed" % (MAX_RTF_OBJECTS, MAX_RTF_OBJECTS))
    out["objects"]["first"] = rows[:20]
    # Fields and templates: the word that says what a field is; the rest by length, the whole only in the values file.
    field_rows = []
    for text in fields[:2000]:
        clean = text.decode("latin-1").strip()
        m2 = re.match(r"[\s{\\*a-z]*([A-Za-z]{2,20})", clean)
        kind = m2.group(1).upper() if m2 else None
        finding = ctx.next_finding("F")
        field_rows.append({"finding_id": finding, "instruction_word": kind, "instruction_length": len(clean)})
        ctx.values.add(finding, {"kind": "field_instruction"}, clean)
    out["fields"] = {"count": len(fields) + fields_over[0], "listed": field_rows[:200]}
    if fields_over[0] or fields_over[1]:
        ctx.limit_hit("the file holds more than %d field instructions or %d templates: the rest are counted, not listed" % (MAX_FIELDS, MAX_TEMPLATES))
    tmpl_rows = []
    for text in templates[:200]:
        clean = text.decode("latin-1").strip()
        finding = ctx.next_finding("T")
        tmpl_rows.append({"finding_id": finding, "target": redact_url(clean) if re.match(r"[A-Za-z][A-Za-z0-9+.-]*://", clean) else cell(shown_path(clean)), "target_length": len(clean)})
        ctx.values.add(finding, {"kind": "template"}, clean)
    out["templates"] = tmpl_rows
    out["data_stores"] = stores
    out["coverage"] = {"structures_read": RTF_READ, "structures_not_read": RTF_NOT_READ}
    return out


# --- the call ---------------------------------------------------------------------------------------------------------------

def positive_int(args, key, default, maximum=None):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or (maximum is not None and value > maximum):
        fail("%s must be an integer from 1%s" % (key, " to %d" % maximum if maximum else ""))
    return value


def file_problem(path):
    """Why `path` is not a file this tool can read, in words that fit: a missing file, a directory, a device, a loop."""
    try:
        mode = os.stat(path).st_mode
    except FileNotFoundError:
        return "no such file"
    except OSError as exc:
        return "the file could not be examined: %s" % describe(exc)
    import stat as _stat
    if _stat.S_ISREG(mode):
        return None
    kinds = ((_stat.S_ISDIR, "a directory"), (_stat.S_ISFIFO, "a named pipe"), (_stat.S_ISSOCK, "a socket"), (_stat.S_ISBLK, "a block device"), (_stat.S_ISCHR, "a character device"))
    return "not a regular file (%s)" % next((n for t, n in kinds if t(mode)), "a special file")


# Keys whose values the tool made itself: a hex dump of header bytes, a GUID, and the names of the files it wrote (a tool name, a table name
# and a digest of the call, which a token-shaped-text test would otherwise take for a token).
SAFE_KEYS = {"head_hex", "tool", "clsid", "root_clsid", "first_bytes_hex", "all_results", "withheld_names_file"}


def shown_answer(value, key=""):
    if key in SAFE_KEYS:
        return value
    if isinstance(value, str):
        return shown_path(value)
    if isinstance(value, list):
        return [shown_answer(v) for v in value]
    if isinstance(value, dict):
        return {k: shown_answer(v, k) for k, v in value.items()}
    return value


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a document to read the structure of")
    why_not = file_problem(path)
    if why_not:
        fail(why_not, path=path)
    extract_to = args.get("extract_to")
    if extract_to is not None and (not isinstance(extract_to, str) or not extract_to):
        fail("extract_to must be a non-empty path when supplied")
    selectors = args.get("extract", [])
    if not isinstance(selectors, list) or not all(isinstance(x, str) and x for x in selectors) or len(selectors) > MAX_EXTRACT:
        fail("extract must be a list of at most %d selectors (vba, javascript, ole:<stream path>, zip:<member name>, pdf:<object number>, pdf-raw:<object number>, rtf:<object number>)" % MAX_EXTRACT)
    if selectors and extract_to is None:
        fail("extract names objects to write and needs extract_to: a directory under work/<your agent id>/ (in a job, under $OUT)")
    if extract_to is not None:
        extract_to = resolve_output(extract_to, "extract_to")
        try:
            os.makedirs(extract_to, exist_ok=True)
        except OSError as exc:
            fail("extract_to could not be created: %s" % describe(exc))
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    cfg = {
        "max_stream_bytes": positive_int(args, "max_stream_bytes", DEFAULT_STREAM),
        "max_total_bytes": positive_int(args, "max_total_bytes", DEFAULT_TOTAL),
        "max_entries": positive_int(args, "max_entries", DEFAULT_ENTRIES, MAX_ENTRIES),
        "max_objects": positive_int(args, "max_objects", DEFAULT_OBJECTS, MAX_OBJECTS),
        "max_depth": positive_int(args, "max_depth", DEFAULT_DEPTH, MAX_DEPTH),
        "max_ratio": positive_int(args, "max_ratio", DEFAULT_RATIO),
        "limit": positive_int(args, "limit", DEFAULT_LIMIT),
    }
    seconds = positive_int(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    try:
        values = SecretValues(write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False)
    VALUES[0] = values

    size = os.path.getsize(path)
    ctx = Ctx(os.path.realpath(path), cfg, values, seconds)
    shown = shown_path(path)
    if shown != path:
        ctx.names.add(path, shown, "input_path")
    try:
        with open(path, "rb") as fh:
            head = fh.read(HEAD_BYTES)
    except OSError as exc:
        values.close()
        fail("the file could not be opened: %s" % describe(exc), path=path)
    if not head:
        values.close()
        fail("the file is empty", path=path)
    extractor = Extractor(ctx, extract_to, selectors) if selectors else None
    body, stop = {}, None
    try:
        if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
            try:
                body = probe_zip(path, size, ctx, extractor)
            except Stop as exc:
                stop = exc
                body = exc.partial
        else:
            with open(path, "rb") as fh:
                blob = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    if head[:8] == CFB_MAGIC:
                        try:
                            body, cfb = probe_ole_blob(blob, ctx, extractor)
                            body = {"container": "OLE compound file", **body}
                            body["coverage"] = {"structures_read": OLE_READ, "structures_not_read": OLE_NOT_READ}
                        except CfbError as exc:
                            stop = Stop("the compound file cannot be read: %s" % exc, {"container": "OLE compound file"})
                            body = stop.partial
                    elif b"%PDF-" in head:
                        body = probe_pdf(blob, ctx, extractor)
                    elif b"{\\rtf" in head:
                        body = probe_rtf(blob, ctx, extractor)
                    else:
                        values.close()
                        fail("this is not a container this tool reads", status="unsupported", path=path, head_hex=head[:8].hex(),
                             reads=["OLE compound file", "OOXML or ZIP", "PDF", "RTF"])
                finally:
                    blob.close()
    finally:
        values.close()
        ctx.names.close()

    if extractor is not None:
        for text in extractor.unmatched():
            ctx.problem("extract %s matched nothing in this document" % text_of(text, None, "names"))
    tables = {}
    for name, page in ctx.pages.items():
        tables[name] = page.finish()
        if page.not_written:
            ctx.problem("the whole %s table could not be written to a file: %s" % (name, page.not_written))
    if ctx.names.error:
        ctx.problem("the real names behind the withheld ones could not be kept: %s" % ctx.names.error)
    for name, table in tables.items():
        table["rows"] = ctx.pages[name].page
    extension = os.path.splitext(path)[1].lower().lstrip(".")
    truncated = any(p["truncated"] for p in tables.values())
    members = body.get("members")
    unread = bool(members and (members["encrypted"] or members["unsupported"] or members["failed"] or members["over_budget"] or members["not_attempted"]))
    head_out = {"tool": TOOL, "parser": PARSER, "path": shown, "bytes": size, "extension": scrub(extension, "names") or None}
    # One normalised block for what the structures say about encryption and protection.
    encryption_items = body.pop("encryption_items", None)
    protection_items = body.pop("protection_items", None)
    if stop is not None:
        print(json.dumps(shown_answer({**head_out, **body, "status": "failed", "status_basis": stop.message, "error": stop.message,
                                       "problems": ctx.problems, "limits_hit": ctx.limits, "withheld": COUNTS, "secret_values": values.summary(), "note": NOTE}), indent=2))
        raise SystemExit(1)
    status = "partial" if (ctx.problems or ctx.limits or unread) else "complete"
    basis = ("every structure this tool reads was read in full" if status == "complete" else
             "%d problem(s), %d limit(s)%s: see `problems`, `limits_hit` and `coverage`" % (len(ctx.problems), len(ctx.limits), "; some members were not read" if unread else ""))
    container = body.get("container")
    if container == "PDF":
        enc = body.get("encryption") or {}
        if enc.get("in_current_trailer"):
            body["encryption_summary"] = {"found": True, "basis": "the newest trailer names an encryption dictionary, which was read", "items": [enc.get("dictionary")]}
        elif enc.get("in_an_earlier_revision_only"):
            body["encryption_summary"] = {"found": None, "basis": "not determined: the newest trailer names no encryption dictionary and an earlier revision's trailer does",
                                          "note": enc["note"]}
        elif enc.get("present") is False and body.get("structure_source") == "cross-reference chain":
            body["encryption_summary"] = {"found": False, "basis": "no trailer of the cross-reference chain names an encryption dictionary",
                                          "limit": "bounded to the cross-reference chain this tool read; not read: objects the chain does not list"}
        else:
            body["encryption_summary"] = {"found": None, "basis": "the cross-reference chain was not usable or the trailer's encryption entry could not be read: not determined"}
    elif encryption_items is not None:
        body["encryption_summary"] = {"found": bool(encryption_items), "items": encryption_items,
                                      "basis": ("structures named in the coverage list were read and one or more records encryption" if encryption_items else
                                                "none of the encryption structures this tool reads was found; encryption not recorded in those structures is not excluded"),
                                      "not_determined": "whether any password opens the file: no key is tried"}
    if protection_items:
        body["protection_items"] = protection_items
    if extractor is not None:
        body["extracted"] = ctx.extracted
        body["extraction_note"] = "Objects are written byte for byte, under budgets, mode 0600, and can contain secrets: run extraction in a job with secret_output: true. A file is the whole object or absent."
        body["extracted_parts_may_contain_secrets"] = True
    result = {**head_out, **body, "status": status, "status_basis": basis, "problems": ctx.problems, "limits_hit": ctx.limits, "tables": tables, "truncated": truncated,
              "budgets": {"max_stream_bytes": cfg["max_stream_bytes"], "max_total_bytes": cfg["max_total_bytes"], "max_entries": cfg["max_entries"], "max_objects": cfg["max_objects"],
                          "max_depth": cfg["max_depth"], "max_ratio": cfg["max_ratio"], "max_seconds": seconds, "stream_bytes_read": ctx.budget.used},
              "withheld": COUNTS, "secret_values": values.summary(), "note": NOTE}
    if ctx.names.shown:
        result["withheld_names_file"] = ctx.names.shown
        result["withheld_names_note"] = ("The real name behind every name withheld here is in this file (mode 0600, always written when a name is withheld): "
                                         "run the job with secret_output: true.")
    if ctx.problems_dropped:
        result["problems_not_listed"] = ctx.problems_dropped
    if values.enabled or COUNTS["urls"] or COUNTS["names"] or COUNTS["text"]:
        result["withheld_note"] = ("Credentials and token-shaped text in a URL or a name are withheld from this answer; the length is kept. "
                                   "The whole target is in the values file when write_values was asked for in a secret_output job.")
    print(json.dumps(shown_answer(result), indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never a traceback and never a clean answer for a failure
        fail("unexpected failure: %s" % (describe(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, scrub(str(exc)))))

#!/usr/bin/env python3
"""Normalise a backup or hypervisor job record into canonical events, one source line or record at a time, and say what
was not understood.

The products and layouts read, and no others:

    Proxmox VE and Proxmox Backup Server   the task index (UPID lines: node, pid, start, type, id, user, then the end time
                                           and status; a Backup Server UPID carries one more field, the task counter, and
                                           escapes its worker id) and a Proxmox VE task log (vzdump log lines and the
                                           TASK result line; a Backup Server task log is not read)
    declared_csv, declared_jsonl,          an export of ANY product, read through a mapping the CALLER declares (which
    declared_xml                           column or field is the time, the action, the result, the actor and the object, how
                                           the time is written, and what each action means). The tool does not know the
                                           product: it reads the columns you name and says so on every event.

A product that is none of these is `unsupported` until fixtures for its format exist: this tool does not guess a vendor's
layout from a name or a sample. Name the format (`format`) or let `auto` recognise the Proxmox layouts only; asking for
another product by name is refused, with the declared route offered.

What an event is. It is what a line or record says happened, with where it was read (file, line or record, byte offset) and
how its time was read. It is not proof the operation took place as described, that it succeeded because a record says so, or
who did it: an actor field is the account the product wrote. A category is a label from this tool's table (or the caller's
category_map) for the action's name; the raw action stays beside it. A job record that says success is not a restore that
worked; a delete request is not a loss (see the skills).

Time is read exactly as declared: epoch seconds are UTC by definition; an ISO 8601 time with an offset is converted; a time
with no zone is NOT assumed UTC, it stays raw (`time_utc` is null and `time_basis` says why) unless the caller declares a fixed
offset, which does not account for daylight saving.

A declared field a record does not have is counted per field (the CSV header check's twin for JSON Lines and XML), and a
time or action absent makes the answer partial. A declared XML record is held in memory one at a time and is bounded in
bytes: a record over the budget is counted and located, never read in part.

SENSITIVE OUTPUT. A log message, an error text and an object path can hold a path, a user name, a token or a repository string
with user-info. The answer carries the structured fields after the shape check of the shared block (a token-shaped run or
user-info is withheld; a long text is shown cut with its whole length) and the length of the free-text message; the message
itself and the original of anything withheld go to one private file only when write_text is asked for, in a job. Every key
and value of the answer and of its paging files passes the one way out (SHARED BOUNDARY), which withholds by shape again and
checks what it wrote; a time basis is a fixed phrase, never an exception's text.
"""
import collections
import csv
import datetime
import errno
import itertools
import json
import math
import os
import posixpath
import re
import secrets
import stat
import sys
import tempfile
import time
from pathlib import Path

TOOL = "backup_audit_normalise"
PARSER = "backup_audit_normalise/1"
DEFAULT_LIMIT = 200
DEFAULT_SECONDS = 50.0          # the manifest allows 60
MAX_SECONDS = 50.0
MAX_LINE = 1 << 20
MAX_FIELD = 1 << 20
MAX_DISTINCT = 10000
MAX_XML_RECORD_ELEMENTS = 10000
MAX_XML_RECORD_BYTES = 4 << 20   # text and attributes one declared XML record may hold; a record over it is counted, not read
MAX_XML_TOKEN = 16 << 20         # bytes the XML reader may take in without one element or text callback (a giant tag or comment)
MAX_XML_DEPTH = 64
MAX_PATHS = 100
CATEGORIES = ("backup_job", "backup_start", "backup_end", "backup_error", "archive_created", "restore", "snapshot_create", "snapshot_delete",
              "snapshot_rollback", "retention_prune", "retention_gc", "retention_remove", "verification", "sync", "vm_create", "vm_delete",
              "vm_power", "vm_start", "clone", "migrate", "disk_delete", "config_change", "repository_change", "login", "task_end", "other")
RESULTS = ("ok", "warning", "error", "unknown")
PVE_TYPES = {"vzdump": "backup_job", "backup": "backup_job", "qmsnapshot": "snapshot_create", "vzsnapshot": "snapshot_create",
             "qmdelsnapshot": "snapshot_delete", "vzdelsnapshot": "snapshot_delete", "qmrollback": "snapshot_rollback", "vzrollback": "snapshot_rollback",
             "qmdestroy": "vm_delete", "vzdestroy": "vm_delete", "qmrestore": "restore", "vzrestore": "restore", "reader": "restore", "imgdel": "disk_delete",
             "qmstart": "vm_start", "vzstart": "vm_start", "qmstop": "vm_power", "vzstop": "vm_power", "qmshutdown": "vm_power", "vzshutdown": "vm_power",
             "qmreboot": "vm_power", "qmreset": "vm_power", "qmclone": "clone", "qmigrate": "migrate", "vzmigrate": "migrate", "qmcreate": "vm_create",
             "vzcreate": "vm_create", "prune": "retention_prune", "prunejob": "retention_prune", "garbage_collection": "retention_gc", "verify": "verification",
             "verificationjob": "verification", "syncjob": "sync", "sync": "sync"}
KNOWN_UNSUPPORTED = ("veeam", "commvault", "rubrik", "cohesity", "acronis", "veritas", "netbackup", "networker", "nakivo", "altaro", "hycu", "druva",
                     "backup_exec", "arcserve", "vcenter", "vsphere", "hyper-v", "hyperv", "nutanix", "ovirt", "xen", "azure_backup", "aws_backup")

VOCABULARY = frozenset()     # words the way out shows as they are (see SHARED BOUNDARY): none here

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
# BEGIN SHARED COMMON
# The same text is in virtualization_inventory, snapshot_chain_check and backup_audit_normalise (a tool is standalone, none
# imports another); tests/pack-virtualization-shared.test.ts holds the copies equal. Arguments, the status every answer
# carries, lossless paging, and the one place a withheld text is kept when, and only when, it was asked for.


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def describe(exc):
    """An exception as text for an answer: its type and errno name, and its message withheld by shape (the way out's whole
    rules, so that nothing they would take is split first), never cut."""
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return seal_text("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)), "text")


def fail(message, **extra):
    """An error answer: JSON, exit 1, the same `status` every answer of this pack carries, through the one way out."""
    print(answer_text({"error": message, "tool": TOOL, "status": "failed", "status_basis": "the tool stopped with an error (see error)", **extra}))
    raise SystemExit(1)


def read_args():
    try:
        raw = sys.stdin.buffer.read(8 << 20 | 1)
        if len(raw) > 8 << 20:
            fail("arguments are larger than 8 MiB: pass a list of files, not their contents")
        args = json.loads(raw.decode("utf-8") or "{}")
    except (ValueError, UnicodeDecodeError) as exc:
        fail("arguments are not valid JSON", reason=describe(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args


MAX_ARG_STRING = 8192


def want_str(args, key, required=None, maximum=MAX_ARG_STRING):
    value = args.get(key)
    if value is None:
        if required:
            fail(required)
        return None
    if not isinstance(value, str):
        fail("%s must be a string" % key)
    if required and not value:
        fail(required)
    if len(value) > maximum:
        fail("%s is longer than %d characters" % (key, maximum))
    return value


def want_str_list(args, key, maximum=100000):
    value = args.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) and x and len(x) <= MAX_ARG_STRING for x in value):
        fail("%s must be a list of non-empty strings of at most %d characters" % (key, MAX_ARG_STRING))
    if len(value) > maximum:
        fail("%s holds more than %d entries: pass a directory as root instead" % (key, maximum))
    return value


def want_flag(args, key):
    value = args.get(key, False)
    if not isinstance(value, bool):
        fail("%s must be true or false" % key)
    return value


def want_int(args, key, default, minimum, maximum):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > maximum:
        fail("%s must be an integer from %d to %d" % (key, minimum, maximum))
    return value


def want_seconds(args, key, default, maximum):
    """A time budget: a finite number above zero and no more than `maximum` (NaN and Infinity are not budgets)."""
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0 or value > maximum:
        fail("%s must be a number of seconds above 0 and at most %d" % (key, maximum))
    return float(value)


def status_of(complete, failed, basis_complete, basis_partial, basis_failed):
    """The `status` every answer of this pack carries, with the reason for it: complete (everything the request asked
    for was read and nothing was left out), partial (some of it was, and the answer names what was not) or failed."""
    if failed:
        return {"status": "failed", "status_basis": basis_failed}
    if complete:
        return {"status": "complete", "status_basis": basis_complete}
    return {"status": "partial", "status_basis": basis_partial}


class Overtime(Exception):
    pass


class Clock:
    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds
        self.count = 0

    def check(self, every=1):
        self.count += 1
        if self.count % every == 0 and time.monotonic() > self.deadline:
            raise Overtime()

    def left(self):
        return max(0.0, self.deadline - time.monotonic())


def blen(text):
    return len(text.encode("utf-8", "surrogateescape"))


def decode(data):
    """Bytes as text with no byte lost: an undecodable byte is a lone surrogate, which a JSON escape writes and which
    encodes back to the byte."""
    return data.decode("utf-8", "surrogateescape")


# Lossless paging: the page an agent reads stays small, and when there are more rows the whole result is written as JSON
# Lines under work/<agent>/tool-output (in a job, $OUT/tool-output) and named. The file name is random: it is never a
# digest of anything asked for (sixteen decimal digits), and the way out shows this exact name, registered here, as it is. Every row is sealed
# (the one way out, below) as it is written. A write that fails is an error answer naming the file, never a loss that
# goes unsaid.
class LosslessPage:
    def __init__(self, tool, key, limit):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.key = re.sub(r"[^A-Za-z0-9_.-]", "_", key)
        self.limit = limit
        self.page = []
        self.total = 0
        self._out = None
        self._tmp = None
        name = "%s-%s-%016d.jsonl" % (self.tool, self.key, secrets.randbelow(10 ** 16))
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        OWN_NAMES.update((self.shown, str(self.path)))     # this exact name, and no other of its shape, is shown as it is

    def _write(self, row):
        line = row_text(row, "pages/%s/all_results" % self.key)
        try:
            self._out.write(line)
            self._out.write("\n")
        except OSError as exc:
            fail("the whole result could not be written: %s" % describe(exc), paging_file=str(self.path))

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="ascii", errors="backslashreplace")
            except OSError as exc:
                fail("the whole result could not be written: the paging file cannot be created (%s)" % describe(exc), paging_file=str(self.path))
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                os.replace(self._tmp, self.path)
            except OSError as exc:
                fail("the whole result could not be written: %s" % describe(exc), paging_file=str(self.path))
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete row per line"
        return result


class TextRefused(Exception):
    pass


class TextFile:
    """Where the original of a withheld or shortened text goes when, and only when, the caller asked for it.

    The secret-safe output pattern of recovery_key_scan's SecretValues, for rows. With `enabled` false it writes
    nothing and `summary()` says so. Enabled, it is refused outside a job; inside one the file is created before
    anything is read (mode 0600, exclusively: a file or a link already at that name is refused by name) under $OUT, and
    the answer names it and says it may hold secrets. With nothing to keep it stays an empty file and says written: 0.
    """

    def __init__(self, name, enabled, what, flag="write_text"):
        self.enabled = enabled
        self.written = 0
        self.what = what
        self.flag = flag
        self._fh = None
        self.path = None
        self.shown = None
        if not enabled:
            return
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out):
            raise TextRefused("%s is refused outside a job: the originals written here would be an ordinary file, not a "
                              "sealed output. Run this as job_run tool=%s with secret_output: true, and ask again there. "
                              "Nothing was written." % (flag, TOOL))
        self.path = Path(out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        OWN_NAMES.update((self.shown, str(self.path)))
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise TextRefused("the values file already exists: %s" % name)
        except OSError as exc:
            raise TextRefused("the values file could not be created (%s)" % describe(exc))
        self._fh = os.fdopen(fd, "wb")

    def add(self, row):
        if self._fh is None:
            return
        try:
            self._fh.write(json.dumps(row, default=str).encode("ascii") + b"\n")
        except OSError as exc:
            fail("the values file could not be written (%s)" % describe(exc))
        self.written += 1

    def close(self):
        if self._fh is not None:
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._fh.close()
            except OSError as exc:
                fail("the values file could not be closed (%s)" % describe(exc))
            self._fh = None

    def summary(self):
        if not self.enabled:
            return {"requested": False, "written": 0, "file": None, "contains_text_that_may_hold_secrets": False,
                    "hint": "Nothing withheld or shortened is kept. %s: true, in a job run with secret_output: true, keeps the "
                            "original of each in a private file under $OUT." % self.flag}
        return {"requested": True, "written": self.written, "file": self.shown,
                "contains_text_that_may_hold_secrets": self.written > 0, "format": self.what}


class Shown(str):
    """A string that has been through the shape check: it is not checked again."""


# An open-ended authority or name:secret run at the point where a long text was cut might have its user-info separator beyond
# the cut, and a run of name characters the cut ends might be the head of a token: each is withheld whole.
_OPEN_AUTHORITY = re.compile(r"(?<=//)[^/?#\s]*$")
_OPEN_BARE = re.compile(r"[^\s/@:<>]{1,64}:[^\s/@<>]*$")
_OPEN_RUN = re.compile(r"[A-Za-z0-9_+%/=.:@-]+$")


def cut_safely(text, limit):
    """`text` cut to at most `limit` characters (plus a marker), never leaving the head of a run the cut split: a text
    is withheld by shape BEFORE it is cut, and what the cut leaves open is withheld whole, not shown in part."""
    if len(text) <= limit:
        return text
    head = text[:limit]
    if _OPEN_RUN.match(text, limit):          # the cut fell inside a run
        head = _OPEN_RUN.sub(lambda m: _withheld("open run at a cut", len(m.group()), "cut"), head)
    head = _OPEN_AUTHORITY.sub(lambda m: _withheld("userinfo", len(m.group()), "text"), head)
    return _OPEN_BARE.sub(lambda m: _withheld("userinfo", len(m.group()), "text"), head)


def brief(text, limit=300):
    """A message from a library or a program, withheld by shape whole and then cut safely: never cut first."""
    return cut_safely(seal_text(text if isinstance(text, str) else str(text), "text"), limit)


class Shower:
    """Every string the answer shows a name, a path or a value of passes through here: token-shaped runs and user-info are
    withheld, a text over `limit` characters is shown cut with its whole length, and the original of what was changed goes
    to the values file when one was asked for (never anywhere else). Only the first EXAMINED characters of a long text are
    checked (the check is not linear in the length of an adversary's text): a run of name characters, an authority or a
    name:secret run that the EXAMINED cut leaves open is withheld whole before the shape check, so that no fragment of a
    token the cut split can be shown; the check runs on the whole examined text, and the shorter cut to `limit` comes
    after it and leaves no run open either."""

    EXAMINED = 4096

    def __init__(self, values, limit=512):
        self.values = values
        self.limit = limit
        self.changed = 0
        self.cut = 0

    def __call__(self, text, where=None, field=None):
        if text is None:
            return None
        if not isinstance(text, str):
            text = str(text)
        total = len(text)
        head = text
        if total > self.EXAMINED:
            head = cut_safely(text, self.EXAMINED)
        shown = seal_text(head, "text")
        was_cut = total > self.EXAMINED
        if len(shown) > self.limit:
            shown = cut_safely(shown, self.limit)
            was_cut = True
        if was_cut:
            shown += "...(whole text: %d characters)" % total
            self.cut += 1
        if shown != text:
            self.changed += 1
            if self.values.enabled:
                self.values.add({"record_type": "original", "where": where, "field": field, "value": text})
        return Shown(shown)


def withheld_summary(shower):
    return {"strings_withheld_by_shape": dict(COUNTS), "strings_changed": shower.changed, "strings_shortened": shower.cut,
            "note": ("Names, paths and values the answer shows are checked by shape: a token-shaped run, user-info in a URL and a key "
                     "are withheld, and a string over %d characters is shown cut with its whole length. A secret that does not look "
                     "like a token (a short password in a name) is not recognised, so run the tool as a job with secret_output: true.") % shower.limit}
# END SHARED COMMON
# BEGIN SHARED BOUNDARY
# The same text is in virtualization_inventory, snapshot_chain_check and backup_audit_normalise; tests/pack-virtualization-
# shared.test.ts holds the copies equal. The one way out. Every key and every value of an answer, of an error answer and of
# every row a paging file holds is sealed when it is serialised, whatever code made it: the whole string is withheld by
# shape before anything cuts or folds it, and the rules are applied until they change nothing more. One pass: user-info
# first (name:password@host is withheld up to the LAST `@` before the host, so an `@` inside a password shows nothing of
# it), then the shared withholding block's user-info rules, then every token rule (the shared block's and the shapes
# added here) on the same text: the spans they find are joined where they touch or overlap and each is withheld once, so
# that no rule's order leaves a piece of what another would take (a JWT in a path, an AWS-style key after `=`). A string
# that holds zero-width or control characters, a byte that was not UTF-8, or the escape of one (\u200b, \x00) is judged
# with them taken out as well, and when that reading has something to withhold it is the one shown.
#
# Shown as they are: a GUID or a VMFS volume id that stands alone (or follows `_`, as in a Hyper-V file name), an
# identifier the formats carry that the shape check would take for a token; the exact names of the files this run made
# (its paging files and its values file, registered as each is created: never a pattern, so that a name in the evidence
# shaped like one is withheld like any other); and a word of the tool's own closed vocabulary (VOCABULARY, set by each
# tool: VMDK create types). An integer of more than 18 digits is withheld by its size.
#
# The shapes added to the shared block's: user-info after `:` or `/` (a Proxmox storage:user:password@host, a path with
# user:password@host in it); a base64 key with its padding that holds `/` or `+` (a 16-byte key is 24 characters, under
# the shared block's 30-character slashed rule); a base64 run with a `/` in it whose letters change case as random text
# does (an AWS-style secret key with one `/`), also right after `=`; the head of a prefixed token (AKIA..., ghp_...,
# github_pat_..., xoxb-..., eyJ...) too short for the shared rule, as a cut or a damaged file can leave it, and prefixes
# the shared block does not know (glpat-, sk_live_ and its kin, SG., AIza); the value after a name that says it is a
# secret (password=, secret:, AccountKey=, api_key=, token=); a private key in PEM form; and a run of more than 18 digits.
#
# Then the serialised text is read back and checked (the backstop): by the same rules once, and by a second check written
# apart from them (_suspect: a PEM private-key marker, a named secret, a long digit run, a known token prefix, user-info,
# and a long run whose letters and digits change class as random text does, each after zero-width and control characters,
# their escapes and bytes that were not UTF-8 are taken out), so that a gap in the rules is not by itself a gap in the
# check. A string either would still change is replaced by <withheld: N bytes>, its place and the check that fired are
# listed in boundary.replaced_at, and the answer is partial.
BOUNDARY = {"withheld": 0, "replaced": 0, "where": [], "not_listed": 0, "by": collections.Counter()}
OWN_NAMES = set()               # the exact names of the files this run made, as the answer shows them
MAX_REPLACED_LISTED = 1000
# a GUID, or a VMFS volume id (8-8-4-12 hexadecimal digits), standing alone or after `_` as a Hyper-V file name puts it
_GUID_ALONE = re.compile(r"(?<![A-Za-z0-9+%/=-])(?:\{?[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}?|[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{12})(?![A-Za-z0-9_+%/=-])")
_MARKER = re.compile(r"<(?:[a-z][a-z -]{0,40} )?withheld(?: \d+ characters|: \d+ bytes|: an integer of \d+ bits)>")
# name:secret@host, the secret running to the last `@` before the host (an `@` inside a password is part of it)
_ANY_USERINFO = re.compile(r"(?<![A-Za-z0-9._%+-])(?!mailto:)[^\s/@:<>\"'`]{1,64}:[^\s/<>\"'`]{1,128}(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
_SLASHED_RANDOM = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+=])")
_BASE64_KEY = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={1,2}(?![A-Za-z0-9+=])")
_TOKEN_HEAD = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{4,}|gh[pousr]_[A-Za-z0-9]{4,}|github_pat_[A-Za-z0-9_]{4,}|xox[abeprs]-[A-Za-z0-9-]{6,}|eyJ[A-Za-z0-9_-]{10,}"
                         r"|glpat-[A-Za-z0-9_-]{4,}|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{4,}|SG\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?|AIza[0-9A-Za-z_-]{8,}")
_NAMED_SECRET = re.compile(r"(?i)(?<![A-Za-z0-9])((?:[A-Za-z0-9]+[_.-])*(?:pass(?:word|wd|phrase)|secret|token|api[_-]?key|access[_-]?key|account[_-]?key"
                           r"|private[_-]?key|client[_-]?secret)s?[\"']?\s*[=:]\s*[\"']?)([^\s\"'<>;,&]{1,512})")
_LONG_DIGITS = re.compile(r"(?<![0-9])[0-9]{19,}(?![0-9])")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)", re.S)
# zero-width and control characters, and a byte that was not UTF-8 (a lone surrogate)
_INVISIBLE = re.compile("[\x00-\x08\x0b-\x1f\x7f\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\udc80-\udcff]")
# the same characters written as escapes (a nested JSON value a tool shows as text, a control byte a path shows as \xNN)
_INVISIBLE_TEXT = re.compile(r"\\u(?:00[01][0-9A-Fa-f]|007[Ff]|00[Aa][Dd]|180[Ee]|200[B-Fb-f]|202[A-Ea-e]|206[0-4]|[Ff][Ee][Ff][Ff])|\\x(?:[01][0-9A-Fa-f]|7[Ff])")
# A string none of whose rules can match is passed without the slow path: every rule needs one of these.
_QUICK = re.compile(r"[A-Za-z0-9_+%/=-]{14,}|@|AKIA|ASIA|gh[pousr]_|github_pat_|xox[abeprs]-|sk-|eyJ|(?i:basic|bearer)\s|[0-9]{19}|(?i:pass|secret|token|key)|-----BEGIN")
_SEALED = {}


def _random_slashed(run):
    """A base64 run holding `/`: random when its letters change case as random text does, or digits sit among them."""
    if "/" not in run:
        return False
    flat = run.replace("/", "").rstrip("=")
    letters = [c for c in flat if c.isalpha()]
    if not (any(c.isdigit() for c in flat) and any(c.islower() for c in letters) and any(c.isupper() for c in letters)):
        return False
    flips = sum(1 for a, b in zip(letters, letters[1:]) if a.islower() != b.islower())
    packed = len(re.findall(r"(?<=[A-Za-z])[0-9]{1,3}(?=[A-Za-z])", flat))
    return len(letters) >= 16 and (flips >= 0.33 * len(letters) or (packed and flips >= 0.25 * len(letters))) or _token_run(flat)


def _outside(text, pattern, fn):
    """`fn` applied to the parts of `text` that `pattern` does not match; the matches are kept as they are."""
    out, last = [], 0
    for m in pattern.finditer(text):
        out.append(fn(text[last:m.start()]) if m.start() > last else "")
        out.append(m.group())
        last = m.end()
    out.append(fn(text[last:]) if last < len(text) else "")
    return "".join(out)


def _rules_once(text, kind="boundary"):
    """One application of every withholding rule to a whole string; a GUID standing alone, a name this run made and a word
    of VOCABULARY are kept. A string that holds zero-width or control characters is judged with them taken out as well:
    when that reading has something to withhold, it is the one shown (a token split by invisible characters is a token)."""
    if text in OWN_NAMES or text in VOCABULARY:
        return text
    if _INVISIBLE.search(text) or _INVISIBLE_TEXT.search(text):
        flat = _INVISIBLE.sub("", _INVISIBLE_TEXT.sub("", text))
        sealed = _rules_once(flat, kind)
        if sealed != flat:
            return sealed
    if not _QUICK.search(text):
        return text
    hit = _outside(text, _GUID_ALONE, lambda piece: _rules_piece(piece, kind))
    if kind == "boundary":
        COUNTS.pop("boundary", None)
    return hit


def _rules_piece(piece, kind):
    if not piece or not _QUICK.search(piece):
        return piece
    piece = _ANY_USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), piece)
    # the shared block's user-info rules, then every token rule on the same text: what any of them takes is withheld as one
    # run, so that no rule's order leaves a piece of what another would have taken
    piece = _outside(piece, _MARKER, lambda part: _BARE_USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind),
                                                                      _USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), part)))
    return _outside(piece, _MARKER, lambda part: _spans_withheld(part, kind))


def _spans_withheld(part, kind):
    """Every span the shared block's token rules and the shapes added here find in `part`, joined where they touch or
    overlap, each withheld once."""
    spans = [(a, b, "token-shaped text") for a, b in token_spans(part)]
    spans += [m.span() + ("token-shaped text",) for m in _SLASHED_RANDOM.finditer(part) if _random_slashed(m.group())]
    spans += [m.span() + ("token-shaped text",) for m in _BASE64_KEY.finditer(part) if re.search(r"[/+]", m.group())]
    spans += [m.span() + ("token-shaped text",) for m in _TOKEN_HEAD.finditer(part)]
    spans += [m.span(2) + ("secret",) for m in _NAMED_SECRET.finditer(part)]
    spans += [m.span() + ("long number",) for m in _LONG_DIGITS.finditer(part)]
    spans += [m.span() + ("private key",) for m in _PRIVATE_KEY.finditer(part)]
    if not spans:
        return part
    spans.sort()
    merged = []
    for a, b, what in spans:
        if merged and a <= merged[-1][1]:
            prev = merged[-1]
            merged[-1] = (prev[0], max(prev[1], b), prev[2] if prev[2] == what else "token-shaped text")
        else:
            merged.append((a, b, what))
    out, last = [], 0
    for a, b, what in merged:
        out.append(part[last:a])
        out.append(_withheld(what, b - a, kind))
        last = b
    out.append(part[last:])
    return "".join(out)


def seal_text(text, kind="boundary"):
    """The rules applied to a whole string until they change nothing (a string that keeps changing is withheld whole), so
    that the backstop's one application finds nothing to change. The Shower uses this too, so that what it shows and what
    the way out lets through are judged by the same rules."""
    if not isinstance(text, str):
        text = str(text)
    hit = _SEALED.get(text)
    if hit is None:
        hit = text
        for _ in range(6):
            before, hit = hit, _rules_once(hit, kind)
            if hit == before:
                break
        else:
            hit = "<withheld: %d bytes>" % blen(text)
        if len(text) <= 2048:
            if len(_SEALED) >= 50000:
                _SEALED.clear()
            _SEALED[text] = hit
    return hit


def boundary_text(text):
    """The seal of one string at the way out, counted when it changed something."""
    hit = seal_text(text)
    if hit != text:
        BOUNDARY["withheld"] += 1
    return hit


def big_int(value):
    """An integer of more than 18 digits: no format this pack reads carries one, and its digits can be a secret's."""
    return isinstance(value, int) and not isinstance(value, bool) and abs(value) >= 10 ** 18


def seal(value, depth=0):
    """Every key and every value of a structure, as JSON will write it, through boundary_text; a key two keys seal to is
    numbered (`<key> #2`), never merged."""
    if isinstance(value, str):
        return boundary_text(value)
    if big_int(value):
        BOUNDARY["withheld"] += 1
        return "<withheld: an integer of %d bits>" % value.bit_length()
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else boundary_text(repr(value))
    if depth > 64:
        return boundary_text(json.dumps(value, default=str))
    if isinstance(value, dict):
        out, taken = {}, {}
        for k, v in value.items():
            key = boundary_text(k if isinstance(k, str) else json.dumps(k) if isinstance(k, (bool, type(None))) else str(k))
            if key in out:
                n = taken.get(key, 1) + 1
                while "%s #%d" % (key, n) in out:
                    n += 1
                taken[key] = n
                key = "%s #%d" % (key, n)
            out[key] = seal(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [seal(v, depth + 1) for v in value]
    return boundary_text(str(value))


# The second check, written apart from the rules above (none of their patterns is reused): what a secret looks like after
# zero-width and control characters (or their escapes) and bytes that were not UTF-8 are taken out.
_S_INVISIBLE = re.compile("[\x00-\x08\x0b-\x1f\x7f\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\udc80-\udcff]|\\\\u(?:00[01][0-9a-f]|20(?:0[b-f]|2[a-e]|6[0-4])|feff|00ad|180e|007f)|\\\\x(?:[01][0-9a-f]|7f)", re.I)
_S_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY|PRIVATE KEY-----")
_S_NAMED = re.compile(r"(?i)(?<![a-z])(?:pass(?:word|wd|phrase)|secret|token|api[_-]?key|access[_-]?key|account[_-]?key|private[_-]?key|client[_-]?secret)s?"
                      r"[\"']?\s*[=:]\s*[\"']?(?![<\s\"'])[^\s\"']")
_S_DIGITS = re.compile(r"[0-9]{19}")
_S_PREFIX = re.compile(r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{12}|(?:gh[pousr]_|github_pat_|glpat-|xox[a-z]-|xapp-|sk-|sk_live_|rk_live_|pk_live_|sk_test_"
                       r"|npm_|pypi-|shpat_|dop_v1_|AIza|ya29\.|SG\.)[A-Za-z0-9_-]{12}|eyJ[A-Za-z0-9_-]{12}")
_S_USERINFO = re.compile(r"[^\s/@:<>\"']{1,64}:[^\s/<>\"']{1,128}@[A-Za-z0-9\[]")
_S_RUN = re.compile(r"[A-Za-z0-9+/_-]{20,}")
_S_HEX = re.compile(r"[0-9A-Fa-f-]+")
_S_IDS = re.compile(r"[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")


def _class(c):
    return 0 if c.isdigit() else 1 if c.isupper() else 2


def _random_run(run):
    """A run that changes between capitals, small letters and digits as random text does (an English name, a path, a
    version or a hexadecimal identifier does not)."""
    if _S_HEX.fullmatch(run):
        return False
    pieces = [p for p in re.split(r"[/_+-]", run) if p]
    alnum = "".join(pieces)
    if len(alnum) < 20 or max(len(p) for p in pieces) < 12:
        return False
    kinds = {_class(c) for c in alnum}
    if len(kinds) < 2:
        return False
    lower = [len(r) for r in re.findall(r"[a-z]+", alnum)]
    if lower and sum(lower) >= 3 * len(lower) and not re.search(r"[A-Z]{2}", alnum):
        return False                        # words written together (WebServerPrimary01): capitals one at a time, words of three letters or more
    changes = sum(1 for a, b in zip(alnum, alnum[1:]) if _class(a) != _class(b)) / (len(alnum) - 1)
    digit_runs = len(re.findall(r"[0-9]+", alnum))
    if kinds == {0, 1, 2}:
        return changes >= 0.42 or (changes >= 0.3 and digit_runs >= 4 and len(set(alnum)) >= 0.6 * len(alnum))
    if kinds == {1, 2}:                    # letters only: only a case pattern no word has
        return changes >= 0.5 and len(alnum) >= 24
    return changes >= 0.4 and digit_runs >= 5 and len(set(alnum)) >= 0.5 * len(alnum)     # one case of letters and digits


def _suspect(text):
    """The name of the check a string fails, or None."""
    if text in OWN_NAMES or text in VOCABULARY:
        return None
    flat = _S_INVISIBLE.sub("", text)
    for name, rule in (("a PEM marker", _S_PEM), ("a named secret", _S_NAMED), ("a long digit run", _S_DIGITS), ("a token prefix", _S_PREFIX), ("user-info", _S_USERINFO)):
        if rule.search(flat):
            return name
    for m in _S_RUN.finditer(_S_IDS.sub(" ", flat)):
        if _random_run(m.group()):
            return "a random-looking run"
    return None


def _replace(value, where, check):
    BOUNDARY["replaced"] += 1
    BOUNDARY["by"][check] += 1
    if len(BOUNDARY["where"]) < MAX_REPLACED_LISTED:
        BOUNDARY["where"].append({"at": where or "/", "check": check})
    else:
        BOUNDARY["not_listed"] += 1
    return "<withheld: %d bytes>" % blen(value)


def backstop(value, where=""):
    """The serialised answer read back and checked by the same rules once and by the second check: a string either would
    still change (a key or a value) is replaced by <withheld: N bytes>, counted, and its place named."""
    if isinstance(value, str):
        if _rules_once(value) != value:
            return _replace(value, where, "the same rules")
        check = _suspect(value)
        return _replace(value, where, "second check: %s" % check) if check else value
    if big_int(value):
        return _replace(str(value), where, "second check: a long digit run")
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            key = backstop(k, where + "/(key)")
            while key in out:
                key += " #"
            out[key] = backstop(v, where + "/" + key)
        return out
    if isinstance(value, list):
        return [backstop(v, "%s/%d" % (where, i)) for i, v in enumerate(value)]
    return value


def row_text(row, where):
    """One row of a paging file: sealed, serialised, read back and checked."""
    text = json.dumps(seal(row))
    before = BOUNDARY["replaced"]
    checked = backstop(json.loads(text), where)
    return text if BOUNDARY["replaced"] == before else json.dumps(checked)


def answer_text(doc):
    """The answer (or an error answer): sealed, serialised, read back and checked; a string the check had to replace,
    here or in a paging file, makes a complete answer partial, and the answer says so."""
    text = json.dumps(seal(doc), indent=2)
    checked = backstop(json.loads(text), "")
    checked["boundary"] = {"strings_withheld_at_the_way_out": BOUNDARY["withheld"], "strings_replaced_by_the_check": BOUNDARY["replaced"],
                           "replaced_by_check": dict(BOUNDARY["by"]), "replaced_at": list(BOUNDARY["where"]), "replaced_not_listed": BOUNDARY["not_listed"],
                           "note": "every key and value of this answer and of its paging files was withheld by shape as it was written, then read back "
                                   "and checked by the same rules and by a second check written apart from them; a string either check replaced is "
                                   "<withheld: N bytes> and its place is in replaced_at (the first %d)" % MAX_REPLACED_LISTED}
    if BOUNDARY["replaced"] and checked.get("status") == "complete":
        checked["status"] = "partial"
        checked["status_basis"] = "%s; %d string(s) still held a token-shaped text when the answer was checked on its way out and were replaced by <withheld: N bytes> (see boundary)" % (
            checked.get("status_basis") or "", BOUNDARY["replaced"])
    return json.dumps(checked, indent=2)
# END SHARED BOUNDARY


def iso_from_epoch(value):
    try:
        stamp = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=value)
        return stamp.strftime("%Y-%m-%dT%H:%M:%S") + (".%06d" % stamp.microsecond if stamp.microsecond else "") + "Z"
    except (OverflowError, ValueError, OSError):
        return None


ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?\s*(Z|[+-]\d{2}:?\d{2})?$")


class TimeReader:
    """Reads a time exactly as the caller declared it, or says why it could not."""

    def __init__(self, fmt, offset_minutes):
        self.fmt, self.offset = fmt, offset_minutes

    def read(self, raw):
        """(utc iso or None, basis)"""
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            return None, "no time in the record"
        text = raw.strip() if isinstance(raw, str) else raw
        try:
            if self.fmt in ("epoch_seconds", "epoch_milliseconds"):
                value = float(text)
                if not math.isfinite(value) or value < 0:
                    return None, "not a usable epoch value"
                if self.fmt == "epoch_milliseconds":
                    value /= 1000.0
                if value > 253402300799:
                    return None, "epoch value out of range"
                return iso_from_epoch(value), "epoch %s, which are UTC by definition" % self.fmt.split("_")[1]
            if self.fmt == "iso8601":
                m = ISO.match(str(text))
                if not m:
                    return None, "not an ISO 8601 date and time"
                y, mo, d, h, mi, s, frac, zone = m.groups()
                if zone:
                    sign = -1 if zone.startswith("-") else 1
                    digits = zone.lstrip("Z+-").replace(":", "")
                    off = datetime.timedelta(hours=int(digits[:2] or 0), minutes=int(digits[2:] or 0)) * sign
                    basis = "the offset written in the value"
                elif self.offset is not None:
                    off = datetime.timedelta(minutes=self.offset)
                    basis = "a fixed offset of %d minutes declared by the caller; daylight saving is not accounted for" % self.offset
                else:
                    return None, "no zone in the value and none declared: naive local time, not assumed to be UTC"
                local = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), tzinfo=datetime.timezone(off))
                utc = local.astimezone(datetime.timezone.utc)
                return utc.strftime("%Y-%m-%dT%H:%M:%S") + ("." + frac if frac else "") + "Z", basis
            if self.fmt.startswith("strptime:"):
                try:
                    parsed = datetime.datetime.strptime(str(text), self.fmt[9:])
                except ValueError:
                    return None, "the value does not match the declared format (strptime)"
                if parsed.tzinfo is not None:
                    return parsed.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "the zone written in the value (%z)"
                if self.offset is not None:
                    local = parsed.replace(tzinfo=datetime.timezone(datetime.timedelta(minutes=self.offset)))
                    return local.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "a fixed offset of %d minutes declared by the caller; daylight saving is not accounted for" % self.offset
                return None, "no zone in the value and none declared: naive local time, not assumed to be UTC"
        except (ValueError, OverflowError, OSError, TypeError):
            # a fixed phrase: the exception's text quotes the value, and a basis is a dictionary key of the answer too
            return None, "the value does not match the declared format (not a number, or a date or time out of range)"
        return None, "unknown time format"


class Events:
    """The canonical events: counted, paged whole, and aggregated within a bound."""

    def __init__(self, limit, shown, text):
        self.page = LosslessPage(TOOL, "events", limit)
        self.shown, self.text = shown, text
        self.n = 0
        self.by_category = collections.Counter()
        self.by_result = collections.Counter()
        self.first = self.last = None
        self.time_derived = self.time_not_derived = 0
        self.distinct = {"object": collections.Counter(), "actor": collections.Counter(), "host": collections.Counter()}
        self.distinct_over = collections.Counter()
        self.time_reasons = collections.Counter()

    def add(self, source, locator, fmt, **f):
        self.n += 1
        fid = source["id"]
        category = f.get("category", "other")
        result = f.get("result", "unknown")
        self.by_category[category] += 1
        self.by_result[result] += 1
        t = f.get("time_utc")
        if t:
            self.time_derived += 1
            self.first = t if self.first is None or t < self.first else self.first
            self.last = t if self.last is None or t > self.last else self.last
        else:
            self.time_not_derived += 1
            self.time_reasons[f.get("time_basis") or ""] += 1
        row = {"seq": self.n, "source_id": fid, "format": fmt, "locator": locator}
        for key in ("object", "actor", "host"):
            if f.get(key) is not None:
                f[key] = self.shown(f[key], "%s#%d" % (fid, self.n), key)
                counter = self.distinct[key]
                if f[key] in counter or len(counter) < MAX_DISTINCT:
                    counter[f[key]] += 1
                else:
                    self.distinct_over[key] += 1
        for key in ("action_raw", "result_raw", "category_raw", "job", "time_raw", "end_time_raw"):
            if f.get(key) is not None:
                f[key] = self.shown(f[key], "%s#%d" % (fid, self.n), key)
        message = f.pop("message", None)
        if message is not None:
            f["message_chars"] = len(message)
            if self.text.enabled:
                self.text.add({"record_type": "message", "seq": self.n, "source_id": fid, "locator": locator, "message": message})
        row.update(f)
        self.page.add(row)


def read_lines(fh, max_line):
    """(number, offset, length, bytes or None for an over-long line) a line at a time, never holding more than max_line + 1 bytes."""
    n, offset = 0, 0
    while True:
        raw = fh.readline(max_line + 1)
        if not raw:
            return
        n += 1
        start, length = offset, len(raw)
        if len(raw) > max_line and not raw.endswith(b"\n"):
            while True:
                more = fh.readline(max_line)
                length += len(more)
                if not more or more.endswith(b"\n"):
                    break
            offset += length
            yield n, start, length, None
            continue
        offset += length
        yield n, start, length, raw


def decode_line(raw):
    body = raw[:-1] if raw.endswith(b"\n") else raw
    if body.endswith(b"\r"):
        body = body[:-1]
    return body.decode("utf-8", "surrogateescape")


# ---- Proxmox ---------------------------------------------------------------------------------------------------------

# Proxmox VE: UPID:node:pid:pstart:starttime:type:id:user:   (pid, starttime 8 hexadecimal digits; pstart 8 or more)
# Proxmox Backup Server: UPID:node:pid:pstart:task_id:starttime:worker_type:worker_id:auth_id:   (one more field, the task
# counter; the worker id is escaped as a systemd unit name, \xNN, `-` for `/`). Either is followed, in the task index, by
# the end time (8 hexadecimal digits) and the status when the task ended.
UPID = re.compile(r"^UPID:([^:]*):([0-9A-Fa-f]{8}):([0-9A-Fa-f]{8,16}):([0-9A-Fa-f]{8}):([^:]*):([^:]*):([^:]*):(?:\s+([0-9A-Fa-f]{8})\s*(.*))?$")
UPID_PBS = re.compile(r"^UPID:([^:]*):([0-9A-Fa-f]{8}):([0-9A-Fa-f]{8,16}):([0-9A-Fa-f]{8}):([0-9A-Fa-f]{8}):([^:]*):([^:]*):([^:]*):(?:\s+([0-9A-Fa-f]{8})\s*(.*))?$")


def systemd_unescape(text):
    """A PBS worker id as written (systemd unit-name escaping: `-` stands for `/`, \\xNN for a byte) back to its text."""
    out, i = [], 0
    while i < len(text):
        if text.startswith("\\x", i) and re.fullmatch(r"[0-9a-fA-F]{2}", text[i + 2:i + 4]):
            out.append(chr(int(text[i + 2:i + 4], 16)))
            i += 4
        else:
            out.append("/" if text[i] == "-" else text[i])
            i += 1
    return "".join(out)


def pve_category(task_type):
    t = (task_type or "").lower()
    if t in PVE_TYPES:
        return PVE_TYPES[t], "worker type table of this tool"
    for needle, cat in (("prune", "retention_prune"), ("garbage", "retention_gc"), ("verif", "verification"), ("delsnap", "snapshot_delete")):
        if needle in t:
            return cat, "keyword '%s' in the worker type (this tool's table; check the product version)" % needle
    return "other", "the worker type is not in this tool's table"


def parse_task_index(fh, source, events, clock, max_line, stats):
    for n, off, length, raw in read_lines(fh, max_line):
        clock.check(1024)
        if raw is None:
            stats["over_limit"] += 1
            stats["problem_lines"].append({"source_id": source["id"], "line": n, "byte_offset": off, "reason": "line over max_line_bytes: located, not read"})
            continue
        line = decode_line(raw)
        if not line.strip():
            stats["blank"] += 1
            continue
        m = UPID_PBS.match(line.strip())
        product = "proxmox_backup_server"
        if m:
            node, pid, pstart, task_no, starttime, ttype, wid, user, endtime, status = m.groups()
            tid = systemd_unescape(wid) if wid else wid
        else:
            m = UPID.match(line.strip())
            product, task_no, wid = "proxmox_ve", None, None
            if m:
                node, pid, pstart, starttime, ttype, tid, user, endtime, status = m.groups()
        if not m:
            stats["unparsed"] += 1
            if len(stats["problem_lines"]) < 200:
                stats["problem_lines"].append({"source_id": source["id"], "line": n, "byte_offset": off, "reason": "not a UPID task line"})
            continue
        start_utc = iso_from_epoch(int(starttime, 16))
        end_utc = iso_from_epoch(int(endtime, 16)) if endtime else None
        status = (status or "").strip()
        category, basis = pve_category(ttype)
        if endtime is None:
            result, result_basis = "unknown", "no end time or status on the line: the task was running, interrupted or not yet indexed"
        elif status == "OK":
            result, result_basis = "ok", "status OK"
        elif status.upper().startswith("WARNINGS"):
            result, result_basis = "warning", "status begins WARNINGS"
        elif status.lower() == "unknown":
            # the product wrote that it does not know how the task ended (a task whose worker went away); not an error
            result, result_basis = "unknown", "status unknown: the product did not derive how the task ended (this tool's mapping of that word)"
        else:
            result, result_basis = "error", "status other than OK, WARNINGS or unknown (this tool's mapping)"
        stats["parsed"] += 1
        task = {"pid": int(pid, 16), "pstart": pstart, "upid_layout": product}
        if product == "proxmox_backup_server":
            # the escaped form shows what the unescaped one holds (\x41 is A): it is withheld whenever the unescaped id is
            as_written = None
            if wid:
                obj_shown = events.shown(tid, "%s#%d" % (source["id"], events.n + 1), "worker id")
                as_written = events.shown(wid, "%s#%d" % (source["id"], events.n + 1), "worker id as written") if obj_shown == tid else (
                    "<withheld %d characters: the unescaped worker id (object) is withheld>" % len(wid))
            task.update(task_counter=int(task_no, 16), worker_id_as_written=as_written,
                        worker_id_note="Proxmox Backup Server writes the worker id escaped as a systemd unit name; object is it unescaped")
        events.add(source, {"line": n, "byte_offset": off, "byte_length": length}, "pve_task_index", time_utc=start_utc, time_raw=starttime, time_basis="start time, epoch seconds in hexadecimal, UTC by definition",
                   end_time_utc=end_utc, end_time_raw=endtime, category=category, category_basis=basis, action_raw=ttype, object=tid or None, actor=user or None, host=node or None,
                   result=result, result_basis=result_basis, result_raw=status or None, task=task)


LOG_PREFIX = re.compile(r"^(INFO|WARN|ERROR|TASK OK|TASK ERROR|TASK WARNINGS)(?::\s?|$)(.*)$")
LOG_PATTERNS = [
    (re.compile(r"^starting new backup job: vzdump(.*)$"), "backup_job", "unknown", "job start", "starting new backup job"),
    (re.compile(r"^Starting Backup of VM (\d+) \((\w+)\)$"), "backup_start", "unknown", "backup of one guest started", "Starting Backup of VM"),
    (re.compile(r"^Finished Backup of VM (\d+) \(([\d:]+)\)$"), "backup_end", "ok", "backup of one guest finished", "Finished Backup of VM"),
    (re.compile(r"^Backup of VM (\d+) failed - (.*)$"), "backup_error", "error", "backup of one guest failed", "Backup of VM failed"),
    (re.compile(r"^creating (?:vzdump|pbs) archive '(.*)'$"), "archive_created", "unknown", "an archive was started", "creating archive"),
    (re.compile(r"^Backup job finished successfully$"), "task_end", "ok", "the job's own closing line", "Backup job finished successfully"),
    (re.compile(r"^Backup job finished with errors$"), "task_end", "error", "the job's own closing line", "Backup job finished with errors"),
    (re.compile(r"^removing backup '(.*)'$"), "retention_remove", "unknown", "an older backup was removed (the retention setting's step)", "removing backup"),
    (re.compile(r"^(?:prune|pruned) .*$"), "retention_prune", "unknown", "a prune step", "prune"),
]
LOG_TIME = re.compile(r"^Backup (started|finished) at (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$")


def parse_vzdump_log(fh, source, events, clock, max_line, stats, times):
    for n, off, length, raw in read_lines(fh, max_line):
        clock.check(1024)
        if raw is None:
            stats["over_limit"] += 1
            stats["problem_lines"].append({"source_id": source["id"], "line": n, "byte_offset": off, "reason": "line over max_line_bytes: located, not read"})
            continue
        line = decode_line(raw)
        if not line.strip():
            stats["blank"] += 1
            continue
        m = LOG_PREFIX.match(line)
        if not m:
            stats["unparsed"] += 1
            if len(stats["problem_lines"]) < 200:
                stats["problem_lines"].append({"source_id": source["id"], "line": n, "byte_offset": off, "reason": "no INFO, WARN, ERROR or TASK prefix"})
            continue
        level, rest = m.group(1), m.group(2).strip()
        loc = {"line": n, "byte_offset": off, "byte_length": length}
        if level.startswith("TASK"):
            result = {"TASK OK": "ok", "TASK ERROR": "error", "TASK WARNINGS": "warning"}[level]
            stats["parsed"] += 1
            events.add(source, loc, "pve_task_log", time_utc=None, time_raw=None, time_basis="the line carries no time", category="task_end", category_basis="the TASK result line of a task log",
                       action_raw=level, result=result, result_basis="the task's own result line", message=rest)
            continue
        tm = LOG_TIME.match(rest)
        if tm:
            utc, basis = times.read(tm.group(2))
            stats["parsed"] += 1
            events.add(source, loc, "pve_task_log", time_utc=utc, time_raw=tm.group(2), time_basis=basis + " (a node-local time as the log prints it)", category="backup_start" if tm.group(1) == "started" else "backup_end",
                       category_basis="'Backup %s at' line" % tm.group(1), action_raw="Backup %s at" % tm.group(1), result="unknown", result_basis="a time line states no result", message=rest)
            continue
        for pattern, category, result, why, label in LOG_PATTERNS:
            pm = pattern.match(rest)
            if not pm:
                continue
            stats["parsed"] += 1
            groups = pm.groups()
            obj = groups[0] if category in ("backup_start", "backup_end", "backup_error", "archive_created", "retention_remove") else None
            events.add(source, loc, "pve_task_log", time_utc=None, time_raw=None, time_basis="the line carries no time", category=category, category_basis=why, action_raw=label,
                       object=obj, result=result if level != "ERROR" else "error", result_basis=("the level of the line (%s)" % level) if level != "INFO" else "the pattern's meaning, not a confirmed outcome",
                       message=rest)
            break
        else:
            stats["unparsed"] += 1
            if len(stats["problem_lines"]) < 200:
                stats["problem_lines"].append({"source_id": source["id"], "line": n, "byte_offset": off, "reason": "a %s line this tool has no pattern for" % level})
            if level in ("WARN", "ERROR"):
                stats["parsed"] += 1
                stats["unparsed"] -= 1
                if stats["problem_lines"] and stats["problem_lines"][-1]["line"] == n and stats["problem_lines"][-1]["source_id"] == source["id"]:
                    stats["problem_lines"].pop()
                events.add(source, loc, "pve_task_log", time_utc=None, time_raw=None, time_basis="the line carries no time", category="other", category_basis="a WARN or ERROR line this tool has no pattern for",
                           action_raw=level, result="warning" if level == "WARN" else "error", result_basis="the level of the line", message=rest)


# ---- declared mappings -----------------------------------------------------------------------------------------------

MISSING = object()   # a declared field the record does not have (a field that is there and null or empty is not missing)


def get_path(obj, path):
    """A value of a nested JSON object by dotted path; MISSING when the path is not in the object."""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return MISSING
    return cur


def scalar(value):
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value)[:MAX_FIELD]
    return str(value)


def declared_event(events, source, loc, fmt, record_get, mapping, times, category_map, result_map, stats):
    stats["records_declared"] += 1

    def field(name):
        """The declared field's value; a field the record does not have is counted per field (the CSV header check's twin)."""
        if not mapping.get(name):
            return None
        value = record_get(mapping[name])
        if value is MISSING:
            stats["fields_absent"][name] += 1
            return None
        return scalar(value)
    raw_time = field("time")
    utc, basis = times.read(raw_time)
    action = field("action")
    result_raw = field("result")
    if action is not None and action.lower() in category_map:
        category, category_basis = category_map[action.lower()], "declared in category_map"
    else:
        category, category_basis = "other", "not in the caller's category_map" if category_map else "no category_map declared: the action is kept raw"
        if action is not None:
            key = events.shown(action, "actions", "action")      # withheld by shape whole, then cut: never cut first
            if key in stats["unmapped_actions"] or len(stats["unmapped_actions"]) < 500:
                stats["unmapped_actions"][key] += 1
            else:
                stats["unmapped_actions_over"] += 1
    if result_raw is not None and result_raw.lower() in result_map:
        result, result_basis = result_map[result_raw.lower()], "declared in result_map"
    else:
        result, result_basis = "unknown", ("not in the caller's result_map" if result_map else "no result_map declared") if result_raw is not None else "no result field in the record"
    events.add(source, loc, fmt, time_utc=utc, time_raw=raw_time, time_basis=basis, category=category, category_basis=category_basis, action_raw=action,
               object=field("object"), actor=field("actor"), host=field("host"), job=field("job"),
               result=result, result_basis=result_basis, result_raw=result_raw, message=field("message"),
               mapping_declared_by="the caller; the tool does not know the product")
    stats["parsed"] += 1


def parse_csv(fh, source, events, clock, max_line, stats, mapping, times, category_map, result_map, delimiter, has_header, columns):
    csv.field_size_limit(MAX_FIELD)
    text = (l.decode("utf-8", "surrogateescape") for l in iter(lambda: fh.readline(max_line + 1), b""))
    reader = csv.reader(text, delimiter=delimiter)
    header, record = columns, 0
    used = {v for v in mapping.values() if isinstance(v, str)}
    try:
        for row in reader:
            clock.check(1024)
            if header is None and has_header:
                header = [c.strip().lstrip("﻿") for c in row]
                missing = sorted(u for u in used if u not in header)
                if missing:
                    stats["mapping_errors"].append("the declared column(s) %s are not in the header (%d columns)" % (", ".join(shown_names(missing)), len(header)))
                    return
                continue
            if header is None:
                header = columns
            record += 1
            if not row:
                stats["blank"] += 1
                continue
            if len(row) != len(header):
                stats["unparsed"] += 1
                if len(stats["problem_lines"]) < 200:
                    stats["problem_lines"].append({"source_id": source["id"], "record": record, "line": reader.line_num, "reason": "%d fields and the header has %d" % (len(row), len(header))})
                continue
            fields = dict(zip(header, row))
            declared_event(events, source, {"record": record, "line": reader.line_num}, "declared_csv", fields.get, mapping, times, category_map, result_map, stats)
    except csv.Error as exc:
        stats["unparsed"] += 1
        stats["read_errors"].append("the CSV reader stopped at record %d, line %d: %s" % (record + 1, reader.line_num, brief(exc, 100)))


def shown_names(names):
    return [seal_text(n, "text") for n in names]


def parse_jsonl(fh, source, events, clock, max_line, stats, mapping, times, category_map, result_map):
    for n, off, length, raw in read_lines(fh, max_line):
        clock.check(1024)
        if raw is None:
            stats["over_limit"] += 1
            stats["problem_lines"].append({"source_id": source["id"], "line": n, "byte_offset": off, "reason": "line over max_line_bytes: located, not read"})
            continue
        line = decode_line(raw).strip()
        if not line:
            stats["blank"] += 1
            continue
        try:
            obj = json.loads(line)
        except (ValueError, RecursionError):
            stats["unparsed"] += 1
            if len(stats["problem_lines"]) < 200:
                stats["problem_lines"].append({"source_id": source["id"], "line": n, "byte_offset": off, "reason": "not a JSON value (or nested too deeply)"})
            continue
        if not isinstance(obj, dict):
            stats["unparsed"] += 1
            if len(stats["problem_lines"]) < 200:
                stats["problem_lines"].append({"source_id": source["id"], "line": n, "byte_offset": off, "reason": "a JSON value that is not an object"})
            continue
        declared_event(events, source, {"line": n, "byte_offset": off, "byte_length": length}, "declared_jsonl", lambda p: get_path(obj, p), mapping, times, category_map, result_map, stats)


class Node:
    __slots__ = ("tag", "attrib", "text", "kids")

    def __init__(self, tag, attrib):
        self.tag, self.attrib, self.text, self.kids = tag, attrib, None, []


def xml_stream(fh, record_tag, on_record, max_bytes, clock, on_over):
    """Feed expat in chunks; every <record_tag> element is built, handed over and dropped, so memory follows one record."""
    import xml.parsers.expat as expat

    def refuse(*_a):
        raise ValueError("a DOCTYPE or ENTITY declaration is refused: no entity is expanded")
    # Memory follows one record, and one record is bounded: its text and attributes together (MAX_XML_RECORD_BYTES), any one
    # field (MAX_FIELD); a record over either is counted and located, never read in part (on_over). What the reader takes in
    # without a callback (a giant tag, attribute list or comment, which expat holds whole) is bounded by MAX_XML_TOKEN.
    state = {"stack": [], "rec": None, "elements": 0, "records": 0, "depth": 0, "last_line": 1, "bytes": 0, "over": None, "calls": 0}

    def start(tag, attrs):
        state["calls"] += 1
        state["depth"] += 1
        if state["depth"] > MAX_XML_DEPTH:
            raise ValueError("nested deeper than %d" % MAX_XML_DEPTH)
        name = tag.rsplit(":", 1)[-1]
        if state["rec"] is None:
            if name == record_tag:
                state["rec"] = Node(name, attrs)
                state["stack"] = [state["rec"]]
                state["elements"] = 1
                state["bytes"] = sum(len(k) + len(v) for k, v in attrs.items())
                state["over"] = None
                if state["bytes"] > MAX_XML_RECORD_BYTES:
                    state["over"] = "its attributes hold more than %d bytes" % MAX_XML_RECORD_BYTES
                    state["rec"].attrib = {}
            return
        state["elements"] += 1
        if state["elements"] > MAX_XML_RECORD_ELEMENTS:
            raise ValueError("a record has more than %d elements" % MAX_XML_RECORD_ELEMENTS)
        size = sum(len(k) + len(v) for k, v in attrs.items())
        if state["over"] is None and state["bytes"] + size > MAX_XML_RECORD_BYTES:
            state["over"] = "it holds more than %d bytes of text and attributes" % MAX_XML_RECORD_BYTES
        node = Node(name, {} if state["over"] else attrs)
        state["bytes"] += 0 if state["over"] else size
        state["stack"][-1].kids.append(node)
        state["stack"].append(node)

    def end(tag):
        state["calls"] += 1
        state["depth"] -= 1
        if state["rec"] is None:
            return
        node = state["stack"].pop()
        if not state["stack"]:
            state["records"] += 1
            if state["over"]:
                on_over(state["records"], parser.CurrentLineNumber, state["over"])
            else:
                on_record(state["rec"], state["records"], parser.CurrentLineNumber)
            state["rec"] = None

    def chars(text):
        state["calls"] += 1
        if state["rec"] is not None and state["stack"] and state["over"] is None:
            node = state["stack"][-1]
            if (len(node.text) if node.text else 0) + len(text) > MAX_FIELD:
                state["over"] = "one of its fields is over %d bytes" % MAX_FIELD
            elif state["bytes"] + len(text) > MAX_XML_RECORD_BYTES:
                state["over"] = "it holds more than %d bytes of text and attributes" % MAX_XML_RECORD_BYTES
            else:
                node.text = (node.text or "") + text
                state["bytes"] += len(text)
            if state["over"]:
                for kept in state["stack"]:
                    kept.text = None
                state["rec"].kids = []

    parser = expat.ParserCreate()
    parser.buffer_text = True
    parser.StartElementHandler, parser.EndElementHandler, parser.CharacterDataHandler = start, end, chars
    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    total, quiet = 0, 0
    while True:
        chunk = fh.read(65536)
        total += len(chunk)
        if total > max_bytes:
            raise ValueError("the file is over max_file_bytes (%d)" % max_bytes)
        clock.check()
        calls = state["calls"]
        parser.Parse(chunk, not chunk)
        quiet = quiet + len(chunk) if state["calls"] == calls else 0
        if quiet > MAX_XML_TOKEN:
            raise ValueError("more than %d bytes were read at byte %d without one element or text ending (a tag, an attribute list or a comment that large is not read)" % (MAX_XML_TOKEN, total))
        if not chunk:
            break
    return state["records"]


def xml_get(rec, path):
    """A value of an XML record: 'tag/sub' (text of the first match), '@attr' (an attribute of the record), 'tag@attr';
    MISSING when the element or the attribute is not in the record."""
    node, _, attr = path.partition("@")
    cur = rec
    for part in [p for p in node.split("/") if p]:
        nxt = None
        for k in cur.kids:
            if k.tag == part:
                nxt = k
                break
        if nxt is None:
            return MISSING
        cur = nxt
    if attr:
        return cur.attrib.get(attr, MISSING)
    return (cur.text or "").strip() if (cur is not rec or not node) else (rec.text or "").strip() or None


def parse_xml(fh, source, events, clock, stats, mapping, times, category_map, result_map, record_tag, max_bytes):
    def on_record(rec, number, line):
        declared_event(events, source, {"record": number, "line": line}, "declared_xml", lambda p: xml_get(rec, p), mapping, times, category_map, result_map, stats)

    def on_over(number, line, why):
        stats["over_limit"] += 1
        if len(stats["problem_lines"]) < 200:
            stats["problem_lines"].append({"source_id": source["id"], "record": number, "line": line, "reason": "a record over the reader's budget (%s): located, not read" % why})
    import xml.parsers.expat as expat
    try:
        count = xml_stream(fh, record_tag, on_record, max_bytes, clock, on_over)
    except (expat.ExpatError, ValueError, LookupError, RecursionError, MemoryError) as exc:
        # one file's damage (an encoding the reader does not know is a LookupError) ends the reading of that file only
        stats["read_errors"].append("%s: the XML stopped being readable (%s)" % (source["id"], brief(exc, 160)))
        return
    if count == 0:
        stats["read_errors"].append("%s: no <%s> element in the file" % (source["id"], seal_text(record_tag, "text")))


# ---- the run ---------------------------------------------------------------------------------------------------------

def want_mapping(args):
    mapping = args.get("mapping")
    if not isinstance(mapping, dict):
        fail("a declared format needs mapping: an object naming the field of each of time, action, and (optional) result, actor, object, host, job, message")
    allowed = ("time", "action", "result", "actor", "object", "host", "job", "message")
    for key, value in mapping.items():
        if key not in allowed or not isinstance(value, str) or not value or len(value) > 200:
            fail("mapping holds a key this tool does not know or a value that is not a field name (allowed keys: %s)" % ", ".join(allowed))
    if not mapping.get("time") or not mapping.get("action"):
        fail("mapping needs at least time and action")
    return mapping


def want_map(args, key, allowed):
    value = args.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > 5000:
        fail("%s must be an object of at most 5000 entries" % key)
    out = {}
    for k, v in value.items():
        if not isinstance(k, str) or len(k) > 200 or v not in allowed:
            fail("%s: every value must be one of %s" % (key, ", ".join(allowed)))
        out[k.lower()] = v
    return out


def main():
    args = read_args()
    paths = want_str_list(args, "paths", MAX_PATHS)
    one = want_str(args, "path")
    if one:
        paths = [one] + paths
    if not paths:
        fail("name the exports: path is one file, paths a list of up to %d" % MAX_PATHS)
    fmt = args.get("format", "auto")
    if fmt not in ("auto", "pve_task_index", "pve_vzdump_log", "declared_csv", "declared_jsonl", "declared_xml"):
        fail("format must be auto, pve_task_index, pve_vzdump_log, declared_csv, declared_jsonl or declared_xml")
    product = want_str(args, "product", maximum=200)
    if product and fmt == "auto" and product.lower() not in ("proxmox", "proxmox_ve", "proxmox_backup_server", "pve", "pbs"):
        known = product.lower() in KNOWN_UNSUPPORTED
        fail("product %s is unsupported: no fixture of its format exists, so none is read (%s). Use format declared_csv, declared_jsonl or declared_xml with a mapping you declare." % (
            seal_text(product, "text"), "a product this tool knows it does not read" if known else "this tool does not know it"), status_note="unsupported", unsupported_product=seal_text(product, "text"))
    limit = want_int(args, "limit", DEFAULT_LIMIT, 1, 100000)
    max_line = want_int(args, "max_line_bytes", MAX_LINE, 4096, 16 << 20)
    max_file = want_int(args, "max_file_bytes", 8 << 30, 1 << 20, 64 << 30)
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    write_text = want_flag(args, "write_text")
    time_format = args.get("time_format", "iso8601")
    if not isinstance(time_format, str) or not (time_format in ("iso8601", "epoch_seconds", "epoch_milliseconds") or (time_format.startswith("strptime:") and 9 < len(time_format) < 120)):
        fail("time_format must be iso8601, epoch_seconds, epoch_milliseconds or strptime:<format>")
    offset = args.get("time_zone_offset_minutes")
    if offset is not None and (isinstance(offset, bool) or not isinstance(offset, int) or abs(offset) > 14 * 60):
        fail("time_zone_offset_minutes must be a whole number of minutes between -840 and 840")
    mapping = category_map = result_map = None
    delimiter, has_header, columns, record_tag = ",", True, None, None
    if fmt.startswith("declared_"):
        mapping = want_mapping(args)
        category_map = want_map(args, "category_map", CATEGORIES)
        result_map = want_map(args, "result_map", RESULTS)
        if fmt == "declared_csv":
            delimiter = args.get("delimiter", ",")
            if not isinstance(delimiter, str) or len(delimiter) != 1 or delimiter in ("\n", "\r", '"'):
                fail("delimiter must be one character")
            has_header = args.get("has_header", True)
            if not isinstance(has_header, bool):
                fail("has_header must be true or false")
            columns = args.get("columns")
            if columns is not None and (not isinstance(columns, list) or not all(isinstance(c, str) and len(c) <= 200 for c in columns) or len(columns) > 1000):
                fail("columns must be a list of at most 1000 names of at most 200 characters")
            if not has_header and not columns:
                fail("a CSV with no header row needs columns")
        if fmt == "declared_xml":
            record_tag = want_str(args, "record_tag", "declared_xml needs record_tag: the element name of one record", maximum=200)
    times = TimeReader(time_format, offset)
    try:
        values = TextFile("audit-values.jsonl", write_text, "JSON Lines, mode 0600: record_type message (seq, source_id, locator, the free-text message of the "
                          "event) or original (where, field, value: the original of a string the answer shows withheld or shortened)")
    except TextRefused as exc:
        fail(str(exc))
    shown = Shower(values)
    events = Events(limit, shown, values)
    clock = Clock(seconds)
    sources, problems = [], []
    stats = {"parsed": 0, "unparsed": 0, "blank": 0, "over_limit": 0, "problem_lines": [], "mapping_errors": [], "read_errors": [], "unmapped_actions": collections.Counter(), "unmapped_actions_over": 0,
             "fields_absent": collections.Counter(), "records_declared": 0}
    unrecognised = []
    partial = []
    for number, p in enumerate(paths, 1):
        rec = {"id": "S%06d" % number, "path": p}
        try:
            st = os.lstat(p)
        except OSError as exc:
            problems.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "reason": describe(exc)})
            sources.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "state": "unreadable"})
            continue
        if not stat.S_ISREG(st.st_mode):
            problems.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "reason": "not a regular file (a link, a pipe or a device): never opened"})
            sources.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "state": "not_opened"})
            continue
        rec["size"] = st.st_size
        try:
            fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        except OSError as exc:
            problems.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "reason": describe(exc)})
            sources.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "state": "unreadable"})
            continue
        with os.fdopen(fd, "rb") as fh:
            before_n, before_errors = events.n, len(stats["mapping_errors"]) + len(stats["read_errors"])
            kind = fmt
            if fmt == "auto":
                head = fh.read(4096)
                fh.seek(0)
                first = next((l for l in head.decode("utf-8", "replace").splitlines() if l.strip()), "")
                if first.startswith("UPID:"):
                    kind = "pve_task_index"
                elif LOG_PREFIX.match(first):
                    kind = "pve_vzdump_log"
                else:
                    shape = "XML" if first.lstrip().startswith("<") else "JSON" if first.lstrip()[:1] in "{[" else "delimited text" if first.count(",") + first.count("\t") + first.count(";") >= 2 else "text"
                    unrecognised.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "shape": shape,
                                         "reason": "no layout this tool reads was recognised; the file was not parsed. A %s export can be read with format declared_%s and a mapping you declare" % (
                                             shape, {"XML": "xml", "JSON": "jsonl", "delimited text": "csv"}.get(shape, "csv"))})
                    sources.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "size": rec["size"], "state": "unsupported", "shape": shape})
                    continue
            try:
                if rec["size"] > max_file:
                    raise ValueError("the file is %d bytes, over max_file_bytes (%d): named and not read" % (rec["size"], max_file))
                if kind == "pve_task_index":
                    parse_task_index(fh, rec, events, clock, max_line, stats)
                elif kind == "pve_vzdump_log":
                    parse_vzdump_log(fh, rec, events, clock, max_line, stats, times)
                elif kind == "declared_csv":
                    parse_csv(fh, rec, events, clock, max_line, stats, mapping, times, category_map, result_map, delimiter, has_header, columns)
                elif kind == "declared_jsonl":
                    parse_jsonl(fh, rec, events, clock, max_line, stats, mapping, times, category_map, result_map)
                else:
                    parse_xml(fh, rec, events, clock, stats, mapping, times, category_map, result_map, record_tag, max_file)
                state = "parsed"
            except Overtime:
                state = "partial"
                partial.append("the read stopped at max_seconds (%s) in %s: the lines after the last event of that file were not read" % (seconds, rec["id"]))
            except (ValueError, LookupError) as exc:
                state = "failed"
                problems.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "reason": brief(exc, 300)})
            except OSError as exc:
                state = "failed"
                problems.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "reason": "a read failed (%s)" % describe(exc)})
            if state == "parsed" and len(stats["mapping_errors"]) + len(stats["read_errors"]) > before_errors:
                state = "partial" if events.n > before_n else "failed"     # this file's own errors, not an earlier file's
            sources.append({"source_id": rec["id"], "file": shown(p, rec["id"], "file"), "size": rec["size"], "format": kind, "state": state, "events": events.n - before_n})
        if clock.left() <= 0:
            partial.append("max_seconds (%s) was reached: the files after %s were not read" % (seconds, rec["id"]))
            break
    if mapping and stats["records_declared"]:
        for name in ("time", "action"):
            if stats["fields_absent"].get(name):
                partial.append("the declared %s field (%s) is absent from %d of %d record(s): those events carry no %s" % (
                    name, shown(mapping[name], "mapping", name), stats["fields_absent"][name], stats["records_declared"], name))
    values.close()
    page = events.page.finish()
    unmapped = sorted(stats["unmapped_actions"].items(), key=lambda kv: -kv[1])[:50]
    not_whole = [s for s in sources if s["state"] in ("partial", "failed", "unreadable", "not_opened")]
    complete = (not not_whole and not stats["unparsed"] and not stats["over_limit"] and not stats["mapping_errors"] and not stats["read_errors"] and not partial
                and not unrecognised and not problems)
    outcome = status_of(complete, events.n == 0 and bool(problems or unrecognised or stats["mapping_errors"]),
                        "every line or record of every file became an event or was a blank line; nothing was left unread",
                        "%d unparsed line(s) or record(s), %d over the line limit, %d file(s) not read whole, %d file(s) unrecognised%s: the answer names them" % (
                            stats["unparsed"], stats["over_limit"], len(not_whole), len(unrecognised), ("; " + "; ".join(partial)) if partial else ""),
                        "no event could be read")
    print(answer_text({
        "parser": PARSER, **outcome,
        "format_requested": fmt, "product_label": seal_text(product, "text") if product else None,
        "product_label_note": "the caller's label for a declared format; not verified" if product and fmt.startswith("declared_") else None,
        "sources": sources, "unrecognised": unrecognised, "problems": problems,
        "events": events.page.page, "pages": {"events": page},
        "counts": {"events": events.n, "parsed": stats["parsed"], "unparsed": stats["unparsed"], "blank": stats["blank"], "over_line_limit": stats["over_limit"]},
        "problem_lines": stats["problem_lines"][:200], "mapping_errors": stats["mapping_errors"], "read_errors": stats["read_errors"],
        "declared_fields_absent": ({"records": stats["records_declared"], "absent_by_field": dict(stats["fields_absent"]),
                                    "note": "a declared field the record does not have at all (present and empty is not absent); time or action absent makes the answer partial"}
                                   if mapping else None),
        "by_category": dict(events.by_category), "by_result": dict(events.by_result),
        "time": {"derived": events.time_derived, "not_derived": events.time_not_derived, "first_utc": events.first, "last_utc": events.last,
                 "not_derived_reasons": dict(events.time_reasons.most_common(10)), "time_format": time_format, "declared_offset_minutes": offset,
                 "note": "events are in source order, not time order; sort on time_utc where it is set. A time with no zone is not assumed to be UTC."},
        "distinct": {k: {"listed": len(v), "over_cap": events.distinct_over[k], "top": [{"value": a, "count": b} for a, b in v.most_common(20)]} for k, v in events.distinct.items()},
        "unmapped_actions_top": [{"action": a, "count": c} for a, c in unmapped] if fmt.startswith("declared_") else None,
        "unmapped_actions_distinct_over_cap": stats["unmapped_actions_over"] if fmt.startswith("declared_") else None,
        "partial_reasons": partial, "text": values.summary(), "withheld": withheld_summary(shown),
        "truncated": page["truncated"],
        "limits": {"max_line_bytes": max_line, "max_file_bytes": max_file, "max_distinct_per_aggregate": MAX_DISTINCT, "xml_record_elements": MAX_XML_RECORD_ELEMENTS},
        "note": "Each event says what a line or record says happened, where it was read and how its time was read. It is not proof the operation took place as described, that a reported success "
                "was a usable restore point, or who did it: an actor is the account the product wrote. A category is a label from a table (this tool's, or the caller's category_map) for the action's name; "
                "the raw action stays beside it. A job that ended OK is not a restore that worked.",
    }))
    return 0 if outcome["status"] != "failed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
        fail("unexpected failure: %s" % describe(exc))

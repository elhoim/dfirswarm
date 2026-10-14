#!/usr/bin/env python3
"""Read the descriptors of a set of virtual-disk files and say how they chain: which file names which as its parent,
whether the parent is there, whether the identity the child recorded is the identity the parent carries, which extents
a descriptor needs and which are missing, and which markers a consolidation or an unclean close may leave behind.

The formats read, from their public descriptions, and no others (a file of any other kind is counted and named, never
guessed at):

    VMware VMDK   a text descriptor (# Disk DescriptorFile: CID, parentCID, parentFileNameHint, createType, extent lines)
                  or the descriptor embedded in a sparse extent (KDMV header, version 1 to 3). A COWD extent is
                  recognised and not read.
    VMware        .vmx (the disk files the configuration names) and .vmsd (the snapshot database), read for the names
                  they hold, to hold the descriptors against.
    VHD           the footer (conectix), the dynamic-disk header (cxsparse) of a dynamic or differencing disk, the
                  parent's unique id, name and locators
    VHDX          the file identifier, the two headers (CRC-32C, sequence number, GUIDs, log GUID), the region table, the
                  metadata table, the file parameters, the virtual disk id and the parent locator
    QCOW2         versions 2 and 3: the header, the backing file name, the header extensions, the feature bits, and the
                  internal snapshot table

What it is and is not. It is a reading of headers and descriptors, not of disk content: no sector of a disk is
interpreted, no extent is opened but to measure it, and nothing is mounted, converted, repaired or merged. A chain it
calls complete is a chain whose named parents are present in the set and whose recorded identities agree; it is not a
disk that boots, and it says nothing about what the parent held when the child was made (QCOW2 records no identity of its
backing file at all). A marker is a candidate with the observation beside it; it is not a verdict. The layouts are
implemented from the format descriptions; they have not been checked against files made by every product or version, and
a version this tool does not know is reported and not read.

qemu-img is run only when asked (qemu_img: auto or require), once per image with the format fixed and never with
--backing-chain, and its answer is kept beside the native reading and never replaces it. Nothing in the set is
executed, and a name inside a file is looked up among the files given, never opened: a parent named outside the set is
reported as missing.

SENSITIVE OUTPUT. Names, hints, snapshot names and descriptions are shown after the shape check of the shared block:
a token-shaped run or user-info is withheld, a long text is shown cut with its whole length, and the original goes to
one private file only when write_text is asked for, in a job. A VM configuration can hold a password or a token under a
key this tool does not read: only the names of the disk files and the snapshot database's names are taken from it.
"""
import collections
import datetime
import errno
import itertools
import json
import math
import os
import posixpath
import re
import secrets
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

TOOL = "snapshot_chain_check"
PARSER = "snapshot_chain_check/1"
DEFAULT_LIMIT = 200
DEFAULT_SECONDS = 50.0          # the manifest allows 60
MAX_SECONDS = 50.0
MAX_DESCRIPTOR = 1 << 20        # a descriptor, embedded or alone, is read to this many bytes
MAX_DESC_LINES = 20000
MAX_EXTENTS = 10000             # extent lines kept per descriptor; the rest are counted
MAX_CONFIG_BYTES = 16 << 20     # a .vmx or .vmsd over this is named and not read
MAX_CONFIG_LINE = 1 << 16
MAX_CONFIG_LINES = 500000
MAX_SNAPSHOT_ENTRIES = 20000    # distinct snapshotN indexes kept from one .vmsd; the rest are counted
DEFAULT_MAX_SNAPSHOTS = 100000  # internal QCOW2 snapshots read from one image
MAX_CHAIN_SHOWN = 50
MAX_CONFIG_ENTRIES_TOTAL = 100000  # snapshot entries (and disk entries) kept across every .vmsd (and .vmx) of one run
CREATE_TYPES = {"monolithicSparse", "monolithicFlat", "twoGbMaxExtentSparse", "twoGbMaxExtentFlat", "fullDevice", "partitionedDevice", "vmfs", "vmfsSparse",
                "vmfsEagerZeroedThick", "vmfsThin", "vmfsRaw", "vmfsRawDeviceMap", "vmfsPassthroughRawDeviceMap", "streamOptimized", "seSparse", "custom"}
KNOWN_DDB = ("ddb.adapterType", "ddb.virtualHWVersion", "ddb.toolsVersion", "ddb.thinProvisioned", "ddb.longContentID", "ddb.uuid")
WITHHELD_CONFIG_NOTE = "other keys of a .vmx are not read: they can hold a password or a token"

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
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def fail(message, **extra):
    """An error answer: JSON, exit 1, the same `status` every answer of this pack carries, nothing identifier-shaped."""
    safe = {k: (scrub(v) if isinstance(v, str) else v) for k, v in extra.items()}
    print(json.dumps({"error": scrub(message), "tool": TOOL, "status": "failed",
                      "status_basis": "the tool stopped with an error (see error)", **safe}))
    raise SystemExit(1)


def read_args():
    try:
        raw = sys.stdin.buffer.read(8 << 20 | 1)
        if len(raw) > 8 << 20:
            fail("arguments are larger than 8 MiB: pass a list of files, not their contents")
        args = json.loads(raw.decode("utf-8") or "{}")
    except (ValueError, UnicodeDecodeError) as exc:
        fail("arguments are not valid JSON", reason=str(exc))
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
# digest of anything asked for. A write that fails is an error answer naming the file, never a loss that goes unsaid.
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
        name = "%s-%s-%s.jsonl" % (self.tool, self.key, secrets.token_hex(8))
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row):
        try:
            self._out.write(json.dumps(row, default=str))
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
# the cut: it is withheld whole.
_OPEN_AUTHORITY = re.compile(r"(?<=//)[^/?#\s]*$")
_OPEN_BARE = re.compile(r"(?<![\w.%+:/-])[\w.%+-]{1,64}:[^\s/@:]*$")


class Shower:
    """Every string the answer shows a name, a path or a value of passes through here: token-shaped runs and user-info are
    withheld, a text over `limit` characters is shown cut with its whole length, and the original of what was changed goes
    to the values file when one was asked for (never anywhere else). Only the first EXAMINED characters of a long text are
    checked (the check is not linear in the length of an adversary's text); the last 20 of them are dropped so that no
    fragment of a token the cut split can be shown, and a run that is still open at the cut and might be user-info is
    withheld whole."""

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
            head = text[:self.EXAMINED - 20]
            head = _OPEN_AUTHORITY.sub(lambda m: _withheld("userinfo", len(m.group()), "text"), head)
            head = _OPEN_BARE.sub(lambda m: _withheld("userinfo", len(m.group()), "text"), head)
        shown = scrub(head)
        was_cut = total > self.EXAMINED
        if len(shown) > self.limit:
            shown = shown[:self.limit]
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
# BEGIN SHARED FILES
# The same text is in virtualization_inventory and snapshot_chain_check; tests/pack-virtualization-shared.test.ts holds the
# copies equal. The evidence is a set of files: a directory walked without following a link, and/or files named one by one.
# Nothing outside that set is ever opened, whatever a file inside it names.


def open_regular(path):
    """Open a regular file for reading without following a final link and without blocking on a pipe; None and the
    reason when it is not one."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        return None, describe(exc)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None, "not a regular file"
    except OSError as exc:
        os.close(fd)
        return None, describe(exc)
    return os.fdopen(fd, "rb"), None


class FileSet:
    """The files an examination covers, in a fixed order (names sorted), each with an id that is a sequence number and
    derived from nothing. What was not reached is counted and named: a link, a special file, a directory too deep, a
    listing that was cut at a cap."""

    def __init__(self, shower):
        self.files = []
        self.by_rel = {}
        self.shower = shower
        self.skipped = {"links": [], "special": [], "unreadable": [], "too_deep": []}
        self.skipped_counts = {"links": 0, "special": 0, "unreadable": 0, "too_deep": 0}
        self.lock_dirs = []
        self.lock_dirs_total = 0
        self.entries_seen = 0
        self.truncated = None
        self.root_shown = None

    def note(self, which, rel):
        self.skipped_counts[which] += 1
        if len(self.skipped[which]) < 200:
            self.skipped[which].append(self.shower(rel, "walk", which))

    def add_file(self, rel, path, size):
        if len(self.files) >= self.max_files:
            self.truncated = self.truncated or "max_files (%d) was reached: the files after the last one listed were not examined" % self.max_files
            return False
        fid = "S%06d" % (len(self.files) + 1)
        rec = {"id": fid, "rel": rel, "path": path, "size": size}
        self.files.append(rec)
        self.by_rel[rel] = rec
        return True

    def walk(self, root, paths, max_files, max_entries, max_depth, clock):
        self.max_files = max_files
        if root is not None:
            if os.path.islink(root):
                fail("refusing a symlink root: pass the evidence directory itself", root=root)
            if not os.path.isdir(root):
                fail("root is not a directory", root=root)
            self.root_shown = self.shower(root, "root", "root")
            stack = [("", 0)]
            while stack:
                rel_dir, depth = stack.pop()
                clock.check()
                here = os.path.join(root, rel_dir) if rel_dir else root
                try:
                    with os.scandir(here) as it:
                        entries = list(itertools.islice(it, max_entries - self.entries_seen + 1))
                except OSError as exc:
                    self.note("unreadable", (rel_dir or ".") + ": " + describe(exc))
                    continue
                if self.entries_seen + len(entries) > max_entries:
                    entries = entries[:max(0, max_entries - self.entries_seen)]
                    self.truncated = self.truncated or "max_entries (%d) was reached: the directories after the last one listed were not read" % max_entries
                    stack = []
                self.entries_seen += len(entries)
                entries.sort(key=lambda e: e.name)
                subdirs = []
                for e in entries:
                    clock.check(256)
                    rel = (rel_dir + "/" + e.name) if rel_dir else e.name
                    try:
                        if e.is_symlink():
                            self.note("links", rel)
                        elif e.is_dir(follow_symlinks=False):
                            if e.name.lower().endswith(".lck") or e.name.lower().startswith(".lck-"):
                                self.lock_dirs_total += 1
                                if len(self.lock_dirs) < 1000:
                                    self.lock_dirs.append(rel)
                            if depth + 1 > max_depth:
                                self.note("too_deep", rel)
                            else:
                                subdirs.append((rel, depth + 1))
                        elif e.is_file(follow_symlinks=False):
                            self.add_file(rel, os.path.join(root, rel), e.stat(follow_symlinks=False).st_size)
                        else:
                            self.note("special", rel)
                    except OSError as exc:
                        self.note("unreadable", rel + ": " + describe(exc))
                for item in reversed(subdirs):
                    stack.append(item)
                if self.truncated and "max_entries" in self.truncated:
                    break
        for p in paths:
            clock.check()
            try:
                st = os.lstat(p)
            except OSError as exc:
                self.note("unreadable", p + ": " + describe(exc))
                continue
            if stat.S_ISLNK(st.st_mode):
                self.note("links", p)
            elif not stat.S_ISREG(st.st_mode):
                self.note("special", p)
            else:
                rel = p
                if rel not in self.by_rel:
                    self.add_file(rel, p, st.st_size)

    def skipped_summary(self):
        return {"counts": dict(self.skipped_counts), "named": self.skipped,
                "note": "A link is listed and never followed; a special file is never opened; at most 200 of each are named, all are counted."}
class Index:
    def __init__(self, files):
        self.exact = {f["rel"]: f for f in files}
        self.fold = collections.defaultdict(list)
        self.base = collections.defaultdict(list)
        for f in files:
            self.fold[f["rel"].casefold()].append(f)
            self.base[posixpath.basename(f["rel"]).casefold()].append(f)

    def resolve(self, from_rel, hint):
        """(file or None, how). The hint is a string some file wrote; it is looked up among the files given and never opened."""
        if not hint or "\x00" in hint:
            return None, "no_name"
        h = hint.replace("\\", "/") if ("\\" in hint and "/" not in hint) else hint
        drive = bool(re.match(r"^[A-Za-z]:", h)) or h.startswith("/") or h.startswith("//") or h.startswith("vmfs/") or h.startswith("[")
        joined = None
        if not drive:
            joined = posixpath.normpath(posixpath.join(posixpath.dirname(from_rel), h))
            if joined.startswith("../") or joined == "..":
                joined = None
        if joined is not None:
            f = self.exact.get(joined)
            if f:
                return f, "relative_exact"
            hits = self.fold.get(joined.casefold(), [])
            if len(hits) == 1:
                return hits[0], "relative_case_insensitive"
        hits = self.base.get(posixpath.basename(h.rstrip("/")).casefold(), [])
        if len(hits) == 1:
            return hits[0], "basename_only"
        if len(hits) > 1:
            return None, "ambiguous_basename"
        return None, "not_in_set"
# END SHARED FILES
# BEGIN SHARED PROCESS
# The same text is in pcap_extract, zeek_run, suricata_run and the network-capture recipe; tests/pack-network-process.test.ts
# holds the copies equal. A program an engine tool runs is started in THIS tool's process group, never in a session of
# its own: the harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid,
# SIGKILL)), and an engine in a group of its own goes on writing into the output directory after the tool is gone. On
# Linux the kernel is also asked to kill it if the tool dies. A deadline kills the program and what it started by
# walking the process tree, and SIGTERM, SIGINT and SIGHUP do the same and then give the tool a last word.
try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

STATE = {"last_word": None}    # what to do, with the signal number, when the tool is stopped by a signal
ACTIVE = []                    # the programs running now

def _die_with_parent():  # runs in the child between fork and exec
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGKILL)   # PR_SET_PDEATHSIG
    except Exception:  # noqa: BLE001
        pass


def spawn(argv, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    if sys.platform.startswith("linux") and ctypes is not None:
        kwargs["preexec_fn"] = _die_with_parent
    return subprocess.Popen(argv, **kwargs)


def descendants(pid):
    """Every process below `pid`, from /proc where there is one, else from ps."""
    kids = {}
    try:
        if os.path.isdir("/proc/self"):
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        kids.setdefault(int(fields[1]), []).append(int(entry))
                    except (OSError, IndexError, ValueError):
                        continue
        else:
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    kids.setdefault(int(parts[1]), []).append(int(parts[0]))
    except (OSError, subprocess.SubprocessError):
        return []
    found, stack = [], [pid]
    while stack:
        for child in kids.get(stack.pop(), []):
            found.append(child)
            stack.append(child)
    return found


def kill_tree(proc):
    """Kill the program and everything it started. The children are listed first: once the parent is gone they are
    adopted by init and can no longer be found below it."""
    victims = descendants(proc.pid)
    try:
        proc.kill()
    except OSError:
        pass
    for pid in victims:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def _on_signal(signum, _frame):
    for proc in list(ACTIVE):
        kill_tree(proc)
    last_word = STATE.get("last_word")
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    os._exit(128 + signum)


def preflight(argv, seconds):
    """Run a short program, bounded; (exit code or None, stdout bytes, stderr bytes, timed out)."""
    try:
        proc = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        return None, b"", describe(exc).encode("utf-8", "replace"), False
    ACTIVE.append(proc)
    try:
        out, err = proc.communicate(timeout=max(1.0, seconds))
        return proc.returncode, out, err, False
    except subprocess.TimeoutExpired:
        kill_tree(proc)
        out, err = proc.communicate()
        return None, out, err, True
    finally:
        ACTIVE.remove(proc)


def run_to_files(argv, stdout_path, stderr_path, seconds, cwd=None):
    """One program with its output in files, killed with what it started at `seconds`. (exit code, timed out)."""
    with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
        proc = spawn(argv, stdout=stdout, stderr=stderr, cwd=cwd)
        ACTIVE.append(proc)
        try:
            return proc.wait(timeout=max(0.1, seconds)), False
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            proc.wait()
            return None, True
        finally:
            ACTIVE.remove(proc)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
# END SHARED PROCESS


# A value that is a number, a UUID or a run of hex bytes is shown as it is.
SAFE_VALUE = re.compile(r"[0-9]{1,12}|[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}|(?:[0-9A-Fa-f]{2}[ -]){3,31}[0-9A-Fa-f]{2}")


def make_net(shown, fid):
    """The net under every record: a string from the evidence that no call site has checked is checked here."""
    def net(value, depth=0):
        if isinstance(value, str):
            if isinstance(value, Shown) or value in CREATE_TYPES or SAFE_VALUE.fullmatch(value):
                return value
            return shown(value, fid, "value")
        if depth > 5:
            return value
        if isinstance(value, dict):
            return {k: net(v, depth + 1) for k, v in value.items()}
        if isinstance(value, list):
            return [net(v, depth + 1) for v in value]
        return value
    return net


# ---- small readers -----------------------------------------------------------------------------------------------

def read_at(fh, offset, length):
    if offset < 0 or length < 0:
        return b""
    fh.seek(offset)
    return fh.read(length)


def iso_utc(epoch, base=0):
    try:
        stamp = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=epoch + base)
        return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return None


def guid_text(raw):
    return str(uuid.UUID(bytes_le=raw)).upper()


_CRC = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0x82F63B78 if _c & 1 else _c >> 1
    _CRC.append(_c)


def crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


# ---- VMDK ------------------------------------------------------------------------------------------------------------

EXTENT = re.compile(r'^(RW|RDONLY|NOACCESS)\s+(\d+)\s+([A-Za-z0-9_]+)(?:\s+"((?:[^"\\]|\\.)*)")?(?:\s+(\d+))?\s*(?:#.*)?$')
DESC_KV = re.compile(r'^([A-Za-z][A-Za-z0-9_.]*)\s*=\s*(.*)$')
HEX8 = re.compile(r"^[0-9a-fA-F]{8}$")


def unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return value


def parse_descriptor(text):
    """The fields of a VMDK descriptor, its extents (up to MAX_EXTENTS) and the counts of what was not kept."""
    d = {"fields": {}, "extents": [], "extents_total": 0, "ddb": {}, "ddb_other": 0, "lines_over_cap": False, "other_lines": 0}
    for number, raw in enumerate(text.split("\n"), 1):
        if number > MAX_DESC_LINES:
            d["lines_over_cap"] = True
            break
        line = raw.strip().rstrip("\r")
        if not line or line.startswith("#"):
            continue
        m = EXTENT.match(line)
        if m:
            d["extents_total"] += 1
            if len(d["extents"]) < MAX_EXTENTS:
                d["extents"].append({"access": m.group(1), "sectors": int(m.group(2)), "type": m.group(3).upper(),
                                     "name": m.group(4), "offset": int(m.group(5)) if m.group(5) else None, "line": number})
            continue
        m = DESC_KV.match(line)
        if not m:
            d["other_lines"] += 1
            continue
        key, value = m.group(1), unquote(m.group(2))
        if key.lower().startswith("ddb."):
            if key in KNOWN_DDB:
                d["ddb"][key] = value
            else:
                d["ddb_other"] += 1
        elif key.lower() in ("version", "encoding", "cid", "parentcid", "createtype", "parentfilenamehint", "isnativesnapshot"):
            d["fields"].setdefault(key.lower(), value)
        else:
            d["other_lines"] += 1
    return d


def descriptor_node(d, source, shown, fid):
    f = d["fields"]
    cid, pcid = f.get("cid"), f.get("parentcid")
    node = {"format": "vmdk", "version": shown(f.get("version"), fid, "version"), "create_type": f.get("createtype") if f.get("createtype") in CREATE_TYPES else shown(f.get("createtype"), fid, "createType"), "encoding": shown(f.get("encoding"), fid, "encoding"),
            "cid": cid.lower() if cid and HEX8.match(cid) else None, "cid_raw": shown(cid, fid, "CID"),
            "parent_cid": pcid.lower() if pcid and HEX8.match(pcid) else None, "parent_cid_raw": shown(pcid, fid, "parentCID"),
            "has_parent": bool(pcid and HEX8.match(pcid) and pcid.lower() != "ffffffff"),
            "parent_hint": shown(f.get("parentfilenamehint"), fid, "parentFileNameHint"), "native_snapshot": shown(f.get("isnativesnapshot"), fid, "isNativeSnapshot"),
            "extents_total": d["extents_total"], "capacity_sectors_by_extents": sum(e["sectors"] for e in d["extents"]) if d["extents_total"] == len(d["extents"]) else None, "ddb": {k: shown(v, fid, k) for k, v in d["ddb"].items()}, "ddb_other_keys": d["ddb_other"], "descriptor_source": source}
    if cid and not HEX8.match(cid):
        node["problem"] = "CID is not 8 hexadecimal digits"
    if pcid and not HEX8.match(pcid):
        node["problem"] = "parentCID is not 8 hexadecimal digits"
    if node["has_parent"] and not node["parent_hint"]:
        node["problem"] = "a parentCID is recorded and no parentFileNameHint names the parent"
    return node


def parse_vmdk_text(fh, size, head):
    raw = head if size <= len(head) else head + read_at(fh, len(head), min(size, MAX_DESCRIPTOR) - len(head))
    over = size > MAX_DESCRIPTOR
    text = raw[:MAX_DESCRIPTOR].replace(b"\x00", b"\n").decode("utf-8", "replace")
    d = parse_descriptor(text)
    return d, over


def parse_vmdk_sparse(fh, size, head):
    if len(head) < 512:
        return {"state": "failed", "reason": "a sparse extent header is 512 bytes and the file is shorter"}
    (magic, version, flags, capacity, grain, doff, dsize, gtes, rgd, gd, overhead, unclean, c1, c2, c3, c4, comp) = struct.unpack("<4sIIQQQQIQQQBccccH", head[:79])
    info = {"format": "vmdk_sparse_extent", "sparse_version": version, "flags": "0x%08x" % flags, "capacity_sectors": capacity,
            "grain_size_sectors": grain, "descriptor_offset_sectors": doff, "descriptor_sectors": dsize, "overhead_sectors": overhead,
            "unclean_shutdown_flag": bool(unclean), "compress_algorithm": comp}
    markers = []
    if unclean:
        markers.append({"kind": "unclean_shutdown_flag", "observation": "the sparse extent header's uncleanShutdown byte is %d" % unclean,
                        "reading": "the extent was open for writing when the file was last written; a candidate for an interrupted write, a snapshot "
                                   "taken while running or a copy of a live file, not a verdict"})
    if flags & 1 and (c1, c2, c3, c4) != (b"\n", b" ", b"\r", b"\n"):
        markers.append({"kind": "newline_detection_mismatch", "observation": "the header's newline-detection bytes differ from the values the format fixes",
                        "reading": "the file may have been transferred in a mode that rewrites line ends; a candidate for an altered copy"})
    if version not in (1, 2, 3):
        return {"state": "unsupported", "reason": "sparse extent version %d is not one this tool reads" % version, "info": info, "markers": markers}
    desc = None
    if doff and dsize:
        want = min(dsize * 512, MAX_DESCRIPTOR)
        start = doff * 512
        if start >= size:
            return {"state": "failed", "reason": "the descriptor offset (%d sectors) is past the end of the file" % doff, "info": info, "markers": markers}
        data = read_at(fh, start, min(want, size - start))
        text = data.split(b"\x00", 1)[0].decode("utf-8", "replace")
        desc = parse_descriptor(text)
        info["descriptor_over_read_cap"] = dsize * 512 > MAX_DESCRIPTOR
    return {"state": "parsed", "info": info, "descriptor": desc, "markers": markers}


# ---- VHD -------------------------------------------------------------------------------------------------------------

VHD_FOOTER = struct.Struct(">8sIIQI4sI4sQQ4sII16sB")
VHD_TYPES = {2: "fixed", 3: "dynamic", 4: "differencing"}
VHD_EPOCH = 946684800  # 2000-01-01T00:00:00Z


def vhd_checksum_ok(raw, offset):
    zeroed = raw[:offset] + b"\x00\x00\x00\x00" + raw[offset + 4:]
    return (~sum(zeroed)) & 0xFFFFFFFF == struct.unpack(">I", raw[offset:offset + 4])[0]


def parse_vhd(fh, size, head):
    first = head[:512] if head[:8] == b"conectix" else None
    last = read_at(fh, size - 512, 512) if size >= 512 else b""
    footer = last if last[:8] == b"conectix" else first
    if footer is None or len(footer) < 512:
        return {"state": "failed", "reason": "no VHD footer (conectix) at the start or in the last 512 bytes"}
    (cookie, features, version, data_off, stamp, creator, creator_ver, host_os, original, current, geom, dtype, checksum, uid, saved) = VHD_FOOTER.unpack(footer[:85])
    info = {"format": "vhd", "disk_type": VHD_TYPES.get(dtype, "type %d (not read)" % dtype), "file_format_version": "0x%08x" % version,
            "footer_checksum_ok": vhd_checksum_ok(footer, 64), "unique_id": str(uuid.UUID(bytes=uid)).upper(),
            "created_utc": iso_utc(stamp, VHD_EPOCH), "created_raw": stamp, "created_epoch": "seconds since 2000-01-01T00:00:00Z",
            "original_size": original, "current_size": current, "saved_state": bool(saved),
            "creator_application": creator.decode("ascii", "replace"), "creator_version": "0x%08x" % creator_ver,
            "creator_host_os": host_os.decode("ascii", "replace"), "footer_location": "start" if footer is first and footer is not last else "end"}
    markers = []
    if saved:
        markers.append({"kind": "vhd_saved_state_flag", "observation": "the footer's Saved State byte is set",
                        "reading": "the disk was attached to a VM in a saved state when the footer was written; a candidate that the VM's saved state "
                                   "must be preserved with it"})
    if version >> 16 != 1:
        return {"state": "unsupported", "reason": "VHD file format version 0x%08x is not one this tool reads (major version 1 is)" % version, "info": info, "markers": markers}
    if dtype not in VHD_TYPES:
        return {"state": "unsupported", "reason": "disk type %d is not one this tool reads" % dtype, "info": info, "markers": markers}
    if dtype == 2:
        return {"state": "parsed", "info": info, "markers": markers, "vhd": {"identity": info["unique_id"], "hints": [], "parent_identity": None}}
    if head[:8] == b"conectix" and last[:8] == b"conectix" and head[:512] != last[:512]:
        markers.append({"kind": "vhd_footer_copy_differs", "observation": "the footer copy at the start differs from the footer at the end",
                        "reading": "the two copies were not written together; a candidate for an interrupted write or an edit, not a verdict"})
    if data_off == 0xFFFFFFFFFFFFFFFF or data_off + 1024 > size:
        return {"state": "failed", "reason": "the footer's data offset does not point at a dynamic-disk header inside the file", "info": info, "markers": markers}
    hdr = read_at(fh, data_off, 1024)
    if len(hdr) < 1024 or hdr[:8] != b"cxsparse":
        return {"state": "failed", "reason": "no dynamic-disk header (cxsparse) at the footer's data offset", "info": info, "markers": markers}
    (_c, _d, table_off, hver, max_entries, block, hsum, pid, pstamp, _r, pname_raw) = struct.unpack(">8sQQIIII16sII512s", hdr[:576])
    pname = pname_raw.decode("utf-16-be", "replace").split("\x00", 1)[0]
    info.update({"dynamic_header_checksum_ok": vhd_checksum_ok(hdr, 36), "block_size": block, "max_table_entries": max_entries, "header_version": "0x%08x" % hver})
    if hver >> 16 != 1:
        return {"state": "unsupported", "reason": "VHD dynamic header version 0x%08x is not one this tool reads" % hver, "info": info, "markers": markers}
    hints, locators = [], []
    if dtype == 4:
        info["parent_unique_id"] = str(uuid.UUID(bytes=pid)).upper()
        info["parent_timestamp_utc"] = iso_utc(pstamp, VHD_EPOCH)
        info["parent_timestamp_raw"] = pstamp
        info["parent_name"] = pname
        if pname:
            hints.append(pname)
        for i in range(8):
            code, space, length, _res, loff = struct.unpack(">4sIIIQ", hdr[576 + 24 * i:576 + 24 * (i + 1)])
            if code == b"\x00\x00\x00\x00" or not length:
                continue
            entry = {"platform_code": code.decode("ascii", "replace"), "data_length": length, "data_offset": loff}
            if length <= 65536 and loff + length <= size:
                data = read_at(fh, loff, length)
                text = data.decode("utf-8" if code == b"MacX" else "utf-16-le", "replace").split("\x00", 1)[0]
                if text:
                    entry["path_present"] = True
                    hints.append(text)
            else:
                entry["problem"] = "the locator data is outside the file or over 64 KiB"
            locators.append(entry)
        info["parent_locators"] = len(locators)
    return {"state": "parsed", "info": info, "markers": markers,
            "vhd": {"identity": info["unique_id"], "hints": hints, "parent_identity": info.get("parent_unique_id")}}


# ---- VHDX ------------------------------------------------------------------------------------------------------------

G_METADATA = "8B7CA206-4790-4B9A-B8FE-575F050F886E"
G_FILE_PARAMS = "CAA16737-FA36-4D43-B3B6-33F0AA44E76B"
G_DISK_ID = "BECA12AB-B2E6-4523-93EF-C309E000C746"
G_DISK_SIZE = "2FA54224-CD1B-4876-B211-5DBED83BF4B8"
G_PARENT_LOCATOR = "A8D35F2D-B30B-454D-ABF7-D3D84834AB0C"
G_LOCATOR_VHDX = "B04AEFB7-D19E-4A81-B789-25B8E9445913"
ZERO_GUID = "00000000-0000-0000-0000-000000000000"
GUID_TEXT = re.compile(r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}")


def vhdx_header(fh, offset, size):
    raw = read_at(fh, offset, 4096)
    if len(raw) < 4096 or raw[:4] != b"head":
        return None
    checksum = struct.unpack("<I", raw[4:8])[0]
    ok = crc32c(raw[:4] + b"\x00\x00\x00\x00" + raw[8:]) == checksum
    seq = struct.unpack("<Q", raw[8:16])[0]
    return {"offset": offset, "checksum_ok": ok, "sequence": seq, "file_write_guid": guid_text(raw[16:32]), "data_write_guid": guid_text(raw[32:48]),
            "log_guid": guid_text(raw[48:64]), "log_version": struct.unpack("<H", raw[64:66])[0], "version": struct.unpack("<H", raw[66:68])[0],
            "log_length": struct.unpack("<I", raw[68:72])[0], "log_offset": struct.unpack("<Q", raw[72:80])[0]}


def parse_vhdx(fh, size, head):
    markers = []
    headers = [h for h in (vhdx_header(fh, 65536, size), vhdx_header(fh, 131072, size)) if h]
    if not headers:
        return {"state": "failed", "reason": "no header with the head signature at 64 KiB or 128 KiB"}
    valid = [h for h in headers if h["checksum_ok"]]
    current = max(valid or headers, key=lambda h: h["sequence"])
    info = {"format": "vhdx", "headers_found": len(headers), "headers_checksum_ok": len(valid), "current_header_offset": current["offset"],
            "sequence_numbers": [h["sequence"] for h in headers], "file_write_guid": current["file_write_guid"], "data_write_guid": current["data_write_guid"],
            "log_guid": current["log_guid"], "log_length": current["log_length"], "version": current["version"]}
    if not valid:
        markers.append({"kind": "vhdx_headers_checksum_fail", "observation": "no header's CRC-32C matched",
                        "reading": "the headers are damaged or were edited; the current header was chosen by sequence number alone"})
    if current["version"] != 1:
        return {"state": "unsupported", "reason": "VHDX header version %d is not one this tool reads" % current["version"], "info": info, "markers": markers}
    if current["log_guid"] != ZERO_GUID:
        markers.append({"kind": "vhdx_log_guid_set", "observation": "the current header's LogGuid is not zero (log length %d)" % current["log_length"],
                        "reading": "a log is present; whether it holds entries that were not replayed is not read here, so this is a candidate for an "
                                   "interrupted write and also what a log in use looks like"})
    region = read_at(fh, 196608, 65536)
    if len(region) < 16 or region[:4] != b"regi":
        return {"state": "failed", "reason": "no region table (regi) at 192 KiB", "info": info, "markers": markers}
    count = struct.unpack("<I", region[8:12])[0]
    info["region_table_checksum_ok"] = crc32c(region[:4] + b"\x00\x00\x00\x00" + region[8:]) == struct.unpack("<I", region[4:8])[0] if len(region) == 65536 else None
    meta_off = meta_len = None
    for i in range(min(count, 2047)):
        e = region[16 + 32 * i:48 + 32 * i]
        if len(e) < 32:
            break
        if guid_text(e[:16]) == G_METADATA:
            meta_off, meta_len = struct.unpack("<QI", e[16:28])
    if meta_off is None or meta_off + 65536 > size:
        return {"state": "failed", "reason": "the region table names no metadata region inside the file", "info": info, "markers": markers}
    table = read_at(fh, meta_off, 65536)
    if table[:8] != b"metadata":
        return {"state": "failed", "reason": "no metadata table at the region the region table names", "info": info, "markers": markers}
    items = {}
    for i in range(min(struct.unpack("<H", table[10:12])[0], 2047)):
        e = table[32 + 32 * i:64 + 32 * i]
        if len(e) < 32:
            break
        items[guid_text(e[:16])] = struct.unpack("<II", e[16:24])
    vx = {"identity": None, "hints": [], "parent_identity": None, "parent_identity_2": None}
    if G_FILE_PARAMS in items:
        off, length = items[G_FILE_PARAMS]
        raw = read_at(fh, meta_off + off, 8) if length >= 8 else b""
        if len(raw) == 8:
            block, flags = struct.unpack("<II", raw)
            info["block_size"] = block
            info["has_parent"] = bool(flags & 2)
            info["leave_blocks_allocated"] = bool(flags & 1)
    if G_DISK_SIZE in items:
        off, length = items[G_DISK_SIZE]
        raw = read_at(fh, meta_off + off, 8) if length >= 8 else b""
        if len(raw) == 8:
            info["virtual_size"] = struct.unpack("<Q", raw)[0]
    if G_DISK_ID in items:
        off, length = items[G_DISK_ID]
        raw = read_at(fh, meta_off + off, 16) if length >= 16 else b""
        if len(raw) == 16:
            vx["identity"] = info["virtual_disk_id"] = guid_text(raw)
    if G_PARENT_LOCATOR in items:
        off, length = items[G_PARENT_LOCATOR]
        raw = read_at(fh, meta_off + off, min(length, 1 << 20))
        if len(raw) >= 20:
            ltype = guid_text(raw[:16])
            kv = struct.unpack("<H", raw[18:20])[0]
            info["parent_locator_type"] = ltype
            pairs = {}
            if ltype == G_LOCATOR_VHDX:
                for i in range(min(kv, 1024)):
                    e = raw[20 + 12 * i:32 + 12 * i]
                    if len(e) < 12:
                        break
                    ko, vo, kl, vl = struct.unpack("<IIHH", e)
                    if ko + kl <= len(raw) and vo + vl <= len(raw):
                        pairs[raw[ko:ko + kl].decode("utf-16-le", "replace")] = raw[vo:vo + vl].decode("utf-16-le", "replace")
                for key in ("relative_path", "absolute_win32_path", "volume_path"):
                    if pairs.get(key):
                        info["parent_" + key] = pairs[key]
                        if key != "volume_path":
                            vx["hints"].append(pairs[key])
                for key, slot in (("parent_linkage", "parent_identity"), ("parent_linkage2", "parent_identity_2")):
                    if pairs.get(key):
                        text = pairs[key].strip("{}").upper()
                        if GUID_TEXT.fullmatch(text):
                            vx[slot] = info[key] = text
                        else:
                            info[key + "_problem"] = "the value is not a GUID (%d characters): not compared" % len(pairs[key])
                info["parent_locator_keys"] = sorted(k for k in pairs if k in ("parent_linkage", "parent_linkage2", "relative_path", "volume_path", "absolute_win32_path"))
                info["parent_locator_other_keys"] = len(pairs) - len(info["parent_locator_keys"])
            else:
                info["parent_locator_note"] = "a locator of another type: not read"
    if info.get("has_parent") and not (vx["parent_identity"] or vx["hints"]):
        info["problem"] = "the file parameters say a parent exists and the parent locator names none"
    return {"state": "parsed", "info": info, "markers": markers, "vhdx": vx}


# ---- QCOW2 -----------------------------------------------------------------------------------------------------------

QCOW_EXT_NAMES = {0xE2792ACA: "backing_file_format", 0x6803F857: "feature_name_table", 0x0537BE77: "full_disk_encryption_header",
                  0x23852875: "bitmaps", 0x44415441: "external_data_file_name"}
QCOW_INCOMPAT = ((0, "dirty"), (1, "corrupt"), (2, "external_data_file"), (3, "compression_type"), (4, "extended_l2_entries"))


def parse_qcow2(fh, size, head, snapshot_sink, max_snapshots, clock):
    if len(head) < 72:
        return {"state": "failed", "reason": "a QCOW2 header is at least 72 bytes and the file is shorter"}
    (magic, version, boff, bsize, cbits, vsize, crypt, l1size, l1off, rcoff, rcclusters, nsnap, soff) = struct.unpack(">4sIQIIQIIQQIIQ", head[:72])
    info = {"format": "qcow2", "version": version, "virtual_size": vsize, "cluster_bits": cbits, "encryption_method_field": crypt,
            "backing_file_offset": boff, "snapshots_declared": nsnap}
    markers = []
    if version not in (2, 3):
        return {"state": "unsupported", "reason": "QCOW version %d is not one this tool reads" % version, "info": info, "markers": markers}
    if not 9 <= cbits <= 21:
        return {"state": "failed", "reason": "cluster_bits %d is outside 9 to 21" % cbits, "info": info, "markers": markers}
    header_len = 72
    if version == 3:
        if len(head) < 104:
            return {"state": "failed", "reason": "a version 3 header is at least 104 bytes and the file is shorter", "info": info, "markers": markers}
        incompat, compat, autoclear, rorder, header_len = struct.unpack(">QQQII", head[72:104])
        info.update({"incompatible_features": "0x%x" % incompat, "compatible_features": "0x%x" % compat, "autoclear_features": "0x%x" % autoclear,
                     "refcount_order": rorder, "header_length": header_len})
        flags = [name for bit, name in QCOW_INCOMPAT if incompat & (1 << bit)]
        info["incompatible_feature_names"] = flags
        if incompat >> 5:
            info["incompatible_unknown_bits"] = "0x%x" % (incompat >> 5 << 5)
        if incompat & 1:
            markers.append({"kind": "qcow2_dirty_bit", "observation": "incompatible feature bit 0 (dirty) is set",
                            "reading": "the image's reference counts may be stale because it was not closed cleanly; a candidate for an interrupted "
                                       "write or a copy of a live image, not a verdict"})
        if incompat & 2:
            markers.append({"kind": "qcow2_corrupt_bit", "observation": "incompatible feature bit 1 (corrupt) is set",
                            "reading": "the image was marked corrupt by the program that last wrote it"})
    # header extensions
    exts, backing_format, ext_data = [], None, None
    ext_start = header_len if version == 3 else 72
    cluster = 1 << cbits
    window = read_at(fh, ext_start, min(max(0, cluster - ext_start), 1 << 20)) if ext_start < size else b""
    pos, n = 0, 0
    while pos + 8 <= len(window) and n < 64:
        etype, elen = struct.unpack(">II", window[pos:pos + 8])
        if etype == 0:
            break
        data = window[pos + 8:pos + 8 + elen]
        name = QCOW_EXT_NAMES.get(etype, "0x%08x" % etype)
        exts.append(name)
        if etype == 0xE2792ACA:
            backing_format = data.decode("utf-8", "replace")
        elif etype == 0x44415441:
            ext_data = data.decode("utf-8", "surrogateescape")
        pos += 8 + ((elen + 7) & ~7)
        n += 1
    info["header_extensions"] = exts
    if backing_format is not None:
        info["backing_format"] = backing_format
    if ext_data is not None:
        info["external_data_file"] = ext_data
    hints = []
    if boff:
        if bsize > 1023:
            info["problem"] = "the backing file name is declared %d bytes; the format allows 1023" % bsize
        raw = read_at(fh, boff, min(bsize, 4096)) if boff < size else b""
        if len(raw) < min(bsize, 4096):
            info["problem"] = "the backing file name lies outside the file"
        else:
            name = decode(raw)
            info["backing_file"] = name
            hints.append(name)
    # internal snapshots, streamed
    snaps = {"declared": nsnap, "read": 0, "stopped": None}
    if nsnap:
        pos = soff
        if soff == 0 or soff >= size:
            snaps["stopped"] = "the snapshot table offset is %s" % ("0" if soff == 0 else "outside the file")
        else:
            for index in range(min(nsnap, max_snapshots)):
                clock.check(1024)
                raw = read_at(fh, pos, 40)
                if len(raw) < 40:
                    snaps["stopped"] = "the file ends inside entry %d" % index
                    break
                (l1o, l1s, idsz, namesz, dsec, dnsec, vmclock, vmstate, extra) = struct.unpack(">QIHHIIQII", raw)
                if idsz == 0:
                    snaps["stopped"] = "entry %d has an empty id string: the table ends or is damaged here" % index
                    break
                if extra > 65536 or pos + 40 + extra + idsz + namesz > size:
                    snaps["stopped"] = "entry %d declares sizes that run past the file or over 64 KiB of extra data" % index
                    break
                body = read_at(fh, pos + 40, extra + idsz + namesz)
                sid = decode(body[extra:extra + idsz])
                sname = decode(body[extra + idsz:extra + idsz + namesz])
                snapshot_sink({"index": index, "id": sid, "name": sname, "date_utc": iso_utc(dsec), "date_raw": dsec, "date_nsec": dnsec,
                               "vm_clock_ns": vmclock, "vm_state_size": vmstate, "l1_size": l1s, "l1_table_offset": l1o})
                snaps["read"] += 1
                pos += (40 + extra + idsz + namesz + 7) & ~7
            if snaps["read"] < nsnap and not snaps["stopped"]:
                snaps["stopped"] = "max_snapshots (%d) was reached" % max_snapshots
    info["internal_snapshots"] = snaps
    return {"state": "parsed", "info": info, "markers": markers, "qcow2": {"hints": hints, "backing_format": backing_format}}


# ---- VMX and VMSD ----------------------------------------------------------------------------------------------------

CONFIG_KV = re.compile(r'^\s*([A-Za-z0-9_.:\-]+)\s*=\s*"(.*)"\s*$')
DISK_KEY = re.compile(r"^(scsi|ide|sata|nvme)\d+:\d+\.filename$", re.I)
SNAP_KEY = re.compile(r"^snapshot(\d+)\.(.+)$", re.I)


def read_config(fh, size):
    """Yield (line number, key, value) of the key = "value" lines of a .vmx or .vmsd, a line at a time."""
    n = 0
    while True:
        raw = fh.readline(MAX_CONFIG_LINE + 1)
        if not raw:
            return
        n += 1
        if n > MAX_CONFIG_LINES:
            yield n, None, "line cap"
            return
        if len(raw) > MAX_CONFIG_LINE:
            while raw and not raw.endswith(b"\n"):
                raw = fh.readline(MAX_CONFIG_LINE)
            yield n, None, "over-long line"
            continue
        m = CONFIG_KV.match(raw.decode("utf-8", "surrogateescape").rstrip("\r\n"))
        if m:
            yield n, m.group(1), m.group(2)


def parse_vmx(fh, size):
    disks, problems, keys = [], [], 0
    for n, key, value in read_config(fh, size):
        if key is None:
            problems.append(value)
            continue
        keys += 1
        if DISK_KEY.match(key):
            disks.append({"key": key, "file": value, "line": n})
    return {"state": "parsed", "info": {"format": "vmx", "keys_read": keys, "disk_entries": len(disks), "note": WITHHELD_CONFIG_NOTE},
            "vmx": {"disks": disks, "problems": problems}}


def parse_vmsd(fh, size):
    entries = collections.OrderedDict()
    top, over, problems = {}, 0, []
    for n, key, value in read_config(fh, size):
        if key is None:
            problems.append(value)
            continue
        low = key.lower()
        if low in ("snapshot.numsnapshots", "snapshot.current", "snapshot.lastuid"):
            top[low.split(".", 1)[1]] = value
            continue
        m = SNAP_KEY.match(key)
        if not m:
            continue
        idx = int(m.group(1))
        if idx not in entries:
            if len(entries) >= MAX_SNAPSHOT_ENTRIES:
                over += 1
                continue
            entries[idx] = {"index": idx, "line": n, "disks": {}}
        sub, e = m.group(2), entries[idx]
        sl = sub.lower()
        dm = re.match(r"^disk(\d+)\.(.+)$", sl)
        if dm:
            if dm.group(2) == "filename":
                e["disks"][int(dm.group(1))] = value
        elif sl in ("uid", "filename", "displayname", "parent", "numdisks", "createtimehigh", "createtimelow", "type", "description", "id"):
            e[sl] = value
    return {"state": "parsed", "info": {"format": "vmsd", "snapshots_listed": len(entries), "snapshot_entries_over_cap": over,
                                          "numsnapshots": top.get("numsnapshots"), "current": top.get("current"), "lastuid": top.get("lastuid")},
            "vmsd": {"entries": list(entries.values()), "over": over, "top": top, "problems": problems}}


# ---- classification --------------------------------------------------------------------------------------------------

def classify(rec, fh, size):
    head = fh.read(min(size, 65536))
    name = rec["rel"].lower()
    if head[:4] == b"KDMV":
        return "vmdk_sparse", head
    if head[:4] == b"COWD":
        return "vmdk_cowd", head
    if head[:4] == b"QFI\xfb":
        return "qcow2", head
    if head[:8] == b"vhdxfile":
        return "vhdx", head
    if head[:8] == b"conectix":
        return "vhd", head
    if size >= 512:
        fh.seek(size - 512)
        if fh.read(8) == b"conectix":
            return "vhd", head
    text = head[3:] if head[:3] == b"\xef\xbb\xbf" else head
    if text.lstrip()[:24].startswith(b"# Disk DescriptorFile"):
        return "vmdk_descriptor", head
    if name.endswith(".vmsd"):
        return "vmsd", head
    if name.endswith(".vmx"):
        return "vmx", head
    if name.endswith(".lck") or posixpath.basename(name).startswith(".lck-"):
        return "lock_file", head
    return "other", head


def ext_of(rel):
    base = posixpath.basename(rel)
    return posixpath.splitext(base)[1].lower() or "(none)"


# ---- the run ---------------------------------------------------------------------------------------------------------

def qemu_format(kind):
    return {"vmdk": "vmdk", "vhd": "vpc", "vhdx": "vhdx", "qcow2": "qcow2"}.get(kind)


def run_qemu(path, kind, seconds):
    fmt = qemu_format(kind)
    argv = ["qemu-img", "info", "--output=json", "-f", fmt, path]
    code, out, err, timed_out = preflight(argv, seconds)
    result = {"command_format": fmt, "exit_code": code, "timed_out": timed_out}
    if code is None and not timed_out:
        result["available"] = False
        result["error"] = scrub(err.decode("utf-8", "replace")[:300])
        return result
    result["available"] = True
    if timed_out or code != 0:
        result["error"] = scrub(err.decode("utf-8", "replace")[:400])
        return result
    try:
        data = json.loads(out[:1 << 20].decode("utf-8", "replace"))
        result.update({"format": data.get("format"), "virtual_size": data.get("virtual-size"), "actual_size": data.get("actual-size"),
                       "backing_filename": scrub(str(data["backing-filename"])) if data.get("backing-filename") else None,
                       "backing_filename_format": data.get("backing-filename-format"), "dirty_flag": data.get("dirty-flag")})
    except (ValueError, AttributeError):
        result["error"] = "qemu-img printed output that is not JSON"
    return result


def main():
    install_signal_handlers()
    args = read_args()
    root = want_str(args, "root")
    paths = want_str_list(args, "paths", 100000)
    if root is None and not paths:
        fail("name the evidence: root is a directory of descriptors and images, paths is a list of files")
    limit = want_int(args, "limit", DEFAULT_LIMIT, 1, 100000)
    max_files = want_int(args, "max_files", 20000, 1, 200000)
    max_entries = want_int(args, "max_entries", 200000, 1, 2000000)
    max_depth = want_int(args, "max_depth", 16, 1, 64)
    max_snapshots = want_int(args, "max_snapshots", DEFAULT_MAX_SNAPSHOTS, 1, 1000000)
    max_chain = want_int(args, "max_chain_depth", 10000, 1, 1000000)
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    qemu_mode = args.get("qemu_img", "off")
    if qemu_mode not in ("off", "auto", "require"):
        fail("qemu_img must be off, auto or require")
    qemu_max = want_int(args, "qemu_img_max_images", 50, 1, 1000)
    write_text = want_flag(args, "write_text")
    try:
        values = TextFile("chain-values.jsonl", write_text, "JSON Lines, mode 0600: record_type original, where (a source id and the field), field, value (the "
                          "original text of a name, hint or snapshot name the answer shows withheld or shortened)")
    except TextRefused as exc:
        fail(str(exc))
    shown = Shower(values)
    clock = Clock(seconds)
    files = FileSet(shown)
    partial = []
    try:
        files.walk(root, paths, max_files, max_entries, max_depth, clock)
    except Overtime:
        partial.append("the walk stopped at max_seconds (%s): the files after the last one listed were not reached" % seconds)
    if files.truncated:
        partial.append(files.truncated)
    index = Index(files.files)

    pages = {k: LosslessPage(TOOL, k, limit) for k in ("sources", "disks", "edges", "chains", "extents", "snapshot_database", "internal_snapshots", "markers")}
    nodes, vmx_list, vmsd_list = {}, [], []
    kinds = collections.Counter()
    other_ext = collections.Counter()
    state_counts = collections.Counter()
    problems = []                      # files recognised and not read
    config_total = {"disks": 0, "snapshots": 0, "dropped": 0}

    def marker(kind, ids, observation, reading, corroborate=None, **extra):
        pages["markers"].add({"kind": kind, "source_ids": ids, "observation": observation, "reading": reading,
                              "corroborate": corroborate or "the VM's own records of the operation (task or event log), the file times and a second copy", **extra})

    def snapshot_sink_for(fid):
        def sink(row):
            row = dict(row)
            row["source_id"] = fid
            row["id"] = shown(row["id"], fid, "snapshot id")
            row["name"] = shown(row["name"], fid, "snapshot name")
            pages["internal_snapshots"].add(row)
        return sink

    disks, extent_targets = {}, {}

    def build_disk(fid, res):
        rec = res["rec"]
        kind = res["row"]["kind"]
        d = {"id": fid, "file": res["row"]["file"], "rel": rec["rel"], "state": res["state"], "has_identity": False, "own_id": None, "parent_id": None, "hints": []}
        if kind == "vmdk_cowd":
            d["role"] = "extent_only"
            disks[fid] = d
            return
        if kind in ("vmdk_descriptor", "vmdk_sparse"):
            desc = res.pop("descriptor", None)
            if kind == "vmdk_sparse" and desc is None:
                d["role"] = "extent_only"
                disks[fid] = d
                return
            if desc is None:
                disks[fid] = d
                return
            node = descriptor_node(desc, "embedded in a sparse extent" if kind == "vmdk_sparse" else "text descriptor", shown, fid)
            if kind == "vmdk_sparse":
                node["sparse_header"] = res["row"]["info"]
            d.update(format="vmdk", has_identity=node["cid"] is not None, own_id=node["cid"], parent_id=node["parent_cid"] if node["has_parent"] else None,
                     hints=[desc["fields"]["parentfilenamehint"]] if desc["fields"].get("parentfilenamehint") else [], has_parent=node["has_parent"], detail=node)
            if node.get("problem"):
                marker("descriptor_problem", [fid], node["problem"], "the descriptor is inconsistent as written; the chain through it is not read further than it says")
            for i, ext in enumerate(desc["extents"]):
                target, how = (None, "no_name")
                if ext["name"] is not None and ext["type"] not in ("ZERO", "VMFSRDM", "VMFSRAW", "VMFSPASSTHRU"):
                    target, how = index.resolve(rec["rel"], ext["name"].replace('\\"', '"'))
                erow = {"descriptor_id": fid, "index": i, "line": ext["line"], "access": ext["access"], "sectors": ext["sectors"], "type": shown(ext["type"], fid, "extent type"),
                        "file": shown(ext["name"], fid, "extent file name") if ext["name"] is not None else None, "offset_sectors": ext["offset"],
                        "found": target["id"] if target else None, "resolution": how}
                if ext["name"] is None or ext["type"] in ("ZERO", "VMFSRDM", "VMFSRAW", "VMFSPASSTHRU"):
                    erow["state"] = "not_a_file_extent"
                elif target is None:
                    erow["state"] = "missing"
                    marker("extent_missing", [fid], "extent %d of the descriptor names a file that is not in the set (%s)" % (i, how),
                           "the disk cannot be read whole from this set; whether the file existed is not shown", line=ext["line"])
                else:
                    if target["id"] != fid:                # a monolithic sparse disk names its own file as its extent
                        extent_targets[target["id"]] = fid
                    if ext["type"] in ("FLAT", "VMFS"):
                        expected = (ext["sectors"] + (ext["offset"] or 0)) * 512
                        erow["expected_size_at_least"] = expected
                        erow["actual_size"] = target["size"]
                        erow["state"] = "short" if target["size"] < expected else "present"
                        if erow["state"] == "short":
                            marker("extent_short", [fid, target["id"]], "extent %d is %d bytes and the descriptor needs at least %d" % (i, target["size"], expected),
                                   "the extent file is smaller than the descriptor says: truncated, partly copied or rewritten", line=ext["line"])
                    else:
                        erow["state"] = "present"
                        erow["size_check"] = "not made: a sparse extent has no size to compare"
                pages["extents"].add(erow)
        elif kind == "vhd":
            v = res.get("vhd")
            if v:
                d.update(format="vhd", has_identity=True, own_id=v["identity"], parent_id=v["parent_identity"], hints=v["hints"], has_parent=res["row"]["info"].get("disk_type") == "differencing", detail=res["row"]["info"])
        elif kind == "vhdx":
            v = res.get("vhdx")
            if v:
                d.update(format="vhdx", has_identity=bool(v["identity"]), own_id=v["identity"], parent_id=v["parent_identity"], parent_id_2=v.get("parent_identity_2"),
                         hints=v["hints"], has_parent=bool(res["row"]["info"].get("has_parent")), detail=res["row"]["info"])
        elif kind == "qcow2":
            v = res.get("qcow2")
            if v:
                d.update(format="qcow2", has_identity=False, hints=v["hints"], has_parent=bool(v["hints"]), detail=res["row"]["info"], backing_format=v.get("backing_format"))
        disks[fid] = d

    examined = 0
    try:
        for rec in files.files:
            clock.check()
            fh, why = open_regular(rec["path"])
            if fh is None:
                files.note("unreadable", rec["rel"] + ": " + (why or ""))
                continue
            with fh:
                kind, head = classify(rec, fh, rec["size"])
                kinds[kind] += 1
                if kind == "other":
                    ext = ext_of(rec["rel"])[:32]
                    other_ext[ext if (ext in other_ext or len(other_ext) < 2000) else "(other extensions)"] += 1
                    continue
                examined += 1
                row = {"source_id": rec["id"], "file": shown(rec["rel"], rec["id"], "file"), "size": rec["size"], "kind": kind}
                try:
                    if kind == "vmdk_sparse":
                        res = parse_vmdk_sparse(fh, rec["size"], head)
                    elif kind == "vmdk_descriptor":
                        d, over = parse_vmdk_text(fh, rec["size"], head)
                        res = {"state": "parsed", "info": {"format": "vmdk"}, "descriptor": d}
                        if over:
                            res["state"] = "partial"
                            res["reason"] = "the descriptor file is over %d bytes: read to that point" % MAX_DESCRIPTOR
                    elif kind == "vmdk_cowd":
                        res = {"state": "parsed", "info": {"format": "vmdk_cowd_extent", "header_read": False,
                                                          "note": "a COWD sparse extent (the delta of a VMFS sparse snapshot) is recognised by its first four bytes; its header is not read, because the chain is in the descriptor that names it"}}
                    elif kind == "vhd":
                        res = parse_vhd(fh, rec["size"], head)
                    elif kind == "vhdx":
                        res = parse_vhdx(fh, rec["size"], head)
                    elif kind == "qcow2":
                        res = parse_qcow2(fh, rec["size"], head, snapshot_sink_for(rec["id"]), max_snapshots, clock)
                    elif kind in ("vmx", "vmsd"):
                        if rec["size"] > MAX_CONFIG_BYTES:
                            res = {"state": "failed", "reason": "a configuration file over %d bytes is named and not read" % MAX_CONFIG_BYTES, "info": {"format": kind}}
                        else:
                            fh.seek(0)
                            res = parse_vmx(fh, rec["size"]) if kind == "vmx" else parse_vmsd(fh, rec["size"])
                    elif kind == "lock_file":
                        res = {"state": "parsed", "info": {"format": "lock_file"},
                               "markers": [{"kind": "lock_artefact", "observation": "a file named like a lock file is present",
                                            "reading": "a lock is made while a program holds the disk or the VM; it can be a copy of a live VM's directory or a left-over after a crash: a candidate"}]}
                    else:
                        res = {"state": "unsupported", "reason": "unknown kind"}
                except (struct.error, ValueError, OverflowError, MemoryError) as exc:
                    res = {"state": "failed", "reason": "the structure could not be read (%s)" % describe(exc)}
                except OSError as exc:
                    res = {"state": "failed", "reason": "a read failed (%s)" % describe(exc)}
            state_counts[res["state"]] += 1
            row["state"] = res["state"]
            if res.get("reason"):
                row["reason"] = res["reason"]
            if res["state"] in ("failed", "unsupported", "partial"):
                problems.append(rec["id"])
            net = make_net(shown, rec["id"])
            row["info"] = net(res.get("info") or {})
            for m in res.get("markers") or []:
                marker(m["kind"], [rec["id"]], m["observation"], m["reading"])
            res["row"] = row
            res["rec"] = rec
            pages["sources"].add(row)
            if kind == "vmx":
                config_total["disks"] += len(res.get("vmx", {}).get("disks", ()))
                if config_total["disks"] > MAX_CONFIG_ENTRIES_TOTAL:
                    res["vmx"]["disks"] = []
                    config_total["dropped"] += 1
                vmx_list.append(res)
            elif kind == "vmsd":
                config_total["snapshots"] += len(res.get("vmsd", {}).get("entries", ()))
                if config_total["snapshots"] > MAX_CONFIG_ENTRIES_TOTAL:
                    res["vmsd"]["entries"] = []
                    config_total["dropped"] += 1
                vmsd_list.append(res)
            elif kind in ("vmdk_descriptor", "vmdk_sparse", "vmdk_cowd", "vhd", "vhdx", "qcow2"):
                res["rec"], res["row"] = rec, row
                build_disk(rec["id"], res)
                nodes[rec["id"]] = {"rec": rec, "row": {"kind": kind}}
    except Overtime:
        partial.append("the examination stopped at max_seconds (%s): the files after %s were not read" % (seconds, "the last one listed in sources"))

    # ---- edges ---------------------------------------------------------------------------------------------------
    parent_of, edge_of = {}, {}
    for fid, d in disks.items():
        if d.get("role") == "extent_only" or not d.get("format"):
            continue
        if not d.get("has_parent") and not d["hints"]:
            continue
        target, how = None, "no_name"
        for h in d["hints"]:
            target, how = index.resolve(d["rel"], h)
            if target:
                break
        edge = {"child": fid, "parent_name": shown(d["hints"][0], fid, "parent name") if d["hints"] else None, "names_tried": len(d["hints"]),
                "resolved_to": target["id"] if target else None, "resolution": how, "id_check": "not_available", "format": d["format"]}
        pdisk = disks.get(target["id"]) if target else None
        if target and pdisk is None:
            edge["parent_state"] = "the file is in the set and is not a disk this tool reads"
            edge["id_check"] = "not_available"
        elif pdisk:
            edge["parent_state"] = pdisk["state"]
            if d["format"] in ("vmdk", "vhd", "vhdx"):
                want, have = d.get("parent_id"), pdisk.get("own_id")
                if pdisk.get("format") and pdisk["format"] != d["format"]:
                    edge["id_check"] = "not_available"
                    edge["format_note"] = "the parent is a %s file and the child a %s file" % (pdisk["format"], d["format"])
                elif want and have:
                    if want.upper() == have.upper():
                        edge["id_check"] = "match"
                    elif d["format"] == "vhdx" and d.get("parent_id_2") and d["parent_id_2"].upper() == have.upper():
                        edge["id_check"] = "match_via_parent_linkage2"
                    else:
                        edge["id_check"] = "mismatch"
                        edge["recorded_by_child"] = want
                        edge["carried_by_parent"] = have
                        marker({"vmdk": "parent_cid_mismatch", "vhd": "parent_unique_id_mismatch", "vhdx": "parent_linkage_mismatch"}[d["format"]], [fid, target["id"]],
                               "the child records parent identity %s and the parent file carries %s" % (want, have),
                               "the named parent is not the file the child was made against, or the parent was written after the child was made; the "
                               "chain through this edge cannot be trusted as one history")
            elif d["format"] == "qcow2":
                edge["id_check"] = "not_available"
                edge["id_note"] = "QCOW2 records no identity of its backing file: the name is all the link there is"
                bf = d.get("backing_format")
                if bf and pdisk.get("format") and bf.lower() != pdisk["format"].lower():
                    edge["format_note"] = "the child says the backing file is %s and the file found is %s" % (shown(bf, fid, "backing format"), pdisk["format"])
            if pdisk.get("role") == "extent_only":
                edge["parent_state"] = "a sparse extent without a descriptor of its own"
            parent_of[fid] = target["id"]
        if not target and how == "ambiguous_basename":
            marker("parent_ambiguous", [fid], "the parent's name matches more than one file in the set by file name alone", "which file is the parent is not decided by the set")
        elif not target:
            marker("parent_missing", [fid], "the parent named by the child (%s) is not in the set" % how, "the chain is broken in this set: whether the parent existed, was deleted, "
                                                                                                    "or was not collected is not shown")
        edge_of[fid] = edge
        pages["edges"].add(edge)

    for fid, d in disks.items():
        if d.get("role") == "extent_only" and fid not in extent_targets:
            marker("extent_without_descriptor", [fid], "a sparse extent file is present and no descriptor in the set names it as an extent",
                   "its descriptor was not collected, was removed, or the extent belongs to a disk outside this set: a candidate; the descriptor, if found, holds the chain")

    # ---- chains: each disk's depth and base, found without recursion ----------------------------------------------
    depth, base, state_of = {}, {}, {}
    for start in disks:
        if start in depth:
            continue
        path_nodes, seen_here, cur = [], set(), start
        outcome = None
        while True:
            if cur in depth:
                outcome = ("known", cur)
                break
            if cur in seen_here:
                outcome = ("cycle", cur)
                break
            if len(path_nodes) >= max_chain:
                outcome = ("too_deep", cur)
                break
            seen_here.add(cur)
            path_nodes.append(cur)
            nxt = parent_of.get(cur)
            if nxt is None:
                outcome = ("end", cur)
                break
            cur = nxt
        kind_, at = outcome
        if kind_ == "known":
            b, dp, st = base[at], depth[at], state_of[at]
            for n in reversed(path_nodes):
                dp += 1
                depth[n], base[n] = dp, b
                state_of[n] = st or ("chain deeper than max_chain_depth" if dp > max_chain else None)
        else:
            st = {"end": None, "cycle": "cycle", "too_deep": "chain deeper than max_chain_depth"}[kind_]
            for k, n in enumerate(reversed(path_nodes)):
                depth[n] = k + 1
                base[n] = path_nodes[-1] if kind_ == "end" else at
                state_of[n] = st
            if kind_ == "cycle":
                marker("chain_cycle", [at], "following parent names from %s returns to %s" % (at, at), "the set contains files that name each other as parents; no history has a cycle, so at least one name or file is wrong")
    named_as_parent = set(parent_of.values())
    leaves = [f for f in disks if f not in named_as_parent and disks[f].get("role") != "extent_only" and disks[f].get("format") and f not in extent_targets]
    chain_summary = collections.Counter()
    for leaf in leaves:
        ids, cur, seen = [], leaf, set()
        while cur and cur not in seen and len(ids) < MAX_CHAIN_SHOWN:
            ids.append(cur)
            seen.add(cur)
            cur = parent_of.get(cur)
        # one pass along the whole chain (iterative, bounded): a parent that is not in the set, an identity that does not match
        detail, walk, steps, mismatch = None, leaf, 0, None
        while walk is not None and steps < max_chain:
            steps += 1
            dd = disks[walk]
            if (dd.get("has_parent") or dd["hints"]) and walk not in parent_of:
                detail = "the parent of %s is not in the set (%s)" % (walk, edge_of[walk]["resolution"] if walk in edge_of else "no_name")
                break
            if walk in edge_of and edge_of[walk]["id_check"] == "mismatch" and mismatch is None:
                mismatch = walk
            walk = parent_of.get(walk)
        status = "complete"
        if state_of.get(leaf) == "cycle":
            status = "cycle"
        elif state_of.get(leaf):
            status = "too_deep"
        elif detail:
            status = "broken"
        elif mismatch:
            status, detail = "identity_mismatch", "the identity %s records for its parent is not the identity the parent file carries" % mismatch
        chain_summary[status] += 1
        pages["chains"].add({"leaf": leaf, "leaf_file": disks[leaf]["file"], "format": disks[leaf].get("format"), "chain_length": depth.get(leaf, 1),
                             "base": base.get(leaf, leaf), "chain_shown": ids, "chain_shown_cut": depth.get(leaf, 1) > len(ids), "status": status, "detail": detail})

    # ---- the configuration files held against the descriptors ---------------------------------------------------------
    descriptor_files = {fid for fid, d in disks.items() if d.get("format") == "vmdk"}
    snap_disk_names = {}
    for res in vmsd_list:
        rec = res["rec"]
        data = res["vmsd"]
        for e in data["entries"]:
            names = [shown(n, rec["id"], "snapshot disk file") for n in e["disks"].values()]
            pages["snapshot_database"].add({"source_id": rec["id"], "index": e["index"], "line": e["line"], "uid": shown(e.get("uid"), rec["id"], "snapshot uid"), "parent": shown(e.get("parent"), rec["id"], "snapshot parent"),
                                            "display_name": shown(e.get("displayname"), rec["id"], "snapshot name") if e.get("displayname") is not None else None,
                                            "description_present": "description" in e, "state_file": shown(e.get("filename"), rec["id"], "snapshot state file") if e.get("filename") is not None else None,
                                            "disk_files": names, "create_time_high_raw": shown(e.get("createtimehigh"), rec["id"], "createTimeHigh"), "create_time_low_raw": shown(e.get("createtimelow"), rec["id"], "createTimeLow"),
                                            "create_time_note": "raw values as written; how the two fields encode a time is not decoded here"})
            for n in e["disks"].values():
                target, how = index.resolve(rec["rel"], n)
                snap_disk_names.setdefault(rec["id"], set()).add(target["id"] if target else None)
                if target is None:
                    marker("snapshot_disk_missing", [rec["id"]], "snapshot %s of the database names a disk file that is not in the set (%s)" % (e["index"], how),
                           "the snapshot's disk is missing from this set: removed, never collected or renamed; the database entry alone does not say which", line=e["line"])
        if data["over"]:
            partial.append("a snapshot database lists more than %d snapshot indexes: the first %d are listed, %d more entries were counted and not listed" % (MAX_SNAPSHOT_ENTRIES, MAX_SNAPSHOT_ENTRIES, data["over"]))
    for res in vmx_list:
        rec = res["rec"]
        for dk in res["vmx"]["disks"]:
            target, how = index.resolve(rec["rel"], dk["file"])
            d = disks.get(target["id"]) if target else None
            if d and d.get("has_parent"):
                same_dir_vmsd = [v for v in vmsd_list if posixpath.dirname(v["rec"]["rel"]) == posixpath.dirname(rec["rel"])]
                for v in same_dir_vmsd:
                    n = len(v["vmsd"]["entries"])
                    declared = v["vmsd"]["top"].get("numsnapshots")
                    if n == 0 or declared in ("0", 0):
                        marker("running_disk_is_a_delta_without_snapshots", [rec["id"], target["id"], v["rec"]["id"]],
                               "the configuration's disk %s is a delta (it records a parent) and the snapshot database lists %s snapshot(s)" % (dk["key"], declared if declared is not None else n),
                               "a consolidation that did not finish, a snapshot removed without its delta merged, or a database that was not collected with the disk: a "
                               "candidate; the VM's task log decides it", line=dk["line"])
    if vmsd_list:
        referenced = set()
        for ids in snap_disk_names.values():
            referenced.update(i for i in ids if i)
        for res in vmx_list:
            for dk in res["vmx"]["disks"]:
                target, _how = index.resolve(res["rec"]["rel"], dk["file"])
                if target:
                    referenced.add(target["id"])
        reachable, stack = set(), list(referenced)
        while stack and len(reachable) < len(disks) + 1:          # the ancestors of every disk the configuration names are in use
            cur = stack.pop()
            if cur in reachable:
                continue
            reachable.add(cur)
            if cur in parent_of:
                stack.append(parent_of[cur])
        listing = [v["rec"]["id"] for v in vmsd_list]
        for fid, d in disks.items():
            if d.get("format") == "vmdk" and d.get("has_parent") and fid not in reachable and fid not in extent_targets:
                marker("delta_not_in_snapshot_database", [fid] + listing,
                       "this descriptor records a parent, and it is neither named by the snapshot database or the configuration nor a parent of a disk they name",
                       "a delta left behind by a removed snapshot or a consolidation, or a file of another VM in the set: a candidate; the task log decides it")
    for rel in files.lock_dirs:
        marker("lock_artefact", [], "an entry named %s is present" % shown(rel, "walk", "lock directory"),
               "a lock directory or file is made while a program holds the disk or the VM; it can be a copy of a live VM's directory or a left-over after a crash: a candidate")
    # ---- qemu-img, when asked ------------------------------------------------------------------------------------------
    qemu_report = {"mode": qemu_mode, "checked": 0, "available": None, "note": "qemu-img was not run (qemu_img: off); the reading above is the tool's own"}
    if qemu_mode != "off":
        qemu_report["note"] = ("qemu-img info was run once per image with the format fixed and without --backing-chain; its answer sits beside the "
                               "native reading in `qemu_img` of the disk row and replaces nothing")
        cross = []
        count = 0
        for fid, d in disks.items():
            if count >= qemu_max or clock.left() < 2:
                break
            fmt_kind = {"vmdk": "vmdk", "vhd": "vhd", "vhdx": "vhdx", "qcow2": "qcow2"}.get(d.get("format"))
            if not fmt_kind or d.get("role") == "extent_only" or d["state"] != "parsed":
                continue
            rec = nodes[fid]["rec"]
            if d["format"] == "vmdk" and nodes[fid]["row"]["kind"] != "vmdk_sparse":
                # a text descriptor is a VMware descriptor: qemu-img reads it with its extents, which are opened by name; leave it to a copy made for that
                pass
            result = run_qemu(rec["path"], fmt_kind, min(30.0, max(1.0, clock.left() - 1)))
            count += 1
            qemu_report["available"] = result.get("available")
            if result.get("available") is False:
                break
            d["qemu_img"] = result
            native = d.get("detail") or {}
            if d["format"] == "vmdk":
                cap = (native.get("sparse_header") or {}).get("capacity_sectors")
                native_size = (cap if cap is not None else native.get("capacity_sectors_by_extents"))
                native_size = native_size * 512 if native_size is not None else None
            else:
                native_size = native.get("virtual_size") if d["format"] in ("qcow2", "vhdx") else native.get("current_size") if d["format"] == "vhd" else None
            if result.get("virtual_size") is not None and native_size is not None and result["virtual_size"] != native_size:
                marker("qemu_img_disagrees", [fid], "qemu-img reports virtual size %s and the header reads %s" % (result["virtual_size"], native_size),
                       "one of the two readings is wrong or the file is damaged; neither is preferred")
            cross.append(fid)
        qemu_report["checked"] = len(cross)
        if qemu_mode == "require" and qemu_report["available"] is False:
            fail("qemu_img: require was asked for and qemu-img is not on PATH (the base pack lists it as optional: check the image the job runs in)")
        if qemu_report["available"] is False:
            qemu_report["note"] = "qemu-img is not on PATH here (the base pack lists it as optional): the native reading above is all there is"
        elif qemu_report["checked"] == 0:
            qemu_report["note"] += "; no parsed image was eligible"

    # ---- disks page ------------------------------------------------------------------------------------------------
    for fid, d in disks.items():
        row = {"source_id": fid, "file": d["file"], "format": d.get("format"), "state": d["state"], "role": d.get("role", "disk"),
               "own_id": d.get("own_id"), "records_a_parent": bool(d.get("has_parent")), "is_extent_of": extent_targets.get(fid),
               "depth": depth.get(fid), "base": base.get(fid), "chain_state": state_of.get(fid), "detail": make_net(shown, fid)(d.get("detail"))}
        if d.get("qemu_img"):
            row["qemu_img"] = d["qemu_img"]
        pages["disks"].add(row)

    if config_total["dropped"]:
        partial.append("the .vmx and .vmsd files hold more than %d entries between them: %d file(s) were counted and their entries were not held against the descriptors" % (MAX_CONFIG_ENTRIES_TOTAL, config_total["dropped"]))
    values.close()
    result_pages = {k: v.finish() for k, v in pages.items()}
    all_parsed = not problems
    complete = all_parsed and not partial and not files.skipped_counts["unreadable"] and not files.skipped_counts["too_deep"]
    outcome = status_of(complete, bool(files.files) and examined == 0 and bool(problems),
                        "every recognised file in the set was read, none was left out, and every limit held",
                        "%d recognised file(s) were not read whole (failed, unsupported or partial), %d unreadable, %d directory(ies) too deep%s: the answer names them" % (
                            len(problems), files.skipped_counts["unreadable"], files.skipped_counts["too_deep"], ("; " + "; ".join(partial)) if partial else ""),
                        "no recognised file could be read")
    recognised = sum(c for k, c in kinds.items() if k != "other")
    if files.files and not recognised and outcome["status"] == "complete":
        outcome = {"status": "complete", "status_basis": "the set holds no file of a kind this tool reads (%d other file(s), counted by extension): zero disks is a statement about this tool's formats, not about the VM" % sum(other_ext.values())}
    if not files.files:
        skipped = sum(files.skipped_counts.values())
        outcome = ({"status": "partial", "status_basis": "the set holds no file that could be read; %d entr(ies) were skipped (links, special files, directories too deep, unreadable)%s: the answer names them" % (skipped, ("; " + "; ".join(partial)) if partial else "")}
                   if skipped or partial else {"status": "failed", "status_basis": "the set holds no file"})
    print(json.dumps({
        "parser": PARSER, **outcome,
        "root": files.root_shown, "files_in_set": len(files.files), "kinds": dict(kinds), "other_files_by_extension": dict(other_ext.most_common(20)),
        "other_files_note": "files of no kind this tool reads are counted by extension and not examined; absence of a disk here is not absence of a disk",
        "states": dict(state_counts), "recognised_not_read_whole": problems[:200],
        "sources": pages["sources"].page, "disks": pages["disks"].page, "edges": pages["edges"].page, "chains": pages["chains"].page,
        "extents": pages["extents"].page, "snapshot_database": pages["snapshot_database"].page, "internal_snapshots": pages["internal_snapshots"].page,
        "markers": pages["markers"].page, "pages": result_pages,
        "chain_summary": dict(chain_summary),
        "chain_note": "A chain is complete when every parent a disk names is in the set and the identities agree where the format records one. It is not a disk that boots, and it says nothing about the parent's content when the child was made.",
        "walk": files.skipped_summary(), "walk_truncated": files.truncated, "partial_reasons": partial, "lock_directories_total": files.lock_dirs_total,
        "qemu_img": qemu_report,
        "text": values.summary(), "withheld": withheld_summary(shown),
        "truncated": any(p["truncated"] for p in result_pages.values()),
        "limits": {"max_files": max_files, "max_entries": max_entries, "max_depth": max_depth, "max_snapshots": max_snapshots, "max_chain_depth": max_chain, "descriptor_read_cap": MAX_DESCRIPTOR},
        "note": "Markers are candidates with the observation beside them. A header or a descriptor says what its writer recorded; it does not say who or what wrote it, when, or why. "
                "Corroborate with the hypervisor's own task and event records before calling a snapshot deleted, a consolidation failed or a disk tampered with.",
    }, indent=2))
    return 0 if outcome["status"] != "failed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
        fail("unexpected failure: %s" % describe(exc))

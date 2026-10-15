#!/usr/bin/env python3
"""Inventory the virtual machines, disks, snapshots and datastores that configuration files and inventory exports name.

The inputs read, from their public descriptions, and no others (a file of any other kind is counted, and a product's
file this tool recognises and does not read is listed as unsupported, never guessed at):

    VMware    .vmx (the VM's configuration: its name, guest OS, hardware version, devices and the disk files it names),
              .vmsd (the snapshot database), and ESXi's vmInventory.xml (the registered VMs' configuration paths)
    libvirt   a domain XML (<domain>: devices, disks with their backing stores), a domain snapshot XML (<domainsnapshot>)
              and a storage pool XML (<pool>)
    Proxmox   a VM or container configuration (/etc/pve/qemu-server/<id>.conf, /etc/pve/lxc/<id>.conf, with its snapshot
              sections; a [special:...] section such as the cloud-init settings is listed as special, not as a snapshot)
              and storage.cfg

What it is and is not. It lists what the files say exist, with the file and the line or element each statement came from.
A configuration that names a VM does not show the VM ran, exists on a host now, or was not deleted; a disk it names is
checked only against the files given, and "not in the set" is a statement about the set. Hyper-V (.vmcx, .vmrs),
VirtualBox (.vbox) and OVF are recognised by name or root element and are not read. The keys of a configuration that this
tool shows are the ones listed in the manifest; every other key is counted, and the names of those that look like
credentials are listed (never their values), so a reader knows a secret sits at that line.

SENSITIVE OUTPUT. A configuration can hold a console password, a cloud-init password, an SSH key or a user-data blob
under a key this tool does not show. Names, paths and values it does show pass the shape check of the shared block
(a token-shaped run or user-info is withheld; a long text is shown cut with its whole length); the original goes to one
private file only when write_text is asked for, in a job. XML files are read with entity declarations refused and the
element count and depth bounded. A credential-like key is named in every section it sits in (a snapshot keeps its own
copy of the settings), and credential-like attributes are named to a cap and counted past it. Every key and value of the
answer and of its paging files passes the one way out (SHARED BOUNDARY), which withholds by shape again and checks what it
wrote; a piece of a path (a datastore, a node, a storage name) is taken from the path after the whole was withheld.
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
import stat
import sys
import tempfile
import time
from pathlib import Path

TOOL = "virtualization_inventory"
PARSER = "virtualization_inventory/1"
DEFAULT_LIMIT = 200
DEFAULT_SECONDS = 50.0          # the manifest allows 60
MAX_SECONDS = 50.0
DEFAULT_MAX_FILE = 16 << 20
MAX_XML_ELEMENTS = 100000
MAX_XML_DEPTH = 64
MAX_LINE = 1 << 16
MAX_LINES = 500000
MAX_RECORDS_PER_FILE = 100000
MAX_NAMED_KEYS = 200

VMX_SHOWN = ("displayname", "guestos", "config.version", "virtualhw.version", "uuid.bios", "uuid.location", "vc.uuid", "memsize", "numvcpus",
             "cpuid.corespersocket", "nvram", "firmware", "vmx.hypervisor", "annotation.present")
VMX_ETHERNET = re.compile(r"^ethernet\d+\.(address|generatedaddress|networkname|virtualdev|present|addresstype)$", re.I)
VMX_DEVICE = re.compile(r"^((?:scsi|ide|sata|nvme)\d+:\d+)\.(\w+)$", re.I)
VMX_DEVICE_SHOWN = ("filename", "present", "devicetype", "mode", "redo", "writethrough", "sharing", "persistent")
SENSITIVE_KEY = re.compile(r"(?<![a-z])(pass(word|wd|phrase)?|secret|token|auth|cred(ential)?s?|userdata|user-data|cipassword|sshkeys?|encryption|vnc|(private|api|access|secret|ssh|license|licence)[-_.]?keys?)(?![a-z])", re.I)
UNSUPPORTED_NAMES = {".vmcx": "Hyper-V virtual machine configuration (binary)", ".vmrs": "Hyper-V runtime state", ".vmgs": "Hyper-V guest state",
                     ".vbox": "VirtualBox machine settings", ".vbox-prev": "VirtualBox machine settings (previous)", ".ovf": "OVF descriptor",
                     ".ova": "OVA archive", ".vmtx": "VMware template configuration", ".vmxf": "VMware team file", ".vmss": "VMware suspended state",
                     ".vmsn": "VMware snapshot state", ".utf16xml": "XML in a UTF-16 or UTF-32 encoding (not read)"}

# A value that is a number, a UUID or a run of hex bytes is shown as it is; anything else that comes from the evidence goes through the shape check.
SAFE_VALUE = re.compile(r"[0-9]{1,12}|[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}|(?:[0-9A-Fa-f]{2}[ -]){3,31}[0-9A-Fa-f]{2}")
# Keys whose values the tool built itself (identifiers, constants, derived times), never the evidence's text.
TOOL_BUILT = {"id", "source_id", "vm", "found", "how", "in_set", "in_set_note", "role", "format", "locator", "note", "credential_note", "time_utc", "time_basis", "node_basis",
              "kind", "layer", "keys_not_shown", "credential_like_keys_total", "description_present", "pending_section_present",
              "comment_lines_not_shown", "configuration_in_set", "index", "line", "element", "first_line", "value_chars"}

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


_CHECKED = {}


def _verdict(text):
    """None when the string passes both checks, else the check it fails; remembered per string (keys and values repeat
    across rows)."""
    hit = _CHECKED.get(text, False)
    if hit is False:
        if _rules_once(text) != text:
            hit = "the same rules"
        else:
            check = _suspect(text)
            hit = "second check: %s" % check if check else None
        if len(text) <= 2048:
            if len(_CHECKED) >= 50000:
                _CHECKED.clear()
            _CHECKED[text] = hit
    return hit


def backstop(value, where=""):
    """The serialised answer read back and checked by the same rules once and by the second check: a string either would
    still change (a key or a value) is replaced by <withheld: N bytes>, counted, and its place named."""
    if isinstance(value, str):
        check = _verdict(value)
        return _replace(value, where, check) if check else value
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


EXTENSION = re.compile(r"\.[A-Za-z0-9]{1,10}")


def ext_of(rel):
    """The extension a file is counted under: a short one of letters and digits as it is (lower case), none as (none),
    and any other under one bucket that shows nothing of it (a file name can carry a token after its last dot)."""
    ext = posixpath.splitext(posixpath.basename(rel))[1]
    if not ext:
        return "(none)"
    return ext.lower() if EXTENSION.fullmatch(ext) else "(other extensions)"
# END SHARED FILES


def iso_epoch(value):
    try:
        number = int(str(value).strip())
        return datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc).__add__(datetime.timedelta(seconds=number)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError):
        return None


# ---- XML, bounded ----------------------------------------------------------------------------------------------------

class Node:
    __slots__ = ("tag", "attrib", "text", "kids")

    def __init__(self, tag, attrib):
        self.tag, self.attrib, self.text, self.kids = tag, attrib, None, []

    def __iter__(self):
        return iter(self.kids)


def load_xml(source, limit):
    """(root Node, None) or (None, reason). `source` is read in chunks, never whole. Built on expat directly: a DOCTYPE or an entity declaration is refused whatever the
    encoding, no external entity is fetched, and the element count, the depth and the text of one element are bounded."""
    import xml.parsers.expat as expat

    def refuse(*_a):
        raise ValueError("a DOCTYPE or ENTITY declaration is refused: no entity is expanded")
    state = {"root": None, "count": 0, "stack": []}

    def start(tag, attrs):
        state["count"] += 1
        if state["count"] > MAX_XML_ELEMENTS:
            raise ValueError("more than %d elements" % MAX_XML_ELEMENTS)
        if len(state["stack"]) >= MAX_XML_DEPTH:
            raise ValueError("nested deeper than %d" % MAX_XML_DEPTH)
        node = Node(tag, attrs)
        if state["stack"]:
            state["stack"][-1].kids.append(node)
        elif state["root"] is None:
            state["root"] = node
        state["stack"].append(node)

    def end(_tag):
        state["stack"].pop()

    def chars(text):
        if state["stack"]:
            node = state["stack"][-1]
            if node.text is None or len(node.text) < (1 << 20):
                node.text = (node.text or "") + text

    parser = expat.ParserCreate()
    parser.buffer_text = True
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    total = 0
    try:
        while True:
            chunk = source.read(65536)
            total += len(chunk)
            if total > limit:
                raise ValueError("the file is over max_file_bytes (%d)" % limit)
            if not chunk:
                break
            parser.Parse(chunk, False)
        parser.Parse(b"", True)
    except (expat.ExpatError, ValueError, LookupError, RecursionError, MemoryError) as exc:
        # an encoding the reader does not know (LookupError) is this file's failure, never the run's
        return None, "not well-formed, in an encoding the reader does not know, or over a limit (%s)" % brief(exc, 160)
    return state["root"], None


def local(tag):
    return tag.rsplit(":", 1)[-1] if isinstance(tag, str) else ""


def child(el, name):
    for c in el:
        if local(c.tag) == name:
            return c
    return None


def children(el, name):
    return [c for c in el if local(c.tag) == name]


def text_of(el, name):
    c = child(el, name)
    return (c.text or "").strip() if c is not None else None


# ---- the sink: every record passes through here ----------------------------------------------------------------------

class Sink:
    def __init__(self, limit, shown, index):
        self.shown, self.index = shown, index
        self.pages = {k: LosslessPage(TOOL, k, limit) for k in ("vms", "disks", "snapshots", "datastores", "hosts", "sources")}
        self.counts = collections.Counter()
        self.seq = collections.Counter()
        self.per_file = collections.Counter()
        self.over_cap = collections.Counter()
        self.current_file = None

    def new_id(self, prefix):
        self.seq[prefix] += 1
        return "%s%06d" % (prefix, self.seq[prefix])

    def clean(self, value, key=None, depth=0):
        """The net under every record: a string from the evidence that no call site has checked is checked here."""
        if isinstance(value, str):
            if isinstance(value, Shown) or key in TOOL_BUILT or SAFE_VALUE.fullmatch(value):
                return value
            return self.shown(value, self.current_file["id"], key)
        if key in TOOL_BUILT or depth > 5:
            return value
        if isinstance(value, dict):
            return {k: self.clean(v, k, depth + 1) for k, v in value.items()}
        if isinstance(value, list):
            return [self.clean(v, key, depth + 1) for v in value]
        return value

    def emit(self, kind, row):
        row = self.clean(row)
        fid = self.current_file["id"]
        if self.per_file[fid] >= MAX_RECORDS_PER_FILE:
            self.over_cap[fid] += 1
            return None
        self.per_file[fid] += 1
        self.counts[kind] += 1
        row = {"id": self.new_id({"vms": "V", "disks": "D", "snapshots": "N", "datastores": "T", "hosts": "H"}[kind]), "source_id": fid, **row}
        self.pages[kind].add(row)
        return row["id"]

    def disk_ref(self, vm, rel, name, file_like=True, **fields):
        """A disk file a configuration names: checked against the files given, and nothing else. A storage volume of a
        hypervisor (an LVM volume, a Ceph image) is not a file: it is listed and not looked up."""
        target, how = None, "no_name"
        if name and file_like:
            target, how = self.index.resolve(rel, name)
        elif name:
            how = "storage_volume_not_a_file"
        row = {"vm": vm, "file": self.shown(name, self.current_file["id"], "disk file") if name is not None else None,
               "in_set": ("yes" if target else ("ambiguous" if how == "ambiguous_basename" else "no")) if (name and file_like) else ("not_a_file" if name else "no_name"),
               "found": target["id"] if target else None, "how": how if name else "no_name", **fields}
        if how == "basename_only":
            row["in_set_note"] = "matched by file name alone: the configuration's path is not a path in the set"
        return self.emit("disks", row)


# ---- VMware ----------------------------------------------------------------------------------------------------------

CONFIG_KV = re.compile(r'^\s*([A-Za-z0-9_.:\-]+)\s*=\s*"(.*)"\s*$')


def read_lines(fh):
    n = 0
    while True:
        raw = fh.readline(MAX_LINE + 1)
        if not raw:
            return
        n += 1
        if n > MAX_LINES:
            yield n, None
            return
        if len(raw) > MAX_LINE:
            while raw and not raw.endswith(b"\n"):
                raw = fh.readline(MAX_LINE)
            yield n, ""
            continue
        yield n, raw.decode("utf-8", "surrogateescape").rstrip("\r\n")


def key_report(not_shown, sensitive):
    return {"keys_not_shown": not_shown, "keys_that_look_like_credentials": [dict({"name": e[0], "line": e[1], "value_chars": e[2]}, **({"section": e[3]} if len(e) > 3 else {}))
                                                                             for e in sensitive[:MAX_NAMED_KEYS]],
            "credential_like_keys_total": len(sensitive),
            "note": "a value under such a key is at that line of the file, not in this answer; treat it as a secret to rotate"}


def parse_vmx(fh, sink, rec, shown):
    shown_vals, devices, not_shown, sensitive, bad, capped = {}, collections.OrderedDict(), 0, [], 0, False
    for n, line in read_lines(fh):
        if line is None:
            capped = True
            break
        m = CONFIG_KV.match(line)
        if not m:
            bad += 1 if line.strip() and not line.lstrip().startswith("#") else 0
            continue
        key, value = m.group(1), m.group(2)
        low = key.lower()
        dm = VMX_DEVICE.match(key)
        if low in VMX_SHOWN or VMX_ETHERNET.match(key):
            shown_vals[key] = (value, n)
        elif dm and dm.group(2).lower() in VMX_DEVICE_SHOWN:
            devices.setdefault(dm.group(1), {})[dm.group(2).lower()] = (value, n)
        else:
            not_shown += 1
            if SENSITIVE_KEY.search(key):
                sensitive.append((shown(key, rec["id"], "key"), n, len(value)))
    get = lambda k: shown_vals.get(k, (None, None))[0]
    lowered = {k.lower(): v for k, v in shown_vals.items()}
    vm = sink.emit("vms", {"format": "vmx", "name": shown(lowered.get("displayname", (None,))[0], rec["id"], "displayName"), "guest_os": shown(lowered.get("guestos", (None,))[0], rec["id"], "guestOS"),
                           "config_version": lowered.get("config.version", (None,))[0], "hardware_version": lowered.get("virtualhw.version", (None,))[0],
                           "bios_uuid": lowered.get("uuid.bios", (None,))[0], "location_uuid": lowered.get("uuid.location", (None,))[0],
                           "vcenter_instance_uuid": lowered.get("vc.uuid", (None,))[0], "memory_mb": lowered.get("memsize", (None,))[0], "vcpus": lowered.get("numvcpus", (None,))[0],
                           "firmware": lowered.get("firmware", (None,))[0], "nvram": shown(lowered.get("nvram", (None,))[0], rec["id"], "nvram"),
                           "network_adapters": sorted({k.split(".")[0] for k in shown_vals if VMX_ETHERNET.match(k)}),
                           "network": {k: shown(v[0], rec["id"], k) for k, v in shown_vals.items() if VMX_ETHERNET.match(k)},
                           "locator": {"file": rec["id"], "first_line": 1}, **key_report(not_shown, sensitive)})
    if vm is None:
        return "partial", "record cap reached"
    for dev, fields in devices.items():
        name, line = fields.get("filename", (None, None))
        if name is None:
            continue
        raw_type = fields.get("devicetype", (None,))[0]
        kind = (raw_type or "").lower()        # folded for the comparison only: the value is shown as written, through the shape check
        sink.disk_ref(vm, rec["rel"], name, device=dev, device_type=shown(raw_type, rec["id"], "deviceType") if raw_type else None, present=fields.get("present", (None,))[0],
                      mode=fields.get("mode", (None,))[0], locator={"file": rec["id"], "line": line},
                      role="optical or image" if "cdrom" in kind or name.lower().endswith(".iso") else "disk")
    if capped:
        return "partial", "the file has more than %d lines: read to that point, and what was read is listed" % MAX_LINES
    return ("parsed", None) if not bad else ("parsed", "%d line(s) were neither a key = \"value\" line nor a comment: counted, not read" % bad)


def parse_vmsd(fh, sink, rec, shown):
    entries, top, over, capped = collections.OrderedDict(), {}, 0, False
    for n, line in read_lines(fh):
        if line is None:
            capped = True
            break
        m = CONFIG_KV.match(line)
        if not m:
            continue
        key, value = m.group(1), m.group(2)
        low = key.lower()
        if low in ("snapshot.numsnapshots", "snapshot.current", "snapshot.lastuid"):
            top[low.split(".", 1)[1]] = value
            continue
        sm = re.match(r"^snapshot(\d+)\.(.+)$", key, re.I)
        if not sm:
            continue
        idx = int(sm.group(1))
        if idx not in entries:
            if len(entries) >= MAX_RECORDS_PER_FILE:
                over += 1
                continue
            entries[idx] = {"index": idx, "line": n, "disks": []}
        sub, e = sm.group(2).lower(), entries[idx]
        dm = re.match(r"^disk(\d+)\.(.+)$", sub)
        if dm:
            if dm.group(2) == "filename":
                e["disks"].append((value, n))
        elif sub in ("uid", "filename", "displayname", "parent", "createtimehigh", "createtimelow", "description", "type"):
            e[sub] = (value, n)
    for e in entries.values():
        sid = sink.emit("snapshots", {"vm": None, "format": "vmsd", "index": e["index"], "uid": e.get("uid", (None,))[0], "parent_uid": e.get("parent", (None,))[0],
                                      "name": shown(e.get("displayname", (None,))[0], rec["id"], "displayName"),
                                      "description_present": "description" in e, "state_file": shown(e.get("filename", (None,))[0], rec["id"], "snapshot state file"),
                                      "time_raw": {"createTimeHigh": e.get("createtimehigh", (None,))[0], "createTimeLow": e.get("createtimelow", (None,))[0]},
                                      "time_utc": None, "time_basis": "two raw fields as written; how they encode a time is not decoded here",
                                      "snapshot_database": {"numSnapshots": top.get("numsnapshots"), "current": top.get("current"), "lastUID": top.get("lastuid")},
                                      "locator": {"file": rec["id"], "line": e["line"]}})
        for name, line in e["disks"]:
            sink.disk_ref(sid, rec["rel"], name, role="snapshot disk", locator={"file": rec["id"], "line": line})
    if capped:
        return "partial", "the file has more than %d lines: read to that point, and what was read is listed" % MAX_LINES
    if over:
        return "partial", "%d snapshot index(es) past the cap of %d were counted and not listed" % (over, MAX_RECORDS_PER_FILE)
    return "parsed", None


def vmware_path(path):
    """The datastore a /vmfs/volumes/<datastore>/... path names, which is all this tool takes from the path. The piece
    is taken from the path AFTER the whole was withheld by shape: a token split at `/` is withheld as one, never shown
    piece by piece."""
    m = re.match(r"^/vmfs/volumes/([^/]+)/", seal_text(path, "text") if path else "")
    return m.group(1) if m else None


def parse_vm_inventory_xml(root, sink, rec, shown):
    entries = [c for c in root if local(c.tag) == "ConfigEntry"]
    for i, e in enumerate(entries, 1):
        path = text_of(e, "vmxCfgPath")
        sink.emit("vms", {"format": "esxi_vm_inventory_xml", "name": None, "entry_id": e.attrib.get("id"), "object_id": text_of(e, "objID"),
                          "configuration_path": shown(path, rec["id"], "vmxCfgPath"), "datastore_hint": shown(vmware_path(path), rec["id"], "datastore"),
                          "configuration_in_set": ("yes" if sink.index.resolve(rec["rel"], path)[0] else "no") if path else "no_name",
                          "locator": {"file": rec["id"], "element": "/ConfigRoot/ConfigEntry[%d]" % i},
                          "note": "a VM registered in the inventory when the file was written; it is not evidence that it ran, still exists, or is on this host now"})
    return ("parsed", None) if entries else ("parsed", "no ConfigEntry element: the file holds no registered VM (or is another layout)")


# ---- libvirt ---------------------------------------------------------------------------------------------------------

def disk_entries(disk, sink, vm, rec, base_loc, shown):
    """A <disk> and its <backingStore> chain, one disk reference per layer."""
    dev = child(disk, "target")
    driver = child(disk, "driver")
    layer, cur, loc = 0, disk, base_loc
    while cur is not None and layer < 256:
        src = child(cur, "source")
        fmt = child(cur, "format")
        name = None
        if src is not None:
            name = src.attrib.get("file") or src.attrib.get("dev") or src.attrib.get("name") or src.attrib.get("volume")
        kind = (cur.attrib.get("type") or "") if cur is not disk else (disk.attrib.get("type") or "")
        proto = src.attrib.get("protocol") if src is not None else None
        if name is not None or layer == 0:
            sink.disk_ref(vm, rec["rel"], name if kind in ("file", "block", "dir", "") else None, layer=layer, role=("disk" if layer == 0 else "backing store"),
                          device=dev.attrib.get("dev") if dev is not None else None, bus=dev.attrib.get("bus") if dev is not None else None,
                          device_type=disk.attrib.get("device"), source_type=kind or None, source_protocol=proto,
                          source_name=shown(name, rec["id"], "disk source") if (kind not in ("file", "block", "dir", "") and name is not None) else None,
                          disk_format=(fmt.attrib.get("type") if fmt is not None else (driver.attrib.get("type") if (driver is not None and layer == 0) else None)),
                          locator={"file": rec["id"], "element": loc})
        nxt = child(cur, "backingStore")
        if nxt is None or (not list(nxt) and not nxt.attrib):
            break
        cur, layer = nxt, layer + 1
        loc += "/backingStore"


def parse_libvirt_domain(root, sink, rec, shown):
    name = text_of(root, "name")
    os_el = child(root, "os")
    type_el = child(os_el, "type") if os_el is not None else None
    mem = child(root, "memory")
    devices = child(root, "devices")
    credential_attrs, credential_total = [], 0
    if devices is not None:
        for i, g in enumerate(children(devices, "graphics"), 1):
            if "passwd" in g.attrib:
                credential_total += 1
                if len(credential_attrs) < MAX_NAMED_KEYS:          # named up to the cap, all counted
                    credential_attrs.append({"where": "/domain/devices/graphics[%d]@passwd" % i, "value_chars": len(g.attrib["passwd"])})
    vm = sink.emit("vms", {"format": "libvirt_domain", "name": shown(name, rec["id"], "name"), "uuid": text_of(root, "uuid"), "virt_type": root.attrib.get("type"),
                           "machine": type_el.attrib.get("machine") if type_el is not None else None, "arch": type_el.attrib.get("arch") if type_el is not None else None,
                           "memory": (mem.text or "").strip() + " " + mem.attrib.get("unit", "KiB") if mem is not None else None,
                           "vcpus": text_of(root, "vcpu"), "locator": {"file": rec["id"], "element": "/domain"},
                           "credential_like_attributes": credential_attrs, "credential_like_attributes_total": credential_total,
                           "credential_note": "a console password sits at that attribute; it is not shown and is a secret to rotate" if credential_attrs else None})
    if devices is None:
        return "parsed", "the domain has no <devices> element"
    for i, d in enumerate(children(devices, "disk"), 1):
        disk_entries(d, sink, vm, rec, "/domain/devices/disk[%d]" % i, shown)
    return "parsed", None


def parse_libvirt_snapshot(root, sink, rec, shown):
    name = text_of(root, "name")
    parent = child(root, "parent")
    dom = child(root, "domain")
    memory = child(root, "memory")
    disks = child(root, "disks")
    sid = sink.emit("snapshots", {"vm": None, "format": "libvirt_domainsnapshot", "name": shown(name, rec["id"], "name"), "uid": None,
                                  "parent_name": shown(text_of(parent, "name") if parent is not None else None, rec["id"], "parent"),
                                  "state": text_of(root, "state"), "time_raw": text_of(root, "creationTime"), "time_utc": iso_epoch(text_of(root, "creationTime")),
                                  "time_basis": "creationTime is seconds since 1970-01-01T00:00:00Z", "description_present": bool(text_of(root, "description")),
                                  "memory": memory.attrib.get("snapshot") if memory is not None else None, "domain_name": shown(text_of(dom, "name") if dom is not None else None, rec["id"], "domain"),
                                  "locator": {"file": rec["id"], "element": "/domainsnapshot"}})
    if disks is not None:
        for i, d in enumerate(children(disks, "disk"), 1):
            src = child(d, "source")
            f = src.attrib.get("file") if src is not None else None
            sink.disk_ref(sid, rec["rel"], f, role="snapshot disk", device=d.attrib.get("name"), snapshot_mode=d.attrib.get("snapshot"), locator={"file": rec["id"], "element": "/domainsnapshot/disks/disk[%d]" % i})
    return "parsed", None


def parse_libvirt_pool(root, sink, rec, shown):
    target = child(root, "target")
    sink.emit("datastores", {"format": "libvirt_pool", "name": shown(text_of(root, "name"), rec["id"], "name"), "type": root.attrib.get("type"), "uuid": text_of(root, "uuid"),
                             "path": shown(text_of(target, "path") if target is not None else None, rec["id"], "path"), "locator": {"file": rec["id"], "element": "/pool"}})
    return "parsed", None


# ---- Proxmox ---------------------------------------------------------------------------------------------------------

PVE_DISK = re.compile(r"^(virtio|scsi|sata|ide|efidisk|tpmstate|unused)(\d*)$")
PVE_SHOWN = ("name", "hostname", "ostype", "machine", "bios", "cores", "sockets", "vcpus", "memory", "boot", "agent", "onboot", "lock", "template", "arch", "cpu", "scsihw", "vmgenid", "protection", "tags")
PVE_SNAP_SHOWN = ("parent", "snaptime", "vmstate", "snapstate", "description")


def pve_ids(rel):
    parts = seal_text(rel, "text").split("/")      # the pieces of the path after the whole was withheld by shape
    node = parts[parts.index("nodes") + 1] if "nodes" in parts and parts.index("nodes") + 1 < len(parts) - 1 else None
    m = re.match(r"^(\d+)\.conf$", parts[-1])
    return node, (m.group(1) if m else None)


def pve_section_kind(sname):
    """current (the configuration), pending (changes not applied yet), special (Proxmox's own sections such as
    [special:cloudinit], the cloud-init settings last applied) or snapshot (every other section is named by a snapshot)."""
    name = sname.split("#dup")[0]
    if sname == "":
        return "current"
    if name == "PENDING":
        return "pending"
    if name.startswith("special:"):
        return "special"
    return "snapshot"


def parse_pve_conf(fh, sink, rec, shown):
    node, vmid = pve_ids(rec["rel"])
    sections = collections.OrderedDict([("", {"line": 1, "kv": collections.OrderedDict(), "comment_lines": 0})])
    cur, bad, sensitive, not_shown, capped, sections_over = "", 0, [], 0, False, False
    for n, line in read_lines(fh):
        if line is None:
            capped = True
            break
        if not line.strip():
            continue
        if line.startswith("#"):
            sections[cur]["comment_lines"] += 1
            continue
        m = re.match(r"^\[([^\]]*)\]\s*$", line)
        if m:
            cur = m.group(1)
            if cur in sections:
                cur = cur + "#dup%d" % n
            sections[cur] = {"line": n, "kv": collections.OrderedDict(), "comment_lines": 0}
            if len(sections) > MAX_RECORDS_PER_FILE:
                sections_over = True
                del sections[cur]
                break
            continue
        m = re.match(r"^([A-Za-z0-9_\-]+):\s?(.*)$", line)
        if not m:
            bad += 1
            continue
        sections[cur]["kv"][m.group(1)] = (m.group(2), n)
    main = sections[""]["kv"]
    if node:
        sink.emit("hosts", {"node": shown(node, rec["id"], "node"), "node_basis": "a directory name in the path of the configuration file; no host record was read",
                            "locator": {"file": rec["id"]}})
    for sname, sec in sections.items():
        for k, (v, n) in sec["kv"].items():
            if sname == "" and k not in PVE_SHOWN and not PVE_DISK.match(k) and not re.match(r"^net\d+$", k) and k not in PVE_SNAP_SHOWN:
                not_shown += 1
            # a credential-like key is named wherever it sits: a snapshot or a special section keeps its own copy of the settings
            if SENSITIVE_KEY.search(k) and (sname != "" or k not in PVE_SHOWN):
                sensitive.append((shown(k, rec["id"], "key"), n, len(v), "current" if sname == "" else shown(sname.split("#dup")[0], rec["id"], "section")))
    snapshot_names = [s for s in sections if pve_section_kind(s) == "snapshot"]
    special_names = [s for s in sections if pve_section_kind(s) == "special"]
    vm = sink.emit("vms", {"format": "pve_conf", "vmid": vmid, "node": shown(node, rec["id"], "node"), "name": shown((main.get("name") or main.get("hostname") or (None,))[0], rec["id"], "name"),
                           "kind": "container" if "/lxc/" in "/" + rec["rel"] else "qemu", "os_type": (main.get("ostype") or (None,))[0], "machine": (main.get("machine") or (None,))[0],
                           "bios": (main.get("bios") or (None,))[0], "cores": (main.get("cores") or (None,))[0], "sockets": (main.get("sockets") or (None,))[0],
                           "memory_mb": (main.get("memory") or (None,))[0], "lock": (main.get("lock") or (None,))[0], "template": (main.get("template") or (None,))[0],
                           "current_parent_snapshot": shown((main.get("parent") or (None,))[0], rec["id"], "parent"),
                           "snapshot_sections": [shown(s.split("#dup")[0], rec["id"], "snapshot") for s in snapshot_names[:MAX_NAMED_KEYS]],
                           "snapshot_sections_total": len(snapshot_names),
                           "snapshot_sections_note": "the first %d section names; every snapshot section is a row of snapshots (paged whole)" % MAX_NAMED_KEYS,
                           "special_sections": [shown(s.split("#dup")[0], rec["id"], "section") for s in special_names[:MAX_NAMED_KEYS]],
                           "special_sections_total": len(special_names),
                           "special_sections_note": "a [special:...] section is Proxmox's own (such as the cloud-init settings last applied), not a snapshot; the first %d are named" % MAX_NAMED_KEYS,
                           "pending_section_present": "PENDING" in sections, "comment_lines_not_shown": sections[""]["comment_lines"],
                           "locator": {"file": rec["id"], "first_line": 1}, **key_report(not_shown, sensitive)})
    for sname, sec in sections.items():
        is_snap = pve_section_kind(sname) == "snapshot"
        label = "snapshot %s" % sname if is_snap else ""
        sid = None
        if is_snap:
            kv = sec["kv"]
            snaptime = (kv.get("snaptime") or (None,))[0]
            sid = sink.emit("snapshots", {"vm": vm, "format": "pve_conf_section", "name": shown(sname.split("#dup")[0], rec["id"], "snapshot"), "uid": None,
                                          "parent_name": shown((kv.get("parent") or (None,))[0], rec["id"], "parent"), "time_raw": snaptime, "time_utc": iso_epoch(snaptime) if snaptime else None,
                                          "time_basis": "snaptime is seconds since 1970-01-01T00:00:00Z", "vm_state_volume": shown((kv.get("vmstate") or (None,))[0], rec["id"], "vmstate"),
                                          "snapstate": (kv.get("snapstate") or (None,))[0], "description_present": "description" in kv,
                                          "locator": {"file": rec["id"], "line": sec["line"]}})
        for k, (v, n) in sec["kv"].items():
            m = PVE_DISK.match(k)
            if m or re.match(r"^(mp\d+|rootfs)$", k):
                volume, _, options = v.partition(",")
                storage, _, vol = seal_text(volume, "text").partition(":")    # split after the whole was withheld: user-info spans the `:`
                opts = dict(o.split("=", 1) for o in options.split(",") if "=" in o) if options else {}
                sink.disk_ref(sid or vm, rec["rel"], volume if (":" in volume or "/" in volume) else None, file_like=bool(re.search(r"\.(qcow2|raw|vmdk|vhdx?|img|iso)$", volume, re.I)), section=sname or "current", device=k, role=("snapshot disk" if is_snap else "disk"),
                              storage=shown(storage, rec["id"], "storage") if vol else None, volume=shown(vol, rec["id"], "volume") if vol else None,
                              size=opts.get("size"), backup=opts.get("backup"), media=opts.get("media"), options_count=len(opts), locator={"file": rec["id"], "line": n})
    if capped:
        return "partial", "the file has more than %d lines: read to that point, and what was read is listed" % MAX_LINES
    if sections_over:
        return "partial", "more than %d sections: the first %d are listed and the rest were not read" % (MAX_RECORDS_PER_FILE, MAX_RECORDS_PER_FILE)
    if len(special_names) > MAX_NAMED_KEYS:
        return "partial", "%d [special:...] sections: the first %d are named and the rest are counted (special_sections_total)" % (len(special_names), MAX_NAMED_KEYS)
    return ("parsed", None) if not bad else ("parsed", "%d line(s) matched no key: value shape: counted, not read" % bad)


def parse_pve_storage(fh, sink, rec, shown):
    cur, capped = None, False
    allowed = ("path", "content", "shared", "nodes", "disable", "prune-backups", "maxfiles", "server", "export", "pool", "vgname", "thinpool", "datastore", "username", "mkdir", "is_mountpoint")
    sensitive, not_shown = [], 0
    def flush():
        if cur is not None:
            sink.emit("datastores", {"format": "pve_storage_cfg", "type": cur["type"], "name": shown(cur["name"], rec["id"], "storage name"),
                                     "settings": {k: shown(v, rec["id"], k) for k, v in cur["kv"].items() if k in allowed},
                                     "locator": {"file": rec["id"], "line": cur["line"]}, **key_report(cur["not_shown"], cur["sensitive"])})
    for n, line in read_lines(fh):
        if line is None:
            capped = True
            break
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            m = re.match(r"^([A-Za-z0-9_\-]+):\s+(\S.*)$", line)
            flush()
            cur = {"type": m.group(1), "name": m.group(2).strip(), "kv": {}, "line": n, "not_shown": 0, "sensitive": []} if m else None
            continue
        if cur is None:
            continue
        parts = line.strip().split(None, 1)
        key, value = parts[0], parts[1] if len(parts) > 1 else ""
        if key in allowed:
            cur["kv"][key] = value
        else:
            cur["not_shown"] += 1
            if SENSITIVE_KEY.search(key):
                cur["sensitive"].append((shown(key, rec["id"], "key"), n, len(value)))
    flush()
    if capped:
        return "partial", "the file has more than %d lines: read to that point, and what was read is listed" % MAX_LINES
    return "parsed", None


# ---- dispatch --------------------------------------------------------------------------------------------------------

def classify(rec, head, max_file):
    name = posixpath.basename(rec["rel"]).lower()
    ext = posixpath.splitext(name)[1]
    if head[:2] in (b"\xff\xfe", b"\xfe\xff") or head[:4] in (b"\x00\x00\xfe\xff", b"<\x00?\x00", b"\x00<\x00?", b"<\x00d\x00", b"\x00<\x00d"):
        return "unsupported:.utf16xml"
    stripped = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    if stripped[:1] == b"<":
        pos = 0
        while pos < len(stripped):              # skip an XML declaration and comments by position: no pattern can backtrack over a hostile prefix
            while pos < len(stripped) and stripped[pos:pos + 1] in (b" ", b"\t", b"\r", b"\n"):
                pos += 1
            if stripped.startswith(b"<?", pos):
                end = stripped.find(b"?>", pos)
            elif stripped.startswith(b"<!--", pos):
                end = stripped.find(b"-->", pos)
            elif stripped[pos:pos + 9].upper() in (b"<!DOCTYPE", b"<!ENTITY "):
                return "refused:doctype"
            else:
                break
            if end < 0:
                pos = len(stripped)
                break
            pos = end + (2 if stripped.startswith(b"<?", pos) else 3)
        m = re.match(rb"<([A-Za-z_][\w.\-]*)", stripped[pos:pos + 256])
        tag = m.group(1).decode("ascii", "replace") if m else ""
        if tag == "domain":
            return "libvirt_domain"
        if tag == "domainsnapshot":
            return "libvirt_snapshot"
        if tag == "pool":
            return "libvirt_pool"
        if tag == "ConfigRoot":
            return "vm_inventory_xml" if name in ("vminventory.xml",) or b"vmxCfgPath" in head else "xml_other"
        if tag == "VirtualBox":
            return "unsupported:.vbox"
        if tag in ("Envelope",) or ext == ".ovf":
            return "unsupported:.ovf"
        return "xml_other"
    if ext == ".vmsd":
        return "vmsd"
    if ext == ".vmx":
        return "vmx"
    if name == "storage.cfg":
        return "pve_storage"
    if ext == ".conf" and ("qemu-server/" in rec["rel"] + "" or "/lxc/" in "/" + rec["rel"] or "qemu-server" in rec["rel"]):
        return "pve_conf"
    if ext in UNSUPPORTED_NAMES:
        return "unsupported:" + ext
    if ext == ".conf":
        lines = [l for l in head.decode("utf-8", "replace").splitlines() if l and not l.startswith("#")][:30]
        hits = sum(1 for l in lines if re.match(r"^(boot|cores|memory|ostype|scsihw|sockets|vmgenid|smbios1|bios|machine|net\d+|virtio\d+|scsi\d+|ide\d+|sata\d+|efidisk0|name|cpu|agent|onboot|rootfs|hostname|arch):\s", l))
        if hits >= 3:
            return "pve_conf"
    return "other"


def main():
    args = read_args()
    root = want_str(args, "root")
    paths = want_str_list(args, "paths", 100000)
    if root is None and not paths:
        fail("name the evidence: root is a directory of configuration files and exports, paths is a list of files")
    limit = want_int(args, "limit", DEFAULT_LIMIT, 1, 100000)
    max_files = want_int(args, "max_files", 20000, 1, 200000)
    max_entries = want_int(args, "max_entries", 200000, 1, 2000000)
    max_depth = want_int(args, "max_depth", 16, 1, 64)
    max_file = want_int(args, "max_file_bytes", DEFAULT_MAX_FILE, 4096, 256 << 20)
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    write_text = want_flag(args, "write_text")
    try:
        values = TextFile("inventory-values.jsonl", write_text, "JSON Lines, mode 0600: record_type original, where (a source id), field, value (the original text of "
                          "a name, path or value the answer shows withheld or shortened)")
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
    sink = Sink(limit, shown, index)
    kinds, other_ext, states = collections.Counter(), collections.Counter(), collections.Counter()
    unreadable = []
    parsers_xml = {"libvirt_domain": parse_libvirt_domain, "libvirt_snapshot": parse_libvirt_snapshot, "libvirt_pool": parse_libvirt_pool, "vm_inventory_xml": parse_vm_inventory_xml}
    parsers_text = {"vmx": parse_vmx, "vmsd": parse_vmsd, "pve_conf": parse_pve_conf, "pve_storage": parse_pve_storage}
    problems = 0
    try:
        for rec in files.files:
            clock.check()
            fh, why = open_regular(rec["path"])
            if fh is None:
                files.note("unreadable", rec["rel"] + ": " + (why or ""))
                continue
            with fh:
                head = fh.read(65536)
                kind = classify(rec, head, max_file)
                kinds[kind.split(":")[0] if kind.startswith(("unsupported", "refused")) else kind] += 1
                if kind == "other":
                    ext = ext_of(rec["rel"])
                    other_ext[ext if (ext in other_ext or len(other_ext) < 2000) else "(other extensions)"] += 1
                    continue
                sink.current_file = rec
                row = {"source_id": rec["id"], "file": shown(rec["rel"], rec["id"], "file"), "size": rec["size"], "kind": kind}
                state, reason = "parsed", None
                before = sum(sink.counts.values())
                try:
                    if kind == "refused:doctype":
                        state, reason = "failed", "a DOCTYPE or ENTITY declaration is refused: no entity is expanded, and the file was not handed to a parser"
                    elif kind.startswith("unsupported:"):
                        state, reason = "unsupported_recognised", "%s: recognised and not read" % UNSUPPORTED_NAMES.get(kind.split(":", 1)[1], "a product file")
                    elif kind == "xml_other":
                        state, reason = "unsupported_recognised", "an XML file whose root is not one this tool reads"
                    elif rec["size"] > max_file:
                        state, reason = "failed", "the file is %d bytes, over max_file_bytes (%d): named and not read" % (rec["size"], max_file)
                    elif kind in parsers_xml:
                        fh.seek(0)
                        xml_root, err = load_xml(fh, max_file)
                        if xml_root is None:
                            state, reason = "failed", err
                        else:
                            state, reason = parsers_xml[kind](xml_root, sink, rec, shown)
                    elif kind in parsers_text:
                        fh.seek(0)
                        state, reason = parsers_text[kind](fh, sink, rec, shown)
                except (ValueError, LookupError, OverflowError, RecursionError, MemoryError, IndexError, KeyError, AttributeError) as exc:
                    state, reason = "failed", "the structure could not be read (%s)" % describe(exc)
                except OSError as exc:
                    state, reason = "failed", "a read failed (%s)" % describe(exc)
            if sink.over_cap[rec["id"]]:
                state, reason = "partial", "%d record(s) past the cap of %d for one file were counted and not listed" % (sink.over_cap[rec["id"]], MAX_RECORDS_PER_FILE)
            states[state] += 1
            if state in ("failed", "partial"):
                problems += 1
            row.update(state=state, reason=reason, records=sum(sink.counts.values()) - before)
            sink.pages["sources"].add(row)
    except Overtime:
        partial.append("the examination stopped at max_seconds (%s): the files after the last one listed in sources were not read" % seconds)
    values.close()
    result_pages = {k: v.finish() for k, v in sink.pages.items()}
    unsupported = sum(c for k, c in kinds.items() if k.startswith("unsupported") or k == "xml_other")
    complete = not problems and not partial and not files.skipped_counts["unreadable"] and not files.skipped_counts["too_deep"]
    outcome = status_of(complete, bool(files.files) and not sum(sink.counts.values()) and problems and not unsupported,
                        "every file of a kind this tool reads was read and nothing was left out" + ("; %d file(s) of a recognised kind it does not read are listed as unsupported" % unsupported if unsupported else ""),
                        "%d file(s) were not read whole, %d unreadable, %d directory(ies) too deep%s: the answer names them" % (
                            problems, files.skipped_counts["unreadable"], files.skipped_counts["too_deep"], ("; " + "; ".join(partial)) if partial else ""),
                        "no file could be read")
    recognised = sum(c for k, c in kinds.items() if k != "other")
    if files.files and not recognised and outcome["status"] == "complete":
        outcome = {"status": "complete", "status_basis": "the set holds no file of a kind this tool reads (%d other file(s), counted by extension): zero records is a statement about this tool's formats, not about the system" % sum(other_ext.values())}
    if not files.files:
        skipped = sum(files.skipped_counts.values())
        outcome = ({"status": "partial", "status_basis": "the set holds no file that could be read; %d entr(ies) were skipped (links, special files, directories too deep, unreadable)%s: the answer names them" % (skipped, ("; " + "; ".join(partial)) if partial else "")}
                   if skipped or partial else {"status": "failed", "status_basis": "the set holds no file"})
    print(answer_text({
        "parser": PARSER, **outcome,
        "root": files.root_shown, "files_in_set": len(files.files), "kinds": dict(kinds), "states": dict(states),
        "other_files_by_extension": dict(other_ext.most_common(20)),
        "other_files_note": "files of no kind this tool reads are counted by extension and not examined; absence of a configuration here is not absence of a VM",
        "counts": {"vms": sink.counts["vms"], "disks": sink.counts["disks"], "snapshots": sink.counts["snapshots"], "datastores": sink.counts["datastores"], "hosts": sink.counts["hosts"]},
        "sources": sink.pages["sources"].page, "vms": sink.pages["vms"].page, "disks": sink.pages["disks"].page, "snapshots": sink.pages["snapshots"].page,
        "datastores": sink.pages["datastores"].page, "hosts": sink.pages["hosts"].page, "pages": result_pages,
        "walk": files.skipped_summary(), "walk_truncated": files.truncated, "partial_reasons": partial,
        "text": values.summary(), "withheld": withheld_summary(shown),
        "truncated": any(p["truncated"] for p in result_pages.values()),
        "limits": {"max_files": max_files, "max_entries": max_entries, "max_depth": max_depth, "max_file_bytes": max_file, "max_records_per_file": MAX_RECORDS_PER_FILE,
                   "xml_elements": MAX_XML_ELEMENTS, "xml_depth": MAX_XML_DEPTH},
        "note": "An inventory lists what the files say exist. A configuration or an inventory entry does not show that a VM ran, still exists or was not deleted; a disk 'not in the set' is a "
                "statement about the files given. Versions are the strings the files carry; what they mean for a given product release is for the vendor's documentation of that release.",
    }))
    return 0 if outcome["status"] != "failed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
        fail("unexpected failure: %s" % describe(exc))

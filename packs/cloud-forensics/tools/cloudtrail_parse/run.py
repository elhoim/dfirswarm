#!/usr/bin/env python3
"""Read AWS CloudTrail records offline, and say what was read, what was not, and what the records do and do not show.

What it does. It reads CloudTrail log files (a `{"Records": [...]}` file, a bare array, one event, JSON Lines, a
`lookup-events` page, any of them gzip-compressed) from a file or a directory, one record at a time, and normalises each
event: when, what, by whom, from where, whether an error was recorded, with the identity, the request, the response and
the additional event data kept (a value that is named or shaped like a credential is withheld, see below).

What it counts, loudly. Every file is named in a census with its status. A malformed line, a record that is not a
CloudTrail event, a file that is not a CloudTrail export, a gzip that ends early, a file whose expansion passed its cap,
a response page that names a next page: each is counted, located (file, record, line) and listed in a file the answer
names. `status` is complete only when every record of every supplied file was read and nothing was left out; that says
nothing about whether the export holds everything the account logged.

Sessions. `userIdentity.type` AssumedRole names a session, not a person. `session_origin` links a session to the
successful AssumeRole-family events in the supplied records that could have issued it: by the access key id the response
returned, else by the session ARN the response returned (or, where the response is absent, the ARN derived from the
request, in the request's own partition and without the role's path), narrowed by the session's creationDate. A failed
call is never indexed. Every link is a candidate with its basis and the source event; more than one possible source is
`unresolved` and names them all, none is `not_found`. It is never attribution to a person.

Errors. An error code is classified by its name (authorisation_denied, authentication, throttling, validation,
not_found, service, unclassified); the code itself is always kept. Only authorisation_denied is counted in
refusals_by_identity. The classes are a heuristic by name, not the provider's taxonomy.

What it does not do. It does not validate CloudTrail digest files or the chain they form (it names the digest files it
saw and says no integrity validation was performed). It does not establish what a trail was configured to record: an
absent data event is not evidence that nothing was read.

SECRET-SAFE OUTPUT (docs/packs.md, "Secrets and sensitive output"). A request, a response or an event's additional data
can hold a secret. A field whose name says it is one (a password, a secret, a token), and any text shaped like one (a JSON
Web Token, a private key block, a value assigned to a credential name, the common token families), is withheld in every
channel: a row, a path, an error message, the file the answer names. The row says how many characters, and the original
goes to `cloudtrail-values.jsonl` under $OUT (mode 0600, created first) only when `write_values: true` is asked, in a
job, which the skill says to run with `secret_output: true`. A name and a shape recognise some secrets and never all:
run the tool as a `secret_output` job whenever the export may hold request parameters.
"""
# ---- BEGIN SHARED BLOCK ----------------------------------------------------------------------------------------------
# Identical in cloudtrail_parse, signin_analyse and ual_parse. A tool is standalone, so what the three share is copied,
# as LosslessPage is in every pack tool, and tests/pack-cloud-shared.test.ts holds the three copies equal. Edit it in all
# three, never in one. It holds: the answer's error form, typed arguments, where an output may be written and published
# without replacing another, the lossless page, the secret-safe values file (the SecretValues of recovery_key_scan), the
# withholding of anything shaped like a credential, timestamps, and a bounded streaming reader for JSON and JSON Lines.
import atexit
import calendar
import codecs
import csv
import datetime
import errno
import gzip
import json
import os
import re
import secrets
import sqlite3
import stat
import sys
import tempfile
import time
import zlib
from pathlib import Path

DEFAULT_LIMIT = 500
FIRST_PROBLEMS = 25               # how many failures an answer names inline; every one is in the file the page names
MAX_RECORD_BYTES = 16 << 20       # one record (a JSON Lines line, an array element, a CSV field) larger than this is rejected, named
MAX_DOCUMENT_BYTES = 256 << 20    # a JSON document read whole (it names no array first) larger than this is unsupported, named
MAX_EXPANDED_BYTES = 4 << 30      # per file, after decompression
MAX_SCAN_CHARS = 1 << 20          # a string longer than this is withheld whole, not scanned
MAX_DEPTH = 200                   # a value nested deeper than this is withheld whole
INLINE_BUDGET = 4 << 20           # bytes of rows an answer carries inline; the rest of a page is in its file
MAX_DISTINCT = 1000000            # distinct values a summary table counts; beyond it they are counted as uncounted
MAX_FIELD_BYTES = 64 << 20        # one CSV line (a field may span lines) longer than this stops the file, named
CHUNK = 1 << 20
DEADLINE = [None]


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def scrub_all(value):
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, dict):
        return {k: scrub_all(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub_all(v) for v in value]
    return value


def fail(message, **extra):
    """An error answer: JSON, exit 1, the same `status` every answer of this pack carries. A name in it that is shaped
    like a credential is withheld like any other output."""
    print(json.dumps({"error": scrub(str(message)), "status": "failed",
                      "status_basis": "the tool stopped with an error (see error)", **scrub_all(extra)}, default=str))
    raise SystemExit(1)


def read_args():
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=type(exc).__name__)
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args


def want_str(args, key, required=None):
    value = args.get(key)
    if value is None:
        if required:
            fail(required)
        return None
    if not isinstance(value, str) or not value or "\0" in value:
        fail("%s must be a non-empty string" % key)
    return value


def want_bool(args, key, default=False):
    value = args.get(key, default)
    if not isinstance(value, bool):
        fail("%s must be true or false" % key)
    return value


def want_int(args, key, default, minimum=1, maximum=None):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or (maximum is not None and value > maximum):
        fail("%s must be an integer of at least %d%s" % (key, minimum, "" if maximum is None else " and at most %d" % maximum))
    return value


def want_str_list(args, key):
    value = args.get(key)
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(v, (str, int)) and not isinstance(v, bool) for v in value):
        fail("%s must be a list of strings" % key)
    return [str(v) for v in value]


def want_regex(args, key):
    text = want_str(args, key)
    if text is None:
        return None
    if len(text) > 2000:
        fail("%s is longer than 2000 characters" % key)
    try:
        return re.compile(text, re.I)
    except re.error as exc:
        fail("%s is not a valid regex" % key, reason=str(exc))


def start_clock(args, default=540, maximum=580):
    seconds = args.get("time_limit_seconds", default)
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds < 1 or seconds > maximum:
        fail("time_limit_seconds must be a number from 1 to %d" % maximum)
    DEADLINE[0] = time.monotonic() + seconds
    return seconds


def out_of_time():
    return DEADLINE[0] is not None and time.monotonic() > DEADLINE[0]


_PAGINATION = re.compile(r"(?i)next.?(page.?)?(token|link)|continuation")


def pagination_key(name):
    """A key of an API response that names the next page: the export is one page of more (the key's value is a token, and is
    never printed)."""
    return bool(_PAGINATION.search(str(name)))


def compact(row, keep=("success", "time_utc")):
    """A row without its empty fields; an unknown that means something (a null success, a time that could not be decoded) stays."""
    return {k: v for k, v in row.items() if k in keep or v not in (None, "", {}, [])}


def status_of(failed, complete, basis_complete, basis_partial, basis_failed):
    """`status`, with the reason: complete (every record of the supplied files was read, nothing was left out), partial
    (some were, and the answer names what was not) or failed. Complete says nothing about the export's own coverage."""
    if failed:
        return {"status": "failed", "status_basis": basis_failed}
    if complete:
        return {"status": "complete", "status_basis": basis_complete}
    return {"status": "partial", "status_basis": basis_partial}


# ---- where an output may be written ------------------------------------------------------------------------------


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place outside it, the run directory itself, or
    anything under inputs/ is refused. A string check is not enough: `work/../inputs/x`, an absolute path and a symlink
    that points out all name a place the tool must not write, so the path is resolved first and directories compared.
    In a job the run directory is read-only and only $OUT is written, so a place outside $OUT is refused with the way
    to name one (work/<your agent id>/..., which the harness maps to $OUT), not left to fail on a read-only file system."""
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    if in_job():
        base = Path(os.environ["OUT"]).resolve()
        if dest == base or base not in dest.parents:
            fail("%s is not under this job's output directory: a job writes only $OUT, and the run directory is read-only. "
                 "Name a place under work/<your agent id>/ and the harness maps it there, or leave %s out." % (what, what),
                 **{what: str(out)})
    return str(dest.relative_to(root))


def shown_output(path):
    """How an output is named in an answer: a job's $OUT is sealed as store/jobs/<job>/out, so a place under it is
    shown as it will be cited."""
    try:
        rel = Path(path).resolve().relative_to(Path(os.environ["OUT"]).resolve())
        return "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ["JOB_ID"]), rel.as_posix())
    except (KeyError, ValueError, OSError):
        return str(path)


def same_bytes(a, b):
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                x, y = fa.read(CHUNK), fb.read(CHUNK)
                if x != y:
                    return False
                if not x:
                    return True
    except OSError:
        return False


def publish(tmp, path):
    """Move a finished file to `path` without replacing what is there: a file at the name is an earlier answer (a
    complete one, perhaps, where this run was cut short by a lower limit) and stays; this one is kept beside it as
    name.2.ext, unless it holds the same bytes, when the file already there is it. Returns the path it has."""
    stem, ext = os.path.splitext(str(path))
    k = 1
    while True:
        candidate = Path(stem + ("" if k == 1 else ".%d" % k) + ext)
        try:
            os.link(tmp, candidate)
        except FileExistsError:
            if same_bytes(tmp, candidate):
                os.unlink(tmp)
                return candidate
            k += 1
            continue
        except OSError:                                   # a file system with no hard links: a look, then a rename
            if os.path.lexists(candidate):
                if same_bytes(tmp, candidate):
                    os.unlink(tmp)
                    return candidate
                k += 1
                continue
            os.rename(tmp, candidate)
            return candidate
        os.unlink(tmp)
        return candidate


_TEMPS = set()


def _drop_unpublished():
    """A refused or failed run leaves no half-written result behind: only a finished file is published."""
    for path in list(_TEMPS):
        try:
            os.unlink(path)
        except OSError:
            pass


atexit.register(_drop_unpublished)


class LosslessPage:
    """The page an answer carries, and the whole in a file it names. Rows past `limit` (or past the inline byte budget)
    go to a JSON Lines file, so nothing is cut: under $OUT/tool-output in a job, work/<agent>/tool-output otherwise, with a
    random name (never a digest of the request). With `dest` the whole is always written there (never over a file that is
    already there: it is kept and this one named beside it). Rows are written with ASCII escapes, so a lone surrogate
    from a non-UTF-8 name survives and no row can raise."""

    def __init__(self, tool, limit, dest=None, budget=INLINE_BUDGET):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit, self.budget, self.dest = limit, budget, dest
        self.page, self.total, self.bytes = [], 0, 0
        self._out = self._tmp = None
        if dest:
            self.path = Path(dest)
            self._open_tmp(self.path.parent)
        else:
            name = "%s-%s.jsonl" % (self.tool, secrets.token_hex(8))
            job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
            if job and out:
                self.path = Path(out) / "tool-output" / name
            else:
                agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
                self.path = Path("work") / agent / "tool-output" / name

    def _open_tmp(self, directory):
        try:
            directory.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=directory, prefix=".%s-" % self.tool)
            self._tmp = Path(name)
            _TEMPS.add(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace")
        except OSError as exc:
            fail("the whole result could not be written: %s cannot be created (%s)" % (shown_output(directory), describe(exc)))

    def _write(self, text):
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            fail("the whole result could not be written to %s: %s" % (shown_output(self.path), describe(exc)))

    def add(self, row):
        text = json.dumps(row, default=str)
        self.total += 1
        if self._out is None and (len(self.page) >= self.limit or self.bytes + len(text) > self.budget):
            self._open_tmp(self.path.parent)
            for kept in self.page:
                self._write(json.dumps(kept, default=str))
        if self._out is not None:
            self._write(text)
        if len(self.page) < self.limit and self.bytes + len(text) <= self.budget:
            self.page.append(row)
            self.bytes += len(text)

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                final = publish(self._tmp, self.path)
                _TEMPS.discard(str(self._tmp))
            except OSError as exc:
                fail("the whole result could not be written to %s: %s" % (shown_output(self.path), describe(exc)))
            result["all_results"] = shown_output(final)
            result["all_results_format"] = "JSON Lines, one complete result per line"
            if str(final) != str(self.path):
                result["all_results_note"] = "a different file was already at %s and was kept; this result is beside it" % shown_output(self.path)
        return result


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The secret-safe output pattern of recovery_key_scan (docs/packs.md, "Secrets and sensitive output"), copied
    unchanged but for the file's name and the tool named in the refusal. With `enabled` false it writes nothing and
    `summary()` says so. Enabled, it is refused outside a job; inside one the file is created at once, before anything
    is read (mode 0600, O_EXCL and O_NOFOLLOW: a file or a link already at that name is refused by name, a dangling link
    included), so with nothing withheld it stays an empty file and the answer says written: 0.
    """

    def __init__(self, enabled, name, tool):
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
                "file, not a sealed secret output. Run this as job_run tool=%s with "
                "secret_output: true, and ask again there. Nothing was written." % tool
            )
        self.path = Path(self.out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), name)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.shown)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.shown, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace")

    def add(self, finding_id, locator, value):
        if not self.enabled:
            return
        self._fh.write(json.dumps({"finding_id": finding_id, **locator, "value": value}, default=str))
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
            "format": "JSON Lines, mode 0600: finding_id, file (the real path), record, line, pointer, why, value" if self.enabled else None,
        }


# ---- withholding: nothing shaped like a credential is printed ----------------------------------------------------
# The values a cloud log can carry that are secrets are named, or they are shaped, or neither. A name or a shape is a
# way to recognise some of them and never all, so the skill says to run the tool as a job with secret_output: true
# whenever the export may hold request parameters or properties; what the two rules catch is withheld regardless, in
# every channel (rows, paths, error messages, the files the answer names), the same strings in all three tools.

REDACTED = re.compile(r"^\W*(?:hidden_due_to_security_reasons|redacted|masked|removed|\*+|x{3,}|\[\])\W*$", re.I)
SENSITIVE_EXACT = {
    "password", "newpassword", "oldpassword", "currentpassword", "passwd", "pwd", "passphrase", "passcode", "pin", "otp",
    "secret", "clientsecret", "secretkey", "secretaccesskey", "secretstring", "secretbinary", "accesskeysecret",
    "sessiontoken", "securitytoken", "accesstoken", "refreshtoken", "idtoken", "bearertoken", "authtoken", "token",
    "authorization", "proxyauthorization", "cookie", "setcookie", "apikey", "privatekey", "privatekeypem",
    "sharedaccesskey", "accountkey", "connectionstring", "credential", "credentials", "assertion", "samlresponse",
    "mfasecret", "verificationcode", "authorizationcode", "sastoken", "sassignature", "signature",
}
SENSITIVE_SUFFIX = ("password", "passwd", "passphrase", "secret", "apikey", "privatekey", "sessiontoken", "securitytoken",
                    "accesstoken", "refreshtoken", "clientsecret", "token")
NOT_SECRET_TOKEN = ("nexttoken", "pagetoken", "continuationtoken", "paginationtoken", "nextpagetoken", "pagingtoken",
                    "startingtoken", "nextmarkertoken")
CONTAINERS = ("credential", "credentials")
_NAME_CACHE = {}


def is_container_name(name):
    """`credentials` names a group of fields (an access key id, an expiry, a token): each is judged by its own name."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower()) in CONTAINERS


def name_is_sensitive(name):
    hit = _NAME_CACHE.get(name)
    if hit is None:
        flat = re.sub(r"[^a-z0-9]", "", str(name).lower())
        hit = flat in SENSITIVE_EXACT or (len(flat) > 6 and flat.endswith(SENSITIVE_SUFFIX) and not flat.endswith(NOT_SECRET_TOKEN))
        if len(_NAME_CACHE) < 20000:
            _NAME_CACHE[name] = hit
    return hit


_B64_RUN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{128,}={0,2}(?![A-Za-z0-9+/_-])")
TOKEN_RULES = [
    ("a JSON Web Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"), 0),
    ("a private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|[\s\S]*)"), 0),
    ("an authorization header value", re.compile(r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{16,})"), 1),
    ("a value assigned to a credential name", re.compile(
        r"(?i)(?<![A-Za-z0-9])(?:password|passwd|pwd|passphrase|secret|client[_-]?secret|api[_-]?key|access[_-]?token|"
        r"refresh[_-]?token|id[_-]?token|session[_-]?token|security[_-]?token|auth[_-]?token|token|sig|signature|"
        r"sas[_-]?token|authorization|aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key)"
        r"[\"']?\s*[:=]\s*[\"']?([^\s\"'&;,<>{}\[\]]{4,})"), 1),
    ("a token of a known family", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}\b|"
        r"ya29\.[0-9A-Za-z_-]{20,}|1//0[0-9A-Za-z_-]{30,}|(?:IQoJb3JpZ2lu|FQoGZXIvYXdz|FwoGZXIvYXdz)[A-Za-z0-9+/=]{40,}|"
        r"[A-Za-z0-9_.-]{3}[0-9]Q~[A-Za-z0-9_.~-]{30,}|[01]\.A[A-Za-z0-9_-]{50,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,})"), 0),
]
WITHHELD_TEXT = "[withheld: %s, %d characters]"
LOCAL = {"paths": 0, "text": 0}


def _random_like(run):
    """A long run that looks like random base64 and not like a path or a name: mixed case and digits in the proportions
    random text has (a long path is mostly lower case with few capitals)."""
    n = len(run)
    upper = sum(1 for ch in run if "A" <= ch <= "Z")
    lower = sum(1 for ch in run if "a" <= ch <= "z")
    digit = sum(1 for ch in run if "0" <= ch <= "9")
    return upper * 100 >= 15 * n and lower * 100 >= 15 * n and digit * 100 >= 5 * n


def token_spans(text):
    """(start, end, why) of each stretch of `text` shaped like a credential, in order and not overlapping."""
    spans = []
    for why, rx, group in TOKEN_RULES:
        for m in rx.finditer(text):
            start, end = m.span(group)
            if group and (REDACTED.match(text[start:end]) or text[start:end].lower() in ("bearer", "basic", "digest", "negotiate")):
                continue
            spans.append((start, end, why))
    for m in _B64_RUN.finditer(text):
        if _random_like(m.group(0)):
            spans.append((m.start(), m.end(), "a long unbroken base64-like run"))
    spans.sort()
    merged = []
    for s in spans:
        if merged and s[0] < merged[-1][1]:
            if s[1] > merged[-1][1]:
                merged[-1] = (merged[-1][0], s[1], merged[-1][2])
            continue
        merged.append(s)
    return merged


def scrub(text):
    """`text` with each stretch shaped like a credential replaced by a marker that holds only its length."""
    if not isinstance(text, str) or len(text) < 8:
        return text
    if len(text) > MAX_SCAN_CHARS:
        LOCAL["text"] += 1
        return WITHHELD_TEXT % ("text longer than 1 MiB", len(text))
    spans = token_spans(text)
    if not spans:
        return text
    out, at = [], 0
    for start, end, why in spans:
        out.append(text[at:start])
        out.append(WITHHELD_TEXT % (why, end - start))
        LOCAL["text"] += 1
        at = end
    out.append(text[at:])
    return "".join(out)


def shown_path(path):
    """A path as it may be printed: a component shaped like a credential (a file named after a token) is withheld."""
    if not isinstance(path, str):
        return path
    parts = path.split("/")
    for i, part in enumerate(parts):
        clean = scrub(part)
        if clean != part:
            parts[i] = clean
            LOCAL["paths"] += 1
    return "/".join(parts)


class Withheld:
    """Cleans values on their way into an answer, counts what was withheld, lists where, and hands the originals to the
    values file when the caller asked for it (write_values, in a job). A row's `locator` says which record it came from."""

    VALUE_KEYS = ("Value", "NewValue", "OldValue", "value", "newValue", "oldValue")

    def __init__(self, vault, limit):
        self.vault = vault
        self.count = 0
        self.reasons = {}
        self.page = LosslessPage("withheld", limit)

    def note(self, locator, pointer, why, length, original):
        self.count += 1
        self.reasons[why] = self.reasons.get(why, 0) + 1
        fid = "W%06d" % self.count
        shown = {k: (shown_path(v) if k == "file" else v) for k, v in locator.items()}
        self.page.add({"finding_id": fid, **shown, "pointer": scrub(pointer), "why": why, "length": length})
        if self.vault is not None:
            self.vault.add(fid, {**locator, "pointer": pointer, "why": why}, original)

    @staticmethod
    def size_of(value):
        if isinstance(value, str):
            return "%d characters" % len(value)
        if isinstance(value, dict):
            return "object with %d keys" % len(value)
        if isinstance(value, list):
            return "list of %d items" % len(value)
        return "a number"

    def clean(self, value, locator, pointer="", depth=0):
        if isinstance(value, str):
            return self.clean_text(value, locator, pointer)
        if depth > MAX_DEPTH and isinstance(value, (dict, list)):
            self.note(locator, pointer, "nested deeper than %d levels" % MAX_DEPTH, len(json.dumps(value, default=str)), value)
            return "[withheld: nested deeper than %d levels, %s]" % (MAX_DEPTH, self.size_of(value))
        if isinstance(value, dict):
            named = None
            for key in ("Name", "name"):
                if isinstance(value.get(key), str):
                    named = value[key]
                    break
            pair_secret = named is not None and name_is_sensitive(named)
            out = {}
            for k, v in value.items():
                ks = str(k)
                point = "%s/%s" % (pointer, ks.replace("~", "~0").replace("/", "~1"))
                safe_key = scrub(ks)
                if safe_key in out:
                    safe_key = "%s#%d" % (safe_key, len(out))
                sensitive = name_is_sensitive(ks) or (pair_secret and ks in self.VALUE_KEYS)
                if sensitive and is_container_name(ks) and isinstance(v, (dict, list)):
                    sensitive = False
                if sensitive and v not in (None, "", True, False) and not (isinstance(v, str) and REDACTED.match(v)):
                    self.note(locator, point, "credential-named field", len(v) if isinstance(v, str) else len(json.dumps(v, default=str)), v)
                    out[safe_key] = "[withheld: credential-named field, %s]" % self.size_of(v)
                else:
                    out[safe_key] = self.clean(v, locator, point, depth + 1)
            return out
        if isinstance(value, list):
            return [self.clean(v, locator, "%s/%d" % (pointer, i), depth + 1) for i, v in enumerate(value)]
        return value

    def clean_text(self, text, locator, pointer):
        if len(text) < 8:
            return text
        if len(text) > MAX_SCAN_CHARS:
            self.note(locator, pointer, "text longer than 1 MiB", len(text), text)
            return WITHHELD_TEXT % ("text longer than 1 MiB", len(text))
        spans = token_spans(text)
        if not spans:
            return text
        out, at = [], 0
        for start, end, why in spans:
            out.append(text[at:start])
            out.append(WITHHELD_TEXT % (why, end - start))
            self.note(locator, "%s@%d" % (pointer, start), why, end - start, text[start:end])
            at = end
        out.append(text[at:])
        return "".join(out)

    def summary(self):
        page = self.page.finish()
        return {"count": self.count, "by_reason": self.reasons, "locators": self.page.page, "page": page,
                "text_withheld_from_paths_and_messages": LOCAL["paths"] + LOCAL["text"]}


# ---- timestamps -------------------------------------------------------------------------------------------------

_EPOCH = datetime.datetime(1970, 1, 1)
ISO_STAMP = re.compile(r"^\s*(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?\s*(Z|z|[+-]\d{2}(?::?\d{2})?)?\s*$")
SLASH_STAMP = re.compile(r"^\s*(\d{1,2})/(\d{1,2})/(\d{4})[ ,T]+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?\s*([AaPp][Mm])?\s*(Z|z|[+-]\d{2}(?::?\d{2})?)?\s*$")


def _clock_ok(y, mo, d, h, mi, s):
    return 1 <= mo <= 12 and 1 <= d <= calendar.monthrange(y, mo)[1] and 0 <= h <= 23 and 0 <= mi <= 59 and 0 <= s <= 59


def slash_order(raw):
    """'mdy', 'dmy', 'either' (the two fields are equal) or 'ambiguous' for a day/month/year string; None if it is not one."""
    m = SLASH_STAMP.match(raw) if isinstance(raw, str) else None
    if not m:
        return None
    a, b = int(m.group(1)), int(m.group(2))
    if a == b:
        return "either"
    if a > 12 >= b:
        return "dmy"
    if b > 12 >= a:
        return "mdy"
    return "ambiguous" if a <= 12 and b <= 12 else None


def parse_stamp(raw, order=None, assume_utc=False):
    """A time as the export wrote it, decoded without a guess.

    Returns {utc, ns, status, basis}. `utc` is ISO 8601 UTC with the fractions as written; `ns` is nanoseconds from the
    1970 epoch (for sorting and differences). `status` is zoned (the string carried an offset or Z), assumed_utc (it carried
    none and the caller said to read it as UTC), no_zone (it carried none and nothing was assumed), ambiguous_date_order
    (a day/month/year string with both fields up to 12 and no declared order), unparseable or missing. Nothing is
    assumed unless asked: a clock with no zone is not UTC because it is convenient, and 03/04/2026 is not March because
    a program was written in one country."""
    if raw is None or raw == "":
        return {"utc": None, "ns": None, "status": "missing", "basis": "no time in the record"}
    if not isinstance(raw, str):
        return {"utc": None, "ns": None, "status": "unparseable", "basis": "the time is not a string (%s)" % type(raw).__name__}
    m = ISO_STAMP.match(raw)
    if m:
        y, mo, d, h, mi = (int(m.group(i)) for i in (1, 2, 3, 4, 5))
        s, frac, zone = int(m.group(6) or 0), m.group(7) or "", m.group(8)
        am = None
    else:
        m = SLASH_STAMP.match(raw)
        if not m:
            return {"utc": None, "ns": None, "status": "unparseable", "basis": "not an ISO 8601 or day/month/year time"}
        got = slash_order(raw)
        use = order if order in ("mdy", "dmy") else ("mdy" if got == "mdy" else "dmy" if got == "dmy" else "mdy" if got == "either" else None)
        if use is None:
            return {"utc": None, "ns": None, "status": "ambiguous_date_order",
                    "basis": "both leading fields are 12 or less and no date_order was declared or proved by other rows"}
        if got in ("mdy", "dmy") and got != use:
            return {"utc": None, "ns": None, "status": "unparseable", "basis": "the field order contradicts date_order %s" % use}
        a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        mo, d = (a, b) if use == "mdy" else (b, a)
        h, mi, s, frac, am, zone = int(m.group(4)), int(m.group(5)), int(m.group(6) or 0), m.group(7) or "", m.group(8), m.group(9)
        if am:
            if not 1 <= h <= 12:
                return {"utc": None, "ns": None, "status": "unparseable", "basis": "an hour outside 1-12 beside AM or PM"}
            h = h % 12 + (12 if am.lower() == "pm" else 0)
    if not _clock_ok(y, mo, d, h, mi, s):
        return {"utc": None, "ns": None, "status": "unparseable", "basis": "a date or clock value out of range"}
    offset = 0
    if zone and zone not in ("Z", "z"):
        digits = zone[1:].replace(":", "")
        offset = (int(digits[:2]) * 3600 + int(digits[2:4] or 0) * 60) * (1 if zone[0] == "+" else -1)
        status, basis = "zoned", "the string carries the offset %s" % zone
    elif zone:
        status, basis = "zoned", "the string carries Z"
    elif assume_utc:
        status, basis = "assumed_utc", "the string carries no zone; read as UTC because assume_utc was set"
    else:
        return {"utc": None, "ns": None, "status": "no_zone", "basis": "the string carries no zone and assume_utc was not set"}
    try:
        secs = calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0)) - offset
        base = (_EPOCH + datetime.timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S")
    except (ValueError, OverflowError):
        return {"utc": None, "ns": None, "status": "unparseable", "basis": "a date outside the years 1 to 9999"}
    ns = secs * 1000000000 + (int(frac.ljust(9, "0")) if frac else 0)
    if not -(1 << 63) < ns < (1 << 63):
        return {"utc": None, "ns": None, "status": "unparseable", "basis": "a date outside 1678-2261, the range of nanoseconds a 64-bit integer holds"}
    return {"utc": base + ("." + frac if frac else "") + "Z", "ns": ns, "status": status, "basis": basis}


def ns_to_utc(ns):
    if ns is None:
        return None
    secs, rest = divmod(ns, 1000000000)
    try:
        base = (_EPOCH + datetime.timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S")
    except (ValueError, OverflowError):
        return None
    return base + ("." + ("%09d" % rest).rstrip("0") if rest else "") + "Z"


class Tally:
    """A count of each distinct value, bounded: past MAX_DISTINCT a new value is counted in `uncounted`, never lost
    silently (the records themselves are in the whole-result file)."""

    def __init__(self):
        self.counts = {}
        self.uncounted = 0

    def add(self, key):
        if key in self.counts:
            self.counts[key] += 1
        elif len(self.counts) < MAX_DISTINCT:
            self.counts[key] = 1
        else:
            self.uncounted += 1

    def rows(self):
        return [{"value": k, "count": v} for k, v in sorted(self.counts.items(), key=lambda kv: (-kv[1], str(kv[0])))]

def dbtext(value):
    """A string for SQLite: a lone surrogate (a JSON escape such as \\ud800, or a name that is not UTF-8) cannot be stored as text, so
    it is kept as its escape; every other character is unchanged."""
    return value.encode("utf-8", "backslashreplace").decode("utf-8") if isinstance(value, str) else value


class Skips:
    """What a directory walk did not read: the first rows are kept for the answer, every one is counted."""

    def __init__(self, keep=100):
        self.items, self.total, self.by_name, self.keep = [], 0, 0, keep

    def append(self, row):
        self.total += 1
        if row["reason"].startswith("its name"):
            self.by_name += 1
        if len(self.items) < self.keep:
            self.items.append(row)

    @property
    def unreadable(self):
        return self.total - self.by_name


def named(items, limit=FIRST_PROBLEMS):
    """The first `limit` of a list, for an answer that also gives the count."""
    return list(items[:limit])


def open_temp_db(prefix):
    """A SQLite database on disk (in $OUT in a job, where only $OUT is writable; the temporary directory otherwise), so a
    large export does not have to fit in memory. Returns (db, directory, where); in memory only if no directory can be made."""
    try:
        directory = tempfile.mkdtemp(prefix=prefix, dir=os.environ["OUT"] if in_job() else None)
        return sqlite3.connect(os.path.join(directory, "work.sqlite")), directory, "a temporary file"
    except (OSError, sqlite3.Error):
        return sqlite3.connect(":memory:"), None, "memory (no temporary directory could be created)"


def remove_temp_db(db, directory):
    try:
        db.close()
    except sqlite3.Error:
        pass
    if directory:
        for name in os.listdir(directory):
            try:
                os.unlink(os.path.join(directory, name))
            except OSError:
                pass
        try:
            os.rmdir(directory)
        except OSError:
            pass


# ---- reading files: a bounded stream of JSON values -------------------------------------------------------------

BOM = "﻿"
REPLACEMENT = "�"
_SPACE = re.compile(r"\s*")
_DEC = json.JSONDecoder()


def walk_inputs(top, wanted, skipped):
    """The regular files under `top`: the files of a directory in name order, then its subdirectories in name order. A link,
    a special file (a pipe is never opened) and an unlistable directory are named in `skipped`, and so is a file whose name
    `wanted` refuses."""
    stack = [top]
    found = []
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            skipped.append({"path": shown_path(directory), "reason": "the directory could not be listed", "error": describe(exc)})
            continue
        subdirs = []
        for entry in entries:
            try:
                if entry.is_symlink():
                    skipped.append({"path": shown_path(entry.path), "reason": "a symbolic link: links are not followed"})
                elif entry.is_dir(follow_symlinks=False):
                    subdirs.append(entry.path)
                elif not stat.S_ISREG(entry.stat(follow_symlinks=False).st_mode):
                    skipped.append({"path": shown_path(entry.path), "reason": "not a regular file: it is not opened"})
                elif wanted(entry.name):
                    found.append(entry.path)
                else:
                    skipped.append({"path": shown_path(entry.path), "reason": "its name is not one this tool reads"})
            except OSError as exc:
                skipped.append({"path": shown_path(entry.path), "reason": "the entry could not be examined", "error": describe(exc)})
        stack.extend(reversed(subdirs))
    return found


class Source:
    """One file as a stream of text. Gzip is recognised by its magic bytes (not its name) and expanded as it is read, at most
    `cap` bytes of expansion; UTF-8 is assumed, UTF-16 where a byte order mark says so; bytes that do not decode become U+FFFD and are counted in `replaced`; a read that fails (a
    truncated gzip, a failed CRC) is kept in `error` with everything read before it."""

    def __init__(self, path, cap):
        self.path, self.cap = path, cap
        self.buf, self.pos = "", 0
        self.eof = False
        self.bytes_read = 0
        self.compressed = False
        self.error = None
        self.capped = False
        self.replaced = 0
        self.line = 1
        self.chars_before = 0
        self._dec = codecs.getincrementaldecoder("utf-8")("replace")
        self.encoding = "utf-8"
        self._first = True
        self.fh = self._raw = None
        try:
            if not stat.S_ISREG(os.stat(path).st_mode):
                raise OSError(errno.EINVAL, "not a regular file")
            self._raw = open(path, "rb")
            magic = self._raw.read(2)
            self._raw.seek(0)
            if magic == b"\x1f\x8b":
                self.compressed = True
                self.fh = gzip.GzipFile(fileobj=self._raw)
            else:
                self.fh = self._raw
        except OSError as exc:
            self.error = describe(exc)
            self.eof = True

    def close(self):
        for h in (self.fh, self._raw):
            try:
                if h is not None:
                    h.close()
            except OSError:
                pass

    def fill(self):
        """Read one more chunk into the buffer; False at the end."""
        if self.eof:
            return False
        room = self.cap - self.bytes_read
        try:
            data = self.fh.read(min(CHUNK, room + 1))
        except (OSError, EOFError, zlib.error) as exc:
            self.error = "%s while reading%s" % (describe(exc), " the compressed stream" if self.compressed else "")
            self.eof = True
            data = b""
        if len(data) > room:
            data = data[:room]
            self.capped = True
            self.eof = True
        elif not data:
            self.eof = True
        if self._first and data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            # A byte order mark: the export is UTF-16 (PowerShell's Export-Csv -Encoding Unicode writes it), not UTF-8.
            self._dec = codecs.getincrementaldecoder("utf-16")("replace")
            self.encoding = "utf-16"
        self.bytes_read += len(data)
        text = self._dec.decode(data, final=self.eof)
        if self._first and text:
            self._first = False
            if text[0] == BOM:
                text = text[1:]
        self.replaced += text.count(REPLACEMENT)
        self.buf += text
        return bool(data)

    def advance(self, new_pos):
        self.line += self.buf.count("\n", self.pos, new_pos)
        self.pos = new_pos
        if self.pos > 4 * CHUNK:
            self.chars_before += self.pos
            self.buf = self.buf[self.pos:]
            self.pos = 0

    def ensure(self, n):
        while len(self.buf) - self.pos < n and self.fill():
            pass

    def skip_ws(self):
        while True:
            end = _SPACE.match(self.buf, self.pos).end()
            self.advance(end)
            if self.pos < len(self.buf) or not self.fill():
                return

    def offset(self):
        return self.chars_before + self.pos


class TooLong(Exception):
    pass


def _decode_at(src, limit, lead=""):
    """One JSON value at the read position (with `lead` put in front of the text, to read the rest of an object whose
    first key was already consumed), reading more while it is incomplete; `limit` bounds the text held while waiting for it
    to end. Returns the value and the buffer index after it. The position is not moved."""
    while True:
        text = lead + src.buf[src.pos:] if lead else src.buf
        at = 0 if lead else src.pos
        try:
            value, end = _DEC.raw_decode(text, at)
            if not isinstance(value, (dict, list)) and end >= len(text) and not src.eof:
                raise json.JSONDecodeError("a value that may continue", text, end)
            return value, (src.pos + end - len(lead)) if lead else end
        except json.JSONDecodeError as exc:
            if src.eof:
                raise
            # An error well inside the text is a real one; at its end, or in an unterminated string, the record may only be
            # incomplete, and more is read (within `limit`).
            if exc.pos < len(text) - 16 and not exc.msg.startswith("Unterminated string"):
                raise
            if len(src.buf) - src.pos > limit:
                raise TooLong()
            src.fill()
        except RecursionError:
            raise json.JSONDecodeError("nested too deeply", text, at)


_PAIR = re.compile(r'\s*"((?:[^"\\]|\\.)*)"\s*:\s*(?:"(?:[^"\\]|\\.)*"|-?[0-9.eE+-]+|true|false|null)\s*,')


def envelope_start(env_rx, buf, pos):
    """If the object at `pos` is `{` then scalar members (an @odata.context, a kind, an etag) then a named array of records:
    (the array's key, the buffer index after its `[`, the names of the members before it); otherwise None."""
    at = pos + 1
    leading = []
    while True:
        m = env_rx.match(buf, at)
        if m:
            return m.group(1), m.end(), leading
        p = _PAIR.match(buf, at)
        if not p or len(leading) > 64:
            return None
        leading.append(p.group(1))
        at = p.end()


def read_units(src, envelope_keys, record_cap=MAX_RECORD_BYTES, document_cap=MAX_DOCUMENT_BYTES):
    """Yield the records of a JSON file as ("item", info, value) or ("reject", info, reason), one by one, whatever the
    shape: an array, an object whose first key is a named array of records (streamed, with the object's other keys
    read after it), JSON Lines (a bad line is rejected and the next is read), or one pretty-printed document (read
    whole, within `document_cap`); several arrays or envelopes one after another are read in turn. `info` is {record,
    line, offset, chars, envelope}. After the last unit `src.mode` names the shape, `src.extra_keys` the other top-level
    keys of the envelopes (names only) and `src.stopped` says why reading ended before the end of the file, if it did."""
    src.mode, src.extra_keys, src.stopped, src.envelope = "empty", [], None, None
    count, modes, extra = [0], [], set()
    env_rx = re.compile(r'\s*"(%s)"\s*:\s*\[' % "|".join(re.escape(k) for k in envelope_keys)) if envelope_keys else None

    def info(line, offset, chars, envelope):
        count[0] += 1
        return {"record": count[0], "line": line, "offset": offset, "chars": chars, "envelope": envelope}

    def finish():
        src.extra_keys = sorted(extra)
        src.mode = modes[0] if len(set(modes)) == 1 else ("mixed" if modes else "empty")

    while True:
        src.ensure(4096)
        src.skip_ws()
        src.ensure(4096)
        if src.pos >= len(src.buf):
            break
        first = src.buf[src.pos]
        env = envelope_start(env_rx, src.buf, src.pos) if env_rx and first == "{" else None
        if first == "[" or env:
            modes.append("envelope" if env else "array")
            key = env[0] if env else None
            if key:
                src.envelope = src.envelope or key
                extra.update(env[2])
            src.advance(env[1] if env else src.pos + 1)
            src.skip_ws()
            expecting_item = True
            while True:
                while src.pos >= len(src.buf):
                    if not src.fill():
                        src.stopped = "the array was not closed: the file ends inside it"
                        finish()
                        return
                here = src.buf[src.pos]
                if here == "]":
                    src.advance(src.pos + 1)
                    break
                if here == ",":
                    if expecting_item:
                        src.stopped = "an unexpected comma at line %d: the rest of the array was not read" % src.line
                        yield "reject", info(src.line, src.offset(), None, key), "malformed JSON: an unexpected comma"
                        finish()
                        return
                    src.advance(src.pos + 1)
                    src.skip_ws()
                    expecting_item = True
                    continue
                if not expecting_item:
                    src.stopped = "no comma between records at line %d: the rest of the array was not read" % src.line
                    yield "reject", info(src.line, src.offset(), None, key), "malformed JSON: no comma between records"
                    finish()
                    return
                start_line, start_off, start_pos = src.line, src.offset(), src.pos
                try:
                    value, end = _decode_at(src, record_cap)
                except TooLong:
                    src.stopped = "a record larger than max_record_bytes at line %d: the rest of the array was not read" % start_line
                    yield "reject", info(start_line, start_off, None, key), "a record larger than max_record_bytes (%d)" % record_cap
                    finish()
                    return
                except json.JSONDecodeError as exc:
                    src.stopped = "the JSON stopped being valid at line %d (%s): the rest was not read" % (start_line, exc.msg)
                    yield "reject", info(start_line, start_off, None, key), "malformed JSON: %s" % exc.msg
                    finish()
                    return
                src.advance(end)
                yield "item", info(start_line, start_off, end - start_pos, key), value
                expecting_item = False
                src.skip_ws()
            if key:
                # the rest of the envelope object: its other keys, names only (a next-page token is a token)
                src.skip_ws()
                if src.pos < len(src.buf) and src.buf[src.pos] == ",":
                    src.advance(src.pos + 1)
                try:
                    obj, end = _decode_at(src, record_cap, lead="{")
                except (TooLong, json.JSONDecodeError):
                    src.stopped = "the object around the records does not end validly: its other keys were not read"
                    finish()
                    return
                src.advance(end)
                extra.update(str(k) for k in obj)
            continue
        # not an array: one pretty-printed document, or JSON Lines to the end of the file
        line_end = src.buf.find("\n", src.pos)
        if src.buf[src.pos: line_end if line_end >= 0 else len(src.buf)].strip() == "{":
            modes.append("document")
            start_line, start_off, start_pos = src.line, src.offset(), src.pos
            try:
                value, end = _decode_at(src, document_cap)
            except TooLong:
                src.stopped = ("a JSON document larger than max_document_bytes (%d) that does not start with a named array of records: "
                               "it was not read" % document_cap)
                yield "reject", info(start_line, start_off, None, None), src.stopped
                finish()
                return
            except json.JSONDecodeError as exc:
                src.stopped = "the JSON stopped being valid at line %d (%s): the rest was not read" % (start_line, exc.msg)
                yield "reject", info(start_line, start_off, None, None), "malformed JSON: %s" % exc.msg
                finish()
                return
            src.advance(end)
            yield from _expand(value, envelope_keys, info, start_line, start_off, src, extra)
            continue
        modes.append("lines")
        while True:
            i = src.buf.find("\n", src.pos)
            while i < 0 and not src.eof and len(src.buf) - src.pos <= record_cap:
                src.fill()
                i = src.buf.find("\n", src.pos)
            if i < 0 and src.pos >= len(src.buf):
                break
            start_line, start_off = src.line, src.offset()
            if (i if i >= 0 else len(src.buf)) - src.pos > record_cap:
                size = 0
                while True:
                    i = src.buf.find("\n", src.pos)
                    if i >= 0:
                        size += i - src.pos
                        src.advance(i + 1)
                        break
                    size += len(src.buf) - src.pos
                    src.advance(len(src.buf))
                    if not src.fill():
                        break
                yield "reject", info(start_line, start_off, size, None), "a line larger than max_record_bytes (%d)" % record_cap
                continue
            text = src.buf[src.pos: i if i >= 0 else len(src.buf)]
            src.advance(i + 1 if i >= 0 else len(src.buf))
            stripped = text.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except (ValueError, RecursionError) as exc:
                yield "reject", info(start_line, start_off, len(text), None), "malformed JSON: %s" % getattr(exc, "msg", type(exc).__name__)
                continue
            yield from _expand(value, envelope_keys, info, start_line, start_off, src, extra)
        break
    finish()


def _expand(value, envelope_keys, info, line, offset, src, extra):
    """A parsed top-level value of a lines or document file: an envelope object yields its records, a list its elements."""
    if isinstance(value, dict):
        for key in envelope_keys:
            if isinstance(value.get(key), list):
                src.envelope = src.envelope or key
                extra.update(str(k) for k in value if k != key)
                for element in value[key]:
                    yield "item", info(line, offset, None, key), element
                return
        yield "item", info(line, offset, None, None), value
    elif isinstance(value, list):
        for element in value:
            yield "item", info(line, offset, None, None), element
    else:
        yield "reject", info(line, offset, None, None), "a JSON %s, not a record" % type(value).__name__


# ---- CSV and what both CSV and JSON rows need ------------------------------------------------------------------------


def csv_lines(src):
    """The lines of a CSV file, newline kept, one at a time (a quoted field may span several)."""
    while True:
        i = src.buf.find("\n", src.pos)
        while i < 0 and not src.eof and len(src.buf) - src.pos <= MAX_FIELD_BYTES:
            src.fill()
            i = src.buf.find("\n", src.pos)
        if i < 0 and src.pos >= len(src.buf):
            return
        end = i + 1 if i >= 0 else len(src.buf)
        if end - src.pos > MAX_FIELD_BYTES:
            raise TooLong()
        line = src.buf[src.pos:end]
        src.advance(end)
        yield line


def csv_rows(src, delimiter, field_limit):
    """Yield ("row", info, dict) / ("reject", info, reason) for a CSV file; a bad row is rejected and the next is read; a failure
    of the reader itself stops the file, says where, and keeps what was read."""
    src.mode, src.stopped, src.extra_keys, src.envelope = "csv", None, [], None
    csv.field_size_limit(field_limit)
    reader = csv.reader(csv_lines(src), delimiter=delimiter)
    header, count = None, 0
    while True:
        before = reader.line_num
        try:
            row = next(reader)
        except StopIteration:
            return
        except TooLong:
            src.stopped = "a line longer than %d characters at line %d: the rest of the file was not read" % (MAX_FIELD_BYTES, before + 1)
            yield "reject", {"record": count + 1, "line": before + 1, "offset": src.offset(), "chars": None, "envelope": None}, src.stopped
            return
        except csv.Error as exc:
            src.stopped = "the CSV reader stopped at line %d (%s): the rest of the file was not read" % (before + 1, exc)
            yield "reject", {"record": count + 1, "line": before + 1, "offset": src.offset(), "chars": None, "envelope": None}, "CSV error: %s" % exc
            return
        if not row:
            continue
        if header is None:
            header = row
            src.header = header
            if len(header) == 1 and re.search(r"[;\t|]", header[0]):
                src.stopped = "the header is one column that contains ';', a tab or '|': the file may use another delimiter (pass delimiter)"
                yield "reject", {"record": 0, "line": before + 1, "offset": 0, "chars": None, "envelope": None}, src.stopped
                return
            continue
        count += 1
        info = {"record": count, "line": before + 1, "offset": None, "chars": None, "envelope": None}
        if len(row) != len(header):
            yield "reject", info, "the row has %d fields and the header %d" % (len(row), len(header))
            continue
        yield "row", info, dict(zip(header, row))


def sniff(path):
    """'json' or 'csv', from the first characters of the file's own content (decompressed if it is gzip), never its name."""
    src = Source(path, MAX_EXPANDED_BYTES)
    try:
        src.ensure(4096)
        head = src.buf[src.pos:].lstrip()
    finally:
        src.close()
    return "json" if head[:1] in ("{", "[") else "csv"


def key_map(item):
    return {k.strip().lower(): k for k in item if isinstance(k, str)}


def first_of(item, keys, *names):
    for n in names:
        k = keys.get(n.lower())
        if k is not None and item.get(k) not in (None, ""):
            return item[k]
    return None


# ---- END SHARED BLOCK -------------------------------------------------------------------------------------------

TOOL = "cloudtrail_parse"
PARSER = "cloudtrail_parse/3"
VALUES_NAME = "cloudtrail-values.jsonl"
RECORDS_NAME = "cloudtrail-records.jsonl"
ENVELOPE_KEYS = ("Records", "Events")
ASSUME_EVENTS = ("AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity")
CREATION_TOLERANCE_NS = 5 * 1000000000
CANDIDATE_CAP = 50
EVENT_KEYS = ("eventName", "eventSource", "eventTime", "eventID", "userIdentity")

# What the tool lists for a second look: the API name only. A call recorded is not a change made; the result, the request
# and the configuration in force say what changed.
NOTABLE = {
    "ConsoleLogin": "a console sign-in record (its result is in responseElements, MFA context in additionalEventData)",
    "CreateAccessKey": "an access key creation call",
    "CreateUser": "an IAM user creation call",
    "CreateLoginProfile": "a call that sets a console password on a user",
    "AttachUserPolicy": "a managed policy attachment call (user)",
    "AttachRolePolicy": "a managed policy attachment call (role)",
    "PutUserPolicy": "an inline user policy write call",
    "CreatePolicyVersion": "a managed policy version creation call",
    "UpdateAssumeRolePolicy": "a role trust policy update call",
    "PutBucketPolicy": "a bucket policy write call",
    "PutBucketAcl": "a bucket ACL write call",
    "PutBucketPublicAccessBlock": "a bucket public-access-block setting call",
    "ModifySnapshotAttribute": "a snapshot attribute change call (sharing is one use of it)",
    "ModifyImageAttribute": "an image attribute change call (sharing is one use of it)",
    "DeleteTrail": "a trail deletion call",
    "StopLogging": "a StopLogging call for a trail (what it stopped, and for how long, needs the response, the trail's configuration and the delivery that follows)",
    "UpdateTrail": "a trail update call",
    "GetSecretValue": "a secret value read call",
    "Decrypt": "a key decrypt call",
    "AssumeRole": "a role assumption call",
    "DeleteDetector": "a detector deletion call",
    "DisableSecurityHub": "a call that disables a security hub",
    "RunInstances": "an instance launch call",
}

# Classified by the words in the code, in this order; the code itself is always kept beside the class.
ERROR_CLASSES = [
    ("authorisation_denied", re.compile(r"(?i)accessdenied|unauthorized|notauthorized|forbidden|explicitdeny")),
    ("authentication", re.compile(r"(?i)expiredtoken|invalidclienttokenid|signaturedoesnotmatch|authfailure|unrecognizedclient|"
                                  r"incompletesignature|missingauthentication|invalidsignature|tokenrefreshrequired|invalidaccesskey")),
    ("throttling", re.compile(r"(?i)throttl|requestlimitexceeded|toomanyrequests|slowdown|provisionedthroughput")),
    ("validation", re.compile(r"(?i)validation|invalidparameter|malformedpolicy|invalidinput|missingparameter|invalidrequest|"
                              r"missingrequiredparameter|invalidargument|malformedquery")),
    ("not_found", re.compile(r"(?i)nosuch|notfound|doesnotexist")),
    ("service", re.compile(r"(?i)internalfailure|internalerror|serviceunavailable|internalserver|serviceexception")),
]


def classify_error(code):
    if not code:
        return None
    for name, rx in ERROR_CLASSES:
        if rx.search(str(code)):
            return name
    return "unclassified"


def as_dict(value):
    return value if isinstance(value, dict) else {}


def identity_of(record):
    """The fields of userIdentity that name a principal and its session, as the record gives them."""
    who = as_dict(record.get("userIdentity"))
    out = {"identity_type": who.get("type"), "arn": who.get("arn"), "account": who.get("accountId"),
           "user_name": who.get("userName"), "principal": who.get("principalId"),
           "access_key_id": who.get("accessKeyId")}
    session = as_dict(who.get("sessionContext"))
    issuer = as_dict(session.get("sessionIssuer"))
    if issuer:
        out["assumed_role"] = issuer.get("arn") or issuer.get("userName")
        out["role_account"] = issuer.get("accountId")
    attributes = as_dict(session.get("attributes"))
    if attributes:
        out["session_started"] = attributes.get("creationDate")
        out["mfa"] = attributes.get("mfaAuthenticated")
    source = who.get("sourceIdentity") or session.get("sourceIdentity")
    if source:
        out["source_identity"] = source
    if who.get("invokedBy"):
        out["invoked_by"] = who["invokedBy"]
    return {k: v for k, v in out.items() if v not in (None, "")}


ROLE_ARN = re.compile(r"^arn:([^:]+):iam::(\d{12}):role/(?:.*/)?([^/]+)$")


def derived_session_arn(role_arn, session_name):
    """The assumed-role ARN a successful AssumeRole of this role under this session name would give: in the role ARN's own
    partition, and without the role's path (the session ARN carries the role's name only)."""
    if not isinstance(role_arn, str) or not isinstance(session_name, str):
        return None
    m = ROLE_ARN.match(role_arn)
    return "arn:%s:sts::%s:assumed-role/%s/%s" % (m.group(1), m.group(2), m.group(3), session_name) if m else None


class SessionIndex:
    """The successful AssumeRole-family calls of the supplied records, on disk (a temporary SQLite file, in $OUT in a job),
    looked up by what the response returned. A call with an error recorded is counted and never indexed."""

    def __init__(self):
        self.db, self.dir, self.where = open_temp_db(".cloudtrail-sessions-")
        self.db.executescript(
            "CREATE TABLE assume(id INTEGER PRIMARY KEY, event_id TEXT, name TEXT, ns INTEGER, time TEXT, key_id TEXT, "
            "sess_arn TEXT, derived_arn TEXT, caller TEXT, file TEXT, record INTEGER, shared TEXT, has_response INTEGER);")
        self.indexed = 0
        self.failed = 0
        self.indexes_made = False

    def add(self, row, who, stamp, file, record):
        if row.get("errorCode"):
            self.failed += 1
            return
        request, response = as_dict(row.get("requestParameters")), as_dict(row.get("responseElements"))
        creds, user = as_dict(response.get("credentials")), as_dict(response.get("assumedRoleUser"))
        self.db.execute(
            "INSERT INTO assume(event_id, name, ns, time, key_id, sess_arn, derived_arn, caller, file, record, shared, has_response) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            tuple(dbtext(v) for v in (row.get("eventID") if isinstance(row.get("eventID"), str) else None, row.get("eventName") if isinstance(row.get("eventName"), str) else None,
                                      stamp["ns"], stamp["utc"], creds.get("accessKeyId") if isinstance(creds.get("accessKeyId"), str) else None,
                                      user.get("arn") if isinstance(user.get("arn"), str) else None,
                                      derived_session_arn(request.get("roleArn"), request.get("roleSessionName")),
                                      json.dumps(who, default=str), file, record,
                                      row.get("sharedEventID") if isinstance(row.get("sharedEventID"), str) else None, 1 if response else 0)))
        self.indexed += 1

    def finish_indexing(self):
        self.db.executescript("CREATE INDEX k ON assume(key_id); CREATE INDEX s ON assume(sess_arn); CREATE INDEX d ON assume(derived_arn);")
        self.db.commit()
        self.indexes_made = True

    def find(self, column, value, use_ns):
        rows = self.db.execute(
            "SELECT event_id, name, ns, time, caller, file, record, key_id, sess_arn FROM assume WHERE %s = ? ORDER BY id LIMIT ?" % column,
            (dbtext(value), CANDIDATE_CAP + 1)).fetchall()
        # a call logged after the use cannot have issued the session
        return [r for r in rows if use_ns is None or r[2] is None or r[2] <= use_ns]

    def close(self):
        remove_temp_db(self.db, self.dir)


def session_link(index, who, use_ns, creation_ns, withheld, locator):
    """What the supplied records say about which call issued this AssumedRole session: a candidate with its basis, or
    unresolved with every candidate named, or not found. Never attribution to a person."""
    key, arn = who.get("access_key_id"), who.get("arn")
    rows, basis = [], None
    if key:
        rows, basis = index.find("key_id", key, use_ns), "access_key_id_returned_by_the_call"
    if not rows and arn:
        rows, basis = index.find("sess_arn", arn, use_ns), "session_arn_returned_by_the_call"
        if not rows:
            rows, basis = index.find("derived_arn", arn, use_ns), "session_arn_derived_from_the_request"
        if rows and creation_ns is not None:
            near = [r for r in rows if r[2] is not None and abs(r[2] - creation_ns) <= CREATION_TOLERANCE_NS]
            if near:
                rows, basis = near, basis + "_and_session_creationDate"
            else:
                return {"label": "unresolved", "reason": "%d successful call(s) match the session ARN and none was logged within 5 seconds of the session's "
                                                         "creationDate" % len(rows), "candidate_event_ids": [r[0] for r in rows[:10]]}
    if not rows:
        return {"label": "not_found", "reason": "no successful AssumeRole-family call in the supplied records matches this session's access key id "
                                                "or session ARN, at or before this event; the call may be in records that were not supplied"}
    if len(rows) > 1:
        return {"label": "unresolved", "basis": basis, "reason": "%s successful calls match; none was chosen" % ("more than %d" % CANDIDATE_CAP if len(rows) > CANDIDATE_CAP else len(rows)),
                "candidate_event_ids": [r[0] for r in rows[:CANDIDATE_CAP]]}
    event_id, name, ns, time_utc, caller, file, record, key_id, sess_arn = rows[0]
    link = {"label": "candidate", "basis": basis, "source_event_id": event_id, "source_event": name, "source_time": time_utc,
            "source_file": shown_path(file), "source_record": record,
            "caller": withheld.clean(json.loads(caller), locator, "/session_origin/caller")}
    if sess_arn:
        link["session_arn_agrees"] = sess_arn == arn
    if creation_ns is not None and ns is not None:
        link["within_5_seconds_of_session_creationDate"] = abs(ns - creation_ns) <= CREATION_TOLERANCE_NS
    return link


def is_digest(value):
    return isinstance(value, dict) and ("digestPublicKeyFingerprint" in value or ("logFiles" in value and "digestStartTime" in value))


def event_of(value):
    """(event dict, None) for a CloudTrail event, a `lookup-events` entry's embedded event included; (None, reason) otherwise."""
    if not isinstance(value, dict):
        return None, "a JSON %s, not an event" % type(value).__name__
    if isinstance(value.get("CloudTrailEvent"), str):
        try:
            inner = json.loads(value["CloudTrailEvent"])
        except (ValueError, RecursionError):
            return None, "a lookup-events entry whose CloudTrailEvent text is not valid JSON"
        return (inner, None) if isinstance(inner, dict) and any(k in inner for k in EVENT_KEYS) else (None, "a lookup-events entry whose CloudTrailEvent is not an event")
    if "CloudTrailEvent" in value:
        return None, "a lookup-events entry with no CloudTrailEvent text"
    if is_digest(value):
        return None, "a CloudTrail digest file entry: digest files are not events and are not validated here"
    if not any(k in value for k in EVENT_KEYS):
        return None, "not a CloudTrail event: none of eventName, eventSource, eventTime, eventID or userIdentity"
    return value, None


class Census:
    """What happened to each file, and to the records in it."""

    def __init__(self, limit):
        self.files = LosslessPage("file_census", limit)
        self.rejected = LosslessPage("rejected_records", limit)
        self.problems = []
        self.counts = {"files_found": 0, "files_read": 0, "files_partial": 0, "files_failed": 0, "files_unsupported": 0,
                       "files_empty": 0, "files_skipped": 0, "files_not_attempted": 0, "records_read": 0,
                       "records_rejected": 0, "replacement_characters": 0, "bytes_read": 0}
        self.digest_files = []
        self.pagination = []

    def problem(self, text):
        if len(self.problems) < FIRST_PROBLEMS:
            self.problems.append(scrub(text))


def scan_file(path, census, record_problems, per_record, max_expanded, record_cap):
    """Read one file to its end (or to the deadline) and hand each CloudTrail event to `per_record(event, locator)`.
    Returns the file's census row."""
    src = Source(path, max_expanded)
    shown = shown_path(path)
    row = {"file": shown, "status": "read", "mode": None, "compressed": False, "records": 0, "rejected": 0, "bytes_read": 0}
    events = rejected = 0
    first_reject = None
    digest = False
    stopped_early = False
    try:
        for kind, info, value in read_units(src, ENVELOPE_KEYS, record_cap, max(MAX_DOCUMENT_BYTES, record_cap)):
            if out_of_time():
                stopped_early = True
                break
            locator = {"file": path, "record": info["record"], "line": info["line"]}
            if kind == "reject":
                rejected += 1
                first_reject = first_reject or (info["record"], info["line"], value)
                if record_problems:
                    census.rejected.add({"file": shown, "record": info["record"], "line": info["line"], "chars": info["chars"], "reason": scrub(value)})
                continue
            event, reason = event_of(value)
            if event is None:
                rejected += 1
                first_reject = first_reject or (info["record"], info["line"], reason)
                digest = digest or (is_digest(value))
                if record_problems:
                    census.rejected.add({"file": shown, "record": info["record"], "line": info["line"], "reason": reason})
                continue
            events += 1
            per_record(event, locator, info)
    finally:
        src.close()
    row.update({"mode": getattr(src, "mode", None), "compressed": src.compressed, "encoding": src.encoding, "records": events, "rejected": rejected,
                "bytes_read": src.bytes_read})
    problems = []
    if src.error:
        problems.append(src.error)
    if src.capped:
        problems.append("the expansion reached max_expanded_bytes (%d): the rest of the file was not read" % max_expanded)
    if getattr(src, "stopped", None):
        problems.append(src.stopped)
    if stopped_early:
        problems.append("the time limit ended the read inside this file")
    if rejected:
        problems.append("%d record(s) were not read as events (the first, record %d at line %s: %s); every one is in rejected_records" % (
            rejected, first_reject[0], first_reject[1], first_reject[2]))
    extra = getattr(src, "extra_keys", [])
    markers = [k for k in extra if pagination_key(k)]
    if markers:
        row["pagination_marker_keys"] = markers
    if stopped_early:
        row["status"] = "partial"
    elif src.bytes_read == 0 and not src.error:
        row["status"] = "empty"
    elif events == 0 and src.error:
        row["status"] = "failed"
    elif events == 0 and (rejected or problems):
        row["status"] = "unsupported"
    elif events == 0 and src.mode == "empty":
        row["status"] = "empty"
    elif problems or rejected:
        row["status"] = "partial"
    if problems:
        row["problems"] = [scrub(p) for p in problems]
    if src.replaced:
        row["replacement_characters"] = src.replaced
    if digest:
        row["digest_file"] = True
    if record_problems:
        census.counts["replacement_characters"] += src.replaced
        census.counts["bytes_read"] += src.bytes_read
        census.counts["records_rejected"] += rejected
        census.counts["records_read"] += events
        c = {"read": "files_read", "partial": "files_partial", "failed": "files_failed", "unsupported": "files_unsupported", "empty": "files_empty"}[row["status"]]
        census.counts[c] += 1
        if digest:
            census.digest_files.append(shown)
        if markers:
            census.pagination.append({"file": shown, "keys": markers})
        if row["status"] != "read":
            census.problem("%s: %s" % (shown, "; ".join(row.get("problems", [])) or row["status"]))
        census.files.add(row)
    return row, stopped_early


def timestamp_of(event):
    return parse_stamp(event.get("eventTime"))


def main():
    args = read_args()
    path = want_str(args, "path", "path is required: a CloudTrail file or a directory of them")
    if not os.path.exists(path):
        fail("no such file or directory", path=shown_path(path))
    limit = want_int(args, "limit", DEFAULT_LIMIT)
    out_file = want_str(args, "out_file")
    wanted = set(want_str_list(args, "events"))
    pattern = want_regex(args, "identity")
    errors_only = want_bool(args, "errors_only")
    notable_only = want_bool(args, "notable_only")
    link_sessions = want_bool(args, "link_sessions", True)
    max_expanded = want_int(args, "max_expanded_bytes", MAX_EXPANDED_BYTES, 1024)
    record_cap = want_int(args, "max_record_bytes", MAX_RECORD_BYTES, 1024, 1 << 30)
    write_values = want_bool(args, "write_values")
    seconds = start_clock(args)
    started = time.monotonic()
    if out_file is not None:
        out_file = resolve_output(out_file, "out_file")
    try:
        vault = SecretValues(write_values, VALUES_NAME, TOOL)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False)

    skipped = Skips()
    if os.path.isdir(path):
        targets = walk_inputs(path, lambda n: n.lower().endswith((".json", ".json.gz", ".gz", ".jsonl", ".ndjson", ".jsonl.gz", ".ndjson.gz")), skipped)
        if not targets:
            fail("no CloudTrail files there", path=shown_path(path), skipped=named(skipped.items))
    elif os.path.isfile(path):
        targets = [path]
    else:
        fail("the path is neither a regular file nor a directory: it is not opened", path=shown_path(path))

    census = Census(limit)
    census.counts["files_found"] = len(targets)
    census.counts["files_skipped"] = skipped.total
    withheld = Withheld(vault, limit)
    complete_target = LosslessPage(TOOL, limit, dest=out_file or None)
    index = SessionIndex() if link_sessions else None
    link_totals = {"performed": bool(link_sessions)}
    first_ns = last_ns = None
    zone_counts = {}
    by_event, by_identity, by_address, errors, error_classes = Tally(), Tally(), Tally(), Tally(), {}
    matched = 0
    stop_all = False
    not_attempted = []
    try:
        if index is not None:
            # pass 1: the sessions, within 40 percent of the time; the records themselves are read again in pass 2
            DEADLINE[0] = time.monotonic() + seconds * 0.4

            def remember(event, locator, info):
                if event.get("eventName") in ASSUME_EVENTS:
                    index.add(event, identity_of(event), timestamp_of(event), shown_path(locator["file"]), locator["record"])

            index_complete = True
            for target in targets:
                row, early = scan_file(target, None, False, remember, max_expanded, record_cap)
                if early:
                    index_complete = False
                    break
            index.finish_indexing()
            link_totals.update({"index_complete": index_complete, "index_kept_in": index.where, "assume_calls_indexed": index.indexed,
                                "assume_calls_with_an_error_not_indexed": index.failed, "linked": {}})
            DEADLINE[0] = started + seconds

        def handle(event, locator, info):
            nonlocal matched, first_ns, last_ns
            who = identity_of(event)
            stamp = timestamp_of(event)
            zone_counts[stamp["status"]] = zone_counts.get(stamp["status"], 0) + 1
            if stamp["ns"] is not None:
                first_ns = stamp["ns"] if first_ns is None else min(first_ns, stamp["ns"])
                last_ns = stamp["ns"] if last_ns is None else max(last_ns, stamp["ns"])
            name = event.get("eventName") if isinstance(event.get("eventName"), str) else None
            code = event.get("errorCode") if isinstance(event.get("errorCode"), str) else None
            actor = who.get("arn") or who.get("user_name") or who.get("identity_type") or "?"
            note = NOTABLE.get(name)
            outcome = "error_recorded" if event.get("errorCode") or event.get("errorMessage") else "no_error_recorded"
            response = as_dict(event.get("responseElements"))
            if response.get("ConsoleLogin") == "Failure":
                outcome = "failure_recorded_in_the_response"
            if wanted and (name or "?") not in wanted:
                return
            if notable_only and not note:
                return
            if errors_only and outcome == "no_error_recorded":
                return
            if pattern and not pattern.search(actor):
                return
            klass = classify_error(code) if code else None
            additional = event.get("additionalEventData")
            entry = {
                "time": event.get("eventTime"), "time_utc": stamp["utc"], "time_status": stamp["status"],
                "event": name, "source": event.get("eventSource"), "region": event.get("awsRegion"),
                "address": event.get("sourceIPAddress"), "user_agent": withheld.clean(event.get("userAgent"), locator, "/userAgent"),
                "outcome": outcome, "error": code, "error_class": klass,
                "error_message": withheld.clean(event.get("errorMessage"), locator, "/errorMessage"),
                "read_only": event.get("readOnly"), "event_id": event.get("eventID"), "event_type": event.get("eventType"),
                "event_category": event.get("eventCategory"), "management_event": event.get("managementEvent"),
                "recipient_account": event.get("recipientAccountId"), "shared_event_id": event.get("sharedEventID"),
                "source_file": shown_path(locator["file"]), "record": locator["record"], "line": locator["line"], "parser": PARSER,
            }
            entry.update(withheld.clean(who, locator, "/userIdentity"))
            entry["user_identity"] = withheld.clean(event.get("userIdentity"), locator, "/userIdentity")
            if isinstance(additional, dict) and "MFAUsed" in additional:
                entry["mfa_used"] = additional["MFAUsed"]
            if "ConsoleLogin" in response:
                entry["console_login"] = response["ConsoleLogin"]
            entry["resources"] = withheld.clean(event.get("resources"), locator, "/resources")
            entry["request"] = withheld.clean(event.get("requestParameters"), locator, "/requestParameters")
            entry["response"] = withheld.clean(event.get("responseElements"), locator, "/responseElements")
            entry["additional"] = withheld.clean(additional, locator, "/additionalEventData")
            if note:
                entry["notable"] = note
            if index is not None and who.get("identity_type") == "AssumedRole":
                creation = parse_stamp(who.get("session_started"))
                link = session_link(index, who, stamp["ns"], creation["ns"], withheld, locator)
                entry["session_origin"] = link
                key = link["label"] + (":" + link.get("basis", "") if link["label"] == "candidate" else "")
                link_totals["linked"][key] = link_totals["linked"].get(key, 0) + 1
            matched += 1
            by_event.add(name or "?")
            by_identity.add(scrub(actor))
            if entry.get("address"):
                by_address.add(scrub(str(entry["address"])))
            if code or outcome != "no_error_recorded":
                errors.add((scrub(actor), code or "(" + outcome + ")", klass or "none"))
                error_classes[klass or "none"] = error_classes.get(klass or "none", 0) + 1
            complete_target.add(compact(entry))

        for n, target in enumerate(targets):
            if out_of_time():
                stop_all = True
                not_attempted = targets[n:]
                break
            row, early = scan_file(target, census, True, handle, max_expanded, record_cap)
            if early:
                stop_all = True
                not_attempted = targets[n + 1:]
                break
    finally:
        if index is not None:
            index.close()
        vault.close()

    census.counts["files_not_attempted"] = len(not_attempted)
    pages = {"records": complete_target.finish(), "file_census": census.files.finish(), "rejected_records": census.rejected.finish()}
    withheld_summary = withheld.summary()
    refusals = {}
    detail = {}
    for (actor, code, klass), n in sorted(errors.counts.items(), key=lambda kv: (-kv[1], str(kv[0]))):
        d = detail.setdefault(actor, {"identity": actor, "errors": {}, "classes": {}, "total": 0})
        d["errors"][code] = d["errors"].get(code, 0) + n
        d["classes"][klass] = d["classes"].get(klass, 0) + n
        d["total"] += n
        if klass == "authorisation_denied":
            refusals.setdefault(actor, {"identity": actor, "errors": {}, "total": 0})
            refusals[actor]["errors"][code] = refusals[actor]["errors"].get(code, 0) + n
            refusals[actor]["total"] += n
    error_rows = sorted(detail.values(), key=lambda d: (-d["total"], str(d["identity"])))
    refusal_rows = sorted(refusals.values(), key=lambda d: (-d["total"], str(d["identity"])))
    tables = {}
    for name, tally in (("by_event", by_event), ("by_identity", by_identity), ("by_address", by_address)):
        page = LosslessPage(TOOL + "-" + name, limit)
        for r in tally.rows():
            page.add(r)
        pages[name] = page.finish()
        tables[name] = page.page
    err_page = LosslessPage(TOOL + "-errors", limit)
    for r in error_rows:
        err_page.add(r)
    pages["errors_by_identity"] = err_page.finish()
    ref_page = LosslessPage(TOOL + "-refusals", limit)
    for r in refusal_rows:
        ref_page.add(r)
    pages["refusals_by_identity"] = ref_page.finish()

    c = census.counts
    time_stopped = bool(stop_all)
    complete = (not time_stopped and c["files_partial"] == c["files_failed"] == c["files_unsupported"] == c["files_empty"] == 0
                and c["records_rejected"] == 0 and not skipped.unreadable and not census.pagination and not census.digest_files
                and c["files_not_attempted"] == 0 and c["replacement_characters"] == 0)
    nothing_read = c["records_read"] == 0
    status = status_of(nothing_read and (c["files_failed"] or c["files_unsupported"] or c["files_empty"] or c["files_not_attempted"]), complete,
                       "every record of every supplied file was read and nothing was left out; that says nothing about whether the export holds everything the account logged",
                       "some of what was supplied was not read as events or not read at all (see coverage, file_census, rejected_records, file_problems, skipped, pagination_markers and digest_files)",
                       "no CloudTrail event could be read from what was supplied (see file_problems)")
    answer = {
        "parser": PARSER, **status, "path": shown_path(path),
        "coverage": {**c, "time_limit_seconds": seconds, "stopped_by_time_limit": time_stopped, "max_expanded_bytes": max_expanded,
                     "records_matched": matched, "time_statuses": zone_counts},
        "files": len(targets), "rows_read": c["records_read"], "unreadable_files": c["files_failed"],
        "file_census": census.files.page, "rejected_records": census.rejected.page,
        "file_problems": census.problems,
        "files_not_attempted_named": [shown_path(p) for p in not_attempted[:FIRST_PROBLEMS]],
        "skipped": named(skipped.items), "skipped_count": skipped.total, "skipped_by_name_count": skipped.by_name,
        "pagination_markers": named(census.pagination), "pagination_marker_count": len(census.pagination),
        "digest_files": named(census.digest_files), "digest_file_count": len(census.digest_files),
        "integrity": {"digest_chain_validated": False, "performed": False,
                      "note": "No integrity validation of the log files or of a digest chain was performed; a file hash from the case's own custody record is byte identity from when it was taken, not CloudTrail's validation."},
        "records": complete_target.page, "record_count": matched, "records_inline": len(complete_target.page),
        "complete_records": pages["records"].get("all_results"),
        "first_event": ns_to_utc(first_ns), "last_event": ns_to_utc(last_ns),
        "table_scope": "the matched records (after events, identity, errors_only and notable_only); first_event and last_event cover every event read",
        "by_event": tables["by_event"], "by_identity": tables["by_identity"], "by_address": tables["by_address"],
        "errors_by_identity": err_page.page, "refusals_by_identity": ref_page.page,
        "error_classes": error_classes,
        "inline_limited": pages["records"]["truncated"],
        "tables_uncounted": {"by_event": by_event.uncounted, "by_identity": by_identity.uncounted, "by_address": by_address.uncounted, "errors": errors.uncounted,
                             "note": "distinct values past %d are counted here and not in the tables; every record is in the whole-result file" % MAX_DISTINCT},
        "session_links": link_totals if link_sessions else {"performed": False, "why": "link_sessions was false"},
        "values_withheld": {"count": withheld_summary["count"], "by_reason": withheld_summary["by_reason"], "locators": withheld_summary["locators"],
                            "page": withheld_summary["page"], "text_withheld_from_paths_and_messages": withheld_summary["text_withheld_from_paths_and_messages"]},
        "secret_values": vault.summary(),
        "sensitive_output": {"payloads_inline": True, "withholding": "by field name and by shape only; other secrets are not recognised",
                             "advice": "run this tool as a job with secret_output: true when the export may hold request parameters, responses or additional event data"},
        "pages": pages,
        "truncated": any(p["truncated"] for p in pages.values()),
        "note": "An AssumedRole identity names a session, not a person: session_origin says which successful AssumeRole-family call in these records could have "
                "issued it and on what basis (a candidate, never attribution; unresolved names every candidate; not_found means none in these files). "
                "outcome says what the record carries (an error recorded or not), not whether a change took effect. Error classes are by the code's name, a heuristic, "
                "and only authorisation_denied is in refusals_by_identity. A call that is not in the records (data events, other regions, other accounts, "
                "an export that stopped) is not evidence that it did not happen.",
    }
    if status["status"] == "failed":
        answer["error"] = "no CloudTrail event could be read from what was supplied"
    print(json.dumps(answer, indent=2, default=str))
    if status["status"] == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure
        fail("unexpected failure: %s: %s" % (type(exc).__name__, scrub(str(exc))))

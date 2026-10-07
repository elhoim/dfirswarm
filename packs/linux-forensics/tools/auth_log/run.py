#!/usr/bin/env python3
"""Read auth.log and secure as records rather than as text.

What this exists to get right, because doing it by hand with grep is where the mistakes are.

Rotation. The current file usually covers days, and an intrusion usually is not in it. auth.log.1,
auth.log.2.gz and the rest hold the rest. They are read oldest first by the suffix the rotation scheme
wrote (a number, a date, or none for the live file); the answer says which basis ordered each file and
whether the files' own time ranges agree with that order.

The missing year and the missing zone. A traditional syslog line carries a month, a day and a time and
no year and no zone, so every date is an inference until something supplies one. The year applied comes
from the file's modification time (which is the time of extraction on a copied tree) or from the
caller's `year`; the answer says which, per file, and each record carries its stamp as written
(`time_raw`), the year applied and `time_zone: "unknown"`. A year is counted only where the months wrap
forward through the year end; a line out of order by months is flagged `reordered` and placed by its
nearness to the lines around it, never counted as a second year end. An RFC 3339 stamp keeps its own
offset and its fraction of a second.

The shape of each line. "Accepted publickey for deploy from 10.0.0.5 ... ssh2: ED25519 SHA256:..."
names a key, not a person: the fingerprint maps to an entry in some authorized_keys file and says
nothing about when that entry was made. A PAM session is the named service's session (sshd, sudo, cron
and others), not necessarily a login. A line that matches no rule stays `other`, with its text.

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"). A sudo line carries a
whole command line, and a name typed at a prompt can be a password typed into the wrong field. The answer
therefore carries fields and locators (file, physical line, byte offset), the length of the text and never
the text: `raw` and `command` are in a file under $OUT only when `write_text: true` is asked, in a job, and
in the answer only with `preview_text: true`, in a job. The skill says the job runs with secret_output:
true. Nothing is hashed, and a secret never goes on a command line: this tool takes a path and flags.

A tool that fails loudly: a file it cannot open or read to its end is a named, partial file and not an
empty one; a line no rule places is counted, located and kept; `all_lines_parsed` is true only when every
line matched a syslog shape and every file was read through.
"""
import datetime
import gzip
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
import zlib
from pathlib import Path

TOOL = "auth_log"
PARSER = "auth_log/4"
DEFAULT_LIMIT = 200
FIRST_FAILURES = 20
MAX_LINE = 1 << 20          # a physical line longer than this is located, not parsed
DEFAULT_EXPANDED = 1 << 30  # a gzip stream is read to at most this many decompressed bytes
ZONE_SLACK = datetime.timedelta(hours=26)   # the log's zone is unknown: UTC-12 to UTC+14 is 26 hours
TEXT_NAME = "auth-text.jsonl"

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


# ---- The parts every tool of this pack that pages or keeps text copies (a tool is standalone; none imports another) ----


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def describe(exc):
    return "%s: %s" % (type(exc).__name__, exc)


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def want_flag(args, key):
    value = args.get(key, False)
    if not isinstance(value, bool):
        fail("%s must be true or false" % key)
    return value


def want_limit(args):
    limit = args.get("limit", DEFAULT_LIMIT)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        fail("limit must be a positive integer")
    return limit


# Lossless paging (the same in every library tool that pages): the page an agent reads stays small, and when
# there are more rows the whole result is written as JSON Lines under work/<agent>/tool-output (in a job,
# $OUT/tool-output) and named. The file name is a digest of the page's key (a path), never of a value.
class LosslessPage:
    def __init__(self, tool, key, limit):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page = []
        self.total = 0
        self._out = None
        self._tmp = None
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        name = "%s-%s.jsonl" % (self.tool, digest)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row):
        self._out.write(json.dumps(row, ensure_ascii=False, default=str))
        self._out.write("\n")

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            os.replace(self._tmp, self.path)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


def require_job(flag):
    """What leaves a record's text is held to the secret-safe output pattern (docs/packs.md, "Secrets and
    sensitive output"): the text goes into the answer or into a file only in a job, whose output the skill
    says to seal with secret_output: true. Outside a job the request is refused and nothing is written."""
    if not in_job():
        fail("%s is refused outside a job: a command line, a message or an environment value written or "
             "printed here would be an ordinary file or an ordinary answer, not a sealed output. Run this as "
             "job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % (flag, TOOL))


class TextRefused(Exception):
    pass


class TextFile:
    """Where the text of a tool's records goes when, and only when, the caller asked for it.

    The secret-safe output pattern of recovery_key_scan's SecretValues, for rows. With `enabled` false it
    writes nothing and `summary()` says so. Enabled, it is refused outside a job; inside one the file is
    created before anything is read (mode 0600, exclusively: a file or a link already at that name is
    refused by name) under $OUT, and the answer names it and says it may hold secrets.
    """

    def __init__(self, name, enabled, what, flag="write_text"):
        self.enabled = enabled
        self.written = 0
        self.what = what
        self._fh = None
        self.path = None
        self.shown = None
        if not enabled:
            return
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out):
            raise TextRefused("%s is refused outside a job: the text of the records written here would be an "
                              "ordinary file, not a sealed output. Run this as job_run tool=%s with secret_output: "
                              "true, and ask again there. Nothing was written." % (flag, TOOL))
        self.path = Path(out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise TextRefused("the text file already exists: %s" % self.path)
        except OSError as exc:
            raise TextRefused("the text file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "wb")

    def add(self, row):
        if self._fh is None:
            return
        self._fh.write(json.dumps(row, ensure_ascii=False, default=str).encode("utf-8", "replace") + b"\n")
        self.written += 1

    def add_bytes(self, data):
        """One record exactly as its source wrote it (a native export's line, newline included)."""
        if self._fh is None:
            return
        self._fh.write(data)
        self.written += 1

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self):
        if not self.enabled:
            return {"requested": False, "written": 0, "file": None, "contains_text_that_may_hold_secrets": False,
                    "hint": "No text of any record is in this answer or in a file. write_text: true, in a job run with "
                            "secret_output: true, keeps the whole of each record in a private file under $OUT."}
        return {"requested": True, "written": self.written, "file": self.shown,
                "contains_text_that_may_hold_secrets": self.written > 0,
                "format": self.what}


TRADITIONAL = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
ISO = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
ISO_PARTS = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$")

# The ssh key that follows "ssh2:" in an acceptance: "TYPE FINGERPRINT", or for a certificate
# "TYPE-CERT FINGERPRINT ID <key id> (serial N) CA TYPE FINGERPRINT".
KEY_CERT = re.compile(
    r"^(?P<keytype>\S+)\s+(?P<fingerprint>\S+)\s+ID\s+(?P<cert_id>.*?)\s+\(serial\s+(?P<cert_serial>\d+)\)\s+"
    r"CA\s+(?P<ca_keytype>\S+)\s+(?P<ca_fingerprint>\S+)\s*$")
KEY_PLAIN = re.compile(r"^(?P<keytype>\S+)\s+(?P<fingerprint>\S+)\s*$")
PAM_PAIR = re.compile(r"(\w+)=(\S*)")

# Explicit variants, one per message form. Fields are named for what the line says; a value that is not an
# address is never a `source`.
RULES = [
    ("ssh_accepted", re.compile(
        r"^Accepted (?P<method>\S+) for (?P<user>.+?) from (?P<source>\S+) port (?P<port>\d+)(?: ssh2)?"
        r"(?::\s*(?P<key>.*))?")),
    ("ssh_failed", re.compile(
        r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.+?) from (?P<source>\S+) "
        r"port (?P<port>\d+)(?: ssh2)?")),
    ("ssh_invalid_user", re.compile(r"^Invalid user (?P<user>.*?) from (?P<source>\S+)(?: port (?P<port>\d+))?")),
    ("ssh_disconnect", re.compile(
        r"^Received disconnect from (?P<source>\S+) port (?P<port>\d+):(?P<disconnect_code>\d+):\s*(?P<reason>.*?)\s*$")),
    ("ssh_disconnect", re.compile(
        r"^Disconnected from (?:(?P<role>authenticating user|invalid user|user) (?P<user>.+?) )?"
        r"(?P<source>\S+)(?: port (?P<port>\d+))?(?P<stage>.*)$")),
    ("key_observed_authentication", re.compile(
        r"^Accepted key (?P<keytype>\S+) (?P<fingerprint>\S+)"
        r"(?: found at (?P<authorized_keys_file>.+?):(?P<authorized_keys_line>\d+))?")),
    ("sudo", re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S*)\s*;\s*PWD=(?P<pwd>\S*)\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<command>.*)$")),
    ("sudo_failed", re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*(?:\d+ incorrect password attempts?|user NOT in sudoers|command not allowed)")),
    ("su", re.compile(r"^(?:\(to (?P<target>\S+)\)|Successful su for) (?P<user>\S+)")),
    ("session_opened", re.compile(
        r"^pam_unix\((?P<pam_service>[^:)]*):session\): session opened for user (?P<user>[^\s(]+)"
        r"(?:\(uid=(?P<uid>-?\d+)\))?(?: by (?P<by>[^\s(]*)(?:\(uid=(?P<by_uid>-?\d+)\))?)?")),
    ("session_closed", re.compile(
        r"^pam_unix\((?P<pam_service>[^:)]*):session\): session closed for user (?P<user>[^\s(]+)(?:\(uid=(?P<uid>-?\d+)\))?")),
    ("auth_failure", re.compile(r"^pam_unix\((?P<pam_service>[^:)]*):auth\): authentication failure;(?P<kv>.*)$")),
    ("account_added", re.compile(
        r"^new (?P<what>user|group): name=(?P<name>[^,]+)(?:, UID=(?P<uid>\d+))?(?:, GID=(?P<gid>\d+))?"
        r"(?:, home=(?P<home>[^,]*))?(?:, shell=(?P<shell>[^,]*))?")),
    ("account_changed", re.compile(
        r"^(?:pam_unix\([^)]*:chauthtok\): )?(?:changed password|password changed) for (?P<user>\S+)")),
]
KINDS = sorted({k for k, _ in RULES} | {"other"})
INT_FIELDS = ("port", "uid", "by_uid", "gid", "cert_serial", "authorized_keys_line", "disconnect_code")
# What is the text of a line and not a field of it: held back from the answer, kept in the text file.
TEXT_FIELDS = ("raw", "command")


def address_ok(text):
    try:
        ipaddress.ip_address(text.split("%", 1)[0])
        return True
    except ValueError:
        return False


def finish(kind, fields):
    if kind == "ssh_accepted":
        key = fields.pop("key", None)
        if key:
            found = KEY_CERT.match(key) or KEY_PLAIN.match(key)
            if found:
                fields.update({k: v for k, v in found.groupdict().items() if v})
            else:
                fields["key_text_unparsed"] = True
    if kind == "ssh_failed":
        if fields.pop("invalid", None):
            fields["invalid_user"] = True
    if kind == "ssh_disconnect":
        role = fields.pop("role", None)
        if role:
            fields["user_role"] = role
        stage = (fields.pop("stage", "") or "").strip()
        if stage:
            fields["stage"] = stage
    if kind == "auth_failure":
        for key, value in PAM_PAIR.findall(fields.pop("kv", "") or ""):
            if value == "":
                continue
            fields["source" if key == "rhost" else key] = value
    if "source" in fields and not address_ok(fields["source"]):
        fields["source_unvalidated"] = fields.pop("source")
    for key in INT_FIELDS:
        if key in fields:
            try:
                fields[key] = int(fields[key])
            except ValueError:
                fields.pop(key)
    return fields


def classify(message):
    for kind, pattern in RULES:
        found = pattern.match(message)
        if found:
            fields = {k: v for k, v in found.groupdict().items() if v not in (None, "")}
            return kind, finish(kind, fields)
    return "other", {}


# --- the files and their order ---------------------------------------------------------------------

def rotation_basis(path):
    """(rank, key, basis): oldest first. A number is a rotation count (a higher one is older), a date is
    that day, and the live file is the newest. Anything else is ordered by name, and said so."""
    name = os.path.basename(path)
    found = re.search(r"\.(\d+)(?:\.gz)?$", name)
    if found:
        return 1, -int(found.group(1)), "numeric rotation suffix"
    found = re.search(r"-(\d{8})(?:\.gz)?$", name)
    if found:
        return 1, int(found.group(1)), "date suffix"
    if re.fullmatch(r"(?:auth\.log|secure)", name):
        return 2, 0, "current file"
    return 0, 0, "name only"


class FileState:
    def __init__(self, path):
        self.path = path
        self.errors = []
        self.compression = "none"
        self.lines_before_error = 0


def open_binary(path, state):
    raw = open(path, "rb")
    magic = raw.read(2)
    raw.seek(0)
    if magic == b"\x1f\x8b":
        state.compression = "gzip"
        return gzip.GzipFile(fileobj=raw)
    return raw


def physical_lines(path, state, expanded_cap=None):
    """(line number, byte offset, bytes or None when over MAX_LINE, bytes in the line) for each physical line.

    A read or a decompression error ends the iteration, is recorded in state.errors with where it
    happened, and is not raised: what was read before it is kept. The offset is into the stream as it
    comes out (the decompressed one for a gzip file); a gzip stream that expands past `expanded_cap`
    bytes ends there as a recorded error, so a compression bomb costs a bounded amount of work."""
    try:
        handle = open_binary(path, state)
    except OSError as exc:
        state.errors.append({"file": path, "error": describe(exc), "line": 0, "byte_offset": 0})
        return
    offset, number = 0, 0
    try:
        with handle:
            while True:
                chunk = handle.readline(MAX_LINE + 1)
                if not chunk:
                    return
                length = len(chunk)
                if expanded_cap is not None and state.compression == "gzip" and offset + length > expanded_cap:
                    state.errors.append({"file": path, "error": "the decompressed stream passed max_expanded_bytes (%d): not read past it" % expanded_cap,
                                         "line": number, "byte_offset": offset})
                    return
                if length > MAX_LINE and not chunk.endswith(b"\n"):
                    # Read on to the end of the line without holding it.
                    while True:
                        more = handle.readline(MAX_LINE + 1)
                        length += len(more)
                        if not more or more.endswith(b"\n"):
                            break
                    number += 1
                    yield number, offset, None, length
                    offset += length
                    continue
                number += 1
                yield number, offset, chunk, length
                offset += length
    except (OSError, EOFError, zlib.error) as exc:
        state.errors.append({"file": path, "error": describe(exc), "line": number, "byte_offset": offset})


# --- months, years, zones ---------------------------------------------------------------------------

class MonthTracker:
    """Which way the months of a traditional stamp move from one line to the next.

    A forward step of up to six months is the log advancing, and it is a year end when the number goes
    down (Dec to Jan). Anything else is a step back in time: the line is out of order, and it does not
    move the place the next line is compared with. A month going down is therefore not, by itself, a
    year end: January, December, January is one year with one late line in it."""

    def __init__(self):
        self.prev = None
        self.rollovers = 0
        self.reordered = 0

    def feed(self, month):
        if self.prev is None:
            self.prev = month
            return "first"
        step = (month - self.prev) % 12
        if step == 0:
            return "same"
        if step <= 6:
            wrapped = month < self.prev
            self.prev = month
            if wrapped:
                self.rollovers += 1
                return "rollover"
            return "forward"
        self.reordered += 1
        return "reordered"


def valid_clock(day_time):
    h, m, s = (int(x) for x in day_time.split(":"))
    return h < 24 and m < 60 and s < 61


def anchor_year(last, mtime):
    """The year of the last in-order line: the latest year in which that date is no later than the file's
    modification time plus the 26 hours the log's unknown zone allows."""
    limit = mtime + ZONE_SLACK
    year = limit.year
    for _ in range(8):
        try:
            when = datetime.datetime(year, *last)
        except ValueError:
            year -= 1
            continue
        if when <= limit:
            return year
        year -= 1
    return None


def traditional_time(year, month, day, clock):
    try:
        h, m, s = (int(x) for x in clock.split(":"))
        return datetime.datetime(year, month, day, h, m, min(s, 59)), None
    except ValueError:
        return None, "no such date or time: month %d day %d %s in %d" % (month, day, clock, year)


def iso_time(stamp):
    """(time, time_utc, time_zone, error) for an RFC 3339 stamp, its fraction kept."""
    found = ISO_PARTS.match(stamp)
    if not found:
        return None, None, "unknown", "stamp does not match RFC 3339"
    y, mo, d, h, mi, s, frac, zone = found.groups()
    micro = int((frac or "0")[:6].ljust(6, "0"))
    try:
        naive = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), micro)
    except ValueError:
        return None, None, zone or "unknown", "no such date or time in the stamp"
    shown = naive.isoformat()
    if zone is None:
        return shown, None, "unknown", None
    if zone == "Z":
        offset = datetime.timedelta(0)
    else:
        digits = zone[1:].replace(":", "")
        offset = datetime.timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
        offset = offset if zone[0] == "+" else -offset
    utc = (naive - offset).isoformat() + "Z"
    kept = zone if zone == "Z" else zone[0] + zone[1:].replace(":", "")[:2] + ":" + zone[1:].replace(":", "")[2:]
    return utc, utc, kept, None


# --- the run -----------------------------------------------------------------------------------------

def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an auth.log or secure file, or a directory holding them")
    if os.path.islink(path):
        fail("refusing a symlink: pass the log file or directory inside the evidence", path=path,
             target=os.readlink(path))
    limit = want_limit(args)
    write_text, preview_text = want_flag(args, "write_text"), want_flag(args, "preview_text")
    if preview_text:
        require_job("preview_text")
    year_arg = args.get("year")
    if year_arg is not None and (isinstance(year_arg, bool) or not isinstance(year_arg, int) or not 1970 <= year_arg <= 2200):
        fail("year must be a whole year between 1970 and 2200")
    kinds = args.get("kinds") or []
    if not isinstance(kinds, list):
        fail("kinds must be a list of kinds", known=KINDS)
    wanted = {str(k) for k in kinds}
    if "key_added" in wanted:
        fail("key_added was renamed key_observed_authentication: an `Accepted key` line is sshd matching a "
             "login against an authorized_keys entry, not a key being installed", known=KINDS)
    unknown = sorted(wanted - set(KINDS))
    if unknown:
        fail("unknown kinds: %s" % ", ".join(unknown), known=KINDS)
    needle = (args.get("contains") or "").lower()
    expand_cap = args.get("max_expanded_bytes", DEFAULT_EXPANDED)
    if isinstance(expand_cap, bool) or not isinstance(expand_cap, int) or expand_cap < 1:
        fail("max_expanded_bytes must be a positive integer")

    walk_errors, skipped_symlinks, targets = [], [], []
    if os.path.isdir(path):
        def on_error(exc):
            walk_errors.append({"path": getattr(exc, "filename", None), "error": describe(exc)})
        for root, dirs, names in os.walk(path, onerror=on_error):
            for name in list(dirs):
                if os.path.islink(os.path.join(root, name)):
                    skipped_symlinks.append({"file": os.path.join(root, name), "target": os.readlink(os.path.join(root, name))})
                    dirs.remove(name)
            for name in names:
                if re.match(r"^(auth\.log|secure)", name):
                    candidate = os.path.join(root, name)
                    if os.path.islink(candidate):
                        skipped_symlinks.append({"file": candidate, "target": os.readlink(candidate)})
                    else:
                        targets.append(candidate)
    elif os.path.isfile(path):
        targets = [path]
    else:
        fail("no such file or directory", path=path)
    if not targets:
        fail("no auth.log or secure file found there", path=path, skipped_symlinks=skipped_symlinks, walk_errors=walk_errors)
    ranked = sorted(((rotation_basis(t), t) for t in targets), key=lambda row: (row[0][0], row[0][1], row[1]))
    schemes = {basis for (rank, _k, basis), _t in ranked if rank == 1}

    try:
        text = TextFile(TEXT_NAME, write_text, "JSON Lines, mode 0600: the record's id, locator and fields as in the answer, "
                        "with `raw` (the message), `command` (a sudo command line) and `line_text` (the physical line)")
    except TextRefused as exc:
        fail(str(exc))
    page = LosslessPage(TOOL, ["records", path, sorted(wanted), needle, year_arg, preview_text], limit)
    unparsed_page = LosslessPage(TOOL, ["unparsed", path], limit)

    files, read_errors, by_kind = [], [], {}
    counts = {"physical": 0, "blank": 0, "read": 0, "unparsed": 0, "time_errors": 0, "invalid_utf8": 0}
    seq = 0
    for (rank, _key, basis), target in ranked:
        state = FileState(target)
        info = {"path": target, "order_basis": basis, "compression": "none", "size": None, "modified": None,
                "physical_lines": 0, "unparsed_lines": 0, "records": 0, "formats": {}, "year_basis": None,
                "first_year": None, "last_year": None, "rollovers": 0, "reordered_lines": 0,
                "first_time": None, "last_time": None, "partial": False}
        try:
            info["size"] = os.path.getsize(target)
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(target), datetime.timezone.utc).replace(tzinfo=None)
            info["modified"] = mtime.isoformat() + "Z"
        except OSError:
            mtime = None
        # Pass one: how the months run, so the year of the first line can be worked back from the last.
        tracker, last_valid = MonthTracker(), None
        for _n, _o, chunk, _l in physical_lines(target, state, expand_cap):
            if chunk is None:
                continue
            found = TRADITIONAL.match(chunk.decode("utf-8", "replace").rstrip("\r\n"))
            if not found or found.group("mon") not in MONTHS:
                continue
            month = MONTHS[found.group("mon")]
            kind = tracker.feed(month)
            day = int(found.group("day"))
            try:
                datetime.datetime(2000, month, day)
                valid = valid_clock(found.group("time"))
            except ValueError:
                valid = False
            if valid and kind != "reordered":
                h, m, s = (int(x) for x in found.group("time").split(":"))
                last_valid = (month, day, h, m, min(s, 59))
        info["rollovers"], info["reordered_lines"] = tracker.rollovers, tracker.reordered
        if year_arg is not None:
            first_year, info["year_basis"] = year_arg, "argument"
            info["year_argument_spans_rollover"] = tracker.rollovers > 0
        elif mtime is not None and last_valid is not None:
            anchor = anchor_year(last_valid, mtime)
            first_year = None if anchor is None else anchor - tracker.rollovers
            info["year_basis"] = "file mtime (UTC, with 26 hours allowed for the log's unknown zone; on a copied tree it is the time of the copy)"
        else:
            first_year, info["year_basis"] = None, "none: no readable modification time or no dated line"
        # Pass two: the records.
        state = FileState(target)
        tracker, year, cursor = MonthTracker(), first_year, None
        for number, offset, chunk, length in physical_lines(target, state, expand_cap):
            counts["physical"] += 1
            info["physical_lines"] += 1
            if chunk is None:
                counts["unparsed"] += 1
                info["unparsed_lines"] += 1
                row = {"file": target, "line": number, "byte_offset": offset, "bytes": length, "reason": "line longer than %d bytes: located, not parsed" % MAX_LINE}
                unparsed_page.add(row)
                text.add({"record_type": "unparsed", **row, "line_text": None})
                continue
            decoded = chunk.decode("utf-8", "replace")
            if "\ufffd" in decoded:
                try:
                    chunk.decode("utf-8")
                except UnicodeDecodeError:
                    counts["invalid_utf8"] += 1
            line = decoded.rstrip("\r\n")
            if not line.strip():
                counts["blank"] += 1
                continue
            counts["read"] += 1
            found = TRADITIONAL.match(line)
            iso = None if found else ISO.match(line)
            reason = None
            if found and found.group("mon") not in MONTHS:
                reason, found = "unknown month %r: not placed in any year" % found.group("mon"), None
            elif not found and not iso:
                reason = "not a syslog line"
            if reason:
                counts["unparsed"] += 1
                info["unparsed_lines"] += 1
                row = {"file": target, "line": number, "byte_offset": offset, "bytes": length, "reason": reason}
                unparsed_page.add(row)
                text.add({"record_type": "unparsed", **row, "line_text": line})
                continue
            parts = (found or iso).groupdict()
            time_fields = {}
            if found:
                info["formats"]["traditional"] = info["formats"].get("traditional", 0) + 1
                month, day = MONTHS[parts["mon"]], int(parts["day"])
                step = tracker.feed(month)
                reordered = step == "reordered"
                when, error, use = None, None, None
                if year_arg is not None:
                    use = year_arg
                    when, error = traditional_time(use, month, day, parts["time"])
                else:
                    if step == "rollover" and year is not None:
                        year += 1
                    if year is None:
                        error = "no year could be applied (%s)" % info["year_basis"]
                    elif reordered and cursor is not None:
                        # Out of order by months: the year that puts it nearest the lines around it.
                        best = None
                        for candidate in (year - 1, year, year + 1):
                            dt, _err = traditional_time(candidate, month, day, parts["time"])
                            if dt is not None and (best is None or abs(dt - cursor) < abs(best[0] - cursor)):
                                best = (dt, candidate)
                        if best:
                            when, use = best
                        else:
                            error = "no such date or time: month %d day %d %s" % (month, day, parts["time"])
                    else:
                        use = year
                        when, error = traditional_time(use, month, day, parts["time"])
                if when is not None and not reordered:
                    cursor = when
                    info["first_time"] = info["first_time"] or when.isoformat()
                    info["last_time"] = when.isoformat()
                    info["first_year"] = info["first_year"] or when.year
                    info["last_year"] = when.year
                time_fields = {"time": when.isoformat() if when else None,
                               "time_raw": line[:found.start("host")].rstrip(),
                               "time_zone": "unknown", "time_utc": None, "year": use if when else None}
                if error:
                    time_fields["time_error"] = error
                if reordered:
                    time_fields["reordered"] = True
            else:
                info["formats"]["rfc3339"] = info["formats"].get("rfc3339", 0) + 1
                shown, utc, zone, error = iso_time(parts["stamp"])
                time_fields = {"time": shown, "time_raw": parts["stamp"], "time_zone": zone, "time_utc": utc}
                if error:
                    time_fields["time_error"] = error
            if time_fields.get("time_error"):
                counts["time_errors"] += 1
            kind, fields = classify(parts["msg"])
            by_kind[kind] = by_kind.get(kind, 0) + 1
            if wanted and kind not in wanted:
                continue
            if needle and needle not in line.lower():
                continue
            seq += 1
            info["records"] += 1
            record_id = "A%06d" % seq
            texts = {"raw": parts["msg"]}
            if "command" in fields:
                texts["command"] = fields.pop("command")
            row = {"id": record_id, "parser": PARSER, "file": target, "line": number, "byte_offset": offset,
                   **time_fields, "host": parts.get("host"), "process": parts.get("proc"),
                   "pid": int(parts["pid"]) if parts.get("pid") else None, "kind": kind, **fields,
                   "text_bytes": len(parts["msg"].encode("utf-8", "replace"))}
            if "command" in texts:
                row["command_bytes"] = len(texts["command"].encode("utf-8", "replace"))
            text.add({**row, **texts, "line_text": line})
            page.add({**row, **texts} if preview_text else row)
        info["compression"] = state.compression
        for err in state.errors:
            read_errors.append(err)
            info["partial"] = True
        files.append(info)
    text.close()

    # Do the files' own time ranges agree with the order they were read in?
    overlaps = []
    for earlier, later in zip(files, files[1:]):
        if earlier["last_time"] and later["first_time"] and later["first_time"] < earlier["last_time"]:
            overlaps.append({"earlier": earlier["path"], "later": later["path"], "earlier_last": earlier["last_time"], "later_first": later["first_time"]})
    pages = {"records": page.finish(), "unparsed": unparsed_page.finish()}
    all_parsed = counts["unparsed"] == 0 and not read_errors and not walk_errors
    print(json.dumps({
        "parser": PARSER,
        "path": path,
        "files": files,
        "file_count": len(files),
        "mixed_rotation_schemes": len(schemes) > 1,
        "cross_file_order": "consistent" if not overlaps and len(schemes) <= 1 else ("overlap" if overlaps else "not established: more than one rotation scheme"),
        "cross_file_order_overlaps": overlaps,
        "physical_lines": counts["physical"],
        "blank_lines": counts["blank"],
        "lines_read": counts["read"],
        "unparsed_lines": counts["unparsed"],
        "lines_with_time_errors": counts["time_errors"],
        "lines_with_invalid_utf8": counts["invalid_utf8"],
        "by_kind": by_kind,
        "record_count": pages["records"]["matched"],
        "records": page.page,
        "unparsed": unparsed_page.page,
        "pages": pages,
        "text": text.summary(),
        "all_lines_parsed": all_parsed,
        "read_errors": read_errors,
        "walk_errors": walk_errors,
        "skipped_symlinks": skipped_symlinks,
        "truncated": any(p["truncated"] for p in pages.values()),
        "note": "A traditional syslog stamp carries no year and no zone: each file says the year basis applied "
                "(its modification time, which on a copied tree is the time of the copy, or your `year`) and each "
                "record keeps its stamp as written in time_raw. A line out of order by months is flagged reordered "
                "and placed by nearness, and is not a year end. all_lines_parsed says that every line matched a "
                "syslog shape and every file was read through; it is not coverage of the host's authentication "
                "events. An ssh_accepted line says sshd accepted an authentication: its fingerprint names a key, not "
                "a person, and not when the key was installed. A PAM session is the named service's, not necessarily "
                "a login. Text files are editable by root: compare the sessions that matter with wtmp (utmp_parse) "
                "and the journal, and treat a disagreement as a question to explain (rotation, forwarding, filtering, "
                "a damaged file and an edit all produce one), not as an answer.",
    }, indent=2))


if __name__ == "__main__":
    main()

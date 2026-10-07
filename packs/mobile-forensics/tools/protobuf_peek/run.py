#!/usr/bin/env python3
"""Read a protobuf message that arrived without its schema: its wire structure, and nothing more.

More and more of Android and iOS stores its records as protobuf rather than as SQLite: usage
statistics, some Biome payloads, app caches. Without the .proto file there are no field names, but
the wire format carries each field's number, its wire type and its value, which is enough to see the
shape of a blob and to decide whether it matters.

The wire format, which is all this reads (protobuf encoding, as documented by the protobuf project):

    key       a varint: field number = key >> 3 (1 to 536870911), wire type = key & 7
    type 0    varint            an integer, a boolean, an enum, or a zigzag-encoded signed integer
    type 1    64-bit            a fixed64, an sfixed64 or a double
    type 2    length-delimited  a string, bytes, a nested message, or a packed repeated field
    type 5    32-bit            a fixed32, an sfixed32 or a float
    type 3, 4 start and end of a group: deprecated, NOT supported here (see below)

A varint is at most ten bytes, and the tenth may hold only the top bit of a 64-bit value; a longer one,
a field number of 0 or above 536870911, a wire type of 6 or 7 and a field that runs past its message
are structural errors, named with the offset where they were met. A message that holds a group is
`unsupported`: it is not parsed past the group and it is never reported as valid.

A length-delimited field is read as a nested message only when every field number in it is at most
300: real messages use small numbers, and the bytes of a string or a token that happen to parse as fields
mostly do not (what such a reading shows of itself is derived from those bytes).

THE SHAPE IS NOT THE MEANING. A length-delimited field is ambiguous by design: each is tried as a
nested message, then as text, and `read_as` says which reading was taken and `also_reads_as` the others
that were possible. A varint is returned raw, with its zigzag reading and, where it has the top bit
set, its two's-complement reading; which of them is meant is the schema's to say, and so is every field
name, unit and enum. A clean parse says the bytes are consistent with protobuf, not that they are one:
a short or ordinary blob can parse by chance, and a corrupt message stops at the first error.

Offsets are absolute: the byte position in the file (the `offset` given, plus the position in the
window read), for a nested field as much as a top-level one, with the full field-number path
(`3.1.2`). Only a bounded window is read (`length`, at most 8 MiB unless raised, never more than 64
MiB), and what lies past it is counted and the offset to continue at is named.

THE SECRET-SAFE OUTPUT PATTERN. A protobuf blob can hold message text, a token or any other string.
A top-level varint is printed (a timestamp, a counter and an enum are what it is read for). Nothing
else that holds a value is: not the text of a string field, not the bytes of a bytes field, not a
number under a length-delimited field (the bytes of a string or a token parse as a nested message
now and then, and their "numbers" are its content) and not a fixed-width value, which is raw bytes.
The answer carries each one's offset, length and reading, and the value goes only to the values
file, on `write_values: true` in a job run with `secret_output: true`. `hex` (a message passed in the call) is recorded in the trace: use it only for
a few bytes that are not sensitive, and a file for anything else.
"""
import binascii
import errno
import hashlib
import json
import math
import os
import re
import signal
import struct
import sys
import tempfile
import time
from pathlib import Path

PARSER = "protobuf_peek/2"
TOOL = "protobuf_peek"
VALUES_NAME = "protobuf-values.jsonl"
VALUES_FORMAT = ("JSON Lines, mode 0600: finding_id, source (the real file), field_path, offset, payload_offset, "
                 "kind (text, bytes or number), bytes, value (the text, the bytes as hexadecimal, or the number's readings)")


# --- shared with the pack's other tools: begin ---------------------------------------------
# The three tools of this pack carry this block byte for byte (a test holds the copies equal),
# so that they withhold the same strings, write the same files the same way and refuse in the
# same words. Standalone tools do not import each other: the block is copied.
#
# THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"), as the
# encrypted-containers pack's recovery_key_scan introduced it and the macOS pack's plist_read
# copied it:
#   1. The answer carries presence, kind, location (file and offset or path), length and counts.
#      It carries no value, no characters of one, no masked shape and no digest of one.
#   2. A value is written only on `write_values: true`, only when the tool runs as a job
#      (JOB_ID and OUT are set), and only to a file under $OUT: JSON Lines, mode 0600, created
#      exclusively before anything is read. The skill that sends the agent here says the job runs
#      with `secret_output: true`. Outside a job the request is refused and nothing is written.
#   3. A secret is never on a command line: these tools take a path and flags only.
#   4. A printed path component shaped like a recovery password is withheld on every output
#      channel (the answer, the files it names, an error message); the values file keeps the
#      real path.

WITHHELD = "<recovery-password-shaped name withheld>"
PATHS_WITHHELD = [0]
# A BitLocker recovery password is eight groups of six digits. A file or a directory named after
# one (people save a key under its own name) would print it in every row that names the file.
RECOVERY = re.compile(rb"(?<![0-9])(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})(?![0-9])")
RECOVERY_UTF16LE = re.compile(
    rb"(?<![0-9]\x00)" + (rb"-\x00".join([rb"((?:[0-9]\x00){6})"] * 8)) + rb"(?![0-9]\x00)"
)
RECOVERY_TEXT = re.compile(RECOVERY.pattern.decode("ascii"))


def shown(path, count=True):
    """A path as it may be printed: any component shaped like a recovery password is withheld."""
    if not isinstance(path, str):
        return path
    parts = path.split("/")
    for i, part in enumerate(parts):
        if RECOVERY.search(part.encode("utf-8", "replace")) or RECOVERY_UTF16LE.search(part.encode("utf-16-le", "replace")):
            parts[i] = WITHHELD
            if count:
                PATHS_WITHHELD[0] += 1
    return "/".join(parts)


def scrub(text):
    """Text that may quote a path, with anything shaped like a recovery password withheld."""
    return RECOVERY_TEXT.sub(WITHHELD, text)


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def clean(value):
    """The value as strict JSON: a float that is not finite (JSON has no NaN or Infinity) is its text."""
    if isinstance(value, float) and not math.isfinite(value):
        return {"_float": repr(value)}
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean(v) for v in value]
    return value


def dumps(value, **kwargs):
    return json.dumps(clean(value), allow_nan=False, default=str, **kwargs)


# What is open when a run fails: the pages and the values file are closed and named in the error, so a
# result read before the failure is kept, whole, and never left as a hidden temporary file.
OPEN_PAGES = []
OPEN_VALUES = []
NONCE = "%d-%d" % (os.getpid(), time.time_ns())


def fail(message, **extra):
    kept = []
    for page in OPEN_PAGES:
        if page._out is not None:
            try:
                kept.append(page.finish().get("all_results"))
            except Exception:
                pass
    answer = {"error": scrub(str(message)), **{k: (scrub(v) if isinstance(v, str) else v) for k, v in extra.items()}}
    if kept:
        answer["rows_read_before_the_failure_kept_in"] = kept
    for values in OPEN_VALUES:
        values.close()
        if values.written:
            answer["values_written_before_the_failure"] = {"file": values.shown, "rows": values.written}
    print(dumps(answer))
    raise SystemExit(1)


class Timeout(Exception):
    pass


def alarm_handler(signum, frame):
    raise Timeout()


def timed_search(pattern, text, seconds):
    """pattern.search(text), stopped after `seconds` where the platform can: a pattern the caller
    wrote can backtrack without end."""
    if not hasattr(signal, "setitimer"):
        return pattern.search(text)
    old = signal.signal(signal.SIGALRM, alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return pattern.search(text)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text)


class LosslessPage:
    """A page an agent reads, and the whole result in a file the answer names.

    The page stays small (rows, and bytes when a byte limit is given); when there are more rows
    the whole result is written as JSON Lines under work/<agent>/tool-output (in a job,
    $OUT/tool-output) and named: nothing is cut. The file name is a digest of the page's key (a
    path), never of a value. Rows are written with ensure_ascii on: a path the filesystem gave as
    bytes that are not UTF-8 reaches Python as lone surrogates, which a UTF-8 file cannot hold
    and an escape can. A rerun that would replace a larger earlier file of the same name writes a
    new name and says which earlier file it kept.
    """

    def __init__(self, tool, key, limit, byte_limit=None):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = safe_name(tool)
        self.limit = limit
        self.byte_limit = byte_limit
        self.page = []
        self.page_bytes = 0
        self.full = False
        self.bytes_bound_hit = False
        self.total = 0
        self._out = None
        self._tmp = None
        OPEN_PAGES.append(self)
        # The key is the question (a path as it may be printed, a filter), plus this call's own nonce: two
        # questions that print alike (two files in directories whose names are withheld, two messages passed
        # in the call) never share a file, and a rerun never replaces an earlier result.
        digest = hashlib.sha256(dumps([key, NONCE], sort_keys=True).encode("utf-8")).hexdigest()[:16]
        name = "%s-%s.jsonl" % (self.tool, digest)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's output: the whole
            # result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (safe_name(job), name)
        else:
            agent = safe_name(os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row):
        self._out.write(dumps(row))
        self._out.write("\n")

    def add(self, row):
        self.total += 1
        if not self.full and len(self.page) < self.limit:
            size = len(dumps(row)) if self.byte_limit is not None else 0
            if self.byte_limit is None or self.page_bytes + size <= self.byte_limit:
                self.page.append(row)
                self.page_bytes += size
                return
            self.bytes_bound_hit = True
        # From the first row that does not fit, every later row goes to the file only: the page
        # is a prefix.
        self.full = True
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
        if self.byte_limit is not None:
            result["inline_byte_limit"] = self.byte_limit
            if self.bytes_bound_hit:
                result["inline_bounded_by_bytes"] = True
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            target, shown_as = self.path, self.shown
            if target.exists() and target.stat().st_size > os.path.getsize(self._tmp):
                n = 2
                while target.with_name("%s-%d%s" % (target.stem, n, target.suffix)).exists():
                    n += 1
                target = target.with_name("%s-%d%s" % (target.stem, n, target.suffix))
                shown_as = self.shown.rsplit("/", 1)[0] + "/" + target.name
                result["kept_earlier_larger_result"] = self.shown
            os.replace(self._tmp, target)
            result["all_results"] = shown_as
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The pattern of recovery_key_scan (encrypted-containers), copied: call `add` once per finding
    with its id, its locator and the value. With `enabled` false it writes nothing and
    `summary()` says so.
    """

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
                "file, not a sealed secret output. Run this as job_run tool=%s with "
                "secret_output: true, and ask again there. Nothing was written." % TOOL
            )
        self.path = Path(self.out) / VALUES_NAME
        self.shown = "store/jobs/%s/out/%s" % (safe_name(self.job), VALUES_NAME)
        # Created now, before anything is read: a file or a link already at that name is refused
        # by name at once (O_EXCL does not follow a link, a dangling one included), instead of
        # failing, or writing through it, after the scan. With nothing found it stays an empty
        # file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")
        OPEN_VALUES.append(self)

    def add(self, finding_id, locator, value):
        if not self.enabled:
            return
        # ensure_ascii: a file name that is not UTF-8 is a lone surrogate to Python; an escape
        # reads back, a raw write cannot.
        self._fh.write(dumps({"finding_id": finding_id, **locator, "value": value}))
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
            "format": VALUES_FORMAT if self.enabled else None,
        }


def open_values(args):
    """The values file, or a refusal as JSON: write_values must be true or false."""
    wanted = args.get("write_values", False)
    if not isinstance(wanted, bool):
        fail("write_values must be true or false")
    try:
        return SecretValues(wanted)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False)


def positive(args, name, default, maximum=None):
    value = args.get(name, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        fail("%s must be a positive integer" % name, **{name: value})
    if maximum is not None and value > maximum:
        fail("%s is at most %d" % (name, maximum), **{name: value})
    return value


def read_args():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args


def send(result):
    print(dumps(result, indent=2))


def run_main(main):
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure, and never a traceback
        fail("unexpected failure: " + (describe(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, exc)))
# --- shared with the pack's other tools: end -----------------------------------------------

WIRE = {0: "varint", 1: "64-bit", 2: "length-delimited", 3: "start group", 4: "end group", 5: "32-bit"}
MAX_FIELD_NUMBER = (1 << 29) - 1
DEFAULT_WINDOW = 8 << 20
HARD_WINDOW = 64 << 20
HEX_LIMIT = 65536
DEFAULT_DEPTH, HARD_DEPTH = 6, 32
DEFAULT_FIELDS, HARD_FIELDS = 100000, 500000
DEFAULT_LIMIT = 200
INLINE_BYTES = 1 << 20
DEFAULT_SECONDS = 60
# What a number field carries. A top-level varint is printed; every other number is held back (see emit).
# A length-delimited field is read as a nested message only when every field in it has a number up to this.
# Real messages use small numbers; the bytes of a string or a token that happen to parse as fields mostly
# do not, and what such a reading shows (field numbers, wire types, lengths) is derived from those bytes.
NESTED_FIELD_MAX = 300
NUMBER_KEYS = ("value", "as_bool", "zigzag_reading", "twos_complement_reading", "hex", "float_reading", "double_reading")


class Stop(Exception):
    """The field budget or the time limit ended the parse."""


class Context:
    def __init__(self, blob, base, max_depth, max_fields, deadline):
        self.blob = blob
        self.base = base
        self.max_depth = max_depth
        self.max_fields = max_fields
        self.deadline = deadline
        self.fields = 0
        self.stopped = None


def read_varint(blob, at, end):
    """(value, next, problem): a varint of at most ten bytes whose tenth byte is 0 or 1."""
    value, shift, start = 0, 0, at
    while True:
        if at >= end:
            return None, at, "a varint that starts at offset %d runs past the end of its message" % start
        byte = blob[at]
        at += 1
        if shift == 63 and byte > 1:
            return None, at, "a varint that starts at offset %d is longer than a 64-bit value" % start
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, at, None
        shift += 7
        if shift > 63:
            return None, at, "a varint that starts at offset %d is longer than ten bytes" % start


def printable(body):
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    # Every character, not most of them: a real string field has no control bytes in it, and a
    # nested message nearly always does (its field keys are low byte values).
    if all(c.isprintable() or c in "\n\r\t" for c in text):
        return text
    return None


def parse(ctx, start, end, depth, path):
    """(rows, status, problem) for the message in blob[start:end].

    status is ok, invalid (a structural error, in `problem`), unsupported (a group) or stopped (the
    budget or the clock). The rows before a problem are returned with it.
    """
    rows, at = [], start
    while at < end:
        ctx.fields += 1
        if ctx.fields > ctx.max_fields:
            ctx.stopped = "max_fields (%d) reached" % ctx.max_fields
            return rows, "stopped", {"offset": ctx.base + at, "reason": ctx.stopped}
        if ctx.fields % 256 == 0 and time.monotonic() > ctx.deadline:
            ctx.stopped = "max_seconds passed"
            return rows, "stopped", {"offset": ctx.base + at, "reason": ctx.stopped}
        field_start = at
        key, at, bad = read_varint(ctx.blob, at, end)
        if bad:
            return rows, "invalid", {"offset": ctx.base + field_start, "reason": bad}
        number, wire = key >> 3, key & 7
        if number == 0 or number > MAX_FIELD_NUMBER:
            return rows, "invalid", {"offset": ctx.base + field_start,
                                      "reason": "field number %d is not in 1 to %d" % (number, MAX_FIELD_NUMBER)}
        field_path = path + [number]
        row = {"field_path": ".".join(str(n) for n in field_path), "field": number, "wire_type": WIRE.get(wire, str(wire)),
               "depth": depth, "offset": ctx.base + field_start}
        if wire in (3, 4):
            return rows, "unsupported", {"offset": ctx.base + field_start,
                                         "reason": "a group (wire type %d): groups are deprecated and not parsed, and nothing after this "
                                                   "point in this message is read" % wire}
        if wire not in (0, 1, 2, 5):
            return rows, "invalid", {"offset": ctx.base + field_start, "reason": "wire type %d is not defined" % wire}
        if wire == 0:
            value, at, bad = read_varint(ctx.blob, at, end)
            if bad:
                return rows, "invalid", {"offset": ctx.base + field_start, "reason": bad}
            row["value"] = value
            if value in (0, 1):
                row["as_bool"] = bool(value)
            row["zigzag_reading"] = (value >> 1) ^ -(value & 1)
            if value >= 1 << 63:
                row["twos_complement_reading"] = value - (1 << 64)
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            if at + size > end:
                return rows, "invalid", {"offset": ctx.base + field_start,
                                         "reason": "a %d-bit field runs past the end of its message" % (size * 8)}
            raw = ctx.blob[at:at + size]
            at += size
            row["value"] = int.from_bytes(raw, "little")
            row["hex"] = raw.hex()
            real = struct.unpack("<d" if wire == 1 else "<f", raw)[0]
            if math.isfinite(real):
                row["float_reading" if wire == 5 else "double_reading"] = real
        else:
            length, at, bad = read_varint(ctx.blob, at, end)
            if bad:
                return rows, "invalid", {"offset": ctx.base + field_start, "reason": bad}
            if at + length > end:
                return rows, "invalid", {"offset": ctx.base + field_start,
                                         "reason": "a length-delimited field of %d bytes at offset %d runs past the end of its message"
                                                   % (length, ctx.base + at)}
            body = ctx.blob[at:at + length]
            row["payload_offset"] = ctx.base + at
            row["payload_bytes"] = length
            nested, text = None, None
            if length:
                if depth < ctx.max_depth:
                    inner, state, _ = parse(ctx, at, at + length, depth + 1, field_path)
                    if ctx.stopped:
                        return rows, "stopped", {"offset": ctx.base + field_start, "reason": ctx.stopped}
                    if state == "ok" and inner and all(r["field"] <= NESTED_FIELD_MAX for r in inner):
                        nested = inner
                text = printable(body)
            readings = []
            if nested:
                readings.append("nested message")
            if text is not None:
                readings.append("text")
            if nested and not (text is not None and length < 64):
                row["read_as"] = "nested message"
                row["children"] = len(nested)
                row["_children"] = nested
            elif text is not None:
                row["read_as"] = "text"
                row["characters"] = len(text)
                row["_value"] = ("text", text)
            elif length == 0:
                row["read_as"] = "empty"
            else:
                row["read_as"] = "bytes"
                row["_value"] = ("bytes", body.hex())
            others = [r for r in readings if r != row["read_as"]]
            if others:
                row["also_reads_as"] = others
            at += length
        rows.append(row)
    return rows, "ok", None


def main():
    started = time.monotonic()
    args = read_args()
    values = open_values(args)
    limit = positive(args, "limit", DEFAULT_LIMIT)
    max_depth = args.get("max_depth", DEFAULT_DEPTH)
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or not 0 <= max_depth <= HARD_DEPTH:
        fail("max_depth must be an integer from 0 to %d" % HARD_DEPTH, max_depth=max_depth)
    max_fields = positive(args, "max_fields", DEFAULT_FIELDS, HARD_FIELDS)
    max_seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if not isinstance(max_seconds, (int, float)) or isinstance(max_seconds, bool) or max_seconds <= 0:
        fail("max_seconds must be a positive number")
    offset = args.get("offset", 0)
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        fail("offset must be a non-negative integer")
    length = args.get("length")
    if length is not None:
        length = positive(args, "length", None, HARD_WINDOW)

    window = {}
    if args.get("hex"):
        if not isinstance(args["hex"], str):
            fail("hex must be a string")
        try:
            data = binascii.unhexlify("".join(args["hex"].split()))
        except (binascii.Error, ValueError) as exc:
            fail("hex is not valid hexadecimal", reason=str(exc))
        if len(data) > HEX_LIMIT:
            fail("hex is limited to %d bytes: what is passed in a call is recorded in the trace; pass a file with path" % HEX_LIMIT,
                 bytes=len(data))
        source, source_real, file_bytes = "hex", "hex", None
        if offset > len(data):
            fail("offset is past the end of the message", offset=offset, bytes=len(data))
        blob = data[offset:]
        if length is not None:
            blob = blob[:length]
        window = {"offset": offset, "bytes": len(blob), "file_bytes": None, "bytes_after_window": len(data) - offset - len(blob)}
    else:
        path = args.get("path")
        if not isinstance(path, str) or not path:
            fail("path or hex is required: a file holding a protobuf message")
        try:
            with open(path, "rb") as fh:
                file_bytes = os.fstat(fh.fileno()).st_size
                if offset > file_bytes:
                    fail("offset is past the end of the file", offset=offset, bytes=file_bytes)
                want = min(length or DEFAULT_WINDOW, file_bytes - offset)
                fh.seek(offset)
                blob = fh.read(want)
        except OSError as exc:
            fail("cannot read that file", path=shown(path, False), reason=describe(exc))
        source, source_real = shown(path), os.path.realpath(path)
        window = {"offset": offset, "bytes": len(blob), "file_bytes": file_bytes, "bytes_after_window": file_bytes - offset - len(blob)}
        if len(blob) < want:
            window["short_read"] = "the file returned %d of %d bytes asked for" % (len(blob), want)
    if window["bytes_after_window"] > 0:
        window["next_offset"] = offset + len(blob)
        window["note"] = ("Only this window was read: the %d bytes after it are not decoded. Run again at next_offset to continue; "
                          "a message that spans the boundary will be reported as running past its end." % window["bytes_after_window"])

    ctx = Context(blob, offset, max_depth, max_fields, started + max_seconds)
    rows, state, problem = parse(ctx, 0, len(blob), 0, [])

    fields = LosslessPage(TOOL, [source, offset, length, max_depth], limit, INLINE_BYTES)
    counters = {"fields": 0, "varint": 0, "64-bit": 0, "32-bit": 0, "length-delimited": 0, "nested_messages": 0,
                "text_values_withheld": 0, "bytes_values_withheld": 0, "number_values_withheld": 0, "deepest": 0}
    serial = [0]

    def emit(items):
        for row in items:
            children = row.pop("_children", None)
            held = row.pop("_value", None)
            counters["fields"] += 1
            counters[row["wire_type"]] += 1
            counters["deepest"] = max(counters["deepest"], row["depth"])
            row["source"] = source
            # A number is printed only when it is a top-level varint. Under a length-delimited field it may be
            # the content of a string or of bytes read as a nested message (a token's bytes parse as fields about
            # one time in a few hundred), and a fixed-width value is raw bytes: those go to the values file.
            if row["wire_type"] in ("varint", "64-bit", "32-bit") and (row["depth"] >= 1 or row["wire_type"] != "varint"):
                numbers = {k: row.pop(k) for k in NUMBER_KEYS if k in row}
                serial[0] += 1
                finding = "V%06d" % serial[0]
                row["finding_id"] = finding
                row["value_withheld"] = ("inside a length-delimited field, so it may be the content of a string or of bytes"
                                         if row["depth"] >= 1 else "a fixed-width value is raw bytes")
                counters["number_values_withheld"] += 1
                values.add(finding, {"source": source_real, "field_path": row["field_path"], "offset": row["offset"],
                                     "payload_offset": None, "kind": "number", "bytes": None}, numbers)
            if held:
                serial[0] += 1
                finding = "V%06d" % serial[0]
                row["finding_id"] = finding
                kind, value = held
                counters["text_values_withheld" if kind == "text" else "bytes_values_withheld"] += 1
                values.add(finding, {"source": source_real, "field_path": row["field_path"], "offset": row["offset"],
                                     "payload_offset": row.get("payload_offset"), "kind": kind,
                                     "bytes": row["payload_bytes"]}, value)
            if children:
                counters["nested_messages"] += 1
            fields.add(row)
            if children:
                emit(children)

    emit(rows)
    values.close()
    page = fields.finish()
    if not blob:
        structure = {"status": "empty", "reason": "the window holds no bytes"}
    elif state == "ok":
        structure = {"status": "valid", "reason": "every byte of the window parsed as protobuf wire format"}
    elif state == "stopped":
        structure = {"status": "partial", "reason": problem["reason"]}
    else:
        structure = {"status": state, "reason": problem["reason"]}
    if problem:
        structure["problem_offset"] = problem["offset"]
    structure["bytes_in_window"] = len(blob)
    structure["consistent_with_protobuf_wire_format"] = bool(state == "ok" and rows)
    send({
        "source": source,
        "parser": PARSER,
        "window": window,
        "structure": structure,
        "fields": fields.page,
        "field_count": counters["fields"],
        "top_level_fields": len(rows),
        "counts": counters,
        "limits": {"max_depth": max_depth, "max_fields": max_fields, "max_seconds": max_seconds, "inline_rows": limit,
                   "window_default_bytes": DEFAULT_WINDOW, "window_hard_cap_bytes": HARD_WINDOW},
        "pages": {"fields": page},
        "truncated": page["truncated"],
        "secret_values": values.summary(),
        "paths_withheld": PATHS_WITHHELD[0],
        "note": "This is wire structure, not meaning: no field name, unit, enum or signedness is known without the .proto "
                "file. A top-level varint is printed raw, with its zigzag reading (and, where the top bit is set, the two's-"
                "complement reading) beside it; which one is meant is the schema's to say. Nothing else that holds a "
                "value is printed: not the text of a string field, not the bytes of a bytes field, not a number under a "
                "length-delimited field (it may be the content of a string that parsed as a nested message), not a "
                "fixed-width value. Each has its offset, length and reading, and a finding id; the value is in the values "
                "file only when write_values was asked for in a job run with secret_output: true. read_as is a guess between a nested message, text and bytes "
                "(also_reads_as lists the others it could be), and a nested reading needs every field number in it to be at most 300 "
                "(what a misread string would show of itself is derived from its bytes). A group makes the message `unsupported`, and any "
                "structural error names its offset: consistent_with_protobuf_wire_format means the whole window parsed, "
                "and a short or ordinary blob can parse by chance. Offsets are absolute in the file.",
    })


if __name__ == "__main__":
    run_main(main)

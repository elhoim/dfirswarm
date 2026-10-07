#!/usr/bin/env python3
"""Say what a delivered directory holds, which collectors left records in it, and what those records say was not copied.

This is a survey of names, a few first bytes and the collectors' own logs. It is a hypothesis about the delivery, not an
audit of it. What it measures:

  - every object it walks, classified one by one (the delivery is `mixed` when copied files sit beside a disk container, a
    memory capture, an archive or a file named like one): a signature in the first bytes where there is one, the extension
    otherwise, and each says which. A name that says image or raw with no signature is `unknown`, not a physical image: a
    raw memory capture has no signature either. Nothing is opened but the first 4 KiB of the objects named in
    `reads_first_bytes_of`; an archive or a container is not opened and its members are not listed;
  - the collector markers found, by their paths (more than one collector may have left records in one delivery, and one
    collector may have run more than once): KAPE `*_CopyLog.csv`, `*_SkipLog.csv` and `*_ConsoleLog.txt`, UAC `uac.log`
    and the `[root]`, `[bodyfile]`, `[live_response]` directories, Velociraptor `uploads.json`. A top-level directory named
    C, C$ or Windows is a layout clue only: KAPE targets, CyLR output and a hand copy all look like it, and nothing here
    names CyLR;
  - what each recognised log records, read whole and streamed: the columns and row counts of a KAPE copy or skip log, the
    lines of a UAC log that start with a date, a time and an upper-case level word (INFO, WARNING, ERROR, COMMAND, DEBUG,
    CRITICAL: UAC's own format is not verified here, so a line that matches nothing is counted and kept unlabelled), the
    rows of a Velociraptor `uploads.json` (JSON Lines) and any non-empty Error field. A log whose columns or lines are not
    recognised is `partial` or `unsupported`, and then there is no failure count at all, never a zero.

What it does not measure: that the collector finished, what it was asked to copy (the profile, targets and artefacts are not
read), whether a recorded failure matters, whether a digest in a log matches the delivered file, the original path of a file
(collection_index), the collector's version (reported only where a log states it, with its line), or what a log omits. A
skip-log row is a recorded skip with the collector's own words; whether it is a failure is the collector's meaning, not this
tool's. "No failure recorded" is a statement about the rows read, not about the acquisition.

SECRET-SAFE OUTPUT (docs/packs.md, "Secrets and sensitive output"). Paths and log text are printed through the shared
withholding block: a string shaped like a recovery password, an access key, a token, a private-key header or the user-info of
a URL is replaced by its kind and length, in every channel (a path, a log line, an error). The shapes are few and exact, so a
secret of no recognisable shape can still appear in a collector's log: the skill says to run this as a job with
`secret_output: true`. `write_values: true` (a job only) writes the real strings to `$OUT/collection-id-values.jsonl`, mode
0600, created before anything is read.
"""
# ---- BEGIN SHARED BLOCK ----------------------------------------------------------------------------------------------
# Identical in collection_id and collection_index. A tool is standalone, so what the two share is copied, as LosslessPage
# is in every pack tool, and tests/pack-triage-collection.test.ts holds the two copies equal. Edit it in both, never in
# one. It holds: the error form, typed arguments, where an output may be written and published without replacing another,
# the lossless table, the secret-safe values file (the SecretValues of recovery_key_scan), the withholding of strings
# shaped like a credential, the head-of-file classifier for what a delivery may hold besides copied files, and a deadline.
import atexit
import errno
import json
import os
import re
import secrets
import stat
import sys
import tempfile
import time
from pathlib import Path

DEFAULT_LIMIT = 200
FIRST_PROBLEMS = 25               # how many problems an answer names inline; every one is in the file the table names
INLINE_BUDGET = 256 << 10         # bytes of rows an answer carries inline; the rest of a table is in its file
CHUNK = 1 << 20
HEAD_BYTES = 4096
MIN_RAW_BYTES = 1 << 20           # a file smaller than this is not read for a volume signature ($Boot is a boot sector, not a disk)
DEADLINE = [None]


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def fail(message, **extra):
    """An error answer: JSON, exit 1, never a traceback. A name in it that is shaped like a credential is withheld."""
    print(json.dumps({"error": scrub(str(message)), "status": "failed", **{k: scrub_all(v) for k, v in extra.items()}}, default=str))
    raise SystemExit(1)


def scrub_all(value):
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, dict):
        return {k: scrub_all(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub_all(v) for v in value]
    return value


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


def start_clock(seconds):
    DEADLINE[0] = time.monotonic() + seconds


def out_of_time():
    return DEADLINE[0] is not None and time.monotonic() > DEADLINE[0]


# ---- where an output may be written ------------------------------------------------------------------------------


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place outside it, the run directory itself, or
    anything under inputs/ is refused. A string check is not enough: `work/../inputs/x`, an absolute path and a symlink
    that points out all name a place the tool must not write, so the path is resolved first and directories compared.
    In a job the run directory is read-only and only $OUT is written, so a place outside $OUT is refused with the way to
    name one (work/<your agent id>/..., which the harness maps to $OUT), not left to fail on a read-only file system."""
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
    """How an output is named in an answer: a job's $OUT is sealed as store/jobs/<job>/out, so a place under it is shown
    as it will be cited."""
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
    """Move a finished file to `path` without replacing what is there: a file at the name is an earlier answer (a complete
    one, perhaps, where this run was cut short by a lower limit) and stays; this one is kept beside it as name.2.ext,
    unless it holds the same bytes, when the file already there is it. Returns the path it has."""
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


class Table:
    """The rows an answer carries inline, and the whole in a JSON Lines file it names. Rows past `limit` (or past the
    inline byte budget) go to the file, so nothing is cut: under $OUT/tool-output in a job, work/<agent>/tool-output
    otherwise, with a random name (never a digest of the request). With `dest` or `always` the whole is written even when
    it fits; with `dest` it goes there, and never over a file that is already there: that one is kept and this one is
    named beside it. Rows are written with ASCII escapes, so a lone surrogate from a non-UTF-8 name survives and no row can
    raise."""

    def __init__(self, tool, limit, dest=None, always=False, budget=INLINE_BUDGET):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit, self.budget, self.dest, self.always = limit, budget, dest, always
        self.page, self.total, self.bytes = [], 0, 0
        self._out = self._tmp = None
        if dest:
            self.path = Path(dest)
        else:
            name = "%s-%s.jsonl" % (self.tool, secrets.token_hex(8))
            job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
            if job and out:
                self.path = Path(out) / "tool-output" / name
            else:
                agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
                self.path = Path("work") / agent / "tool-output" / name
        if dest or always:
            self._open_tmp()

    def _open_tmp(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.tool)
            self._tmp = Path(name)
            _TEMPS.add(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace")
        except OSError as exc:
            fail("the whole result could not be written: %s cannot be created (%s)" % (shown_output(self.path.parent), describe(exc)))

    def open_now(self):
        """Create the file now (a table whose file would lie inside the tree being walked must be known before the walk)."""
        if self._out is None:
            self._open_tmp()

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
            self._open_tmp()
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

    The secret-safe output pattern of recovery_key_scan (docs/packs.md, "Secrets and sensitive output"), copied unchanged
    but for the file's name and the tool named in the refusal. With `enabled` false it writes nothing and `summary()` says
    so. Enabled, it is refused outside a job; inside one the file is created at once, before anything is read (mode 0600,
    O_EXCL and O_NOFOLLOW: a file or a link already at that name is refused by name, a dangling link included), so with
    nothing withheld it stays an empty file and the answer says written: 0.
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
            "format": "JSON Lines, mode 0600: finding_id, where, value (the real string)" if self.enabled else None,
        }


# ---- withholding: nothing shaped like a credential is printed ------------------------------------------------------
# A path or a line of a collector's log can carry a string that is a secret. Only shapes that name their own kind are
# withheld (a name that merely looks random is a GUID, a hash or a cache name, and is evidence): so a secret of no
# recognisable shape is not caught, and the skill says to run the tool as a job with secret_output: true. What is caught is
# withheld in every channel (a path, a log line, an error), the same strings in both tools of the pack; the real string goes
# to the values file when write_values is asked, in a job.

SHAPES = [
    ("recovery-password-shaped text", re.compile(r"(?<![0-9])[0-9]{6}(?:-[0-9]{6}){7}(?![0-9])")),
    ("access-key-shaped text", re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}(?![A-Za-z0-9])")),
    ("token-shaped text", re.compile(r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}"
                                     r"|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}"
                                     r"|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)")),
    ("private-key header", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("user-info of a URL", re.compile(r"(?<=://)[^/?#\s@]+(?=@)")),
]
_ANY = re.compile("|".join("(?:%s)" % rx.pattern for _kind, rx in SHAPES))
WITHHELD = {"count": 0}
VALUES = [None]


def scrub(text, where=None):
    """The text with every string of a withheld shape replaced by what it was (a kind and a length). With a values file
    open, the original goes there once per call, named by `where`."""
    if not isinstance(text, str) or not _ANY.search(text):
        return text
    out = text
    for kind, rx in SHAPES:
        out = rx.sub(lambda m, k=kind: "<%s withheld, %d characters>" % (k, len(m.group())), out)
    if out != text:
        WITHHELD["count"] += 1
        if VALUES[0] is not None:
            VALUES[0].add("W%06d" % WITHHELD["count"], {"where": where or "text"}, text)
    return out


def shown(path, where=None):
    """A path as it may be printed: the whole string goes through scrub (a component shaped like a recovery password, a
    key id or a token is withheld wherever it stands in the path)."""
    return scrub(path, where)


# ---- what a delivery may hold besides copied files ---------------------------------------------------------------------

DISK_SIGNATURES = [
    (0, b"EVF\x09\x0d\x0a\xff\x00", "disk_container", "EnCase evidence file (EWF, E01 family)"),
    (0, b"EVF2\x0d\x0a\x81\x00", "disk_container", "EnCase evidence file version 2 (Ex01)"),
    (0, b"QFI\xfb", "disk_container", "QCOW disk image"),
    (0, b"KDMV", "disk_container", "VMware sparse extent (VMDK)"),
    (0, b"# Disk DescriptorFile", "disk_container", "VMware VMDK descriptor"),
    (0, b"vhdxfile", "disk_container", "VHDX virtual disk"),
    (0, b"conectix", "disk_container", "VHD virtual disk (dynamic or differencing: the footer is repeated at the start)"),
    (0, b"<<< Oracle VM VirtualBox Disk Image >>>", "disk_container", "VirtualBox VDI"),
    (0, b"LVF\x09\x0d\x0a\xff\x00", "archive", "EnCase logical evidence file (L01)"),
    (0, b"ADSEGMENTEDFILE\x00", "archive", "AccessData AD1 logical image"),
    (0, b"ADCRYPT", "archive", "AccessData AD1 logical image, encrypted"),
    (0, b"PK\x03\x04", "archive", "ZIP"),
    (0, b"PK\x05\x06", "archive", "ZIP (empty)"),
    (0, b"7z\xbc\xaf\x27\x1c", "archive", "7-Zip"),
    (0, b"Rar!\x1a\x07", "archive", "RAR"),
    (0, b"\x1f\x8b", "archive", "gzip"),
    (0, b"BZh", "archive", "bzip2"),
    (0, b"\xfd7zXZ\x00", "archive", "xz"),
    (0, b"\x28\xb5\x2f\xfd", "archive", "Zstandard"),
    (257, b"ustar", "archive", "tar"),
    (0, b"EMiL", "memory_capture", "LiME memory capture"),
    (0, b"PAGEDU64", "memory_capture", "Windows crash dump (what it holds depends on the dump type, which is not read here)"),
    (0, b"PAGEDUMP", "memory_capture", "Windows crash dump (what it holds depends on the dump type, which is not read here)"),
]
RAW_SIGNATURES = [
    (512, b"EFI PART", "a GPT header at offset 512"),
    (3, b"NTFS    ", "an NTFS boot sector (OEM id at offset 3)"),
    (3, b"EXFAT   ", "an exFAT boot sector (OEM id at offset 3)"),
    (3, b"-FVE-FS-", "a BitLocker volume header (OEM id at offset 3)"),
    (82, b"FAT32   ", "a FAT32 boot sector (type string at offset 82)"),
    (0, b"LUKS\xba\xbe", "a LUKS header"),
    (0, b"XFSB", "an XFS superblock"),
    (32, b"NXSB", "an APFS container superblock (offset 32)"),
]
DISK_EXT = {".e01", ".ex01", ".dd", ".raw", ".img", ".vhd", ".vhdx", ".vmdk", ".qcow2", ".qcow", ".vdi", ".001"}
RAW_EXT = {".dd", ".raw", ".img", ".bin", ".001", ""}
MEMORY_EXT = {".mem", ".vmem", ".vmss", ".lime"}
ARCHIVE_EXT = {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".bz2", ".xz", ".zst", ".ad1", ".l01"}


def wants_head(name, size, top_level):
    """Whether a file's first bytes are read to classify it: a top-level object, a file named like an image, a memory
    capture or an archive, and any file of at least MIN_RAW_BYTES (a renamed image is large). The rest are copied files."""
    ext = os.path.splitext(name)[1].lower()
    return top_level or ext in DISK_EXT or ext in MEMORY_EXT or ext in ARCHIVE_EXT or size >= MIN_RAW_BYTES


def open_regular(path, **kw):
    """A regular file opened for reading as text without following a link at its name and without blocking on a pipe: a
    log that was swapped for a link or a pipe after the walk is refused, not read."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        return os.fdopen(fd, "r", **kw)
    except BaseException:
        os.close(fd)
        raise


def read_head(path):
    """The first HEAD_BYTES of a regular file, opened without following a link and without blocking on a pipe; None for
    anything that is not a regular file once opened."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.read(fd, HEAD_BYTES)
    finally:
        os.close(fd)


def classify_head(name, head, size, top_level):
    """What a file is, from its first bytes and its name, or None when it is an ordinary file. The answer says which
    (`basis`: bytes, or extension only), and what in the bytes it rests on. A raw image has no container header: its
    volume or partition signatures are looked for only in a file of at least MIN_RAW_BYTES. A name that says image, raw or
    memory with nothing in the bytes to confirm it is `unknown`: a raw memory capture carries no signature either. An
    archive signature counts only on a file named like an archive, or on a top-level file with no extension (a .docx is a ZIP
    and is a document)."""
    ext = os.path.splitext(name)[1].lower()
    for offset, magic, kind, fmt in DISK_SIGNATURES:
        if kind == "archive" and ext not in ARCHIVE_EXT and not (top_level and ext == ""):
            continue
        if head[offset:offset + len(magic)] == magic:
            return {"class": kind, "format": fmt, "basis": "bytes", "evidence": "signature at offset %d" % offset}
    if head[:4] == b"\x7fELF" and len(head) > 17 and head[5] in (1, 2):
        etype = int.from_bytes(head[16:18], "little" if head[5] == 1 else "big")
        if etype == 4:
            return {"class": "memory_capture", "format": "ELF core dump (one process, or a kernel core)", "basis": "bytes",
                    "evidence": "ELF header, type core"}
    if ext in RAW_EXT and size >= MIN_RAW_BYTES:
        seen = [what for offset, magic, what in RAW_SIGNATURES if head[offset:offset + len(magic)] == magic]
        if len(head) >= 512 and head[510:512] == b"\x55\xaa":
            seen.append("a boot signature at offset 510 (an MBR, or a FAT or NTFS boot sector)")
        if len(head) > 1082 and head[1080:1082] == b"\x53\xef":
            seen.append("an ext superblock magic at offset 1080")
        if seen:
            return {"class": "disk_container", "format": "raw image (no container header)", "basis": "bytes",
                    "evidence": "; ".join(seen) + ". Whether it is a whole disk or one volume is not decided here"}
    if ext in MEMORY_EXT:
        return {"class": "memory_capture", "format": "named like a memory capture (no signature to confirm it)",
                "basis": "extension only", "evidence": "name ends %s" % ext}
    if ext in DISK_EXT:
        return {"class": "unknown", "format": None, "basis": "extension only",
                "evidence": "name ends %s but the first bytes carry no recognised container or volume signature; a raw "
                            "memory capture and a raw disk with an unusual first sector both look like this" % ext}
    if ext in ARCHIVE_EXT:
        return {"class": "archive", "format": "named like an archive (no signature to confirm it)", "basis": "extension only",
                "evidence": "name ends %s" % ext}
    return None
# ---- END SHARED BLOCK ------------------------------------------------------------------------------------------------

import csv
import json
import os
import re
import stat

PARSER = "collection_id/2"
TOOL = "collection_id"
VALUES_NAME = "collection-id-values.jsonl"
MAX_LINE = 1 << 20                # a log line longer than this is read in part; the whole line stays in the evidence at its locator
MAX_CONSECUTIVE_CSV_ERRORS = 1000
MAX_DISTINCT = 100000             # distinct artefact names counted from a Velociraptor index; beyond it they are counted, not named

FAMILIES = {
    "$mft": "the NTFS master file table", "$j": "the USN change journal", "$logfile": "the NTFS transaction log",
    "system": "the SYSTEM hive", "software": "the SOFTWARE hive", "sam": "the SAM hive", "security": "the SECURITY hive",
    "ntuser.dat": "a user hive", "usrclass.dat": "a shell-bag hive", "amcache.hve": "Amcache", "srudb.dat": "SRUM",
    "consolehost_history.txt": "PowerShell history",
    "auth.log": "a Linux authentication log", "secure": "a Linux authentication log",
    "wtmp": "Linux login records", "btmp": "Linux failed logins",
    "packages.xml": "the Android package list", "manifest.db": "an iOS backup manifest",
}
UAC_DIRS = ("[root]", "[bodyfile]", "[live_response]")
UAC_EVENT = re.compile(r"^\s*\[?(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:\s?(?:Z|[+-]\d{2}:?\d{2}))?)\]?\s*"
                       r"(?:[-:|]\s*)?\[?(?P<level>INFO|WARNING|ERROR|COMMAND|DEBUG|CRITICAL)\]?(?:\s|:|$)")
UAC_FAILURE_WORDS = ("error", "cannot", "permission denied", "failed")
KAPE_VERSION = re.compile(r"KAPE version\s+(\d+(?:\.\d+)+)")
SKIP_TARGET_COLUMNS = ("sourcefile", "source", "filename", "file", "path")
SKIP_REASON_COLUMNS = ("reason", "message", "error", "status")
UPLOAD_TARGET_KEYS = ("vfs_path", "Path", "path", "StoredName", "ComponentPath")
UPLOAD_ERROR_KEYS = ("Error", "error", "_Error")


class Survey:
    def __init__(self, root, limit):
        self.root = root
        self.directories = self.files = 0
        self.links = []                       # first problems only; `links_total` counts all
        self.links_total = self.special_total = 0
        self.special = []
        self.errors = []
        self.errors_total = 0
        self.stopped = None
        self.families = {}
        self.kape = {}                        # (directory, run id) -> {"copy": rel, "skip": rel, "console": rel}
        self.uac_logs, self.uac_dirs, self.uploads = [], [], []
        self.layout_clues = []
        self.counts = {"logical_files": 0, "disk_container": 0, "memory_capture": 0, "archive": 0, "unknown": 0}
        self.nested_archives = 0
        self.reads_head = 0
        self.head_errors = 0
        self.objects = Table(TOOL + "-objects", limit)

    def problem(self, path, what, exc):
        self.errors_total += 1
        if len(self.errors) < FIRST_PROBLEMS:
            self.errors.append({"path": shown(path, "walk error"), "what": what, "error": describe(exc)})


def rel_of(root, path):
    return os.path.relpath(path, root)


def walk(survey):
    root = survey.root
    stack = [root]
    while stack:
        if out_of_time():
            survey.stopped = {"reason": "the time limit ended the walk", "directories_not_listed": len(stack)}
            return
        directory = stack.pop()
        is_top = directory == root
        try:
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            survey.problem(directory, "the directory could not be listed", exc)
            continue
        survey.directories += 1
        subdirs = []
        for entry in entries:
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                survey.problem(entry.path, "the entry could not be examined", exc)
                continue
            mode = st.st_mode
            if stat.S_ISLNK(mode):
                survey.links_total += 1
                if len(survey.links) < FIRST_PROBLEMS:
                    survey.links.append(shown(rel_of(root, entry.path), "symbolic link"))
            elif stat.S_ISDIR(mode):
                subdirs.append(entry.path)
                if entry.name in UAC_DIRS:
                    survey.uac_dirs.append(rel_of(root, entry.path))
                if is_top and entry.name.lower() in ("c", "c$", "windows"):
                    survey.layout_clues.append({"path": shown(entry.name, "layout clue"), "basis": "a top-level directory name",
                                                "compatible_with": ["a KAPE target tree", "CyLR output", "a hand-made copy"]})
            elif stat.S_ISREG(mode):
                survey.files += 1
                handle_file(survey, entry, st, is_top)
            else:
                survey.special_total += 1
                if len(survey.special) < FIRST_PROBLEMS:
                    survey.special.append(shown(rel_of(root, entry.path), "special file"))
        stack.extend(reversed(subdirs))


def handle_file(survey, entry, st, is_top):
    name, root = entry.name, survey.root
    lower = name.lower()
    rel = rel_of(root, entry.path)
    if lower in FAMILIES:
        fam = survey.families.setdefault(FAMILIES[lower], {"count": 0, "first_paths": []})
        fam["count"] += 1
        if len(fam["first_paths"]) < 3:
            fam["first_paths"].append(shown(rel, "artefact family path"))
    directory = os.path.dirname(rel)
    for suffix, key in (("_copylog.csv", "copy"), ("_skiplog.csv", "skip"), ("_consolelog.txt", "console")):
        if lower.endswith(suffix):
            survey.kape.setdefault((directory, name[:-len(suffix)]), {})[key] = rel
    if name == "uac.log":
        survey.uac_logs.append(rel)
    if name == "uploads.json":
        survey.uploads.append(rel)
    if wants_head(name, st.st_size, is_top):
        survey.reads_head += 1
        try:
            head = read_head(entry.path)
        except OSError as exc:
            survey.head_errors += 1
            survey.problem(entry.path, "the first bytes could not be read", exc)
            head = None
        found = classify_head(name, head, st.st_size, is_top) if head is not None else None
        if found:
            if found["class"] == "archive" and not is_top:
                survey.nested_archives += 1
                return
            survey.counts[found["class"]] += 1
            survey.objects.add({"path": shown(rel, "object path"), "top_level": is_top, "bytes": st.st_size, **found,
                                "note": "classified by this tool from the first bytes and the name; the object was not opened"})


# ---- the collectors' own records ---------------------------------------------------------------------------------------


def open_text(path):
    return open_regular(path, encoding="utf-8-sig", errors="surrogateescape", newline="")


def undecodable(text):
    return any("\udc80" <= c <= "\udcff" for c in text)


def read_csv_log(root, rel, kind, failures):
    """A KAPE copy or skip log, streamed. A skip-log row is kept whole as a failure row with the collector's own words; a copy
    log is counted. Columns that are not the ones expected make the log `partial`, and a log that cannot be read `unsupported`."""
    path = os.path.join(root, rel)
    record = {"log": shown(rel, "log path"), "kind": kind, "adapter": "kape_csv/1", "status": "parsed", "rows": 0,
              "malformed_rows": 0, "rows_with_undecodable_bytes": 0, "problems": []}
    try:
        fh = open_text(path)
    except OSError as exc:
        record.update(status="unreadable", reason=describe(exc))
        return record
    with fh:
        reader = csv.reader(fh)
        try:
            header = next(reader)
        except StopIteration:
            record.update(status="unsupported", reason="the file is empty: no header row")
            return record
        except (csv.Error, OSError) as exc:
            record.update(status="unsupported", reason="the header row could not be read (%s)" % describe(exc))
            return record
        names = [h.strip() for h in header]
        lowered = [n.lower() for n in names]
        record["columns"] = [scrub(n, "csv header") for n in names]
        target_col = next((i for i, n in enumerate(lowered) if n in SKIP_TARGET_COLUMNS), None)
        reason_col = next((i for i, n in enumerate(lowered) if n in SKIP_REASON_COLUMNS), None)
        if kind == "copy_log":
            if "sourcefile" not in lowered:
                record.update(status="partial", reason="no SourceFile column: rows are counted, nothing else is read")
        elif target_col is None and reason_col is None:
            record.update(status="partial", reason="neither a target column nor a reason column is recognised: every row is kept whole")
        ordinal, consecutive = 0, 0
        while True:
            if out_of_time():
                record.update(status="partial", reason="the time limit stopped the read after row %d" % ordinal)
                break
            try:
                row = next(reader)
            except StopIteration:
                break
            except csv.Error as exc:
                record["malformed_rows"] += 1
                consecutive += 1
                if len(record["problems"]) < FIRST_PROBLEMS:
                    record["problems"].append({"line": reader.line_num, "error": describe(exc)})
                if consecutive >= MAX_CONSECUTIVE_CSV_ERRORS:
                    record.update(status="partial", reason="the read stopped after %d consecutive unreadable rows" % consecutive)
                    break
                continue
            consecutive = 0
            if not row:
                continue
            ordinal += 1
            record["rows"] = ordinal
            bad = len(row) != len(names)
            if bad:
                record["malformed_rows"] += 1
                if len(record["problems"]) < FIRST_PROBLEMS:
                    record["problems"].append({"line": reader.line_num, "error": "%d fields where the header has %d" % (len(row), len(names))})
            if any(undecodable(v) for v in row):
                record["rows_with_undecodable_bytes"] += 1
            if kind == "skip_log":
                where = "skip log row %d" % ordinal
                failures.add({"collector": "KAPE", "log": record["log"], "locator": {"row": ordinal, "line": reader.line_num},
                              "outcome": "skipped",
                              "target": scrub(row[target_col], where) if target_col is not None and target_col < len(row) else None,
                              "reason": scrub(row[reason_col], where) if reason_col is not None and reason_col < len(row) else None,
                              "row_values": {scrub(n, where): scrub(v, where) for n, v in zip(names, row)},
                              "malformed": bad})
        if record["malformed_rows"] and record["status"] == "parsed":
            record["status"] = "partial"
            record["reason"] = "some rows are malformed (see problems): they are counted, and kept whole where they are a skip row"
    return record


def read_console_version(root, rel):
    path = os.path.join(root, rel)
    try:
        with open_text(path) as fh:
            for number, line in enumerate(fh, 1):
                if number > 200:
                    break
                found = KAPE_VERSION.search(line)
                if found:
                    return {"value": found.group(1), "from": "%s line %d" % (shown(rel, "log path"), number)}
    except OSError:
        pass
    return None


def read_uac_log(root, rel, failures):
    path = os.path.join(root, rel)
    record = {"log": shown(rel, "log path"), "kind": "uac_log", "adapter": "uac_log_lines/1", "status": "parsed", "lines": 0,
              "events": 0, "levels": {}, "unmatched_lines": 0, "unlabelled_lines_with_failure_words": 0,
              "unlabelled_examples": [], "lines_naming_dates_or_host": [], "long_lines": 0, "problems": []}
    try:
        fh = open_regular(path, encoding="utf-8", errors="surrogateescape", newline="")
    except OSError as exc:
        record.update(status="unreadable", reason=describe(exc))
        return record
    with fh:
        number = 0
        while True:
            if out_of_time():
                record.update(status="partial", reason="the time limit stopped the read after line %d" % number)
                break
            try:
                line = fh.readline(MAX_LINE)
            except OSError as exc:
                record.update(status="partial", reason="the read stopped at line %d (%s)" % (number + 1, describe(exc)))
                break
            if not line:
                break
            number += 1
            if len(line) == MAX_LINE and not line.endswith("\n"):
                record["long_lines"] += 1
                while True:                  # the rest of the line is skipped, not stored: the whole line is in the evidence at this number
                    rest = fh.readline(MAX_LINE)
                    if not rest or rest.endswith("\n"):
                        break
            record["lines"] = number
            text = line.rstrip("\r\n")
            low = text.lower()
            if ("start date" in low or "end date" in low or "hostname" in low) and len(record["lines_naming_dates_or_host"]) < FIRST_PROBLEMS:
                record["lines_naming_dates_or_host"].append({"line": number, "text": scrub(text, "UAC log line %d" % number)})
            found = UAC_EVENT.match(text)
            if found:
                record["events"] += 1
                level = found.group("level")
                record["levels"][level] = record["levels"].get(level, 0) + 1
                if level == "ERROR":
                    failures.add({"collector": "UAC", "log": record["log"], "locator": {"line": number}, "outcome": "error",
                                  "target": None, "reason": scrub(text, "UAC log line %d" % number),
                                  "long_line": len(line) == MAX_LINE and not line.endswith("\n")})
            elif text.strip():
                record["unmatched_lines"] += 1
                if any(w in low for w in UAC_FAILURE_WORDS):
                    record["unlabelled_lines_with_failure_words"] += 1
                    if len(record["unlabelled_examples"]) < FIRST_PROBLEMS:
                        record["unlabelled_examples"].append({"line": number, "text": scrub(text, "UAC log line %d" % number)})
    if record["status"] == "parsed" and record["events"] == 0:
        record["status"] = "unsupported"
        record["reason"] = "no line starts with a date, a time and a level word this adapter knows: failures are not counted from this log"
    elif record["status"] == "parsed" and record["unmatched_lines"]:
        record["status"] = "partial"
        record["reason"] = "%d line(s) match no recognised event shape: counted, kept unlabelled, never counted as failures" % record["unmatched_lines"]
    return record


def read_uploads(root, rel, failures):
    path = os.path.join(root, rel)
    record = {"log": shown(rel, "log path"), "kind": "uploads_json", "adapter": "velociraptor_uploads_jsonl/1", "status": "parsed",
              "rows": 0, "objects": 0, "malformed_rows": 0, "non_object_rows": 0, "rows_with_error_field": 0,
              "artefacts": {}, "artefacts_uncounted": 0, "problems": [], "failure_basis": "rows with a non-empty %s field" % "/".join(UPLOAD_ERROR_KEYS)}
    try:
        fh = open_text(path)
    except OSError as exc:
        record.update(status="unreadable", reason=describe(exc))
        return record
    with fh:
        number = 0
        first = True
        while True:
            if out_of_time():
                record.update(status="partial", reason="the time limit stopped the read after line %d" % number)
                break
            try:
                line = fh.readline(MAX_LINE)
            except OSError as exc:
                record.update(status="partial", reason="the read stopped at line %d (%s)" % (number + 1, describe(exc)))
                break
            if not line:
                break
            number += 1
            if len(line) == MAX_LINE and not line.endswith("\n"):
                record["malformed_rows"] += 1
                if len(record["problems"]) < FIRST_PROBLEMS:
                    record["problems"].append({"line": number, "error": "a line longer than %d bytes: read no further" % MAX_LINE})
                while True:
                    rest = fh.readline(MAX_LINE)
                    if not rest or rest.endswith("\n"):
                        break
                continue
            if not line.strip():
                continue
            if first and line.lstrip().startswith("["):
                record.update(status="unsupported", reason="the file is a JSON array, not JSON Lines: nothing was read from it")
                return record
            first = False
            record["rows"] += 1
            try:
                row = json.loads(line)
            except (ValueError, RecursionError):
                record["malformed_rows"] += 1
                if len(record["problems"]) < FIRST_PROBLEMS:
                    record["problems"].append({"line": number, "error": "not valid JSON"})
                continue
            if not isinstance(row, dict):
                record["non_object_rows"] += 1
                continue
            record["objects"] += 1
            source = row.get("_Source")
            if isinstance(source, str) and source:
                name = scrub(source, "artefact name")
                if name in record["artefacts"] or len(record["artefacts"]) < MAX_DISTINCT:
                    record["artefacts"][name] = record["artefacts"].get(name, 0) + 1
                else:
                    record["artefacts_uncounted"] += 1
            err = next((row[k] for k in UPLOAD_ERROR_KEYS if k in row and row[k] not in (None, "", [], {})), None)
            if err is not None:
                record["rows_with_error_field"] += 1
                where = "uploads row at line %d" % number
                target = next((row[k] for k in UPLOAD_TARGET_KEYS if isinstance(row.get(k), str) and row.get(k)), None)
                failures.add({"collector": "Velociraptor", "log": record["log"], "locator": {"line": number}, "outcome": "error",
                              "target": scrub(target, where) if target else None,
                              "reason": scrub(err if isinstance(err, str) else json.dumps(err, default=str), where),
                              "row_values": scrub_all(row)})
    if record["status"] == "parsed" and (record["malformed_rows"] or record["non_object_rows"]):
        record["status"] = "partial" if record["objects"] else "unsupported"
        record["reason"] = "%d row(s) are not JSON objects or not valid JSON: counted, located in problems" % (record["malformed_rows"] + record["non_object_rows"])
    elif record["status"] == "parsed" and record["objects"] == 0:
        record["status"] = "unsupported"
        record["reason"] = "no row was read"
    return record


def main():
    args = read_args()
    root = want_str(args, "root", "root is required: the collection directory")
    limit = want_int(args, "limit", DEFAULT_LIMIT)
    seconds = want_int(args, "time_limit_seconds", 1500, 1, 3400)
    try:
        VALUES[0] = SecretValues(want_bool(args, "write_values"), VALUES_NAME, TOOL)
    except SecretValuesRefused as exc:
        fail(str(exc))
    if not os.path.isdir(root):
        fail("no such directory", root=root)
    start_clock(seconds)
    survey = Survey(root, limit)
    walk(survey)

    failures = Table(TOOL + "-failures", limit)
    records, collectors = [], []
    for (directory, run_id), logs in sorted(survey.kape.items()):
        run = {"run_id": scrub(run_id, "KAPE run id"), "directory": shown(directory or ".", "log path"), "logs": []}
        if "copy" in logs:
            rec = read_csv_log(root, logs["copy"], "copy_log", failures)
            run["logs"].append(rec)
            run["files_in_copy_log"] = rec["rows"] if rec["status"] in ("parsed", "partial") else None
        if "skip" in logs:
            run["logs"].append(read_csv_log(root, logs["skip"], "skip_log", failures))
        version = read_console_version(root, logs["console"]) if "console" in logs else None
        if "console" in logs:
            run["console_log"] = shown(logs["console"], "log path")
        run["collector_version"] = version or "unknown"
        records.extend(run["logs"])
        collectors.append(("KAPE", run))
    uac_runs = []
    for rel in survey.uac_logs:
        rec = read_uac_log(root, rel, failures)
        records.append(rec)
        uac_runs.append({"log": rec["log"], "collector_version": "unknown", "record": rec})
    upload_runs = []
    for rel in survey.uploads:
        rec = read_uploads(root, rel, failures)
        records.append(rec)
        upload_runs.append({"log": rec["log"], "collector_version": "unknown", "record": rec})

    candidates = []
    kape_runs = [run for _name, run in collectors]
    if kape_runs:
        markers = []
        for run in kape_runs:
            markers += [lg["log"] for lg in run["logs"]] + ([run["console_log"]] if "console_log" in run else [])
        candidates.append({"collector": "KAPE", "basis": "log files named like KAPE's copy, skip and console logs",
                           "observed_markers": markers, "runs": kape_runs})
    if survey.uac_logs or survey.uac_dirs:
        candidates.append({"collector": "UAC",
                           "basis": "a uac.log file" if survey.uac_logs else "directory names only: [root], [bodyfile] or [live_response]",
                           "observed_markers": [shown(p, "log path") for p in survey.uac_logs] + [shown(p, "marker directory") for p in survey.uac_dirs],
                           "runs": uac_runs})
    if survey.uploads:
        candidates.append({"collector": "Velociraptor", "basis": "uploads.json file(s)",
                           "observed_markers": [shown(p, "log path") for p in survey.uploads], "runs": upload_runs})

    failure_page = failures.finish()
    objects_page = survey.objects.finish()
    values = VALUES[0]
    values.close()

    statuses = [r["status"] for r in records]
    read_whole = bool(records) and all(s == "parsed" for s in statuses)
    counted = [r for r in records if r["status"] in ("parsed", "partial")]
    any_failure_source = any(r["kind"] in ("skip_log", "uac_log", "uploads_json") and r["status"] in ("parsed", "partial") for r in records)
    if any_failure_source:
        failure_count = failure_page["matched"]
        failure_basis = ("rows the recognised logs record as skipped (KAPE skip log), lines with an ERROR level (UAC) and rows "
                         "with a non-empty Error field (Velociraptor); a skip is the collector's own recorded outcome, not a judgement")
    else:
        failure_count = None
        failure_basis = ("no skip log, UAC log or Velociraptor index was read in a form this tool recognises: there is no failure "
                         "count, which is not zero failures")
    complete_failures = any_failure_source and read_whole and not survey.stopped and survey.errors_total == 0

    total_files = survey.files
    # an archive counts as an object of its own only at the top level (see handle_file); a nested one is a copied file
    logical = total_files - survey.counts["disk_container"] - survey.counts["memory_capture"] - survey.counts["unknown"] - survey.counts["archive"]
    survey.counts["logical_files"] = logical
    parts = []
    if logical > 0:
        parts.append("logical")
    for key in ("disk_container", "memory_capture", "unknown", "archive"):
        if survey.counts[key]:
            parts.append(key)
    kind = "empty" if total_files == 0 else (parts[0] if len(parts) == 1 else "mixed")
    not_observed = [label for key, label in (("disk_container", "disk containers"), ("memory_capture", "memory captures"))
                    if survey.counts[key] == 0]

    problems = []
    if survey.stopped:
        problems.append("the walk stopped early: %s" % survey.stopped["reason"])
    if survey.errors_total:
        problems.append("%d walk or read error(s): see walk_errors" % survey.errors_total)
    for r in records:
        if r["status"] != "parsed":
            problems.append("%s is %s" % (r["log"], r["status"]))
    status = "complete" if not problems else "partial"

    out = {
        "tool": TOOL, "parser": PARSER, "root": shown(root, "root"), "status": status,
        "status_basis": ("every directory was listed and every recognised log was read whole" if status == "complete" else "; ".join(problems[:10])),
        "walk": {"directories": survey.directories, "files": total_files, "symbolic_links_not_followed": survey.links_total,
                 "special_files_not_read": survey.special_total, "errors": survey.errors_total, "first_errors": survey.errors,
                 "first_links": survey.links, "first_special_files": survey.special, "stopped": survey.stopped,
                 "reads_first_bytes_of": "%d object(s): top-level files, files named like an image, a memory capture or an archive, and files of %d bytes or more" % (survey.reads_head, MIN_RAW_BYTES),
                 "first_bytes_unreadable": survey.head_errors},
        "delivery": {"kind": kind, "object_counts": survey.counts, "nested_archives_named_like_archives": survey.nested_archives,
                     "basis": "each object classified on its own (see objects); mixed means more than one kind is present",
                     "not_observed": not_observed,
                     "not_observed_basis": "no object of this kind was seen among the files walked, by signature or name; a limit of this delivery, not a finding about the source"},
        "objects": survey.objects.page,
        "objects_table": objects_page,
        "collector_candidates": candidates,
        "layout_clues": survey.layout_clues,
        "failed_targets": failures.page,
        "failed_target_count": failure_count,
        "failed_target_count_basis": failure_basis,
        "failed_target_count_complete": complete_failures,
        "failed_targets_table": failure_page,
        "artefact_families_by_name": dict(sorted(survey.families.items(), key=lambda kv: (-kv[1]["count"], kv[0]))),
        "artefact_families_basis": "a file's own name only: a file of that name may be empty, truncated or not that artefact",
        "withheld": {"strings_withheld": WITHHELD["count"], "values": values.summary()},
        "note": ("A hypothesis from names, first bytes and the collectors' own logs. It does not say the collector finished, what it was "
                 "asked to copy, or whether a digest matches; the logs and manifests themselves are the record. A recorded skip or error "
                 "is the collector's outcome, to be reported with its own words and not explained or judged. Source paths are not "
                 "reconstructed here: collection_index offers hypotheses, and only a collector's own mapping observes one."),
    }
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    try:
        main()
    except (SystemExit, KeyboardInterrupt):
        raise
    except BaseException as exc:                  # a bug here is a JSON error that names it, not a traceback and a half-written answer
        fail("the tool stopped on an unexpected error (%s)" % type(exc).__name__, detail=str(exc)[:300])

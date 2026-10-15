#!/usr/bin/env python3
"""Read an ESE (Extensible Storage Engine) database as tables.

The gap this closes is recorded in a delivered report's own words: "No
`esedbexport`: WebCacheV01.dat and spartan.edb could not be parsed as
tables". That file appears in four of the fifteen measured runs across 144
trace events and was never once read as tables. The same wrapper opens
SRUDB.dat (the System Resource Usage Monitor) and Edge's database, so one
tool covers three artefacts that a Windows case asks for every time.

Backed by `esedbexport` (libesedb), which writes one TSV per table into a
directory. This wraps it: list the tables, or read one, and return JSON either
way. It exports TABLES, as text: it does not decode what a table means (a SRUM
table is not joined to the application or user it names, a WebCache container
is not resolved to a browser), and it does not read an ESE log.

The export is made once per database, into `esedb-export/<sha256 of the database,
first 16 hex>/` under the job's $OUT (or the agent's own work directory), with the
exporter's whole standard output and standard error in files beside it and an
`export-manifest.json` that records the database's digest, the exporter's version, argv
and exit status and every table file. A later call with the same database reuses a
complete export. An exporter that exits non-zero, or is stopped by its time limit, leaves a
PARTIAL export: the answer says status: partial, never lists it as the database's tables,
and keeps the logs. A table name that matches more than one export file is refused with
the candidates, never resolved by taking the first. An earlier export is reused only when its
manifest was written by this version of the tool, its exit status was 0, and every table file
it lists is on disk with the size it recorded and nothing else is there; otherwise it is made again.

READING AND BOUNDS. The table file is read as the exporter wrote it: tab-separated text, a row to a line, no quoting rule (a quote is a
character of its cell; a carriage return is one too, unless the whole file ends its lines with CR LF, which the answer says), and `_row` is the
1-based line of the row after the header. What an answer prints inline is bounded: the rows that fit `limit` and 256 KiB, with a cell longer than
4,096 characters shown cut (`_cells_shortened` names it). The file `all_results` names holds EVERY row with EVERY cell whole, and is written
whenever the inline rows are not the whole of the table (more rows than fit, or a cell cut); it is never replaced by another result. A row longer
than 8 MiB is read to that length (said, with its length) and is whole in the export. The tool stops at its own time limit (285 seconds, below the
manifest's 300) with the rows read and says partial; SIGTERM, SIGINT and SIGHUP end it with JSON (status interrupted) and no temporary file.

SENSITIVE OUTPUT. The export directory holds every table whole, so it holds whatever the database
holds (a WebCache URL with a token in it, a SRUM user, the password material of an Active Directory
database): it is made with mode 0700 (its files 0600), it is a sensitive output of the job that made it, and
it is cited by file and table, never by value. The answer withholds, in the rows it returns, the cells
of a column whose name says password, secret, token, encrypted, credential, a card, an IBAN or an SSN,
and of the attributes of an Active Directory datatable that carry password hashes, their history,
supplemental credentials and the password encryption keys, replacing each by a marker that holds only its
length (`columns_withheld`); and the secrets of every URL in a cell (a token or password in its query
string, fragment or user-info), listed in `url_secrets_withheld`. A URL's text is written whole only with
`write_url_secrets: true`, in a job run with secret_output: true, to a file under $OUT of mode 0600; the
request is refused anywhere else. Binary cells are exported as text by esedbexport and are not inspected.
"""
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

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


PARSER = "esedb_query/7"
MAX_EXPORT_SECONDS = 270
# The tool's own clock: the manifest allows 300 seconds, so the export is stopped at 270 and everything the tool does stops at 285, with
# the rows it has read said to be a part (status partial), never a kill by the harness with no answer.
DEADLINE_SECONDS = 285
# What one answer carries inline. The rows shown are the first rows of the table that fit; every row, with every cell whole, is in the
# file the answer names (all_results), which is written whenever the inline rows are not the whole of it.
INLINE_BYTES = 256 * 1024
CELL_INLINE_CHARS = 4096
COLUMNS_INLINE = 1000
# One row of the exported table is read up to this many characters; a longer row is read to its end (so that the next row is found) and
# is said to be cut, with the file and the line where its whole text is (the export keeps every table whole).
ROW_READ_CHARS = 8 * 1024 * 1024
RESERVED_COLUMNS = ("_row", "_cells_shortened", "_row_read_cut")


# BEGIN SHARED PLACE
# The same text is in every windows-forensics tool that keeps a result file (a windows-forensics test holds the copies equal).
# A result file that is there is never replaced by another result: a file of the same bytes is named again, any other result takes the next free
# <stem>-<n><suffix>. The name is taken first, with an exclusive create, so a result written at the same moment cannot be replaced either.
def same_bytes(a, b):
    """Whether two files hold the same bytes (read in blocks, never whole)."""
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                x, y = fa.read(1 << 20), fb.read(1 << 20)
                if x != y:
                    return False
                if not x:
                    return True
    except OSError:
        return False


def place_without_replacing(tmp, path):
    """Move the finished `tmp` to `path` and never replace what is there. The name is taken first, with an exclusive create, so a
    result written at the same moment cannot be replaced either. Returns the path that holds it."""
    for n in range(1, 1000):
        candidate = path if n == 1 else path.with_name("%s-%d%s" % (path.stem, n, path.suffix))
        try:
            fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            if not os.path.islink(candidate) and same_bytes(tmp, candidate):
                os.unlink(tmp)
                return candidate
            continue
        os.close(fd)
        os.replace(tmp, candidate)             # only replaces the empty file this call just made
        return candidate
    raise OSError("no free name beside %s" % path)
# END SHARED PLACE


class NoReplacePage(LosslessPage):
    """LosslessPage whose finished file is placed without replacing an earlier file of the same name (a rerun with other limits,
    or one the time limit stopped, must not leave a smaller file where a larger one was). Every row it writes goes through the boundary."""

    def _write(self, row):
        super()._write(row_object(row))

    def finish(self) -> dict:
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                placed = place_without_replacing(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            self._tmp = None
            self.path = placed
            self.shown = self.shown[: len(self.shown) - len(Path(self.shown).name)] + placed.name
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


class WholeRows(NoReplacePage):
    """The rows of a table: a page of the first rows that fit `limit` rows and `budget` bytes, with a cell longer than the inline cut
    shown cut; and a file of EVERY row with EVERY cell whole, written whenever the page is not the whole of the table (more rows than
    fit, or a cell shown cut). Rows are written as they are read, so memory does not grow with the table."""

    def __init__(self, tool, key, limit, budget):
        super().__init__(tool, key, limit)
        self.budget, self.used, self.closed = budget, 0, False
        self.cells_shortened = 0
        self.rows_not_inline = 0

    def open_file(self):
        if self._out is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            for kept in self.page:                    # rows that went inline whole are the rows of the file
                self._write(kept)

    def add_row(self, whole, shown=None):
        """`whole`: the row with every cell whole. `shown`: the row as it goes inline when a cell is cut, else None."""
        self.total += 1
        inline = whole if shown is None else shown
        fits = False
        if not self.closed and len(self.page) < self.limit:
            size = len(json.dumps(inline, ensure_ascii=True, default=str))
            fits = self.used + size <= self.budget
            if fits:
                self.used += size
        if not fits:
            self.closed = True                        # the rows shown stay the first rows, one after the other
            self.rows_not_inline += 1
        if shown is not None:
            self.cells_shortened += 1
        if not fits or shown is not None:
            self.open_file()
        if fits:
            self.page.append(inline)
        if self._out is not None:
            self._write(whole)

    def finish(self) -> dict:
        result = super().finish()
        result["truncated"] = self.total > len(self.page) or self.cells_shortened > 0
        result["rows_not_inline"] = self.rows_not_inline
        result["rows_with_a_cell_shown_cut"] = self.cells_shortened
        result["inline_budget_bytes"] = self.budget
        return result


def read_row(fh, cap):
    """The next line of a table file as (text, chars, cut): `text` is its first `cap` characters without the line end, `chars` how
    many characters the line has, `cut` whether `text` is not all of it. (None, 0, False) at the end of the file. A line ends at
    a line feed and nowhere else (the file is opened so that no carriage return is a line end)."""
    parts, got, total, last = [], 0, 0, ""
    while True:
        piece = fh.readline(1 << 16)
        if not piece:
            break
        last = piece
        total += len(piece)
        if got < cap:
            take = piece[: cap - got]
            parts.append(take)
            got += len(take)
        if piece.endswith("\n"):
            break
    if total == 0:
        return None, 0, False
    chars = total - (1 if last.endswith("\n") else 0)
    text = "".join(parts)
    if len(text) > chars:
        text = text[:chars]
    return text, chars, len(text) < chars


# BEGIN SHARED PROCESS
# The same text is in esedb_query, extract_stream, sigma_hunt, vss_stores and yara_scan; tests/pack-windows-forensics-process.test.ts
# holds the copies equal. A program a tool runs is started in THIS tool's process group, never in a session of its own: the
# harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid, SIGKILL)), and a
# program in a group of its own goes on writing after the tool is gone. On Linux the kernel is also asked to kill it if the
# tool dies. The tool's own deadline kills the program and what it started by walking the process tree, and SIGTERM, SIGINT
# and SIGHUP do the same and then give the tool a last word.
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


def wait_for(proc, seconds):
    """(exit code, timed out): wait for the program for at most `seconds`; at the deadline it and what it started are killed."""
    ACTIVE.append(proc)
    try:
        try:
            return proc.wait(timeout=seconds), False
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            return proc.wait(), True
    finally:
        if proc in ACTIVE:
            ACTIVE.remove(proc)


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


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
# END SHARED PROCESS


# BEGIN SHARED BOUNDARY
# WINDOWS BOUNDARY v0: the same text is in every windows-forensics tool that prints names, paths, event data, registry data or table
# cells from evidence (a windows-forensics test holds the copies equal), so that the shared-block task can converge it with the other
# withholding blocks. It is the owner-approved HYBRID design: an allow-list for identifier-shaped fields, a deny-list for free text,
# and an independent backstop on the way out.
#
# LAYER 1, an allow-list per field type. A string the evidence supplied is shown as it is only when it fits the plain grammar of the
# type of the field it fills: a name (registry key and value names, event field names, provider and channel names, table and column
# names), a path (file names and paths, a registry path, a URL path), a key, a URL, or a typed id (GUID, SID, MAC, IP address, digest,
# time, number, version). The grammar is: letters of any script, digits, space and `_ - . $ @ ? : ~ + , # ( ) [ ] { } ' < > *`, at
# most 128 characters a component, no user-info shape (a `:` before an `@`), and no chain of 16 or more characters made of
# random-looking pieces (pieces that break into one- and two-character parts, flip between letters and digits, or are letters with
# no pronounceable word in them; a 16-hex id, a GUID or a number up to 18 digits is plain). Below 16 characters a chain is shown
# whatever it looks like: a short random password in a name is not recognised. A path is judged component by component and only the
# offending span is replaced; a string with a format, control or combining character is withheld whole.
#
# LAYER 2, for every kind: user-info up to the last `@` before the host; the value after a secret's name (password, secret, token,
# api/access/account/private key, credential, auth) found anywhere; a PEM private key; a vendor token with its own prefix (AKIA,
# gh?_, github_pat_, xox?-, glpat-, sk_live_, SG., AIza, npm_, dop_v1_, ya29., sk-, JWT) in any case; a base64 key with its padding;
# and the same rules on a copy with invisible characters taken out and NFKC applied (a hit withholds the whole string).
# FREE TEXT (event data, messages, command lines, registry data strings, table cells) is on the deny-list: the same chain test
# applied to the text with its typed ids (GUID, SID, IP address, time, labelled digest, number) left alone, plus layer 2, and no
# character grammar.
#
# LAYER 3, the backstop, written apart from the layers above: every key and value of what is about to be written is read once more
# by its own normaliser and patterns (a PEM marker, a named secret, a run of 19 or more digits, a token prefix, user-info, a run of
# 40 or more hex digits outside a typed field, a base64 run, a run that changes class as random text does). A string it finds
# suspect is replaced by <withheld N bytes: backstop>, counted, its place named in boundary.replaced_at, and the answer is partial.
#
# ONE WAY OUT: emit() writes an answer, row_text() a row of a paging file, and both seal every key and value first. Binary data
# written as hex (a REG_BINARY value, an ESE binary column) is decoded and its printable views (Latin-1 and UTF-16LE) are judged by
# the free-text rules; hex that holds a secret-shaped text is withheld, and any other is shown. What is withheld is a placeholder with its length
# and the reason; its original goes to the values file only when write_values was asked for in a job run as secret output.
# NOT RECOGNISED, by design: a secret that does not look like one (a plain password, a pronounceable passphrase, a UUID-shaped key,
# anything under 16 characters in a name, a secret hidden in words or in an encoding this block does not read).
import collections
import unicodedata

LMIN = 16
MAX_ONE_STRING = 1 << 18
MAX_HEX_JUDGED = 1 << 20
_BIGRAMS_TEXT = "aaabacadaeafagahaiajakalamanaoapaqarasatauavawaxayazbabbbcbdbebfbhbibjblbmbnbobpbrbsbtbubvbycacbcccdcecfchcickclcncocqcrcsctcucydadbdcdddedfdgdhdidjdldmdndodpdrdsdtdudvdwdyeaebecedeeefegeheiejekelemeneoepeqereseteuevewexeyezfafbfcfdfefffiflfofrftfufygagbgdgegfggghgiglgmgngogrgsgtgugwgyhahbhchdhehfhhhihlhmhnhohphrhshthuhwhyiaibicidieifigihiiijikiliminioipiqirisitiuiviwixizjajejijojukakbkekfkhkikkklkmknkokpkrksktkukwkylalblcldlelflglhlilklllmlnlolplrlsltlulvlwlymambmemfmimlmmmnmompmrmsmumwmynanbncndnenfngnhninjnknlnmnnnonpnqnrnsntnunvnwnxnynzoaobocodoeofogohoiojokolomonooopoqorosotouovowoxoyozpapbpcpepfphpiplpmpnpoppprpsptpupwpyqurarbrcrdrerfrgrhrirjrkrlrmrnrorprqrrrsrtrurvrwryrzsasbscsdsesfsgshsiskslsmsnsospsqsrssstsusvswsytatbtctdtetftgthtitltmtntotptrtstttutvtwtytzuaubucudueufuguhuiukulumunuoupurusutuvuxuyuzvavevivovuvywawbwdwewfwhwiwkwlwmwnwowrwswtwuwyxaxcxexhxixoxpxtxuxxxyyaybycydyeyfygyhyiylymynyoypyrysytyuywyxyyyzzazezizlzozuzyzz"           # the 474 letter pairs that words and identifiers use (the system word list and Python identifiers)
_BIGRAMS = frozenset(_BIGRAMS_TEXT[i:i + 2] for i in range(0, len(_BIGRAMS_TEXT), 2))
BOUNDARY = {"withheld": 0, "by": collections.Counter(), "replaced": 0, "replaced_by": collections.Counter(), "where": [], "not_listed": 0}
OWN_NAMES = set()               # exact strings this run made and shows as they are (file names of its own results)
FIELDS = {}                     # a JSON key -> the kind of what it holds (a tool fills this in); other keys hold free text
KEY_KINDS = {}                  # a JSON key holding a dict -> the kind of that dict's own keys (registry value names are paths); default: name
MAX_WHERE = 200


class T(str):
    """A string with its field type, made by the tool where it knows the type (a registry type, an event field, a column)."""
    kind = "text"

    def __new__(cls, kind, text):
        self = super().__new__(cls, text)
        self.kind = kind
        return self


def _mark(n, label, unit="characters"):
    return "<withheld %d %s: %s>" % (n, unit, label)


_MARK = re.compile(r"<withheld \d+ (?:characters|bytes)(?:: [a-z][a-z ,-]{0,60})?>|\[withheld: \d+ characters\]")
_VALUES = {"fh": None, "shown": None, "written": 0, "seen": set(), "count": 0}


class ValuesRefused(Exception):
    pass


def bind_values(enabled, tool):
    """The values file: the originals of what the boundary withheld, in a job run as secret output and only when asked for. Decided before
    anything is opened or created (the harness sets SECRET_OUTPUT=1 for a secret job's process)."""
    if not enabled:
        return None
    job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
    if not (job and out) or os.environ.get("SECRET_OUTPUT") != "1":
        raise ValuesRefused("write_values is refused: the originals of what was withheld are written only in a job the harness runs as secret output "
                            "(job_run with secret_output: true), where the file is a sealed secret output. Nothing was written.")
    name = "%s-values.jsonl" % re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
    path = Path(out) / name
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        raise ValuesRefused("the values file already exists: %s" % path)
    except OSError as exc:
        raise ValuesRefused("the values file could not be created: %s: %s" % (path, exc.strerror or exc))
    _VALUES["fh"] = os.fdopen(fd, "w", encoding="utf-8")
    _VALUES["shown"] = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
    return _VALUES["shown"]


def close_values():
    fh = _VALUES["fh"]
    if fh is not None:
        fh.flush()
        os.fsync(fh.fileno())
        fh.close()
        _VALUES["fh"] = None


def values_summary():
    return {"requested": _VALUES["shown"] is not None, "values_file": _VALUES["shown"], "written": _VALUES["written"], "contains_secret_values": _VALUES["written"] > 0,
            "format": "JSON Lines, mode 0600: id, field, label, length, value (the original text that was withheld)" if _VALUES["shown"] else None}


def _withheld(original, label, field=""):
    n = len(original)
    BOUNDARY["withheld"] += 1
    BOUNDARY["by"][label] += 1
    fh = _VALUES["fh"]
    if fh is not None and original not in _VALUES["seen"]:
        if len(_VALUES["seen"]) < 200000:
            _VALUES["seen"].add(original)
        _VALUES["count"] += 1
        text = json.dumps({"id": _VALUES["count"], "field": field, "label": label, "length": n, "value": original}, ensure_ascii=False)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            text = json.dumps({"id": _VALUES["count"], "field": field, "label": label, "length": n, "value": original}, ensure_ascii=True)
        fh.write(text + "\n")
        _VALUES["written"] += 1
    return _mark(n, label)


# ---- normalisation ----------------------------------------------------------------------------------------------------------------
_STRIP_CATS = frozenset(("Cf", "Cc", "Mn", "Me", "Cs", "Co", "Cn", "Zl", "Zp"))
_FILLERS = frozenset((0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800))


class _Strip(dict):
    def __missing__(self, o):
        if len(self) > 20000:
            self.clear()
        keep = unicodedata.category(chr(o)) not in _STRIP_CATS and o not in _FILLERS
        self[o] = o if keep else None
        return self[o]


_STRIP = _Strip()
_ESCAPED = re.compile(r"\\+(?:u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|x([0-9A-Fa-f]{2})|u\{([0-9A-Fa-f]{1,6})\})")


def _unescape_invisible(m):
    try:
        c = chr(int(m.group(1) or m.group(2) or m.group(3) or m.group(4), 16))
    except (ValueError, OverflowError):
        return m.group(0)
    return "" if (unicodedata.category(c) in _STRIP_CATS or ord(c) in _FILLERS) else m.group(0)


def _flat(text):
    """The text with invisible characters (and the escapes of such characters) taken out, and past ASCII in NFKC form."""
    if "\\" in text:
        text = _ESCAPED.sub(_unescape_invisible, text)
    if text.isascii():
        return text if text.isprintable() else text.translate(_STRIP)
    out = text.translate(_STRIP)
    return unicodedata.normalize("NFKC", out) if not out.isascii() else out


# ---- layer 1: the allow-list ------------------------------------------------------------------------------------------------------
_PIECE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
_GUID = re.compile(r"\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?|[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{12}")
_SID = re.compile(r"S-1-[0-9]{1,2}(?:-[0-9]{1,10}){1,15}")
_IPV4 = re.compile(r"(?<![0-9A-Za-z.])[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?![0-9A-Za-z])")
_HEX_NUMBER = re.compile(r"(?<![0-9A-Za-z])0[xX][0-9A-Fa-f]{1,16}(?![0-9A-Za-z])")
# the publisher ids that follow the name of an AppX package family (the hash of the publisher's name), and the assembly public key tokens of Microsoft
_KNOWN_ID = re.compile(r"(?<![0-9A-Za-z])(?:8wekyb3d8bbwe|cw5n1h2txyewy|kzf8qxf38zg5c|31bf3856ad364e35|b77a5c561934e089|b03f5f7f11d50a3a|0x[0-9A-Fa-f]{1,16})(?![0-9A-Za-z])")
_NAME_SEPS = " _-.$@?:~+,#()[]{}'`<>*"
_PATH_EXTRA = "&!';=^%\""
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")
_PCT_UNRESERVED = re.compile(r"%((?:4[1-9A-Fa-f]|5[0-9Aa]|6[1-9A-Fa-f]|7[0-9Aa]|3[0-9]|2[DdEe]|5[Ff]|7[Ee]))")
_JOIN_NAME, _JOIN_PATH = "-_+", "-_+/\\"
_CTRL = "\x01\x02\x03\x04\x05\x06\x07\x08\x09"


def _pronounceable(piece):
    p = piece.lower()
    bad = sum(1 for a, b in zip(p, p[1:]) if (a + b) not in _BIGRAMS)
    return bad <= 1 + len(p) // 10


def _structure_ok(seg):
    if re.fullmatch(r"[0-9]+", seg):
        return len(seg) <= 18
    if len(seg) <= 24 and re.fullmatch(r"[0-9a-f]+|[0-9A-F]+", seg):
        return True                       # a hexadecimal id up to 24 digits (a USB serial, a 16-digit object id, a hash of a few bytes) is plain
    if len(seg) >= 20 and re.fullmatch(r"[0-9A-Fa-f]+", seg):
        return False
    pieces = _PIECE.findall(seg)
    short = sum(1 for p in pieces if len(p) <= 2)
    if short > max(2, 0.4 * len(pieces)):
        return False
    flips = sum(1 for a, b in zip(seg, seg[1:]) if a.isdigit() != b.isdigit())
    if flips > 3 + len(seg) // 16:
        return False
    alpha = [p for p in pieces if p.isalpha()]
    if sum(len(p) for p in alpha) >= 12 and sum(len(p) for p in alpha) < 3.4 * len(alpha):
        return False
    return True


def _plain_segment(seg, lmin=None):
    lmin = LMIN if lmin is None else lmin
    if len(seg) < lmin:
        return True
    if not _structure_ok(seg):
        return False
    return all(not (p.isalpha() and len(p) >= 6) or _pronounceable(p) for p in _PIECE.findall(seg))


def _prepare(s, typed=True):
    """A same-length copy of `s` in which a GUID, a SID, an IPv4 address and a %XX escape are replaced by `~` and a non-ASCII letter by `e`;
    None when `s` holds a format, control or combining character, a non-NFKC character or a stray space character."""
    if not s.isascii():
        for ch in s:
            cat = unicodedata.category(ch)
            if cat[0] in "CM" or (cat[0] == "Z" and ch != " "):
                return None
        if unicodedata.normalize("NFKC", s) != s:
            return None
        s = "".join(ch if ch.isascii() else "e" for ch in s)
    t = _GUID.sub(lambda m: "~" * len(m.group()), s)
    if typed:
        t = _SID.sub(lambda m: "~" * len(m.group()), t)
        t = _IPV4.sub(lambda m: "~" * len(m.group()), t)
        t = _KNOWN_ID.sub(lambda m: "~" * len(m.group()), t)
    return _PCT.sub("   ", t)


def _unpercent(s):
    out = _PCT_UNRESERVED.sub(lambda m: chr(int(m.group(1), 16)), s)
    return out if out != s else None


def _bad_runs(t, join):
    """Intervals of `t` that are not plain, judged on CHAINS: maximal sequences of alphanumeric segments joined only by `join` characters. A
    chain is bad when (A) its random-looking segments, adjacent ones taken together, add up to LMIN characters or more, or (B) it is LMIN
    characters or longer, holds 8 or more characters of letter-and-digit-mixed segments, and holds no word of five or more letters."""
    segs = [(m.start(), m.end()) for m in re.finditer(r"[A-Za-z0-9]+", t)]
    chains, cur = [], []
    for a, b in segs:
        if cur and t[cur[-1][1]:a] and all(c in join for c in t[cur[-1][1]:a]):
            cur.append((a, b))
        else:
            if cur:
                chains.append(cur)
            cur = [(a, b)]
    if cur:
        chains.append(cur)
    bad = []
    for chain in chains:
        rnd = [not _plain_segment(t[a:b], 0) for a, b in chain]
        if not any(rnd):
            continue
        run = None
        for (a, b), r in zip(chain, rnd):
            if r:
                run = [a, b, b - a] if run is None else [run[0], b, run[2] + (b - a)]
            else:
                if run is not None and run[2] >= LMIN:
                    bad.append((run[0], run[1]))
                run = None
        if run is not None and run[2] >= LMIN:
            bad.append((run[0], run[1]))
        total = sum(b - a for a, b in chain)
        mixed = sum(b - a for a, b in chain if not _structure_ok(t[a:b]))
        if total >= LMIN and mixed >= 8 and not any(len(p) >= 5 and p.isalpha() and _pronounceable(p) for a, b in chain for p in _PIECE.findall(t[a:b])):
            bad.append((chain[0][0], chain[-1][1]))
    return bad


def _chars_ok(comp, extra_ok):
    return all(ch.isalnum() or ch in _NAME_SEPS or ch in extra_ok for ch in comp)


def _userinfo_shape(t):
    return ":" in t and "@" in t and t.index(":") < t.rindex("@")


def _plain_name(s, extra_ok=""):
    if not s or len(s) > 128:
        return False
    t = _prepare(s)
    if t is None or not _chars_ok(t, extra_ok) or _userinfo_shape(t):
        return False
    u = _unpercent(s)
    if u is not None:
        pu = _prepare(u)
        if pu is None or _bad_runs(pu, _JOIN_NAME):
            return False
    return not _bad_runs(t, _JOIN_NAME)


def _merge(spans):
    merged = []
    for a, b in sorted(spans):
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def _path_spans(s, extra_ok=_PATH_EXTRA):
    t = _prepare(s)
    if t is None:
        return [(0, len(s))]
    bad, pos = [], 0
    for part in re.split(r"([\\/])", t):
        a, b = pos, pos + len(part)
        pos = b
        judged = part.lstrip(_CTRL)
        if part in ("\\", "/") or part == "" or re.fullmatch(r"[A-Za-z]:|\?|\.", part):
            continue
        if len(part) - len(judged) > 1 or len(part) > 255 or not _chars_ok(judged, extra_ok) or _userinfo_shape(judged):
            bad.append((a, b))
    bad += _bad_runs(t, _JOIN_PATH)
    u = _unpercent(s)
    if u is not None:
        pu = _prepare(u)
        if pu is None or _bad_runs(pu, _JOIN_PATH):
            bad.append((0, len(s)))
    return _merge(bad)


def _replace_spans(s, spans, label, field):
    out, last = [], 0
    for a, b in spans:
        out.append(s[last:a])
        out.append(_withheld(s[a:b], label, field))
        last = b
    out.append(s[last:])
    return "".join(out)


def _show_name(s, field):
    return s if _plain_name(s) else _withheld(s, "not a plain name", field)


def _show_path(s, field, extra_ok=_PATH_EXTRA):
    return _replace_spans(s, _path_spans(s, extra_ok), "not a plain name", field)


def _show_key(s, field):
    return _show_path(s, field, _PATH_EXTRA + "*^<>")


_URL = re.compile(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)(?:([^/?#]*)@)?([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#(.*))?$", re.S)


def _show_host(s, field):
    """A host name is on the deny-list: a random-looking label of a host is evidence (a C2 name), not a secret."""
    return _deny_text(s, field)


def _show_value(v):
    return v if re.fullmatch(r"[0-9]{1,12}|true|false|null|yes|no", v) or (v.isalpha() and len(v) <= 24 and _plain_name(v)) else None


def _show_url(s, field):
    m = _URL.match(s)
    if not m:
        return _show_path(s, field)
    scheme, userinfo, host, path, query, frag = m.groups()
    out = scheme
    if userinfo is not None:
        out += _withheld(userinfo, "user-info", field) + "@"
    hostname, colon, port = host.partition(":") if not host.startswith("[") else (host, "", "")
    out += _show_host(hostname, field) + (colon + (port if port.isdigit() else _withheld(port, "not a port", field)) if colon else "")
    out += _show_path(path, field)
    if query is not None:
        pairs = []
        for pair in query.split("&"):
            k, eq, v = pair.partition("=")
            kk = _show_name(k, field) if k else k
            if eq:
                sv = _show_value(v)
                pairs.append(kk + "=" + (sv if sv is not None else _withheld(v, "query value", field)))
            else:
                pairs.append(kk)
        out += "?" + "&".join(pairs)
    if frag is not None:
        sv = _show_value(frag)
        out += "#" + (sv if sv is not None else _withheld(frag, "fragment", field))
    return out


_TYPED = {
    "guid": re.compile(_GUID.pattern),
    "digest": re.compile(r"(?:sha256:|sha1:|md5:)?[0-9A-Fa-f]{32,128}|T1[0-9A-Fa-f]{60,72}|[0-9]{1,6}:[A-Za-z0-9+/]{3,}:[A-Za-z0-9+/]{3,}"),
    "sid": re.compile(_SID.pattern),
    "mac": re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"),
    "ip": re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]{2,45}(?:%[0-9A-Za-z_.-]{1,16})?"),
    "time": re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[T ][0-9:.]+(?:Z|[+-][0-9:]+)?)?|D:[0-9]{8,14}(?:[Zz+-][0-9']*)?|[0-9]{1,18}"),
    "number": re.compile(r"-?[0-9]{1,18}(?:\.[0-9]{1,18})?|0x[0-9A-Fa-f]{1,16}|(?:true|false|null)"),
    "version": re.compile(r"v?[0-9]+(?:\.[0-9A-Za-z]+){1,4}(?:[-+][0-9A-Za-z.]+)?"),
}


# ---- layer 2: position and prefix rules -------------------------------------------------------------------------------------------
_USERINFO = re.compile(r"(?<![A-Za-z0-9._%+-])(?!mailto:)[^\s/@:<>\"'`]{1,64}:[^\s/<>\"'`]{1,128}(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
_URL_USERINFO = re.compile(r"(?<=//)[^/?#\s@]+(?=@)")
_NAMED = re.compile(r"(?i)(?:(?<![Bb]y)(?<![Cc]om)(?<![Oo]ver)(?<![Uu]nder)(?<![Tt]res)(?<![Ee]ncom)(?<![Ss]ur)(?<![Ii]m)pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|account[_-]?key|private[_-]?key|client[_-]?secret|credential|auth(?:orization)?)s?[\"']?[ \t]{0,3}[=:][ \t]{0,3}[\"']?(?P<value>[^\s\"'<>;,&]{1,512})")
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)", re.S)
_PREFIX = re.compile(r"(?i:(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abeprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}"
                     r"|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{30,}|npm_[A-Za-z0-9]{30,}"
                     r"|dop_v1_[0-9a-f]{40,}|ya29\.[0-9A-Za-z_-]{30,})|sk-(?=[A-Za-z0-9_-]{0,19}[0-9])[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?")
_BASE64_PADDED = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={1,2}(?![A-Za-z0-9+=])")
_LONG_DIGITS = re.compile(r"(?<![0-9])[0-9]{19,}(?![0-9])")


def _b64_shape(run):
    """Whether a padded run can be base64 of random bytes: its length with the padding is a multiple of 4, and it holds a digit, `+` or `/` (a long
    identifier before an `=` in a line of text, RelatedActivityID=, is not one)."""
    return len(run) % 4 == 0 and re.search(r"[0-9+/]", run) is not None


def _layer2_once(s, field):
    s = _outside(s, _MARK, lambda p: _PEM.sub(lambda m: _withheld(m.group(), "private key", field), p))
    s = _outside(s, _MARK, lambda p: _URL_USERINFO.sub(lambda m: _withheld(m.group(), "user-info", field), p))
    s = _outside(s, _MARK, lambda p: _USERINFO.sub(lambda m: _withheld(m.group(), "user-info", field), p))
    s = _outside(s, _MARK, lambda p: _NAMED.sub(lambda m: m.group()[:m.start("value") - m.start()] + _withheld(m.group("value"), "secret value", field), p))
    s = _outside(s, _MARK, lambda p: _BASE64_PADDED.sub(lambda m: _withheld(m.group(), "token-shaped text", field) if _b64_shape(m.group()) else m.group(), p))
    s = _outside(s, _MARK, lambda p: _LONG_DIGITS.sub(lambda m: _withheld(m.group(), "long number", field), p))
    return _outside(s, _MARK, lambda p: _PREFIX.sub(lambda m: _withheld(m.group(), "token-shaped text", field), p))


def _outside(text, pattern, fn):
    """`fn` applied to the parts of `text` that `pattern` does not match; the matches are kept as they are."""
    if "<" not in text and "[" not in text:
        return fn(text)
    out, last = [], 0
    for m in pattern.finditer(text):
        out.append(fn(text[last:m.start()]) if m.start() > last else "")
        out.append(m.group())
        last = m.end()
    out.append(fn(text[last:]) if last < len(text) else "")
    return "".join(out)


def _layer2(s, field):
    out = s
    for _ in range(3):
        nxt = _layer2_once(out, field)
        if nxt == out:
            break
        out = nxt
    return out


# ---- free text: the deny-list ------------------------------------------------------------------------------------------------------
_LABELLED_DIGEST = re.compile(r"(?i)(?:md5|sha-?1|sha-?256|sha-?384|sha-?512|imphash|hashes?|filehash|ssdeep|tlsh)[\"'=:> \t]{1,6}(?:(?:md5|sha-?1|sha-?256|imphash)=)?([0-9a-f]{32,128})")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.,][0-9]{1,9})?(?:Z|[+-][0-9]{2}:?[0-9]{2})?")
_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{32,}(?![0-9A-Za-z])")


def _mask_typed(s):
    """A same-length copy of free text in which what is a typed id (GUID, SID, IPv4, time, labelled digest) is `~`."""
    t = _GUID.sub(lambda m: "~" * len(m.group()), s)
    t = _SID.sub(lambda m: "~" * len(m.group()), t)
    t = _IPV4.sub(lambda m: "~" * len(m.group()), t)
    t = _TIME.sub(lambda m: "~" * len(m.group()), t)
    t = _KNOWN_ID.sub(lambda m: "~" * len(m.group()), t)
    if "ash" in s or "ASH" in s or "md5" in s.lower() or "sha" in s.lower():
        t = _LABELLED_DIGEST.sub(lambda m: m.group().replace(m.group(1), "~" * len(m.group(1))), t)
    return t


def _deny_text(s, field):
    t = _mask_typed(s)
    t = t.replace("\x00", " ")
    spans = _bad_runs(t, _JOIN_PATH)
    spans += [m.span() for m in _HEX_RUN.finditer(t)]
    return _replace_spans(s, _merge(spans), "token-shaped text", field) if spans else s


# ---- the entry point for one string ---------------------------------------------------------------------------------------------------
_MEMO = {}


def _hex_views(s):
    """The printable views of binary data written as hex: Latin-1 runs of 6 or more and UTF-16LE runs of 4 or more."""
    try:
        raw = bytes.fromhex(s[: MAX_HEX_JUDGED])
    except ValueError:
        return None
    views = [m.group().decode("latin-1") for m in re.finditer(rb"[\x20-\x7e]{6,}", raw)]
    views += [m.group().decode("utf-16-le", "replace") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", raw)]
    return views


def _show_hex(s, field):
    if not s or not re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", s):
        return s if re.fullmatch(r"[0-9A-Fa-f]*", s) else _show_text(s, field)
    if len(s) > MAX_HEX_JUDGED:
        return _withheld(s, "binary data over the judged size", field)
    for v in _hex_views(s) or ():
        if _layer2(v, "") != v or _deny_text(v, "") != v or _suspect(v):
            return _withheld(s, "binary data holding a secret-shaped text", field)
    return s


def _show_text(s, field):
    out = _deny_text(s, field)
    return _layer2(out, field)


def _show(s, kind, field):
    if s in OWN_NAMES or _MARK.fullmatch(s):
        return s
    if len(s) > MAX_ONE_STRING:
        return _show(s[:MAX_ONE_STRING], kind, field) + _withheld(s[MAX_ONE_STRING:], "rest of a long string", field)
    if kind in _TYPED:
        return s if len(s) <= 3 or _TYPED[kind].fullmatch(s) else _withheld(s, "not a %s" % kind, field)
    if kind == "hex":
        return _show_hex(s, field)
    flat = _flat(s)
    if flat != s:
        # an invisible character, or the escape of one: identifiers fail closed; free text is judged without it
        if kind in ("name", "path", "key", "url"):
            return _withheld(s, "invisible characters in a name", field)
        sealed = _show_text(flat, field)
        return sealed if sealed != flat else s
    if kind == "name":
        base = _show_name(s, field)
    elif kind == "path":
        base = _show_path(s, field)
    elif kind == "key":
        base = _show_key(s, field)
    elif kind == "url":
        base = _show_url(s, field)
    elif kind == "host":
        base = _show_host(s, field)
    else:
        return _show_text(s, field)
    return _layer2(base, field)


def show(s, kind="text", field=""):
    """The text the answer may show for the string `s` of a field of type `kind` (a T carries its own)."""
    if not isinstance(s, str) or not s:
        return s
    kind = getattr(s, "kind", kind)
    memo = (kind, field, s) if len(s) <= 512 else None
    if memo is not None:
        hit = _MEMO.get(memo)
        if hit is not None:
            return hit
    out = _show(str(s), kind, field)
    if memo is not None:
        if len(_MEMO) > 40000:
            _MEMO.clear()
        _MEMO[memo] = out
    return out


# ---- layer 3: the backstop, written apart from the layers above ------------------------------------------------------------------------
_S_ESC = re.compile(r"\\+(?:[uU]\{?([0-9a-fA-F]{4,8})\}?|x([0-9a-fA-F]{2}))")
_S_FILL = "\u115f\u1160\u3164\uffa0\u2800"


def _s_gone(c):
    cat = unicodedata.category(c)
    return cat[0] == "C" or cat in ("Mn", "Me", "Zl", "Zp") or c in _S_FILL


def _s_unesc(m):
    try:
        c = chr(int(m.group(1) or m.group(2), 16))
    except (ValueError, OverflowError):
        return m.group(0)
    return "" if _s_gone(c) else m.group(0)


def _s_normal(text):
    if "\\" in text:
        text = _S_ESC.sub(_s_unesc, text)
    if text.isascii() and text.isprintable():
        return text
    kept = [c for c in text if not _s_gone(c)]
    return unicodedata.normalize("NFKC", "".join(kept))


_S_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY|PRIVATE KEY-----")
_S_DELIM = re.compile(r"[=:]")
_S_LINE = re.compile(r"[ \t]*line[ \t]+[0-9]")
_S_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_S_STRONG = ("password", "passwd", "passphrase", "passw", "pwd", "secret", "token", "credential", "apikey", "api_key", "api-key", "accesskey", "access_key", "access-key",
             "accountkey", "account_key", "account-key", "privatekey", "private_key", "private-key", "masterkey", "master_key", "sharedkey", "shared_key", "signingkey", "encryptionkey",
             "secretkey", "secret_key", "secret-key")
_S_WEAK = ("pass", "pw", "auth", "sig", "sas")
_S_NOT_PASS = ("bypass", "compass", "overpass", "underpass", "trespass", "encompass", "surpass", "impass")
_S_DIGITS = re.compile(r"[0-9]{19}")
_S_HEXRUN = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{40,}(?![0-9A-Za-z])")
_S_B64NOPAD = re.compile(r"[A-Za-z0-9+/]{20,}")
_S_B64PAD = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{15,}={1,2}(?![A-Za-z0-9+=])")
_S_PREFIX = re.compile(r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{12}|(?:gh[pousr]_|github_pat_|glpat-|xox[a-z]-|xapp-|sk_live_|rk_live_|pk_live_|sk_test_"
                       r"|npm_|pypi-|shpat_|dop_v1_|AIza|ya29\.|SG\.)[A-Za-z0-9_-]{12}|sk-(?=[A-Za-z0-9_-]{0,11}[0-9])[A-Za-z0-9_-]{12}|eyJ[A-Za-z0-9_-]{12}")
_S_USERINFO = re.compile(r"[^\s/@:<>\"']{1,64}:[^\s/<>\"']{1,128}@[^\s/@<>\"']")
_S_RUN = re.compile(r"[A-Za-z0-9+/_-]{20,}")
_S_HEX = re.compile(r"[0-9A-Fa-f-]+")
_S_IDS = re.compile(r"\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?|S-1-[0-9]{1,2}(?:-[0-9]{1,10}){1,15}|[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.]+Z?")
_S_MARK = re.compile(r"<withheld[^<>]{0,120}>|\[withheld: \d+ characters\]")
_S_DIGEST_LABEL = re.compile(r"(?i)(?:md5|sha-?1|sha-?256|sha-?384|sha-?512|imphash|hashes?|filehash|ssdeep|tlsh)[\"'=:> \t]{1,6}(?:(?:md5|sha-?1|sha-?256|imphash)=)?[0-9a-f]{32,128}")
_TYPED_KINDS = frozenset(("guid", "digest", "sid", "mac", "ip", "time", "number", "version", "hex"))


def _class(c):
    return 0 if c.isdigit() else 1 if c.isupper() else 2


def _random_run(run):
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
        return False
    changes = sum(1 for a, b in zip(alnum, alnum[1:]) if _class(a) != _class(b)) / (len(alnum) - 1)
    digit_runs = len(re.findall(r"[0-9]+", alnum))
    if kinds == {0, 1, 2}:
        return changes >= 0.42 or (changes >= 0.3 and digit_runs >= 4 and len(set(alnum)) >= 0.6 * len(alnum))
    if kinds == {1, 2}:
        return changes >= 0.5 and len(alnum) >= 24
    return changes >= 0.4 and digit_runs >= 5 and len(set(alnum)) >= 0.5 * len(alnum)


def _s_named(flat):
    pos = 0
    while True:
        m = _S_DELIM.search(flat, pos)
        if not m:
            return False
        i = m.start()
        pos = m.end()
        after = flat[i + 1:i + 6].lstrip(" \t\"'\\")
        if not after or after[0] in "<>" or _S_LINE.match(flat, i + 1):
            continue
        j = i
        while j > 0 and flat[j - 1] in " \t\"'\\" and i - j < 5:
            j -= 1
        k = j
        while k > 0 and j - k < 64 and flat[k - 1] in _S_NAME_CHARS:
            k -= 1
        low = flat[k:j].lower()
        for plural in ("", "s"):
            if low.endswith(tuple(w + plural for w in _S_STRONG)):
                return True
            if low.endswith(tuple(w + plural for w in _S_WEAK)) and not low.endswith(tuple(w + plural for w in _S_NOT_PASS)):
                return True


def _suspect(text, kind="text"):
    """The name of the check a string fails, or None. A string of a typed kind is not tested for runs of hexadecimal digits or random-looking runs."""
    if not text or text in OWN_NAMES:
        return None
    if len(text) > MAX_ONE_STRING:
        text = text[:MAX_ONE_STRING]
    flat = _s_normal(text)
    if _S_MARK.search(flat):
        flat = _S_MARK.sub("<>", flat)
    if _S_PEM.search(flat):
        return "a PEM marker"
    bare = _S_IDS.sub(" ", flat)
    if _s_named(bare) or re.search(r"(?<![\w-])--?(?:pass|password|passwd|pwd|secret|token|apikey|api-key)[= ]\S", flat, re.I):
        return "a named secret"
    if _S_PREFIX.search(flat):
        return "a token prefix"
    if _S_USERINFO.search(re.sub("(?i)mailto:", "mailto ", flat)):
        return "user-info"
    if kind in _TYPED_KINDS:
        return None
    if _S_DIGITS.search(bare):
        return "a long digit run"
    labelled = _S_DIGEST_LABEL.sub(" ", bare) if "ash" in bare or "sha" in bare.lower() or "md5" in bare.lower() or "ASH" in bare else bare
    if _S_HEXRUN.search(labelled):
        return "a long hexadecimal run"
    for m in _S_B64NOPAD.finditer(labelled):
        if "/" in m.group() and "+" in m.group() and len({_class(c) for c in m.group() if c.isalnum()}) == 3:
            return "a base64 run with / and +"
    for m in _S_B64PAD.finditer(labelled):
        body = m.group().rstrip("=")
        if len(m.group()) % 4 == 0 and re.search(r"[0-9+/]", body) and len({_class(c) for c in body}) >= 2 and (("/" in body or "+" in body) or len(body) >= 20):
            return "a padded base64 run"
    for m in _S_RUN.finditer(labelled):
        if _random_run(m.group()):
            return "a random-looking run"
    return None


def _replace(value, where, check):
    BOUNDARY["replaced"] += 1
    BOUNDARY["replaced_by"][check] += 1
    if len(BOUNDARY["where"]) < MAX_WHERE:
        BOUNDARY["where"].append({"at": where or "/", "check": check})
    else:
        BOUNDARY["not_listed"] += 1
    return _mark(len(value.encode("utf-8", "replace")), "backstop: %s" % check, "bytes")


_CHECKED = {}


def _verdict(text, kind):
    memo = (kind, text) if len(text) <= 512 else None
    hit = _CHECKED.get(memo, False) if memo else False
    if hit is False:
        hit = None if _MARK.fullmatch(text) else _suspect(text, kind)
        if memo:
            if len(_CHECKED) >= 30000:
                _CHECKED.clear()
            _CHECKED[memo] = hit
    return hit


# ---- the walker ----------------------------------------------------------------------------------------------------------------------------
def _seal(value, kind, field, where, guard, fname=""):
    """`value` with every string sealed by the type of its field, and (guard) read back by the backstop. Keys are names. FIELDS maps a JSON key to the
    kind of what it holds, or to a function of the key of one item for a dict whose items have kinds of their own (event data, registry values)."""
    if isinstance(value, str):
        k = getattr(value, "kind", kind)
        out = show(value, k, field)
        if guard:
            check = _verdict(out, k)
            if check:
                return _replace(out, where, check)
        return out
    if isinstance(value, dict):
        hook = FIELDS.get(fname)
        hook = hook if callable(hook) else None
        out = {}
        for key, v in value.items():
            if isinstance(key, str):
                kk = KEY_KINDS.get(fname, "name")
                sk = show(key, kk, field)
                if guard:
                    check = _verdict(sk, kk)
                    if check:
                        sk = _replace(sk, where + "/(key)", check)
            else:
                sk = key
            while sk in out:
                sk = "%s #" % sk
            fk = key if isinstance(key, str) else ""
            sub_kind = (hook(key) if hook else None) or _kind_of(fk, kind)
            out[sk] = _seal(v, sub_kind, (field + "." + fk) if field and fk else (fk or field), where + "/" + str(key)[:60], guard, fk)
        return out
    if isinstance(value, (list, tuple)):
        return [_seal(v, kind, field, "%s/%d" % (where, i), guard, fname) for i, v in enumerate(value)]
    return value


def _kind_of(field, inherited):
    k = FIELDS.get(field)
    return k if isinstance(k, str) else inherited


def seal(value, kind="text", field=""):
    return _seal(value, kind, field, "", True)


def row_object(row):
    """A row of a paging file, sealed and read back: what the file may hold."""
    return _seal(row, "text", "", "", True)


def boundary_summary():
    return {"strings_withheld": BOUNDARY["withheld"], "withheld_by_reason": dict(BOUNDARY["by"]),
            "strings_replaced_by_the_backstop": BOUNDARY["replaced"], "replaced_by_check": dict(BOUNDARY["replaced_by"]),
            "replaced_at": list(BOUNDARY["where"]), "replaced_not_listed": BOUNDARY["not_listed"], "values": values_summary(),
            "note": "every key and value of this answer and of its paging files was judged by the type of its field: a name, path, key or URL is shown only when it "
                    "fits a plain grammar (a path component by component), free text has token-shaped runs, user-info and the value after a secret's name withheld, "
                    "and a second check written apart from both read it back. A withheld text is <withheld N characters: reason>. Not recognised: a secret that does "
                    "not look like one (a plain password or passphrase, a UUID-shaped key, anything under 16 characters in a name)."}


def answer_object(doc):
    """The answer (or an error answer), sealed and read back. A string the backstop had to replace makes a complete answer partial."""
    out = _seal(doc, "text", "", "", True)
    if isinstance(out, dict):
        out["boundary"] = boundary_summary()
        if BOUNDARY["replaced"] > 0 and out.get("status") == "complete":
            out["status"] = "partial"
            out["status_basis"] = "%s; %d string(s) still held a secret-shaped text when the answer was checked on its way out and were replaced (see boundary)" % (
                out.get("status_basis") or "", BOUNDARY["replaced"])
    return out


def emit(doc, **dumps_kwargs):
    """Print an answer through the boundary (the only way an answer leaves a tool that carries this block)."""
    obj = answer_object(doc)
    try:
        text = json.dumps(obj, ensure_ascii=False, default=str, **dumps_kwargs)
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = json.dumps(obj, ensure_ascii=True, default=str, **dumps_kwargs)
    print(text, flush=True)
# END SHARED BOUNDARY


# What the boundary is told about the fields of this tool's answers: the type of what a key holds. A key that is not listed holds free text; a
# table cell carries the type the tool gave it (T) when it was read.
FIELDS.update({
    "tables": "name", "tables_in_partial_export": "name", "table": "name", "columns": "name", "duplicate_columns_renamed": "name", "column": "name",
    "export_file": "path", "candidates": "path", "path": "path", "export_dir": "path", "export_manifest": "path", "stdout_file": "path", "stderr_file": "path",
    "all_results": "path", "values_file": "path", "db_sha256": "digest", "rule": "name", "kind": "name", "parameter": "name",
})


# ---- URL secrets: one design in browser_history, utf16_urls and esedb_query (a test holds the three copies identical)
#
# A URL can carry a session token, an API key or a password in its query string, its fragment or its user-info. Every URL in an
# answer has those values replaced by a marker that holds only their length ("[withheld: 12 characters]"), and the answer says how
# many were withheld, of what kind and where. The text is written whole only when the caller asks (write_url_secrets: true), only in
# a job (JOB_ID and OUT), to a file of mode 0600 that is created first and never replaced. NOT covered: a secret in a URL's path or
# title, a URL whose scheme this does not see, and a secret in free text.
import urllib.parse


class SecretValuesRefused(Exception):
    pass


def describe(exc):
    if isinstance(exc, OSError):
        return "%s: %s" % (type(exc).__name__, exc.strerror or exc)
    return "%s: %s" % (type(exc).__name__, exc)


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it (the secret-safe pattern of docs/packs.md)."""

    def __init__(self, enabled, tool, flag, name):
        self.enabled = enabled
        self.tool = tool
        self.flag = flag
        self.written = 0
        self._fh = None
        self.shown = None
        if not enabled:
            return
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out):
            raise SecretValuesRefused(
                "%s is refused outside a job: a value written here would be an ordinary file, not a sealed secret output. "
                "Run this as job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % (flag, tool)
            )
        path = Path(out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        # Created now, before anything is read: a file or a link already at that name is refused by name at once (O_EXCL does
        # not follow a link, a dangling one included). With nothing found it stays an empty file, mode 0600.
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id, locator, value):
        if self._fh is None:
            return
        text = json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=False)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            text = json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=True)
        self._fh.write(text + "\n")
        self.written += 1

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self, format_note):
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            "format": format_note if self.enabled else None,
        }


URL_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.\-]{1,15}://[^\s\"'<>\\^`{|}\x00-\x1f]+")
SECRET_SUBSTRINGS = ("token", "secret", "passw", "pwd", "auth", "bearer", "session", "signature", "credential", "assertion",
                     "jwt", "csrf", "xsrf", "ticket", "apikey", "accesskey")
SECRET_WORDS = {"sig", "sid", "key", "code", "pass", "otp", "sas", "saml", "hmac"}


def secret_parameter(name):
    """A query or fragment parameter whose name says its value is a credential: by a whole word (key, sig, code) or a substring (token)."""
    lowered = urllib.parse.unquote(name).lower()
    if any(s in lowered for s in SECRET_SUBSTRINGS):
        return True
    return any(w.lower() in SECRET_WORDS for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", urllib.parse.unquote(name)))


def url_marker(value):
    return "[withheld: %d characters]" % len(value)


def mask_parameters(text, kind, found, url):
    parts = re.split(r"([&;])", text)
    for i, part in enumerate(parts):
        if "=" not in part or part in ("&", ";"):
            continue
        key, value = part.split("=", 1)
        if value and secret_parameter(key):
            found.append((kind, key, value, url))
            parts[i] = key + "=" + url_marker(value)
    return "".join(parts)


def mask_url(url):
    """The URL with its secrets replaced by markers, and what was withheld: [(kind, parameter, value, url)]."""
    found = []
    start = url.index("://") + 3
    rest = url[start:]
    boundary = re.search(r"[/?#]", rest)
    cut = boundary.start() if boundary else len(rest)
    authority, tail = rest[:cut], rest[cut:]
    if "@" in authority:
        userinfo, host = authority.rsplit("@", 1)
        if ":" in userinfo:
            user, password = userinfo.split(":", 1)
            if password:
                found.append(("userinfo_password", None, password, url))
                userinfo = user + ":" + url_marker(password)
        elif len(userinfo) >= 16 and re.fullmatch(r"[A-Za-z0-9_.~%\-]+", userinfo):
            found.append(("userinfo_token", None, userinfo, url))
            userinfo = url_marker(userinfo)
        authority = userinfo + "@" + host
    before_hash, hash_mark, fragment = tail.partition("#")
    path, query_mark, query = before_hash.partition("?")
    if query:
        query = mask_parameters(query, "query_parameter", found, url)
    if "=" in fragment:
        fragment = mask_parameters(fragment, "fragment_parameter", found, url)
    return url[:start] + authority + path + query_mark + query + hash_mark + fragment, found


def mask_text(text):
    """`text` with the secrets of every URL in it withheld, and what was withheld."""
    if "://" not in text:
        return text, []
    found = []

    def one(match):
        masked, withheld = mask_url(match.group(0))
        found.extend(withheld)
        return masked

    return URL_RE.sub(one, text), found


class UrlSecrets:
    """Counts and locates what mask_text withheld; the values themselves go only to `values` (a SecretValues)."""

    def __init__(self, values, tool, key, limit):
        self.values = values
        self.count = 0
        self.by_kind = {}
        self.by_parameter = {}
        self.locators = LosslessPage(tool + "-url-secrets", key, limit)

    def mask(self, text, where):
        masked, found = mask_text(text)
        for kind, parameter, value, url in found:
            self.count += 1
            finding_id = "U%06d" % self.count
            self.by_kind[kind] = self.by_kind.get(kind, 0) + 1
            if parameter is not None:
                self.by_parameter[parameter] = self.by_parameter.get(parameter, 0) + 1
            self.locators.add({"finding_id": finding_id, "kind": kind, "parameter": parameter, "length": len(value), **where})
            self.values.add(finding_id, {"kind": kind, "parameter": parameter, **where, "url": url}, value)
        return masked

    def summary(self):
        page = self.locators.finish()
        return {
            "count": self.count,
            "by_kind": self.by_kind,
            "by_parameter": self.by_parameter,
            "locators": self.locators.page,
            "locators_page": page,
            "marker": "a withheld value is replaced by [withheld: N characters] (N is its length in the URL's own text); "
                      "where it was, its kind and its length are in locators; the value is not in this answer",
            "not_covered": "a secret in a URL's path, in a title, in free text, or in a URL whose scheme is not followed by ://",
        }
# ---- end of URL secrets


# Columns whose cells are withheld from the rows an answer returns: by name, and the attributes of an Active Directory datatable
# (NTDS.dit is an ESE database) that carry password hashes, their history, supplemental credentials and the password encryption keys.
CREDENTIAL_ATTRIBUTES = {"attk589914", "attk589879", "attk589918", "attk589984", "attk590689", "attk589949"}
SENSITIVE_NAME = re.compile(r"passw(or)?d|passwd|\bpwd\b|secret|token|api_?key|private_?key|encrypted|card_?number|cvc|cvv|bearer|credential", re.I)
CARD_WORDS = {"cc", "cvc", "cvv", "cvc2", "pin", "ssn", "iban", "card", "cards", "creditcard", "cardnumber", "ccnumber"}


def words(name):
    return {w.lower() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", name)}


def withheld_column(name):
    """Why the cells of a column are withheld, or None."""
    if name.lower() in CREDENTIAL_ATTRIBUTES:
        return "directory_credential_attribute"
    if SENSITIVE_NAME.search(name) or CARD_WORDS & words(name):
        return "name"
    return None


def fail(message, **extra):
    close_values()
    emit({"error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error)", **extra})
    raise SystemExit(1)


def work_root():
    """Where exports live, and the name they are cited by: $OUT/esedb-export in a job, else the agent's own directory."""
    out, job = os.environ.get("OUT"), os.environ.get("JOB_ID")
    if job and out:
        return Path(out) / "esedb-export", "store/jobs/%s/out/esedb-export" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)
    d = Path("work") / re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool") / "esedb-export"
    return d, str(d)


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def exporter_version():
    try:
        p = subprocess.run(["esedbexport", "-V"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        lines = p.stdout.decode("utf-8", "replace").strip().splitlines()
        return lines[0].strip() if p.returncode == 0 and lines else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def table_files(export):
    """The export's files, by table name. libesedb names each export file <table>.<its index>
    (Containers.4, Container_1.6): the table is the part before the index, the name an agent
    knows it by."""
    files = {}
    for f in sorted(os.listdir(export)):
        full = os.path.join(export, f)
        if os.path.isfile(full) and not os.path.islink(full):
            base = f[: -len(".csv")] if f.endswith(".csv") else f
            m = re.fullmatch(r"(.+)\.(\d+)", base)
            files[f] = m.group(1) if m else base
    return files


def reusable(record, base, digest, path):
    """An earlier export is trusted only when this tool wrote its manifest, it finished, and its files are the files it lists."""
    try:
        if record.get("parser") != PARSER or record.get("db_sha256") != digest or record.get("db_bytes") != os.path.getsize(path):
            return False
        if record.get("exporter_exit_status") != 0 or record.get("timed_out"):
            return False
        export = base / "db.export"
        if export.is_symlink() or not export.is_dir():
            return False
        files = record.get("files")
        if not isinstance(files, dict) or not files:
            return False
        recorded = {f: [v["table"], v["bytes"]] for f, v in files.items()}
        on_disk = {}
        for f in os.listdir(export):
            st = os.lstat(os.path.join(export, f))
            on_disk[f] = st.st_size if stat.S_ISREG(st.st_mode) else None
        if {f: v[1] for f, v in recorded.items()} != on_disk:
            return False
        if {f: v[0] for f, v in recorded.items()} != table_files(str(export)):
            return False
        return all((base / record[k]).is_file() for k in ("stdout_file", "stderr_file"))
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return False


def make_export(path, digest, timeout, root):
    """Run esedbexport once into root/<digest[:16]>/, or reuse a complete export of the same bytes.
    Returns (record, reused). The record is the export-manifest.json content. The export holds every table
    whole, so its directory is 0700 and its files 0600."""
    base = root / digest[:16]
    manifest_path = base / "export-manifest.json"
    if base.is_symlink():
        fail("the export directory is a link, which this tool does not follow", status="failed", export_dir=str(base))
    if manifest_path.is_file():
        try:
            record = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            record = None
        if isinstance(record, dict) and reusable(record, base, digest, path):
            return record, True
        shutil.rmtree(base, ignore_errors=True)       # a partial, unreadable or changed earlier export is made again
    if base.exists():
        shutil.rmtree(base, ignore_errors=True)       # a directory with no manifest is an export that was stopped: made again
    old_umask = os.umask(0o077)
    try:
        try:
            base.mkdir(parents=True, exist_ok=True, mode=0o700)
            target = str(base / "db")
            out_file, err_file = base / "esedbexport.stdout.txt", base / "esedbexport.stderr.txt"
            # -t names the export root; libesedb appends ".export". No -q: the esedbexport Debian
            # ships (20181229) has none, and refused the call.
            argv = ["esedbexport", "-t", target, path]
            def interrupted(signum):
                emit({"error": "stopped by signal %d before esedbexport finished" % signum, "status": "interrupted",
                      "status_basis": "the tool was stopped by signal %d; the export it was making is not complete" % signum, "signal": signum,
                      "export_dir": str(base),
                      "note": "The export is not complete and has no manifest; the next call makes it again."})

            STATE["last_word"] = interrupted
            with open(out_file, "wb") as so, open(err_file, "wb") as se:
                proc = spawn(argv, stdout=so, stderr=se)
                rc, timed_out = wait_for(proc, timeout)
            export = target + ".export"
            files = {}
            if os.path.isdir(export):
                files = {f: {"table": t, "bytes": os.path.getsize(os.path.join(export, f))} for f, t in table_files(export).items()}
            record = {
                "parser": PARSER,
                "db": path,
                "db_bytes": os.path.getsize(path),
                "db_sha256": digest,
                "exporter_argv": argv,
                "exporter_version": exporter_version(),
                "exporter_exit_status": rc,
                "timed_out": timed_out,
                "export_dir": "db.export" if os.path.isdir(export) else None,
                "stdout_file": out_file.name,
                "stderr_file": err_file.name,
                "files": files,
            }
            manifest_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        except OSError as exc:
            fail("the export could not be made: its directory could not be created or written, or esedbexport could not be run",
                 status="failed", export_dir=str(base), reason=describe(exc))
    finally:
        os.umask(old_umask)
    # Whatever the exporter's own umask made, nothing in the export is readable by anyone but its owner.
    try:
        for dirpath, dirnames, filenames in os.walk(base):
            os.chmod(dirpath, 0o700)
            for name in filenames:
                full = os.path.join(dirpath, name)
                if not os.path.islink(full):
                    os.chmod(full, 0o600)
    except OSError:
        pass
    return record, False


def cell_kind(v):
    """The type the boundary judges a table cell by: a number, binary data the exporter wrote as hexadecimal text, or text."""
    if len(v) <= 19 and re.fullmatch(r"-?[0-9]{1,18}", v):
        return "number"
    if len(v) >= 16 and len(v) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", v):
        return "hex"
    return "text"


def main():
    started = time.monotonic()
    deadline = started + DEADLINE_SECONDS
    install_signal_handlers()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the .dat or .edb file to read", path=args.get("path"))
    if not os.path.isfile(path):
        fail("no such file", path=path)

    table = args.get("table")
    if table is not None and not isinstance(table, str):
        fail("table must be a string", table=table)
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))
    limit = min(limit, 20000)
    timeout = args.get("export_timeout_seconds", 240)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
        fail("export_timeout_seconds must be a positive integer", export_timeout_seconds=args.get("export_timeout_seconds"))
    timeout = min(timeout, MAX_EXPORT_SECONDS)       # the tool's own limit is 300 s: esedbexport stops before it

    write_url_secrets = args.get("write_url_secrets", False)
    if not isinstance(write_url_secrets, bool):
        fail("write_url_secrets must be true or false")
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    # Both modes write secrets to a file: they are held to a job the harness runs as secret output (it sets SECRET_OUTPUT=1 for such a job's process),
    # decided before anything is opened or created.
    if write_url_secrets and os.environ.get("SECRET_OUTPUT") != "1":
        fail("write_url_secrets is refused: it is allowed only in a job the harness runs as secret output (job_run with secret_output: true), where the file is a "
             "sealed secret output. Nothing was written.")
    try:
        bind_values(write_values, "esedb_query")
    except ValuesRefused as exc:
        fail(str(exc))

    if shutil.which("esedbexport") is None:
        fail(
            "esedbexport is not on PATH",
            hint="brew install libesedb, or apt-get install libesedb-utils; "
            "scripts/toolbox.sh reports it with the dfir set",
        )

    try:
        values = SecretValues(write_url_secrets, "esedb_query", "write_url_secrets", "esedb_query-url-secrets.jsonl")
    except SecretValuesRefused as exc:
        fail(str(exc))
    url_secrets = UrlSecrets(values, "esedb_query", [path, table, limit], limit)

    root, shown_root = work_root()
    try:
        full = sha256_of(path)
    except OSError as exc:
        values.close()
        fail("the database could not be read: nothing was exported", path=path, status="failed", reason=describe(exc))
    digest = full[:16]
    # The directory is named by the first 16 hex digits; the manifest holds the whole digest. What hashing took is taken from the
    # exporter's time, and 15 seconds are left for reading the table.
    timeout = max(1, min(timeout, int(deadline - time.monotonic()) - 15))
    record, reused = make_export(path, full, timeout, root)
    base = root / digest
    export = base / "db.export"
    shown = "%s/%s" % (shown_root, digest)
    complete = record["exporter_exit_status"] == 0 and not record["timed_out"]
    logs = {"stdout_file": "%s/%s" % (shown, record["stdout_file"]), "stderr_file": "%s/%s" % (shown, record["stderr_file"])}
    try:
        stderr_text = (base / record["stderr_file"]).read_text(encoding="utf-8", errors="replace")
    except OSError:
        stderr_text = ""
    common = {
        "parser": PARSER,
        "path": path,
        "db_sha256": full,
        "exporter_version": record["exporter_version"],
        "exporter_exit_status": record["exporter_exit_status"],
        "timed_out": record["timed_out"],
        "export_reused": reused,
        "export_manifest": "%s/export-manifest.json" % shown,
        "export_dir": "%s/db.export" % shown,
        "export_dir_sensitive": "the export directory holds every table whole, including the cells and URL secrets this answer withholds: "
                               "it is mode 0700, a sensitive output of the job that made it, and is cited by file and table, never by value",
        **logs,
    }
    # The names of what this run made, and the path the caller gave, are the tool's own words: they are shown as they are.
    OWN_NAMES.update([path, common["export_manifest"], common["export_dir"], logs["stdout_file"], logs["stderr_file"], shown])
    if not os.path.isdir(str(export)) or not record["files"]:
        fail("esedbexport produced no tables",
             **{**common, "status": "failed", "stderr_first_lines": stderr_text.strip().splitlines()[:10]})

    files = {f: v["table"] for f, v in record["files"].items()}
    names = sorted(set(files.values()))
    if not complete:
        common.update({
            "status": "partial",
            "status_basis": "esedbexport %s, so the export is a part of the database; the rows of the tables it wrote are exactly what it wrote"
                            % ("was stopped by its time limit" if record["timed_out"] else "exited with status %s" % record["exporter_exit_status"]),
            "complete": False,
            "warning": "esedbexport %s: this is a PARTIAL export, and a table missing from it, or short, is not absent from the database; "
                       "the exporter's own output is in stdout_file and stderr_file" % ("was stopped by its time limit" if record["timed_out"] else "exited with status %s" % record["exporter_exit_status"]),
            "stderr_first_lines": stderr_text.strip().splitlines()[:10],
        })
    else:
        common.update({"status": "complete", "status_basis": "esedbexport exited 0 and wrote the tables listed", "complete": True})

    if table is None:
        sizes = {}
        for f, name in files.items():
            sizes[name] = sizes.get(name, 0) + record["files"][f]["bytes"]
        listing = {"tables_in_partial_export" if not complete else "tables": names}
        emit({
            **common,
            **listing,
            "table_count": len(names),
            "bytes_per_table": sizes,
            "files": {f: v["bytes"] for f, v in record["files"].items()},
            "hint": "call again with table=<name> to read one; the export is kept and reused",
        }, indent=2)
        values.close()
        close_values()
        return

    # By its name, or by the export file's own name (index and all).
    wanted = table.lower()
    exact = sorted(f for f in files if wanted in (f.lower(), f.lower().removesuffix(".csv")))
    hits = exact or sorted(f for f, name in files.items() if name.lower() == wanted)
    if not hits:
        values.close()
        fail("no such table", table=table, tables=names, export_status=common["status"], export_complete=common["complete"])
    if len(hits) > 1:
        values.close()
        fail("the table name matches more than one export file; name one of them", table=table, candidates=hits)
    chosen = files[hits[0]]
    src = str(export / hits[0])

    # The table file is what the exporter wrote: tab-separated text, one row to a line. It is read as that and as nothing else: a
    # quote is a character, not a quoting rule, so a cell that begins with one does not run on over the tabs and lines after it, and a
    # carriage return is a character of its cell. A file the exporter ended its lines with CR LF is read as that (said in the answer).
    rows = WholeRows("esedb_query", [path, table, hits[0], full], limit, INLINE_BYTES)
    url_secrets.locators = NoReplacePage("esedb_query-url-secrets", [path, table, limit], min(limit, 200))

    def last_word(signum):
        for page in (rows, url_secrets.locators):
            if page._tmp is not None:
                try:
                    os.unlink(page._tmp)
                except OSError:
                    pass
        values.close()
        close_values()
        emit({"error": "stopped by signal %d while the table was being read" % signum, "status": "interrupted",
              "status_basis": "the tool was stopped by signal %d; the rows it had read are not an answer" % signum,
              "signal": signum, "rows_read": rows.total, "table": chosen, "export_file": hits[0],
              "note": "The export is complete on disk and is reused; the whole of it is in export_dir."})

    STATE["last_word"] = last_word
    try:
        fh = open(src, "r", encoding="utf-8", errors="replace", newline="\n")
    except OSError as exc:
        values.close()
        fail("the exported table file could not be read", table=chosen, export_file=hits[0], status="failed", reason=describe(exc))
    stopped = None                                    # why the reading ended before the end of the file, or None
    rows_cut = []                                     # rows read only up to ROW_READ_CHARS: [(row, chars)]
    with fh:
        head, head_chars, head_cut = read_row(fh, ROW_READ_CHARS)
        crlf = bool(head is not None and head.endswith("\r"))
        if crlf:
            head = head[:-1]
        header = head.split("\t") if head else []
        # Two columns of one name would overwrite each other in a row (and one named like a key the tool adds would replace it): the
        # later ones are numbered.
        count, used, columns = {}, set(), []
        for h in header:
            count[h] = count.get(h, 0) + 1
            candidate = h if count[h] == 1 and h not in RESERVED_COLUMNS else "%s_%d" % (h, count[h] + (1 if h in RESERVED_COLUMNS else 0))
            while candidate in used:
                candidate += "_"
            used.add(candidate)
            columns.append(candidate)
        renamed = [c for c, h in zip(columns, header) if c != h]
        # Cells of a credential column are replaced by a marker that holds only their length; every other cell has the secrets of
        # its URLs withheld.
        why = {i: withheld_column(h) for i, h in enumerate(header)}
        withheld = {i: {"column": columns[i], "rule": r, "cells_withheld": 0, "total_length": 0} for i, r in why.items() if r}
        ordinal = 0
        while True:
            if time.monotonic() > deadline:
                stopped = "the tool's own time limit (%d seconds) was reached after row %d" % (DEADLINE_SECONDS, ordinal)
                break
            line, chars, cut = read_row(fh, ROW_READ_CHARS)
            if line is None:
                break
            ordinal += 1
            if crlf and line.endswith("\r") and not cut:
                line = line[:-1]
            if cut:
                rows_cut.append((ordinal, chars))
            cells, shown, shortened = {}, {}, {}
            for i, v in enumerate(line.split("\t")):
                name = columns[i] if i < len(columns) else "col%d" % i
                if i in withheld and v != "":
                    withheld[i]["cells_withheld"] += 1
                    withheld[i]["total_length"] += len(v)
                    v = "[withheld: %d characters]" % len(v)
                else:
                    v = url_secrets.mask(v, {"table": chosen, "row": ordinal, "column": name}) if "://" in v else v
                kind = cell_kind(v)
                cells[name] = T(kind, v)
                if len(v) > CELL_INLINE_CHARS:
                    shown[name] = T(kind, v[:CELL_INLINE_CHARS])
                    shortened[name] = len(v)
                else:
                    shown[name] = cells[name]
            whole = {"_row": ordinal, **cells}
            if cut:
                whole["_row_read_cut"] = {"chars_read": ROW_READ_CHARS, "row_chars": chars}
            if shortened or cut:
                inline = {"_row": ordinal, **shown, "_cells_shortened": {k: {"chars": n, "shown": CELL_INLINE_CHARS} for k, n in shortened.items()}}
                if cut:
                    inline["_row_read_cut"] = whole["_row_read_cut"]
                rows.add_row(whole, inline)
            else:
                rows.add_row(whole)
    page = rows.finish()
    status = "partial" if (stopped or rows_cut or not complete) else common["status"]
    if stopped:
        basis = stopped + "; the rows after it were not read (the whole table is in export_file)"
    elif rows_cut:
        basis = "%d row(s) were longer than %d characters and were read only that far (rows_read_cut)" % (len(rows_cut), ROW_READ_CHARS)
    elif not complete:
        basis = common["status_basis"]
    else:
        basis = "esedbexport exited 0 and every row of the table file was read"
    columns_shown = header[:COLUMNS_INLINE]
    url_summary = url_secrets.summary()
    OWN_NAMES.update(x for x in (page.get("all_results"), url_summary["locators_page"].get("all_results"), _VALUES["shown"], values.shown) if x)
    emit({
        **common,
        "status": status,
        "status_basis": basis,
        "table": chosen,
        "export_file": hits[0],
        "export_file_line_ending": "CR LF" if crlf else "LF",
        "columns": columns_shown,
        "column_count": len(header),
        "columns_not_shown": len(header) - len(columns_shown),
        "duplicate_columns_renamed": renamed,
        "rows": rows.page,
        "row_count": page["matched"],
        "rows_complete": stopped is None,
        "rows_stopped": stopped,
        "rows_read_cut": [{"row": r, "row_chars": n} for r, n in rows_cut[:50]],
        "rows_read_cut_count": len(rows_cut),
        "row_ordinals": "_row is the 1-based line of the row in the exported table file, counting from the line after the header; the file is "
                        "in export_dir and holds every row and cell whole",
        "cells": "cells are the text the exporter wrote, not decoded; a cell longer than %d characters is shown cut inline "
                 "(_cells_shortened names it) and is whole in all_results" % CELL_INLINE_CHARS,
        "columns_withheld": list(withheld.values()),
        "url_secrets_withheld": url_summary,
        "secret_values": values.summary("JSON Lines, mode 0600: finding_id, kind, parameter, table, row, column, url (the whole text), value (the secret)"),
        **page,
    }, indent=2)
    values.close()
    close_values()


if __name__ == "__main__":
    main()

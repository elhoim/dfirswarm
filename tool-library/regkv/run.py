#!/usr/bin/env python3
"""Read a Windows registry hive with regipy: a key's values, its subkeys, and a bounded recursive listing.

What it is: a reader, not a decoder. A binary value comes back as hex and nothing more: UserAssist, ShimCache,
BAM, SAM and ShellBag values are not decoded here, and a typed reading of any of them needs a decoder that
knows its layout and its Windows version. Every value carries its registry type and length beside its
value, and nothing is cut (regipy's default trims a value to 256 characters; this reads them whole).

Completeness is said, not assumed. A key or value that cannot be read is named under `problems`, a key that
declares more values than were read is a problem too, a branch the walk did not enter (depth limit, node limit,
an error, or a subkey list that was already reached: a cycle) under `stopped_branches`, and the answer says
whether the hive is dirty (its two sequence numbers differ: its newest state may be in the .LOG files) and which
transaction logs sit beside it. The logs are NOT replayed here. The inline listing holds the first 2000 keys;
every key listed is also in the file `all_subkeys` names when there are more, and the answer is then `partial`.
depth is 0 to 128, because the nested listing is a JSON document and a deeper one cannot be written.

SENSITIVE OUTPUT. A value whose name says password, secret, token or credential, the values of the LSA secrets
and cached-logon keys of a SECURITY hive, and the V value of each SAM user (which holds password verifiers) are
registry material that can be a secret. Their text and bytes are never in the answer: the value is replaced by
a marker that holds its length, and `sensitive_values_withheld` lists key, name, type and length. No flag brings
one back; this tool produces no secret and has no capability to recover one.

The key path is read from the hive's root, a leading backslash or not, with / or \\ between names. A value
is judged by its name and by where it sits (the canonical path of names the hive itself holds, never the
spelling the caller typed) and never by its type, so a value of an odd type under a secret's name or place is
withheld too; only a DWORD or QWORD is let through under a secret-sounding name. A secret inside a value that
does not look like one (a command line with a password in it) is NOT recognised and comes back whole.
"""
import collections
import datetime
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

PARSER = "regkv/4"
MAX_DEPTH = 128
FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
SENSITIVE_NAME = re.compile(r"passw(or)?d|pwd|secret|token|credential|api_?key|private_?key", re.I)
NUMBER_TYPES = ("REG_DWORD", "REG_DWORD_BIG_ENDIAN", "REG_QWORD")
INLINE_NODES = 2000
MAX_NODES = 1_000_000
DEADLINE_SECONDS = 27             # the manifest allows 30
INLINE_PROBLEMS = 50
INLINE_NAMES = 200

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib


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


# BEGIN SHARED PAGE
# The same text is in every windows-forensics tool that pages through LosslessPage (held equal by a windows-forensics test): LosslessPage replaces a file of the
# same name; this one places its finished file with place_without_replacing, and registers itself so that a stop can remove its temporary file.
PAGES = []


class NoReplacePage(LosslessPage):
    """LosslessPage whose finished file is placed without replacing an earlier file of the same name (a rerun with other limits, or one
    the time limit stopped, must not leave a smaller file where a larger one was)."""

    def __init__(self, tool, key, limit):
        super().__init__(tool, key, limit)
        PAGES.append(self)

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
# END SHARED PAGE


# BEGIN SHARED STOP
# The same text is in regkv, shellbags and amcache_apps (held equal by a windows-forensics test). SIGTERM, SIGINT and SIGHUP end the tool with JSON (status
# interrupted, exit 128 + the signal) and remove the temporary file a page was writing; the tool's own clock (set_deadline) is below the manifest's.
import signal
import time

STOP = {"last_word": None, "deadline": None}


def set_deadline(seconds):
    STOP["deadline"] = time.monotonic() + seconds


def out_of_time():
    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"]


def _on_signal(signum, _frame):
    for page in list(PAGES):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    last_word = STOP["last_word"]
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    os._exit(128 + signum)


def install_signal_handlers(last_word=None):
    STOP["last_word"] = last_word
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


def interrupted_answer(signum, **extra):
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "interrupted",
                      "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer" % signum,
                      "signal": signum, **extra}), flush=True)
# END SHARED STOP


# BEGIN SHARED HIVE BOUNDS
# The same text is in regkv, shellbags and amcache_apps (a windows-forensics test holds the copies equal).
# A hive of N bytes holds at most N // 76 key cells (an nk cell is at least 76 bytes) and N // 20 value cells (a vk cell is at least 20), however
# many elements an index claims: regipy follows a subkey index (ri) element by element, so one list repeated by an index is read as many times as
# it is repeated (a 61 KB hive listed a million keys and took 1.2 GB). Every list of subkeys and values is read through these bounds, and what is
# past one is said, never followed.
import itertools
import logging
import warnings

KEY_CELL_BYTES = 76
VALUE_CELL_BYTES = 20


class LibraryLog(logging.Handler):
    """regipy reports what it cannot parse through the logging module, and its text carries bytes of the value or the name it failed on
    (for a text value that is neither UTF-16 nor UTF-8: the byte and its position). The text is not printed anywhere: it is counted."""
    messages = 0
    errors = 0

    def emit(self, record):
        LibraryLog.messages += 1
        if record.levelno >= logging.ERROR:
            LibraryLog.errors += 1


def withhold_library_output():
    logging.root.handlers[:] = [LibraryLog()]
    warnings.simplefilter("ignore")


class HiveBounds:
    def __init__(self, hive_path, size=None):
        size = os.path.getsize(hive_path) if size is None else size
        self.hive_bytes = size
        self.key_cells = max(size // KEY_CELL_BYTES, 1)
        self.value_cells = max(size // VALUE_CELL_BYTES, 1)
        self.keys_read = 0                      # subkey elements read over the whole walk
        self.data_read = 0                      # bytes of value data read over the whole walk
        self.repeats = 0                        # elements that named a key already named in the same list

    def subkeys(self, node, where, problems):
        """The distinct subkeys of `node`, at most the keys the hive can still hold; what is past that, or repeated, is a problem line."""
        room = max(self.key_cells - self.keys_read, 0)
        raw = list(itertools.islice(node.iter_subkeys() or [], room + 1))
        if len(raw) > room:
            raw = raw[:room]
            problems.append({"where": where, "what": "subkeys",
                             "error": "its subkey list yields more keys than a %d-byte hive can hold (%d keys at most, %d already read in this walk): "
                                      "an index that repeats a list; the elements past that are not read" % (self.hive_bytes, self.key_cells, self.keys_read)})
        self.keys_read += len(raw)
        seen, distinct, repeated = set(), [], 0
        for sub in raw:
            header = getattr(sub, "header", None)
            identity = (str(getattr(sub, "name", "")).lower(), getattr(header, "last_modified", None),
                        getattr(header, "subkeys_list_offset", None), getattr(header, "values_list_offset", None))
            if identity in seen:
                repeated += 1
                continue
            seen.add(identity)
            distinct.append(sub)
        if repeated:
            self.repeats += repeated
            problems.append({"where": where, "what": "subkeys",
                             "error": "its subkey list names %d key(s) more than once; each is listed once" % repeated})
        return distinct

    def values(self, node, where, problems, **kwargs):
        """At most the values the hive can hold, as a list, and at most the data it can hold over the whole walk (a value list that names one big
        record again and again reads that record every time); a key that lists more is a problem line."""
        raw = []
        for v in itertools.islice(node.iter_values(**kwargs), self.value_cells + 1):
            if len(raw) >= self.value_cells:
                problems.append({"where": where, "what": "values",
                                 "error": "its value list yields more values than a %d-byte hive can hold (%d at most): the elements past that are not read"
                                          % (self.hive_bytes, self.value_cells)})
                break
            data = getattr(v, "value", None)
            self.data_read += len(data) if isinstance(data, (bytes, bytearray, str)) else sum(len(x) for x in data if isinstance(x, (str, bytes))) if isinstance(data, list) else 0
            if self.data_read > 4 * self.hive_bytes:
                problems.append({"where": where, "what": "values",
                                 "error": "the values read in this walk hold more data than a %d-byte hive can: records that a value list names again and again; "
                                          "the values past that are not read" % self.hive_bytes})
                break
            raw.append(v)
        return raw
# END SHARED HIVE BOUNDS


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


_MARK = re.compile(r"<withheld \d+ (?:characters|bytes)(?:: [a-z][a-z ,-]{0,60})?>")
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
    if "<" not in text:
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
_S_MARK = re.compile(r"<withheld[^<>]{0,120}>")
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
# registry value carries the type the tool gave it (T) when it was read.
FIELDS.update({
    "hive": "path", "key": "key", "path": "key", "where": "key", "deepest_found": "key", "missing": "key", "subkeys_there": "key", "name": "key",
    "all_nodes": "path", "all_subkeys": "path", "all_stopped_branches": "path", "all_problems": "path", "transaction_logs_beside_hive": "path",
    "last_modified": "time", "last_modified_filetime": "number", "regipy_version": "version", "values_file": "path", "type": "name",
})
KEY_KINDS.update({"values": "key", "value_types": "key", "value_lengths": "key"})   # registry value names are often paths (MuiCache, UserAssist)


def ft_to_iso(ft):
    """A FILETIME (100 ns since 1601-01-01 UTC) as ISO 8601 UTC with seven fractional digits, by integer arithmetic."""
    try:
        whole, ticks = divmod(int(ft), 10_000_000)
        return (FILETIME_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (TypeError, ValueError, OverflowError):
        return None


class KeyMissing(Exception):
    """The key asked for is not in the hive: what was found, what is missing, and the names that are there."""

    def __init__(self, found, missing, there):
        super().__init__(missing)
        self.found, self.missing, self.there = found, missing, there


def split_path(path):
    return [p for p in str(path).replace("/", "\\").split("\\") if p]


def resolve(hive, path, bounds=None):
    """The key at `path`, from the hive's root, and the names of it as the hive itself holds them. regipy's get_key
    takes the first part of a path that does not start with a backslash for the root's own name and drops it, so
    the path is walked here: the root's name is dropped when the caller gave it, / is taken for \\, and a part is
    matched without regard to case. The canonical names are what a value is judged by (a place such as
    Policy\\Secrets is the same place however the caller spelled it)."""
    parts = split_path(path)
    if parts and parts[0].lower() == (hive.root.name or "").lower():
        parts = parts[1:]
    bounds = bounds or HiveBounds(None, 1 << 40)
    node, names = hive.root, []
    for part in parts:
        kids = bounds.subkeys(node, "\\" + "\\".join(names), [])
        match = next((kid for kid in kids if kid.name.lower() == part.lower()), None)
        if match is None:
            raise KeyMissing("\\" + "\\".join(names), part, [kid.name for kid in kids])
        node, names = match, names + [match.name]
    return node, names


def hive_kind(hive):
    kind = getattr(hive, "hive_type", None)
    return str(kind).lower() if kind else None


SAM_USER_KEY = re.compile(r"\\domains\\account\\users\\[0-9a-f]{8}\\$")
CACHED_LOGON = re.compile(r"^NL\$", re.I)
SECRET_PLACES = ("\\policy\\secrets\\", "\\policy\\poleklist\\", "\\policy\\polsecretencryptionkey\\")


def sensitive_value(names, name, vtype):
    """Whether this value is registry material that can be a secret (see the module note). Decided by the value's
    name and the key's place in the hive (its canonical names), never by the value's type and never by what the hive
    file calls itself. The one thing a type buys is that a DWORD or QWORD is not text and is let through under a
    secret-sounding name; a place withholds every value in it."""
    name = name or ""
    if (SENSITIVE_NAME.search(name) or CACHED_LOGON.match(name)) and vtype not in NUMBER_TYPES:
        return True
    path = "\\" + "\\".join(names).lower() + "\\"
    if any(place in path for place in SECRET_PLACES):
        return True
    return bool(SAM_USER_KEY.search(path)) and name.lower() == "v"


UNDECODED_TYPES = ("REG_DWORD_BIG_ENDIAN",)


def read_values(k, shown, names, withheld, problems, bounds):
    """Every value of key `k`, whole: the value as regipy decodes it (bytes as hex), its type and its length."""
    values, types, lengths, corrupted = {}, {}, {}, []
    renamed, next_free = {}, {}                               # a name -> [how many later values were renamed, the first new name]; a name -> the last number given
    read = 0
    try:
        # trim_values=False: the default cuts a binary value to 128 bytes and a string to 256 characters.
        for v in bounds.values(k, shown, problems, trim_values=False):
            read += 1
            val = v.value
            vtype = str(v.value_type)
            if isinstance(val, (bytes, bytearray)):
                length, unit = len(val), "bytes"
                val = T("hex", bytes(val).hex())
            elif isinstance(val, str):
                length, unit = len(val), "characters"
                val = T("text", val)
            elif isinstance(val, list):
                length, unit = len(val), "strings"
                val = [T("text", x) if isinstance(x, str) else x for x in val]
            else:
                length, unit = None, None
            if sensitive_value(names, v.name, vtype):
                withheld.append({"key": shown, "name": v.name, "type": vtype, "length": length})
                val = "[withheld: %d %s]" % (length, unit) if length is not None else "[withheld]"
            elif vtype in UNDECODED_TYPES:
                problems.append({"where": shown, "what": "values", "error": "the value %r is of type %s, for which regipy returns no data: its bytes are not in this answer" % (v.name, vtype)})
            # One pointer per name, which only moves forward: the second value of a name is "name (2)", the third "name (3)", and a
            # name that a value already holds (one really called "name (2)") is passed over. (A loop that starts at 2 for every
            # duplicate is quadratic: 8,000 values of one name took nine seconds.)
            name = v.name
            if name in values:
                n = max(next_free.get(v.name, 1), 1)
                while True:
                    n += 1
                    name = "%s (%d)" % (v.name, n)
                    if name not in values:
                        break
                next_free[v.name] = n
                renamed.setdefault(v.name, [0, name])[0] += 1
            values[name] = val
            types[name] = vtype
            lengths[name] = length
            if getattr(v, "is_corrupted", False):
                corrupted.append(name)
    except Exception as exc:                                  # a damaged value list: what was read is kept, the rest is named
        problems.append({"where": shown, "what": "values", "error": "%s: %s" % (type(exc).__name__, exc)})
    for name, (count, first) in renamed.items():
        problems.append({"where": shown, "what": "values",
                         "error": "the key holds more than one value named %r; the %d later one(s) are listed as %r and so on" % (name, count, first)})
    declared = getattr(k, "values_count", None)
    if isinstance(declared, int) and not isinstance(declared, bool) and declared != read:
        problems.append({"where": shown, "what": "values",
                         "error": "the key declares %d values and %d were read (regipy stops at a value record it cannot parse and skips one of a type it does not know)" % (declared, read)})
    return values, types, lengths, corrupted


def list_id(node):
    """What names a key's subkey list: two keys that share it are a cycle or a damaged hive, never two lists."""
    header = getattr(node, "header", None)
    return getattr(header, "subkeys_list_offset", None)


class SealedPage(NoReplacePage):
    """A page whose rows are written through the boundary."""

    def _write(self, row):
        super()._write(row_object(row))


class Sink:
    """A list that is a page: what is appended is kept in the page and its file."""

    def __init__(self, page):
        self.page = page

    def append(self, item):
        self.page.add(item)


def dump(hive_path, key, recurse=False, depth=2, limit=500, max_nodes=MAX_NODES):
    from regipy.registry import RegistryHive
    h = RegistryHive(hive_path)
    bounds = HiveBounds(hive_path)
    k, names = resolve(h, key, bounds)
    shown = "\\".join(names)
    withheld = []
    # Problems go to a page as they are found (a hive can have one for every key): the first INLINE_PROBLEMS are inline, all are in the file.
    problem_page = SealedPage("regkv-problems", [hive_path, key, depth, max_nodes], INLINE_PROBLEMS)
    problems = Sink(problem_page)
    out = {"key": key, "values": {}, "subkeys": []}
    values, types, lengths, corrupted = read_values(k, shown, names, withheld, problems, bounds)
    out["values"], out["value_types"], out["value_lengths"] = values, types, lengths
    if corrupted:
        out["corrupted_values"] = corrupted
    hdr = getattr(k, "header", None)
    if hdr is not None:
        out["last_modified"] = ft_to_iso(hdr.last_modified)
        out["last_modified_filetime"] = str(hdr.last_modified)
    # The names of the whole results do not hold anything a caller can choose except what was asked about and how far (the bounds are part
    # of what was asked), and a result file that is there is not replaced by a smaller one.
    page_key = [hive_path, key, depth, bool(recurse), max_nodes]
    nodes = SealedPage("regkv", [hive_path, key, depth, max_nodes], limit)
    every = SealedPage("regkv-subkeys", page_key, INLINE_NODES)
    stopped = SealedPage("regkv-stopped", [hive_path, key, depth, max_nodes], 50)
    seen = 0
    tree_complete = True
    out_of_time_at = None
    visited = set()
    if list_id(k) is not None and k.subkey_count:
        visited.add(list_id(k))
    # Breadth first from the key asked for: (a key's node, the list its entries go in, its path, its depth).
    queue = collections.deque([(k, out["subkeys"], shown, 0)])
    while queue:
        if out_of_time():
            out_of_time_at = seen
            break
        node, target, path, d = queue.popleft()
        try:
            children = bounds.subkeys(node, path, problems)
        except Exception as exc:
            problems.append({"where": path, "what": "subkeys", "error": "%s: %s" % (type(exc).__name__, exc)})
            stopped.add({"path": path, "reason": "its subkeys could not be read", "error": "%s: %s" % (type(exc).__name__, exc)})
            continue
        for s in children:
            seen += 1
            entry = {"name": s.name, "subkeys": s.subkey_count, "values": s.values_count}
            sh = getattr(s, "header", None)
            if sh is not None:
                entry["last_modified"] = ft_to_iso(sh.last_modified)
                entry["last_modified_filetime"] = str(sh.last_modified)
            child_path = (path + "\\" + s.name) if path else s.name
            # Every key listed goes to the paging block, so that what the inline list leaves out is in a file the answer names.
            every.add({"path": child_path, "depth": d + 1, "subkeys": s.subkey_count, "values": s.values_count,
                       "last_modified": entry.get("last_modified"), "last_modified_filetime": entry.get("last_modified_filetime")})
            if seen <= INLINE_NODES:
                target.append(entry)
            else:
                tree_complete = False
            if recurse:
                nodes.add({"path": child_path, "depth": d + 1, "subkeys": s.subkey_count, "values": s.values_count,
                           "last_modified": entry.get("last_modified"), "last_modified_filetime": entry.get("last_modified_filetime")})
            if recurse and s.subkey_count:
                lid = list_id(s)
                if d >= depth:
                    stopped.add({"path": child_path, "reason": "depth limit (%d)" % depth, "subkeys": s.subkey_count})
                elif seen >= max_nodes:
                    stopped.add({"path": child_path, "reason": "node limit (%d)" % max_nodes, "subkeys": s.subkey_count})
                elif lid is not None and lid in visited:
                    problems.append({"where": child_path, "what": "subkeys",
                                     "error": "its subkey list (offset %s) was already reached: a cycle, or a list two keys share; it is not entered again" % lid})
                    stopped.add({"path": child_path, "reason": "its subkey list was already reached (a cycle or a shared list)", "subkeys": s.subkey_count})
                else:
                    if lid is not None:
                        visited.add(lid)
                    sub = []
                    if seen <= INLINE_NODES:
                        entry["subkey_list"] = sub
                    queue.append((s, sub, child_path, d + 1))
    if out_of_time_at is not None:
        # Whatever is still queued was not opened: each is named, none is passed over.
        for node, _target, path, d in queue:
            stopped.add({"path": path, "reason": "the tool's own time limit (%d seconds) was reached" % DEADLINE_SECONDS, "subkeys": getattr(node, "subkey_count", None)})
        problems.append({"where": shown, "what": "walk", "error": "the tool's own time limit (%d seconds) was reached after %d keys; %d branch(es) were not opened" % (DEADLINE_SECONDS, seen, len(queue))})
    out["tree_complete"] = tree_complete
    out["nodes_listed"] = seen
    every_page = every.finish()
    if every_page.get("all_results"):
        out["all_subkeys"] = every_page["all_results"]
        out["all_subkeys_note"] = "every key listed, with its path: the inline subkeys and subkey_list hold the first %d" % INLINE_NODES
    stopped_page = stopped.finish()
    out["stopped_branches"] = stopped.page
    out["stopped_branch_count"] = stopped_page["matched"]
    if stopped_page.get("all_results"):
        out["all_stopped_branches"] = stopped_page["all_results"]
    node_page = nodes.finish()
    if recurse:
        out["nodes"] = nodes.page
        out["node_count"] = node_page["matched"]
        if node_page.get("all_results"):
            out["all_nodes"] = node_page["all_results"]
    if LibraryLog.messages:
        problems.append({"where": shown, "what": "library", "error": "regipy logged %d message(s) (%d of them errors) while reading; its text can hold bytes of a value or a name and is not shown" % (LibraryLog.messages, LibraryLog.errors)})
    problem_result = problem_page.finish()
    out["problems"] = problem_page.page
    out["problem_count"] = problem_result["matched"]
    if problem_result.get("all_results"):
        out["all_problems"] = problem_result["all_results"]
    out["walk_stopped_by_time_limit"] = out_of_time_at is not None
    out["library_messages_withheld"] = LibraryLog.messages
    out["sensitive_values_withheld"] = withheld
    header = h.header
    out["hive_dirty"] = header.primary_sequence_num != header.secondary_sequence_num
    out["hive_sequence_numbers"] = [header.primary_sequence_num, header.secondary_sequence_num]
    out["transaction_logs_beside_hive"] = [hive_path + s for s in (".LOG1", ".LOG2", ".LOG") if os.path.isfile(hive_path + s)]
    out["transaction_logs_replayed"] = False
    out["hive_type"] = hive_kind(h)
    out["hive_bounds"] = {"hive_bytes": bounds.hive_bytes, "most_keys": bounds.key_cells, "most_values": bounds.value_cells,
                          "subkey_elements_read": bounds.keys_read, "repeated_subkey_elements_skipped": bounds.repeats}
    return out


def refuse(message, **extra):
    close_values()
    emit({"ok": False, "error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error); no key was read", **extra})
    sys.exit(1)


def main():
    withhold_library_output()
    set_deadline(DEADLINE_SECONDS)
    install_signal_handlers(lambda signum: interrupted_answer(signum))
    raw = sys.stdin.read()
    if not raw.strip():
        refuse('no JSON input')
    try:
        args = json.loads(raw)
    except ValueError as exc:
        refuse("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        refuse("the arguments are one JSON object")
    hive = args.get('hive'); key = args.get('key')
    if not isinstance(hive, str) or not hive or not isinstance(key, str):
        refuse('hive and key are required, both text')
    try:
        mode = os.stat(hive).st_mode
    except OSError:
        refuse('no such hive', hive=hive)
    if not stat.S_ISREG(mode):
        # A named pipe or a device would be opened and waited on: it is not read.
        refuse('the hive is not a regular file, so it was not opened', hive=hive, not_attempted=1)
    write_values = args.get('write_values', False)
    if not isinstance(write_values, bool):
        refuse('write_values must be true or false')
    try:
        bind_values(write_values, 'regkv')
    except ValuesRefused as exc:
        refuse(str(exc))
    OWN_NAMES.update([hive, key])
    recurse = bool(args.get('recurse', False))
    depth = args.get('depth', 2)
    limit = args.get('limit', 500)
    max_nodes = args.get('max_nodes', MAX_NODES)
    for name, v, low, high in (("depth", depth, 0, MAX_DEPTH), ("limit", limit, 1, None), ("max_nodes", max_nodes, 1, None)):
        if isinstance(v, bool) or not isinstance(v, int) or v < low or (high is not None and v > high):
            refuse("%s must be a whole number from %d%s" % (name, low, " to %d" % high if high is not None else " up"), name=v)
    try:
        import regipy.registry  # noqa: F401  (dump() imports what it uses; this is where a missing library is said)
    except ImportError as exc:
        refuse("regipy is not installed: python3 -m pip install regipy", reason=str(exc))
    try:
        out = dump(hive, key, recurse, depth, limit, max_nodes)
    except KeyMissing as gone:
        there = gone.there
        refuse('key not found', key=key, deepest_found=gone.found, missing=gone.missing, subkeys_there=there[:INLINE_NAMES],
               subkeys_there_count=len(there), subkeys_there_not_shown=max(len(there) - INLINE_NAMES, 0),
               subkeys_there_note="the first %d names of the key that was reached, in order; read that key to list them all (all_subkeys)" % INLINE_NAMES)
    except Exception as exc:                                  # not a hive, or one regipy cannot open
        refuse("could not read the hive", hive=hive, reason="%s: %s" % (type(exc).__name__, exc))
    try:
        from importlib.metadata import version
        regipy_version = version("regipy")
    except Exception:
        regipy_version = None
    reasons = []
    if out["problem_count"]:
        reasons.append("%d problem(s) are named under problems" % out["problem_count"])
    if out["stopped_branch_count"]:
        reasons.append("%d branch(es) were not entered (stopped_branches)" % out["stopped_branch_count"])
    if not out["tree_complete"]:
        reasons.append("the inline listing holds the first %d keys (the rest are in all_subkeys)" % INLINE_NODES)
    out = {"parser": PARSER, "regipy_version": regipy_version, "hive": hive,
           "status": "partial" if reasons else "complete",
           "status_basis": "; ".join(reasons) if reasons else "every subkey and value list the answer needed was read to its end: no problem is named and no branch was left unentered", **out}
    emit(out, indent=1)
    close_values()


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        emit({"ok": False, "error": "the read failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error", "reason": "%s: %s" % (type(exc).__name__, exc)})
        sys.exit(1)

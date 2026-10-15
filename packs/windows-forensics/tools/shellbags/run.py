#!/usr/bin/env python3
"""Walk BagMRU and say which folders a user opened in Explorer.

Shell bags record that a shell component opened a folder on an account, including
folders that no longer exist (a volume that was taken away, a share that has been
decommissioned). They do not say who opened it, that a file in it was opened, or
when it was first or last viewed.

Two roots, depending on the Windows version and the hive:

    UsrClass.dat  Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU
    NTUSER.DAT    Software\\Microsoft\\Windows\\Shell\\BagMRU
                  Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU   (older)

Each key holds one numbered value per child, and that value is a shell item.
Shell items are a family of formats, so this decodes the ones that carry a name
and, for anything else, falls back to pulling the readable strings out of the
item and says it did. A name recovered by fallback is a candidate, found by
search, and is labelled as one (`decoded: strings`, `long_name_from: strings`); a
name read from a layout is labelled `layout`, and only where the layout is one this
reader applies (a shell item extension block of version 3, 7, 8 or 9, read at the offset the
libfwsi notes give for its version and only when the block's own name offset, the 2-byte field
at 0x10, agrees). Every BagMRU root the
hive has is walked and named (a hive can hold the Shell and the ShellNoRoam trees at
once), each entry says which, and a numbered value with no key under it is listed, not
dropped. A folder in a bag is a folder some shell opened on this account; the artefact
does not say by whom, and its times are two clocks (see the note in the answer).

Two traps the output is shaped around:

- The key's last-write time is a real FILETIME set by the kernel. The shell
  item's own timestamps are **DOS date and time, in the machine's local time**,
  with two-second resolution. Do not put them in a UTC timeline without saying
  what you converted from.
- A path here means the folder was browsed, not that the folder still exists and
  not that a file in it was opened.

The whole tree is walked. The page returned inline is `limit` long, and when
more entries match the whole list is written to a file the output names. A key
below max_depth whose subkeys were not walked is named in the output, never
passed over in silence.
"""
import datetime
import json
import os
import re
import stat
import struct
import sys

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


# What the boundary is told about the fields of this tool's answers: the type of what a key holds. A key that is not listed holds free text.
FIELDS.update({
    "hive": "path", "key": "key", "root": "key", "roots_walked": "key", "roots_not_found": "key", "registry_key": "key", "deepest_found": "key", "missing": "key", "subkeys_there": "key",
    "path": "path", "name": "path", "short_name": "path", "long_name": "path", "localized_name": "path", "slot": "name", "class": "name", "type": "name", "guid": "guid",
    "all_results": "path", "all_problems": "path", "all_not_walked": "path", "all_values_without_subkey": "path",
    "key_last_written": "time", "key_last_written_filetime": "number", "extension_layout": "text",
})


FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
BEEF0004 = 0xBEEF0004
PARSER = "shellbags/4"
DEADLINE_SECONDS = 115            # the manifest allows 120
MAX_DEPTH = 128
DEFAULT_ROOTS = [
    r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    r"Software\Microsoft\Windows\Shell\BagMRU",
    r"Software\Microsoft\Windows\ShellNoRoam\BagMRU",
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
]


def fail(message, **extra):
    close_values()
    emit({"error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error); no BagMRU key was walked", **extra})
    raise SystemExit(1)


def filetime(value):
    """ISO 8601 UTC with seven fractional digits, by integer arithmetic; None for 0 or an unreadable value."""
    try:
        value = int(value)
        if value <= 0:
            return None
        whole, ticks = divmod(value, 10_000_000)
        return (FILETIME_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def dos_datetime(value):
    """FAT date and time, in the machine's own local time. Never call it UTC."""
    if not value:
        return None
    date, time = value & 0xFFFF, (value >> 16) & 0xFFFF
    year = ((date >> 9) & 0x7F) + 1980
    month, day = (date >> 5) & 0x0F, date & 0x1F
    hour, minute, second = (time >> 11) & 0x1F, (time >> 5) & 0x3F, (time & 0x1F) * 2
    if not (1 <= month <= 12 and 1 <= day <= 31 and hour < 24 and minute < 60 and second < 60):
        return None
    return "%04d-%02d-%02dT%02d:%02d:%02d (local)" % (year, month, day, hour, minute, second)


def readable(data):
    """Whatever a human would recognise in the item, when the layout is unknown."""
    wide = re.findall(rb"(?:[\x20-\x7e]\x00){3,}", data)
    if wide:
        return max((w.decode("utf-16-le", "replace") for w in wide), key=len)
    narrow = re.findall(rb"[\x20-\x7e]{4,}", data)
    return max((n.decode("ascii", "replace") for n in narrow), key=len) if narrow else ""


def wide_strings(data):
    return [w.decode("utf-16-le", "replace") for w in re.findall(rb"(?:[^\x00][\x00]){2,}", data)]


# Where the long name begins in a 0xBEEF0004 (file entry) extension block, by its version, as the libfwsi notes
# lay the block out: size (2), version (2), the signature (4), the FAT creation and access times (4 each), then
# the 2-byte field at 0x10 (the offset of the long name, which is how a block says where its name is), and the
# fields that differ by version before the NUL-terminated UTF-16LE long name: version 3 has a 2-byte long-string
# size and the name at 0x14, version 7 a file reference and the name at 0x26, version 8 four more bytes and the
# name at 0x2A, version 9 four more again and the name at 0x2E. The name is followed, from version 7 on, by the
# localised name when the item has one (`@shell32.dll,-21813`), and the block ends with the 2-byte offset of its
# own start in the item. Windows 10 writes version 9: every block of one real Windows 10 UsrClass.dat read here
# had 0x2E in the 0x10 field and its name there.
LONG_NAME_AT = {3: 0x14, 7: 0x26, 8: 0x2A, 9: 0x2E}
LOCALISED_FROM = 7


def utf16_string(block, at):
    """The NUL-terminated UTF-16LE string at `at` in `block`, with the offset after its terminator; None when it
    is not terminated inside the block."""
    end = at
    while end + 1 < len(block) and (block[end] or block[end + 1]):
        end += 2
    if end + 1 >= len(block):
        return None
    return block[at:end].decode("utf-16-le", "replace"), end + 2


def extension_block(data):
    """The beef0004 block: two more DOS timestamps, and the long name.

    The timestamps sit at fixed offsets in every version. The block is bounded by the size it declares. The long
    name is read from its documented offset only for the versions in LONG_NAME_AT, only when the block's own name
    offset (the 2-byte field at 0x10) says the same offset, and only when what is there is a printable string that
    ends inside the block. For any other version, or when a check fails, the longest wide string in the block is
    offered instead and the output says it was found by search (`long_name_from: strings`): a candidate, not a
    decode, and `extension_layout` says why the layout was not applied. A name read from a layout guessed for a
    version this reader does not know would be worse than a candidate.
    """
    at = data.find(struct.pack("<I", BEEF0004))
    if at < 4:
        return {}
    start = at - 4
    if start + 0x12 > len(data):
        return {}
    size, version = struct.unpack_from("<HH", data, start)
    created, accessed = struct.unpack_from("<II", data, start + 8)
    fits = 0x12 <= size <= len(data) - start
    block = data[start:start + size] if fits else data[start:]
    out = {"created": dos_datetime(created), "accessed": dos_datetime(accessed),
           "extension_version": version, "extension_block_size": size}
    if not fits:
        out["extension_block_size_fits"] = False
    expected = LONG_NAME_AT.get(version)
    own = struct.unpack_from("<H", block, 0x10)[0] if len(block) >= 0x12 else None
    why = None
    if expected is None:
        why = "not decoded for this version"
    elif own != expected:
        why = "not decoded: the block's own name offset (0x10) is 0x%x and this reader expects 0x%x for version %d" % (own or 0, expected, version)
    else:
        got = utf16_string(block, expected)
        if got is None or not got[0] or not got[0].isprintable():
            why = "not decoded: what sits at 0x%x is not a printable string that ends inside the block" % expected
        else:
            out["long_name"], out["long_name_from"], out["extension_layout"] = got[0], "layout", "decoded"
            if version >= LOCALISED_FROM:
                # The localised name, when the item has one, follows the long name and ends before the block's last two bytes.
                more = utf16_string(block, got[1]) if got[1] + 2 <= len(block) - 2 else None
                if more is not None and more[0] and more[0].isprintable() and more[1] <= len(block) - 2:
                    out["localized_name"] = more[0]
                    out["localized_name_from"] = "the string after the long name"
    if why is not None:
        out["extension_layout"] = why
        found = [w for w in wide_strings(block) if w.isprintable()]
        if found:
            out["long_name"] = max(found, key=len)
            out["long_name_from"] = "strings"
    return out


def decode_item(data):
    """Name what the shell item is, and say how the name was recovered."""
    if len(data) < 3:
        return {"type": "empty", "decoded": "none"}
    klass = data[2]
    item = {"class": "0x%02x" % klass}
    if klass == 0x1F:
        item["type"] = "root folder"
        if len(data) >= 20:
            # Data1-3 little-endian at 4, Data4 as stored at 12 (it was read
            # at 10, two bytes early: My Computer came out -6910-A2D808002B30).
            guid = struct.unpack_from("<IHH", data, 4) + (data[12:14].hex().upper(), data[14:20].hex().upper())
            item["guid"] = "{%08X-%04X-%04X-%s-%s}" % guid
        item["decoded"] = "layout"
        item["name"] = item.get("guid", "")
        return item
    if klass == 0x2F:
        item["type"] = "volume"
        item["name"] = data[3:data.find(b"\x00", 3) if data.find(b"\x00", 3) > 0 else len(data)].decode("ascii", "replace")
        item["decoded"] = "layout"
        return item
    if klass & 0x70 == 0x30:
        item["type"] = "directory" if klass & 0x01 else "file"
        if len(data) >= 14:
            size, modified = struct.unpack_from("<II", data, 4)
            item["file_size"] = size
            item["modified"] = dos_datetime(modified)
        end = data.find(b"\x00", 14)
        primary = data[14:end if end > 14 else len(data)].decode("latin-1", "replace")
        item.update(extension_block(data))
        item["name"] = item.get("long_name") or primary
        item["short_name"] = primary
        item["decoded"] = "layout"
        return item
    item["type"] = "unrecognised"
    item["name"] = readable(data)
    item["decoded"] = "strings"
    return item


def binary(value):
    """A REG_BINARY value as bytes. regipy hands one over as a hex string (5.x
    and 6.x alike), and this tool took only bytes: in the third CTF round no
    shell item was ever decoded, every entry said "no shell item on the
    parent" and MRUListEx gave no order."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str) and len(value) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]*", value):
        return bytes.fromhex(value)
    return None


def values_of(key, bounds, where, sink):
    """The values of a key whole, at most as many as the hive can hold: regipy's iter_values cuts a binary value to 128 bytes unless told
    not to, and a shell item is often longer. (A reader stub that does not take the argument is called without it.)"""
    try:
        return bounds.values(key, where, sink, trim_values=False)
    except TypeError:
        return bounds.values(key, where, sink)


class SealedPage(NoReplacePage):
    """A page whose rows are written through the boundary."""

    def _write(self, row):
        super()._write(row_object(row))


class BoundProblems:
    """What HiveBounds says about a list it cut or de-duplicated, as a line of the problem page."""

    def __init__(self, page):
        self.page = page

    def append(self, item):
        self.page.add({"key": item["where"], "why": item["error"]})


def mru_order(values):
    raw = values.get("MRUListEx")
    if not isinstance(raw, (bytes, bytearray)):
        return []
    order = []
    for i in range(0, len(raw) - 3, 4):
        index = struct.unpack_from("<i", raw, i)[0]
        if index < 0:
            break
        order.append(index)
    return order


def rooted_key(hive, path):
    """The key at `path`, from the hive's root. regipy's get_key takes the
    first part of a path that does not start with a backslash for the root's
    own name and drops it: "Local Settings\\...\\BagMRU" in a UsrClass.dat was
    not found, and in an NTUSER.DAT it answered Software\\...\\BagMRU under
    the name asked for. The path is rooted here, the root's name dropped when
    the caller gave it, and / taken for \\."""
    parts = [p for p in str(path).replace("/", "\\").split("\\") if p]
    if parts and parts[0].lower() == (hive.root.name or "").lower():
        parts = parts[1:]
    return hive.get_key("\\" + "\\".join(parts)) if parts else hive.root


def nearest_key(hive, path, bounds=None):
    """Where `path` stops existing: the deepest key of it the hive has, the
    part that is not there, and the names that are. A caller who guessed a
    key (a printer key one Windows version keeps and another does not, a
    control set an offline SYSTEM hive numbers) picks from these instead of
    guessing again."""
    parts = [p for p in str(path).replace("/", "\\").split("\\") if p]
    if parts and parts[0].lower() == (hive.root.name or "").lower():
        parts = parts[1:]
    bounds = bounds or HiveBounds(None, 1 << 40)
    node, found = hive.root, []
    for part in parts:
        kids = bounds.subkeys(node, "\\" + "\\".join(found), [])
        match = next((k for k in kids if k.name.lower() == part.lower()), None)
        if match is None:
            there = [k.name for k in kids]
            more = {"subkeys_there_count": len(there)} if len(there) > 200 else {}
            return {"deepest_found": "\\" + "\\".join(found), "missing": part, "subkeys_there": there[:200], **more}
        node, found = match, found + [match.name]
    return {"deepest_found": "\\" + "\\".join(found), "missing": None, "subkeys_there": []}


def safe_nearest_key(hive, path, bounds=None):
    """nearest_key, which walks a hive that may be the damaged one: a failure of its own is said, not raised."""
    try:
        return nearest_key(hive, path, bounds)
    except Exception as exc:
        return {"deepest_found": None, "missing": None, "subkeys_there": [], "nearest_key_failed": "%s: %s" % (type(exc).__name__, exc)}


def main():
    withhold_library_output()
    set_deadline(DEADLINE_SECONDS)
    install_signal_handlers(lambda signum: interrupted_answer(signum))
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("the arguments are one JSON object")

    hive_path = args.get("hive")
    if not isinstance(hive_path, str) or not hive_path:
        fail("hive is required: an extracted UsrClass.dat or NTUSER.DAT")
    try:
        hive_mode = os.stat(hive_path).st_mode
    except OSError:
        fail("no such hive", hive=hive_path)
    if not stat.S_ISREG(hive_mode):
        # A named pipe or a device would be opened and waited on: it is not read.
        fail("the hive is not a regular file, so it was not opened", hive=hive_path, not_attempted=1)

    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))
    max_depth = args.get("max_depth", 24)
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or not 1 <= max_depth <= MAX_DEPTH:
        fail("max_depth must be a whole number from 1 to %d" % MAX_DEPTH, max_depth=args.get("max_depth"))
    contains = (args.get("contains") or "").lower()
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    try:
        bind_values(write_values, "shellbags")
    except ValuesRefused as exc:
        fail(str(exc))
    OWN_NAMES.add(hive_path)

    try:
        from regipy.registry import RegistryHive
    except ImportError as exc:
        fail("regipy is not installed: python3 -m pip install regipy", reason=str(exc))

    try:
        hive = RegistryHive(hive_path)
    except Exception as exc:
        fail("regipy cannot open this hive", hive=hive_path, reason="%s: %s" % (type(exc).__name__, exc))

    bounds = HiveBounds(hive_path)
    roots = [args["key"]] if args.get("key") else DEFAULT_ROOTS
    found_roots = []
    tried = []
    for candidate in roots:
        try:
            found_roots.append((rooted_key(hive, candidate), candidate))
        except Exception as exc:
            tried.append({"key": candidate, "why": str(exc), **safe_nearest_key(hive, candidate, bounds)})
    if not found_roots:
        fail("no BagMRU root in this hive", hive=hive_path, tried=tried)

    # The names of the whole results are made from what was asked about and never from `contains`: a needle can be a secret, and a name, like
    # the answer, is not a place for it or for a digest of it (a digest is a way to confirm a guess offline). Whether a needle was given is in
    # the name; two runs with different needles get the next free name, and a result file is never replaced.
    key = [hive_path, [r[1] for r in found_roots], bool(contains), max_depth]
    entries = SealedPage("shellbags", key, limit)
    problems = SealedPage("shellbags-problems", key, 40)
    bound_problems = BoundProblems(problems)
    stopped = SealedPage("shellbags-not-walked", key, 40)
    orphans = SealedPage("shellbags-orphan-values", key, 40)
    counts = {"strings": 0, "orphans": 0, "other_values": 0, "walked": 0, "unread_for_time": 0}

    def item_entry(raw, slot_name, key_path, parent_path, depth, order, root_path, header=None, orphan=False):
        try:
            item = decode_item(bytes(raw)) if isinstance(raw, (bytes, bytearray)) else \
                {"type": "no shell item on the parent", "name": slot_name, "decoded": "none"}
        except Exception as exc:                              # a shell item that defeats the reader is listed as such
            item = {"type": "undecodable", "name": "", "decoded": "none", "error": "%s: %s" % (type(exc).__name__, exc)}
            problems.add({"key": key_path + "\\" + slot_name, "why": "the shell item could not be decoded: %s: %s" % (type(exc).__name__, exc)})
        name = item.get("name") or ""
        path = (parent_path + "\\" + name).strip("\\") if name else parent_path
        entry = {
            "root": root_path,
            "path": path,
            "name": name,
            "registry_key": key_path + "\\" + slot_name,
            "slot": slot_name,
            "depth": depth,
            "mru_position": order.index(int(slot_name)) if slot_name.isdigit() and int(slot_name) in order else None,
            "item": item,
        }
        if isinstance(raw, (bytes, bytearray)):
            entry["item_bytes"] = len(raw)
        if orphan:
            entry["no_subkey"] = True
        if header is not None:
            entry["key_last_written"] = filetime(header.last_modified)
            entry["key_last_written_filetime"] = str(header.last_modified)
        return entry, path

    visited = set()

    def walk(key, key_path, parent_path, depth, root_path):
        counts["walked"] += 1
        # A key whose subkey list was already reached is a cycle (or a list two keys share): it is said, not walked again.
        lid = getattr(getattr(key, "header", None), "subkeys_list_offset", None)
        if lid is not None and getattr(key, "subkey_count", 0):
            if lid in visited:
                problems.add({"key": key_path, "why": "its subkey list (offset %s) was already walked: a cycle, or a list two keys share; not walked again" % lid})
                return
            visited.add(lid)
        if out_of_time():
            counts["unread_for_time"] += 1
            stopped.add({"key": key_path, "depth": depth, "reason": "the tool's own time limit (%d seconds) was reached" % DEADLINE_SECONDS})
            return
        if depth > max_depth:
            # Name the key where the walk stopped, and how much lies under it.
            try:
                below = len(bounds.subkeys(key, key_path, bound_problems))
            except Exception as exc:
                problems.add({"key": key_path, "why": "subkeys unreadable: %s" % exc})
                return
            if below:
                stopped.add({"key": key_path, "depth": depth, "subkeys": below})
            return
        values = {}
        try:
            for value in values_of(key, bounds, key_path, bound_problems):
                raw = binary(value.value)
                values[value.name] = raw if raw is not None else value.value
        except Exception as exc:
            problems.add({"key": key_path, "why": "values unreadable: %s" % exc})
        order = mru_order(values)
        try:
            subkeys = bounds.subkeys(key, key_path, bound_problems)
        except Exception as exc:
            problems.add({"key": key_path, "why": "subkeys unreadable: %s" % exc})
            return
        names = {s.name for s in subkeys}
        for sub in subkeys:
            entry, path = item_entry(values.get(sub.name), sub.name, key_path, parent_path, depth, order, root_path, getattr(sub, "header", None))
            if not contains or contains in show(path, "path", "path").lower():
                entries.add(entry)
                if entry["item"].get("decoded") == "strings":
                    counts["strings"] += 1
            walk(sub, key_path + "\\" + sub.name, path, depth + 1, root_path)
        # A numbered value with no key under it is a shell item with no bag of its own: decoded and listed, not dropped.
        for vname, raw in values.items():
            if vname in names:
                continue
            if vname.isdigit():
                entry, path = item_entry(raw, vname, key_path, parent_path, depth, order, root_path, orphan=True)
                counts["orphans"] += 1
                orphans.add(entry)
                if not contains or contains in show(path, "path", "path").lower():
                    entries.add(entry)
                    if entry["item"].get("decoded") == "strings":
                        counts["strings"] += 1
            else:
                counts["other_values"] += 1

    for root_key, root_path in found_roots:
        walk(root_key, root_path, "", 1, root_path)

    if LibraryLog.messages:
        problems.add({"key": None, "why": "regipy logged %d message(s) (%d of them errors) while reading; its text can hold bytes of a value or a name and is not shown" % (LibraryLog.messages, LibraryLog.errors)})
    page = entries.finish()
    problem_page = problems.finish()
    stopped_page = stopped.finish()
    orphan_page = orphans.finish()
    reasons = []
    if problem_page["matched"]:
        reasons.append("%d problem(s) are named under problems" % problem_page["matched"])
    if stopped_page["matched"]:
        reasons.append("%d key(s) were not walked (not_walked_below_max_depth)" % stopped_page["matched"])
    out = {
        "parser": PARSER,
        "status": "partial" if reasons else "complete",
        "status_basis": "; ".join(reasons) if reasons else "every BagMRU key reached was walked to its end: no problem is named and no key was left unwalked",
        "walk_stopped_by_time_limit": counts["unread_for_time"] > 0,
        "library_messages_withheld": LibraryLog.messages,
        "hive": hive_path,
        "root": found_roots[0][1],
        "roots_walked": [r[1] for r in found_roots],
        "roots_not_found": [t["key"] for t in tried],
        "keys_walked": counts["walked"],
        "entries": entries.page,
        "entry_count": page["matched"],
        "recovered_by_strings": counts["strings"],
        **page,
        "not_walked_below_max_depth": stopped.page,
        "not_walked_count": stopped_page["matched"],
        "values_without_subkey": orphans.page,
        "values_without_subkey_count": orphan_page["matched"],
        "other_values_ignored": counts["other_values"],
        "problems": problems.page,
        "problem_count": problem_page["matched"],
        "note": "key_last_written is a kernel FILETIME in UTC. The item's own created, "
                "modified and accessed values are DOS timestamps in the machine's local "
                "time, to two seconds; convert them with the timezone from "
                "SYSTEM\\ControlSet00n\\Control\\TimeZoneInformation and say so. A name from "
                "`decoded: strings` or `long_name_from: strings` is a candidate found by search, not a decode.",
    }
    if problem_page.get("all_results"):
        out["all_problems"] = problem_page["all_results"]
    if stopped_page.get("all_results"):
        out["all_not_walked"] = stopped_page["all_results"]
    if orphan_page.get("all_results"):
        out["all_values_without_subkey"] = orphan_page["all_results"]
    emit(out, indent=2)
    close_values()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        emit({"error": "the read failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error", "reason": "%s: %s" % (type(exc).__name__, exc)})
        sys.exit(1)

#!/usr/bin/env python3
"""Query an EVTX event log: filter its records and return them with named data fields.

What a run reports, separately: `records_examined` (every record the reader produced), `events_matched`
(records that parsed and passed every filter), `parse_errors` (records or chunk chains that could not be
read, each with its offset). An error row is never counted as a match, and an event log that could not be
read to its end says status: partial. Every matched event, with its whole XML, is kept in the result file
(JSON Lines) the answer names; the inline `events` is a page of `limit` of them.

Every row carries where it came from: `record_offset` (the byte offset of the record in the file),
`chunk_offset`, the EventRecordID, and `record_filetime` (the FILETIME in the record's header, as a decimal
string, with `record_time_utc` from it by integer arithmetic) beside `timestamp`, the SystemTime the XML
carries. The filters are `event_ids`, `contains` (a case-insensitive substring of the XML), the EventRecordID
range `start_record` to `end_record`, and `start_time` to `end_time`. A time is `YYYY-MM-DD`, then optionally
`THH`, `THH:MM`, `THH:MM:SS` or `THH:MM:SS.fffffff`, and from the hour on optionally `Z` or a numeric offset such as
`+03:00`; no zone means UTC. What it names is the span its precision gives (`2026-09-01` the whole day,
`2026-09-01T10:00` that minute): start_time is the beginning of its span, end_time the end of its. Each bound is
converted to UTC and compared with the SystemTime of the record as a number of 100 ns ticks, not as text. A word
(`yesterday`), a malformed time or a range that ends before it starts is refused, never answered with an empty list.
A record whose XML has no SystemTime cannot be placed in a time range: it is left out and counted under
`events_without_time_excluded`, and the run is partial.

The whole of the log is accounted for: `chunks_declared` (what the file header says the file holds),
`chunks_read` (what the reader gave), `bytes_expected` and `file_bytes`. A file shorter than its header says, or a
reader that gave fewer chunks than the header declares, is status partial with a problem naming both numbers: a log
cut short is not a log with no records.

The file is read to its end, not to the header's count: `chunks_in_file` is what the file holds, and a chunk past the declared count that
has an ElfChnk signature and passes the chunk-header checks is read (`chunk_beyond_declared: true` on its rows; `header_flags` and
`header_dirty` say whether the log was open and changed). A chunk whose string or template table loops or points outside the chunk is
not given to python-evtx, which follows those tables without end; the library is called under a timer per chunk, the run has a clock of
its own below the manifest's, and a stop signal ends it with a partial file that is named as one.

The XML is rendered by python-evtx; a record whose template it cannot expand is an error row, not a skip.
Event data can hold command lines and text typed into a command line, which can hold a secret: run it as a
job with secret_output: true when the log may.
"""
import datetime
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

PARSER = "evtx_query/4"
CHUNK_BYTES = 0x10000
DEADLINE_SECONDS = 57             # the manifest allows 60
FILE_MAGIC = b"ElfFile\x00"


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


# BEGIN SHARED EVTX READ
# The same text is in evtx_query and evtx_carve (a windows-forensics test holds the copies equal). python-evtx follows a chunk's string and
# template tables without a bound: a table entry whose next pointer names itself never ends, and nothing in the library has a clock. So a
# chunk is checked before the library is given it (chain_problem), whatever else it holds is read under a timer of its own (chunk_guard,
# which raises ChunkTimeout inside the library and gives the chunk up), and the whole run has a clock below the manifest's (out_of_time).
# SIGTERM, SIGINT and SIGHUP are cooperative: inside the library they unwind it (Interrupted), elsewhere they are noted and the next
# check_stop() raises, so that a result file is closed between two rows and never in the middle of one.
import signal
import struct
import time

CHUNK_MAGIC = b"ElfChnk\x00"
CHUNK_SIZE = 65536
HEADER_BYTES = 0x80
CHUNK_SECONDS = 8
CLOCK = {"deadline": None}
STOP = {"signal": None, "in_library": False}


class ChunkTimeout(BaseException):
    """A chunk took longer than CHUNK_SECONDS to read. BaseException: a library that catches Exception does not swallow it."""


class Interrupted(BaseException):
    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


def set_deadline(seconds):
    CLOCK["deadline"] = time.monotonic() + seconds


def out_of_time():
    return CLOCK["deadline"] is not None and time.monotonic() > CLOCK["deadline"]


def _on_alarm(signum, _frame):
    raise ChunkTimeout()


def _on_signal(signum, _frame):
    if STOP["in_library"]:
        raise Interrupted(signum)
    STOP["signal"] = signum


def install_signal_handlers():
    signal.signal(signal.SIGALRM, _on_alarm)
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


def check_stop():
    if STOP["signal"] is not None:
        raise Interrupted(STOP["signal"])


class chunk_guard:
    """`with chunk_guard():` the library is called under a CHUNK_SECONDS timer (and never longer than the run's clock has left); a stop
    signal unwinds it. Not for code that writes a result: that runs outside it."""

    def __enter__(self):
        left = CLOCK["deadline"] - time.monotonic() if CLOCK["deadline"] is not None else CHUNK_SECONDS
        check_stop()
        STOP["in_library"] = True
        signal.setitimer(signal.ITIMER_REAL, max(0.05, min(CHUNK_SECONDS, left)))
        return self

    def __exit__(self, *exc):
        signal.setitimer(signal.ITIMER_REAL, 0)
        STOP["in_library"] = False
        return False


def reject_signature(head):
    """Why the 128 bytes after an ElfChnk signature are not a chunk header, or None when they could be one. The layout is the format's (the
    libevtx notes on the EVTX chunk header): the first and last record numbers at 0x08 and 0x10, the header size (0x80) at 0x28, the offset
    of the last record at 0x2C and of the free space at 0x30, each inside the 64 KiB chunk. python-evtx's ChunkHeader reads whatever it is
    given without complaint, so this check is the tool's own."""
    if len(head) < HEADER_BYTES:
        return "the file ends %d bytes after the signature and a chunk header is %d bytes" % (len(head), HEADER_BYTES)
    first, last = struct.unpack_from("<QQ", head, 0x08)
    header_size, last_offset, next_offset = struct.unpack_from("<III", head, 0x28)
    if header_size != HEADER_BYTES:
        return "its header size is %d, not %d" % (header_size, HEADER_BYTES)
    if last_offset > CHUNK_SIZE or next_offset > CHUNK_SIZE:
        return ("its record offsets (last %d, free space %d) lie outside a %d-byte chunk"
                % (last_offset, next_offset, CHUNK_SIZE))
    if next_offset > 0x200 and first > last:
        return "its first record number %d is after its last, %d" % (first, last)
    return None


def chain_problem(raw):
    """Why `raw` (one chunk) must not be handed to python-evtx, or None. It mirrors ChunkHeader._load_strings and _load_templates, which
    follow 64 string chains and 32 template chains until a next pointer of 0: a pointer that names an offset already seen is a loop, one
    outside the chunk is a read past it."""
    if len(raw) < 0x200:
        return "the chunk is shorter than its 0x200-byte header area"
    for count, base, label in ((64, 0x80, "string"), (32, 0x180, "template")):
        for i in range(count):
            ofs = struct.unpack_from("<I", raw, base + 4 * i)[0]
            seen = set()
            while ofs > 0:
                if ofs in seen:
                    return "%s table entry %d loops back to offset 0x%x" % (label, i, ofs)
                seen.add(ofs)
                if label == "string":
                    if ofs + 8 > len(raw):
                        return "%s table entry %d points outside the chunk (0x%x)" % (label, i, ofs)
                    ofs = struct.unpack_from("<I", raw, ofs)[0]
                else:
                    if ofs < 10 or ofs + 4 > len(raw):
                        return "%s table entry %d points outside the chunk (0x%x)" % (label, i, ofs)
                    if raw[ofs - 10] != 0x0C or struct.unpack_from("<I", raw, ofs - 4)[0] != ofs:
                        break                       # python-evtx stops here itself (it logs "Unexpected token")
                    ofs = struct.unpack_from("<I", raw, ofs)[0]
                if len(seen) > 100000:
                    return "%s table entry %d chain longer than any chunk can hold" % (label, i)
    return None
# END SHARED EVTX READ


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

IP_FIELDS = frozenset(("ipaddress", "sourceip", "destinationip", "sourceaddress", "destaddress", "destinationaddress", "clientaddress", "sourcenetworkaddress", "workstationip"))
PATH_FIELDS = frozenset(("image", "parentimage", "targetfilename", "imageloaded", "processname", "newprocessname", "parentprocessname", "currentdirectory", "destination",
                         "sourceimage", "targetimage", "path", "filename", "servicefilename", "imagepath", "applicationpath", "configuration", "pipename", "file"))
DIGEST_FIELDS = frozenset(("md5", "sha1", "sha256", "imphash", "filehash", "hash"))


def data_kind(name):
    """The type the boundary judges an EventData value by, from the name of its field; other fields hold free text."""
    low = str(name).lower()
    if "sid" in low and low not in ("sidhistory",):
        return "sid"
    if "guid" in low:
        return "guid"
    if low in DIGEST_FIELDS:
        return "digest"
    if low in IP_FIELDS:
        return "ip"
    if low in ("utctime", "creationutctime", "previouscreationutctime", "timecreated"):
        return "time"
    if low == "targetobject":
        return "key"
    if low in PATH_FIELDS:
        return "path"
    return "text"



FIELDS.update({
    "path": "path", "result_file": "path", "result_file_requested": "path", "partial_result_file": "path", "all_results": "path", "all_problems": "path", "all_channels": "path",
    "channel": "name", "channels": "name", "computer": "host", "provider": "name", "timestamp": "time", "time_created": "time", "record_time_utc": "time", "from": "time", "until_exclusive": "time",
    "record_filetime": "number", "data": data_kind, "user_data": data_kind,
})

NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
FILETIME_EPOCH_SECONDS = 11644473600


def fail(message, **extra):
    close_values()
    emit({'error': message, 'status': 'failed', 'status_basis': 'the tool stopped with an error (see error); no record was examined', **extra})
    raise SystemExit(1)


def whole(args, name, default, low=None):
    v = args.get(name, default)
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int) or (low is not None and v < low):
        fail('%s must be a whole number%s' % (name, ' of at least %d' % low if low is not None else ''), **{name: args.get(name)})
    return v


def filetime_iso(ft):
    """ISO 8601 UTC with seven fractional digits, by integer arithmetic; None for 0 or an unrepresentable date."""
    import datetime
    if not ft:
        return None
    try:
        whole_s, ticks = divmod(ft, 10_000_000)
        base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=whole_s)
        return base.strftime('%Y-%m-%dT%H:%M:%S') + '.%07dZ' % ticks
    except (OverflowError, ValueError):
        return None


TIME_ARG = re.compile(
    r'^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2})(?::(\d{2})(?::(\d{2})(?:\.(\d{1,7}))?)?)?(Z|[+-]\d{2}:\d{2})?)?$')
SYSTEM_TIME = re.compile(r'^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:Z|\+00:00)?$')
EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
TICKS = 10_000_000


def ticks_of(year, month, day, hour, minute, second):
    moment = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
    return (moment - EPOCH) // datetime.timedelta(seconds=1) * TICKS


def time_window(text, name):
    """The span of UTC time (in 100 ns ticks since 1970, [low, high)) an ISO 8601 time argument names: a date is
    its whole day, an hour its hour, down to the number of fractional digits given. No zone is UTC; `Z` and a numeric
    offset are applied. Anything else is refused."""
    m = TIME_ARG.match(text.strip())
    if not m:
        fail('%s is not an ISO 8601 UTC time: use YYYY-MM-DD, optionally with THH, THH:MM, THH:MM:SS or THH:MM:SS.fffffff '
             'and, from the hour on, Z or an offset such as +03:00' % name, **{name: text})
    year, month, day, hour, minute, second, fraction, zone = m.groups()
    try:
        low = ticks_of(int(year), int(month), int(day), int(hour or 0), int(minute or 0), int(second or 0))
    except ValueError as exc:
        fail('%s is not a real date or time: %s' % (name, exc), **{name: text})
    if fraction is not None:
        digits = len(fraction)
        low += int(fraction) * 10 ** (7 - digits)
        unit = 10 ** (7 - digits)
    elif second is not None:
        unit = TICKS
    elif minute is not None:
        unit = 60 * TICKS
    elif hour is not None:
        unit = 3600 * TICKS
    else:
        unit = 86400 * TICKS
    if zone and zone != 'Z':
        sign = 1 if zone[0] == '+' else -1
        offset_hours, offset_minutes = int(zone[1:3]), int(zone[4:6])
        if offset_hours > 23 or offset_minutes > 59:
            fail('%s has an offset that is not a real zone' % name, **{name: text})
        low -= sign * (offset_hours * 3600 + offset_minutes * 60) * TICKS
    return low, low + unit


def system_ticks(text):
    """The SystemTime attribute of a record as ticks since 1970 UTC (python-evtx writes it with a space and six digits,
    and no zone); None when it is absent or not a time."""
    m = SYSTEM_TIME.match((text or '').strip())
    if not m:
        return None
    year, month, day, hour, minute, second, fraction = m.groups()
    try:
        base = ticks_of(int(year), int(month), int(day), int(hour), int(minute), int(second))
    except ValueError:
        return None
    return base + int((fraction or '0')[:7].ljust(7, '0'))


def dumps_row(row):
    """One JSON line, whole; a lone surrogate (text that was not UTF-8) is escaped, not lost."""
    text = json.dumps(row, ensure_ascii=False)
    try:
        text.encode('utf-8')
    except UnicodeEncodeError:
        text = json.dumps(row, ensure_ascii=True)
    return text


class ResultWriteError(Exception):
    """The whole result could not be written: not a record that failed to parse."""


def main():
    set_deadline(DEADLINE_SECONDS)
    install_signal_handlers()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail('arguments are not valid JSON', reason=str(exc))
    if not isinstance(args, dict):
        fail('the arguments must be a JSON object')
    path = args.get('path')
    if not isinstance(path, str) or not path:
        fail('path is required: the EVTX file')
    try:
        mode = os.stat(path).st_mode
    except (OSError, ValueError):
        fail('no such file', path=path)
    if not stat.S_ISREG(mode):
        # A named pipe or a device would be opened and waited on: it is not read.
        fail('the path is not a regular file, so it was not opened', path=path, not_attempted=1)
    raw_ids = args.get('event_ids') or []
    if not isinstance(raw_ids, list) or any(isinstance(i, bool) or not isinstance(i, int) for i in raw_ids):
        fail('event_ids must be a list of whole numbers', event_ids=args.get('event_ids'))
    event_ids = set(raw_ids)
    contains = args.get('contains')
    if contains is not None and not isinstance(contains, str):
        fail('contains must be a string', contains=contains)
    contains_l = contains.lower() if contains else None
    write_values = args.get('write_values', False)
    if not isinstance(write_values, bool):
        fail('write_values must be true or false')
    try:
        bind_values(write_values, 'evtx_query')
    except ValuesRefused as exc:
        fail(str(exc))
    OWN_NAMES.add(path)
    limit = whole(args, 'limit', 200, 1)
    start_record = whole(args, 'start_record', None, 0)
    end_record = whole(args, 'end_record', None, 0)
    if start_record is not None and end_record is not None and start_record > end_record:
        fail('start_record is after end_record: the range is empty', start_record=start_record, end_record=end_record)
    start_time, end_time = args.get('start_time'), args.get('end_time')
    for name, v in (('start_time', start_time), ('end_time', end_time)):
        if v is not None and not isinstance(v, str):
            fail('%s must be an ISO 8601 UTC string' % name, **{name: v})
    time_low = time_high = None
    if start_time is not None:
        time_low = time_window(start_time, 'start_time')[0]
    if end_time is not None:
        time_high = time_window(end_time, 'end_time')[1]
    if time_low is not None and time_high is not None and time_low >= time_high:
        fail('start_time is after end_time: the range is empty', start_time=start_time, end_time=end_time)

    root_dir = Path.cwd().resolve()
    # The name of the whole result is made from the arguments that say where and what was asked, and never from `contains`:
    # a needle can be a secret, and a name, like the answer, is not a place for it or for a digest of it.
    named = {k: v for k, v in args.items() if k not in ('contains', 'out_file')}
    named['contains'] = bool(contains)
    default_name = 'evtx-query-' + hashlib.sha256(json.dumps(named, sort_keys=True).encode()).hexdigest()[:16] + '.jsonl'
    in_job = bool(os.environ.get('JOB_ID') and os.environ.get('OUT'))
    # The whole result: in a job, under $OUT (sealed as the job's output); in an
    # agent's VM, under its own work/<id>/, the only part of work/ it can write.
    if in_job:
        default_path = os.path.join(os.environ['OUT'], default_name)
    else:
        default_path = 'work/%s/tool-output/%s' % (re.sub(r'[^A-Za-z0-9_.-]', '_', os.environ.get('AGENT_ID') or 'tool'), default_name)
    out_file = args.get('out_file')
    if out_file is not None and (not isinstance(out_file, str) or not out_file):
        fail('out_file must be a path', out_file=out_file)
    # The directory is resolved (a link in it is followed to where it lands, and judged there); the name is not: a link
    # left at the name itself is never written through, the placement below refuses it.
    try:
        wanted = Path(os.path.normpath(root_dir / Path(out_file or default_path)))
        result_path = wanted.parent.resolve() / wanted.name
        os.fsencode(str(result_path))
    except (UnicodeEncodeError, ValueError, OSError):
        fail('out_file is not a path this tool can create (it holds bytes that are not text)', status='failed')
    allowed = [root_dir]
    if in_job:
        allowed.append(Path(os.environ['OUT']).resolve())
    if not any(result_path != base and base in result_path.parents for base in allowed):
        fail('out_file must stay inside the run directory' + (' or $OUT' if in_job else ''), out_file=out_file)
    inputs = root_dir / 'inputs'
    if result_path == inputs or inputs in result_path.parents:
        fail('out_file cannot be under inputs/')

    try:
        from Evtx.Evtx import Evtx
    except ImportError as exc:
        fail('python-evtx is not installed', hint='python3 -m pip install python-evtx', reason=str(exc))
    try:
        with open(path, 'rb') as fh:
            magic = fh.read(len(FILE_MAGIC))
    except OSError as exc:
        fail('the file could not be read', path=path, reason='%s: %s' % (type(exc).__name__, exc.strerror or exc))
    if magic != FILE_MAGIC:
        fail('not an EVTX file: it does not begin with ElfFile', path=path, begins_with=magic.hex())
    try:
        evtx = Evtx(path)
        evtx.__enter__()
    except Exception as exc:
        fail('could not open the event log', path=path, reason='%s: %s' % (type(exc).__name__, exc))

    def close_evtx():
        try:
            evtx.__exit__(None, None, None)
        except Exception:
            pass

    def shown_result(p):
        """Where a reader finds the whole result: a job's $OUT is sealed as
        store/jobs/<id>/out/, the path to cite; otherwise the run-relative path."""
        out = os.environ.get('OUT')
        if os.environ.get('JOB_ID') and out and Path(out).resolve() in p.parents:
            return 'store/jobs/%s/out/%s' % (re.sub(r'[^A-Za-z0-9_.-]', '_', os.environ['JOB_ID']), p.relative_to(Path(out).resolve()))
        return os.path.relpath(p, root_dir)

    # What the file header says the log holds, to set against what the file holds and what the reader gave.
    problems = []
    declared = {'chunks_declared': None, 'bytes_expected': None, 'next_record_number': None, 'flags': None}
    file_bytes = os.path.getsize(path)
    header_bytes = 0x1000
    header = None
    try:
        header = evtx.get_file_header()
        header_bytes = int(header.header_chunk_size())
        declared['chunks_declared'] = int(header.chunk_count())
        declared['next_record_number'] = int(header.next_record_number())
        declared['flags'] = int(header.flags())
        declared['bytes_expected'] = header_bytes + declared['chunks_declared'] * CHUNK_BYTES
        if file_bytes < declared['bytes_expected']:
            problems.append('the file is %d bytes and its header declares %d chunks, which take %d: the log is cut short'
                            % (file_bytes, declared['chunks_declared'], declared['bytes_expected']))
    except Exception as exc:
        problems.append('the file header could not be read, so what the log should hold is not known: %s' % exc)

    # The whole result is written to a private temporary file beside its place and put there at the end, under a name that is free:
    # a run that is stopped leaves a file that says it is partial, never one under the name of a result.
    try:
        result_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=result_path.parent, prefix='.%s-' % result_path.name)
        full = os.fdopen(fd, 'w', encoding='utf-8')
        tmp_path = Path(tmp_name)
    except OSError as exc:
        close_evtx()
        fail('the whole result cannot be written to %s: %s. Outside a job the place is your own work/<your id>/ directory; '
             'in a job it is $OUT.' % (os.path.relpath(result_path, root_dir), exc), status='failed')

    def write_row(row):
        try:
            full.write(dumps_row(row_object(row)) + '\n')
        except OSError as exc:
            raise ResultWriteError(str(exc))

    events, errors = [], []
    counts = {'examined': 0, 'matched': 0, 'parse_errors': 0, 'without_time': 0, 'chunks_read': 0, 'beyond_read': 0, 'beyond_rejected': 0,
              'slots_empty_beyond': 0, 'declared_unreadable': 0, 'tables_refused': 0, 'timed_out': 0}
    highest_record = None
    stopped = {'time': None, 'signal': None}
    chunk_report = []                      # [offset, why] of every chunk not read, whole in the result file as a parse_error row

    def error_row(row):
        write_row(row)
        counts['parse_errors'] += 1
        if len(errors) < limit:
            errors.append(row)

    def read_chunk(chunk):
        """The records of one chunk as [(kind, record_offset, xml, filetime, message)], read under the chunk's timer. kind is 'record' (xml
        is there), 'record_error' (the library could not render that record), 'chain' (the chain of records broke: nothing after it in
        the chunk) or 'timeout' (the chunk went past its timer and was given up)."""
        items = []
        try:
            with chunk_guard():
                for rec in chunk.records():
                    offset = xml = ft = None
                    try:
                        offset = rec.offset()
                        xml = rec.xml()
                        try:
                            ft = rec.unpack_qword(0x10)
                        except Exception:
                            ft = None
                        items.append(('record', offset, xml, ft, None))
                    except Exception as e:
                        items.append(('record_error', offset, xml, ft, str(e)))
        except ChunkTimeout:
            counts['timed_out'] += 1
            items.append(('timeout', None, None, None, None))
        except Exception as e:
            items.append(('chain', None, None, None, 'the record chain of this chunk broke: %s' % e))
        return items

    def handle(offset, xml, record_filetime, chunk_offset, beyond):
        nonlocal highest_record
        counts['examined'] += 1
        root = ET.fromstring(xml)
        sysnode = root.find('e:System', NS)
        eid_text = sysnode.findtext('e:EventID', default='', namespaces=NS) if sysnode is not None else ''
        try:
            eid = int(eid_text)
        except Exception:
            eid = None
        recid_text = sysnode.findtext('e:EventRecordID', default='', namespaces=NS) if sysnode is not None else ''
        try:
            recid = int(recid_text)
        except Exception:
            recid = None
        time_created = ''
        if sysnode is not None:
            t = sysnode.find('e:TimeCreated', NS)
            if t is not None:
                time_created = t.attrib.get('SystemTime', '')
        if recid is not None and (highest_record is None or recid > highest_record):
            highest_record = recid
        if start_record is not None and (recid is None or recid < start_record):
            return
        if end_record is not None and (recid is None or recid > end_record):
            return
        if event_ids and eid not in event_ids:
            return
        if time_low is not None or time_high is not None:
            placed = system_ticks(time_created)
            if placed is None:
                counts['without_time'] += 1
                return
            if (time_low is not None and placed < time_low) or (time_high is not None and placed >= time_high):
                return
        if contains_l and contains_l not in show(xml, 'text', 'xml').lower():     # the needle is looked for in what is shown, never in what is withheld
            return
        channel = sysnode.findtext('e:Channel', default='', namespaces=NS) if sysnode is not None else ''
        computer = sysnode.findtext('e:Computer', default='', namespaces=NS) if sysnode is not None else ''
        provider = ''
        if sysnode is not None:
            p = sysnode.find('e:Provider', NS)
            if p is not None:
                provider = p.attrib.get('Name', '')
        eventdata = {}
        for section in ('EventData', 'UserData'):
            sec = root.find('e:%s' % section, NS)
            if sec is not None:
                for elem in sec.iter():
                    if elem is sec:
                        continue
                    tag = elem.tag.rsplit('}', 1)[-1]
                    text = (elem.text or '').strip()
                    if not text:
                        continue
                    name = elem.attrib.get('Name') or tag
                    if name in eventdata:
                        if isinstance(eventdata[name], list):
                            eventdata[name].append(text)
                        else:
                            eventdata[name] = [eventdata[name], text]
                    else:
                        eventdata[name] = text
        entry = {
            'timestamp': time_created,
            'record_filetime': str(record_filetime) if record_filetime is not None else None,
            'record_time_utc': filetime_iso(record_filetime) if record_filetime is not None else None,
            'event_id': eid,
            'channel': channel,
            'computer': computer,
            'provider': provider,
            'record_id': recid,
            'record_offset': offset,
            'chunk_offset': chunk_offset,
            'chunk_beyond_declared': beyond,
            'data': eventdata,
            'xml': xml,
        }
        write_row(entry)
        counts['matched'] += 1
        if len(events) < limit:
            events.append({k: v for k, v in entry.items() if k != 'xml'})

    declared_n = declared['chunks_declared']
    slot_index = [-1]
    try:
        try:
            with open(path, 'rb') as raw_fh:
                slots = (file_bytes - header_bytes) // CHUNK_BYTES if file_bytes > header_bytes else 0
                trailing = (file_bytes - header_bytes) - slots * CHUNK_BYTES if file_bytes > header_bytes else 0
                chunk_iter = iter(header.chunks(include_inactive=True)) if header is not None else iter(())
                index = -1
                while True:
                    check_stop()
                    if out_of_time():
                        stopped['time'] = 'the tool\'s own time limit (%d seconds) was reached after chunk %d of %d' % (DEADLINE_SECONDS, index + 1, slots)
                        break
                    try:
                        with chunk_guard():
                            chunk = next(chunk_iter)
                    except StopIteration:
                        break
                    except ChunkTimeout:
                        break
                    except Exception as e:
                        last = header_bytes + index * CHUNK_BYTES if index >= 0 else None
                        problems.append('the chunks of the log could not be enumerated past offset %s: %s' % (last, e))
                        error_row({'parse_error': 'the chunk enumeration failed after offset %s: %s' % (last, e), 'chunk_offset': last, 'enumeration_failed': True})
                        break
                    index += 1
                    slot_index[0] = index
                    chunk_offset = header_bytes + index * CHUNK_BYTES
                    raw_fh.seek(chunk_offset)
                    raw = raw_fh.read(CHUNK_BYTES)
                    beyond = declared_n is not None and index >= declared_n
                    has_magic = raw[:len(CHUNK_MAGIC)] == CHUNK_MAGIC
                    if not has_magic:
                        if beyond:
                            counts['slots_empty_beyond'] += 1
                        else:
                            counts['declared_unreadable'] += 1
                            chunk_report.append([chunk_offset, 'no ElfChnk signature'])
                            error_row({'parse_error': 'the chunk the file header declares at this offset has no ElfChnk signature and was not read', 'chunk_offset': chunk_offset})
                        continue
                    refusal = reject_signature(raw[:HEADER_BYTES]) if beyond else None
                    if refusal is not None:
                        counts['beyond_rejected'] += 1
                        chunk_report.append([chunk_offset, refusal])
                        error_row({'parse_error': 'past the chunks the file header declares, an ElfChnk signature that is not a chunk: %s' % refusal, 'chunk_offset': chunk_offset})
                        continue
                    loop = chain_problem(raw)
                    if loop is not None:
                        counts['tables_refused'] += 1
                        chunk_report.append([chunk_offset, loop])
                        error_row({'parse_error': 'the chunk was not read: its %s' % loop, 'chunk_offset': chunk_offset})
                        continue
                    counts['chunks_read'] += 1
                    if beyond:
                        counts['beyond_read'] += 1
                    for kind, offset, xml, ft, err in read_chunk(chunk):
                        check_stop()
                        if kind == 'timeout':
                            chunk_report.append([chunk_offset, 'the chunk took more than %d seconds to read' % CHUNK_SECONDS])
                            error_row({'parse_error': 'the chunk took more than %d seconds to read; the records after this point in it were not read' % CHUNK_SECONDS, 'chunk_offset': chunk_offset})
                        elif kind == 'chain':
                            error_row({'parse_error': err, 'chunk_offset': chunk_offset})
                        elif kind == 'record_error':
                            counts['examined'] += 1
                            error_row({'parse_error': err, 'record_offset': offset, 'chunk_offset': chunk_offset, 'xml': xml})
                        else:
                            try:
                                handle(offset, xml, ft, chunk_offset, beyond)
                            except ResultWriteError:
                                raise
                            except Exception as e:
                                error_row({'parse_error': str(e), 'record_offset': offset, 'chunk_offset': chunk_offset, 'xml': xml})
                if trailing and file_bytes > header_bytes:
                    raw_fh.seek(header_bytes + slots * CHUNK_BYTES)
                    if raw_fh.read(len(CHUNK_MAGIC)) == CHUNK_MAGIC:
                        problems.append('the file ends %d bytes into a chunk (a chunk is %d): the records in that part are not read here (evtx_carve reads a chunk cut by the end of the file)' % (trailing, CHUNK_BYTES))
        except Interrupted as stop:
            stopped['signal'] = stop.signum
        full.flush()
        os.fsync(full.fileno())
        full.close()
    except ResultWriteError as exc:
        close_evtx()
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        fail('the whole result could not be written to %s after %d records: %s. Outside a job the place is your own '
             'work/<your id>/ directory; in a job it is $OUT.' % (os.path.relpath(result_path, root_dir), counts['examined'], exc),
             status='failed', records_examined=counts['examined'], events_matched=counts['matched'])
    finally:
        close_evtx()
    if stopped['signal'] is not None:
        # The file is closed between two rows; it is kept beside its place as a partial result and named, never as a result.
        keep = result_path.with_name('%s.partial%s' % (result_path.stem, result_path.suffix))
        partial = tmp_path
        for n in range(1, 1000):
            candidate = keep if n == 1 else keep.with_name('%s-%d%s' % (keep.stem, n, keep.suffix))
            try:
                os.link(tmp_path, candidate)
                os.unlink(tmp_path)
                partial = candidate
                break
            except FileExistsError:
                continue
            except OSError:
                break
        emit({'error': 'stopped by signal %d before the whole log was read' % stopped['signal'], 'status': 'interrupted',
                         'status_basis': 'the tool was stopped by signal %d; the records examined so far are in a partial file, which is not a result' % stopped['signal'],
                         'signal': stopped['signal'], 'records_examined': counts['examined'], 'events_matched': counts['matched'],
                         'partial_result_file': shown_result(partial)})
        sys.exit(128 + stopped['signal'])
    made_path = place_without_replacing(tmp_path, result_path)
    chunks_read = counts['chunks_read']
    if counts['without_time']:
        problems.append('%d record(s) have no usable SystemTime and could not be placed in the time range: they are left out'
                        % counts['without_time'])
    if counts['beyond_read'] or counts['beyond_rejected']:
        problems_note = ('the file holds %d chunk(s) past the %d its header declares: %d were read (chunk_beyond_declared: true on their rows)%s'
                         % (counts['beyond_read'] + counts['beyond_rejected'], declared_n, counts['beyond_read'],
                            ', %d did not pass the chunk header checks and were not read' % counts['beyond_rejected'] if counts['beyond_rejected'] else ''))
        if declared['flags'] is not None and declared['flags'] & 1:
            problems_note += '; the header says the log is dirty (it was opened and changed, and the header was not brought up to date)'
        if counts['beyond_rejected']:
            problems.append(problems_note)
        notes_beyond = problems_note
    else:
        notes_beyond = None
    if counts['declared_unreadable']:
        problems.append('%d chunk(s) the file header declares have no ElfChnk signature and were not read' % counts['declared_unreadable'])
    if counts['tables_refused']:
        problems.append('%d chunk(s) were not given to the reader because a string or template table in them loops or points outside the chunk (chunk_report)' % counts['tables_refused'])
    if counts['timed_out']:
        problems.append('%d chunk(s) took more than %d seconds to read and were given up (chunk_report)' % (counts['timed_out'], CHUNK_SECONDS))
    if stopped['time']:
        problems.append(stopped['time'] + '; the chunks after it were not read')
    visited = min(max(slot_index[0] + 1, 0), declared_n) if declared_n is not None else None
    if visited is not None and visited < declared_n and not stopped['time']:
        problems.append('the reader gave %d of the %d chunks the file header declares: records in the others were not read' % (visited, declared_n))
    time_range = None
    if time_low is not None or time_high is not None:
        def tick_iso(t):
            return None if t is None else (EPOCH + datetime.timedelta(seconds=t // TICKS)).strftime('%Y-%m-%dT%H:%M:%S') + '.%07dZ' % (t % TICKS)
        time_range = {'from': tick_iso(time_low), 'until_exclusive': tick_iso(time_high)}
    complete = counts['parse_errors'] == 0 and not problems
    if complete:
        basis = ('every chunk slot of the file was examined: %d chunk(s) read%s, none failed' %
                 (chunks_read, ' (%d of them past the header\'s count)' % counts['beyond_read'] if counts['beyond_read'] else ''))
    else:
        reasons = []
        if counts['parse_errors']:
            reasons.append('%d record(s) or chunk(s) could not be read (parse_errors)' % counts['parse_errors'])
        if problems:
            reasons.append('%d problem(s) are named under problems' % len(problems))
        basis = '; '.join(reasons)
    answer = {
        'parser': PARSER,
        'status': 'complete' if complete else 'partial',
        'status_basis': basis,
        'path': path,
        'file_bytes': file_bytes,
        'header_flags': declared['flags'],
        'header_dirty': bool(declared['flags'] & 1) if declared['flags'] is not None else None,
        'chunks_declared': declared_n,
        'chunks_in_file': (file_bytes - header_bytes) // CHUNK_BYTES if file_bytes > header_bytes else 0,
        'chunks_read': chunks_read,
        'chunks_read_beyond_declared': counts['beyond_read'],
        'chunks_beyond_declared_rejected': counts['beyond_rejected'],
        'chunk_slots_beyond_declared_empty': counts['slots_empty_beyond'],
        'chunks_not_read': chunk_report[:100],
        'chunks_not_read_count': len(chunk_report),
        'beyond_declared_note': notes_beyond,
        'bytes_expected': declared['bytes_expected'],
        'next_record_number_declared': declared['next_record_number'],
        'highest_record_id_read': highest_record,
        'records_examined': counts['examined'],
        'events_matched': counts['matched'],
        'parse_errors': counts['parse_errors'],
        'events_without_time_excluded': counts['without_time'],
        'walk_stopped_by_time_limit': stopped['time'] is not None,
        'time_range_utc': time_range,
        'count': counts['matched'],
        'returned': len(events),
        'events': events,
        'errors': errors,
        'problems': problems,
        'truncated': counts['matched'] > len(events),
        'result_file': shown_result(made_path),
        'note': 'count is the events that matched the filters; parse_errors are records or chunks that could not be read and are in the result '
                'file as rows with parse_error. A record the reader could not produce is not examined, and a run with parse_errors is partial: '
                'an absence of events is bounded by the records examined, by chunks_read against chunks_declared and chunks_in_file, and by file_bytes '
                'against bytes_expected. The result file holds the whole XML of every matched event (event data can hold a secret): it is mode 0600.',
    }
    if made_path != result_path:
        answer['result_file_requested'] = shown_result(result_path)
        answer['result_file_requested_note'] = ('that name was already taken by an earlier, different result, which is kept as it was; this run '
                                                'wrote %s' % shown_result(made_path))
    emit(answer)
    close_values()


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except Interrupted as stop:
        emit({'error': 'stopped by signal %d' % stop.signum, 'status': 'interrupted', 'status_basis': 'the tool was stopped by signal %d' % stop.signum, 'signal': stop.signum})
        sys.exit(128 + stop.signum)
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        emit({'error': 'the read failed', 'status': 'failed', 'status_basis': 'the tool stopped with an unexpected error', 'reason': '%s: %s' % (type(exc).__name__, exc)})
        sys.exit(1)

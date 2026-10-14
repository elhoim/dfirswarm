#!/usr/bin/env python3
"""Run a read-only SQL query over a SQLite database file, bounded and typed.

What this reads: the main database file, opened read-only and immutable, through
Python's sqlite3 module (never the sqlite3 shell). An authorizer lets a statement
read and nothing else: no write, no ATTACH, no extension, no PRAGMA that sets.
What it does not read: the write-ahead log of the file it is given. An immutable open ignores a -wal and
a -shm beside the database, so rows committed only in the WAL are not in the
result; the tool inventories the sidecars (name, size, WAL frames) and says so
in `snapshot_status`, loudly, instead of leaving it to be found. Applying a WAL
needs a staged copy of the database set, which this tool does not make: the
sqlite_snapshot tool does (it copies the set with hashes and has SQLite apply the
WAL in the copy, never beside the evidence), and `db_path` may be that snapshot's
directory or the database inside it. The answer then carries `snapshot` (what the
snapshot says it holds, and whether the file queried is still the one it recorded)
and `snapshot_status` says which state the rows are. `apply_wal` is not a
parameter here: asking for it is an error that names sqlite_snapshot.

The answer is bounded: an inline page of rows (`limit`, and a byte ceiling), and
when the result is more than that the whole of it in a JSON Lines file, named in
`rows_file`. Each row is typed: NULL is null, an integer or a real is a number,
text is a string (text that is not UTF-8 carries its bytes in base64 beside the
escaped form), a BLOB is {blob_b64, length, sha256}. `stdout` keeps the text form
of the inline page the old tool returned (CSV with a header, or the shell's
`|`-separated list), for the callers that read it.

VALUES TO A FILE (`write_values: true`). On a table that holds secrets (cookies, saved logins, tokens, keys, messages) an
inline page puts values in the agent's context. In this mode no value is ever in the answer: the row values of ONE table go to
a 0600 file under $OUT, and the answer carries locators (table, rowid, column), counts, types and lengths.

  * It takes `table` (and optionally `columns`, `rowid_from`, `rowid_to`), NOT `sql`. A WHERE, LIKE, JOIN or any expression over
    a column whose values are withheld would be an oracle: one call is one bit of every row, and a few hundred calls confirm a
    guess. The mode therefore exports whole rows, selected by position (a rowid range) and never by value; the counts it prints
    are the table's, not a filter's.
  * It follows the secret-safe output pattern of recovery_key_scan (docs/packs.md, "Secrets and sensitive output"): refused
    outside a job (JOB_ID and OUT set) as a JSON answer, the values file created before any row is read with O_EXCL and
    O_NOFOLLOW and mode 0600 (a second run in one job's $OUT is refused by name, never overwrites), no hash, digest or fragment
    of a value anywhere, a printed name that is shaped like a token withheld by the shared block below (the network pack's, byte
    for byte). The skill that sends the agent here says the job runs with `secret_output: true`.
"""
import base64
import collections
import csv
import errno
import hashlib
import io
import json
import math
import os
import re
import sqlite3
import struct
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

TOOL = {"name": "sqlite_query", "version": 6}
DEFAULT_LIMIT = 100
LIMIT_MAX = 10000
INLINE_BYTES = 64 * 1024          # the inline page's JSON and its text form, each, as they are sent (ASCII-escaped, counted in bytes)
RAW_BUFFER_MAX = 8 * 1024 * 1024  # the raw values of the inline page held in memory; past it the rest goes to the file only
FILE_BYTES = 2 * 1024 ** 3        # the whole-result file stops here, and says so
BUDGET_SECONDS = 25
BUDGET_MAX = 110
SQL_MAX = 64 * 1024               # bytes of UTF-8
HASH_MAX = 256 * 1024 * 1024
BLOB_INLINE = 256                 # a BLOB longer than this shows its head inline; the file holds all of it
VALUE_MAX = 64 * 1024 * 1024      # the longest string or BLOB (or whole row) read: sqlite refuses a longer one before it is in memory
STREAM_AT = 1024 * 1024           # a BLOB longer than this is hashed and encoded to the file in slices, never as one more copy
SLICE_BYTES = 3 * 256 * 1024      # a multiple of 3, so each slice's base64 joins the next without padding

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

# What a statement may do. SELECT and READ are reading; FUNCTION is a call to a
# built-in; RECURSIVE is a recursive CTE. Everything else is refused, whatever
# the open mode would have said.
ALLOWED_ACTIONS = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION,
                   getattr(sqlite3, "SQLITE_RECURSIVE", 33)}
DENIED_FUNCTIONS = {"load_extension", "fts3_tokenizer", "readfile", "writefile", "edit"}
# Pragmas that only report. A setter form (an argument) is refused for all but those
# that take a table name as their argument.
READ_PRAGMAS = {"table_info", "table_xinfo", "table_list", "index_list", "index_info", "index_xinfo",
                "foreign_key_list", "foreign_key_check", "database_list", "collation_list", "function_list",
                "module_list", "pragma_list", "compile_options", "page_size", "page_count", "freelist_count",
                "user_version", "application_id", "schema_version", "encoding", "journal_mode", "integrity_check",
                "quick_check", "data_version", "max_page_count", "auto_vacuum", "wal_autocheckpoint", "cache_size"}
PRAGMAS_WITH_NAME = {"table_info", "table_xinfo", "index_list", "index_info", "index_xinfo", "foreign_key_list",
                     "foreign_key_check", "integrity_check", "quick_check"}
LEADING = ("select", "with", "values", "pragma", "explain")


VALUES_MODE = [False]
# What a values-mode answer prints about the evidence's own names (the file, the table, the columns, a message quoting them)
# goes through the shared block's scrub, so a name shaped like a token is withheld on every channel. A digest of the file is
# the file's identity and stays whole.
SCRUBBED_KEYS = ("error", "stderr", "db_path", "database_opened", "table", "reason", "statement")


def scrub_answer(obj):
    out = dict(obj)
    for key in SCRUBBED_KEYS:
        if isinstance(out.get(key), str):
            out[key] = scrub(out[key])
    snap = out.get("snapshot")
    if isinstance(snap, dict):
        out["snapshot"] = {k: (scrub(v) if k in ("source", "receipt") and isinstance(v, str) else v) for k, v in snap.items()}
    return out


def say(obj, code=0):
    if VALUES_MODE[0]:
        obj = scrub_answer(obj)
    print(json.dumps(obj))
    raise SystemExit(code)


def authorizer(action, p1, p2, dbname, source):
    if action in ALLOWED_ACTIONS:
        if action == sqlite3.SQLITE_FUNCTION and (p2 or "").lower() in DENIED_FUNCTIONS:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA:
        name = (p1 or "").lower()
        if name in READ_PRAGMAS and (p2 is None or name in PRAGMAS_WITH_NAME):
            return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def statements(sql):
    """The statements of `sql`, split where sqlite says one is complete (a ';' inside
    a string or a trigger body does not end it). What follows the last ';' is a statement too,
    complete or not: a line comment at its end does not hide it, and an incomplete one (an
    unterminated string, a trigger with no END) is handed to sqlite to refuse, never dropped."""
    out, start = [], 0
    for i, ch in enumerate(sql):
        if ch == ";" and sqlite3.complete_statement(sql[start:i + 1]):
            out.append(sql[start:i + 1])
            start = i + 1
    out.append(sql[start:])
    return [s.strip() for s in out if re.sub(r"(--[^\n]*\n?|/\*.*?\*/|\s|;)+", "", s, flags=re.S)]


def first_word(stmt):
    stripped = re.sub(r"^(\s|--[^\n]*\n|/\*.*?\*/)+", "", stmt, flags=re.S)
    m = re.match(r"[A-Za-z]+", stripped)
    return m.group(0).lower() if m else ""


def entropy(page):
    counts = collections.Counter(page)
    return -sum(c / len(page) * math.log2(c / len(page)) for c in counts.values())


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def wal_inventory(path):
    """What the WAL file says about itself, from its header and its frame headers:
    the frames that belong to its current generation (their salts match the header's)
    and the last commit among them. Checksums are not verified."""
    size = os.path.getsize(path)
    info = {"bytes": size}
    if size < 32:
        info["state"] = "empty or shorter than its 32-byte header"
        info["frames_valid"] = 0
        return info
    with open(path, "rb") as fh:
        head = fh.read(32)
        magic, version, page, seq, salt1, salt2 = struct.unpack(">IIIIII", head[:24])
        if magic not in (0x377F0682, 0x377F0683) or not 512 <= page <= 65536 or page & (page - 1):
            info["state"] = "not a WAL header (magic %08x, page size %d)" % (magic, page)
            info["frames_valid"] = 0
            return info
        stride = 24 + page
        total = (size - 32) // stride
        valid, last_commit = 0, 0
        for i in range(total):
            fh.seek(32 + i * stride)
            fr = fh.read(24)
            if len(fr) < 24:
                break
            pgno, commit, s1, s2 = struct.unpack(">IIII", fr[:16])
            if s1 != salt1 or s2 != salt2 or pgno == 0:
                break
            valid += 1
            if commit:
                last_commit = valid
    info.update({"page_size": page, "checkpoint_sequence": seq, "frames_in_file": total, "frames_valid": valid,
                 "frames_committed": last_commit, "state": "frames of the current generation counted from their salts; checksums not verified"})
    return info


JOURNAL_MAGIC = bytes([0xD9, 0xD5, 0x05, 0xF9, 0x20, 0xA1, 0x63, 0xD7])


def journal_inventory(path):
    """A rollback journal is hot only when its header is the journal's: a header of zeros (what journal_mode
    TRUNCATE and PERSIST leave) means there is nothing to roll back."""
    with open(path, "rb") as fh:
        head = fh.read(28)
    if head[:8] == JOURNAL_MAGIC:
        return {"state": "header present: a journal that was not rolled back"}
    if not head.strip(b"\0"):
        return {"state": "empty or zeroed header: not a hot journal (a persistent or truncated one left behind)"}
    return {"state": "a header that is not a rollback journal's; not applied, not understood"}


def sidecars(db):
    """The files beside the database, named from its real path: SQLite looks for a -wal and a -journal next to the
    file a link points at, not next to the link."""
    real = os.path.realpath(db)
    out = []
    for suffix in ("-wal", "-shm", "-journal"):
        path = real + suffix
        entry = {"name": os.path.basename(path), "present": os.path.isfile(path)}
        if entry["present"]:
            try:
                entry["bytes"] = os.path.getsize(path)
                if suffix == "-wal":
                    entry.update(wal_inventory(path))
                if suffix == "-journal" and entry["bytes"]:
                    entry.update(journal_inventory(path))
                if entry["bytes"] <= HASH_MAX:
                    entry["sha256"] = sha256_file(path)
            except OSError as exc:
                entry["error"] = exc.strerror or str(exc)
        out.append(entry)
    return out


RECEIPT_MAX = 16 * 1024 * 1024


def read_receipt(path):
    try:
        if os.path.getsize(path) > RECEIPT_MAX:
            return None
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    tool = data.get("tool") if isinstance(data, dict) else None
    return data if isinstance(tool, dict) and tool.get("name") == "sqlite_snapshot" else None


def find_snapshot(db):
    """(path of the database to open, snapshot facts or None). `db` may be a sqlite_snapshot directory, or the database inside one
    (<snapshot>/original/database.sqlite or <snapshot>/applied/database.sqlite); anything else is an ordinary file."""
    if os.path.isdir(db):
        receipt = read_receipt(os.path.join(db, "snapshot.json"))
        if receipt is None:
            return db, None
        root = db
        target = os.path.join(root, receipt.get("database") or "")
    else:
        parent = os.path.dirname(os.path.abspath(db))
        root = os.path.dirname(parent)
        receipt = read_receipt(os.path.join(root, "snapshot.json")) if os.path.basename(parent) in ("original", "applied") else None
        if receipt is None:
            return db, None
        target = db
    rel = os.path.relpath(os.path.abspath(target), os.path.abspath(root))
    applied = receipt.get("applied") or {}
    wal = receipt.get("wal") or {}
    which = rel.split(os.sep)[0]
    recorded = applied.get("sha256") if which == "applied" else (receipt.get("source") or {}).get("sha256")
    facts = {
        "receipt": os.path.join(root, "snapshot.json"), "queried": rel, "queried_is": ("the copy with the WAL applied" if which == "applied" else "the copy of the main file as it was"),
        "source": (receipt.get("source") or {}).get("db_path"), "source_sha256": (receipt.get("source") or {}).get("sha256"),
        "wal_applied": bool(receipt.get("wal_applied")), "wal_frames_committed": wal.get("frames_committed"), "wal_frames_valid": wal.get("frames_valid"),
        "wal_frames_uncommitted_valid": wal.get("frames_uncommitted_valid"), "snapshot_status": receipt.get("status"),
        "snapshot_problems": receipt.get("problems") or [], "snapshot_notes": receipt.get("notes") or [], "recorded_sha256": recorded,
        "rollback_journal": (receipt.get("rollback_journal") or {}).get("state"),
    }
    return target, facts


def snapshot_note(facts, side):
    """What state of the source this snapshot's database is, in words; the plain sidecar report would be wrong inside a snapshot."""
    notes = []
    if facts["queried"].startswith("applied"):
        notes.append("SNAPSHOT: this is the copy of %s with its WAL applied by SQLite (%s committed frame(s)); the originals were not touched." % (
            facts["source"] or "the source", facts["wal_frames_committed"]))
        if facts["wal_frames_uncommitted_valid"]:
            notes.append("%d valid WAL frame(s) after the last commit were not applied." % facts["wal_frames_uncommitted_valid"])
    else:
        notes.append("SNAPSHOT: this is the snapshot's copy of the main file as it was%s." % (
            "; its WAL is NOT applied here (the applied copy is applied/database.sqlite)" if facts["wal_frames_committed"] else ""))
    if facts["rollback_journal"] and facts["rollback_journal"].startswith("header present"):
        notes.append("A hot rollback journal was beside the source and was not rolled back: the main file may hold an interrupted write.")
    if facts["snapshot_status"] != "complete":
        notes.append("The snapshot itself is %s: %s" % (facts["snapshot_status"], "; ".join(facts["snapshot_problems"][:3]) or "see its receipt"))
    return " ".join(notes)


def snapshot_status(side):
    """Said plainly: what state of the database this result is."""
    notes = []
    wal = next((s for s in side if s["name"].endswith("-wal") and s.get("present")), None)
    jrn = next((s for s in side if s["name"].endswith("-journal") and s.get("present")), None)
    if wal and wal.get("frames_valid"):
        notes.append("WAL NOT APPLIED: the main file was read immutable, so the %d frame(s) (%d committed) in %s are not in this result; "
                     "a row committed only there is missing. To read that state, run sqlite_snapshot on the database (it copies the set, hashed, and "
                     "has SQLite apply the WAL in the copy) and query the `database` it names." % (wal["frames_valid"], wal.get("frames_committed", 0), wal["name"]))
    elif wal and wal.get("bytes"):
        notes.append("%s is present (%d bytes) and holds no valid frame; the main file is the whole database state this tool can read." % (wal["name"], wal["bytes"]))
    if jrn and jrn.get("bytes") and jrn.get("state", "").startswith("header present"):
        notes.append("%s is present (%d bytes): a rollback journal that was not rolled back; the main file may hold an interrupted write. Not applied." % (jrn["name"], jrn["bytes"]))
    elif jrn and jrn.get("bytes"):
        notes.append("%s is present (%d bytes): %s." % (jrn["name"], jrn["bytes"], jrn.get("state", "its header was not read")))
    if not notes:
        return "main file only; no WAL frames or hot journal beside it"
    return " ".join(notes)


def typed_cell(value):
    """A typed JSON value for a cell: null, number, string, or an object that keeps what a string cannot."""
    if value is None or isinstance(value, (int, float)):
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return {"real": repr(value)}
        return value
    if isinstance(value, bytes):
        return {"blob_b64": base64.b64encode(value).decode("ascii"), "length": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    if isinstance(value, _Text):
        return {"text_invalid_utf8": str(value), "bytes_b64": base64.b64encode(value.raw).decode("ascii"), "length": len(value.raw)}
    return value


class _Text(str):
    """Text from the database that was not valid UTF-8, kept with its bytes."""
    raw = b""


def text_factory(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        t = _Text(raw.decode("utf-8", "backslashreplace"))
        t.raw = bytes(raw)
        return t


def inline_cell(value):
    """The same, with a long BLOB shown by its head: the file holds it whole."""
    c = typed_cell(value)
    if isinstance(c, dict) and "blob_b64" in c and c["length"] > BLOB_INLINE:
        return {"blob_b64_head": base64.b64encode(value[:BLOB_INLINE]).decode("ascii"), "length": c["length"], "sha256": c["sha256"],
                "head_bytes": BLOB_INLINE}
    return c


def text_cell(value, csv_mode):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return "<blob %d bytes>" % len(value)
    if isinstance(value, float):
        return "%.15g" % value
    return str(value)


def blob_json(fh, value):
    """A BLOB as {blob_b64, length, sha256}, written to `fh` in slices: the digest is taken first over views of the value,
    then the base64 is written slice by slice, so a large value costs no second copy of itself in memory."""
    digest = hashlib.sha256()
    view = memoryview(value)
    for at in range(0, len(view), SLICE_BYTES):
        digest.update(view[at:at + SLICE_BYTES])
    fh.write('{"blob_b64": "')
    for at in range(0, len(view), SLICE_BYTES):
        fh.write(base64.b64encode(view[at:at + SLICE_BYTES]).decode("ascii"))
    fh.write('", "length": %d, "sha256": "%s"}' % (len(value), digest.hexdigest()))


def earlier_answers(path):
    """How many other files answer this same question in the folder (name.ext, name.2.ext, ...): one more for every different
    answer, and none is deleted, so the count is said."""
    stem, ext = os.path.splitext(os.path.basename(str(path)))
    base = re.sub(r"\.\d+$", "", stem)
    rx = re.compile(r"^%s(\.\d+)?%s$" % (re.escape(base), re.escape(ext)))
    try:
        return max(0, sum(1 for n in os.listdir(os.path.dirname(str(path)) or ".") if rx.match(n)) - 1)
    except OSError:
        return 0


def same_bytes(a, b):
    """Two files with the same bytes (compared in blocks, never whole)."""
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


def publish(tmp, path, shown):
    """Move a finished file to `path` without replacing what is there: a file at the name is an earlier answer (a complete one,
    perhaps, where this run was cut short) and stays; this one is kept beside it as name.2.ext. Returns the name it has and
    the name to show for it."""
    stem, ext = os.path.splitext(str(path))
    shown_stem, _ = os.path.splitext(shown)
    k = 1
    while True:
        suffix = "" if k == 1 else ".%d" % k
        candidate = Path(stem + suffix + ext)
        try:
            os.link(tmp, candidate)
        except FileExistsError:
            if same_bytes(tmp, candidate):                # the same answer again (a page of the same search): the file is already there
                os.unlink(tmp)
                return candidate, shown_stem + suffix + ext
            k += 1
            continue
        except OSError:                                   # a file system with no hard links: a look, then a rename
            if os.path.lexists(candidate):
                if same_bytes(tmp, candidate):
                    os.unlink(tmp)
                    return candidate, shown_stem + suffix + ext
                k += 1
                continue
            os.rename(tmp, candidate)
            return candidate, shown_stem + suffix + ext
        os.unlink(tmp)
        return candidate, shown_stem + suffix + ext


def raw_size(row):
    return sum(len(v) if isinstance(v, (bytes, str)) else 8 for v in row)


class Rows:
    """One statement's rows: an inline page, and the whole result in a file once it is more than that.

    The inline page is bounded by what is sent (its JSON and its text form, as bytes), by `limit`, and by
    the raw values held to make it (RAW_BUFFER_MAX): a row too large to hold goes to the file only."""

    def __init__(self, stmt_index, key, columns, limit):
        self.limit, self.columns = limit, columns
        self.page, self.raw_page, self.inline_bytes, self.raw_bytes = [], [], 0, 0
        self.total, self.fh, self.tmp, self.written = 0, None, None, 0
        self.file_stopped = None
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode()).hexdigest()[:16]
        name = "sqlite_query-%s-%d.jsonl" % (digest, stmt_index)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        self.error = None

    def _open(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".sqlite_query-")
        self.tmp = Path(name)
        self.fh = os.fdopen(fd, "w", encoding="utf-8")
        self.fh.write(json.dumps({"columns": self.columns}) + "\n")
        for n, row in enumerate(self.raw_page, 1):
            self._write(n, row)

    def _write(self, n, row):
        if self.file_stopped:
            return
        big = any(isinstance(v, bytes) and len(v) > STREAM_AT for v in row)
        if not big:
            line = json.dumps({"n": n, "values": [typed_cell(v) for v in row]}, ensure_ascii=False) + "\n"
            if self.written + len(line) > FILE_BYTES:
                self.file_stopped = n
                return
            self.fh.write(line)
            self.written += len(line)
            return
        # A row with a large BLOB: its size is known before it is written, and the BLOB is encoded in slices.
        size = sum(4 * ((len(v) + 2) // 3) + 120 if isinstance(v, bytes) else len(json.dumps(typed_cell(v), ensure_ascii=False)) + 2 for v in row) + 40
        if self.written + size > FILE_BYTES:
            self.file_stopped = n
            return
        self.fh.write('{"n": %d, "values": [' % n)
        for i, v in enumerate(row):
            if i:
                self.fh.write(", ")
            if isinstance(v, bytes) and len(v) > STREAM_AT:
                blob_json(self.fh, v)
            else:
                self.fh.write(json.dumps(typed_cell(v), ensure_ascii=False))
        self.fh.write("]}\n")
        self.written += size

    def _drop_file(self, exc):
        """The whole-result file cannot be written (a full disk, a read-only directory): said, and no half file left."""
        self.error = "the whole result could not be written (%s): %s" % (self.path.parent, getattr(exc, "strerror", None) or exc)
        try:
            if self.fh:
                self.fh.close()
        except (OSError, ValueError):
            pass
        self.fh = False
        if self.tmp:
            try:
                self.tmp.unlink()
            except OSError:
                pass
            self.tmp = None

    def add(self, row):
        self.total += 1
        if self.fh is None:
            size = raw_size(row)
            if len(self.page) < self.limit and size <= INLINE_BYTES and self.raw_bytes + size <= RAW_BUFFER_MAX:
                inline = [inline_cell(v) for v in row]
                sent = len(json.dumps({"n": self.total, "values": inline}).encode("utf-8"))
                text = len(json.dumps("|".join(text_cell(v, False) for v in row)).encode("utf-8"))
                if self.inline_bytes + sent + text <= 2 * INLINE_BYTES:
                    self.page.append({"n": self.total, "values": inline})
                    self.raw_page.append(row)
                    self.inline_bytes += sent + text
                    self.raw_bytes += size
                    return
            try:
                self._open()
            except (OSError, UnicodeError) as exc:
                self._drop_file(exc)
        if self.fh:
            try:
                self._write(self.total, row)
            except (OSError, UnicodeError) as exc:
                self._drop_file(exc)

    def finish(self):
        info = {"row_count": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self.fh:
            try:
                self.fh.flush()
                os.fsync(self.fh.fileno())
                self.fh.close()
                self.path, self.shown = publish(self.tmp, self.path, self.shown)
                self.tmp = None
                info["rows_file"] = self.shown
                info["earlier_answers"] = earlier_answers(self.path)
                info["rows_file_format"] = "JSON Lines: a header line {columns}, then one {n, values} per row; NULL is null, a BLOB is {blob_b64, length, sha256}"
                if self.file_stopped:
                    info["rows_file_stopped_at_row"] = self.file_stopped
                    info["rows_file_cap_bytes"] = FILE_BYTES
            except OSError as exc:
                self._drop_file(exc)
        if self.error:
            info["rows_file_error"] = self.error
        return info


def render(rows, columns, csv_mode):
    """The old tool's text for the inline page: CSV with a header, or the shell's list mode."""
    buf = io.StringIO()
    raw = [r for r in rows.raw_page]
    if csv_mode:
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(columns)
        for r in raw:
            w.writerow([text_cell(v, True) for v in r])
    else:
        for r in raw:
            buf.write("|".join(text_cell(v, False) for v in r) + "\n")
    return buf.getvalue()


# --- values to a file (write_values) ---------------------------------------------------------------------------

VALUES_NAME = "sqlite-query-values.jsonl"
VALUES_FORMAT = ("JSON Lines, mode 0600, one line per cell that is not NULL: finding_id, table (the real name), rowid (null when the table "
                 "has no rowid), n (the row's position in this export, from 1), column (the real name), type, length, value "
                 "(a BLOB is {blob_b64}, text that is not UTF-8 is {text_invalid_utf8, bytes_b64, length}); no digest of any value")
VALUES_PARAMS = ("table", "columns", "rowid_from", "rowid_to")
ROWID_NAMES = ("rowid", "oid", "_rowid_")


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text)


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The pattern of recovery_key_scan (encrypted-containers), copied: call `add` once per cell with its id, its locator and the
    value. With `enabled` false it writes nothing and `summary()` says so. `add_blob` is `add` for a BLOB written in slices.
    """

    def __init__(self, enabled):
        self.enabled = enabled
        self.written = 0
        self.bytes = 0
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
                "file, not a sealed secret output. Run this as job_run tool=sqlite_query with "
                "secret_output: true, and ask again there. Nothing was written."
            )
        self.path = Path(self.out) / VALUES_NAME
        self.shown = "store/jobs/%s/out/%s" % (safe_name(self.job), VALUES_NAME)
        # Created now, before anything is read: a file or a link already at that name is refused by name at once (O_EXCL does
        # not follow a link, a dangling one included), instead of failing, or writing through it, after the export. With nothing
        # to write it stays an empty file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id, locator, value):
        if not self.enabled:
            return
        line = json.dumps({"finding_id": finding_id, **locator, "value": value}) + "\n"
        self._fh.write(line)
        self.bytes += len(line)
        self.written += 1

    def add_blob(self, finding_id, locator, blob):
        """A BLOB as {blob_b64}, written slice by slice: no second copy of a large value in memory, and no digest of it."""
        if not self.enabled:
            return
        head = json.dumps({"finding_id": finding_id, **locator})[:-1] + ', "value": {"blob_b64": "'
        self._fh.write(head)
        view = memoryview(blob)
        for at in range(0, len(view), SLICE_BYTES):
            self._fh.write(base64.b64encode(view[at:at + SLICE_BYTES]).decode("ascii"))
        self._fh.write('"}}\n')
        self.bytes += len(head) + 4 * ((len(blob) + 2) // 3) + 4
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


def values_fail(message, **extra):
    say({"ok": False, "error": message, "tool": TOOL, **extra}, 1)


def q_ident(name):
    return '"' + name.replace('"', '""') + '"'


def value_kind(value):
    """(type, length) of a cell: the length is bytes for a BLOB and for text (as UTF-8), digits for a number."""
    if value is None:
        return "null", None
    if isinstance(value, bytes):
        return "blob", len(value)
    if isinstance(value, _Text):
        return "text_not_utf8", len(value.raw)
    if isinstance(value, str):
        return "text", len(value.encode("utf-8", "replace"))
    if isinstance(value, float):
        return "real", len(repr(value))
    return "integer", len(str(value))


def value_json(value):
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return {"real": repr(value)}
    if isinstance(value, _Text):
        return {"text_invalid_utf8": str(value), "bytes_b64": base64.b64encode(value.raw).decode("ascii"), "length": len(value.raw)}
    return value


def table_layout(conn, wanted, columns):
    """(table, [(column, declared type)], rowid column name or None) for the table `wanted`, or a refusal as JSON."""
    names = [str(r[0]) for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
    hits = [n for n in names if n == wanted] or [n for n in names if n.lower() == wanted.lower()]
    if len(hits) != 1:
        values_fail("the database has no table of that name (the mode reads one table; a view is not one)" if not hits
                    else "more than one table matches that name without regard to case: give it exactly", table=wanted, tables=len(names))
    table = hits[0]
    info = [r for r in conn.execute("PRAGMA table_xinfo(%s)" % q_ident(table)) if r[6] in (0, 2, 3)]
    have = {str(r[1]): str(r[2] or "") for r in info}
    chosen = columns if columns is not None else [str(r[1]) for r in info]
    if not chosen:
        values_fail("the table has no column that can be read", table=table)
    for c in chosen:
        if c not in have:
            values_fail("the table has no column of that name (names are case-sensitive here)", table=table, column=c)
    lowered = {str(r[1]).lower() for r in info}
    rowid_name = None
    for cand in ROWID_NAMES:
        if cand in lowered:
            continue
        try:
            conn.execute("SELECT %s FROM %s LIMIT 0" % (cand, q_ident(table)))
        except sqlite3.Error:
            break  # WITHOUT ROWID: none of the names will work
        rowid_name = cand
        break
    return table, [(c, have[c]) for c in chosen], rowid_name


def values_mode(obj, values, given, db, size, side, status, snap, limit, budget, csv_mode):
    wanted = obj.get("table")
    if not isinstance(wanted, str) or not wanted:
        values_fail("write_values needs table: the one table whose values go to the file")
    columns = obj.get("columns")
    if columns is not None and (not isinstance(columns, list) or not columns or not all(isinstance(c, str) and c for c in columns)
                                or len(set(columns)) != len(columns)):
        values_fail("columns is a list of distinct column names, or left out for every column")
    bounds = {}
    for key in ("rowid_from", "rowid_to"):
        if key in obj:
            v = obj[key]
            if not isinstance(v, int) or isinstance(v, bool) or not -2 ** 63 <= v < 2 ** 63:
                values_fail("%s is a whole number" % key, **{key: v})
            bounds[key] = v
    for name, text in [("table", wanted)] + [("columns", c) for c in columns or []]:
        if "\0" in text:
            values_fail("%s holds a NUL character" % name)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            values_fail("%s is not text that can be written as UTF-8 (it holds a lone surrogate)" % name)
    uri = "file:%s?mode=ro&immutable=1" % urllib.parse.quote(db)
    started = time.monotonic()
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        values_fail("cannot open the database: %s" % exc, db_path=db)
    conn.text_factory = text_factory
    value_limit = "%d bytes" % VALUE_MAX
    if hasattr(conn, "setlimit") and hasattr(sqlite3, "SQLITE_LIMIT_LENGTH"):
        conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, VALUE_MAX)
    else:
        value_limit = "not enforced (Python before 3.11 has no setlimit)"
    conn.set_authorizer(authorizer)
    conn.set_progress_handler(lambda: 1 if time.monotonic() - started > budget else 0, 20000)
    try:
        table, cols, rowid_name = table_layout(conn, wanted, columns)
    except sqlite3.Error as exc:
        values_fail("the table's layout cannot be read: %s" % exc, table=wanted)
    if bounds and rowid_name is None:
        values_fail("rowid_from and rowid_to select by rowid, and this table has none (WITHOUT ROWID): export the whole table", table=table)
    sel = ([rowid_name] if rowid_name else []) + [q_ident(c) for c, _t in cols]
    stmt = "SELECT %s FROM %s" % (", ".join(sel), q_ident(table))
    params = []
    if rowid_name:
        conds = []
        if "rowid_from" in bounds:
            conds.append("%s >= ?" % rowid_name)
            params.append(bounds["rowid_from"])
        if "rowid_to" in bounds:
            conds.append("%s <= ?" % rowid_name)
            params.append(bounds["rowid_to"])
        if conds:
            stmt += " WHERE " + " AND ".join(conds)
        stmt += " ORDER BY %s" % rowid_name
    names = [scrub(cell(c)) for c, _t in cols]
    stats = [{"values": collections.OrderedDict(), "length_min": None, "length_max": None} for _ in cols]
    page, page_bytes, total, nulls, file_stopped = [], 0, 0, 0, None
    tmp = fh = None
    locator_path = locator_shown = None
    job = os.environ.get("JOB_ID") or ""
    digest = hashlib.sha256(json.dumps([db, size, stmt, params], sort_keys=True, default=str).encode()).hexdigest()[:16]
    name = "sqlite_query-values-%s.jsonl" % digest
    locator_path = Path(os.environ["OUT"]) / "tool-output" / name
    locator_shown = "store/jobs/%s/out/tool-output/%s" % (safe_name(job), name)
    locator_error = None
    failure = None
    timed_out = False

    def locator_line(n, rid, cells):
        return json.dumps({"n": n, "rowid": rid, "cells": cells})

    try:
        cur = conn.execute(stmt, params)
        for row in cur:
            total += 1
            rid = row[0] if rowid_name else None
            vals = row[1:] if rowid_name else row
            cells = []
            for i, ((col, _t), v) in enumerate(zip(cols, vals)):
                kind, length = value_kind(v)
                st = stats[i]
                st["values"][kind] = st["values"].get(kind, 0) + 1
                if length is not None:
                    st["length_min"] = length if st["length_min"] is None else min(st["length_min"], length)
                    st["length_max"] = length if st["length_max"] is None else max(st["length_max"], length)
                if v is None:
                    nulls += 1
                    cells.append("null")
                    continue
                cells.append("%s:%d" % (kind, length))
                if file_stopped:
                    continue
                if values.bytes + (4 * ((length + 2) // 3) if isinstance(v, bytes) else length * 6) + 300 > FILE_BYTES:
                    file_stopped = total
                    continue
                finding = "V%07d" % (values.written + 1)
                locator = {"table": table, "rowid": rid, "n": total, "column": col, "type": kind, "length": length}
                if isinstance(v, bytes) and len(v) > STREAM_AT:
                    values.add_blob(finding, locator, v)
                elif isinstance(v, bytes):
                    values.add(finding, locator, {"blob_b64": base64.b64encode(v).decode("ascii")})
                else:
                    values.add(finding, locator, value_json(v))
            line = locator_line(total, rid, cells)
            if fh is None and len(page) < limit and page_bytes + len(line) <= INLINE_BYTES:
                page.append({"n": total, "rowid": rid, "cells": cells})
                page_bytes += len(line)
            else:
                if fh is None and locator_error is None:
                    try:
                        locator_path.parent.mkdir(parents=True, exist_ok=True)
                        fd, tmp_name = tempfile.mkstemp(dir=str(locator_path.parent), prefix=".sqlite_query-")
                        tmp = Path(tmp_name)
                        fh = os.fdopen(fd, "w", encoding="utf-8")
                        fh.write(json.dumps({"table": scrub(cell(table)), "columns": names, "locator": rowid_name or "n"}) + "\n")
                        for p in page:
                            fh.write(locator_line(p["n"], p["rowid"], p["cells"]) + "\n")
                    except OSError as exc:
                        locator_error = "the locator file could not be written: %s" % describe(exc)
                        fh = None
                if fh is not None:
                    fh.write(line + "\n")
    except (sqlite3.Error, ValueError, UnicodeError, OverflowError, MemoryError) as exc:
        msg = str(exc)
        if "not authorized" in msg:
            msg = "statement refused: it is not a plain read (%s)" % msg
        elif "too big" in msg:
            msg = ("a value or row in this table is longer than %d bytes, which this tool will not read into memory (sqlite: %s): "
                   "export the other columns, or read the value in pieces with sqlite_query's ordinary mode on a non-secret" % (VALUE_MAX, msg))
        elif "interrupted" in msg:
            msg = "stopped at the %d-second time budget; the rows before it are in the values file" % budget
        elif isinstance(exc, MemoryError):
            msg = "out of memory reading a row"
        failure = msg
        timed_out = "interrupted" in str(exc)
    finally:
        values.close()
        conn.close()
    published = None
    if fh is not None:
        try:
            fh.flush()
            os.fsync(fh.fileno())
            fh.close()
            published = publish(tmp, locator_path, locator_shown)
        except OSError as exc:
            locator_error = "the locator file could not be written: %s" % describe(exc)
            try:
                tmp.unlink()
            except OSError:
                pass

    out = {"tool": TOOL, "db_path": given, "database_bytes": size, "sidecars": side, "snapshot_status": status,
           "sqlite_library": sqlite3.sqlite_version, "opened": "read-only, immutable, through an authorizer that allows reading only",
           "value_limit": value_limit}
    if size <= HASH_MAX:
        out["database_sha256"] = sha256_file(db)
    else:
        out["database_sha256"] = None
        out["hashing"] = "skipped: the file is larger than %d bytes; the run's own record has its sha256" % HASH_MAX
    if db != given:
        out["database_opened"] = db
    if snap:
        snap["file_matches_recorded_sha256"] = (out["database_sha256"] == snap["recorded_sha256"]) if out["database_sha256"] and snap["recorded_sha256"] else None
        if snap["file_matches_recorded_sha256"] is False:
            out["snapshot_status"] = "THE FILE QUERIED IS NOT THE ONE THE SNAPSHOT RECORDED (its sha256 differs from the receipt's): it was changed after the snapshot, or the receipt belongs to another file. " + out["snapshot_status"]
        out["snapshot"] = snap
    complete = failure is None and file_stopped is None
    text = "".join("%s|%s\n" % (p["rowid"] if p["rowid"] is not None else p["n"], "|".join("%s=%s" % (nm, c) for nm, c in zip(names, p["cells"]))) for p in page)
    if csv_mode:
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["rowid" if rowid_name else "n"] + names)
        for p in page:
            w.writerow([p["rowid"] if p["rowid"] is not None else p["n"]] + p["cells"])
        text = buf.getvalue()
    out.update({
        "ok": failure is None, "returncode": 0 if failure is None else 1, "stderr": failure or "", "complete": complete,
        "mode": "values_to_file", "table": table,
        "locator": "rowid" if rowid_name else "n: the row's position; this table has no rowid (WITHOUT ROWID)",
        "columns": [{"name": nm, "declared_type": scrub(cell(t)), "values": st["values"], "length_min": st["length_min"], "length_max": st["length_max"]}
                    for nm, (_c, t), st in zip(names, cols, stats)],
        "row_count": total, "returned": len(page), "truncated": total > len(page), "rows": page,
        "cells_with_a_value": values.written, "cells_null": nulls,
        "secret_values": values.summary(), "stdout": text,
    })
    if failure:
        out["error"] = failure
        out["rows_read_before_the_stop"] = total
        if timed_out:
            out["timed_out"] = True
    if published:
        out["locators_file"] = published[1]
        out["locators_file_format"] = "JSON Lines: a header line {table, columns, locator}, then one {n, rowid, cells} per row; a cell is type:length or null; no value"
        out["earlier_answers"] = earlier_answers(published[0])
    if locator_error:
        out["locators_file_error"] = locator_error
    if file_stopped:
        out["values_file_stopped_at_row"] = file_stopped
        out["values_file_cap_bytes"] = FILE_BYTES
        if rowid_name and page:
            out["resume"] = "give rowid_from the first rowid not yet written; it needs a new job, since the values file of this one is kept"
    out["note"] = ("Locator output: no value, fragment, masked shape or digest of one is in this answer or in any file it names except the "
                   "values file. A cell is type:length (bytes for a BLOB and for text, digits for a number). The mode exports whole "
                   "rows of one table, never a filter: row_count and the lengths are the table's, so they confirm no guess. Cite "
                   "table, rowid and column; hand a value on through the channel the operator named. An inline page is not the "
                   "result: locators_file has every row when truncated is true.")
    say(out, 0 if failure is None else 1)


def main():
    try:
        obj = json.load(sys.stdin)
    except ValueError as exc:
        say({"ok": False, "error": "arguments are not valid JSON", "reason": str(exc)}, 1)
    if not isinstance(obj, dict):
        say({"ok": False, "error": "arguments are a JSON object"}, 1)
    write_values = obj.get("write_values", False)
    if not isinstance(write_values, bool):
        say({"ok": False, "error": "write_values must be true or false"}, 1)
    wanted_keys = ("db_path", "table") if write_values else ("db_path", "sql")
    missing = [k for k in wanted_keys if not isinstance(obj.get(k), str) or not obj.get(k)]
    if missing:
        say({"ok": False, "error": "need " + " and ".join(missing),
             "params": ["db_path", "table", "columns", "rowid_from", "rowid_to", "write_values", "limit"] if write_values else ["db_path", "sql", "csv", "limit"]}, 1)
    if write_values:
        VALUES_MODE[0] = True
        if "sql" in obj:
            say({"ok": False, "error": "write_values takes table (and columns, rowid_from, rowid_to), not sql: a WHERE, LIKE, JOIN or any "
                                       "expression over a column whose values are withheld would confirm a guess, one call at a time. The mode "
                                       "exports whole rows of one table by position (a rowid range), never by value. For a query over values you "
                                       "may see, leave write_values out.", "write_values": "refused"}, 1)
    else:
        stray = [k for k in VALUES_PARAMS if k in obj]
        if stray:
            say({"ok": False, "error": "%s belong to write_values, which writes the values of one table to a sealed file; "
                                       "an ordinary query takes sql" % ", ".join(stray)}, 1)
    db = obj["db_path"]
    sql = obj.get("sql", "")
    for name, text in (("db_path", db), ("sql", sql)):
        if "\0" in text:
            say({"ok": False, "error": "%s holds a NUL character" % name}, 1)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            say({"ok": False, "error": "%s is not text that can be written as UTF-8 (it holds a lone surrogate)" % name}, 1)
    csv_mode = obj.get("csv", False)
    if not isinstance(csv_mode, bool):
        say({"ok": False, "error": "csv is true or false (a text such as \"false\" is not false)", "csv": csv_mode}, 1)
    if "readonly" in obj and obj["readonly"] is not True:
        if obj["readonly"] is False:
            say({"ok": False, "error": "readonly=false is not supported: this tool never opens a database for writing. "
                                       "Stage a copy under $OUT and use the sqlite3 module on the copy.", "db_path": db}, 1)
        say({"ok": False, "error": "readonly is true (the only mode this tool has) or left out", "readonly": obj["readonly"]}, 1)
    limit = obj.get("limit", DEFAULT_LIMIT)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= LIMIT_MAX:
        say({"ok": False, "error": "limit is a whole number from 1 to %d" % LIMIT_MAX, "limit": limit}, 1)
    budget = obj.get("max_seconds", BUDGET_SECONDS)
    if not isinstance(budget, int) or isinstance(budget, bool) or not 1 <= budget <= BUDGET_MAX:
        say({"ok": False, "error": "max_seconds is a whole number from 1 to %d" % BUDGET_MAX, "max_seconds": budget}, 1)
    if len(sql.encode("utf-8")) > SQL_MAX:
        say({"ok": False, "error": "sql is longer than %d bytes" % SQL_MAX}, 1)
    if "apply_wal" in obj:
        say({"ok": False, "error": "apply_wal is not a parameter of sqlite_query, which opens the file it is given read-only and immutable and never applies a WAL. "
                                   "Run sqlite_snapshot on the database: it copies the set (database, -wal, -shm, -journal) with hashes and has SQLite apply the WAL "
                                   "in the copy, and then give this tool the snapshot's directory or its `database` as db_path.", "db_path": db}, 1)
    values = None
    if write_values:
        try:
            values = SecretValues(True)
        except SecretValuesRefused as exc:
            say({"ok": False, "error": str(exc), "tool": TOOL, "write_values": "refused", "written": False}, 1)
    if not os.path.exists(db):
        say({"ok": False, "error": "database not found", "db_path": db}, 1)
    given = db
    db, snap = find_snapshot(given)
    if not os.path.isfile(db):
        say({"ok": False, "error": "db_path is not a regular file", "db_path": given}, 1)
    size = os.path.getsize(db)
    if size == 0:
        say({"ok": False, "error": "the file is empty (0 bytes): it holds no database", "db_path": db}, 1)
    # sqlite says only "file is not a database" for anything else, and the sixth CTF round's agents met it on
    # Element's SQLCipher events.db without learning why. The first page says what it can: a SQLite file starts
    # with its magic; a file that does not is random from byte 0 or another format. Entropy measures randomness
    # and identifies nothing: encryption is one explanation, compression and another encrypted container others.
    with open(db, "rb") as fh:
        page = fh.read(4096)
    if not page.startswith(b"SQLite format 3\x00"):
        e = entropy(page)
        say({"ok": False, "error": "not a SQLite file: its first bytes are not the SQLite magic", "db_path": db,
             "header_hex": page[:16].hex(), "first_page_entropy_bits_per_byte": round(e, 3),
             "reading": ("random-looking from the first byte (high entropy), and not identified: an encrypted database (SQLCipher "
                         "or an app's own) is one explanation, compressed or otherwise encoded data another; no query runs without "
                         "knowing which" if e > 7.5 else "another format: identify it from its header (file_type)")}, 1)

    side = sidecars(db)
    status = snapshot_status(side)
    if snap:
        note = snapshot_note(snap, side)
        status = note if snap["queried"].startswith("applied") else note + " " + status
    if write_values:
        for s in side:
            s["name"] = scrub(cell(s["name"]))
        values_mode(obj, values, given, db, size, side, scrub(status), snap, limit, budget, csv_mode)
    # immutable=1 opens a database on a read-only mount, where mode=ro alone cannot create a -shm; the path is
    # percent-encoded because a "#" or "?" in it would end the name early.
    uri = "file:%s?mode=ro&immutable=1" % urllib.parse.quote(db)
    stmts = statements(sql)
    if not stmts:
        say({"ok": False, "error": "sql holds no statement"}, 1)
    results, started = [], time.monotonic()
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        say({"ok": False, "error": "cannot open the database: %s" % exc, "db_path": db}, 1)
    conn.text_factory = text_factory
    value_limit = "%d bytes" % VALUE_MAX
    if hasattr(conn, "setlimit") and hasattr(sqlite3, "SQLITE_LIMIT_LENGTH"):
        conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, VALUE_MAX)
    else:
        value_limit = "not enforced (Python before 3.11 has no setlimit)"
    conn.set_authorizer(authorizer)
    conn.set_progress_handler(lambda: 1 if time.monotonic() - started > budget else 0, 20000)
    base = {"tool": TOOL, "db_path": given, "database_bytes": size, "sidecars": side, "snapshot_status": status,
            "sqlite_library": sqlite3.sqlite_version, "opened": "read-only, immutable, through an authorizer that allows reading only", "value_limit": value_limit}
    if size <= HASH_MAX:
        base["database_sha256"] = sha256_file(db)
    else:
        base["database_sha256"] = None
        base["hashing"] = "skipped: the file is larger than %d bytes; the run's own record has its sha256" % HASH_MAX
    if db != given:
        base["database_opened"] = db
    if snap:
        snap["file_matches_recorded_sha256"] = (base["database_sha256"] == snap["recorded_sha256"]) if base["database_sha256"] and snap["recorded_sha256"] else None
        if snap["file_matches_recorded_sha256"] is False:
            base["snapshot_status"] = "THE FILE QUERIED IS NOT THE ONE THE SNAPSHOT RECORDED (its sha256 differs from the receipt's): it was changed after the snapshot, or the receipt belongs to another file. " + base["snapshot_status"]
        base["snapshot"] = snap
    failure = None
    for i, stmt in enumerate(stmts):
        word = first_word(stmt)
        if word not in LEADING:
            failure = {"error": "statement refused: this tool reads; a %s statement is not allowed" % (word.upper() or "?"), "statement": stmt}
            break
        rows = None
        failure_kind = None
        try:
            cur = conn.execute(stmt)
            columns = [d[0] for d in (cur.description or [])]
            rows = Rows(i, [db, size, stmt, limit], columns, limit)
            for r in cur:                    # a row at a time: a fetch of many would hold many large values at once
                rows.add(r)
        except (sqlite3.Error, ValueError, UnicodeError, OverflowError, MemoryError) as exc:
            msg = str(exc)
            if "not authorized" in msg:
                msg = "statement refused: it is not a plain read (%s)" % msg
            elif "too big" in msg:
                msg = ("a value or row in this result is longer than %d bytes, which this tool will not read into memory (sqlite: %s): select its length(), "
                       "or a piece of it with substr(), hex(substr(...)) or a range, in several queries" % (VALUE_MAX, msg))
                failure_kind = "value_too_long"
            elif "interrupted" in msg:
                msg = "stopped at the %d-second time budget; the rows before it are in rows_file when there is one" % budget
            elif isinstance(exc, MemoryError):
                msg = "out of memory reading a row"
            failure = {"error": msg, "statement": stmt}
            if failure_kind:
                failure["reason"] = failure_kind
            if "interrupted" in str(exc):
                failure["timed_out"] = True
            if rows is not None and rows.total:
                # What was read before the stop is kept and named, not dropped with the file half written.
                failure["rows_read_before_the_stop"] = rows.finish()
                failure["rows_read_before_the_stop"]["note"] = "the rows up to the stop, not the result of the statement"
                failure["rows_read_before_the_stop"]["rows"] = rows.page
            break
        info = rows.finish()
        part = {"statement": stmt, "columns": columns, **info, "rows": rows.page,
                "stdout": render(rows, columns, csv_mode)}
        results.append(part)
    conn.close()

    out = dict(base)
    if failure:
        out.update({"ok": False, "returncode": 1, "stdout": "", "stderr": failure["error"], **failure, "complete": False})
        if results:
            out["completed_statements"] = results
        say(out, 1)
    out.update({"ok": True, "returncode": 0, "stderr": "", "complete": True})
    if len(results) == 1:
        out.update(results[0])
    else:
        out["results"] = results
        out["stdout"] = "".join(r["stdout"] for r in results)
    if any(r.get("truncated") for r in results):
        out["truncated"] = True
        out["note"] = "an inline page is not the result: the whole of it is in rows_file; read it to the end before concluding"
    print(json.dumps(out))


if __name__ == "__main__":
    main()

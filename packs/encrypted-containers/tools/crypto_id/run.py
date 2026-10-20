#!/usr/bin/env python3
"""Say which scheme a volume's or file's first bytes show, and what they do not.

A signature is a lead for a reader, not a finding about the data. This tool
recognises the signatures below from the first kilobytes at a byte offset, reads
the header fields that sit at fixed places in them, and names the reader that
establishes the rest. It parses no BitLocker protector, no LUKS2 keyslot, no APFS
volume flag and no document encryption structure, and it never turns "no
signature found" into "not encrypted".

    BitLocker        "-FVE-FS-" at offset 3 of the volume
    BitLocker To Go  a FAT header ("MSWIN4.1") with an FVE block in its first 4 KiB
    LUKS1 / LUKS2    "LUKS\\xba\\xbe" at offset 0, then the version (1 and 2 only)
    Core Storage     the signature at offset 88
    APFS container   "NXSB" at offset 32 (whether any volume is encrypted is not read)
    ZIP, 7-Zip, PDF, OLE compound file: recognised, with archive_probe as the reader
    no signature     high entropy over the sample is a lead, never an identification

LUKS1 (the LUKS1 on-disk specification): the 592-byte header is 208 bytes of fixed
fields, then eight key slots of 48 bytes: active (4), password iterations (4),
salt (32), key material offset in sectors (4), stripes (4); integers are big-endian.
LUKS2 (cryptsetup's luks2_hdr_disk): a 4096-byte binary header with the label at 24
(48 bytes) and the UUID at 168 (40 bytes), then a JSON area this tool does not read.

What it prints of the file: no raw bytes. The header's text fields are printed only
when they are what the format says they are: the cipher, mode and hash only from a
closed list of the names cryptsetup and the kernel use (anything else is "<unrecognised
header text withheld>"), the UUID only in the UUID form, the LUKS2 label and subsystem
through the SHARED NAMES block below (a part shaped like an identifier or a secret is
withheld). A file that may itself be a key (32 bytes is a usual key file size) is
therefore identified by its size and its entropy, never shown. The tool stops on SIGTERM,
SIGINT and SIGHUP with one JSON answer and the exit status 128 + the signal.
"""
import json
import math
import os
import re
import struct
import sys
from collections import Counter

PARSER = "crypto_id/3"
LUKS_MAGIC = b"LUKS\xba\xbe"
SLOT_ENABLED = 0x00AC71F3
SLOT_DISABLED = 0x0000DEAD
LUKS1_FIXED = 208
LUKS1_HEADER = 592
LUKS2_BINARY = 4096
HEAD_BYTES = 8192
MIN_SAMPLE = 1024
MAX_SAMPLE = 1 << 24



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


# BEGIN SHARED NAMES
# The same text is in recovery_key_scan, archive_probe and crypto_id (a pack test holds the copies equal). It decides what a name,
# a path, a header string or a diagnostic from evidence may show. Layer 1 (shown, withhold) cuts out of a string the spans that are
# shaped like an identifier or a secret and puts a fixed placeholder where each was (no length, no fragment); layer 2 (seal) reads
# every string of what is about to be printed or paged once more, by rules of its own, and replaces a string the first layer let
# through that still looks like a secret.
#
# WITHHELD, by shape: a recovery password (eight groups of six digits) in a path component, whole component; a run of 10 or more digits;
# a run of 8 or more letters and digits that has a digit in it; a letters-only run of 8 or more that is not one word, a camel-case
# word or all capitals; groups of 4 to 6 characters joined by one `-`, `_` or `.` (3 or more digit-only groups, or 4 or more groups that
# each hold a digit), and four or more groups of exactly six digits joined by spaces; the value after password, secret, token,
# api key, credential, auth (`password=...`); user-info; and the token shapes of the shared WITHHOLDING block above (vendor prefixes,
# JWT, long hex, long mixed runs, base64 with `/`). A string is also judged after NFKC and with invisible characters taken out, and a
# hit there that the string as written does not show withholds the whole string.
# NOT WITHHELD, by design: an identifier of 7 characters or fewer, a lowercase-only random run (it reads as a word), a secret that does
# not look like one, an all-capital letters-only run, groups of other sizes, and anything in the data a tool reads rather than prints.
# Measured on random draws and on real directory trees: tests/pack-encrypted-containers-names.test.ts and the manifests give the rates.
import unicodedata

NAMES = {"strings": 0, "replaced": 0}      # printed strings in which something was withheld; strings the output check replaced
RECOVERY_NAME = "<recovery-password-shaped name withheld>"
ID_TEXT = "<identifier-shaped text withheld>"
SECRET_TEXT = "<secret-shaped text withheld>"
LONG_TEXT = "<text too long to judge withheld>"
CHECKED = "<withheld by the output check>"
MAX_JUDGED = 1 << 16
_RECOVERY_SHAPE = re.compile(r"(?<![0-9])[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}(?![0-9])")
_SIX_SPACED = re.compile(r"(?<![0-9])(?:[0-9]{6} ){3,}[0-9]{6}(?![0-9])")
_GROUP = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{4,6}(?![A-Za-z0-9])")
_ALNUM_RUN = re.compile(r"[A-Za-z0-9]{8,}")
_WORDY = re.compile(r"[A-Z]?[a-z]+(?:[A-Z][a-z]+)*|[A-Z]+")
_NAMED = re.compile(r"(?i)(?<![A-Za-z0-9])(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)"
                    r"[A-Za-z0-9_-]{0,16}[ \t]*[=:][ \t]*([^\s\"'&;,/\\]+)")
_CACHE = {}


def _chains(text):
    """Spans of groups of 4 to 6 characters joined by one `-`, `_` or `.`: 3 or more digit-only groups, or 4 or more that each hold a digit."""
    chain = []
    for m in _GROUP.finditer(text):
        g = m.group()
        if chain and m.start() == chain[-1][1] + 1 and text[chain[-1][1]] in "-_." and any(c.isdigit() for c in g):
            chain.append((m.start(), m.end(), g.isdigit()))
            continue
        yield from _close(chain)
        chain = [(m.start(), m.end(), g.isdigit())] if any(c.isdigit() for c in g) else []
    yield from _close(chain)


def _close(chain):
    if len(chain) >= 4 or (len(chain) >= 3 and all(c[2] for c in chain)):
        yield chain[0][0], chain[-1][1]


def _runs(text):
    for m in _ALNUM_RUN.finditer(text):
        t = m.group()
        if t.isdigit():
            if len(t) >= 10:
                yield m.span()
        elif any(c.isdigit() for c in t) or _WORDY.fullmatch(t) is None:
            yield m.span()


def _spans(text):
    """(start, end, secret) of what a string shows that is shaped like an identifier (secret False) or like a secret (True), merged."""
    found = []
    for m in _NAMED.finditer(text):
        found.append((m.start(1), m.end(1), True))
    for rx in (_USERINFO, _BARE_USERINFO):
        for m in rx.finditer(text):
            found.append((m.start(), m.end(), True))
    for m in _SIX_SPACED.finditer(text):
        found.append((m.start(), m.end(), False))
    for a, b in list(token_spans(text)) + list(_chains(text)) + list(_runs(text)):
        found.append((a, b, False))
    found.sort()
    merged = []
    for a, b, secret in found:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b), merged[-1][2] or secret)
        else:
            merged.append((a, b, secret))
    return merged


def _fold(text):
    return unicodedata.normalize("NFKC", "".join(c for c in text if unicodedata.category(c) != "Cf"))


def _judge(text, whole):
    """(the text as it may be shown, whether anything was withheld). `whole`: a recovery-password shape withholds the whole string."""
    if len(text) < 6:
        return text, False
    if len(text) > MAX_JUDGED:
        return LONG_TEXT, True
    key = (text, whole)
    if key in _CACHE:
        return _CACHE[key]
    folded = _fold(text)
    hit = False
    if _RECOVERY_SHAPE.search(text) or _RECOVERY_SHAPE.search(folded):
        if whole:
            return _remember(key, (RECOVERY_NAME, True))
        text, hit = _RECOVERY_SHAPE.sub(RECOVERY_NAME, folded), True
        folded = text
    spans = _spans(text)
    if folded != text and sum(b - a for a, b, _s in _spans(folded)) > sum(b - a for a, b, _s in spans):
        return _remember(key, (ID_TEXT, True))
    if spans:
        parts, last = [], 0
        for a, b, secret in spans:
            parts.append(text[last:a])
            parts.append(SECRET_TEXT if secret else ID_TEXT)
            last = b
        parts.append(text[last:])
        text, hit = "".join(parts), True
    return _remember(key, (text, hit))


def _remember(key, out):
    if len(_CACHE) < 100000:
        _CACHE[key] = out
    return out


def withhold(text):
    """A string of evidence text (a header field, a diagnostic, a string from a header) as it may be printed."""
    if not isinstance(text, str):
        return text
    out, hit = _judge(text, False)
    if hit:
        NAMES["strings"] += 1
    return out


def shown(path, count=True):
    """A path or a member name as it may be printed: every component judged by itself, a separator kept."""
    if not isinstance(path, str):
        return path
    pieces = re.split(r"([/\\])", path)
    hit = False
    for i in range(0, len(pieces), 2):
        pieces[i], one = _judge(pieces[i], True)
        hit = hit or one
    if hit and count:
        NAMES["strings"] += 1
    return "".join(pieces)


# Layer 2: written apart from the rules above, over everything that is written. A string it finds suspect is replaced whole.
_CHECK_QUICK = re.compile(r"(?i)[0-9]{6}|PRIVATE KEY|[A-Za-z0-9+_=-]{24}|pass|pwd|secret|token|api[_-]?key")
_CHECK_DIGITS = re.compile(r"(?<![0-9])(?:[0-9]{6}[-_. ]?){8}(?![0-9])")
_CHECK_PEM = re.compile(r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY|PRIVATE KEY-----")
_CHECK_RUN = re.compile(r"[A-Za-z0-9+_=-]{24,}")
_CHECK_VALUE = re.compile(r"(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key)[A-Za-z0-9_-]{0,16}[ \t]*[=:][ \t]*[^\s\"'<>]{6,}")
OWN_KEYS = {"all_results", "values_file", "paths_note"}      # strings the tool made itself


_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _suspect(text):
    if not _CHECK_QUICK.search(text) or _UUID.fullmatch(text):
        return False
    if _CHECK_DIGITS.search(text) or _CHECK_PEM.search(text) or _CHECK_VALUE.search(text):
        return True
    for m in _CHECK_RUN.finditer(text):
        run = m.group()
        if re.fullmatch(r"[0-9a-fA-F]{32,}", run):
            return True
        flips = sum(1 for a, b in zip(run, run[1:]) if a.isdigit() != b.isdigit() and a.isalnum() and b.isalnum())
        if flips >= 6:
            return True
    return False


def seal(value, key=None):
    """The value with every string the check finds suspect replaced (a dict's keys too). Counted in NAMES['replaced']."""
    if isinstance(value, str):
        if key in OWN_KEYS or len(value) < 8 or not _suspect(value):
            return value
        NAMES["replaced"] += 1
        return CHECKED
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and len(k) >= 8 and _suspect(k):
                NAMES["replaced"] += 1
                k = CHECKED + "#%d" % NAMES["replaced"]
            out[k] = seal(v, k)
        return out
    if isinstance(value, (list, tuple)):
        return [seal(v, key) for v in value]
    return value
# END SHARED NAMES


# BEGIN SHARED STOP
# The same text is in recovery_key_scan, archive_probe and crypto_id (a pack test holds the copies equal). SIGTERM, SIGINT and SIGHUP end the
# tool with ONE JSON answer and the exit status 128 + the signal, with no traceback and no temporary file left. A tool that scans
# (cooperative) only notes the signal: the scan reads stop_wanted() between windows and files, finishes its pages and prints a partial
# answer. If it is not finished GRACE_SECONDS later (a read that never returns), or a second signal comes, the stop is hard: the cleanup
# steps run (a program the tool started is killed, a values file is closed), the temporary files of the pages are removed, the last word
# is printed and the process ends. The tool's own clock (set_deadline) is below the manifest's timeout.
import signal
import time

GRACE_SECONDS = 5
STOP = {"signal": None, "deadline": None, "limit": None, "last_word": None, "cooperative": False, "cleanup": [], "answered": False}


def set_deadline(seconds):
    STOP["limit"] = seconds
    STOP["deadline"] = time.monotonic() + seconds


def out_of_time():
    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"]


def stop_wanted():
    return STOP["signal"] is not None or out_of_time()


def stop_cause():
    if STOP["signal"] is not None:
        return "stopped by signal %d" % STOP["signal"]
    return "the time limit (max_seconds %s) was reached" % STOP["limit"]


def remove_pending_pages():
    """Remove the temporary file of every page that is still being written."""
    for page in list(globals().get("PAGES", [])):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def hard_stop(signum):
    for step in list(STOP["cleanup"]):
        try:
            step()
        except Exception:  # noqa: BLE001 - a cleanup step is best effort
            pass
    remove_pending_pages()
    if STOP["last_word"] and not STOP["answered"]:
        try:
            STOP["last_word"](signum)
        except Exception:  # noqa: BLE001
            pass
    os._exit(128 + signum)


def _on_stop_signal(signum, _frame):
    if STOP["cooperative"] and STOP["signal"] is None:
        STOP["signal"] = signum
        signal.alarm(GRACE_SECONDS)
        return
    hard_stop(STOP["signal"] or signum)


def _on_stop_alarm(_signum, _frame):
    hard_stop(STOP["signal"] or signal.SIGTERM)


def install_stop(last_word=None, cooperative=False):
    STOP["last_word"], STOP["cooperative"] = last_word, cooperative
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_stop_signal)
    signal.signal(signal.SIGALRM, _on_stop_alarm)


def interrupted_answer(signum, **extra):
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "interrupted",
                      "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer" % signum,
                      "signal": signum, **extra}), flush=True)


def emit(answer):
    """Print the answer once, with the stop signals held back until it is out, and leave with 128 + the signal if one was noted."""
    signal.alarm(0)
    held = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
    signal.pthread_sigmask(signal.SIG_BLOCK, held)
    STOP["answered"] = True
    text = json.dumps(seal(answer), indent=2, ensure_ascii=True)
    sys.stdout.write(text + "\n")
    sys.stdout.flush()
    if STOP["signal"] is not None:
        os._exit(128 + STOP["signal"])
# END SHARED STOP


UNRECOGNISED = "<unrecognised header text withheld>"
HASHES = ("sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512", "ripemd160", "rmd160", "whirlpool",
          "wp512", "md5", "blake2b-256", "blake2b-512", "blake2s-256", "streebog256", "streebog512", "sm3", "tgr192")
CIPHERS = ("aes", "serpent", "twofish", "anubis", "arc4", "blowfish", "camellia", "cast5", "cast6", "chacha20", "des", "des3_ede", "fcrypt",
           "khazad", "seed", "sm4", "tea", "xchacha12", "xchacha20", "xeta", "xtea", "aria", "kuznyechik", "lea")
_ALT = lambda names: "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))   # noqa: E731 - longest first
CIPHER_NAME = re.compile(_ALT(CIPHERS))
HASH_NAME = re.compile(_ALT(HASHES))
_MODES = ("ecb", "cbc", "ctr", "xts", "lrw", "cfb", "ofb", "gcm", "ccm", "cts", "plain64be", "plain64", "plain", "benbi", "null", "eboiv",
          "tcw", "random", "adiantum", "essiv(?::(?:%s))?" % _ALT(HASHES))
CIPHER_MODE = re.compile(r"(?:%s)(?:-(?:%s))*" % (_ALT(_MODES), _ALT(_MODES)))
UUID_FORM = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
WITHHELD_FIELDS = []


def fail(message, **extra):
    print(json.dumps(seal({"error": message, "status": "failed",
                           "status_basis": "the tool stopped with an error (see error); no scheme was identified", **extra}), ensure_ascii=True))
    raise SystemExit(1)


def describe(exc):
    return withhold("%s: %s" % (type(exc).__name__, getattr(exc, "strerror", None) or str(exc)))


def entropy(blob):
    if not blob:
        return 0.0
    total = len(blob)
    out = 0.0
    for count in Counter(blob).values():
        p = count / total
        out -= p * math.log2(p)
    return round(out, 3)


def text(raw):
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def closed(field, raw, pattern):
    """A header text field as it may be printed: only a name from the closed list; anything else is not printed."""
    value = text(raw)
    if value == "" or pattern.fullmatch(value):
        return value
    WITHHELD_FIELDS.append(field)
    return UNRECOGNISED


def uuid_text(field, raw):
    value = text(raw)
    if value == "" or UUID_FORM.fullmatch(value):
        return value
    WITHHELD_FIELDS.append(field)
    return UNRECOGNISED


def free_text(field, raw):
    """A header text field that is free text (a LUKS2 label or subsystem): printed through the withholding rules."""
    value = text(raw)
    shown_value = withhold(value)
    if shown_value != value:
        WITHHELD_FIELDS.append(field)
    return shown_value


def read_luks(head):
    if len(head) < 8:
        return {"scheme": "LUKS (version not readable)", "supported": None,
                "header_problem": "the file ends after %d bytes, before the version field is complete" % len(head),
                "basis": "the LUKS magic at offset 0",
                "next_reader": "cryptsetup luksDump, on a complete copy of the header",
                "not_determined": ["the LUKS version", "every header field"]}
    version, = struct.unpack_from(">H", head, 6)
    basis = "the LUKS magic at offset 0 and version %d at offset 6" % version
    if version == 1:
        out = {"scheme": "LUKS1", "version": 1, "basis": basis,
               "next_reader": "cryptsetup luksDump reads and validates the header",
               "not_determined": ["whether any key slot's key material is intact", "which secret opens a slot",
                                  "who added a slot or when"]}
        if len(head) >= LUKS1_FIXED:
            out["cipher"] = closed("cipher", head[8:40], CIPHER_NAME)
            out["cipher_mode"] = closed("cipher_mode", head[40:72], CIPHER_MODE)
            out["hash"] = closed("hash", head[72:104], HASH_NAME)
            out["payload_offset_sectors"], out["key_bytes"] = struct.unpack_from(">II", head, 104)
            out["uuid"] = uuid_text("uuid", head[168:208])
        if len(head) < LUKS1_HEADER:
            out["header_problem"] = ("the header is cut short: %d of %d bytes (the fixed fields and eight key slots), "
                                     "so the key-slot table was not read" % (len(head), LUKS1_HEADER))
            out["not_determined"].insert(0, "the key slots (the table was not read)")
            return out
        slots = []
        for i in range(8):
            at = LUKS1_FIXED + i * 48
            active, iterations = struct.unpack_from(">II", head, at)
            key_material_offset, stripes = struct.unpack_from(">II", head, at + 40)
            slots.append({"slot": i,
                          "state": "enabled" if active == SLOT_ENABLED else
                                   ("disabled" if active == SLOT_DISABLED else hex(active)),
                          "iterations": iterations,
                          "key_material_offset_sectors": key_material_offset,
                          "stripes": stripes})
        out["key_slots"] = slots
        out["enabled_slots"] = sum(1 for s in slots if s["state"] == "enabled")
        out["slot_note"] = ("An enabled slot is one unlock path in the metadata. It is not a count of distinct "
                            "passwords or people, and the header does not say who added it or when.")
        return out
    if version == 2:
        out = {"scheme": "LUKS2", "version": 2, "basis": basis,
               "next_reader": "cryptsetup luksDump (or --dump-json-metadata) reads the keyslots, digests, segments and tokens",
               "not_determined": ["the keyslots", "the digests", "the segments and where the data starts",
                                  "the tokens", "whether the second copy of the metadata agrees"]}
        if len(head) >= 264:
            out["header_size_bytes"], out["sequence_id"] = struct.unpack_from(">QQ", head, 8)
            out["label"] = free_text("label", head[24:72])
            out["checksum_alg"] = closed("checksum_alg", head[72:104], HASH_NAME)
            out["uuid"] = uuid_text("uuid", head[168:208])
            out["subsystem"] = free_text("subsystem", head[208:256])
        if len(head) < LUKS2_BINARY:
            out["header_problem"] = "the header is cut short: %d of %d bytes of the binary header" % (len(head), LUKS2_BINARY)
        out["note"] = ("LUKS2 keeps its keyslots, digests, segments and tokens as JSON after the 4096-byte binary "
                       "header; this tool reads the binary header only.")
        return out
    return {"scheme": "LUKS version %d (unsupported by this tool)" % version, "version": version, "supported": False,
            "basis": basis,
            "next_reader": "cryptsetup luksDump, from a build that supports this version",
            "not_determined": ["every header field: this version's layout is not read"]}


def identify(head, sample):
    if head[3:11] == b"-FVE-FS-":
        return {"scheme": "BitLocker", "basis": "\"-FVE-FS-\" at offset 3 of the volume",
                "next_reader": "bdeinfo (libbde) lists the key protectors, a clear key included, with no secret",
                "not_determined": ["the key protectors", "whether a clear key is present",
                                   "the encryption method and the volume's state"]}
    if head[0:6] == LUKS_MAGIC:
        return read_luks(head)
    if head[3:11] == b"MSWIN4.1" and b"-FVE-FS-" in head[:4096]:
        return {"scheme": "BitLocker To Go",
                "basis": "a FAT header (OEM \"MSWIN4.1\") with an FVE block in the first 4 KiB",
                "next_reader": "bdeinfo (libbde) on the BitLocker volume; the plain FAT discovery volume is why a "
                               "stick can look unencrypted",
                "not_determined": ["the key protectors", "whether the data area is the volume this header describes"]}
    if head[88:96] == b"CS\x00\x00\x00\x00\x00\x00":
        return {"scheme": "Apple Core Storage (the layout of legacy FileVault 2), possibly encrypted",
                "basis": "the Core Storage signature at offset 88",
                "next_reader": "fvdeinfo (libfvde), for the Core Storage layout; whether it reads an APFS volume is not established here",
                "not_determined": ["whether the logical volume is encrypted", "which recovery routes exist"]}
    if head[32:36] == b"NXSB":
        return {"scheme": "APFS container", "basis": "\"NXSB\" at offset 32",
                "next_reader": "fsapfsinfo (libfsapfs) lists the container's volumes; its documented limits apply",
                "not_determined": ["whether any volume in the container is encrypted",
                                   "the hardware the encryption depends on"]}
    if head[0:4] == b"\x50\x4b\x03\x04":
        return {"scheme": "ZIP container", "basis": "a ZIP local file header at offset 0",
                "next_reader": "archive_probe lists the members with per-member encryption",
                "not_determined": ["whether any member is encrypted"]}
    if head[0:6] == b"7z\xbc\xaf\x27\x1c":
        return {"scheme": "7-Zip container", "basis": "the 7-Zip signature at offset 0",
                "next_reader": "archive_probe, which lists through 7z where it is installed",
                "not_determined": ["whether the data or the header is encrypted"]}
    if head[0:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return {"scheme": "OLE compound file", "basis": "the compound file signature at offset 0",
                "next_reader": "archive_probe reports encryption markers as a heuristic; a structural document "
                               "reader is not provided by this pack",
                "not_determined": ["whether the document is encrypted", "which scheme it uses"]}
    if head[0:5] == b"%PDF-":
        return {"scheme": "PDF", "basis": "\"%PDF-\" at offset 0",
                "next_reader": "archive_probe reports encryption markers as a heuristic; a structural document "
                               "reader is not provided by this pack",
                "not_determined": ["whether the document is encrypted", "whether an opening password is required",
                                   "its permission restrictions"]}
    value = entropy(sample)
    leads = ["VeraCrypt or TrueCrypt", "a detached-header LUKS volume", "plain dm-crypt", "other ciphertext",
             "compressed or random data", "wiped or damaged space", "the wrong offset or the wrong storage layer"]
    if value >= 7.9 and not any(head[:16]):
        return {"scheme": "no signature, high entropy, header zeroed", "entropy": value,
                "basis": "no signature in the first bytes; Shannon entropy %.3f bits per byte over the sample" % value,
                "candidates": leads,
                "next_reader": "none: no reader for VeraCrypt or TrueCrypt is provided. The exhibit list, the "
                               "container's provenance and configuration traces are the corroboration",
                "not_determined": ["whether the data is encrypted", "which scheme, if so"]}
    if value >= 7.9:
        return {"scheme": "no signature, high entropy", "entropy": value,
                "basis": "no signature in the first bytes; Shannon entropy %.3f bits per byte over the sample" % value,
                "candidates": leads,
                "next_reader": "none: high entropy alone is not encryption; a compressed archive reads the same way",
                "not_determined": ["whether the data is encrypted", "which scheme, if so"]}
    return {"scheme": "no scheme this tool recognises", "entropy": value,
            "basis": "no signature in the first bytes; Shannon entropy %.3f bits per byte over the sample" % value,
            "next_reader": "file_type for other formats",
            "not_determined": ["whether the data is encrypted"]}


def last_word(signum):
    interrupted_answer(signum)


def main():
    install_stop(last_word, cooperative=False)
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=withhold(str(exc)))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a volume image, a partition or a file")
    if os.path.isdir(path):
        fail("path is a directory, not a file or an image", path=shown(path))
    if not os.path.isfile(path):
        fail("no such file", path=shown(path))
    offset = args.get("offset", 0) or 0
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        fail("offset must be a byte offset, not a sector offset", offset=args.get("offset") if isinstance(args.get("offset"), (int, float)) else None)
    window = args.get("entropy_sample", 65536)
    if not isinstance(window, int) or isinstance(window, bool) or window < MIN_SAMPLE:
        fail("entropy_sample must be an integer of at least %d" % MIN_SAMPLE)
    if window > MAX_SAMPLE:
        fail("entropy_sample must be at most %d (16 MiB)" % MAX_SAMPLE, entropy_sample=window)
    if "include_head_hex" in args:
        fail("include_head_hex was removed: this tool prints no raw bytes of the file, because a short file may itself be a key. "
             "Read the bytes you need with xxd or hexdump on the evidence copy, in the examiner's own session, and record where "
             "they came from, not what they are", include_head_hex="removed")

    try:
        size = os.path.getsize(path)
        if size == 0:
            fail("the file is empty", path=shown(path), bytes=0)
        if offset >= size:
            fail("the offset is past the end of the file", offset=offset, bytes=size)
        with open(path, "rb") as fh:
            fh.seek(offset)
            head = fh.read(HEAD_BYTES)
            sample = head
            if window > len(head):
                sample = head + fh.read(window - len(head))
            sample = sample[:window]
    except OSError as exc:
        fail("the file could not be read: %s" % describe(exc), path=shown(path))

    body = identify(head, sample)
    out = {"path": shown(path), "offset_bytes": offset, "bytes": size, "parser": PARSER, **body}
    out["entropy_sample_bytes"] = len(sample)
    if WITHHELD_FIELDS or NAMES["strings"]:
        out["header_fields_withheld"] = sorted(set(WITHHELD_FIELDS))
        out["withheld_note"] = ("A header text field that is not a name from the format's closed list (cipher, mode, hash), not in the "
                                "UUID form, or free text shaped like an identifier or a secret (a LUKS2 label or subsystem) is not printed. "
                                "cryptsetup luksDump on the evidence copy shows it to the examiner.")
    out["note"] = ("A signature identifies a candidate for a reader; it does not show the data is encrypted, intact or "
                   "openable, and no match does not show it is not. An unreadable volume is not necessarily encrypted: "
                   "rule out a logical volume manager, a damaged partition table and a wrong offset first. This tool "
                   "takes a BYTE offset, where mmls and the Sleuth Kit work in sectors. It prints no raw bytes of the file.")
    problem = out.get("header_problem") or (("an unsupported version: " + out["scheme"]) if out.get("supported") is False else None)
    out["status"] = "partial" if problem else "complete"
    out["status_basis"] = ("the signature was found but %s" % problem) if problem else \
        "the first %d bytes at the offset were read and checked against every signature this tool knows" % len(head)
    sealed = seal(out)
    if NAMES["replaced"]:
        sealed["output_check"] = {"replaced": NAMES["replaced"], "note": "a string the first layer let through was replaced by the output check"}
        sealed["status"] = "partial"
        sealed["status_basis"] += "; %d string(s) were replaced by the output check" % NAMES["replaced"]
    emit(sealed)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure, and never a traceback
        fail("unexpected failure: %s: %s" % (type(exc).__name__, withhold(str(exc))))

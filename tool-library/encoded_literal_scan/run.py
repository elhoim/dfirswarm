#!/usr/bin/env python3
"""encoded_literal_scan: find a known literal hidden in an encoding.

You know how a string starts (a token prefix, a name, the opening of a record)
and how it ends, and a plain search of a file or a memory image for it finds
nothing. This looks for it in the encodings people and malware hide text in,
and decodes what it finds without running any of it:

  base64   the literal's bytes, base64 text, at each of the three byte
           phases the text can start at (standard and URL-safe alphabets);
           the plain text may be UTF-8 (ASCII), UTF-16LE or UTF-16BE
  base32   the same in RFC 4648 base32, at each of five phases, any case
  hex      the bytes as hexadecimal digits, either case
  rot13    the text with its letters rotated (not tried when the marker has
           no letter)
  wide     the literal itself as UTF-16LE, UTF-16BE, UTF-32LE or UTF-32BE,
           at any byte alignment, checked character by character

How it works: the marker (and what the encoding does to it at each phase) is
searched for the way `grep` would; each place it is found has its own
surroundings read from the file, the run of encoded text around it is decoded
at every alignment it could have, and the decoded text is searched for
marker, up to max_body characters, closer. Only a decoded literal is ever
reported: a hit that decodes to nothing of the shape is listed as a marker
hit (it says where the encoded marker is), never with the text around it.

A literal is a candidate, not a finding: the text is what the bytes decode
to, and where they came from is for the examiner to say. The encoded text
around a hit is read up to 8192 bytes each side; a run that goes further is
marked context_capped, and a capped context cannot exclude a later suffix.
A hit's own full result goes to out_dir (the whole result, nothing cut); the
answer carries the counts and the first candidates.

Args, JSON on stdin:
  path            the file or memory image
  marker          how the literal starts: 4 to 64 printable ASCII characters
  closer          how it ends (default "}"): 1 to 16 printable ASCII characters
  max_body        the most characters between marker and closer (default 300)
  encodings       which of base64, base32, hex, rot13, wide (default all)
  out_dir         where the whole result goes (default work/<agent>/encoded_literal_scan)
  start, length   a byte window of the file, by where a hit begins
  chunk_bytes     the read size (default 8 MiB)
  budget_seconds  stop after this long, between two hits, and say where to
                  go on (default 90)
  max_hits        stop once this many marker hits are held (default 50000),
                  between two hits, and say where to go on: a marker that is
                  everywhere is not a search; give a more specific marker or
                  fewer encodings
  limit           the candidates shown in the answer (default 100)
"""
import base64
import binascii
import codecs
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

TOOL = "encoded_literal_scan"
ALL_ENCODINGS = ("base64", "base32", "hex", "rot13", "wide")
CONTEXT = 8192          # each side of a hit, for the encodings that decode a run
WIDE = ("utf-16le", "utf-16be", "utf-32le", "utf-32be")
B64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
B64URL = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
B32 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
HEX = b"0123456789abcdefABCDEF"
SUB = 256 * 1024         # the window a chunk is worked in, so that a stop can come between two hits
PLAIN_ENCODINGS = ("utf-8", "utf-16le", "utf-16be")   # what the decoded bytes may be text in


def fail(message, **extra):
    print(json.dumps({"ok": False, "error": message, **extra}))
    sys.exit(1)


def resolve_output(given):
    """Where `out_dir` lands, refusing anything outside the run directory, the
    read-only inputs, and ledger/ and tools/, which the harness owns."""
    root = Path.cwd().resolve()
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
    want = given if given is not None else (os.path.join(out, TOOL) if job and out else os.path.join("work", agent, TOOL))
    if not isinstance(want, str) or not want:
        fail("out_dir must be a path", got=given)
    dest = Path(want).resolve() if Path(want).is_absolute() else (root / want).resolve()
    if dest == root or root not in dest.parents:
        fail("out_dir must be a directory inside the run directory", out_dir=want)
    for owned in ("inputs", "ledger", "tools"):
        place = root / owned
        if dest == place or place in dest.parents:
            fail("out_dir cannot be under %s/" % owned, out_dir=want)
    if dest.exists() and not dest.is_dir():
        fail("out_dir is a file", out_dir=want)
    return dest


def whole(args, name, default, low, high):
    v = args.get(name)
    if v is None:
        v = default
    if isinstance(v, bool) or not isinstance(v, int) or not low <= v <= high:
        fail("%s must be a whole number from %d to %d" % (name, low, high), got=v)
    return v


def printable(args, name, default, low, high):
    v = args.get(name, default)
    if not isinstance(v, str) or not low <= len(v) <= high or not all(0x20 <= ord(c) < 0x7F for c in v):
        fail("%s must be %d to %d printable ASCII characters" % (name, low, high), got=v if isinstance(v, str) else type(v).__name__)
    return v


# --- the encoded forms of the marker -------------------------------------------------

def packed_pattern(marker_bytes, alphabet, bits_per_char, unit_bytes):
    """For each byte phase the text can start at in its group of `unit_bytes`,
    the base-N text the marker leaves: an anchor (the longest run of characters
    the marker alone fixes), how far into the pattern it lies, and the whole
    pattern as a regular expression (a character the marker fixes in part is a
    class of those it allows)."""
    out = []
    for phase in range(unit_bytes):
        bits = "?" * (phase * 8) + "".join("{:08b}".format(x) for x in marker_bytes) + "?" * 8
        tokens, literal = [], []
        for i in range(0, len(bits) - bits_per_char + 1, bits_per_char):
            q = bits[i:i + bits_per_char]
            if "?" not in q:
                c = bytes([alphabet[int(q, 2)]])
                tokens.append(re.escape(c))
                literal.append(c)
            elif "0" in q or "1" in q:
                allowed = bytes(alphabet[n] for n in range(len(alphabet)) if all(c == "?" or c == format(n, "0%db" % bits_per_char)[j] for j, c in enumerate(q)))
                tokens.append(b"[" + re.escape(allowed) + b"]")
                literal.append(None)
            else:
                tokens.append(None)
                literal.append(None)
        while tokens and tokens[0] is None:
            tokens.pop(0)
            literal.pop(0)
        while tokens and tokens[-1] is None:
            tokens.pop()
            literal.pop()
        runs, start = [], None
        for i, v in enumerate(literal + [None]):
            if v is not None and start is None:
                start = i
            if v is None and start is not None:
                runs.append((start, b"".join(literal[start:i])))
                start = None
        if not runs:
            fail("the marker is too short to anchor a search in this encoding")
        back, needle = max(runs, key=lambda r: len(r[1]))
        out.append({"phase": phase, "needle": needle, "back": back, "check": re.compile(b"".join(tokens)), "span": len(tokens)})
    return out


def build_specs(marker, encodings):
    specs = []
    for plain in PLAIN_ENCODINGS:
        raw = marker.encode(plain)
        if "base64" in encodings:
            standard = packed_pattern(raw, B64, 6, 3)
            for p in standard:
                specs.append({"kind": "base64", "plain": plain, "fold": None, "alphabet": "standard", **p})
            # The URL-safe alphabet writes + and / as - and _: a marker whose fixed
            # characters include one of them is another needle there.
            for p, q in zip(standard, packed_pattern(raw, B64URL, 6, 3)):
                if (p["needle"], p["check"].pattern) != (q["needle"], q["check"].pattern):
                    specs.append({"kind": "base64", "plain": plain, "fold": None, "alphabet": "url", **q})
        if "base32" in encodings:
            for p in packed_pattern(raw, B32, 5, 5):
                specs.append({"kind": "base32", "plain": plain, "fold": "upper", **p})
        if "hex" in encodings:
            hexed = raw.hex().encode()
            specs.append({"kind": "hex", "plain": plain, "fold": "lower", "phase": 0, "needle": hexed, "back": 0, "check": None, "span": len(hexed)})
    if "rot13" in encodings:
        rotated = codecs.encode(marker, "rot13")
        if rotated != marker:
            specs.append({"kind": "rot13", "plain": "utf-8", "fold": None, "phase": 0, "needle": rotated.encode("ascii"), "back": 0, "check": None, "span": len(rotated)})
    if "wide" in encodings:
        for enc in WIDE:
            raw = marker.encode(enc)
            specs.append({"kind": "wide", "plain": enc, "fold": None, "phase": 0, "needle": raw, "back": 0, "check": None, "span": len(raw)})
    return specs


# --- reading a hit's surroundings ------------------------------------------------------

def read_at(fd, n, offset):
    """Up to n bytes at offset, short only at the end of the file."""
    parts = []
    while n > 0:
        b = os.pread(fd, n, offset)
        if not b:
            break
        parts.append(b)
        n -= len(b)
        offset += len(b)
    return b"".join(parts)


def decoded_runs(run, kind):
    """The byte strings a run of encoded text can mean, at each alignment it could have had."""
    if kind == "base64":
        for shift in range(4):
            q = run[shift:]
            try:
                yield base64.b64decode(q[:len(q) // 4 * 4], altchars=b"-_", validate=True)
            except (binascii.Error, ValueError):
                continue
    elif kind == "base32":
        stripped_ok = (0, 2, 4, 5, 7)
        for shift in range(8):
            q = run[shift:].rstrip(b"=")
            for trim in range(8):
                z = q[:len(q) - trim] if trim else q
                if not z or len(z) % 8 not in stripped_ok:
                    continue
                try:
                    yield base64.b32decode(z + b"=" * ((-len(z)) % 8), casefold=True)
                except (binascii.Error, ValueError):
                    continue
    elif kind == "hex":
        for shift in range(2):
            q = run[shift:]
            try:
                yield bytes.fromhex(q[:len(q) // 2 * 2].decode("ascii"))
            except ValueError:
                continue


def literals_in(data, plain, literal):
    """The literals a byte string holds as text in `plain`, at each alignment the text could start at."""
    found = set()
    for alignment in ((0,) if plain == "utf-8" else (0, 1)):
        b = data[alignment:]
        if plain != "utf-8":
            b = b[:len(b) // 2 * 2]
        text = b.decode(plain, errors="replace")
        for value in literal.findall(text):
            try:
                if value.encode(plain) in b:
                    found.add(value)
            except UnicodeError:
                continue
    return found


def wide_literal(raw, enc, marker, closer, max_body):
    """The literal that opens raw (which starts with the marker in `enc`), read one
    character at a time: (text, status). Invalid scalars, NUL, CR and LF in the
    body, and a closer past max_body characters all end it without a literal."""
    unit = 2 if enc.startswith("utf-16") else 4
    decoder = codecs.getincrementaldecoder(enc)("strict")
    text = ""
    for i in range(0, len(raw) - unit + 1, unit):
        try:
            text += decoder.decode(raw[i:i + unit])
        except UnicodeDecodeError:
            return None, "invalid_scalar"
        if len(text) >= len(marker) + len(closer) and text.endswith(closer):
            return text, "complete"
        if len(text) > len(marker) and text[-1] in "\x00\r\n":
            return None, "excluded_character"
        if len(text) > len(marker) + max_body + len(closer):
            return None, "no_closer_within_max_body"
    return None, "truncated"


def inspect_hit(fd, size, spec, begin, marker, closer, max_body, literal):
    """One marker hit at `begin`: what it decodes to, and whether its context was cut short."""
    kind = spec["kind"]
    row = {"encoding": kind, "text_encoding": spec["plain"], "phase": spec["phase"], "offset": begin, "candidates": []}
    if spec.get("alphabet") == "url":
        row["alphabet"] = "url"
    if kind in ("base64", "base32", "hex"):
        alphabet = set({"base64": B64 + b"=_-", "base32": B32 + b"=", "hex": HEX}[kind])
        left = max(0, begin - CONTEXT)
        right = min(size, begin + CONTEXT + spec["span"])
        context = read_at(fd, right - left, left)
        if spec["fold"] == "upper":
            context = context.upper()
        at = begin - left
        if spec["check"] is not None:
            m = spec["check"].match(context, at)
            if m is None:
                row["status"] = "context_disagrees"
                return row
            end = m.end()
        else:
            end = at + spec["span"]
        lo, hi = at, end
        while lo > 0 and context[lo - 1] in alphabet:
            lo -= 1
        while hi < len(context) and context[hi] in alphabet:
            hi += 1
        row["context_capped"] = bool((lo == 0 and left > 0) or (hi == len(context) and right < size))
        found = set()
        for data in decoded_runs(context[lo:hi], kind):
            found |= literals_in(data, spec["plain"], literal)
        row["candidates"] = sorted(found)
    elif kind == "rot13":
        raw = read_at(fd, CONTEXT, begin)
        text = codecs.decode(raw.decode("utf-8", errors="replace"), "rot13")
        row["candidates"] = sorted(set(literal.findall(text)))
    else:  # wide
        unit = 2 if spec["plain"].startswith("utf-16") else 4
        raw = read_at(fd, unit * (len(marker) + max_body + len(closer) + 2), begin)
        text, status = wide_literal(raw, spec["plain"], marker, closer, max_body)
        row["status"] = status
        if text is not None:
            row["candidates"] = [text]
        row.pop("phase")
    row.setdefault("status", "literal" if row["candidates"] else "marker_only")
    return row


# --- the scan ----------------------------------------------------------------------------

def main():
    # The answer carries the literal as it was written, in whatever locale the VM has.
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    try:
        args = json.load(sys.stdin)
    except ValueError as e:
        fail("the arguments are not JSON", reason=str(e))
    if not isinstance(args, dict):
        fail("the arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the file or memory image to scan")
    if not os.path.isfile(path):
        fail("path is not a readable regular file", path=path)
    marker = printable(args, "marker", None, 4, 64) if "marker" in args else fail("marker is required: how the literal you look for starts (4 to 64 printable ASCII characters)")
    closer = printable(args, "closer", "}", 1, 16)
    max_body = whole(args, "max_body", 300, 1, 4096)
    encodings = args.get("encodings") or list(ALL_ENCODINGS)
    if not isinstance(encodings, list) or not encodings or any(e not in ALL_ENCODINGS for e in encodings):
        fail("encodings is a list drawn from %s" % ", ".join(ALL_ENCODINGS), got=encodings)
    chunk = whole(args, "chunk_bytes", 8 * 1024 * 1024, 4096, 1 << 28)
    limit = whole(args, "limit", 100, 1, 100000)
    max_hits = whole(args, "max_hits", 50000, 1, 10_000_000)
    size = os.path.getsize(path)
    start = whole(args, "start", 0, 0, 1 << 62)
    if start > size:
        fail("start is past the end of the file", start=start, size=size)
    end = min(size, start + whole(args, "length", size - start, 0, 1 << 62))
    budget = args.get("budget_seconds", 90)
    if isinstance(budget, bool) or not isinstance(budget, (int, float)) or budget <= 0:
        fail("budget_seconds must be a positive number", got=budget)
    out_dir = resolve_output(args.get("out_dir"))

    literal = re.compile(re.escape(marker) + r"[^\x00\r\n�]{0,%d}?" % max_body + re.escape(closer))
    specs = build_specs(marker, encodings)
    # What a pattern needs after the place it begins: the text of the widest, with room.
    overlap = max(s["span"] for s in specs) + 64
    out_dir.mkdir(parents=True, exist_ok=True)

    hits = []
    stopped = None
    began = time.monotonic()
    pos = start
    fd = os.open(path, os.O_RDONLY)

    def spent():
        """Why this call should stop now, or None."""
        if time.monotonic() - began >= budget:
            return "budget_seconds"
        if len(hits) >= max_hits:
            return "max_hits"
        return None

    try:
        while pos < end and stopped is None:
            if pos > start and spent():
                stopped = spent()
                break
            scan_end = min(end, pos + chunk)
            buf = read_at(fd, min(size, scan_end + overlap) - pos, pos)
            folded = {"upper": buf.upper(), "lower": buf.lower()}
            # A chunk is worked in windows of SUB bytes, and each window's hits in the order they
            # lie: a stop is checked after every place a hit begins, so one chunk full of them
            # cannot hold a call past its budget or its hit count, and what was done is exactly
            # what lies before next_start.
            sub = pos
            while sub < scan_end and stopped is None:
                sub_end = min(scan_end, sub + SUB)
                found = set()
                for index, spec in enumerate(specs):
                    hay = folded.get(spec["fold"], buf)
                    needle, back = spec["needle"], spec["back"]
                    hi = sub_end - pos + back + len(needle)
                    at = hay.find(needle, sub - pos + back, hi)
                    while at >= 0:
                        rel = at - back
                        if rel < sub_end - pos:
                            # The place the pattern begins must be the whole pattern here too.
                            if spec["check"] is None or spec["check"].match(hay, rel):
                                found.add((pos + rel, index))
                        at = hay.find(needle, at + 1, hi)
                ordered = sorted(found)
                i = 0
                while i < len(ordered):
                    begin = ordered[i][0]
                    while i < len(ordered) and ordered[i][0] == begin:
                        hits.append(inspect_hit(fd, size, specs[ordered[i][1]], begin, marker, closer, max_body, literal))
                        i += 1
                    why = spent()
                    nxt = ordered[i][0] if i < len(ordered) else sub_end
                    if why and nxt < end:
                        stopped, pos = why, nxt
                        break
                if stopped is None:
                    sub = sub_end
            if stopped is None:
                pos = scan_end
    finally:
        os.close(fd)

    hits.sort(key=lambda h: (h["offset"], h["encoding"], h["text_encoding"], h.get("phase", -1)))
    candidates = sorted({c for h in hits for c in h["candidates"]})
    complete = pos >= end
    result = {
        "ok": True,
        "tool": TOOL,
        "source": {"path": path, "bytes": size},
        "marker": marker,
        "closer": closer,
        "max_body": max_body,
        "window": {"start": start, "end": end},
        "scanned_to": pos,
        "complete": complete,
        **({} if complete else {
            "next_start": pos,
            "stopped_by": stopped,
            "stopped_hint": "every hit that begins before next_start is in this result; call again with start=next_start" + (", and a more specific marker or fewer encodings if it stops at once again" if stopped == "max_hits" else ""),
        }),
        "encodings": encodings,
        "chunk_bytes": chunk,
        "context_each_side": CONTEXT,
        "patterns": [{"encoding": s["kind"], **({"alphabet": s["alphabet"]} if s.get("alphabet") else {}), "text_encoding": s["plain"], "phase": s["phase"], "anchor_hex": s["needle"].hex()} for s in specs],
        "hit_count": len(hits),
        "hits_by_encoding": {k: sum(1 for h in hits if h["encoding"] == k) for k in sorted({h["encoding"] for h in hits})},
        "literal_hits": sum(1 for h in hits if h["candidates"]),
        "context_capped_hits": sum(1 for h in hits if h.get("context_capped")),
        "candidate_count": len(candidates),
        "candidates": candidates,
        "hits": hits,
        "seconds": round(time.monotonic() - began, 3),
        "limits": "Contiguous text in the named encodings only; no other cipher or transform, no text split by white space or across pages, nothing decrypted or run. A capped context cannot exclude a later suffix; a candidate is what the bytes decode to, not a finding.",
    }
    key = json.dumps([path, marker, closer, max_body, encodings, start, end], sort_keys=True)
    result_file = out_dir / ("%s-%s.json" % (TOOL, hashlib.sha256(key.encode()).hexdigest()[:12]))
    result_file.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    shown = {k: v for k, v in result.items() if k not in ("hits", "candidates", "patterns")}
    shown["candidates"] = candidates[:limit]
    if len(candidates) > limit:
        shown["candidates_shown"] = limit
    shown["literal_hit_offsets"] = [h["offset"] for h in hits if h["candidates"]][:limit]
    shown["result_file"] = os.path.relpath(result_file, Path.cwd())
    shown["result_file_holds"] = "every hit with its offset, encoding, phase and status, every candidate, and the patterns searched"
    print(json.dumps(shown, ensure_ascii=False))


if __name__ == "__main__":
    main()

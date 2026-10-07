#!/usr/bin/env python3
"""Catalogue an Android adb backup without extracting it.

An `.ab` file is a text header (the signature `ANDROID BACKUP`, a format version, a
compression flag and an encryption scheme) followed by a tar, compressed with zlib when the flag
says so, and encrypted when the scheme is not `none`. This reads the header and, for a payload
that is not encrypted, lists every member of the embedded tar; it extracts nothing.

    run.py detect --target T [--probe-out DIR]
    run.py run --target T --out DIR [--max-decompressed-bytes N]

What it does and does not read:

  Versions. Header versions 1 to 5 are read; any other version is `unsupported`, and nothing but
  the header is reported (status partial). The versions are those the format is known to have; the
  payload of an unencrypted backup is a plain tar after the header whichever it is.

  Encryption. `none` is listed. `AES-256` is the one scheme with a documented header layout (user
  salt, checksum salt, rounds, IV, master key blob); its header is parsed for its shape and its
  payload is NOT opened (no password is read or accepted). Any other scheme is `unsupported`. The
  salts, the IV and the master key blob are what an offline password attack starts from: backup.json
  reports their lengths and the rounds, never their values.

  Decompression is bounded. A zlib stream is read in pieces with an output budget
  (`--max-decompressed-bytes`, default 32 GiB): a payload that expands past it stops the listing and
  the run says partial, names the budget and the number of members listed. After the tar's end the
  rest of the zlib stream is read, within the same budget, so that its end marker and checksum are
  verified: `payload_stream` says reached, not_reached (the budget) or truncated.

  The tar is followed as it flows past, header by header, apart from the library that reads it: an
  extended header (a GNU long name, a pax header) that declares more than 16 MiB is not read, since the
  library would hold it whole in memory; and the archive is complete only when its end-of-archive
  block was seen (`tar_end`: reached or missing), so a backup cut at a member boundary is partial.

  A member name is kept as the tar reader returned it: tabs, newlines, backslashes and bytes that are
  not UTF-8 are escaped in `path`, and `path_b64` is the exact bytes of that name. The reader drops the
  trailing slash of a directory's name; `type` says it is a directory.
"""
import argparse
import base64
import datetime
import io
import json
import os
import re
import sys
import tarfile
import zlib

MAGIC = b"ANDROID BACKUP\n"
SUPPORTED_VERSIONS = (1, 2, 3, 4, 5)
DEFAULT_BUDGET = 32 << 30
PIECE = 1 << 20
EXTENDED_HEADER_LIMIT = 16 << 20
SCHEME_WORD = re.compile(r"[A-Za-z0-9._-]{1,16}\Z")
# Typeflags whose size is not followed by data: hard link, symbolic link, character and block device,
# directory, fifo. Every other flag (a regular file, a long name, a pax header, a vendor type) is followed
# by its size in bytes, as the tar library reads it.
NO_DATA_TYPES = set(b"123456")


class TarWatch:
    """Follows a tar stream header by header as its bytes flow past, apart from the library that reads it.

    It bounds what the library holds in memory (an extended header declaring more than the limit), sees
    whether the end-of-archive block came (the library stops quietly at a cut header or a garbled one), and
    follows the sizes the library follows: a pax `size` record overrides the header's, and a GNU sparse
    header may be followed by extension blocks before its data.
    """

    def __init__(self):
        self.block = bytearray()
        self.skip = 0
        self.position = 0
        self.ended = False
        self.end_at = None
        self.violation = None
        self.collect = 0           # bytes of a pax header still to gather
        self.collecting = None
        self.acc = bytearray()
        self.collect_padding = 0
        self.next_size = None      # a pax `size` for the next entry
        self.global_size = None    # one from a global pax header
        self.in_ext = False        # inside the extension blocks of a GNU sparse header
        self.after_ext = 0

    def feed(self, data):
        i, n = 0, len(data)
        while i < n and not self.ended and self.violation is None:
            if self.collect:
                take = min(self.collect, n - i)
                self.acc += data[i:i + take]
                self.collect -= take
                i += take
                self.position += take
                if not self.collect:
                    self.finish_pax()
                continue
            if self.skip:
                step = min(self.skip, n - i)
                self.skip -= step
                i += step
                self.position += step
                continue
            take = min(512 - len(self.block), n - i)
            self.block += data[i:i + take]
            i += take
            self.position += take
            if len(self.block) == 512:
                self.header(bytes(self.block))
                self.block.clear()
        if self.ended:
            self.position += n - i

    @staticmethod
    def pax_size(data):
        """The `size` of a pax header's records ("<length> <key>=<value>\\n"), or None."""
        size, pos = None, 0
        while pos < len(data):
            space = data.find(b" ", pos)
            if space < 0:
                break
            try:
                length = int(data[pos:space])
            except ValueError:
                break
            if length <= 0 or pos + length > len(data):
                break
            key, _, value = data[space + 1:pos + length - 1].partition(b"=")
            if key == b"size":
                try:
                    size = int(value)
                except ValueError:
                    pass
            pos += length
        return size

    def finish_pax(self):
        size = self.pax_size(bytes(self.acc))
        if self.collecting == ord("x"):
            self.next_size = size
        elif size is not None:
            self.global_size = size
        self.acc.clear()
        self.skip = self.collect_padding

    def header(self, block):
        if self.in_ext:
            if not block[504]:
                self.in_ext = False
                self.skip = self.after_ext
            return
        if block == b"\0" * 512:
            self.ended = True
            self.end_at = self.position - 512
            return
        flag = block[156]
        raw = block[124:136]
        try:
            size = int.from_bytes(bytes([raw[0] & 0x7F]) + raw[1:], "big") if raw[0] & 0x80 else int(raw.strip(b"\0 ") or b"0", 8)
        except ValueError:
            size = 0
        if flag in b"xg":
            if size > EXTENDED_HEADER_LIMIT:
                self.violation = size
                return
            self.collecting, self.collect, self.collect_padding = flag, size, -size % 512
            if not size:
                self.finish_pax()
            return
        if flag in b"LKX" and size > EXTENDED_HEADER_LIMIT:
            self.violation = size
            return
        if flag in NO_DATA_TYPES:
            self.next_size = None
            return
        if flag not in b"LK":
            # A pax `size` record is the size of the entry it precedes, over the header's own.
            if self.next_size is not None:
                size = self.next_size
            elif self.global_size is not None:
                size = self.global_size
            self.next_size = None
        padded = -(-size // 512) * 512
        if flag == ord("S") and block[482]:
            self.in_ext, self.after_ext = True, padded
        else:
            self.skip = padded


class ZlibReader(io.RawIOBase):
    """A zlib stream as a file: read in pieces, with an output budget, and its end checked."""

    def __init__(self, source, budget, watch):
        self.source = source
        self.watch = watch
        self.decoder = zlib.decompressobj()
        self.budget = budget
        self.produced = 0
        self.buffer = bytearray()
        self.pending = b""
        self.finished = False
        self.exceeded = False
        self.truncated = False
        self.trailing = 0

    def readable(self):
        return True

    def readinto(self, target):
        wanted = len(target)
        while len(self.buffer) < wanted and not self.finished:
            if self.produced >= self.budget:
                self.exceeded = True
                self.finished = True
                break
            if not self.pending and not self.decoder.eof:
                chunk = self.source.read(PIECE)
                if not chunk:
                    self.truncated = not self.decoder.eof
                    self.finished = True
                    break
                self.pending = chunk
            produced = self.decoder.decompress(self.pending, min(PIECE, self.budget - self.produced))
            self.pending = self.decoder.unconsumed_tail
            self.produced += len(produced)
            self.watch.feed(produced)
            if self.watch.violation is not None:
                # What the library would read next is an extended header too large to hold: the stream ends here.
                self.buffer.extend(produced)
                self.finished = True
                break
            self.buffer.extend(produced)
            if self.decoder.eof:
                # The end marker, and with it the Adler-32 checksum, was read: zlib raises on a mismatch.
                self.trailing = len(self.decoder.unused_data) + len(self.pending)
                self.finished = True
        count = min(wanted, len(self.buffer))
        target[:count] = self.buffer[:count]
        del self.buffer[:count]
        return count

    def drain(self):
        """Read the stream to its end (within the budget), so that its end marker is verified."""
        sink = bytearray(PIECE)
        while not self.finished:
            self.readinto(memoryview(sink))
            self.buffer.clear()


class Tap(io.RawIOBase):
    """An uncompressed payload as a file, followed by the same watch."""

    def __init__(self, source, watch):
        self.source = source
        self.watch = watch

    def readable(self):
        return True

    def readinto(self, target):
        if self.watch.violation is not None:
            return 0
        data = self.source.read(len(target))
        self.watch.feed(data)
        target[:len(data)] = data
        return len(data)

    def drain(self):
        """The rest of the payload after the library stopped, so that the watch sees it."""
        while self.watch.violation is None and not self.watch.ended:
            data = self.source.read(PIECE)
            if not data:
                break
            self.watch.feed(data)


def target_of(value):
    text = open(value, encoding="utf-8").read() if os.path.isfile(value) else value
    target = json.loads(text)
    paths = target.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return paths[0]


def line(handle, label):
    raw = handle.readline(4096)
    if not raw.endswith(b"\n"):
        raise ValueError("Android backup header has no complete %s line" % label)
    return raw[:-1].decode("ascii", "strict")


def label(text):
    """A header word that is printed: a short word of letters, digits and . _ - (a scheme name), and
    otherwise only its length: the line is evidence, and may hold anything."""
    if SCHEME_WORD.match(text):
        return text
    return "<not a scheme word: %d characters, not printed>" % len(text)


def header(handle):
    if handle.read(len(MAGIC)) != MAGIC:
        raise ValueError("no Android backup signature")
    version = line(handle, "version")
    compressed = line(handle, "compression")
    encryption = line(handle, "encryption")
    if not version.isdigit():
        raise ValueError("Android backup version is not numeric")
    if compressed not in ("0", "1"):
        raise ValueError("Android backup compression flag is not 0 or 1")
    details = {"version": int(version), "compressed": compressed == "1", "encryption": label(encryption)}
    details["version_supported"] = details["version"] in SUPPORTED_VERSIONS
    if encryption == "AES-256":
        # What an offline attack on the password starts from: the shape is reported, the values are not.
        fields = {"user_salt": line(handle, "user salt"), "checksum_salt": line(handle, "checksum salt"),
                  "rounds": line(handle, "rounds"), "user_iv": line(handle, "user IV"),
                  "master_key_blob": line(handle, "master key blob")}
        details["encryption_header"] = {
            "layout": "user salt, checksum salt, rounds, IV, master key blob (as the format documents it)",
            "user_salt_chars": len(fields["user_salt"]), "checksum_salt_chars": len(fields["checksum_salt"]),
            "rounds": int(fields["rounds"]) if fields["rounds"].isdigit() else None,
            "user_iv_chars": len(fields["user_iv"]), "master_key_blob_chars": len(fields["master_key_blob"]),
            "values_printed": False,
        }
    details["payload_offset"] = handle.tell()
    return details


def escaped(value):
    """One line, one field, nothing hidden; a byte that is not UTF-8 shows as \\xNN."""
    out = []
    for ch in value:
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


def b64(value):
    return base64.b64encode(value.encode("utf-8", "surrogateescape")).decode("ascii")


def utc(value):
    try:
        return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def member_type(member):
    if member.isfile():
        return "file"
    if member.isdir():
        return "dir"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    return "other"


def detect(path):
    try:
        with open(path, "rb") as handle:
            details = header(handle)
        return True, "Android backup header version %d, encryption %s" % (details["version"], details["encryption"])
    except (OSError, UnicodeError, ValueError) as exc:
        return False, str(exc)


def run(path, out, budget):
    os.makedirs(out, exist_ok=True)
    errors, limits_hit = [], []
    member_count = 0
    stream, tar_end = "not_applicable", "not_applicable"
    produced = 0
    with open(path, "rb") as source:
        details = header(source)
        with open(os.path.join(out, "backup.json"), "w", encoding="utf-8") as handle:
            json.dump(details, handle, indent=2, sort_keys=True)
            handle.write("\n")
        listable = details["encryption"] == "none" and details["version_supported"]
        members_path = os.path.join(out, "members.tsv")
        with open(members_path, "w", encoding="utf-8", newline="\n") as listing:
            listing.write("n\ttype\tpath\tbytes\tmtime_utc\tmode\tlink\tpath_b64\n")
            if listable:
                watch = TarWatch()
                reader = ZlibReader(source, budget, watch) if details["compressed"] else None
                tap = Tap(source, watch) if reader is None else None
                payload = io.BufferedReader(reader if reader is not None else tap)
                try:
                    with tarfile.open(fileobj=payload, mode="r|", encoding="utf-8", errors="surrogateescape") as archive:
                        for member in archive:
                            listing.write("%d\t%s\t%s\t%d\t%s\t%o\t%s\t%s\n" % (
                                member_count, member_type(member), escaped(member.name), member.size,
                                utc(member.mtime), member.mode, escaped(member.linkname or ""), b64(member.name)))
                            member_count += 1
                            archive.members = []
                except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
                    errors.append("embedded tar traversal stopped: %s" % exc)
                if watch.violation is None:
                    try:
                        (reader or tap).drain()
                    except zlib.error as exc:
                        errors.append("the zlib stream is damaged after the tar's end: %s" % exc)
                if reader is not None:
                    produced = reader.produced
                    if reader.exceeded:
                        stream = "not_reached"
                        limits_hit.append("decompressed output budget of %d bytes (the listing stopped after %d members)" % (budget, member_count))
                    elif reader.truncated:
                        stream = "truncated"
                        errors.append("the zlib stream ends before its end marker: the backup is cut short")
                    elif watch.violation is None:
                        stream = "reached"
                else:
                    stream = "not_compressed"
                if watch.violation is not None:
                    tar_end = "not_reached"
                    limits_hit.append("a tar extended header declares %d bytes, over the limit of %d: it is not read, and the listing stopped after %d members"
                                      % (watch.violation, EXTENDED_HEADER_LIMIT, member_count))
                elif watch.ended:
                    tar_end = "reached"
                elif not reader or not reader.exceeded:
                    tar_end = "missing"
                    errors.append("the tar ends without its end-of-archive block (after %d bytes of payload): the backup is cut short or damaged" % watch.position)
                else:
                    tar_end = "not_reached"
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write("file\twhat\n")
        handle.write("backup.json\tAndroid backup header fields and payload offset (key-derivation values are not printed)\n")
        handle.write("members.tsv\tevery embedded tar member when the payload is unencrypted and the version is supported\n")
    if not details["version_supported"]:
        status = "partial"
        covered = "header only; version %d is not one this recipe reads (1 to 5)" % details["version"]
        errors.append("unsupported: header version %d" % details["version"])
    elif details["encryption"] != "none":
        status = "partial"
        covered = "header only; encrypted payload not opened"
        if details["encryption"] == "AES-256":
            errors.append("payload encryption is AES-256; opening it needs a password, and this recipe reads none")
        else:
            errors.append("unsupported: payload encryption scheme %s" % details["encryption"])
    else:
        status = "partial" if errors or limits_hit else "complete"
        covered = "%d embedded tar members" % member_count
    coverage = {
        "recipe": "android-backup",
        "status": status,
        "covered": covered,
        "not_covered": "files excluded by adb backup policy, deleted data, artifact contents, password recovery",
        "limits_hit": limits_hit,
        "errors": errors,
        "payload_stream": stream,
        "tar_end": tar_end,
        "decompressed_bytes": produced,
    }
    with open(os.path.join(out, "coverage.json"), "w", encoding="utf-8") as handle:
        json.dump(coverage, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return coverage, member_count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    # The kickoff's census asks every detect step with --probe-out DIR, a
    # place for what the probe wants kept (evidence_catalog.py). Refused here,
    # it was a usage error (exit 2) for every input of a run, and a phone's
    # tar was catalogued as a member list only. Detect reads the backup's header
    # and keeps nothing, so the directory is taken and left empty.
    parser.add_argument("--probe-out")
    parser.add_argument("--max-decompressed-bytes", type=int, default=DEFAULT_BUDGET)
    args = parser.parse_args()
    try:
        path = target_of(args.target)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    if args.command == "detect":
        applies, why = detect(path)
        print(json.dumps({"applies": applies, "why": why}))
        return 0 if applies else 1
    if not args.out:
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    if args.max_decompressed_bytes < 1:
        print(json.dumps({"ok": False, "error": "--max-decompressed-bytes must be positive"}))
        return 2
    applies, why = detect(path)
    if not applies:
        print(json.dumps({"ok": False, "status": "unsupported", "why": why}))
        return 2
    try:
        coverage, members = run(path, args.out, args.max_decompressed_bytes)
    except (OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    print(json.dumps({"ok": True, "status": coverage["status"], "members": members}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

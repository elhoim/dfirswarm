#!/usr/bin/env python3
"""ad1_extract: write the files and folders of an AccessData AD1 logical image
out as a tree, each file inflated, hashed and checked against the digests the
image records, with a manifest of what went where.

Args, JSON on stdin:
  image     the image's first segment (.ad1); its further segments are
            looked for beside it (x.ad2, x.ad3, ...)
  members   item numbers (n) from the catalogue's members.tsv for this image
            (the ad1-items recipe); a folder's n takes its subtree. Default:
            every item
  out_dir   where the tree goes, a new or empty directory. Default: in a job
            ($OUT set) $OUT/<image name less .ad1>; called directly,
            work/<AGENT_ID>/ad1/<image name less .ad1>

Run it as a job (job_run tool=ad1_extract): what it writes is then sealed
into the store, citable as job:<id>/<path>, and the derived catalogue offers
each file to the recipes, so an archive, a disk image or an executable inside
the AD1 image is catalogued in turn.

Each item lands at out_dir/<its path in the image>. A name this file system
cannot hold as it is (empty, "." or "..", holding "/" or a NUL, not UTF-8,
past 255 bytes, or one a sibling already took, letter case and Unicode
normalisation aside) is written renamed, and the manifest,
out_dir/ad1_extract.tsv, names both (an item at the top named like the
manifest is renamed too):

    n  type  path  path_b64  written  size  sha256  check  note

`path` and `path_b64` are as ad1-items lists them; `written` is under
out_dir; `check` is ok, mismatch, no-stored-hash or not-read, as ad1-items
says it. A file whose content breaks part way is kept as <name>.partial,
holding what inflated, and says so. Nothing is written outside out_dir,
under inputs/, or outside the run directory (in a job, its $OUT).
"""
import base64
import hashlib
import json
import os
import sys
import unicodedata
from pathlib import Path

NAME_MAX = 255
SHOWN_ERRORS = 20
MANIFEST = "ad1_extract.tsv"
ERRORS = "ad1_extract.errors.txt"


# --- AD1 reader ---------------------------------------------------------------
# The same block in recipes/ad1-items/run.py and tools/ad1_extract/run.py;
# tests/ad1-pack.test.ts holds the two equal. An AccessData AD1 logical image
# (FTK Imager's "custom content image") as the public descriptions of the
# format lay it out (AD1-tools' libad1, pyad1):
#
#   every segment file   a header: "ADSEGMENTEDFILE", at 0x18 its index (from
#                        1), at 0x1c the number of segments, at 0x22 its size
#                        in 64 KiB fragments, at 0x28 the header's own size
#                        (512); then its share of the image's data
#   the image's data     one address space running on from segment to
#                        segment, each holding fragments * 65536 - header
#                        bytes of it; at address 0 the logical image header:
#                        "ADLOGICALIMAGE", +16 version, +24 zlib chunk size,
#                        +28 the image's own metadata, +36 the first item,
#                        +44 the data source name's length, +52 its address
#   an item              +0 next sibling, +8 first child, +16 first metadata
#                        entry, +24 chunk table, +32 size, +40 type (0 file,
#                        5 folder), +44 name length, +48 the name (UTF-8)
#   a metadata entry     +0 next, +8 category, +12 key, +16 length, +20 text
#   a chunk table        +0 count, +8 count + 1 addresses: chunk i is the
#                        zlib stream from address i to address i + 1
#
# Every address is held to the data the segments hold, every chain to one
# visit per address, every chunk to the chunk size and every file to its
# size: a damaged or hostile container is named, never followed.
import os as _os
import struct as _struct
import zlib as _zlib

AD1_SEGMENT_MAGIC = b"ADSEGMENTEDFILE\x00"
AD1_LOGICAL_MAGIC = b"ADLOGICALIMAGE"
AD1_ENCRYPTED_MAGIC = b"ADCRYPT"
AD1_FILE, AD1_FOLDER = 0, 5
AD1_NAME_MAX = 1 << 16
AD1_TEXT_MAX = 1 << 20
# Category and key of the metadata entries the descriptions name; anything
# else is kept as it is, by number.
AD1_LABELS = {
    (1, 0x5001): "md5", (1, 0x5002): "sha1", (1, 0x10002): "data source name",
    (2, 0x01): "item class (unknown key)", (2, 0x02): "item class",
    (3, 0x03): "file size", (3, 0x04): "allocated size", (3, 0x2002): "size (unknown key 0x2002)", (3, 0x2003): "size (unknown key 0x2003)",
    (4, 0x0D): "encrypted", (4, 0x0E): "compressed", (4, 0x1E): "flag (unknown key 0x1e)", (4, 0x1002): "hidden",
    (4, 0x1003): "flag (unknown key 0x1003)", (4, 0x1004): "read-only", (4, 0x1005): "archive",
    (5, 0x07): "accessed", (5, 0x08): "modified", (5, 0x09): "changed",
}
AD1_CLASSES = {b"1": "regular file", b"2": "placeholder", b"3": "folder", b"4": "file system metadata", b"6": "file slack", b"9": "symbolic link"}


class AD1Error(Exception):
    pass


def ad1_segment_header(head):
    """The segment header's fields from a file's first bytes, or an AD1Error."""
    if head.startswith(AD1_ENCRYPTED_MAGIC):
        raise AD1Error("an encrypted AD1 image (ADCRYPT header): it is read only once decrypted with its key")
    if len(head) < 0x30 or not head.startswith(AD1_SEGMENT_MAGIC):
        raise AD1Error("no ADSEGMENTEDFILE header")
    index, count = _struct.unpack_from("<II", head, 0x18)
    fragments = _struct.unpack_from("<I", head, 0x22)[0]
    header = _struct.unpack_from("<I", head, 0x28)[0]
    if not 0x30 <= header <= 0x10000:
        raise AD1Error("the segment header says it is %d bytes long" % header)
    if count < 1 or not 1 <= index <= count:
        raise AD1Error("the segment header says segment %d of %d" % (index, count))
    if fragments * 65536 <= header:
        raise AD1Error("the segment header says each segment holds %d fragments of 64 KiB" % fragments)
    return {"index": index, "count": count, "fragments": fragments, "header": header}


def ad1_segment_paths(first, count, given=()):
    """Segment k: the k-th path given, else the first's name with .ad<k> (its
    own case) beside it. The first must be named .ad1 for the rest to be found."""
    out = list(given[:count])
    stem, ext = _os.path.splitext(first)
    for k in range(len(out) + 1, count + 1):
        out.append(stem + ext[:-1] + str(k) if ext[1:3].lower() == "ad" and ext[3:] == "1" else None)
    return out


class AD1:
    """An AD1 image opened read-only from its first segment (and the paths of
    the rest, when given). `missing` names the segments that are not there;
    an address in one of them is an AD1Error where it is read."""

    def __init__(self, first, more=()):
        with open(first, "rb") as fh:
            head = fh.read(0x30)
        self.segment = ad1_segment_header(head)
        if self.segment["index"] != 1:
            raise AD1Error("segment %d of %d of an AD1 image: the image is read from its first segment" % (self.segment["index"], self.segment["count"]))
        self.margin = self.segment["header"]
        self.span = self.segment["fragments"] * 65536 - self.margin
        self.paths = ad1_segment_paths(first, self.segment["count"], [first] + list(more))
        self.files, self.missing = [], []
        for k, p in enumerate(self.paths, 1):
            fh = None
            if p and _os.path.isfile(p):
                fh = open(p, "rb")
                h = ad1_segment_header(fh.read(0x30))
                if h["index"] != k or h["count"] != self.segment["count"]:
                    fh.close()
                    raise AD1Error("%s says it is segment %d of %d, where segment %d of %d belongs" % (_os.path.basename(p), h["index"], h["count"], k, self.segment["count"]))
                size = _os.fstat(fh.fileno()).st_size
                if size - self.margin > self.span:
                    fh.close()
                    raise AD1Error("%s holds more than a segment's %d bytes of data" % (_os.path.basename(p), self.span))
            else:
                self.missing.append(_os.path.basename(p) if p else "segment %d (the first is not named .ad1)" % k)
            self.files.append(fh)
        self.end = self.segment["count"] * self.span
        self.walk_errors = []
        if self.read(0, 14) != AD1_LOGICAL_MAGIC:
            raise AD1Error("no ADLOGICALIMAGE header at the start of the image's data")
        (self.version,) = _struct.unpack("<I", self.read(16, 4))
        (self.chunk_size,) = _struct.unpack("<I", self.read(24, 4))
        self.meta_addr, self.first_item, name_len = _struct.unpack("<QQI", self.read(28, 20))
        (name_addr,) = _struct.unpack("<Q", self.read(52, 8))
        self.source_name = self.read(name_addr, name_len) if name_addr and name_len <= AD1_TEXT_MAX else b""

    def close(self):
        for fh in self.files:
            if fh:
                fh.close()

    def read(self, addr, n):
        """n bytes of the image's data from addr, across segments."""
        if addr < 0 or n < 0 or addr + n > self.end:
            raise AD1Error("address %d (+%d) is outside the image's data" % (addr, n))
        out = bytearray()
        while len(out) < n:
            k, off = divmod(addr + len(out), self.span)
            fh = self.files[k]
            if fh is None:
                raise AD1Error("address %d is in segment %d, which is not there (%s)" % (addr + len(out), k + 1, self.missing[0] if self.missing else "?"))
            want = min(n - len(out), self.span - off)
            got = _os.pread(fh.fileno(), want, self.margin + off)
            if len(got) < want:
                raise AD1Error("address %d (+%d) runs past the end of segment %d: the image is truncated" % (addr, n, k + 1))
            out += got
        return bytes(out)

    def metadata(self, addr):
        """[(category, key, text bytes, address)] of a metadata chain."""
        out, seen = [], set()
        while addr:
            if addr in seen:
                raise AD1Error("the metadata chain loops back to address %d" % addr)
            seen.add(addr)
            nxt, cat, key, length = _struct.unpack("<QIII", self.read(addr, 20))
            if length > AD1_TEXT_MAX:
                raise AD1Error("a metadata entry at address %d says it is %d bytes" % (addr, length))
            out.append((cat, key, self.read(addr + 20, length), addr))
            addr = nxt
        return out

    def walk(self):
        """Every item, depth first in the image's own order (an item, its
        children, then its next sibling), numbered from 0. A node that cannot
        be read ends its chain, and is named in walk_errors."""
        seen, n = set(), 0
        stack = [(self.first_item, (), None)]
        while stack:
            addr, parents, parent_n = stack.pop()
            if not addr:
                continue
            where = "/".join(p.decode("utf-8", "replace") for p in parents) or "the root"
            if addr in seen:
                self.walk_errors.append("the tree loops back to item address %d under %s: not followed" % (addr, where))
                continue
            seen.add(addr)
            try:
                nxt, child, meta, table, size, kind, name_len = _struct.unpack("<QQQQQII", self.read(addr, 48))
                if name_len > AD1_NAME_MAX:
                    raise AD1Error("its name is %d bytes long" % name_len)
                name = self.read(addr + 48, name_len)
                meta = self.metadata(meta)
            except AD1Error as e:
                self.walk_errors.append("item at address %d under %s cannot be read: %s; it and the siblings after it are not listed" % (addr, where, e))
                continue
            item = {"n": n, "addr": addr, "parent": parent_n, "parts": parents + (name,), "name": name, "type": kind,
                    "size": size, "table": table, "meta": meta}
            n += 1
            stack.append((nxt, parents, parent_n))
            stack.append((child, parents + (name,), item["n"]))
            yield item

    def chunks(self, item):
        """The compressed byte ranges of an item's content, from its chunk table."""
        if not item["table"]:
            if item["size"]:
                raise AD1Error("it has no chunk table for its %d bytes" % item["size"])
            return []
        (count,) = _struct.unpack("<Q", self.read(item["table"], 8))
        most = (item["size"] + self.chunk_size - 1) // self.chunk_size if self.chunk_size else item["size"]
        if count > max(most, 1):
            raise AD1Error("its chunk table lists %d chunks for %d bytes" % (count, item["size"]))
        at = _struct.unpack("<%dQ" % (count + 1), self.read(item["table"] + 8, 8 * (count + 1)))
        ranges = []
        for i in range(count):
            if at[i + 1] < at[i] or at[i + 1] > self.end:
                raise AD1Error("its chunk %d runs from address %d to %d" % (i, at[i], at[i + 1]))
            ranges.append((at[i], at[i + 1]))
        return ranges

    def content(self, item):
        """An item's content, chunk by chunk, each inflated within the chunk
        size; an AD1Error when a chunk does not inflate whole or the content
        is not the item's size."""
        bound = self.chunk_size or (1 << 26)
        total = 0
        for i, (start, end) in enumerate(self.chunks(item)):
            z = _zlib.decompressobj()
            try:
                block = z.decompress(self.read(start, end - start), bound + 1)
            except _zlib.error as e:
                raise AD1Error("its chunk %d does not inflate: %s" % (i, e))
            if len(block) > bound or z.unconsumed_tail:
                raise AD1Error("its chunk %d inflates past the chunk size of %d" % (i, bound))
            if not z.eof or z.unused_data:
                raise AD1Error("its chunk %d is not one whole zlib stream" % i)
            total += len(block)
            if total > item["size"]:
                raise AD1Error("its content runs past its size of %d bytes" % item["size"])
            yield block
        if total != item["size"]:
            raise AD1Error("its content is %d bytes, not its size of %d" % (total, item["size"]))


def ad1_text(meta, cat, key):
    """The text of the first metadata entry with this category and key, or None."""
    for c, k, v, _a in meta:
        if c == cat and k == key:
            return v
    return None
# --- end of the AD1 reader ----------------------------------------------------


def fail(message, **extra):
    print(json.dumps({"ok": False, "error": message, **extra}))
    raise SystemExit(1)


def esc(raw):
    """A name for a reader: one line, one field, nothing hidden (as ad1-items writes it)."""
    out = []
    for ch in raw.decode("utf-8", "surrogateescape"):
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


def resolve_output(out):
    """Where `out` really lands, links resolved first: inside the run
    directory (not the run directory itself) or, in a job, its $OUT; never
    under inputs/."""
    root = Path.cwd().resolve()
    dest = Path(out).resolve() if Path(out).is_absolute() else (root / out).resolve()
    job_out = Path(os.environ["OUT"]).resolve() if os.environ.get("OUT") and os.environ.get("JOB_ID") else None
    inside = (dest != root and root in dest.parents) or (job_out is not None and (dest == job_out or job_out in dest.parents))
    if not inside:
        fail("out_dir must be inside the run directory (not the run directory itself), or in a job its $OUT", out_dir=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("out_dir cannot be under inputs/", out_dir=str(out))
    return dest


def fold(name):
    return unicodedata.normalize("NFC", name).casefold()


def safe_name(raw):
    """A name this file system holds, and whether it had to change."""
    try:
        text = raw.decode("utf-8")
        changed = False
    except UnicodeDecodeError:
        text = "".join(ch if not 0xDC80 <= ord(ch) <= 0xDCFF else "%%%02X" % (ord(ch) - 0xDC00) for ch in raw.decode("utf-8", "surrogateescape"))
        changed = True
    if "/" in text or "\x00" in text:
        text = text.replace("%", "%25").replace("/", "%2F").replace("\x00", "%00")
        changed = True
    if text in ("", ".", ".."):
        text = "%2E" * len(text) if text else "%"
        changed = True
    if len(text.encode("utf-8")) > NAME_MAX:
        digest = hashlib.sha256(raw).hexdigest()[:16]
        keep = text.encode("utf-8")[:NAME_MAX - 18].decode("utf-8", "ignore")
        text = "%s~%s" % (keep, digest)
        changed = True
    return text, changed


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as e:
        fail("arguments are JSON on stdin: %s" % e)
    image = args.get("image")
    if not isinstance(image, str) or not image:
        fail("image is required: the AD1 image's first segment (.ad1)")
    members = args.get("members")
    if members is not None and (not isinstance(members, list) or not all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in members)):
        fail("members is a list of item numbers (n from the catalogue's members.tsv)")
    if members == []:
        fail("members is empty: leave it out to take every item")
    stem = os.path.basename(image)
    if stem.lower().endswith(".ad1"):
        stem = stem[:-4]
    in_job = bool(os.environ.get("OUT") and os.environ.get("JOB_ID"))
    out_arg = args.get("out_dir") or (os.path.join(os.environ["OUT"], stem) if in_job else os.path.join("work", os.environ.get("AGENT_ID") or "ad1", "ad1", stem))
    out = resolve_output(out_arg)
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        fail("out_dir already holds something: name a new or empty directory", out_dir=str(out_arg))
    try:
        img = AD1(image)
    except AD1Error as e:
        fail("not an AD1 image this tool reads: %s" % e, image=image)
    except OSError as e:
        fail("cannot read %s: %s" % (image, e.strerror or e))
    out.mkdir(parents=True, exist_ok=True)
    want = set(members) if members is not None else None
    errors = ["the image has %d segments and %s not beside the first: what lies in them is not read" % (img.segment["count"], ", ".join(img.missing))] if img.missing else []
    written_dir = {}   # item n -> where its children go under out (relative)
    # The manifest's own names, at the top of out_dir, are not an item's.
    taken = {"": {fold(MANIFEST), fold(ERRORS)}}  # directory (relative) -> folded names already used there
    selected = {}      # item n -> whether it is taken
    seen_n = set()
    counts = {"items": 0, "files": 0, "folders": 0, "bytes": 0, "renamed": 0, "mismatches": 0, "checked": 0}
    with open(out / MANIFEST, "x", encoding="utf-8", newline="\n") as man:
        man.write("n\ttype\tpath\tpath_b64\twritten\tsize\tsha256\tcheck\tnote\n")
        try:
            for item in img.walk():
                n = item["n"]
                seen_n.add(n)
                parent_dir = written_dir.get(item["parent"], "") if item["parent"] is not None else ""
                name, changed = safe_name(item["name"])
                # Two names one file system takes for one (letter case,
                # Unicode normalisation on APFS): the later is renamed.
                used = taken.setdefault(parent_dir, set())
                if fold(name) in used:
                    name, changed = "%s~n%d" % (name, n), True
                used.add(fold(name))
                rel = os.path.join(parent_dir, name) if parent_dir else name
                is_dir = item["type"] == AD1_FOLDER
                take = want is None or n in want or (item["parent"] is not None and selected.get(item["parent"], False))
                # A file's children (a stream, say) go beside it, in a directory of their own.
                written_dir[n] = rel if is_dir else rel + ".ad1-children"
                selected[n] = take
                if not take:
                    continue
                raw_path = b"/".join(item["parts"])
                notes = ["renamed"] if changed else []
                counts["items"] += 1
                counts["renamed"] += changed
                dest = out / rel
                try:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    if is_dir:
                        dest.mkdir(exist_ok=True)
                except OSError as e:
                    errors.append("item %d (%s): cannot be written at %s: %s" % (n, esc(raw_path), esc(rel.encode()), e.strerror or e))
                    continue
                if is_dir:
                    counts["folders"] += 1
                    man.write("%d\tdir\t%s\t%s\t%s\t\t\t\t%s\n" % (n, esc(raw_path), base64.b64encode(raw_path).decode(), esc(rel.encode()), ",".join(notes)))
                    continue
                md5 = (ad1_text(item["meta"], 1, 0x5001) or b"").strip().decode("ascii", "replace").lower()
                sha1 = (ad1_text(item["meta"], 1, 0x5002) or b"").strip().decode("ascii", "replace").lower()
                hs = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
                size, check = 0, ""
                try:
                    fh = open(dest, "xb")
                except OSError as e:
                    errors.append("item %d (%s): cannot be written at %s: %s" % (n, esc(raw_path), esc(rel.encode()), e.strerror or e))
                    continue
                with fh:
                    try:
                        for block in img.content(item):
                            fh.write(block)
                            size += len(block)
                            for h in hs:
                                h.update(block)
                    except AD1Error as e:
                        check = "not-read"
                        errors.append("item %d (%s): %s" % (n, esc(raw_path), e))
                if check == "not-read":
                    part = dest.with_name(dest.name + ".partial")
                    if not part.exists():
                        os.replace(dest, part)
                        rel += ".partial"
                    notes.append("partial: %d of %d bytes inflated" % (size, item["size"]))
                elif not md5 and not sha1:
                    check = "no-stored-hash"
                elif (md5 and md5 != hs[0].hexdigest()) or (sha1 and sha1 != hs[1].hexdigest()):
                    check = "mismatch"
                    counts["mismatches"] += 1
                else:
                    check = "ok"
                counts["checked"] += check in ("ok", "mismatch", "no-stored-hash")
                counts["files"] += 1
                counts["bytes"] += size
                man.write("%d\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n" % (n, "file" if item["type"] == AD1_FILE else "other:%d" % item["type"], esc(raw_path),
                                                                  base64.b64encode(raw_path).decode(), esc(rel.encode()), size,
                                                                  hs[2].hexdigest() if check != "not-read" else "", check, ",".join(notes)))
        finally:
            img.close()
    errors += img.walk_errors
    if want is not None:
        absent = sorted(want - seen_n)
        if absent:
            errors.append("no item %s in this image (it holds %d items)" % (", ".join(map(str, absent)), len(seen_n)))
    result = {"ok": not errors, "image": image, "out_dir": str(out_arg), "manifest": os.path.join(str(out_arg), MANIFEST),
              **counts, "segments_missing": img.missing}
    if errors:
        result["errors"] = errors[:SHOWN_ERRORS]
        result["errors_total"] = len(errors)
        if len(errors) > SHOWN_ERRORS:
            with open(out / ERRORS, "x", encoding="utf-8") as fh:
                fh.write("\n".join(errors) + "\n")
            result["errors_file"] = os.path.join(str(out_arg), ERRORS)
    if not in_job:
        result["note"] = "written where you called it, not sealed: run it as a job (job_run tool=ad1_extract) to have the files sealed into the store, citable as job:<id>/<path>, and catalogued by the derived catalogue"
    print(json.dumps(result))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())

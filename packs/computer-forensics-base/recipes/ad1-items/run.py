#!/usr/bin/env python3
"""ad1-items: the item list of an AccessData AD1 logical image, each file's
content inflated to check the digests the image records; nothing extracted.

    run.py detect --target TARGET [--probe-out DIR]   exit 0 applies, 1 does not, 2 error
    run.py run --target TARGET --out DIR              members.tsv, attributes.tsv, image.json,
                                                      index.tsv and coverage.json in DIR

TARGET is JSON (inline or a file path): {"paths": [...], "ref": ..., "name": ...};
the image is paths[0], its first segment; paths[1:] are its further segments
when given, else they are looked for beside it (x.ad2, x.ad3, ...). Every
item is one row of members.tsv:

    n  type  path  path_b64  size  packed  mtime  tz  mode  uid  gid  link  locator  flags
    atime  ctime  md5  sha1  sha256  check  class

The first fourteen columns are archive-members' own, so catalog_search
which=members and a member:<generation>#<n> reference read it the same way.
`n` counts from 0 in the image's own order (an item, its children, then its
next sibling) and is what ad1_extract takes; a folder's n takes its subtree.
`path` is the item's names joined by "/", escaped as archive-members escapes
them, and `path_b64` its exact bytes. `size` is the content's size, `packed`
the bytes of its zlib chunks. The times are the image's own text, accessed,
modified and changed (as the public descriptions name the third key), with
no zone the image records: `tz` is unknown. `md5` and `sha1` are the digests
the image records for the item; `sha256` is of the content as this recipe
inflated it; `check` says whether that content matches the recorded digests:
ok, mismatch, no-stored-hash, or not-read (why is in coverage.json). `class`
is the item class the image records (regular file, folder, file slack, ...).
`flags` names what an examiner should know first: escapes-root (a name that
is empty, "." or "..", or holds a "/"), name-not-utf8, hash-mismatch, and
encrypted (the source file system's encryption flag: the content may be
ciphertext). attributes.tsv holds every metadata entry of every item (n,
category, key, label, text), so nothing the image records is left out, and
image.json the segment and logical image headers and the image's own
metadata (its data source name).
"""
import base64
import hashlib
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
COLUMNS = ["n", "type", "path", "path_b64", "size", "packed", "mtime", "tz", "mode", "uid", "gid", "link", "locator", "flags",
           "atime", "ctime", "md5", "sha1", "sha256", "check", "class"]


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


def limits():
    try:
        lim = json.load(open(os.path.join(HERE, "recipe.json"))).get("limits", {})
    except Exception:
        lim = {}
    return int(os.environ.get("RECIPE_SECONDS") or lim.get("seconds") or 3600)


def target_of(arg):
    text = open(arg, encoding="utf-8").read() if os.path.isfile(arg) else arg
    t = json.loads(text)
    paths = t.get("paths") or []
    if not paths or not all(isinstance(p, str) for p in paths):
        raise SystemExit(json.dumps({"ok": False, "error": "the target names no path"}))
    return t, paths


def esc(raw):
    """A name or a text for a reader: one line, one field, nothing hidden."""
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


STAMP = re.compile(rb"^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(\.\d+)?$")


def stamp(raw):
    """The image's time text (20231004T101112.123456) as ISO 8601 with no zone; any other text as it is."""
    if raw is None:
        return ""
    m = STAMP.match(raw.strip())
    if not m:
        return esc(raw)
    g = [x.decode() for x in m.groups(b"")]
    return "%s-%s-%sT%s:%s:%s%s" % tuple(g)


def detect(path):
    """(format, why) or (None, why), from the headers alone."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(0x30)
            seg = ad1_segment_header(head)
            if seg["index"] != 1:
                return None, "segment %d of %d of an AD1 image: the image is read, and catalogued, from its first segment (.ad1)" % (seg["index"], seg["count"])
            fh.seek(seg["header"])
            logical = fh.read(20)
    except OSError as e:
        return None, "unreadable: %s" % (e.strerror or e)
    except AD1Error as e:
        return None, str(e)
    if not logical.startswith(AD1_LOGICAL_MAGIC):
        return None, "an ADSEGMENTEDFILE header with no ADLOGICALIMAGE header after it"
    version = int.from_bytes(logical[16:20], "little")
    if version != 4:
        return None, "an AD1 logical image of version %d: this recipe reads version 4" % version
    return "AD1", "an AD1 logical image (version 4, segment 1 of %d)" % seg["count"]


def row_of(img, item, w, deadline, cov):
    meta = item["meta"]
    raw_path = b"/".join(item["parts"])
    flags = []
    try:
        item["name"].decode("utf-8")
    except UnicodeDecodeError:
        flags.append("name-not-utf8")
    if any(p in (b"", b".", b"..") or b"/" in p for p in item["parts"]):
        flags.append("escapes-root")
    if (ad1_text(meta, 4, 0x0D) or b"").strip().lower() == b"true":
        flags.append("encrypted")
    kind = "dir" if item["type"] == AD1_FOLDER else "file" if item["type"] == AD1_FILE else "other:%d" % item["type"]
    # As recorded, escaped as any text is: a field never breaks the row.
    md5 = esc((ad1_text(meta, 1, 0x5001) or b"").strip()).lower()
    sha1 = esc((ad1_text(meta, 1, 0x5002) or b"").strip()).lower()
    packed, sha256, check = "", "", ""
    try:
        ranges = img.chunks(item)
        packed = sum(e - s for s, e in ranges) if item["table"] else ""
    except AD1Error as e:
        ranges = None
        cov["errors"].append("item %d (%s): %s" % (item["n"], esc(raw_path), e))
    if item["type"] != AD1_FOLDER:
        if ranges is None:
            check = "not-read"
        elif time.monotonic() > deadline:
            check = "not-read"
            cov["unread_at_limit"] += 1
        else:
            hs = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
            try:
                for block in img.content(item):
                    for h in hs:
                        h.update(block)
                sha256 = hs[2].hexdigest()
                if not md5 and not sha1:
                    check = "no-stored-hash"
                elif (md5 and md5 != hs[0].hexdigest()) or (sha1 and sha1 != hs[1].hexdigest()):
                    check = "mismatch"
                    flags.append("hash-mismatch")
                    cov["mismatches"].append(item["n"])
                else:
                    check = "ok"
                cov["checked"] += 1
            except AD1Error as e:
                check = "not-read"
                cov["errors"].append("item %d (%s): %s" % (item["n"], esc(raw_path), e))
    klass = ad1_text(meta, 2, 0x02)
    w.write("\t".join(str(v) for v in (
        item["n"], kind, esc(raw_path), base64.b64encode(raw_path).decode("ascii"), item["size"], packed,
        stamp(ad1_text(meta, 5, 0x08)), "unknown", "", "", "", "", "ad1:item=%d" % item["addr"], ",".join(flags),
        stamp(ad1_text(meta, 5, 0x07)), stamp(ad1_text(meta, 5, 0x09)), md5, sha1, sha256, check,
        AD1_CLASSES.get((klass or b"").strip(), esc(klass or b"")))) + "\n")
    cov["folders" if item["type"] == AD1_FOLDER else "files"] += 1


def label(cat, key):
    return AD1_LABELS.get((cat, key), "")


def run(target, paths, out_dir):
    deadline = time.monotonic() + limits() * 0.9
    os.makedirs(out_dir, exist_ok=True)
    cov = {"recipe": "ad1-items", "target": paths[0], "format": "AD1", "items": 0, "files": 0, "folders": 0, "checked": 0,
           "mismatches": [], "unread_at_limit": 0, "segments_missing": [],
           "covered": "every item of the image's tree, with its metadata, and each file's content inflated and checked against the digests the image records",
           "not_covered": "anything the imager did not put in the image (a logical image holds no unallocated space, and slack only where it was taken as an item); files inside the files; an encrypted (ADCRYPT) image",
           "limits_hit": [], "errors": []}

    def finish(status, code):
        cov["status"] = status
        json.dump(cov, open(os.path.join(out_dir, "coverage.json"), "w"), indent=2)
        print(json.dumps({"ok": code == 0, "status": status, "format": "AD1", "items": cov["items"]}))
        return code

    try:
        img = AD1(paths[0], paths[1:])
    except AD1Error as e:
        cov["why"] = str(e)
        return finish("unsupported", 2)
    except OSError as e:
        cov["errors"].append("%s: %s" % (paths[0], e.strerror or e))
        return finish("failed", 2)
    cov["segments_missing"] = img.missing
    if img.missing:
        cov["errors"].append("the image has %d segments and %s %s not beside the first: what lies in them is not read"
                             % (img.segment["count"], ", ".join(img.missing), "is" if len(img.missing) == 1 else "are"))
    try:
        with open(os.path.join(out_dir, "members.tsv"), "w", encoding="utf-8", newline="\n") as w, \
                open(os.path.join(out_dir, "attributes.tsv"), "w", encoding="utf-8", newline="\n") as a:
            w.write("\t".join(COLUMNS) + "\n")
            a.write("n\tcategory\tkey\tlabel\ttext\n")
            for item in img.walk():
                row_of(img, item, w, deadline, cov)
                for cat, key, text, _addr in item["meta"]:
                    a.write("%d\t%d\t0x%x\t%s\t%s\n" % (item["n"], cat, key, label(cat, key), esc(text)))
                cov["items"] += 1
        cov["errors"] += img.walk_errors
        try:
            own = [{"category": c, "key": "0x%x" % k, "label": label(c, k), "text": esc(t)} for c, k, t, _a in img.metadata(img.meta_addr)]
        except AD1Error as e:
            own = []
            cov["errors"].append("the image's own metadata: %s" % e)
        segs = []
        for k, p in enumerate(img.paths, 1):
            present = bool(p) and img.files[k - 1] is not None
            segs.append({"segment": k, "name": os.path.basename(p) if p else None, "present": present,
                         **({"bytes": os.path.getsize(p)} if present else {})})
        json.dump({"format": "AD1", "segment_header": img.segment, "segments": segs,
                   "logical_image": {"version": img.version, "chunk_size": img.chunk_size, "first_item": img.first_item, "metadata": img.meta_addr},
                   "data_source_name": esc(img.source_name), "metadata": own,
                   "items": cov["items"], "files": cov["files"], "folders": cov["folders"]},
                  open(os.path.join(out_dir, "image.json"), "w"), indent=2, ensure_ascii=False)
    finally:
        img.close()
    if cov["unread_at_limit"]:
        cov["limits_hit"].append("seconds: past the limit, the content of %d file(s) was not inflated, so their digests were not checked (check not-read); every item is still listed" % cov["unread_at_limit"])
    with open(os.path.join(out_dir, "index.tsv"), "w", encoding="utf-8") as fh:
        mism = len(cov["mismatches"])
        fh.write("members.tsv\tAD1 item list (%d items: %d files, %d folders): n, type, path, path_b64, size, packed, mtime, tz, mode, uid, gid, link, locator, flags, atime, ctime, md5, sha1, sha256, check, class; ad1_extract takes n%s\n"
                 % (cov["items"], cov["files"], cov["folders"], "; %d file(s) whose content does not match the digests the image records (check mismatch)" % mism if mism else ""))
        fh.write("attributes.tsv\tevery metadata entry of every item: n, category, key, label, text\n")
        fh.write("image.json\tthe AD1 segment and logical image headers, its segments, its data source name and its own metadata\n")
    status = "complete" if not cov["limits_hit"] and not cov["errors"] else ("partial" if cov["items"] else "failed")
    return finish(status, 0 if status in ("complete", "partial") else 2)


def main(argv):
    if len(argv) < 2 or argv[1] not in ("detect", "run"):
        print(json.dumps({"ok": False, "error": "usage: run.py detect --target T [--probe-out DIR] | run --target T --out DIR"}))
        return 2
    args = dict(zip(argv[2::2], argv[3::2]))
    if "--target" not in args:
        print(json.dumps({"ok": False, "error": "--target is required"}))
        return 2
    target, paths = target_of(args["--target"])
    if argv[1] == "detect":
        fmt, why = detect(paths[0])
        print(json.dumps({"applies": fmt is not None, "format": fmt, "why": why}))
        return 0 if fmt else 1
    if "--out" not in args:
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    return run(target, paths, args["--out"])


if __name__ == "__main__":
    sys.exit(main(sys.argv))

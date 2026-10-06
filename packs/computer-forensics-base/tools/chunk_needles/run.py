#!/usr/bin/env python3
"""Scan a file, or one inode of an image streamed through icat, for ASCII and UTF-16LE needles.

The answer is where each needle is: per needle the number of occurrences as ASCII and as
UTF-16LE, and for each occurrence a locator (an id, the offset in the scanned stream, the
encoding, how many bytes of context surround it). The context bytes are NOT returned by
default: they are where a password, a token or a card number sits. `write_values: true`, in a
job run with `secret_output: true`, writes them to a 0600 file under $OUT, and the answer names
the file. Never put a secret in `needles`: the arguments of a call are recorded in the trace.

What it finds, exactly: every occurrence of each needle, overlapping ones included, whatever
`chunk` is; a match is held back until its context is in the read, so a read boundary neither
loses a match nor cuts its context. `source` names the stream: the file, or the image, the
volume offset, the inode, and any sector size given. The stream is read once and never held whole.
"""
import json, re, sys, subprocess, os

TOOL = {"name": "chunk_needles", "version": 6}
CHUNK_DEFAULT = 8 * 1024 * 1024
CHUNK_MIN, CHUNK_MAX = 16, 256 * 1024 * 1024
CONTEXT_MAX = 65536
HITS_MAX = 1_000_000
NEEDLES_MAX = 1000
NEEDLE_BYTES_MAX = 4096
ROW_CAP = 20_000_000
SECTOR_MAX = 65536
INODE = re.compile(r"^\d+(-\d+(-\d+)?)?$")

def _catalogue_slug(path):
    """The directory name the kickoff's catalogue gives an input: its path under
    inputs/ with every byte outside [A-Za-z0-9._-] made "_" (evidence-catalog.sh)."""
    import os, re
    rel = os.fsencode(os.path.relpath(path, "inputs"))
    return os.fsdecode(re.sub(rb"[^A-Za-z0-9._-]", b"_", rel))


def _resolve_image(explicit=None):
    """A pack tool belongs to no case: find the image under inputs/ instead of
    baking one in. One candidate is used; several mean the caller must say which.
    An image is known by its extension or, lacking one (a raw `dd` of a web
    server named after the host), by the catalogue: the kickoff writes
    catalog/<input>/partitions.txt for every input it read as a disk."""
    import glob, os
    if explicit:
        return explicit
    cands = []
    for ext in ("*.E01", "*.e01", "*.raw", "*.dd", "*.001", "*.img", "*.vhd", "*.vhdx"):
        cands += glob.glob(os.path.join("inputs", ext))
    seen = set()
    for base, _dirs, files in os.walk("inputs", followlinks=True):
        # A link back up the tree is a place already walked, not another one.
        real = os.path.realpath(base)
        if real in seen:
            _dirs[:] = []
            continue
        seen.add(real)
        for f in files:
            p = os.path.join(base, f)
            if os.path.isfile(os.path.join("catalog", _catalogue_slug(p), "partitions.txt")):
                cands.append(p)
    cands = sorted(set(cands))
    if len(cands) == 1:
        return cands[0]
    if not cands:
        raise SystemExit('{"ok": false, "error": "no disk image under inputs/; pass image="}')
    raise SystemExit('{"ok": false, "error": "several images under inputs/; pass image=", "candidates": %s}' % json.dumps(cands))


def _resolve_offset(image, explicit=None):
    """The volume's start sector for icat -o. Given, it is used as is; not
    given, the catalogue says: one filesystem catalogued (catalog/<input>/p<start>/)
    is that start, several mean the caller must say which, none is sector 0."""
    import os, re
    if explicit is not None:
        return explicit
    root = os.path.join("catalog", _catalogue_slug(image))
    starts = sorted(int(d[1:]) for d in (os.listdir(root) if os.path.isdir(root) else [])
                    if re.fullmatch(r"p\d+", d) and os.path.isdir(os.path.join(root, d)))
    if len(starts) == 1:
        return starts[0]
    if not starts:
        return 0
    raise SystemExit('{"ok": false, "error": "several filesystems in %s; pass offset= (a start sector, see %s/partitions.txt)", "candidates": %s}' % (image, root, json.dumps(starts)))


def _resolve_catalog(explicit=None):
    """The catalogue directory for the one image the kickoff catalogued, or
    the one named: by its name under catalog/, as the index lists it
    (catalog=Case4.E01 was a traceback), or by its path."""
    import os
    root = "catalog"
    subs = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))) if os.path.isdir(root) else []
    if explicit:
        for cand in (explicit, os.path.join(root, explicit)):
            if os.path.isdir(cand):
                return cand
        raise SystemExit(json.dumps({"ok": False, "error": "no catalogue %s" % explicit, "candidates": subs}))
    if not os.path.isdir(root):
        raise SystemExit('{"ok": false, "error": "no catalog/ in this run; pass catalog="}')
    if len(subs) == 1:
        return os.path.join(root, subs[0])
    if not subs:
        raise SystemExit('{"ok": false, "error": "catalog/ is empty; pass catalog="}')
    # A disk and a memory image catalogue two directories, and only the
    # disk's has filesystems (partitions.txt): with one such, it is the one.
    disks = [d for d in subs if os.path.isfile(os.path.join(root, d, "partitions.txt"))]
    if len(disks) == 1:
        return os.path.join(root, disks[0])
    raise SystemExit('{"ok": false, "error": "several catalogues; pass catalog=", "candidates": %s}' % json.dumps(subs))

import hashlib
import tempfile
from pathlib import Path


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The reference implementation of the secret-safe output pattern (docs/packs.md, "Writing a
    pack that holds up"), copied as a standalone tool copies LosslessPage: call `add` once per
    finding with the finding's id, its locator and the value. With `enabled` false it writes
    nothing and `summary()` says so.
    """

    NAME = "chunk-needles-values.jsonl"

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.written = 0
        self._fh = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        if enabled and not (self.job and self.out):
            raise SecretValuesRefused(
                "write_values is refused outside a job: a value written here would be an ordinary "
                "file, not a sealed secret output. Run this as job_run tool=chunk_needles with "
                "secret_output: true, and ask again there. Nothing was written."
            )
        self.path = Path(self.out) / self.NAME if enabled else None
        self.shown = ("store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), self.NAME)) if enabled else None

    def add(self, finding_id: str, locator: dict, value: str) -> None:
        if not self.enabled:
            return
        if self._fh is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Exclusively and private: a second run never overwrites a first's file.
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            self._fh = os.fdopen(fd, "w", encoding="utf-8")
        self._fh.write(json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=False))
        self._fh.write("\n")
        self.written += 1

    def close(self) -> None:
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self) -> dict:
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.written else None,
            "contains_secret_values": self.written > 0,
            "format": "JSON Lines, mode 0600: finding_id, source, offset, needle, encoding, value (the printable context around the match)" if self.written else None,
        }


class Locators:
    """One needle's locators: an inline page, and the whole list in a file once it is more than the page."""

    def __init__(self, tool, key, limit):
        self.limit, self.page, self.total, self.stopped_at = limit, [], 0, None
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        name = "%s-%s.jsonl" % (self.tool, digest)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        self.fh = self.tmp = self.error = None
        self.written = 0

    def _open(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.tool)
        self.tmp, self.fh = Path(name), os.fdopen(fd, "w", encoding="utf-8")
        for row in self.page:
            self.fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            self.written += 1

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self.fh is None and self.error is None:
            try:
                self._open()
            except OSError as exc:
                self.error = "the whole result could not be written (%s: %s)" % (self.path.parent, exc.strerror or exc)
        if self.fh:
            if self.written < ROW_CAP:
                self.fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                self.written += 1
            elif self.stopped_at is None:
                self.stopped_at = row["off"]

    def finish(self):
        info = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self.fh:
            self.fh.flush()
            os.fsync(self.fh.fileno())
            self.fh.close()
            os.replace(self.tmp, self.path)
            info["all_results"] = self.shown
            info["all_results_format"] = "JSON Lines, one locator per occurrence: finding_id, off, enc, context_length"
            if self.stopped_at is not None:
                info["all_results_stopped_at_offset"] = self.stopped_at
                info["all_results_cap_rows"] = ROW_CAP
        if self.error:
            info["all_results_error"] = self.error
        return info


def fail(message, **extra):
    print(json.dumps({"error": message, "tool": TOOL, **extra}))
    sys.exit(1)


def whole(args, key, default, low, high):
    value = args.get(key)
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        fail("%s is a whole number from %d to %d" % (key, low, high), **{key: value})
    return value


args = json.load(sys.stdin)
if not isinstance(args, dict):
    fail("arguments are a JSON object")
needles = args.get("needles") or ""
if isinstance(needles, list) and all(isinstance(n, str) for n in needles):
    need_list = [n for n in needles if n]
elif isinstance(needles, str):
    need_list = [n for n in needles.split("|") if n]
else:
    fail("needles is a pipe-separated string or a list of strings")
path = args.get("path") or ""
inode = args.get("inode")
context = whole(args, "context", 60, 0, CONTEXT_MAX)          # 0 is 0, not the default
max_hits = whole(args, "max_hits", 20, 1, HITS_MAX)
chunk = whole(args, "chunk", CHUNK_DEFAULT, CHUNK_MIN, CHUNK_MAX)
sector_size = args.get("sector_size")
if sector_size is not None and (not isinstance(sector_size, int) or isinstance(sector_size, bool)
                                or sector_size < 512 or sector_size > SECTOR_MAX or sector_size % 512):
    fail("sector_size must be a multiple of 512 from 512 to %d (the Sleuth Kit's -b takes no other)" % SECTOR_MAX, sector_size=sector_size)
write_values = args.get("write_values", False)
if not isinstance(write_values, bool):
    fail("write_values is true or false")
if not need_list:
    fail("needles required, pipe-separated")
if len(need_list) > NEEDLES_MAX:
    fail("at most %d needles" % NEEDLES_MAX, given=len(need_list))
variants = []
for n in need_list:
    try:
        raw, wide = n.encode("utf-8"), n.encode("utf-16le")
    except UnicodeEncodeError:
        fail("a needle is not text that can be encoded")
    if len(raw) > NEEDLE_BYTES_MAX:
        fail("a needle is longer than %d bytes" % NEEDLE_BYTES_MAX)
    variants.append((n, "ascii", raw))
    variants.append((n, "utf16le", wide))
longest = max(len(v[2]) for v in variants)
try:
    secret = SecretValues(write_values)
except SecretValuesRefused as exc:
    fail(str(exc), write_values="refused")


def scan_fh(fh, source):
    counts = {n: {"ascii": 0, "utf16le": 0} for n in need_list}
    key = [source["label"], source.get("image"), source.get("volume_offset_sectors"), source.get("inode"), source.get("sector_size"), context]
    pages = {n: Locators("chunk_needles", key + [n], max_hits) for n in need_list}
    next_id = [0]

    def emit(at, name, enc, nb, buf, base):
        i = at - base
        a, b = max(0, i - context), min(len(buf), i + len(nb) + context)
        raw = buf[a:b]
        next_id[0] += 1
        fid = "F%06d" % next_id[0]
        counts[name][enc] += 1
        pages[name].add({"finding_id": fid, "off": at, "enc": enc, "context_length": len(raw)})
        if write_values:
            secret.add(fid, {"source": source["label"], "offset": at, "needle": name, "encoding": enc},
                       "".join(chr(c) if 32 <= c < 127 else "." for c in raw))

    # buf holds the stream's bytes [base, base + len(buf)); positions below `done` are searched. A
    # position is searched once its context is in buf (or the stream has ended), so no match is cut.
    buf, base, done, scanned = b"", 0, 0, 0
    while True:
        data = fh.read(chunk)
        at_end = not data
        buf += data
        scanned += len(data)
        have = base + len(buf)
        process_end = have if at_end else have - (longest + context)
        if process_end > done:
            lo, hi = done - base, process_end - base
            for name, enc, nb in variants:
                stop = min(len(buf), hi + len(nb) - 1)
                j = buf.find(nb, lo, stop)
                while j >= 0:
                    emit(base + j, name, enc, nb, buf, base)
                    j = buf.find(nb, j + 1, stop)
            done = process_end
        if at_end:
            break
        keep_from = max(0, (done - context) - base)
        buf, base = buf[keep_from:], base + keep_from
    hits = {}
    for n in need_list:
        page = pages[n].finish()
        hits[n] = {**counts[n], "locations": pages[n].page, **page}
    return hits, scanned


if path:
    if not os.path.isfile(path):
        print(json.dumps({"error": f"path not found: {path}"}))
        sys.exit(1)
    source = {"kind": "file", "path": path, "bytes": os.path.getsize(path)}
    source["label"] = path
    with open(path, "rb") as f:
        hits, scanned = scan_fh(f, source)
else:
    if inode is None:
        print(json.dumps({"error": "path or inode required"}))
        sys.exit(1)
    if isinstance(inode, bool) or not (isinstance(inode, int) and inode >= 0 or isinstance(inode, str) and INODE.match(inode)):
        fail("inode is a Sleuth Kit address: a number, or number-type-id for an NTFS stream (168-128-4)", inode=inode)
    image = _resolve_image(args.get("image"))
    if not os.path.isfile(image):
        print(json.dumps({"error": f"image not found: {image}"}))
        sys.exit(1)
    offset = _resolve_offset(image, args.get("offset"))
    cmd = ["icat"] + (["-b", str(sector_size)] if sector_size else []) + ["-o", str(offset), image, str(inode)]
    source = {"kind": "icat", "image": image, "volume_offset_sectors": offset, "inode": str(inode),
              "sector_size": sector_size, "command": " ".join(cmd)}
    source["label"] = f"icat:{inode}@{offset}"
    # Streamed, never held whole: capture_output kept a pagefile's gigabytes
    # in memory until the VM's kernel killed the tool, with no word said
    # (sixth CTF round, twice). stderr goes to a file so a chatty icat
    # cannot stall the pipe being read.
    with tempfile.TemporaryFile() as errf:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf)
        hits, scanned = scan_fh(proc.stdout, source)
        rc = proc.wait()
        errf.seek(0)
        err_text = errf.read().decode("utf-8", "replace").strip()
    if rc != 0:
        print(json.dumps({"error": err_text or f"icat exit {rc}", "image": image, "inode": inode, "offset": offset, "scanned_bytes": scanned}))
        sys.exit(1)
secret.close()
print(json.dumps({
    "tool": TOOL, "source": source, "scanned_bytes": scanned, "hits": hits,
    "match_policy": "every occurrence by its start offset in the scanned stream, overlapping ones included, case-sensitive; each needle as UTF-8 and as UTF-16LE",
    "context": {"bytes_each_side": context, "returned_inline": False,
                "note": "context bytes are not returned: they are where a secret sits. write_values: true, in a job run with secret_output: true, writes them to a file under $OUT."},
    "secret_values": secret.summary(),
}))

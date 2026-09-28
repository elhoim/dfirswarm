#!/usr/bin/env python3
"""Contact sheets for looking at many images at once.

Every image in a directory, a list of paths or a tar archive (read in place,
nothing unpacked) is hashed, decoded once per distinct content, and tiled
with a label under it into numbered sheets. Exact duplicates (same sha256)
are listed and not tiled again; dedup=ahash also folds images that look the
same (the same 16x16 average hash), and dedup=none tiles every one.

Everything is kept in out_dir, never cut: manifest.jsonl has one row per
file looked at (its status, hash, format, size, what it duplicates or why it
could not be read), tiles/ one labelled tile per distinct image, sheets/ the
sheets, index.jsonl which tile of which sheet is which file (the whole label,
where a sheet shows at most two lines of it), summary.json the counts.

A large set is done over several calls: each call works for budget_seconds,
keeps what it did, and says complete=false; the same call again carries on
where it stopped. Args come from JSON stdin.
"""
import hashlib
import importlib
import io
import json
import math
import os
import re
import string
import sys
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path

IMAGE_PATTERN = r"\.(jpe?g|jfif|png|gif|bmp|webp|tiff?|heic|heif|ico)$"
LABEL_FIELDS = ("n", "i", "name", "path", "sha8", "sha256", "w", "h", "size", "format", "mtime")
STARTED = time.monotonic()


def fail(msg, **extra):
    print(json.dumps({"ok": False, "error": msg, **extra}))
    sys.exit(1)


def resolve_output(out):
    """Where `out` lands, refusing anything outside the run directory, the
    read-only inputs, and ledger/ and tools/, which the harness owns."""
    root = Path.cwd().resolve()
    dest = Path(out).resolve() if Path(out).is_absolute() else (root / out).resolve()
    if dest == root or root not in dest.parents:
        fail("out_dir must be a directory inside the run directory", out_dir=str(out))
    for owned in ("inputs", "ledger", "tools"):
        place = root / owned
        if dest == place or place in dest.parents:
            fail("out_dir cannot be under %s/" % owned, out_dir=str(out))
    if dest.exists() and not dest.is_dir():
        fail("out_dir is a file", out_dir=str(out))
    return dest


def load_pillow():
    """Pillow, and pillow_heif for HEIC when it is there. Imported by name:
    they are in the mobile image, not in every image, and this tool says so
    when they are missing rather than failing on an import line."""
    try:
        mods = {n: importlib.import_module("PIL." + n) for n in ("Image", "ImageDraw", "ImageFont", "ImageOps")}
    except ImportError:
        fail("Pillow is not installed", hint="the mobile image has Pillow and pillow_heif; elsewhere python3 -m pip install --user pillow pillow-heif")
    heif = None
    try:
        ph = importlib.import_module("pillow_heif")
        ph.register_heif_opener()
        heif = str(getattr(ph, "__version__", "present"))
    except ImportError:
        pass
    return mods, heif


def iso(ts):
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError, TypeError):
        return None


def whole(name, default, low, high):
    v = args.get(name)
    if v is None:
        v = default
    if isinstance(v, bool) or not isinstance(v, int) or not low <= v <= high:
        fail("%s must be a whole number from %d to %d" % (name, low, high), got=v)
    return v


def local(p):
    """A file on disk as a candidate: (path, read, mtime, why it cannot be read)."""
    def read():
        with open(p, "rb") as fh:
            return fh.read()
    try:
        return (p, read, iso(os.stat(p).st_mtime), None)
    except OSError as e:
        return (p, None, None, "%s: %s" % (type(e).__name__, e.strerror or e))


def candidates():
    """What to look at, in a fixed order, so a later call carries on in step."""
    given = [k for k in ("input", "files", "list_file", "archive") if args.get(k)]
    if len(given) != 1:
        fail("name exactly one of input (a directory or a file), files (a list), list_file (a file with one path per line) or archive (a tar)", given=given)
    kind = given[0]
    if kind == "input":
        root = args["input"]
        if os.path.isfile(root):
            return kind, [local(root)]
        if not os.path.isdir(root):
            fail("no such directory or file: %s" % root)
        out = []
        for base, dirs, files in os.walk(root):
            dirs.sort()
            for f in sorted(files):
                p = os.path.join(base, f)
                if pattern.search(os.path.relpath(p, root)):
                    out.append(local(p))
        return kind, out
    if kind in ("files", "list_file"):
        if kind == "files":
            paths = args["files"]
            if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
                fail("files must be a list of paths")
        else:
            if not os.path.isfile(args["list_file"]):
                fail("no such list_file: %s" % args["list_file"])
            with open(args["list_file"], "r", encoding="utf-8", errors="surrogateescape") as fh:
                paths = [ln.rstrip("\r\n") for ln in fh if ln.strip()]
        # A list is what the caller chose: the pattern narrows it only when given.
        return kind, [local(p) for p in paths if not args.get("pattern") or pattern.search(p)]
    arc = args["archive"]
    if not os.path.isfile(arc):
        fail("no such archive: %s" % arc)
    try:
        tf = tarfile.open(arc, "r:*")
        members = tf.getmembers()
    except (tarfile.TarError, OSError, EOFError) as e:
        fail("not a tar archive this can read: %s" % e, archive=arc)
    return kind, [(m.name, (lambda m=m: tf.extractfile(m).read()), iso(m.mtime), None) for m in members if m.isfile() and pattern.search(m.name)]


def label_format(fmt):
    """The label format, checked before any work: simple field names only."""
    try:
        parsed = list(string.Formatter().parse(fmt))
    except ValueError as e:
        fail("label is not a valid format: %s" % e, fields=list(LABEL_FIELDS))
    for _lit, field, _spec, _conv in parsed:
        if field is not None and field not in LABEL_FIELDS:
            fail("label may use only these fields: %s" % ", ".join("{%s}" % f for f in LABEL_FIELDS), got=field)
    sample = {"n": 1, "i": 0, "name": "a.jpg", "path": "d/a.jpg", "sha8": "0" * 8, "sha256": "0" * 64, "w": 1, "h": 1, "size": 1, "format": "JPEG", "mtime": "1970-01-01T00:00:00Z"}
    try:
        fmt.format(**sample)
    except (ValueError, TypeError, KeyError, IndexError) as e:
        fail("label does not format: %s" % e, label=fmt)
    return fmt


def ahash(im):
    g = im.convert("L").resize((16, 16), Image.BILINEAR)
    vals = list(g.tobytes())
    avg = sum(vals) / len(vals)
    return "%064x" % int("".join("1" if v >= avg else "0" for v in vals), 2)


def flatten(im):
    """RGB for a tile; a transparent image on white, not on black."""
    if im.mode in ("RGBA", "LA") or (im.mode == "P" and "transparency" in im.info):
        rgba = im.convert("RGBA")
        bg = Image.new("RGB", rgba.size, "white")
        bg.paste(rgba, mask=rgba.split()[-1])
        return bg
    return im.convert("RGB")


def wrap(text, draw, width, most):
    """At most `most` lines that fit the tile's width, and whether any was left over."""
    lines, cur = [], ""
    for ch in text.replace("\n", " "):
        if draw.textlength(cur + ch, font=font) <= width - 4:
            cur += ch
            continue
        lines.append(cur)
        cur = ch
    if cur:
        lines.append(cur)
    return lines[:most], len(lines) > most


def shown(name):
    return str(Path(args["out_dir"]) / name)


def compose(k, count):
    """Sheet k (1-based) from tiles (k-1)*per+1 .. +count, written whole or not at all."""
    used_rows = math.ceil(count / columns)
    sheet = Image.new("RGB", (columns * tile, used_rows * cell_h), "white")
    d = ImageDraw.Draw(sheet)
    for j in range(count):
        n = (k - 1) * per + j + 1
        with Image.open(tiles_dir / ("%06d.jpg" % n)) as t:
            x, y = (j % columns) * tile, (j // columns) * cell_h
            sheet.paste(t, (x, y))
        d.rectangle([x, y, x + tile - 1, y + cell_h - 1], outline=(210, 210, 210))
    path = sheets_dir / ("sheet_%04d.jpg" % k)
    tmp = sheets_dir / (".sheet_%04d.tmp" % k)
    sheet.save(tmp, format="JPEG", quality=90)
    os.replace(tmp, path)
    return path


def sheet_record(k, count, path):
    return {"sheet": k, "file": shown("sheets/" + path.name), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "tiles": count, "first_n": (k - 1) * per + 1, "last_n": (k - 1) * per + count}


args = json.load(sys.stdin)
if not isinstance(args, dict):
    fail("arguments must be a JSON object")
if not isinstance(args.get("out_dir"), str) or not args["out_dir"].strip():
    fail("need out_dir: a new directory under your work directory for the sheets and their index")
out_dir = resolve_output(args["out_dir"])
try:
    pattern = re.compile(args.get("pattern") or IMAGE_PATTERN, re.IGNORECASE)
except re.error as e:
    fail("pattern is not a valid regex: %s" % e)
tile = whole("tile", 160, 32, 1024)
columns = whole("columns", 10, 1, 50)
rows_per = whole("rows", 10, 1, 50)
budget = whole("budget_seconds", 90, 0, 3600)
per = columns * rows_per
dedup = args.get("dedup") or "sha256"
if dedup not in ("sha256", "ahash", "none"):
    fail("dedup must be sha256, ahash or none", got=dedup)
label = label_format(args.get("label") or "{n:04d} {name}")

P, heif = load_pillow()
Image, ImageDraw, ImageFont, ImageOps = P["Image"], P["ImageDraw"], P["ImageFont"], P["ImageOps"]
font = ImageFont.load_default()
line_h = (ImageDraw.Draw(Image.new("RGB", (8, 8))).textbbox((0, 0), "Ag", font=font)[3] or 10) + 2
cell_h = tile + 2 * line_h + 6

source_kind, todo = candidates()
chosen = {k: args.get(k) for k in ("input", "files", "list_file", "archive", "pattern", "tile", "columns", "rows", "dedup", "label")}
key = hashlib.sha256(json.dumps(chosen, sort_keys=True).encode("utf-8")).hexdigest()
state_path = out_dir / "state.json"
manifest_path = out_dir / "manifest.jsonl"
tiles_dir, sheets_dir = out_dir / "tiles", out_dir / "sheets"
done_rows = []
if out_dir.is_dir() and any(out_dir.iterdir()):
    try:
        state = json.loads(state_path.read_text())
    except (OSError, ValueError):
        fail("out_dir already holds something that is not this tool's work; name a new directory", out_dir=args["out_dir"])
    if state.get("key") != key:
        fail("out_dir holds contact sheets made with other arguments; name a new directory, or call with the same arguments to carry on", out_dir=args["out_dir"])
    if state.get("candidates") != len(todo):
        fail("the input has changed since this out_dir was started (%s files then, %d now); name a new directory" % (state.get("candidates"), len(todo)))
    if state.get("complete") and (out_dir / "summary.json").is_file():
        print(json.dumps({"ok": True, "complete": True, "again": True, **json.loads((out_dir / "summary.json").read_text())["result"]}, ensure_ascii=False))
        sys.exit(0)
    # A call stopped mid-row leaves a torn last line: the rows before it stand.
    if manifest_path.is_file():
        for line in manifest_path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                break
            if row.get("i") != len(done_rows):
                break
            done_rows.append(row)
tiles_dir.mkdir(parents=True, exist_ok=True)
sheets_dir.mkdir(parents=True, exist_ok=True)
state_path.write_text(json.dumps({"key": key, "candidates": len(todo), "complete": False}))
with manifest_path.open("w", encoding="utf-8") as fh:
    for row in done_rows:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")

# sha256 -> the first file with that content: its path, and its tile if it has one.
seen_sha, seen_look, unique = {}, {}, 0
for row in done_rows:
    first = {"path": row["path"], "n": row.get("n")}
    if row.get("status") == "decoded_unique":
        unique = row["n"]
        seen_look.setdefault(row.get("ahash"), first)
    if row.get("sha256") and row.get("status") in ("decoded_unique", "undecodable"):
        seen_sha.setdefault(row["sha256"], first)
    if row.get("status") == "looks_duplicate":
        seen_sha.setdefault(row["sha256"], {"path": row["duplicate_of"], "n": row.get("duplicate_of_n")})

stopped_early = False
with manifest_path.open("a", encoding="utf-8") as man:
    def keep(rec):
        man.write(json.dumps(rec, ensure_ascii=False) + "\n")
        man.flush()

    start_at = len(done_rows)
    for i in range(start_at, len(todo)):
        # Every call does at least one file, so calling again always gets further.
        if i > start_at and time.monotonic() - STARTED > budget:
            stopped_early = True
            break
        path, read, mtime, why = todo[i]
        rec = {"i": i, "path": path, "mtime": mtime}
        try:
            if read is None:
                raise OSError(why)
            data = read()
        except Exception as e:
            rec.update(status="unreadable", error=why or "%s: %s" % (type(e).__name__, e))
            keep(rec)
            continue
        rec["size"] = len(data)
        if not data:
            rec["status"] = "empty"
            keep(rec)
            continue
        sha = hashlib.sha256(data).hexdigest()
        rec["sha256"] = sha
        if dedup != "none" and sha in seen_sha:
            rec.update(status="exact_duplicate", duplicate_of=seen_sha[sha]["path"], duplicate_of_n=seen_sha[sha]["n"])
            keep(rec)
            continue
        try:
            im = Image.open(io.BytesIO(data))
            rec.update(format=im.format, width=im.width, height=im.height, mode=im.mode)
            if im.format == "JPEG":
                im.draft("RGB", (tile * 2, tile * 2))
            im.load()
            try:
                im = ImageOps.exif_transpose(im)
            except Exception:
                pass
            look = ahash(im)
            thumb = flatten(im)
            thumb.thumbnail((tile, tile))
        except Exception as e:
            rec.update(status="undecodable", error="%s: %s" % (type(e).__name__, e))
            if dedup != "none":
                seen_sha.setdefault(sha, {"path": path, "n": None})
            keep(rec)
            continue
        rec["ahash"] = look
        if dedup == "ahash" and look in seen_look:
            rec.update(status="looks_duplicate", duplicate_of=seen_look[look]["path"], duplicate_of_n=seen_look[look]["n"])
            seen_sha.setdefault(sha, seen_look[look])
            keep(rec)
            continue
        unique += 1
        n = unique
        text = label.format(n=n, i=i, name=os.path.basename(path.rstrip("/")), path=path, sha8=sha[:8], sha256=sha, w=rec["width"], h=rec["height"], size=len(data), format=rec["format"] or "", mtime=mtime or "")
        cell = Image.new("RGB", (tile, cell_h), "white")
        cell.paste(thumb, ((tile - thumb.width) // 2, (tile - thumb.height) // 2))
        draw = ImageDraw.Draw(cell)
        lines, over = wrap(text, draw, tile, 2)
        for li, ln in enumerate(lines):
            draw.text((2, tile + 2 + li * line_h), ln, fill="black", font=font)
        cell.save(tiles_dir / ("%06d.jpg" % n), format="JPEG", quality=90)
        rec.update(status="decoded_unique", n=n, label=text, label_whole_on_sheet=not over)
        seen_sha[sha] = {"path": path, "n": n}
        seen_look.setdefault(look, {"path": path, "n": n})
        keep(rec)
        if n % per == 0:
            compose(n // per, per)
    os.fsync(man.fileno())

rows = [json.loads(ln) for ln in manifest_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
if stopped_early:
    print(json.dumps({
        "ok": True,
        "complete": False,
        "out_dir": args["out_dir"],
        "candidates": len(todo),
        "processed": len(rows),
        "distinct_so_far": unique,
        "sheets_so_far": unique // per,
        "next": "call again with the same arguments: it carries on from file %d of %d" % (len(rows) + 1, len(todo)),
    }))
    sys.exit(0)

sheets = []
for k in range(1, math.ceil(unique / per) + 1):
    count = min(per, unique - (k - 1) * per)
    path = sheets_dir / ("sheet_%04d.jpg" % k)
    if not (count == per and path.is_file()):
        path = compose(k, count)
    sheets.append(sheet_record(k, count, path))
dups = {}
for r in rows:
    if r.get("duplicate_of_n"):
        dups[r["duplicate_of_n"]] = dups.get(r["duplicate_of_n"], 0) + 1
index, clipped = [], 0
for r in rows:
    if r.get("status") != "decoded_unique":
        continue
    j = r["n"] - 1
    index.append({
        "n": r["n"], "sheet": j // per + 1, "tile": j % per + 1, "row": (j % per) // columns + 1, "col": j % columns + 1,
        "path": r["path"], "sha256": r["sha256"], "format": r.get("format"), "width": r.get("width"), "height": r.get("height"),
        "label": r.get("label"), "duplicates": dups.get(r["n"], 0),
    })
    clipped += 0 if r.get("label_whole_on_sheet", True) else 1
with (out_dir / "index.jsonl").open("w", encoding="utf-8") as fh:
    for x in index:
        fh.write(json.dumps(x, ensure_ascii=False) + "\n")


def tally(values):
    out = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], str(kv[0]))))


tiled = [r for r in rows if r.get("status") == "decoded_unique"]
result = {
    "out_dir": args["out_dir"],
    "source": source_kind,
    "candidates": len(todo),
    "counts": tally(r["status"] for r in rows),
    "distinct_tiled": unique,
    "tiles_per_sheet": per,
    "sheets": sheets,
    "manifest": shown("manifest.jsonl"),
    "index": shown("index.jsonl"),
    "summary": shown("summary.json"),
    "dedup": dedup,
    "heic": ("pillow_heif " + heif) if heif else "pillow_heif is not installed: a HEIC file is listed as undecodable",
}
if clipped:
    result["labels_note"] = "%d labels are longer than two lines of a tile; index.jsonl has each whole" % clipped
summary = {
    "result": result,
    "by_directory": tally(os.path.dirname(r["path"]) or "." for r in tiled),
    "dimensions": tally("%sx%s" % (r.get("width"), r.get("height")) for r in tiled),
    "formats": tally(r.get("format") or "?" for r in tiled),
    "arguments": chosen,
}
(out_dir / "summary.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False))
state_path.write_text(json.dumps({"key": key, "candidates": len(todo), "complete": True}))
print(json.dumps({"ok": True, "complete": True, **result}, ensure_ascii=False))

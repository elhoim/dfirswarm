#!/usr/bin/env python3
"""marshal_inspect: read a Python marshal stream as data, and never run it.

A compiled module (a .pyc, a stream carved out of a packed executable or a
memory image) is a marshal stream: constants, names and code objects, whose
bytecode is data until something runs it. This parses the stream itself,
byte by byte, with its own reader. It never calls marshal.loads, never builds
a code object, never imports or runs what it reads, so a hostile stream costs
what any other file costs.

For every code object it says its name, qualified name, file name, first line,
argument counts, flags, the names it uses, its constants, and the size and
sha256 of its bytecode (and the bytecode itself, as hex, in the result file).
The whole tree of the stream, every string and byte string in full, goes to
out_dir; the answer carries the counts, the code objects in a short form and
where the rest is.

The code-object layout read here is CPython 3.11 to 3.13 (argcount,
posonlyargcount, kwonlyargcount, stacksize, flags, code, consts, names,
localsplusnames, localspluskinds, filename, name, qualname, firstlineno,
linetable, exceptiontable). A stream of 3.10 or older lays a code object out
differently; when a .pyc header names an older magic number the tool says so
and stops, and one without a header that does not parse as this layout fails
with the position where it stopped rather than being guessed at.

Args, JSON on stdin:
  path        the file
  offset      where the stream starts (default: after a .pyc header when the
              file begins with one, else 0)
  out_dir     where the whole result goes (default work/<agent>/marshal_inspect)
  max_bytes   the largest stream read (default 64 MiB)
  preview     characters of a string or bytes of a byte string shown in the
              answer (default 160); the result file holds them whole
  bytecode    put each code object's bytecode, as hex, in the result file
              (default true)
  limit       code objects shown in the answer (default 200)
"""
import hashlib
import json
import os
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

TOOL = "marshal_inspect"
MAX_DEPTH = 200
MAX_OBJECTS = 2_000_000
OLDEST_MAGIC = 3450       # 3.11's development begins around here; 3.10 ended at 3439
FLAGS = (
    (0x1, "OPTIMIZED"), (0x2, "NEWLOCALS"), (0x4, "VARARGS"), (0x8, "VARKEYWORDS"), (0x10, "NESTED"),
    (0x20, "GENERATOR"), (0x80, "COROUTINE"), (0x100, "ITERABLE_COROUTINE"), (0x200, "ASYNC_GENERATOR"),
)


class StreamError(Exception):
    pass


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


# --- the objects ---------------------------------------------------------------------------

class Raw:
    """A byte string."""
    def __init__(self, data, offset):
        self.data, self.offset = data, offset


class Ref:
    """A reference to a container already read (or still being read): named, never
    followed, so a stream that refers to itself cannot make a loop, and one that
    refers to the same thing many times cannot make a result a million times its size."""
    def __init__(self, index):
        self.index = index


class Pending:
    """A container whose items are still being read."""


class Cont:
    """A tuple, list, set, frozenset or dict (items are (key, value) pairs), with its
    reference number when the stream marks it, and its weight: the objects in it."""
    def __init__(self, kind, items, ref):
        self.kind, self.items, self.ref = kind, items, ref
        self.weight = 1 + sum(weight(i) for pair in items for i in (pair if kind == "dict" else (pair,)))


def weight(x):
    return x.weight if isinstance(x, Cont) else 1


SMALL = 32   # a tuple this small that is referred to again is shown where it is referred to


class Special:
    """None, False, True, StopIteration, Ellipsis."""
    def __init__(self, name):
        self.name = name


class Code:
    def __init__(self, number, start):
        self.number, self.start = number, start


class Reader:
    def __init__(self, data, base):
        self.b, self.p, self.base = data, 0, base     # base: the stream's offset in the file
        self.refs, self.objects, self.depth_max = [], 0, 0
        self.codes = []

    def at(self):
        return self.base + self.p

    def take(self, n):
        if n < 0 or self.p + n > len(self.b):
            raise StreamError("the stream is cut short: %d more byte(s) wanted at offset %d, %d left" % (n, self.at(), len(self.b) - self.p))
        z = self.b[self.p:self.p + n]
        self.p += n
        return z

    def i32(self):
        return struct.unpack("<i", self.take(4))[0]

    def count(self, n, per=1):
        # A count that cannot fit in what is left is a damaged stream, and is
        # refused before anything is allocated for it.
        if n < 0 or n * per > len(self.b) - self.p:
            raise StreamError("a count of %d at offset %d cannot fit in the %d byte(s) left" % (n, self.at(), len(self.b) - self.p))
        return n

    def reserve(self, flag, value=None):
        if flag:
            self.refs.append(value)
            return len(self.refs) - 1
        return None

    def obj(self, depth=0):
        if depth > MAX_DEPTH:
            raise StreamError("nesting deeper than %d at offset %d" % (MAX_DEPTH, self.at()))
        self.objects += 1
        if self.objects > MAX_OBJECTS:
            raise StreamError("more than %d objects" % MAX_OBJECTS)
        self.depth_max = max(self.depth_max, depth)
        start = self.at()
        raw = self.take(1)[0]
        flag, t = bool(raw & 0x80), chr(raw & 0x7F)
        if t == "0":
            return None
        if t == "r":
            n = self.i32()
            if not 0 <= n < len(self.refs):
                raise StreamError("a reference to object %d at offset %d, with %d read" % (n, start, len(self.refs)))
            target = self.refs[n]
            if isinstance(target, Pending) or (isinstance(target, Cont) and not (target.kind in ("tuple", "frozenset") and target.weight <= SMALL)):
                return Ref(n)
            return target
        if t in "NFTS.":
            v = Special({"N": "None", "F": "False", "T": "True", "S": "StopIteration", ".": "Ellipsis"}[t])
            self.reserve(flag, v)
            return v
        if t == "i":
            v = self.i32()
        elif t == "I":
            v = struct.unpack("<q", self.take(8))[0]
        elif t == "l":
            n = self.i32()
            digits = [struct.unpack("<H", self.take(2))[0] for _ in range(self.count(abs(n), 2))]
            if any(d >= 32768 for d in digits):
                raise StreamError("a digit of a long at offset %d is out of range" % start)
            v = sum(d << (15 * j) for j, d in enumerate(digits)) * (-1 if n < 0 else 1)
        elif t == "g":
            v = struct.unpack("<d", self.take(8))[0]
        elif t == "y":
            v = ("complex", *struct.unpack("<dd", self.take(16)))
        elif t in "fx":
            parts = [self.take(self.take(1)[0]).decode("ascii", "replace") for _ in range(1 if t == "f" else 2)]
            v = parts[0] if t == "f" else ("complex-text", *parts)
        elif t == "s":
            n = self.count(self.i32())
            v = Raw(self.take(n), self.at() - n)
        elif t in "tuaA":
            n = self.count(self.i32())
            v = self.take(n).decode("utf-8", "surrogatepass")
        elif t in "zZ":
            v = self.take(self.take(1)[0]).decode("ascii", "replace")
        elif t in "()[<>":
            idx = self.reserve(flag, Pending())
            n = self.take(1)[0] if t == ")" else self.count(self.i32())
            items = [self.obj(depth + 1) for _ in range(n)]
            v = Cont({"(": "tuple", ")": "tuple", "[": "list", "<": "set", ">": "frozenset"}[t], items, idx)
            if idx is not None:
                self.refs[idx] = v
            return v
        elif t == "{":
            idx = self.reserve(flag, Pending())
            pairs = []
            while True:
                k = self.obj(depth + 1)
                if k is None:
                    break
                pairs.append((k, self.obj(depth + 1)))
                if len(pairs) > MAX_OBJECTS:
                    raise StreamError("a dictionary of more than %d pairs" % MAX_OBJECTS)
            v = Cont("dict", pairs, idx)
            if idx is not None:
                self.refs[idx] = v
            return v
        elif t == "c":
            return self.code(flag, start, depth)
        else:
            raise StreamError("marshal type %r (byte 0x%02x) at offset %d is not one this reader knows" % (t, raw, start))
        self.reserve(flag, v)
        return v

    def code(self, flag, start, depth):
        idx = self.reserve(flag, Pending())
        c = Code(len(self.codes), start)
        self.codes.append(c)
        c.ref = idx
        c.argcount, c.posonlyargcount, c.kwonlyargcount, c.stacksize, c.flags = struct.unpack("<5i", self.take(20))
        for name in ("code", "consts", "names", "localsplusnames", "localspluskinds", "filename", "name", "qualname"):
            setattr(c, name, self.obj(depth + 1))
        c.firstlineno = self.i32()
        c.linetable = self.obj(depth + 1)
        c.exceptiontable = self.obj(depth + 1)
        c.end = self.at()
        if not isinstance(c.code, Raw) or not isinstance(c.name, str) or not isinstance(c.filename, str):
            raise StreamError("the code object at offset %d does not have the 3.11 to 3.13 layout this reader knows (its code is not bytes, or its name or file name is not text)" % start)
        if idx is not None:
            self.refs[idx] = c
        return c


# --- views -------------------------------------------------------------------------------------

def view(x, preview=None, depth=0):
    """A JSON form of an object; `preview` shortens text and bytes (None: whole)."""
    if depth > MAX_DEPTH + 4:
        return {"depth_limit": True}
    if isinstance(x, Special):
        if x.name in ("None", "False", "True"):
            return {"None": None, "False": False, "True": True}[x.name]
        return {"const": x.name}
    if isinstance(x, Raw):
        d = x.data if preview is None else x.data[:preview]
        out = {"bytes": len(x.data), "hex": d.hex()}
        if preview is not None and len(x.data) > preview:
            out["shown"] = preview
        return out
    if isinstance(x, str):
        if preview is not None and len(x) > preview:
            return {"text": x[:preview], "length": len(x), "shown": preview}
        return x
    if isinstance(x, Ref):
        return {"ref": x.index}
    if isinstance(x, Code):
        return {"code": x.number}
    if isinstance(x, Cont):
        if x.kind == "dict":
            body = [[view(k, preview, depth + 1), view(v, preview, depth + 1)] for k, v in x.items]
        else:
            body = [view(i, preview, depth + 1) for i in x.items]
        if x.kind == "tuple" and (x.ref is None or x.weight <= SMALL):
            return body
        return {x.kind: body, **({"ref": x.ref} if x.ref is not None else {})}
    if isinstance(x, tuple) and x and x[0] in ("complex", "complex-text"):
        return {x[0]: list(x[1:])}
    if isinstance(x, float) and (x != x or x in (float("inf"), float("-inf"))):
        return {"float": repr(x)}
    return x


def type_name(x):
    if isinstance(x, Cont):
        return x.kind
    if isinstance(x, Special):
        return x.name
    if isinstance(x, Raw):
        return "bytes"
    if isinstance(x, Code):
        return "code"
    if isinstance(x, Ref):
        return "ref"
    if isinstance(x, tuple):
        return x[0]
    return type(x).__name__ if x is not None else "none"


def code_row(c, preview, bytecode):
    names = [name for bit, name in FLAGS if c.flags & bit]
    row = {
        "code": c.number, "ref": c.ref, "stream_start": c.start, "stream_end": c.end,
        "name": view(c.name, preview), "qualname": view(c.qualname, preview), "filename": view(c.filename, preview),
        "firstlineno": c.firstlineno, "argcount": c.argcount, "posonlyargcount": c.posonlyargcount, "kwonlyargcount": c.kwonlyargcount,
        "stacksize": c.stacksize, "flags": c.flags, "flag_names": names,
        "names": view(c.names, preview), "localsplusnames": view(c.localsplusnames, preview), "consts": view(c.consts, preview),
        "bytecode_bytes": len(c.code.data), "bytecode_sha256": hashlib.sha256(c.code.data).hexdigest(),
        "linetable_bytes": len(c.linetable.data) if isinstance(c.linetable, Raw) else None,
        "exceptiontable_bytes": len(c.exceptiontable.data) if isinstance(c.exceptiontable, Raw) else None,
    }
    if bytecode:
        row["bytecode_hex"] = c.code.data.hex()
        row["linetable_hex"] = c.linetable.data.hex() if isinstance(c.linetable, Raw) else None
        row["exceptiontable_hex"] = c.exceptiontable.data.hex() if isinstance(c.exceptiontable, Raw) else None
    return row


def pyc_header(head):
    """The fields of a .pyc header (16 bytes, since Python 3.7), or None when it is not one."""
    if len(head) < 16 or head[2:4] != b"\r\n":
        return None
    magic = struct.unpack("<H", head[:2])[0]
    flags = struct.unpack("<I", head[4:8])[0]
    info = {"magic": magic, "flags": flags}
    if flags & 1:
        info["source_hash"] = head[8:16].hex()
        info["hash_checked"] = bool(flags & 2)
    else:
        mtime, size = struct.unpack("<II", head[8:16])
        info["source_mtime"] = datetime.fromtimestamp(mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        info["source_size"] = size
    return info


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as e:
        fail("the arguments are not JSON", reason=str(e))
    if not isinstance(args, dict):
        fail("the arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the file holding the marshal stream")
    if not os.path.isfile(path):
        fail("path is not a readable regular file", path=path)
    max_bytes = whole(args, "max_bytes", 64 * 1024 * 1024, 16, 1 << 32)
    preview = whole(args, "preview", 160, 8, 1 << 20)
    limit = whole(args, "limit", 200, 1, 1 << 20)
    bytecode = args.get("bytecode", True)
    if not isinstance(bytecode, bool):
        fail("bytecode is true or false", got=bytecode)
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(16)
        header, offset = None, args.get("offset")
        if offset is None:
            header = pyc_header(head)
            offset = 16 if header else 0
        else:
            offset = whole(args, "offset", 0, 0, 1 << 62)
        if offset > size:
            fail("offset is past the end of the file", offset=offset, size=size)
        if size - offset > max_bytes:
            fail("the stream is %d bytes, over max_bytes (%d); raise max_bytes or give an offset nearer its end" % (size - offset, max_bytes), size=size - offset)
        if header and header["magic"] < OLDEST_MAGIC:
            fail("the .pyc header names magic number %d, a Python older than 3.11, whose code objects are laid out differently from what this reads" % header["magic"], pyc_header=header)
        fh.seek(offset)
        data = fh.read()
    out_dir = resolve_output(args.get("out_dir"))

    reader = Reader(data, offset)
    error, root = None, None
    try:
        root = reader.obj()
    except StreamError as e:
        error = str(e)
    except RecursionError:
        error = "the stream nests deeper than this reader can follow"
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = [code_row(c, None, bytecode) for c in reader.codes if hasattr(c, "end")]
    shown = [code_row(c, preview, False) for c in reader.codes[:limit] if hasattr(c, "end")]
    summary = {
        "ok": error is None,
        "tool": TOOL,
        "source": {"path": path, "bytes": size, "stream_offset": offset, **({"pyc_header": header} if header else {})},
        "mode": "data only: never marshal.loads, never a code object built, nothing imported or run",
        "layout": "CPython 3.11 to 3.13 code objects",
        "consumed_bytes": reader.p,
        "trailing_bytes": len(data) - reader.p,
        "objects": reader.objects,
        "references": len(reader.refs),
        "max_depth": reader.depth_max,
        "code_objects": len(rows),
        **({"error": error, "stopped_at": reader.at()} if error else {}),
    }
    result = dict(summary, root=view(root), codes=rows)
    key = json.dumps([path, offset, bytecode], sort_keys=True)
    result_file = out_dir / ("%s-%s.json" % (TOOL, hashlib.sha256(key.encode()).hexdigest()[:12]))
    result_file.write_text(json.dumps(result, indent=2, ensure_ascii=True))
    answer = dict(summary, root_type=type_name(root))
    answer["root"] = view(root, preview)
    answer["codes"] = shown
    if len(rows) > limit:
        answer["codes_shown"] = limit
    answer["result_file"] = os.path.relpath(result_file, Path.cwd())
    answer["result_file_holds"] = "the whole tree, every string and byte string in full, and each code object's bytecode as hex" if bytecode else "the whole tree and every string and byte string in full"
    print(json.dumps(answer, ensure_ascii=True))
    if error:
        sys.exit(1)


if __name__ == "__main__":
    main()

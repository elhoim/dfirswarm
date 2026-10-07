#!/usr/bin/env python3
"""Extract one data stream of an NTFS volume by inode, to a file, with icat.

The stream is written to `output` (a path under the run, never under inputs/), streamed: icat's standard
output goes straight to the file, so a stream of any size is never held in memory and never printed. The
answer is the record a reader cites: the output path, its size and sha256, the image, the offset in sectors,
the inode address as asked and as parsed (entry, attribute type, attribute id), icat's exit status and its
standard error, whole, in a file beside the output. A failed icat leaves what it wrote as `<output>.partial`
and the answer says so; it is never reported as an extraction.

The inode is a Sleuth Kit address: `168` (the default data attribute) or `168-128-4` (entry, attribute type,
attribute id, which names a stream such as an alternate data stream). `offset` is in SECTORS, as icat's -o
is. A file that already exists at `output` is never overwritten. This is the same contract as the base
pack's icat_extract (a named file, its size and digest), without its image catalogue.
"""
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
from pathlib import Path

PARSER = "extract_stream/3"
INODE = re.compile(r"^(\d+)(?:-(\d+)(?:-(\d+))?)?$")


def fail(message, **extra):
    print(json.dumps({"error": message, "status": "failed", **extra}))
    raise SystemExit(1)


def resolve_output(out):
    """Where `out` really lands, refusing anything outside the run directory or under inputs/. A string check is
    not enough: `work/../inputs/x`, an absolute path and a link that points out all name a place that must not
    be written."""
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("output must be a file inside the run directory", output=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("output cannot be under inputs/", output=str(out))
    return dest


def main():
    try:
        d = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(d, dict):
        fail("the arguments must be a JSON object")
    image = d.get("image")
    if not isinstance(image, str) or not image or "\n" in image:
        fail("image must be a single-line path", image=image)
    inode = d.get("inode")
    if isinstance(inode, int) and not isinstance(inode, bool):
        inode = str(inode)
    m = INODE.match(inode) if isinstance(inode, str) else None
    if not m:
        fail("inode must be an address like 168 or 168-128-4 (entry, attribute type, attribute id), or an integer", inode=d.get("inode"))
    offset = d.get("offset", 0)
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        fail("offset must be a non-negative sector count", offset=d.get("offset"))
    output = d.get("output")
    if not isinstance(output, str) or not output:
        fail("output is required: the file to write the stream to, under the run directory")
    timeout = d.get("timeout_seconds", 280)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < 1:
        fail("timeout_seconds must be a positive integer", timeout_seconds=d.get("timeout_seconds"))
    if not os.path.isfile(image):
        fail("no such image", image=image)
    if shutil.which("icat") is None:
        fail("icat is not on PATH", hint="the Sleuth Kit: brew install sleuthkit, or apt-get install -y sleuthkit")
    dest = resolve_output(output)
    dest.parent.mkdir(parents=True, exist_ok=True)
    stderr_path = Path(str(dest) + ".stderr")
    argv = ["icat", "-o", str(offset), image, inode]
    try:
        # Created, never opened over something already there (a link included).
        fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    except FileExistsError:
        fail("output already exists and is never overwritten", output=output)
    except OSError as exc:
        fail("output could not be created", output=output, reason=str(exc))
    timed_out = False
    with os.fdopen(fd, "wb") as out, open(stderr_path, "wb") as err:
        proc = subprocess.Popen(argv, stdout=out, stderr=err, stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            rc = proc.wait()
    stderr_bytes = stderr_path.stat().st_size
    if not stderr_bytes:
        stderr_path.unlink()
    shown_stderr = str(os.path.relpath(stderr_path, Path.cwd().resolve())) if stderr_bytes else None
    first_lines = []
    if stderr_bytes:
        with open(stderr_path, "r", encoding="utf-8", errors="replace") as fh:
            first_lines = [l.rstrip("\n") for _, l in zip(range(5), fh)]
    h = hashlib.sha256()
    size = 0
    with open(dest, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    answer = {
        "parser": PARSER,
        "image": image,
        "offset_sectors": offset,
        "inode": inode,
        "entry": int(m.group(1)),
        "attribute_type": int(m.group(2)) if m.group(2) is not None else None,
        "attribute_id": int(m.group(3)) if m.group(3) is not None else None,
        "icat_exit_status": rc,
        "timed_out": timed_out,
        "stderr_file": shown_stderr,
        "stderr_bytes": stderr_bytes,
        "stderr_first_lines": first_lines,
    }
    if rc != 0 or timed_out:
        partial = Path(str(dest) + ".partial")
        os.replace(dest, partial)
        answer.update({"status": "failed", "error": "icat failed" if not timed_out else "icat did not finish in time",
                       "partial_output": os.path.relpath(partial, Path.cwd().resolve()), "partial_bytes": size,
                       "note": "What icat wrote before it stopped is kept as partial_output; it is not an extraction."})
        print(json.dumps(answer, indent=2))
        raise SystemExit(1)
    answer.update({"status": "complete", "output": output, "size": size, "sha256": h.hexdigest()})
    print(json.dumps(answer, indent=2))


if __name__ == "__main__":
    main()

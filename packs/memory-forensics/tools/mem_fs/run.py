#!/usr/bin/env python3
"""Drive MemProcFS, which turns a memory image into a file tree.

The reason this pack prefers MemProcFS to Volatility is a licence one and it is
worth stating once: MemProcFS is AGPL-3.0, the same licence as this harness, so
there is nothing to weigh before driving it. Volatility's licence and this one
do not combine, which is why there is no wrapper for it anywhere in this project
and why the skills tell an agent to invoke `vol` directly instead.

What the mount gives you: sys/proc for the process tree, py/ and misc/ for the
parsed artefacts, and a directory per process holding its modules, handles,
memory map and dumped regions. All of it is files, so every other tool in the
packs works on it unchanged.

Mounting needs FUSE, which a sandbox may not allow. When the mount fails the
reason is returned rather than swallowed, because "no framework was available"
is a legitimate line in a report and "the memory was examined and nothing was
found" is not.
"""
import json
import os
import shutil
import subprocess
import sys


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the memory image")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    mount = args.get("mount")
    if not isinstance(mount, str) or not mount:
        fail("mount is required: a directory under work/ to mount the image at")
    timeout = args.get("timeout_seconds", 300)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 10:
        fail("timeout_seconds must be an integer of at least 10")

    binary = shutil.which("memprocfs")
    if not binary:
        fail("memprocfs is not on PATH",
             install="https://github.com/ufrisk/MemProcFS/releases",
             note="MemProcFS is AGPL-3.0, the same licence as this harness. Without it, "
                  "triage/no-framework says what a memory image still gives you, and the report "
                  "should say no framework was available rather than that nothing was found.")
    os.makedirs(mount, exist_ok=True)

    argv = [binary, "-device", path, "-mount", mount]
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except OSError as exc:
        fail("memprocfs would not start", reason=str(exc), command=" ".join(argv))

    listing, problem = [], None
    target = os.path.join(mount, args.get("list") or "sys/proc")
    try:
        import time
        waited = 0.0
        while waited < timeout:
            if os.path.isdir(target) and os.listdir(target):
                break
            if proc.poll() is not None:
                problem = "memprocfs exited before the mount appeared"
                break
            time.sleep(0.5)
            waited += 0.5
        else:
            problem = "the mount did not appear within %ds" % timeout
        if not problem:
            for name in sorted(os.listdir(target))[:500]:
                full = os.path.join(target, name)
                listing.append({"name": name, "directory": os.path.isdir(full)})
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()

    stdout, stderr = "", ""
    try:
        stdout, stderr = proc.communicate(timeout=5)
    except Exception:
        pass

    if problem:
        fail(problem, command=" ".join(argv), mount=mount,
             stderr=(stderr or "").strip()[-600:],
             note="Mounting needs FUSE, which a sandbox may refuse. That is a limit on the host, "
                  "not a finding about the evidence, and the report should say so.")

    print(json.dumps({
        "path": path,
        "mount": mount,
        "listed": args.get("list") or "sys/proc",
        "entries": listing,
        "entry_count": len(listing),
        "command": " ".join(argv),
        "note": "The mount is gone now: this tool starts MemProcFS, reads the listing and stops "
                "it, so nothing is left holding the evidence open. To work inside the tree, run "
                "memprocfs yourself with the command above and keep it running.",
    }, indent=2))


if __name__ == "__main__":
    main()

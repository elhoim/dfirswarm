#!/usr/bin/env python3
"""List the volume shadow copies on an image.

A shadow copy is a second, older state of the same volume, kept by Windows
itself. It holds the registry hives, the event logs and the files as they were
at the moment the snapshot was taken, which is how a file deleted last week is
still readable today and how a Run key that has since been cleaned is still
there to be found.

This tool LISTS stores (through vshadowinfo) and suggests the command that would
mount them; it mounts nothing, and listing a snapshot does not examine it.
vshadowinfo reads a raw volume or disk image: an E01 has to be exposed as raw first.

The unit trap is worth naming once: mmls and the Sleuth Kit's -o work in
**sectors**, and vshadowinfo's -o works in **bytes**. Passing one where the
other belongs is why this returns "unable to open volume" on an image that is
perfectly sound, so this tool takes bytes and says so in its own output.

The answer is judged, never assumed: vshadowinfo's exit status, its whole standard
output and error (kept in files), the number of stores it says it found against the number
this tool could read, and the output's own header. A failed or unrecognised run is `failed`,
never an answer that there are no stores; "no stores" is said only when vshadowinfo ran,
exited 0 and itself reported zero stores.
"""
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys

TIMEOUT = 240
STORE = re.compile(r"^Store:\s*(\d+)\s*$")
FIELD = re.compile(r"^\s+(.+?)\s*:\s*(.*\S)\s*$")


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def key_of(label):
    return re.sub(r"[^a-z0-9]+", "_", label.strip().lower()).strip("_")


def tool_output_dir():
    out, job = os.environ.get("OUT"), os.environ.get("JOB_ID")
    if job and out:
        return os.path.join(out, "tool-output"), "store/jobs/%s/out/tool-output" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)
    d = os.path.join("work", re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"), "tool-output")
    return d, d


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    image = args.get("image")
    if not isinstance(image, str) or not image:
        fail("image is required")
    if not os.path.isfile(image):
        fail("no such image", image=image)

    offset = args.get("offset")
    if offset is not None and (not isinstance(offset, int) or isinstance(offset, bool) or offset < 0):
        fail("offset must be a byte offset, not a sector offset", offset=args.get("offset"))

    # Where a store would be mounted: the seat's own directory. The rest of
    # work/ is read-only in a VM, and a mount is that VM's alone either way.
    mount_dir = args.get("mount_dir")
    if mount_dir is None:
        mount_dir = "work/%s/vss" % (os.environ.get("AGENT_ID") or "<your id>")
    elif not isinstance(mount_dir, str) or not mount_dir:
        fail("mount_dir must be a directory path", mount_dir=mount_dir)
    mount_dir = mount_dir.rstrip("/")

    if not shutil.which("vshadowinfo"):
        fail("vshadowinfo is not on PATH",
             install="brew install libvshadow, or apt-get install -y libvshadow-utils")

    argv = ["vshadowinfo"]
    if offset is not None:
        argv += ["-o", str(offset)]
    argv.append(image)
    with open(image, "rb") as fh:
        head = fh.read(8)
    outdir, shown = tool_output_dir()
    digest = hashlib.sha256(json.dumps(argv).encode("utf-8")).hexdigest()[:16]
    os.makedirs(outdir, exist_ok=True)
    out_path = os.path.join(outdir, "vss_stores-%s.stdout.txt" % digest)
    err_path = os.path.join(outdir, "vss_stores-%s.stderr.txt" % digest)
    timed_out = False
    with open(out_path, "wb") as so, open(err_path, "wb") as se:
        proc = subprocess.Popen(argv, stdout=so, stderr=se, stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            rc = proc.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, 9)
            except (OSError, ProcessLookupError):
                pass
            rc = proc.wait()

    with open(out_path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    with open(err_path, "r", encoding="utf-8", errors="replace") as fh:
        stderr = fh.read().strip()
    stores, current = [], None
    for line in text.splitlines():
        m = STORE.match(line)
        if m:
            current = {"store": int(m.group(1))}
            stores.append(current)
            continue
        if current is None:
            continue
        m = FIELD.match(line)
        if m:
            current[key_of(m.group(1))] = m.group(2)

    claimed = None
    m = re.search(r"Number of stores:\s*(\d+)", text)
    if m:
        claimed = int(m.group(1))

    mountable = shutil.which("vshadowmount") is not None
    for store in stores:
        mkdir_argv = ["mkdir", "-p", mount_dir]
        mount_argv = ["vshadowmount"] + (["-o", str(offset)] if offset is not None else []) + [image, mount_dir + "/"]
        store["mount_argv"] = [mkdir_argv, mount_argv]
        store["mount_with"] = "%s && %s  # then %s/vss%d" % (shlex.join(mkdir_argv), shlex.join(mount_argv), mount_dir, store["store"])

    problems = []
    if timed_out:
        problems.append("vshadowinfo was stopped after %d seconds" % TIMEOUT)
    elif rc != 0:
        problems.append("vshadowinfo exited with status %d" % rc)
    if rc == 0 and claimed is None:
        problems.append("vshadowinfo's output has no 'Number of stores' line; this tool does not recognise its format")
    if claimed is not None and claimed != len(stores):
        problems.append("vshadowinfo reports %d store(s) and %d could be read from its output" % (claimed, len(stores)))
    if head == b"EVF\x09\x0d\x0a\xff\x00":
        problems.append("the image starts with the EWF (E01) signature: vshadowinfo reads raw data, so expose the image raw first")

    if problems and (rc != 0 or timed_out or claimed is None):
        status = "failed"
    elif problems:
        status = "partial"
    else:
        status = "complete"

    out = {
        "parser": "vss_stores/2",
        "status": status,
        "image": image,
        "offset_bytes": offset,
        "mount_dir": mount_dir,
        "stores": stores,
        "store_count": len(stores),
        "stores_claimed": claimed,
        "problems": problems,
        "vshadowmount_present": mountable,
        "exit_code": rc,
        "timed_out": timed_out,
        "command": shlex.join(argv),
        "stdout_file": "%s/%s" % (shown, os.path.basename(out_path)),
        "stderr_file": "%s/%s" % (shown, os.path.basename(err_path)),
        "vshadowinfo_stderr_lines": len(stderr.splitlines()),
        "vshadowinfo_said": stderr.splitlines()[:5],
    }
    if status == "failed":
        out["error"] = "vshadowinfo did not give a usable answer: " + "; ".join(problems)
        out["note"] = ("This is a failure, not a finding: no statement about shadow copies on this volume follows from it, and "
                       "'no stores' must not be reported. Check the offset (BYTES, not sectors), that this is a raw volume or image, and the "
                       "stderr file; then ask again.")
        print(json.dumps(out, indent=2))
        raise SystemExit(1)
    if not stores:
        out["note"] = ("vshadowinfo, run on this image at offset %s, reported 0 stores. That says no store was found in this volume's metadata "
                       "as this reader parsed it. It does not establish that none was ever made or that one was deleted: correlate the host's "
                       "age and configuration with event logs, command history and free-space evidence before saying why no store is present."
                       % (offset if offset is not None else "0 (none given)"))
    elif status == "partial":
        out["note"] = "The list above is incomplete: " + "; ".join(problems) + ". Do not count the stores from it."
    elif not mountable:
        out["note"] = ("vshadowmount is not installed, so the stores cannot be opened here. "
                       "The list above, with the creation times, still belongs in the timeline.")
    else:
        out["note"] = ("Listing is not mounting, and a listed store is not an examined one. To open one, run the mount_argv commands (a FUSE mount "
                       "may be unavailable in a worker), then run the ordinary toolkit against %s/vssN as if it were a volume. The mount is yours alone: "
                       "copy what you derive from it into your own directory and record it. A hive or a log read there is the state at "
                       "the store's creation time, not at acquisition: cite both times." % mount_dir)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()

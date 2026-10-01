#!/usr/bin/env python3
"""kernel-symbols: which Windows kernel a memory image runs, and whether this
image holds the symbol table Volatility needs for it.

  run.py detect --target TARGET [--probe-out DIR]   exit 0 applies, 1 does not, 2 error
  run.py run --target TARGET --out DIR

TARGET is JSON, inline or a file: {"paths": [...], "name": "inputs/x.mem"}.

Volatility's own automagic finds the kernel and names the PDB it wants
(name, GUID, age) whether or not it has the table: with the table, the
`Symbols` row of `windows.info` is the table it read; without it, offline, the
symbol-server address it would have fetched is in its log. Nothing is fetched:
every call is `vol --offline`. detect answers with the identity, and with a
`missing` entry when the table is absent, which the census turns into a line
of catalog/missing.json and a kickoff into a BLOCKER (--allow-missing-symbols
goes on: what needs no kernel table still works). run writes kernel.json,
windows.info.txt (and its stderr, whole), index.tsv and coverage.json.
"""
import json
import os
import re
import subprocess
import sys

PROBE_SECONDS = int(os.environ.get("RECIPE_PROBE_SECONDS", "60"))
STEP_SECONDS = int(os.environ.get("RECIPE_STEP_SECONDS", "900"))
# A file name or file(1) that is not memory: never offered to Volatility.
NOT_MEMORY = (".pdf", ".pcap", ".pcapng", ".evtx", ".txt", ".json", ".csv", ".md", ".html", ".htm", ".xml", ".jpg",
              ".jpeg", ".png", ".gif", ".zip", ".gz", ".xz", ".7z", ".tar", ".doc", ".docx", ".xls", ".xlsx", ".ppt",
              ".pptx", ".mp3", ".mp4", ".wav", ".log", ".js", ".css", ".e01", ".ex01", ".vmdk", ".vhd", ".vhdx", ".ad1")
MEMORY = (".mem", ".dmp", ".vmem", ".raw", ".lime", ".crash", ".dump", ".core", "hiberfil.sys", "pagefile.sys")
# The table Volatility read: .../<pdb>/<GUID>-<age>.json[.xz] (in a directory or a zip).
HELD = re.compile(r"([A-Za-z0-9_.-]+\.pdb)/([0-9A-Fa-f]{32})-([0-9]+)\.json")
# The symbol-server address it wanted: .../download/symbols/<pdb>/<GUID><age in hex>/<pdb>.
WANTED = re.compile(r"/download/symbols/([A-Za-z0-9_.-]+\.pdb)/([0-9A-Fa-f]{32})([0-9A-Fa-f]{1,8})/")


def target(arg):
    t = json.load(open(arg, encoding="utf-8")) if os.path.isfile(arg) else json.loads(arg)
    paths = t.get("paths") or []
    return (paths[0] if paths else ""), (t.get("name") or (paths[0] if paths else ""))


def looks_like_memory(path):
    name = os.path.basename(path).lower()
    if name.endswith(NOT_MEMORY):
        return False
    if name.endswith(MEMORY):
        return True
    try:
        magic = subprocess.run(["file", "-b", path], capture_output=True, text=True, timeout=30).stdout.lower()
    except (OSError, subprocess.TimeoutExpired):
        return False
    return any(w in magic for w in ("crash dump", "hibernation file", "memory dump"))


def have_vol():
    return any(os.access(os.path.join(d, "vol"), os.X_OK) for d in os.environ.get("PATH", "").split(os.pathsep) if d)


def info(path, seconds):
    """(exit code or None on timeout, stdout, stderr) of vol --offline windows.info."""
    try:
        r = subprocess.run(["vol", "--offline", "-vv", "-q", "-f", path, "windows.info"], capture_output=True, text=True, timeout=seconds)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired as e:
        return None, text(e.stdout), text(e.stderr)


def text(x):
    return x.decode("utf-8", "replace") if isinstance(x, bytes) else (x or "")


def identity(stdout, stderr):
    """{"pdb", "guid", "age", "table": "held" | "missing", "symbols": URI or None} or None."""
    for line in stdout.splitlines():
        if line.split("\t", 1)[0].strip() == "Symbols":
            m = HELD.search(line)
            if m:
                return {"pdb": m.group(1), "guid": m.group(2).upper(), "age": int(m.group(3)), "table": "held",
                        "symbols": line.split("\t", 1)[1].strip() if "\t" in line else None}
    m = WANTED.search(stderr) or WANTED.search(stdout)
    if m:
        return {"pdb": m.group(1), "guid": m.group(2).upper(), "age": int(m.group(3), 16), "table": "missing", "symbols": None}
    return None


def missing(ident, shown):
    return [{"kind": "symbols", "identity": {k: ident[k] for k in ("pdb", "guid", "age")},
             "what": f"the symbol table of the Windows kernel {ident['pdb']} {ident['guid']} age {ident['age']}, which {shown} runs: "
                     "this image does not hold it, so Volatility's Windows plugins cannot read it offline "
                     "(what needs no kernel table still works: strings, YARA, carving, a file system of the image)"}]


def main(argv):
    cmd = argv[0] if argv else ""
    args = dict(zip(argv[1::2], argv[2::2]))
    if "--target" not in args:
        print(json.dumps({"ok": False, "error": "--target is required"}))
        return 2
    path, shown = target(args["--target"])
    if not path or not os.path.isfile(path):
        print(json.dumps({"ok": False, "error": "the target is not a readable file"}))
        return 2
    if cmd == "detect":
        if not looks_like_memory(path):
            print(json.dumps({"applies": False, "why": "not memory by its name or file(1)"}))
            return 1
        if not have_vol():
            print(json.dumps({"applies": False, "why": "looks like memory, but vol is not in this image"}))
            return 1
        rc, out, err = info(path, PROBE_SECONDS)
        ident = identity(out, err)
        if not ident:
            why = f"windows.info did not answer within {PROBE_SECONDS}s" if rc is None else "Volatility named no Windows kernel"
            print(json.dumps({"applies": False, "why": f"offered to Volatility as memory; {why}"}))
            return 1
        said = f"Volatility names the kernel {ident['pdb']} {ident['guid']} age {ident['age']}"
        if ident["table"] == "held":
            print(json.dumps({"applies": True, "why": f"{said}, and this image holds its symbol table", "identity": ident}))
        else:
            print(json.dumps({"applies": True, "why": f"{said}; this image does not hold its symbol table", "identity": ident,
                              "missing": missing(ident, shown)}))
        return 0
    if cmd == "run":
        out_dir = args.get("--out")
        if not out_dir:
            print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
            return 2
        os.makedirs(out_dir, exist_ok=True)
        rc, out, err = info(path, STEP_SECONDS)
        with open(os.path.join(out_dir, "windows.info.txt"), "w", encoding="utf-8") as f:
            f.write(out)
        rows = [("windows.info.txt", f"vol --offline windows.info over {shown} (exit {rc if rc is not None else 'timed out'})")]
        if err:
            with open(os.path.join(out_dir, "windows.info.txt.stderr"), "w", encoding="utf-8") as f:
                f.write(err)
            rows.append(("windows.info.txt.stderr", "what vol --offline windows.info said on stderr, whole: the symbol-server address it wanted is there"))
        ident = identity(out, err)
        record = {"input": shown, "how": "vol --offline windows.info (Volatility's automagic names the PDB it wants; nothing is fetched)",
                  **(ident or {"table": "unknown"})}
        with open(os.path.join(out_dir, "kernel.json"), "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)
            f.write("\n")
        rows.insert(0, ("kernel.json", f"the kernel {shown} runs (PDB name, GUID, age) and whether this image holds its symbol table"))
        with open(os.path.join(out_dir, "index.tsv"), "w", encoding="utf-8") as f:
            f.writelines(f"{a}\t{b}\n" for a, b in rows)
        miss = missing(ident, shown) if ident and ident["table"] == "missing" else []
        cov = {"recipe": "kernel-symbols", "status": "complete" if ident else "failed",
               "covered": (f"the kernel identity ({ident['pdb']} {ident['guid']} age {ident['age']}); its table is "
                           + ("held by this image" if ident["table"] == "held" else "not in this image")) if ident else "nothing",
               "not_covered": "every Volatility plugin but windows.info; non-Windows images",
               "missing": miss, "limits_hit": [] if rc is not None else [f"windows.info stopped at {STEP_SECONDS}s"],
               "errors": [] if ident else [f"vol --offline windows.info on {shown} named no Windows kernel (exit {rc}); its stderr is windows.info.txt.stderr"]}
        with open(os.path.join(out_dir, "coverage.json"), "w", encoding="utf-8") as f:
            json.dump(cov, f, indent=2)
        print(json.dumps({"ok": bool(ident), "status": cov["status"]}))
        return 0 if ident else 2
    print(json.dumps({"ok": False, "error": "usage: run.py detect --target T | run --target T --out DIR"}))
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

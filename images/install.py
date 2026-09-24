#!/usr/bin/env python3
"""Runs inside the image build. Installs what spec.json names and records
what the image ended up holding.

A package a pack marks required stops the build if it cannot be installed,
and so does a required program that is not on PATH afterwards. An optional
one that fails is recorded, not fatal: the image says what it lacks rather
than failing to exist. The record, /etc/dfirswarm/image.json, is what a run
cites for "which tools, at which versions, examined this"; /etc/dfirswarm/
NOTICE says whose each program is and under which licence.

A pinned download is fetched over HTTPS, checked against its sha256 before
anything is unpacked, unpacked under /opt/dfir/tools/<name>/ and put on PATH
by a wrapper in /usr/local/bin. An architecture with no entry is recorded,
not guessed.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

VENV = Path("/opt/dfir/venv")
RECORD = Path("/etc/dfirswarm/image.json")
NOTICE = Path("/etc/dfirswarm/NOTICE")
# Where pinned downloads go and where their programs are linked; a test sets both.
TOOLS = Path(os.environ.get("DFIRSWARM_TOOLS_DIR", "/opt/dfir/tools"))
BIN = Path(os.environ.get("DFIRSWARM_BIN_DIR", "/usr/local/bin"))
os.environ.setdefault("DEBIAN_FRONTEND", "noninteractive")


def run(cmd: list[str]) -> bool:
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd).returncode == 0


def arch() -> str:
    try:
        return subprocess.run(["dpkg", "--print-architecture"], capture_output=True, text=True).stdout.strip()
    except FileNotFoundError:
        return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(os.uname().machine, os.uname().machine)


def safe_members(t: tarfile.TarFile, dest: Path) -> list:
    """Regular files, directories and links that stay under dest; nothing
    else. Debian 12's Python (3.11.2) predates extractall's filter argument."""
    root = dest.resolve()
    keep = []
    for m in t.getmembers():
        target = (root / m.name).resolve()
        if not (target == root or str(target).startswith(f"{root}/")):
            raise ValueError(f"{m.name} leaves the download's directory")
        if m.issym() or m.islnk():
            link = (target.parent / m.linkname).resolve() if m.issym() else (root / m.linkname).resolve()
            if not str(link).startswith(f"{root}/"):
                raise ValueError(f"{m.name} links outside the download's directory")
        elif not (m.isfile() or m.isdir()):
            continue
        m.mode &= 0o755
        keep.append(m)
    return keep


def fetch(d: dict, apt: list) -> tuple:
    """Install one pinned download. Returns (record, failure reason)."""
    entry = d.get(arch())
    if not isinstance(entry, dict) or not entry.get("url") or not entry.get("sha256"):
        return None, f"no {arch()} build pinned"
    if d.get("apt_deps") and not run(apt + list(d["apt_deps"])):
        return None, f"its libraries ({', '.join(d['apt_deps'])}) did not install"
    dest = TOOLS / d["name"]
    dest.mkdir(parents=True, exist_ok=True)
    archive = dest / Path(entry["url"]).name
    print(f"+ fetch {entry['url']}", flush=True)
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(entry["url"], timeout=300) as r, open(archive, "wb") as out:
            while chunk := r.read(1 << 20):
                digest.update(chunk)
                out.write(chunk)
    except OSError as e:
        return None, f"download failed: {e}"
    want = entry["sha256"].removeprefix("sha256:").lower()
    if digest.hexdigest() != want:
        archive.unlink(missing_ok=True)
        return None, f"sha256 {digest.hexdigest()} is not the pinned {want}"
    name = archive.name.lower()
    try:
        unpack(archive, name, dest)
    except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile) as e:
        return None, f"could not unpack: {e}"
    program = dest / entry.get("bin", archive.name)
    if not program.is_file():
        return None, f"{entry.get('bin', archive.name)} is not in what was downloaded"
    program.chmod(0o755)
    # A wrapper, not a link: a program that finds its own files from $0 (uac
    # does) would look in the link's directory and find nothing.
    # A program that must run from its own directory (uac checks `pwd`)
    # gets a wrapper that changes into it: paths given to it must then be
    # absolute, which its pack says.
    link = BIN / d["name"]
    link.unlink(missing_ok=True)
    if d.get("run_from_dir"):
        link.write_text(f'#!/bin/sh\ncd "{program.parent}" || exit 1\nexec "./{program.name}" "$@"\n')
    else:
        link.write_text(f'#!/bin/sh\nexec "{program}" "$@"\n')
    link.chmod(0o755)
    return {"version": d.get("version"), "url": entry["url"], "sha256": want}, None


def unpack(archive: Path, name: str, dest: Path) -> None:
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            z.extractall(dest)
        archive.unlink()
    elif name.endswith((".tar.gz", ".tgz", ".tar.xz", ".tar")):
        with tarfile.open(archive) as t:
            t.extractall(dest, members=safe_members(t, dest))
        archive.unlink()


LICENCES = r"""
import json
from importlib import metadata as m
rows = []
for d in m.distributions():
    md = d.metadata
    lic = md.get("License-Expression") or ""
    if not lic:
        classifiers = [c.split(" :: ")[-1] for c in (md.get_all("Classifier") or []) if c.startswith("License")]
        lic = "; ".join(classifiers) or (md.get("License") or "")
    rows.append([md["Name"], d.version, " ".join(lic.split()) or "licence not stated"])
print(json.dumps(sorted(rows)))
"""


def python_licences() -> list:
    """Every Python package in the venv, its version and the licence its metadata states."""
    if not (VENV / "bin" / "python").exists():
        return []
    listed = subprocess.run([str(VENV / "bin" / "python"), "-c", LICENCES], capture_output=True, text=True).stdout
    return [f"{name} {version}  {lic}" for name, version, lic in json.loads(listed or "[]")]


def main(spec_path: str) -> int:
    spec = json.loads(Path(spec_path).read_text())
    failed = {"apt": [], "pip": [], "download": []}

    required_apt = [p for p, req in spec["apt"].items() if req]
    optional_apt = [p for p, req in spec["apt"].items() if not req]
    if not run(["apt-get", "update"]):
        return 1
    apt = ["apt-get", "install", "-y", "--no-install-recommends"]
    if required_apt and not run(apt + required_apt):
        print(f"required apt packages failed: {required_apt}", file=sys.stderr)
        return 1
    for p in optional_apt:
        if not run(apt + [p]):
            failed["apt"].append(p)

    if spec["pip"] or spec["requirements"]:
        # Some wheels have no build for every architecture (flare-floss pulls
        # binary2strings, which arm64 has to compile). The compiler is here
        # for the build only and leaves with it.
        build_deps = ["build-essential", "python3-dev"]
        run(apt + build_deps)
        if not run([sys.executable, "-m", "venv", str(VENV)]):
            return 1
        pip = [str(VENV / "bin" / "pip"), "install", "--no-cache-dir"]
        required = [p for p, req in spec["pip"].items() if req] + spec["requirements"]
        if required and not run(pip + required):
            print(f"required python packages failed: {required}", file=sys.stderr)
            return 1
        for p in [p for p, req in spec["pip"].items() if not req]:
            if not run(pip + [p]):
                failed["pip"].append(p)
        run(["apt-get", "purge", "-y", "--auto-remove", *build_deps])
    downloads = {}
    for d in spec.get("downloads", []):
        got, why = fetch(d, apt)
        if got:
            downloads[d["name"]] = got
        elif d.get("required"):
            print(f"required download {d['name']} failed: {why}", file=sys.stderr)
            return 1
        else:
            failed["download"].append({"name": d["name"], "pack": d.get("pack"), "why": why})
    run(["apt-get", "clean"])
    shutil.rmtree("/var/lib/apt/lists", ignore_errors=True)

    path = f"{VENV / 'bin'}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    record = json.loads(RECORD.read_text()) if RECORD.exists() else {}
    dpkg = subprocess.run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\n", *spec["apt"]],
                          capture_output=True, text=True).stdout
    pip_versions = {}
    if (VENV / "bin" / "pip").exists():
        listed = subprocess.run([str(VENV / "bin" / "pip"), "list", "--format=json"],
                                capture_output=True, text=True).stdout
        pip_versions = {p["name"]: p["version"] for p in json.loads(listed or "[]")}
    record.update({
        "profile": spec["profile"],
        "packs": spec["packs"],
        "pack_versions": spec.get("pack_versions", {}),
        "redistributable": spec.get("redistributable", True),
        "nonredistributable": spec.get("nonredistributable", []),
        "apt": dict(line.split("\t", 1) for line in dpkg.splitlines() if "\t" in line),
        # Every package the image holds, not only the packs' own: what a VM
        # has at stop is compared with this (scripts/vm.ts finishRun), so an
        # install by a guest's root outside the recorded toolchain is named.
        "dpkg_all": dict(line.split("\t", 1) for line in subprocess.run(
            ["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"], capture_output=True, text=True).stdout.splitlines() if "\t" in line),
        "pip": pip_versions,
        "downloads": downloads,
        "binaries": {b["name"]: shutil.which(b["name"], path=path) for b in spec["binaries"]},
        "not_installed": {"apt": failed["apt"], "pip": failed["pip"], "download": failed["download"], "manual": spec["manual"]},
    })
    RECORD.parent.mkdir(parents=True, exist_ok=True)
    RECORD.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n")
    here = Path(spec_path).parent / "NOTICE"
    if here.exists():
        NOTICE.write_text(here.read_text() + "\nPython packages in /opt/dfir/venv:\n" + "\n".join(python_licences()) + "\n")
    found = sum(1 for v in record["binaries"].values() if v)
    print(f"image.json: {found}/{len(record['binaries'])} binaries on PATH, "
          f"{len(failed['apt'])} apt, {len(failed['pip'])} pip and {len(failed['download'])} download optional failures, "
          f"{len(spec['manual'])} manual")
    # A program a pack requires and the image does not have is a broken
    # image, whatever the package manager said: the run would find out first.
    lacking = sorted({b["name"] for b in spec["binaries"] if b.get("required") and not record["binaries"].get(b["name"])})
    if lacking:
        print(f"required programs missing from the image: {', '.join(lacking)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

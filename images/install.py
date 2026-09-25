#!/usr/bin/env python3
"""Runs inside the image build. Installs what spec.json names and records
what the image ended up holding.

  install.py SPEC     a profile image: install what the spec names, then record
  install.py --base   the base image: record only (base.Dockerfile installs)

A package a pack marks required stops the build if it cannot be installed,
and so does a required program that is not on PATH afterwards. An optional
one that fails is recorded, not fatal: the image says what it lacks rather
than failing to exist. The record, /etc/dfirswarm/image.json, is what a run
cites for "which tools, at which versions, examined this"; /etc/dfirswarm/
NOTICE says whose each program is and under which licence; /etc/dfirswarm/
sbom.json lists every package the image holds (Debian, Python, npm, pinned
downloads with their sha256) as a CycloneDX document.

Every image, the base included, records its whole Debian package list
(`dpkg_all`) and its venv (`pip`): what a VM holds at stop is compared with
them (scripts/vm.ts INVENTORY_SCRIPT), so an install outside the image is
named and the image's own packages are not.

A pinned download is fetched over HTTPS, checked against its sha256 before
anything is unpacked, unpacked under /opt/dfir/tools/<name>/ and put on PATH
by a wrapper in /usr/local/bin. An architecture with no entry is recorded,
not guessed.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

# Where the image's venv and record live; a test sets both.
VENV = Path(os.environ.get("DFIRSWARM_VENV", "/opt/dfir/venv"))
ETC = Path(os.environ.get("DFIRSWARM_ETC_DIR", "/etc/dfirswarm"))
RECORD = ETC / "image.json"
NOTICE = ETC / "NOTICE"
SBOM = ETC / "sbom.json"
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


def python_packages() -> list:
    """Every Python package in the venv: [name, version, the licence its metadata states]."""
    if not (VENV / "bin" / "python").exists():
        return []
    listed = subprocess.run([str(VENV / "bin" / "python"), "-c", LICENCES], capture_output=True, text=True).stdout
    return json.loads(listed or "[]")


def npm_packages() -> list:
    """Every package under npm's global root, nested dependencies included:
    [name, version, licence]. Pi and what it pulls in live there."""
    try:
        root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True, timeout=60).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return []
    if not root or not os.path.isdir(root):
        return []
    rows = set()
    top = Path(root)

    def modules(d: Path) -> bool:
        return d == top or d.name == "node_modules"

    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != ".bin"]
        here = Path(dirpath)
        # A package is a directory right under node_modules (npm's global
        # root is one), or under a scope in it.
        if "package.json" not in files or not (
                modules(here.parent) or (here.parent.name.startswith("@") and modules(here.parent.parent))):
            continue
        try:
            pj = json.loads((here / "package.json").read_text())
        except (OSError, ValueError):
            continue
        if not isinstance(pj, dict) or not pj.get("name") or not pj.get("version"):
            continue
        lic = pj.get("license") or pj.get("licenses") or ""
        if isinstance(lic, dict):
            lic = lic.get("type", "")
        elif isinstance(lic, list):
            lic = " OR ".join(str(x.get("type", "")) if isinstance(x, dict) else str(x) for x in lic)
        rows.add((str(pj["name"]), str(pj["version"]), " ".join(str(lic).split()) or "licence not stated"))
    return [list(r) for r in sorted(rows)]


def dpkg_versions(names: list = ()) -> dict:
    """Debian package -> version: the named ones, or every one the image holds."""
    try:
        out = subprocess.run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\n", *names],
                             capture_output=True, text=True).stdout
    except FileNotFoundError:
        return {}
    return dict(line.split("\t", 1) for line in out.splitlines() if "\t" in line)


def pip_versions() -> dict:
    """The venv's packages as `pip list` names them: what INVENTORY_SCRIPT diffs against."""
    if not (VENV / "bin" / "pip").exists():
        return {}
    listed = subprocess.run([str(VENV / "bin" / "pip"), "list", "--format=json"],
                            capture_output=True, text=True).stdout
    return {p["name"]: p["version"] for p in json.loads(listed or "[]")}


def purl(kind: str, name: str, version: str, **qualifiers) -> str:
    q = lambda v: urllib.parse.quote(str(v), safe="")
    if kind == "npm" and name.startswith("@") and "/" in name:
        scope, _, base = name.partition("/")
        path = f"{q(scope)}/{q(base)}"
    elif kind == "pypi":
        path = q(re.sub(r"[-_.]+", "-", name).lower())
    else:
        path = q(name)
    tail = "&".join(f"{k}={q(v)}" for k, v in qualifiers.items() if v)
    return f"pkg:{kind}/{path}@{q(version)}" + (f"?{tail}" if tail else "")


def distro() -> str:
    """debian-12 for a bookworm image, from /etc/os-release."""
    try:
        rel = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
        return f"{rel['ID'].strip(chr(34))}-{rel['VERSION_ID'].strip(chr(34))}"
    except (OSError, KeyError):
        return "debian-12"


def sbom(record: dict, python_rows: list, npm_rows: list) -> dict:
    """The image as a CycloneDX 1.5 document: every Debian package, every
    Python package in the venv, every global npm package, every pinned
    download with the sha256 it was checked against."""
    a = record.get("arch") or arch()
    os_id = distro()
    components, seen = [], set()

    def add(c: dict) -> None:
        if c["bom-ref"] not in seen:
            seen.add(c["bom-ref"])
            components.append(c)

    for name, version in sorted((record.get("dpkg_all") or {}).items()):
        ref = purl("deb", name, version, arch=a, distro=os_id)
        add({"type": "library", "bom-ref": ref, "name": name, "version": version, "purl": ref,
             "properties": [{"name": "dfirswarm:licence", "value": f"/usr/share/doc/{name}/copyright"}]})
    for name, version, lic in python_rows:
        ref = purl("pypi", name, version)
        add({"type": "library", "bom-ref": ref, "name": name, "version": version, "purl": ref,
             "licenses": [{"license": {"name": lic}}]})
    for name, version, lic in npm_rows:
        ref = purl("npm", name, version)
        add({"type": "library", "bom-ref": ref, "name": name, "version": version, "purl": ref,
             "licenses": [{"license": {"name": lic}}]})
    for name, d in sorted((record.get("downloads") or {}).items()):
        ref = purl("generic", name, d.get("version") or "unknown", download_url=d.get("url"),
                   checksum=f"sha256:{d.get('sha256')}")
        add({"type": "application", "bom-ref": ref, "name": name, "version": d.get("version") or "unknown",
             "purl": ref, "hashes": [{"alg": "SHA-256", "content": d.get("sha256")}],
             "externalReferences": [{"type": "distribution", "url": d.get("url")}]})
    profile = record.get("profile", "?")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "dfirswarm images/install.py"}]},
            "component": {
                "type": "container", "bom-ref": f"dfirswarm-{profile}", "name": f"dfirswarm-{profile}",
                "properties": [
                    {"name": "dfirswarm:profile", "value": profile},
                    {"name": "dfirswarm:packs", "value": ",".join(record.get("packs") or [])},
                    {"name": "dfirswarm:redistributable", "value": str(record.get("redistributable", True)).lower()},
                    {"name": "dfirswarm:arch", "value": a},
                ],
            },
        },
        "components": components,
    }


def notice(head: str, record: dict, python_rows: list, npm_rows: list) -> str:
    """The image's NOTICE: its own head (a profile's is the recipe's, program
    by pack), then what the whole image holds, the base's part included."""
    lines = [head.rstrip("\n"), ""]
    if record.get("nonredistributable"):
        lines += ["Not cleared for redistribution: " + ", ".join(record["nonredistributable"])
                  + ". Keep this image on this machine or in a private registry.", ""]
    lines += ["Debian packages: every one in this image, with its version, is in image.json (dpkg_all)",
              "and sbom.json; each one's licence is in /usr/share/doc/<package>/copyright.", ""]
    if npm_rows:
        lines += ["Node packages installed globally (npm root -g):"]
        lines += [f"{name} {version}  {lic}" for name, version, lic in npm_rows] + [""]
    lines += [f"Python packages in {VENV}:"]
    lines += [f"{name} {version}  {lic}" for name, version, lic in python_rows]
    return "\n".join(lines) + "\n"


def write_record(record: dict, head: str) -> None:
    """image.json with the whole package inventory, the NOTICE and the SBOM."""
    record["arch"] = arch()
    record["dpkg_all"] = dpkg_versions()
    record["pip"] = pip_versions()
    record["sbom"] = str(SBOM)
    python_rows, npm_rows = python_packages(), npm_packages()
    ETC.mkdir(parents=True, exist_ok=True)
    RECORD.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n")
    NOTICE.write_text(notice(head, record, python_rows, npm_rows))
    SBOM.write_text(json.dumps(sbom(record, python_rows, npm_rows), indent=1) + "\n")


def base() -> int:
    """The base image's record. base.Dockerfile installs; this says what it
    holds, in the fields a profile image has, so a VM booted from the base
    diffs against a whole baseline. Whether the base may be redistributed is
    the Dockerfile's to say (REDISTRIBUTABLE, NONREDISTRIBUTABLE)."""
    npm = {name: version for name, version, _ in npm_packages()}
    held = [x for x in os.environ.get("NONREDISTRIBUTABLE", "").replace(",", " ").split() if x]
    try:
        node = subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip() or None
    except FileNotFoundError:
        node = None
    record = {
        "profile": "base",
        "pi": npm.get("@earendil-works/pi-coding-agent") or os.environ.get("PI_VERSION"),
        "node": node,
        "python": "%d.%d" % sys.version_info[:2],
        "packs": [],
        "pack_versions": {},
        "redistributable": os.environ.get("REDISTRIBUTABLE", "false") == "true" and not held,
        "nonredistributable": held,
        "apt": {},
        "downloads": {},
        "binaries": {},
        "not_installed": {"apt": [], "pip": [], "download": [], "manual": []},
    }
    write_record(record, "dfirswarm-base: the agent runtime every seat boots, and the third-party software in it.\n"
                         "Each is its authors' work under its own licence; none is dfirswarm's.\n"
                         "Node.js and Pi run the agent, Debian's packages are the examiner's shell, and the venv\n"
                         "holds what the tool library imports (images/library-python.txt).")
    print(f"image.json: base, {len(record['dpkg_all'])} Debian and {len(record['pip'])} Python packages recorded")
    return 0


def profile_record(record: dict, spec: dict, downloads: dict, failed: dict) -> dict:
    """A profile image's record over the one its base wrote. An image is
    redistributable only when what it was built on is too: the base's own
    flags carry into every profile built on it."""
    path = f"{VENV / 'bin'}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    held = sorted(set(record.get("nonredistributable") or []) | set(spec.get("nonredistributable", [])))
    record.update({
        "profile": spec["profile"],
        "packs": spec["packs"],
        "pack_versions": spec.get("pack_versions", {}),
        "redistributable": bool(spec.get("redistributable", True) and record.get("redistributable", True) and not held),
        "nonredistributable": held,
        "apt": dpkg_versions(list(spec["apt"])) if spec["apt"] else {},
        "downloads": downloads,
        "binaries": {b["name"]: shutil.which(b["name"], path=path) for b in spec["binaries"]},
        "not_installed": {"apt": failed["apt"], "pip": failed["pip"], "download": failed["download"], "manual": spec["manual"]},
    })
    return record


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
        # binary2strings, which arm64 has to compile), and some none at all
        # (dfvfs pulls libewf-python and libfvde-python, sdists only). The
        # compiler is here for the build only and leaves with it.
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

    record = profile_record(json.loads(RECORD.read_text()) if RECORD.exists() else {}, spec, downloads, failed)
    here = Path(spec_path).parent / "NOTICE"
    write_record(record, here.read_text() if here.exists() else f"dfirswarm-{spec['profile']}")
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
    sys.exit(base() if sys.argv[1:] == ["--base"] else main(sys.argv[1]))

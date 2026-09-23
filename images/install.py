#!/usr/bin/env python3
"""Runs inside the image build. Installs what spec.json names and records
what the image ended up holding.

A package a pack marks required stops the build if it cannot be installed.
An optional one that fails is recorded, not fatal: the image says what it
lacks rather than failing to exist. The record, /etc/dfirswarm/image.json,
is what a run cites for "which tools, at which versions, examined this".
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

VENV = Path("/opt/dfir/venv")
RECORD = Path("/etc/dfirswarm/image.json")


def run(cmd: list[str]) -> bool:
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd).returncode == 0


def main(spec_path: str) -> int:
    spec = json.loads(Path(spec_path).read_text())
    failed = {"apt": [], "pip": []}

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
        "apt": dict(line.split("\t", 1) for line in dpkg.splitlines() if "\t" in line),
        "pip": pip_versions,
        "binaries": {b["name"]: shutil.which(b["name"], path=path) for b in spec["binaries"]},
        "not_installed": {"apt": failed["apt"], "pip": failed["pip"], "manual": spec["manual"]},
    })
    RECORD.parent.mkdir(parents=True, exist_ok=True)
    RECORD.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n")
    found = sum(1 for v in record["binaries"].values() if v)
    print(f"image.json: {found}/{len(record['binaries'])} binaries on PATH, "
          f"{len(failed['apt'])} apt and {len(failed['pip'])} pip optional failures, "
          f"{len(spec['manual'])} manual")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

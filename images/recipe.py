#!/usr/bin/env python3
"""Turn packs into image recipes, and say which image a run needs.

  recipe.py build PROFILE --out DIR [--base IMAGE] [--packs DIR]
  recipe.py profile-for PACK...        the smallest profile holding these packs
  recipe.py list                       profiles and the packs each resolves to

A profile is a named set of packs (images/profiles.json), with every pack's
dependencies added, so an image never lacks the base its method builds on.
For each pack, `requires/host.json` says which binaries its method calls and
how to install them, and `requires/python.txt` lists the libraries its tools
import. The packs are the single source: a microVM run's probe checks the
image against them (scripts/vm.ts imageFit), and this turns the same lines
into an image. On the host the agents install what they lack themselves.

`build` writes DIR/spec.json (what to install, and what cannot be installed
from a package manager), DIR/NOTICE (every program, its pack, its licence and
where it comes from) and DIR/Dockerfile, and copies install.py beside them,
so DIR is a complete build context:

  docker build -t dfirswarm-re:dev-amd64 DIR

A program a pack marks `redistributable: false` stops the build unless
`--allow-nonredistributable` is given: an image that stays on this machine or
in a private registry, never one published for others to pull. The image then
says so (image.json, its label, its NOTICE).

A program no package manager has may carry a pinned download in its pack
(`install.download`: a version, and per architecture a URL, its sha256 and the
program's path inside the archive). install.py fetches it, checks the sha256
and puts the program on PATH; an architecture with no entry is recorded as not
installed. Anything else is listed under `manual` and never installed.
"""
import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKS = HERE.parent / "packs"
APT = re.compile(r"^(?:sudo\s+)?apt(?:-get)?\s+install\s+(.+)$")
PIP = re.compile(r"^python3\s+-m\s+pip\s+install\s+(.+)$")


def profiles() -> dict:
    """name -> {"packs": [...], "apt": [...]}; a bare list is the packs alone."""
    raw = json.loads((HERE / "profiles.json").read_text())["profiles"]
    return {name: (v if isinstance(v, dict) else {"packs": v}) for name, v in raw.items()}


def depends(packs: Path, name: str) -> list:
    manifest = packs / name / "pack.json"
    if not manifest.exists():
        return []
    deps = json.loads(manifest.read_text()).get("depends") or []
    return [re.split(r"[<>=!~ ]", d, maxsplit=1)[0] for d in deps]


def resolve(packs: Path, names: list) -> list:
    """The packs and everything they depend on, dependencies first."""
    out: list = []

    def visit(name: str, trail: tuple) -> None:
        if name in out:
            return
        if name in trail:
            raise SystemExit(f"recipe: dependency cycle through {name}")
        for dep in depends(packs, name):
            visit(dep, trail + (name,))
        out.append(name)

    for n in names:
        visit(n, ())
    return out


def words(tail: str) -> list:
    return [w for w in tail.split() if not w.startswith("-")]


def pack_version(packs: Path, name: str) -> dict:
    """The pack's version and seal (sha256 of its sorted checksums), as vm.ts packSeal computes it."""
    manifest = json.loads((packs / name / "pack.json").read_text())
    sums = (manifest.get("checksums") or {}).get("sha256") or {}
    ordered = {k: sums[k] for k in sorted(sums)}
    seal = hashlib.sha256(json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return {"version": manifest.get("version", "?"), "seal": seal}


def read_pack(packs: Path, name: str) -> dict:
    spec = {"apt": {}, "pip": {}, "requirements": [], "binaries": [], "manual": [], "downloads": []}
    host = packs / name / "requires" / "host.json"
    if host.exists():
        for b in json.loads(host.read_text())["binaries"]:
            install = b.get("install") or {}
            line = install.get("apt", "").strip()
            required = not b.get("optional", False)
            spec["binaries"].append({"name": b["name"], "pack": name, "required": required,
                                     "licence": b.get("licence"),
                                     "redistributable": b.get("redistributable", True) is not False,
                                     "source": line})
            if isinstance(install.get("download"), dict):
                spec["downloads"].append({"name": b["name"], "pack": name, "required": required,
                                          **install["download"]})
                spec["binaries"][-1]["source"] = f"download {install['download'].get('version', '?')}"
            elif m := APT.match(line):
                for p in words(m.group(1)):
                    spec["apt"][p] = spec["apt"].get(p, False) or required
            elif m := PIP.match(line):
                for p in words(m.group(1)):
                    spec["pip"][p] = spec["pip"].get(p, False) or required
            else:
                spec["manual"].append({"name": b["name"], "pack": name, "how": line or "no install line"})
    reqs = packs / name / "requires" / "python.txt"
    if reqs.exists():
        for raw in reqs.read_text().splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                spec["requirements"].append(line)
    return spec


def merge(specs: list) -> dict:
    out = {"apt": {}, "pip": {}, "requirements": [], "binaries": [], "manual": [], "downloads": []}
    for s in specs:
        for kind in ("apt", "pip"):
            for p, req in s[kind].items():
                out[kind][p] = out[kind].get(p, False) or req
        out["requirements"] += [r for r in s["requirements"] if r not in out["requirements"]]
        out["binaries"] += s["binaries"]
        out["manual"] += s["manual"]
        for d in s["downloads"]:
            if not any(x["name"] == d["name"] for x in out["downloads"]):
                out["downloads"].append(d)
    return out


def notice(spec: dict) -> str:
    """Every program an image holds, its pack, its licence and where it came from."""
    lines = [f"dfirswarm-{spec['profile']}: third-party programs in this image, by pack.",
             "Each is its authors' work under its own licence; none is dfirswarm's.",
             "Python packages follow with their licences, as the build found them.", ""]
    seen = set()
    for b in spec["binaries"]:
        key = (b["name"], b["pack"])
        if key in seen:
            continue
        seen.add(key)
        flag = "" if b.get("redistributable", True) else "  [not for redistribution]"
        lines.append(f"{b['name']}  ({b['pack']})  {b.get('licence') or 'licence not stated'}  <- {b.get('source') or '?'}{flag}")
    for d in spec["downloads"]:
        for arch in ("amd64", "arm64"):
            if isinstance(d.get(arch), dict):
                lines.append(f"  {d['name']} {arch}: {d[arch].get('url')}  sha256 {d[arch].get('sha256')}")
    return "\n".join(lines) + "\n"


def requirement_names(packs: Path, name: str) -> set:
    names = set()
    reqs = packs / name / "requires" / "python.txt"
    if reqs.exists():
        for raw in reqs.read_text().splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                names.add(re.split(r"[<>=!~\[ ;]", line, maxsplit=1)[0].lower())
    return names


def needs_of(packs: Path, names: list) -> tuple:
    """The programs these packs require, every program they name, and the Python packages their tools import."""
    required, named, python = set(), set(), set()
    for n in names:
        host = packs / n / "requires" / "host.json"
        if host.exists():
            for b in json.loads(host.read_text())["binaries"]:
                named.add(b["name"])
                if not b.get("optional", False):
                    required.add(b["name"])
        python |= requirement_names(packs, n)
    return required, named, python


def profile_for(packs: Path, wanted: list) -> str:
    """The smallest profile whose image serves the wanted packs: one that holds
    them and their dependencies, or one that covers what they use, since a
    pack's skills and tools come from the pack itself and not from the image.
    Covering means every program the packs name, required or optional, is one
    the profile's packs name too, and every Python package their tools import
    is in the profile. `full` holds every pack, so it is always a candidate and
    only ever the choice when nothing smaller serves."""
    need = set(resolve(packs, wanted))
    if not need:
        return "base"
    # A pack this checkout does not have cannot be covered by anything known.
    if any(not (packs / n / "pack.json").exists() for n in need):
        return "full"
    _, want_named, want_python = needs_of(packs, sorted(need))
    best = None
    # A profile with extra packages is chosen by name, never by its packs.
    for name, prof in profiles().items():
        if prof.get("apt"):
            continue
        members = resolve(packs, prof["packs"])
        holds = need <= set(members)
        if not holds:
            _, named, python = needs_of(packs, members)
            if not (want_named <= named and want_python <= python):
                continue
        # Fewest packs first; between two of a size, the one that holds them.
        rank = (len(members), 0 if holds else 1)
        if best is None or rank < best[1]:
            best = (name, rank)
    return best[0] if best else "full"


def build(a) -> int:
    table = profiles()
    if a.profile not in table:
        print(f"recipe: no profile {a.profile}; one of {', '.join(sorted(table))}", file=sys.stderr)
        return 2
    members = table[a.profile]["packs"]
    extra_apt = table[a.profile].get("apt", [])
    missing = [p for p in members if not (a.packs / p).is_dir()]
    if missing:
        print(f"recipe: no such pack(s): {', '.join(missing)}", file=sys.stderr)
        return 2
    packs = resolve(a.packs, members)
    spec = merge([read_pack(a.packs, p) for p in packs])
    for pkg in extra_apt:
        spec["apt"][pkg] = True
    held_back = sorted({b["name"] for b in spec["binaries"] if not b.get("redistributable", True)})
    if held_back and not a.allow_nonredistributable:
        print(f"recipe: {a.profile} would hold {len(held_back)} program(s) their packs mark redistributable: false "
              f"({', '.join(held_back)}). Build with --allow-nonredistributable for an image that stays on this "
              f"machine or in a private registry; never publish it.", file=sys.stderr)
        return 3
    spec = {"profile": a.profile, "packs": packs,
            "pack_versions": {p: pack_version(a.packs, p) for p in packs},
            "redistributable": not held_back, "nonredistributable": held_back, **spec}

    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "spec.json").write_text(json.dumps(spec, indent=1) + "\n")
    (a.out / "NOTICE").write_text(notice(spec))
    shutil.copy(HERE / "install.py", a.out / "install.py")
    (a.out / "Dockerfile").write_text(f"""# Generated by images/recipe.py from packs: {", ".join(packs) or "none"}. Do not edit.
ARG BASE={a.base}
FROM ${{BASE}}
COPY install.py spec.json NOTICE /tmp/dfirswarm-build/
RUN python3 /tmp/dfirswarm-build/install.py /tmp/dfirswarm-build/spec.json \\
 && rm -rf /tmp/dfirswarm-build
ENV PATH=/opt/dfir/venv/bin:$PATH
LABEL org.opencontainers.image.title="dfirswarm-{a.profile}" \\
      dev.dfirswarm.profile="{a.profile}" \\
      dev.dfirswarm.packs="{",".join(packs)}" \\
      dev.dfirswarm.redistributable="{str(not held_back).lower()}"
""")
    req_apt = sum(spec["apt"].values())
    print(f"{a.profile}: {len(packs)} pack(s), {len(spec['apt'])} apt ({req_apt} required), {len(spec['pip'])} pip, "
          f"{len(spec['requirements'])} python requirements, {len(spec['downloads'])} pinned downloads, "
          f"{len(spec['manual'])} neither"
          + (f"; NOT for redistribution ({len(held_back)} programs)" if held_back else ""))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("profile")
    b.add_argument("--packs", type=Path, default=PACKS)
    b.add_argument("--out", required=True, type=Path)
    b.add_argument("--base", default="dfirswarm-base:dev-amd64")
    b.add_argument("--allow-nonredistributable", action="store_true",
                   help="build an image holding programs their packs mark redistributable: false (never publish it)")
    f = sub.add_parser("profile-for")
    f.add_argument("packs", nargs="*")
    f.add_argument("--packs-dir", type=Path, default=PACKS)
    sub.add_parser("list").add_argument("--packs-dir", type=Path, default=PACKS)
    a = ap.parse_args()
    if a.cmd == "build":
        return build(a)
    if a.cmd == "profile-for":
        print(profile_for(a.packs_dir, a.packs))
        return 0
    print(json.dumps({name: {"packs": resolve(a.packs_dir, prof["packs"]), "apt": prof.get("apt", [])} for name, prof in profiles().items()}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())

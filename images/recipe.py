#!/usr/bin/env python3
"""Turn packs into image recipes, and say which image a run needs.

  recipe.py build PROFILE --out DIR [--base IMAGE] [--packs DIR]
  recipe.py profile-for PACK...        the smallest profile holding these packs
  recipe.py list                       profiles and the packs each resolves to

A profile is a named set of packs (images/profiles.json), with every pack's
dependencies added, so an image never lacks the base its method builds on.
For each pack, `requires/host.json` says which binaries its method calls and
how to install them, and `requires/python.txt` lists the libraries its tools
import. The packs are the single source: the kickoff checks a host against
them, and this turns the same lines into an image.

`build` writes DIR/spec.json (what to install, and what cannot be installed
from a package manager) and DIR/Dockerfile, and copies install.py beside
them, so DIR is a complete build context:

  docker build -t dfirswarm-re:dev DIR
"""
import argparse
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


def read_pack(packs: Path, name: str) -> dict:
    spec = {"apt": {}, "pip": {}, "requirements": [], "binaries": [], "manual": []}
    host = packs / name / "requires" / "host.json"
    if host.exists():
        for b in json.loads(host.read_text())["binaries"]:
            line = (b.get("install") or {}).get("apt", "").strip()
            required = not b.get("optional", False)
            spec["binaries"].append({"name": b["name"], "pack": name, "required": required,
                                     "licence": b.get("licence")})
            if m := APT.match(line):
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
    out = {"apt": {}, "pip": {}, "requirements": [], "binaries": [], "manual": []}
    for s in specs:
        for kind in ("apt", "pip"):
            for p, req in s[kind].items():
                out[kind][p] = out[kind].get(p, False) or req
        out["requirements"] += [r for r in s["requirements"] if r not in out["requirements"]]
        out["binaries"] += s["binaries"]
        out["manual"] += s["manual"]
    return out


def profile_for(packs: Path, wanted: list) -> str:
    """The profile with the fewest packs that holds every wanted pack and its dependencies."""
    need = set(resolve(packs, wanted))
    if not need:
        return "base"
    best = None
    for name, prof in profiles().items():
        if prof.get("apt"):
            continue  # a profile with extra packages is chosen by name, never by its packs
        have = set(resolve(packs, prof["packs"]))
        if need <= have and (best is None or len(have) < best[1]):
            best = (name, len(have))
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
    spec = {"profile": a.profile, "packs": packs, **spec}

    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "spec.json").write_text(json.dumps(spec, indent=1) + "\n")
    shutil.copy(HERE / "install.py", a.out / "install.py")
    (a.out / "Dockerfile").write_text(f"""# Generated by images/recipe.py from packs: {", ".join(packs) or "none"}. Do not edit.
ARG BASE={a.base}
FROM ${{BASE}}
COPY install.py spec.json /tmp/dfirswarm-build/
RUN python3 /tmp/dfirswarm-build/install.py /tmp/dfirswarm-build/spec.json \\
 && rm -rf /tmp/dfirswarm-build
ENV PATH=/opt/dfir/venv/bin:$PATH
LABEL org.opencontainers.image.title="dfirswarm-{a.profile}" \\
      dev.dfirswarm.profile="{a.profile}" \\
      dev.dfirswarm.packs="{",".join(packs)}"
""")
    req_apt = sum(spec["apt"].values())
    print(f"{a.profile}: {len(packs)} pack(s), {len(spec['apt'])} apt ({req_apt} required), {len(spec['pip'])} pip, "
          f"{len(spec['requirements'])} python requirements, {len(spec['manual'])} not from a package manager")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("profile")
    b.add_argument("--packs", type=Path, default=PACKS)
    b.add_argument("--out", required=True, type=Path)
    b.add_argument("--base", default="dfirswarm-base:dev")
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

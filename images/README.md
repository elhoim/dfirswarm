# VM images

`--isolation microvm` boots every agent in its own microVM (microsandbox),
from an OCI image with Pi inside. The harness's own code — the extensions,
the prompts, the packs, the launcher — is never baked in: it is mounted
read-only at boot, so one image outlives any number of harness changes.

| File | What it is |
|---|---|
| `base.Dockerfile` | The agent runtime every seat boots: Node, Pi, Python with a venv at `/opt/dfir/venv` holding what the tool library imports (`library-python.txt`), and the small tools an examiner's shell has (`strings`, `hexdump`, `file`, `xxd`, `sqlite3`, `jq`, the archive tools), plus `socat` for the hub link. |
| `library-python.txt` | The Python packages the tool library's tools import. In the base, so a library tool handed to any run with `--tools-from` works whatever the run's packs; `tests/recipe.test.sh` keeps it in step with the tools' imports. |
| `profiles.json` | A profile is a set of packs: `disk`, `memory`, `re`, `network`, `linux`, `mobile`, `full` — and `web`, the base with Chromium, which `--playwright` boots (the browser tools drive it with this repository's Playwright, mounted read-only). |
| `recipe.py` | Turns a profile's packs — every `requires/host.json` and `requires/python.txt`, with each pack's dependencies — into a Dockerfile, a spec and a NOTICE. `profile-for PACK...` names the smallest profile that serves a run's packs: one that holds them, or one whose packs name every program they name and install every library their tools import (the ransomware pack runs on `re`). `full` only when nothing smaller serves. |
| `install.py` | Runs inside the build: installs what the spec names, fetches each pinned download and checks its sha256, fails on a required package it cannot install and on a required program that is not on PATH afterwards, and writes `/etc/dfirswarm/image.json` — every program it found, every package version (the image's whole package list too), each pack's version and seal, and what it could not install — and `/etc/dfirswarm/NOTICE`. |

## What a run checks

- **Each VM's probe** looks for every program the run's packs require. One
  missing stops the kickoff, unless the agents may install (`--allow-install`),
  and then they are told. An image built from another version of a pack, or one
  that records no pack versions, is said and recorded (`vm/<id>.json`,
  `image_fit`).
- **One image, by digest.** The kickoff resolves the image's tag to a digest
  once (`msb image inspect`), pulling it first when this host does not have it
  — before the run's clock starts, and refused with how to build it when no
  registry has it. Every VM must boot that digest; custody names one that did
  not, and the report shows the image's own record.
- **At stop**, each VM lists what it holds that its image did not — apt
  packages against the image's whole package list, the image's venv against its
  record. An install outside the seat's recorded toolchain is named in custody.

## Build your own

```bash
docker build -f images/base.Dockerfile -t dfirswarm-base:dev-arm64 images
python3 images/recipe.py build memory --out /tmp/img-memory --base dfirswarm-base:dev-arm64 --allow-nonredistributable
docker build -t dfirswarm-memory:dev-arm64 /tmp/img-memory
docker save dfirswarm-memory:dev-arm64 -o /tmp/memory.tar
"$(node --experimental-strip-types scripts/vm.ts msb-path)" load -i /tmp/memory.tar
```

(`amd64` on an Intel or AMD Linux host.) A kickoff with `--pack
memory-forensics` then boots `dfirswarm-memory:dev-<arch>` on its own; name
any other with `--image`.

**`--allow-nonredistributable`.** Every program in the packs is marked
`redistributable: false` until its licence has been reviewed for
redistribution (GPL, AGPL, the Volatility Software License, CPL/IPL and the
rest; the NOTICE lists each with its licence). A build that would hold one
stops without the flag. With it, the image is for this machine or a private
registry: its label, its `image.json` and its NOTICE all say it is not for
redistribution. Never push such an image anywhere public.

**Pinned downloads.** A program no Debian package or PyPI project provides
may carry a pinned download in its pack's `requires/host.json`
(`install.download`): a version, and per architecture the URL, the sha256
GitHub publishes for that asset, and the program's path inside the archive.
`pack.sh seal` refuses one without an https URL and a whole sha256; the build
refuses bytes that are not the pinned ones and an archive that reaches outside
its directory. MemProcFS, avml, hayabusa (its static build: the glibc one needs
a newer glibc than Debian 12's), velociraptor, uac and PowerShell come this way.
What remains manual — Eric Zimmerman's tools, RegRipper, Zircolite, mac_apt,
bulk_extractor (not packaged for Debian 12), iLEAPP and ALEAPP (not on PyPI) —
is listed in `image.json` under `not_installed.manual`.

## Prebuilt images

The pro edition's prebuilt, digest-pinned images are built in the private
`dfirswarm-pro` repository and pushed there as private packages: an image
bundles separately licensed programs, and a package published from this
public repository is public. Point a kickoff at their lock file:

```bash
SWARM_IMAGES_LOCK=/path/to/dfirswarm-pro/images.lock.json scripts/swarm.sh start --isolation microvm ...
```

A private image needs a registry login first (`msb registry login ghcr.io -u <user> --password-stdin`
on a desktop with a keychain; `docker login ghcr.io` on a server, whose
credentials msb reads).

## No network

An examiner's machine with no route out can still run VMs, once the image is
on it: `msb save <ref> -o image.tar` (or `docker save`) on a machine that has
it, carry the file across, `msb load -i image.tar`, and start with `--image
<ref>`. The kickoff then finds the image and pulls nothing. Two things still
want the network and are not in any image: Volatility's Windows symbol tables
(fetched from `msdl.microsoft.com` the first time a kernel is seen; build them
into a layer of your own under the venv's `volatility3/symbols/` from a
connected machine) and capa's rules (`capa --rules` with a directory you
carried across). A model the run calls has to be reachable too, or local
(`--local-only`).

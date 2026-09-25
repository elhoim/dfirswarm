# VM images

`--isolation microvm` boots every agent in its own microVM (microsandbox),
from an OCI image with Pi inside. Nothing of the harness is baked in, so one
image outlives any number of harness changes. The extensions, the scripts
and the prompts are a copy the kickoff takes (in the hub's directory, outside
the run), mounted read-only where the checkout is, so a `git pull` mid-run
reaches no agent. The run's packs are mounted read-only from where
`scripts/pack.sh` installed them (`$DFIRSWARM_HOME/packs/<id>`), after the
kickoff has verified each against its checksums; they are not copied. The
launcher and probe scripts are written into each VM by the SDK.

| File | What it is |
|---|---|
| `base.Dockerfile` | The agent runtime every seat boots: Node, Pi, Python with a venv at `/opt/dfir/venv` holding what the tool library imports (`library-python.txt`), and the small tools an examiner's shell has (`strings`, `hexdump`, `file`, `xxd`, `sqlite3`, `jq`, the archive tools), plus `socat` for the hub link, and `seekfix.c` preloaded (on a macOS host msb swaps `SEEK_DATA` and `SEEK_HOLE` on a mount, and GNU grep then calls a large text file binary; the shim swaps them back only where it sees the swapped answers). It records itself as a profile image does (`install.py --base`): the whole package inventory, a NOTICE, an SBOM, and that it is not for redistribution (it holds `dissect.util`, AGPL-3.0, and Debian's GPL programs, whose source offer is not written yet). |
| `library-python.txt` | The Python packages the tool library's tools import. In the base, so a library tool handed to any run with `--tools-from` works whatever the run's packs; `tests/recipe.test.sh` keeps it in step with the tools' imports. |
| `profiles.json` | A profile is a set of packs: `disk`, `memory`, `re`, `network`, `linux`, `mobile`, `full` — and `web`, the base with Chromium, which `--playwright` boots (the browser tools drive it with this repository's Playwright, mounted read-only). |
| `recipe.py` | Turns a profile's packs — every `requires/host.json` and `requires/python.txt`, with each pack's dependencies — into a Dockerfile (with a builder stage per program built from source), a spec and a NOTICE. `profile-for PACK...` names the smallest profile that serves a run's packs: one that holds them, or one whose packs name every program they name and install every library their tools import (the ransomware pack runs on `re`). `full` only when nothing smaller serves. It reads each pack where a run does: a path as given, an id from `$DFIRSWARM_HOME/packs` and then this repository, so an installed pro or third-party pack is matched by what it names. `--tools-from DIR` adds the programs a tool directory's manifests name (`requires`): an image smaller than `full` that has them all is preferred. `check-lock FILE` refuses an images lock entry that is not pinned by digest. |
| `install.py` | Runs inside the build: installs what the spec names, fetches each pinned artefact (download, `.deb`, source, or a source a builder stage compiles) and checks its sha256, fails on a required package it cannot install and on a required program that is not on PATH afterwards, and writes `/etc/dfirswarm/image.json` — every program it found, every package version (the image's whole Debian list and its venv too), each pack's version and seal, and what it could not install — `/etc/dfirswarm/NOTICE` and `/etc/dfirswarm/sbom.json`. |

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
  record. Every image records both, the base included, so a fresh VM lists
  nothing. An install outside the seat's recorded toolchain is named in
  custody. The list is the guest's own report, taken by its root; the kept
  disk snapshot is the authority.

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
redistribution. Never push such an image anywhere public. The base is not for
redistribution either, under the same rule (`base.Dockerfile` says why), and a
profile carries its base's flag: `web`, whose packs hold nothing, builds
without the flag and is still marked not for redistribution.

**What an image says about itself.** Three files under `/etc/dfirswarm/`,
in every image:

- `image.json` — the profile, its packs with their versions and seals, every
  program found and where, what could not be installed and why, the whole
  Debian package list (`dpkg_all`) and the venv (`pip`), and whether the
  image may be redistributed.
- `NOTICE` — every pack program with its pack, its licence and where it came
  from; then every global npm package and every Python package in the venv
  with the licence its metadata states. Debian's packages keep theirs in
  `/usr/share/doc/<package>/copyright`.
- `sbom.json` — a CycloneDX 1.5 SBOM, written at build time from the same
  inventory: each Debian, Python and npm package with its version and package
  URL, and each pinned download with the sha256 it was checked against.

**Not signed yet.** No image is signed, and nothing verifies a signature. A
run names its image by digest (the lock, or the tag resolved once at
kickoff) and custody says whether every VM booted that digest, which proves
the VMs ran the same image, not who built it. Signing belongs where images
are published, the private `dfirswarm-pro` repository: `cosign sign` by
digest after the push (keyless, from the workflow's identity) and `cosign
attest --type cyclonedx` with the image's own `sbom.json`. The kickoff would
then run `cosign verify` on the lock's digest before it pulls.

**Pinned artefacts.** A program no Debian package or PyPI project provides
carries what the image needs in its pack's `requires/host.json`, as data: the
harness knows the kinds, never a program. `pack.sh seal` refuses an entry
without an https URL and a whole sha256; the build refuses bytes that are not
the pinned ones and an archive that reaches outside its directory, before
anything is unpacked, installed or built.

- `install.download` — a version, and per architecture the URL, its sha256
  and the program's path inside the archive; an architecture with no entry is
  recorded as not installed. MemProcFS, avml, hayabusa (its static build: the
  glibc one needs a newer glibc than Debian 12's), velociraptor, uac and
  PowerShell come this way. A `.deb` is handed to apt from where it was
  checked, so what it depends on comes from Debian: radare2 (upstream's
  package per architecture) and Zeek (the Zeek project's own `zeek-8.0-core`
  for Debian 12; `bin` names where the package puts it, `/opt/zeek/bin`).
- `run` — the interpreter a program needs: `python`, or a program the image
  holds. Eric Zimmerman's MFTECmd, EvtxECmd and RECmd are their net9 zips,
  one for every architecture, each run by `dotnet`, which the same pack pins
  as a download of its own (the .NET 9 runtime per architecture): a runtime
  is installed once, before what runs on it.
- `install.source` — one archive for every architecture, a tag's tarball,
  unpacked under `/opt/dfir/src/<name>` without its top directory, less the
  paths in `skip`; `pip` is run there in a venv of its own
  (`/opt/dfir/src/<name>/.venv`), so one program's pins (ALEAPP's
  beautifulsoup4 4.8.2, iLEAPP's numpy 1.26.4) never move another's or the
  tool library's; `entry` goes on PATH as the pack names the program, run
  with the checkout on `PYTHONPATH`, as from a clone. Zircolite, mac_apt,
  UnifiedLogReader, iLEAPP and ALEAPP come this way; `build_deps` are there
  for the build only, `apt_deps` stay.
- `install.build` — a source archive compiled in a builder stage of its own
  (`./configure --prefix=/opt/dfir/tools/<name>`, `make`, `make
  install-strip`), from the same base; only the prefix is copied into the
  image, so the compiler and the `-dev` packages are not in it, and every
  profile that builds the program shares the stage's cache. A build that
  fails is recorded beside what it left, and an optional program's failure
  does not stop the image. bulk_extractor (not packaged for Debian 12) comes
  this way.
- An apt line with `-t bookworm-backports` takes its package from the image's
  own Debian backports, added from the mirror the image already uses and from
  nowhere else: Suricata.
- `not_in_image` (with why) — a program that belongs to another system:
  Apple's `log` (macOS only; UnifiedLogReader.py reads the same archives in
  the image) and CyLR (a collector, run on the host being collected). It is
  listed under `not_applicable` in `image.json` and the NOTICE, and a VM's
  toolbox check lists it there too, never as missing; a pack may not require
  one.

Every pinned artefact is in `image.json` (`downloads`, each with its kind,
version, URL and sha256), the NOTICE and the SBOM; a source's own venv is
listed there package by package with its licences. A program that nothing
above installs is listed under `not_installed.manual`; no profile has one
today.

## Prebuilt images

The pro edition's prebuilt, digest-pinned images are built in the private
`dfirswarm-pro` repository and pushed there as private packages: an image
bundles separately licensed programs, and a package published from this
public repository is public. Point a kickoff at their lock file:

```bash
SWARM_IMAGES_LOCK=/path/to/dfirswarm-pro/images.lock.json scripts/swarm.sh start --isolation microvm ...
```

Check a lock before pointing a run at it: `python3 images/recipe.py check-lock
/path/to/images.lock.json` refuses an entry that is not `name@sha256:` and 64
hex digits, since a tag can move under a run and a digest cannot. The kickoff
reads `.images[<profile>][<arch>]` from the lock and boots what it names.

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

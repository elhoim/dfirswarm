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
| `install.py` | Runs inside the build: installs what the spec names, fetches each pinned artefact (download, `.deb`, source, a source a builder stage compiles, or a data file a program reads) and checks its sha256, fails on a required package it cannot install and on a required program that is not on PATH afterwards, and writes `/etc/dfirswarm/image.json` — every program it found, every package version (the image's whole Debian list and its venv too), each pack's version and seal, and what it could not install — `/etc/dfirswarm/NOTICE`, `/etc/dfirswarm/sbom.json` and `/etc/dfirswarm/tools.md`, the list an agent greps. |

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

(`amd64` on an Intel or AMD Linux host.) Check what you built from the inside:
`docker run --rm -v "$PWD/tests:/t:ro" dfirswarm-memory:dev-arm64 sh /t/image-programs.sh`
compiles a C program, finds an AES key schedule planted in random bytes (one of
them past 4 GiB) and round-trips a message through steghide, for each of those
programs the image holds; the `images` workflow runs it on every profile it
builds. The memory image downloads 840 MB of symbol tables and indexes them
once, which adds several minutes to its build. A kickoff with `--pack
memory-forensics` then runs its jobs in `dfirswarm-memory:dev-<arch>` on its
own, while its agents boot the base; name any other with `--image`.

**`--allow-nonredistributable`.** Every program in the packs is marked
`redistributable: false` until its licence has been reviewed for
redistribution (GPL, AGPL, the Volatility Software License, CPL/IPL and the
rest; the NOTICE lists each with its licence). A build that would hold one
stops without the flag. With it, the image is for this machine or a private
registry (an image that carries pinned `install.data` is for the machine that
built it alone: see below): its label, its `image.json` and its NOTICE all say
it is not for redistribution. Never push such an image anywhere public. The base is not for
redistribution either, under the same rule (`base.Dockerfile` says why), and a
profile carries its base's flag: `web`, whose packs hold nothing, builds
without the flag and is still marked not for redistribution.

**What an image says about itself.** Four files under `/etc/dfirswarm/`,
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
- `tools.md` — what an agent in the VM reads: one line a program, with what
  it is for in its pack's words, its pack and the version its package record
  holds; the Python libraries the packs and the tool library install, with the
  note on each; and what a pack names that the image does not hold. The run's
  contract points at this file and names no program itself.

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
  for the build only, `apt_deps` stay. `env` is the environment of its pip:
  mac_apt pins pytsk3 20230125, an sdist whose bundled Sleuth Kit finds the
  libbfio headers the image has for libewf and is then built against libbfio
  without being linked to it, so it would not import; its pack sets
  `ac_cv_header_libbfio_h=no` and the build leaves libbfio out. `arches`
  names the architectures a source is for: mac_apt 1.33.2 looks its statx
  syscall up by `platform.machine()` and knows `arm64` (macOS's name) but
  not `aarch64` (Linux's), so it stops at import on Linux arm64; its packs
  pin it for amd64, and an arm64 image records it as not installed, with why.
- `install.build` — a source archive compiled in a builder stage of its own
  (`./configure --prefix=/opt/dfir/tools/<name>`, `make`, `make
  install-strip`), from the same base; only the prefix is copied into the
  image, so the compiler and the `-dev` packages are not in it, and every
  profile that builds the program shares the stage's cache; `env` is the
  environment of its configure and make. A build that
  fails is recorded beside what it left, and an optional program's failure
  does not stop the image. bulk_extractor (not packaged for Debian 12) comes
  this way. A source with no configure script names its own steps
  (`commands`, each an argument list run in the unpacked tree, with `{prefix}`
  and `{jobs}` filled in) and may be patched first (`patches`, each a url and
  a sha256, applied in order with `patch -p1`): aeskeyfind, which Debian
  packages for amd64 and i386 only, is Debian's pinned upstream tarball and
  Debian's four pinned patches (files over 4 GB among them), built with `make`
  on every architecture.
- `install.data` — a file a program reads and that is not a program: a
  symbol pack, a rule set. One url and its sha256 for every architecture, put
  under the name it has at its url (or `file`) in `into` inside the directory
  of a Python package of the image's venv (`package`), where the program looks
  for it. `warm` is a command run once the file is there, for a program that
  indexes what it finds the first time it runs and would otherwise do it in
  every VM the image boots; a warm that fails is recorded (`warm: failed` in
  `image.json`) and does not lose the file. `check` is a command that must
  succeed once the file is there (the program finds it): a build whose check
  fails does not keep the file, and the images workflow runs every data
  entry's check again with no network. The entry says whether it is
  `redistributable` (the image is not, when either it or its program is not)
  and carries its own `licence`, which goes in the NOTICE beside the program's.
  It hangs from a program's entry and is its own record in `image.json`
  (`downloads`, kind `data`), in the SBOM as a `data` component, and in
  `tools.md` under "Data the programs read". A pinned data file that cannot be
  fetched **fails the build even when its program is optional**: the pack
  pinned it on purpose, and an image without it would say the program is there
  while what it reads is not. `recipe.py build --allow-missing-data` goes on
  without it; the image then records it under `not_installed.data`, and a
  kickoff says so as a WARN. Volatility's Windows symbol tables come this way
  (next section).
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

## Volatility, its symbol tables, and what is not redistributed

Volatility 3 helps a memory examination a great deal, and its licence (the
Volatility Software License 1.0) does not let this project distribute it with
its work. So we do not: the memory and `full` images hold it because their
build installs it (`pip install volatility3`, `packs/memory-forensics`), the
image that results is built by whoever runs it, and its label, `image.json` and
NOTICE say it is not for redistribution. **No image that carries
`install.data` (the Volatility symbol tables) is pushed from any workflow of
ours, the pro one included**: we never distribute Volatility or its data,
whoever runs the images builds their own, and Pro builds those per customer
(the roadmap's "Images for programs we cannot redistribute"). The `images`
workflow builds and boots, never pushes.

A Windows plugin needs the symbols of the kernel it reads, and Volatility
fetches them from Microsoft the first time it sees the kernel: not in a VM
with no network. The memory and `full` images therefore carry the Volatility
Foundation's Windows symbol pack, pinned as data in the memory pack
(`install.data` of `vol`):

- **What it is.** `windows.zip` from `downloads.volatilityfoundation.org`, last
  changed 2019-10-16, 839,727,133 bytes, 3,014 tables. The build checks its
  sha256 (the one the Foundation publishes in its `SHA256SUMS`), puts it as
  named in the venv's `volatility3/symbols/` and lists it once
  (`vol -q isfinfo`). Volatility indexes every table it finds the first time it
  runs, which took 3 minutes 22 seconds for this pack on a fast machine and
  would be repeated in every VM; the index is built at image build time and a
  fresh container lists the pack in well under a second.
- **What it covers.** The Windows builds of 2019 and earlier, not every one. It is a
  snapshot: a kernel from a later Windows build is not in it, and
  `vol -q isfinfo` says which are. For those the options are what they were:
  the run's `--allow-host msdl.microsoft.com:80 --allow-host '*.blob.core.windows.net'`
  (Volatility then fetches the one table it needs), or a table made on a connected machine
  (`pdbconv.py`, in Volatility) and added in a layer of your own under the
  venv's `volatility3/symbols/windows/`. A run that finds no table says so; the
  memory pack's `triage/volatility` skill makes it a limitation, not a silent
  fetch.
- **Its licence, in the NOTICE.** Our reading, not legal advice. The pack
  ships no licence text. The Volatility Software License 1.0
  (<https://www.volatilityfoundation.org/license/vsl-v1.0>) says its "Software"
  includes "any data (such as operating system profiles or configuration
  information)" provided with the software, and we read the tables as such
  data. They are generated from Microsoft's public symbol files, whose
  Microsoft Symbol Server licence terms of June 2022
  (<https://learn.microsoft.com/en-us/legal/windows-sdk/microsoft-symbol-server-license-terms>)
  allow use "solely for purposes of performance, security or functional
  debugging and testing of your software as used with Microsoft software, or as
  otherwise authorized by Microsoft" and say you may not "share, publish, rent,
  or lease the Symbol Items, or provide the Symbol Items as stand-alone
  offerings for others to use". Whether examining evidence is within that use
  is not ours to say: those terms may bear on use as well as on
  redistribution. The NOTICE of the image has both clauses in full.

Other small programs the packs now name, for what a run asked for and no image
had: `steghide` (the base pack, so in every image), `aeskeyfind` (memory),
`gcc` and `make` (memory and re: a C scanner over a memory image Python cannot
hold, a decoder for a format no library reads; the compiler stays in the image,
unlike the one a pip build installs and removes), and Pillow (the base pack's
`requires/python.txt`). Left out on purpose: wordlist front ends for
steganography, ImageMagick, ffmpeg and OpenCV (large, with
codecs and delegates and a policy of their own), and anything that reads
credential artefacts out of Windows memory, which is decided separately.

## Prebuilt images

The pro edition's prebuilt, digest-pinned images are built in the private
`dfirswarm-pro` repository and pushed there as private packages: an image
bundles separately licensed programs, and a package published from this
public repository is public. **Not the images that carry `install.data`** (the
memory and `full` images, with Volatility's symbol tables): none of our
workflows pushes those, the pro one included, since a private registry still
copies the tables to GitHub and to every customer who pulls; Pro builds them
per customer, under the customer's own acceptance of the licences. A workflow
that publishes images checks that `spec.json` of the build context lists no
`data` before it pushes, and builds no profile that does. Point a kickoff at a
lock file:

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
want the network: the Windows symbol tables of a kernel newer than the 2019
pack the memory image carries (fetched from `msdl.microsoft.com` the first time
a kernel is seen; build them into a layer of your own under the venv's
`volatility3/symbols/` from a connected machine) and capa's rules (`capa
--rules` with a directory you carried across). A model the run calls has to be reachable too, or local
(`--local-only`).

# VM images

`--isolation microvm` boots every agent in its own microVM (microsandbox),
from an OCI image with Pi inside. The harness's own code — the extensions,
the prompts, the packs, the launcher — is never baked in: it is mounted
read-only at boot, so one image outlives any number of harness changes.

| File | What it is |
|---|---|
| `base.Dockerfile` | The agent runtime every seat boots: Node, Pi, Python with venv, and the small tools an examiner's shell has (`strings`, `hexdump`, `file`, `xxd`, `sqlite3`, `jq`, the archive tools), plus `socat` for the hub link. |
| `profiles.json` | A profile is a set of packs: `disk`, `memory`, `re`, `network`, `linux`, `mobile`, `full` — and `web`, the base with Chromium, which `--playwright` boots (the browser tools drive it with this repository's Playwright, mounted read-only). |
| `recipe.py` | Turns a profile's packs — every `requires/host.json` and `requires/python.txt`, with each pack's dependencies — into a Dockerfile and a spec. `profile-for PACK...` names the smallest profile that holds a run's packs. |
| `install.py` | Runs inside the build: installs what the spec names, fails on a required package it cannot install, and writes `/etc/dfirswarm/image.json` — every binary it found, every package version, and what it could not install. That file is recorded in each VM's `vm/<id>.json`. |

## Build your own

```bash
docker build -f images/base.Dockerfile -t dfirswarm-base:dev-arm64 images
python3 images/recipe.py build memory --out /tmp/img-memory --base dfirswarm-base:dev-arm64
docker build -t dfirswarm-memory:dev-arm64 /tmp/img-memory
docker save dfirswarm-memory:dev-arm64 -o /tmp/memory.tar
"$(node --experimental-strip-types scripts/vm.ts msb-path)" load -i /tmp/memory.tar
```

(`amd64` on an Intel or AMD Linux host.) A kickoff with `--pack
memory-forensics` then boots `dfirswarm-memory:dev-<arch>` on its own; name
any other with `--image`.

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

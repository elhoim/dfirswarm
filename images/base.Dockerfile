# The agent image the harness boots for every seat: an agent runtime and
# nothing case-specific. Profile images (disk, memory, re, ...) are generated
# from the packs by images/recipe.py and build on this one.
#
#   docker build -f images/base.Dockerfile -t dfirswarm-base:dev images
#   docker save dfirswarm-base:dev | msb load
#
# The harness's own code (extensions, prompts, pack skills and tools) is not
# baked in: it is mounted read-only from the host at boot, where the guest's
# root cannot change it, and the launcher that starts Pi comes with the
# harness too (scripts/vm.ts), so an image outlives any number of harness
# changes.
FROM node:24-bookworm-slim

ARG PI_VERSION=0.87.0
RUN npm install -g --no-audit --no-fund "@earendil-works/pi-coding-agent@${PI_VERSION}" \
 && npm cache clean --force

# What every seat uses whatever the case: Python with venv for the pack
# tools, the small utilities an examiner's shell has and the prompts assume
# (strings, hexdump, the archive tools), and socat, which bridges the hub's
# vsock port to the Unix socket the extension dials.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates python3 python3-venv python3-pip jq sqlite3 file xxd socat procps \
      binutils bsdextrautils less unzip p7zip-full xz-utils bzip2 zstd curl libimage-exiftool-perl \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /etc/dfirswarm \
 && printf '{"profile":"base","pi":"%s","node":"%s","python":"%s"}\n' \
      "$PI_VERSION" "$(node --version)" "$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')" \
      > /etc/dfirswarm/image.json

# No image-wide licence label: an image is an aggregate of separately
# licensed programs, and each keeps its own.
LABEL org.opencontainers.image.title="dfirswarm-base" \
      org.opencontainers.image.source="https://github.com/halilozturkci/dfirswarm" \
      dev.dfirswarm.profile="base" \
      dev.dfirswarm.pi-version="${PI_VERSION}"

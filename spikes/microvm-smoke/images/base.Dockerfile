# The agent image the harness boots for every seat: an agent runtime and
# nothing case-specific. Profile images (disk, memory, re, ...) are generated
# from the packs by recipe.py and build on this one.
#
#   docker build -f images/base.Dockerfile -t dfirswarm-base:dev images
#   docker save dfirswarm-base:dev | msb load
#
# The harness's own code (extensions, prompts, pack skills and tools) is not
# baked in: it is mounted read-only from the host at boot, where the guest's
# root cannot change it (the smoke test's tamper check).
FROM node:24-bookworm-slim

ARG PI_VERSION=0.87.0
RUN npm install -g --no-audit --no-fund "@earendil-works/pi-coding-agent@${PI_VERSION}" \
 && npm cache clean --force

# What every seat uses whatever the case: Python with venv for the pack
# tools, the small utilities the prompts assume, and socat, which bridges the
# host's trace collector (a vsock port) to the Unix socket the harness dials.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates python3 python3-venv jq sqlite3 file xxd socat procps \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /etc/dfirswarm \
 && printf '{"profile":"base","pi":"%s","node":"%s"}\n' "$PI_VERSION" "$(node --version)" > /etc/dfirswarm/image.json

# No image-wide licence label: an image is an aggregate of separately
# licensed programs, and each keeps its own.
LABEL org.opencontainers.image.title="dfirswarm-base" \
      org.opencontainers.image.source="https://github.com/halilozturkci/dfirswarm" \
      dev.dfirswarm.profile="base" \
      dev.dfirswarm.pi-version="${PI_VERSION}"

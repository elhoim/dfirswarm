# The agent image the harness boots for every seat: an agent runtime and
# nothing case-specific. Profile images (disk, memory, re, ...) build on it.
#
#   docker build -f images/base.Dockerfile -t dfirswarm-base:dev .
#   docker save dfirswarm-base:dev | msb load
#
# The harness's own code (extensions, prompts, pack skills) is not baked in:
# it is mounted read-only from the host at boot, where the guest's root
# cannot change it (the smoke test's tamper check).
FROM node:24-bookworm-slim

ARG PI_VERSION=0.87.0
RUN npm install -g --no-audit --no-fund "@earendil-works/pi-coding-agent@${PI_VERSION}" \
 && npm cache clean --force

# One forensic tool, so the smoke run can show a case tool works offline.
RUN apt-get update \
 && apt-get install -y --no-install-recommends sleuthkit python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# No image-wide licence label: an image is an aggregate of separately
# licensed programs, and each keeps its own.
LABEL org.opencontainers.image.title="dfirswarm-base" \
      org.opencontainers.image.source="https://github.com/halilozturkci/dfirswarm" \
      dev.dfirswarm.pi-version="${PI_VERSION}"

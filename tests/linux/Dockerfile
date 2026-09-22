# The Linux host the guards are tested on. Harness dependencies only: the
# agents install what a case needs, inside the sandbox, through the allowlist.
FROM node:22-bookworm
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      zsh jq python3 bubblewrap util-linux iproute2 procps git ca-certificates sqlite3 \
    && rm -rf /var/lib/apt/lists/*
# An unprivileged user, because every guard here is about what an
# unprivileged process can and cannot do.
RUN useradd -m -s /bin/bash pane
USER pane
WORKDIR /work

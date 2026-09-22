---
id: containers/docker
title: Containers, and where the evidence actually lives
when: The host ran Docker, containerd or Podman and the incident touched one.
needs: [triage/system-profile]
tools: [timestamp_decode]
requires_host: [fls, icat]
---

A container is not a machine and its evidence is not in one place. On a dead
host, everything you need is under the runtime's own directory.

    /var/lib/docker/containers/<id>/
        config.v2.json       image, command, env, mounts, created and started times
        hostconfig.json      privileged, capabilities, the host paths mounted in
        <id>-json.log        stdout and stderr, with timestamps: the container's own log
    /var/lib/docker/overlay2/<layer>/diff/
        the writable layer: every file the container changed, as files
    /var/lib/docker/image/overlay2/repositories.json     which image each id is
    /var/lib/containerd/, /var/lib/containers/           the same idea, other runtimes

**The writable layer is the crime scene.** `overlay2/<layer>/diff/` holds only
what the container changed against its image, so it is a ready-made list of
everything that was written inside it — dropped binaries included, with their
own ext4 timestamps intact.

**`config.v2.json` gives you the times and the command line.** `Created`,
`StartedAt` and `FinishedAt` are RFC 3339 UTC. The `Path` and `Args` are the
process that ran. `Config.Env` often carries credentials, and a reviewer will
ask whether you looked.

**`hostconfig.json` answers the question that decides scope.** `Privileged:
true`, a `Binds` entry mounting `/` or `/var/run/docker.sock`, or
`CapAdd: ["SYS_ADMIN"]` all mean the container could reach the host — so a
compromise inside it is a compromise of the host, and you must say so.

Two things that are not there. The container's own `/proc` and its memory are
gone unless the host was imaged live. And a container started with `--rm` leaves
no directory at all: its only trace is the daemon's log
(`journalctl -u docker`), the image pull, and whatever it wrote into a mount.

---
id: triage/identity-files
title: Identity files and install date
when: Establishing release, hostname, machine id, mounts, network configuration and install date.
needs: []
tools: []
requires_host: [fls, icat, fsstat, dumpe2fs]
---

Use only if you need the target's identity files or its install date. Not for zones and boot history (`triage/clocks-boots`).

    /etc/os-release              distribution and version; fall back to the vendor's own files; note missing fields
    /etc/hostname                a configured name; correlate with logs and with cloud or VM identifiers
    /etc/localtime               a symlink into zoneinfo or a TZif file; /etc/timezone is optional and can be stale
    /etc/machine-id              set at first boot or by provisioning; a clone or a re-provisioned host duplicates or changes it
    /proc/version (if captured)  the kernel running at collection; installed kernels are another list
    /etc/fstab                   intended mounts, not mount state; captured mount information is separate evidence
    /var/log/installer/          installer logs where the distribution writes them
    /etc/network/, /etc/netplan/, /etc/NetworkManager/   configured addresses and DNS, not what was leased

Read these out of an image with `fls` and `icat`, or from an extracted tree, and keep each file's path and inode.

**Install date.** Do not pick the oldest timestamp among `/etc/machine-id`, `/var/log/installer/` and the root filesystem's creation time (`dumpe2fs -h` on ext, `fsstat` elsewhere). They are different events: filesystem creation, installer activity, machine-id provisioning and the first observed boot. Golden images, cloned disks, restored backups and later provisioning separate them by months. Correlate installer and package records with any cloud-init data, image or deployment metadata and first-boot logs; where those cannot tell installation from deployment, say the installation date is not determinable.

Shows: what is configured, and the dated events a file records. Does not show: that a hostname or machine id identifies one host (clones share them), or one install date. Record: each file's path and inode, and for the install date the events you found and what could not separate them.

Sensitive output: none beyond host and file names.

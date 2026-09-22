---
id: packages/integrity
title: Which binary on this machine is not the one the distribution shipped
when: You suspect a replaced system binary, or you need to clear thousands of files quickly.
needs: [triage/system-profile]
tools: []
requires_host: [debsums, rpm]
---

Linux ships with a hash database of almost every file it installed. It is the
cheapest strong answer on the whole machine, and first passes skip it.

    debsums -c            Debian, Ubuntu: list packaged files whose hash differs
    debsums -a            include configuration files, which change legitimately
    rpm -Va               Red Hat family, with a flag per attribute that changed
    rpm -Va | grep '^..5' the ones whose hash changed, which is the interesting set

`rpm -Va` output is a nine-character mask: `5` is the digest, `S` size, `T`
mtime, `M` mode, `U` owner, `G` group. `S.5....T.` on `/usr/bin/ssh` is a
replaced binary. `.......T.` on a config file is somebody editing it.

Three things to know before you quote the result:

1. **A clean report is not a clean machine.** Only packaged files are covered.
   Anything in `/opt`, `/usr/local`, a home directory or a container layer was
   never hashed by anyone.
2. **The database is on the machine being examined**, so a sufficiently careful
   operator could have updated it after replacing a binary. Check the
   database's own mtime (`/var/lib/dpkg/info/`, `/var/lib/rpm/`) against the
   incident window; a package database written during the intrusion is a far
   louder finding than a modified binary.
3. **Run it against the image, not against your own host.** `debsums
   --root /mnt/evidence` and `rpm --root /mnt/evidence -Va`. Getting this wrong
   verifies your analysis machine and tells you nothing.

Where neither tool exists, the fallback is the distribution's published hashes
for the exact package version, taken from outside the evidence. Say which route
you used.

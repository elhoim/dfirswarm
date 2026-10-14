---
id: triage/system-profile
title: Linux system profile and acquisition
when: You start on a Linux target and must say what was acquired and what covers it.
needs: []
tools: [image_layout, linux_triage]
requires_host: [target-query]
---

Use when you begin on a Linux target. Not for the identity files and install date (`triage/identity-files`, only if you need them) or for zones and boot history (`triage/clocks-boots`, only if timestamps or boots matter).

Everything later depends on what was acquired and on which clocks apply. Record, before anything else, whether the evidence is a disk image, an extracted root, a logical collection or a memory capture, what was collected when, and whether volatile paths (`/proc`, `/run`, mount and process state) were actually captured; a disk image holds none of them. If the evidence is the output of a collection tool or a memory capture, the triage-collection and memory-forensics packs hold the method for those when they are loaded (check the run's tool inventory): a collected tree is a selection and not a disk, and a memory capture needs symbols that match its kernel. Read the distribution release, architecture and filesystem features from the evidence and treat the release name as a starting point: whether `auth.log`, `secure`, the journal, auditd, classic wtmp or a SQLite accounting database exist on this system is read from its files and configuration, not assumed from its name.

For a disk image start with `image_layout`, then `linux_triage` (how the image was taken: base pack `evidence/imaging`, only if you need it). It runs `target-query` (dissect.target) one function at a time, reads a Linux root inside LVM without activating or mounting the evidence, and keeps each family's complete output and each function's stderr. Read `groups[].functions[].status` and `coverage`: `execution_complete` says the processes exited 0, which is not coverage, and `parsed` says a function produced records, not that the artefacts were all there. Record the function list, the installed dissect.target version and the statuses. Treat an `empty` result as a parser's result, not as an absence.

Then, from the evidence: the identity files and install date (`triage/identity-files`), the clocks and boot history (`triage/clocks-boots`), the accounts and their authorization (`accounts/users`), and what was configured to run (`persistence/mechanisms`), keeping what was configured apart from what the evidence shows ran in the incident window.

Shows: what was acquired and what its own files configure. Does not show: a file's presence or date shows what is configured or last changed, not that it was used; a hostname or machine id does not identify a host once images are cloned; nothing here shows who operated the machine. Record: the acquisition kind and time, the volatile paths captured or not, the function list, the dissect.target version and each status.

Sensitive output: `linux_triage`'s family files are bulk extracts: whole histories, authentication and journal lines and container logs, which can hold secrets, and they are not sealed as sensitive unless the job ran with `secret_output: true`. Read them by path and record, quote only what a question needs, and never a secret, a fragment of one or a hash of one.

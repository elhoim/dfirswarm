---
id: filesystem/deleted
title: Deleted files, the recycle bin, and wiped files
when: Files are missing, or you must say whether they are recoverable.
needs: [filesystem/journals]
tools: [recyclebin_i, sig_carve, file_carver]
requires_host: [icat, fls, tsk_recover]
---

Three different states, three different answers.

**Deleted, record intact.** The entry is unallocated, the clusters may or may
not be reused. `istat` tells you the allocation; check the header of whatever
`icat` returns before you believe it. This is where an extract silently becomes
another file's bytes: one published run recovered a registry hive fragment while
believing it had recovered the malware.

Read `init_size` in `istat` before anything else. When it is zero there is
nothing to recover and `icat` will hand you a file of zeros without complaint.
That is itself a finding, and in one published case it was the finding: the
service had deleted its own prefetch record.

**In the recycle bin.** `$Recycle.Bin/<SID>/` holds `$I` metadata and `$R`
contents per file. `recyclebin_i` reads the `$I`: the original full path, the
original size and the deletion time. The SID in the directory name tells you
whose bin it was, which answers who deleted it without any other artefact.

**Securely wiped.** A secure-delete tool renames the file, usually to a run of
one repeated character, overwrites it, then deletes it. What is left is orphan
records with high-entropy content and names like `ZZZZZZZZZZZZZZZ.ZZ`. That
pattern, together with the tool's own prefetch entry, is how you prove a wipe
rather than a delete. Recoverability is then no, and say so plainly: the
overwrite is the point of the tool.

Do not conclude a file is gone until you have looked in the shadow copies. A
snapshot holds the volume as it was before the delete, and reaching it is one
command: `filesystem/shadowcopies`. Skipping that step is the commonest way a
recoverable file gets reported as unrecoverable.

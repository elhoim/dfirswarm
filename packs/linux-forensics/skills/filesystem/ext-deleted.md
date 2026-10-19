---
id: filesystem/ext-deleted
title: ext deleted files and journal recovery
when: Deciding what an inode, the ext journal and listings say about a deleted file.
needs: []
tools: []
requires_host: [debugfs, dumpe2fs, fls, icat, istat]
---

Use only if the question is whether a deleted file's contents or earlier inode state can be recovered. Not for reading inode times (`filesystem/ext`).

**Deleted files.** Determine whether the filesystem has an internal journal, an external one or none, rather than assuming the journal is inode 8: read the superblock (`dumpe2fs -h`) and its features. A journal transaction can retain old copies of inode blocks, and `debugfs -R "logdump -i <inode>" <volume-copy>` is a way into one; keep its complete output and errors. Wrapping, checkpointing, inode reuse and which journal features the installed tool supports limit what that shows. Whether contents come back depends on fragmentation, overwrite, discard and TRIM, thin provisioning and encryption; a surviving directory entry shows a name, not that its data blocks are intact. `fls` lists names including deleted ones and `istat` shows an inode's extents. Unlinking may leave the extent list cleared, so confirm the inode's state before assuming `icat` returns anything.

**Bounded negative.** State the routes and their scope separately, for example: "The inode named no usable extents and no earlier mapping was found in the supplied journal with the stated tool and version. The contents were not recovered by these routes. Carving, snapshots, backups and other copies were examined as listed, or remain unexamined." Do not write that contents are unrecoverable on the strength of an inode and a journal search; the next route is `filesystem/carving` (base pack).

Shows: what a name, an inode and the journal still hold. Does not show: that contents are gone or intact. Record: the journal kind, the `logdump` output and errors, tool versions, every route tried and the ones not.

Sensitive output: recovered contents can hold secrets; keep them in the job's output and cite the path.

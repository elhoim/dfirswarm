---
id: filesystem/apfs
title: APFS, snapshots, and what deletion means now
when: You need a file's true times, a previous state of the volume, or whether something is recoverable.
needs: [evidence/imaging]
tools: [timestamp_decode]
requires_host: [fsapfsinfo]
---

APFS is a container holding several volumes that share one pool of space. That
single fact changes three answers.

**There is more than one volume and you must say which you read.** A modern
machine has at least a sealed, read-only *system* volume and a writable *data*
volume, joined by firmlinks so a user sees one tree. `fsapfsinfo` lists the
container's volumes; the Sleuth Kit will not. Examining only the system volume
finds no user data at all and looks like an empty machine.

**Snapshots are the highest-yield artefact on the platform** and they are the
APFS answer to shadow copies. Time Machine takes local ones automatically, so a
machine with no backup disk attached still usually has several. Each is the
whole volume as it was at a moment, and a file deleted last Tuesday is
ordinarily still inside one. List them with `fsapfsinfo`, mount one, and run the
rest of the pack against it. Check for snapshots before you conclude anything is
gone.

**Deletion is more final than on NTFS.** APFS is copy-on-write with no file
table to leave a record behind: there is no `$MFT` entry to recover, and the
blocks are returned to the shared pool. What survives is the snapshot, the
FSEvents record of the delete (`artifacts/fsevents`), the path in a Spotlight
index, and carving — in that order of usefulness.

The four timestamps are stored in nanoseconds since the Unix epoch, not the
Apple epoch, which catches people who have just come from a plist. Creation
time is a first-class field here, unlike on ext.

Two more things the container carries: it may be **encrypted per volume**, so
one volume opens and another does not (`filesystem/encrypted` in the base pack),
and it holds the **Fusion or sealed-volume hashes**, which is how a modified
system file on macOS 11 and later is detected — the seal simply does not verify,
and `fsapfsinfo` says so.

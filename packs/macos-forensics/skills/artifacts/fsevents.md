---
id: artifacts/fsevents
title: FSEvents, the change log nobody turns off
when: A file was created, renamed or deleted and you need to prove it happened.
needs: [triage/system-profile]
tools: [fsevents_parse]
requires_host: []
---

`/.fseventsd/` on every volume holds a per-volume log of file system changes,
written by the operating system for Spotlight and backup software and kept
whether anyone wants it or not. It survives the file it describes.

    /.fseventsd/fseventsd-uuid    the volume's identity for this log
    /.fseventsd/0000000000abcdef  gzip-compressed record files, named by event id

`fsevents_parse` decompresses and reads them. Each record is a path, an event
id and a flag word saying what happened: created, removed, renamed, modified,
an inode-metadata change, whether it was a file or a directory, and whether it
was the last event known for that path.

**Event ids are a counter, not a clock.** They increase monotonically per
volume and there is no timestamp in the record at all. That makes FSEvents
excellent for *order* and useless for *time* on its own. To place it in a
timeline, anchor it: find an event whose path you can date from another
artefact, and every id before and after it is bracketed. That anchoring step is
what separates a usable FSEvents finding from a suggestive one.

**A rename appears as two flags on one record**, not as two records, so a file
that "disappeared" may have moved. Check for the renamed flag before you report
a deletion.

The log is not complete. Records are coalesced — many changes to one path
collapse into one record with the flags accumulated — and files roll off as the
volume fills. A path that is absent was not necessarily never touched.

An external volume carries its own `/.fseventsd/`, which is how you prove a USB
disk was written to on this machine long after the disk has gone.

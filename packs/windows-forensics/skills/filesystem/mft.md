---
id: filesystem/mft
title: The master file table, and what a record proves
when: You need a file's true times, its size, whether it was deleted, or what a directory used to hold.
needs: [filesystem/extract]
tools: [mft_records, indx_carve, icat_extract, usn_journal]
requires_host: [fls, istat, icat]
---

Every file on an NTFS volume is a record in `$MFT`, and the record outlives the
file. Work from records, not from paths.

Extract `$MFT` once and read it with `mft_records`. `istat` answers one inode at
a time; `mft_records` gives both time sets side by side, every named stream on
the volume, the bytes of resident files, and filters for the deleted and the
timestomped. It applies the update sequence fixup, which hand-rolled arithmetic
over a hex dump does not, and that fixup is two bytes in the middle of a
timestamp.

An inode here is `<entry>-<type>-<id>`: the record, the attribute type, the
attribute instance. `128` is `$DATA`. A second `$DATA` with a name is an
alternate stream, which is why stream ids end in `-4` and up.

Four timestamps live in two places and they disagree on purpose:

- `$STANDARD_INFORMATION` (type 16) is what the shell and most tools show. It is
  what a timestomper changes, because the API to change it is public.
- `$FILE_NAME` (type 48) is written by the kernel on create, rename and move.
  Ordinary software does not touch it.

When the two disagree, say so. But do not present that as proof on its own: `$FN`
can be set indirectly by creating, stomping `$SI`, then renaming so `$FN`
inherits, and current tools write arbitrary sub-second values, so the old
"nanoseconds are all zero" tell is dead too. Treat both as indicators.

The defensible detection is `$LogFile`: it records when the driver wrote the
attribute, whatever value was written. An `$SI` write logged at one time carrying
a value months earlier is manipulation, and nothing else explains it.

A `$STANDARD_INFORMATION` modification time that precedes its own creation time
is still worth reporting, and an ordering that is internally impossible, earlier
than the volume was formatted, is the strongest form of it.

Small files are resident: the data lives inside the record. That is why a
154-byte note can be recovered in full from `$MFT` alone, and why a file whose
record says resident cannot have had its clusters reused.

A deleted entry keeps its record until it is reused. `istat` tells you whether
it is allocated. Check that before you trust anything `icat` hands back.

The directory index `$I30` keeps entries after a delete. An emptied directory
whose `$INDEX_ALLOCATION` slack still names its old contents is how you prove
what was there before somebody wiped it. Extract the stream and hand it to
`indx_carve`: it walks the live entries and then carves the slack past them,
where a deleted file's whole `$FILE_NAME` — the name, the parent, the four
kernel-written times and the size — is usually still sitting. Those times are
the set a timestomper does not reach.

Where the host has `fsntfsinfo`, run it over the same records and compare. Two
independent parsers agreeing is worth more in a report than one, and it costs
one command.

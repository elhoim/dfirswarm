---
id: filesystem/mft
title: MFT records, timestamps, streams and index remnants
when: You need to examine NTFS metadata and distinguish current, historical, reused and partially decoded records.
needs: [filesystem/extract]
tools: [mft_records, indx_carve, icat_extract, extract_stream, usn_journal]
requires_host: [fls, istat, fsntfsinfo, MFTECmd]
---

Every file and directory on an NTFS volume has a record in `$MFT`. A record of a
deleted file stays readable until the volume reuses it, so work from records
and cite the record number together with its sequence number: a reference with
another sequence number points at a different file that once held the same slot.

**Read the whole `$MFT`, once.** `$MFT` is entry 0. Extract it with `icat_extract`,
hash it, and give the copy to `mft_records`. `istat` answers one inode at a
time and prints its attributes with their ids; use it to confirm any record you
rely on. `mft_records` reads every record and returns both time sets, the names
with their parent, every `$DATA` stream with its attribute `instance` id, the
allocation state (`in_use`) and filters (`name`, `entry`, `deleted_only`,
`streams_only`, `timestomp_only`). `limit` is an inline page: when more records
match, the whole list is written as JSON Lines and named in `all_results`; cite
that file, not the page. The record size is read from the first record's header
or taken from `record_size`, and `record_size_from` says which.

**Check a record's state before its content.** The update sequence fixup puts back
the last two bytes of each 512-byte unit, which belong to whichever field spans
them. A record that fails it is still parsed, marked `fixup_failed` (with
`fixup_problem`) and `unreliable`, and counted in `records_fixup_failed`; it does
not make `status` partial, so read the count. A signature of `BAAD` is flagged
`record_marked_bad`. A range that does not fit inside its attribute gives
`structural_errors`, keeps what was sound, marks the record `unreliable`, and
lists it in `problems` with its offset (`status` is then `partial`). Slots with
neither signature (zeroed or damaged) are not listed: `slots_without_signature`
counts them. Fields of an `unreliable` record are provisional: confirm them with
`istat` or a second parser before they carry a conclusion.

**Names, extensions and paths.** A file can have a base record, extension records
and several `$FILE_NAME` attributes (a long name, a DOS short name, one per hard
link). `mft_records` reports every name with `parent_entry` and `parent_sequence`
and every stream with its `instance`. It does **not** resolve `$ATTRIBUTE_LIST`:
a record flagged `has_attribute_list` (with `attribute_list_resolved: false`) keeps
other attributes in extension records, which appear as records of their own with
`base_record`, `base_sequence` and `is_extension_record`. Treat its names and
streams as partial until you have joined them, and say that you did it by hand.
It does not build a path either: take the path from `fls`, or join parents
yourself and require each parent's sequence number to match, or the path may
belong to a file that no longer exists.

An inode address is `<entry>-<type>-<id>`. Type 128 is `$DATA`; the unnamed
stream and each named stream are told apart by name, and the id is assigned per
record, so no id range means "alternate stream". Take the `instance` that
`mft_records` or `istat` reports; do not assume one (`filesystem/ads`).

**Two time sets that can differ.** `$STANDARD_INFORMATION` (type 16) is what the
shell shows and what the public API sets. `$FILE_NAME` (type 48) is usually
written when the name is created, renamed or moved, and not on ordinary writes.
Software can change either, and a difference between them has ordinary causes:
a copy or restore that keeps the modified time, archive extraction, installers,
backup and synchronisation tools, a rename or a move. Neither set is a clock you
can trust or exclude. The tool's `si_` flags are indicators, not proof:
`si_created_before_fn_created`, `si_modified_before_si_created` (common after a
copy), `si_times_identical`, and `si_times_whole_seconds`, which is printed but
is not in the `timestomp_only` filter because current software writes any
fraction and some ordinary paths write none. Compare against the `$FILE_NAME`
that `file_name_times_source` names, and report every set with its raw FILETIME.

Times are UTC with 100 ns resolution. Convert to a local zone only with the zone
and DST history of that date (`registry/system-profile`), never today's offset.
Last-access updates may be disabled or delayed by system configuration, so an
access time is not evidence of an access.

What corroborates a disagreement: `usn_journal` records of the entry (a
`BASIC_INFO_CHANGE` or rename reason near the time a value was stored), and
independent times for the same file in other artefacts. `$LogFile` could hold
transaction context, but its records carry sequence numbers, not clock times, and
this pack does not read it (`filesystem/journals`). Record the strongest benign
explanation beside the observation; "manipulated" is a conclusion that needs a
second source.

**Resident data is a property of the attribute, not of the size.** `mft_records`
marks each stream `resident`; `with_resident` returns the bytes of resident
streams as base64. They survive in a deleted record that has not been reused, and
they belong to that record only: check `sequence`, `in_use` and `unreliable`
first. For a non-resident stream the tool reports `allocated_size`, `real_size`
and `initialised_size` (flag `zero_initialised_size`) and **no data runs**: use
`istat` for the runs and `extract_stream` for the bytes, and keep what came from a
resident attribute apart from what was read from clusters that may have been
reused (`filesystem/deleted`).

**A deleted record** (`deleted_only`) keeps its names and both time sets until
reuse. Those are the times the file had, not the time of deletion;
that comes from the journal, the Recycle Bin or the event logs. Say "the record is
unallocated", not "the file was deleted by X".

**Index remnants.** A directory's `$INDEX_ALLOCATION` (type 160, the `$I30`
index; `istat` on the directory lists its attributes) is extracted with
`extract_stream` by its `<entry>-<type>-<id>` address, hashed, and given to
`indx_carve`. It walks each INDX block's live entries and carves the slack past
them for `$FILE_NAME` structures. It does not read the small index kept inside
a record's `$INDEX_ROOT`. A raw blob can be swept for INDX blocks, with no
directory attached. Read each entry as follows:

- `source` says `live` (the directory lists it) or `slack` (stale). A slack entry
  gives the name, the parent and the four cached times, with `block_offset` and
  the byte `offset`; it gives no record number of its own, so tie it to a record
  by name, parent and times, and say so.
- Integrity travels with the entry: `fixup_ok`, `node_ok`, `salvaged`. Entries
  from a salvaged block are left out unless `include_unreliable` is true, and the
  answer counts `blocks_salvaged` and `entries_excluded_unreliable` (status
  `partial`). Report that count with the finding, and mark any salvaged entry
  you do show.
- The cached times are historical metadata of that structure: not the file's
  current times, not proof they were unaltered. A name that parses is
  structurally plausible, not verified. A slack entry does not say the file was
  deleted or wiped: a rename, a move out of the directory or an index rebalance
  leaves the same trace. Corroborate with the `$MFT` record where one survives
  and with `usn_journal`.

**A second parser.** `fsntfsinfo` reads the volume itself (image and volume offset;
`fsntfsinfo -h` states the unit) and `MFTECmd` reads an extracted `$MFT` (its
runtime is described in `logs/security`). Run one over the entries that matter and
compare names, sizes, times and streams, recording the version of each. Agreement
lowers the chance of a parser fault; it does not validate what the record says.
Where they disagree, the record's bytes decide, and the report says which parser
read what.

**Sensitive output.** `mft_records` with `with_resident` returns the content of
small files, which can hold credentials, keys or messages. Run it in a job with
`secret_output: true` and never write a value, a fragment or a hash of it into the
ledger or a report: record the entry, sequence, stream instance, length and kind
of content only.

**Does not show.** A record, a time or a name does not show who changed or deleted
a file, why, or when a value was changed; that a timestamp was manipulated; that a
stream is complete when an attribute list is unresolved; or that nothing else
existed. A missing record is no evidence of absence, since records are reused.

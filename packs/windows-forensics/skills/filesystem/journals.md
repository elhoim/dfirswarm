---
id: filesystem/journals
title: NTFS change-journal and transaction-log evidence
when: You need to interpret retained changes, file identities and source-local ordering.
needs: [filesystem/mft]
tools: [usn_journal, extract_stream]
requires_host: [fls, istat]
---

Two NTFS logs, with different jobs. The change journal is read by this pack's
tools; the transaction log is not.

**The change journal.** `$Extend\$UsnJrnl` holds the change records in its named
stream `$J`. Find it in the `fls` listing, take the stream's address
(`<entry>-128-<id>`), confirm it with `istat`, and extract it with
`extract_stream` to a file of its own; keep the hash with the address. The stream
is sparse: the extract starts with a long run of zeros, which the parser skips and
counts. Run `usn_journal` once without a filter and keep the whole result
(`all_results` names the file; `limit` is only the inline page). A name filter
narrows what is returned, never what is read: `records_read` is the journal's
total, and a filter that matches nothing says so.

**Read the result as a record of change reasons.** Each record carries the file's
name at that moment, `file_reference` with `file_sequence`, `parent_reference`
with `parent_sequence`, the `reason` bits as names with `reason_raw`,
`source_info`, `security_id`, the attributes, the `usn`, and the timestamp as
UTC with 7 fractional digits beside the raw FILETIME.

- Reason bits accumulate: one record can carry several, and a record with `CLOSE`
  ends an accumulation. The journal is not one entry per operation, and a
  missing reason is not proof the operation did not happen.
- A rename is two records, `RENAME_OLD_NAME` and `RENAME_NEW_NAME`. Pair them by
  file reference **and sequence** across the surrounding records; they are not
  always adjacent.
- A shell delete to the Recycle Bin appears as a rename into the bin (the new name
  is the `$R` name), and `FILE_DELETE` appears when the item leaves it
  (`filesystem/deleted`).
- `security_id` is the file's security descriptor id, not an actor. A record has
  no process and no account: the journal does not say who or what made the
  change.
- Version 2 and 3 records carry names and timestamps; version 4 (range-tracking)
  records carry neither. A `name` filter leaves version-4 records out and counts
  them in `nameless_excluded_by_filter`; `include_nameless: true` keeps them.
  `records_by_version` says what the journal holds.

**Paths and identity.** The journal names a file and its parent by reference, not
by path. Rebuild a path by joining `parent_reference` and `parent_sequence` to a
`$MFT` record with the same entry and sequence (`filesystem/mft`); a parent whose
sequence no longer matches was reused, and the path is unresolved, not "the
current directory". Say which paths you resolved and against which `$MFT` copy.

**Order and clock.** `usn` orders records within this journal, on this volume. The
timestamp is the clock when the record was written. When they disagree, report
both and the possible causes (a clock change, a journal that was deleted and
recreated); do not choose one as true. The journal's id and lowest valid USN are
kept in `$UsnJrnl:$Max`, which `usn_journal` does not read. USNs say nothing about
order across volumes or hosts.

**What survives.** The journal has a size limit and releases old records, so it
holds a window. State the window (first and last timestamp of the records read,
`first_record_offset`, `zero_bytes_skipped`) with every result. Report
`unrecognised_bytes` and `prefix_unrecognised_bytes` with it: they are stretches
that were not read as records, and `unrecognised_ranges` lists them. A bounded
negative reads: "No record naming X was found in the `$J` extracted from <volume>
(<n> records, <first> to <last> UTC); the journal retains only recent changes, and
an absent record is not an absent change." A volume with no `$J`, an empty one or
one that starts late is a coverage fact; it does not show that a journal was
cleared.

**A rename, overwrite and delete sequence** is consistent with several
workflows: an editor or application that saves through a temporary file, an
installer, a synchronisation or backup client, a cleanup job, a secure-delete
utility. Treat it as a hypothesis until a process, content or application
record points to one. The records do not say which bytes were overwritten,
by whom, or whether another copy survives (`filesystem/shadowcopies`).

**The transaction log.** `$LogFile` is NTFS's recovery log. Its records carry log
sequence numbers (LSNs), which order records within one log generation; they are
not clock times and do not order events across volumes or hosts. This pack
provides no `$LogFile` decoder, so an extracted copy is not an examination: say
that the route was not available, or use a parser you have validated and
inventoried, with its version. Do not cite `$LogFile` as an independent clock or as
proof of the true order of events.

**Does not show.** A journal record does not show who changed or deleted a file, from
which program or session, that the content was overwritten, that the change was
malicious, or the file's current state. It shows that the volume recorded a
change with these reasons, under that name and reference, at that clock time.

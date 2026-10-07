---
id: filesystem/deleted
title: Deleted content, Recycle Bin records and recovery limits
when: You need to evaluate deletion evidence and recoverability within the acquired sources.
needs: [filesystem/journals]
tools: [mft_records, icat_extract, recyclebin_i, usn_journal, sig_carve, file_carver]
requires_host: [fls, istat, tsk_recover]
---

"Deleted" covers states with different answers. Say which one you have, and what
was searched.

**A deleted entry whose record survives.** On NTFS the record is unallocated and
keeps its names, times and run list until it is reused; `mft_records` with
`deleted_only` lists such records and `fls` with its deleted-entries option does the
same on the file systems the Sleuth Kit reads. Before you extract, confirm the
allocation and the sizes with `istat`. Record the logical size, the allocated size
and the initialised size separately: `mft_records` flags a non-resident stream
with a real size but an initialised size of zero (`zero_initialised_size`), and
the extraction then returns zeros. That explains the zeros. It does not show that
no bytes survive in other extents, another stream, a shadow copy, a backup or
unallocated space, and it says nothing about which process deleted the file.
Check it with a second parser where it matters (`filesystem/mft`).

An extraction returns whatever the clusters hold **now**. If they were reused, it
is another file's bytes under this file's name. So validate what `icat_extract`
returned beyond its header: the length against the record, the format's internal
structure (parse it with the tool that fits the type), the extents, and any
independent identifier you have (a hash from another source). A recognisable
header does not show the file is whole. `tsk_recover` extracts every deleted file
whose record the Sleuth Kit reads; its output is a set of candidates, validated
one by one, and it neither carves nor checks that the clusters are still the
file's.

**The Recycle Bin.** `$Recycle.Bin\<SID>\` holds a `$I` metadata file and a `$R`
content file per item. Extract the `$I` files from the image (a deleted `$I` whose
record survives can be read like any deleted file) into a directory that keeps
the SID as its name, and run `recyclebin_i` over one `$I` or the whole directory
(sorted output). It reads version 1 and version 2 records and returns the original
path and size, the deletion time (UTC with 7 fractional digits and the raw
FILETIME), `bin_directory_sid` (taken from the directory name) and `r_file`, which
names the `$R` counterpart only if you extracted that file into the same
directory.

- Check `status`, `truncated` and `trailing_bytes` (`records_truncated`,
  `unknown_header` and `unreadable` count what was not whole): a record shorter
  than its layout is returned with the bytes it has and the path decoded as far
  as they go, and is never a complete path; a file over 1 MiB is not read, and an
  unknown header is not guessed at.
- Pair each `$I` with its `$R` by their shared identifier, and record the state
  of the `$R` in the image (present, size against the `$I`'s original size,
  record allocated or not), whether or not `r_file` found it.
- The SID is the account whose bin received the item. It does not say who
  deleted the file, from which session or program, or from where. Corroborate
  with the rename into the bin and the later `FILE_DELETE` in the change journal
  (`usn_journal`, `filesystem/journals`) and with the session evidence in
  `accounts/logons`; say what is established and what is not.
- The deletion time is when the item went to the bin, as the clock stored it, in
  UTC. It is not when the bin was emptied. No `$I` for a file does not show that it
  was not deleted: a deletion that bypasses the bin, a disabled bin, or an
  emptied one (its `$I` records may survive as deleted entries) leaves no live one.

**Overwritten, wiped or discarded.** Separate deletion, later reuse, overwrite,
storage discard (SSD or virtual-disk TRIM and unmap) and missing coverage in the
acquisition. A repeated-character name, high-entropy content, orphan records or
the execution record of a wiping utility are consistent with an attempt; none shows
that a particular file's bytes are gone. To claim an overwrite, show it in the
extents and the surviving content, for the part of the file you mean, and allow for
sparse allocation, compression and encryption, which also give zeros or noise.
State recoverability only for the sources and methods you used.

**Before you write "not recovered".** Name each route you tried and its result, for
example: the record and its extents (`istat`), the extraction and its validation,
`tsk_recover`, a signature scan of unallocated space (`sig_carve`), a cut of a hit
(`file_carver`: it returns offset, size and hash, with no name or times; carved
content has only its image offset as provenance, `filesystem/carving`), the Bin's
`$R`, and the shadow copies and backups that were acquired
(`filesystem/shadowcopies`). A bounded negative reads: "The content of <file> was
not recovered from <sources>: <routes and results>. This does not show that it
cannot be recovered from sources that were not supplied." Record when a secondary
source was not acquired or could not be opened.

**Sensitive output.** Recovered content (from `icat_extract`, `tsk_recover`, a carve) can
hold credentials, keys or messages, and a Recycle Bin path can name one. Extract in a
job with `secret_output: true`, read the content and never run it, and record the
location, the kind of content, its length and what it would grant: never a value, a
fragment or a hash of a secret in a note or a report.

**Does not show.** A deleted record, a `$I` or a carved hit does not show who deleted
the file, why, whether it was deleted deliberately, whether the content was ever
copied elsewhere, or that the content that came back is the content the file had.

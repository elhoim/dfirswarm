---
id: execution/prefetch
title: Prefetch structure, launch history and limitations
when: You need to interpret a Prefetch file or carved candidate using a parser validated for its format.
needs: [execution/overview]
tools: [prefetch_mam, mam_scan, icat_extract]
requires_host: [sccainfo]
---

`C:\Windows\Prefetch\<NAME>.EXE-<HASH>.pf`. The name is the executable's file name;
the hash is derived from the executable's path (with format- and
hosted-application-specific inputs), so the same binary in two directories
normally makes two files. It is not a hash of the file's bytes: do not use it to tie
two copies of a binary together or to identify content. Extract the file with
`icat_extract` and keep the image, the offset and the digest. The `.pf` file's own
filesystem times are separate observations and are not the run times.

**Pick the parser from the header, not from an operating-system label.** `MAM` and a
method byte of 4 mean an Xpress Huffman body; `SCCA` at offset 4 means a plain file.
`prefetch_mam` reads either, and reads the fields by the layout of the SCCA version
(17, 23, 26, 30, 31; 31 is read with version 30's layout and the answer says so).
Another SCCA version, or a MAM method byte other than 4 (a checksum variant), returns
`status: unsupported` with the reason and no run count, time or string. A stream that
inflates past its declared size plus 64 KiB, or ends short, is a failed parse (exit 1,
with the sizes): report it as failed, never as an empty file. `status` is `complete`,
`partial` or `unsupported`: read it and `problems` before you quote a field.

**Observation.** `exe_name`, `prefetch_hash`, `run_count`; `last_runs` in UTC with
seven fractional digits (one slot for versions 17 and 23, up to eight from 26) and the
raw FILETIMEs in `last_runs_detail`; `filename_strings`, the section the header
locates, every string whole; `volumes_decoded`, the first volume entry only (device
path, serial, creation time), with `volumes_claimed` counting the rest, which are not
decoded. The file metrics and the trace chains are located, not decoded. Tie a path in
the string list to a volume through the volume entries, not through a drive letter.

**What it shows.** The run count and the last-run times are what the prefetcher
recorded for this executable path; the slots are the most recent runs, not all of
them. The string list is the set of files and directories the prefetcher referenced
for the executable: a bounded trace and a lead, not a complete list of what the
program opened. A networking library in it is common to legitimate programs and shows
neither a download nor a connection. A reference to the Prefetch directory does not
show that the program deleted Prefetch files. Report behaviour only with process
records, filesystem changes (`filesystem/journals`), application logs or network
evidence.

**Corroborate with an independent reader.** `sccainfo` (optional, built on other
code) over the same file: compare run count, last runs and volumes, and record its
version and what it read. `prefetch_mam` and `mam_scan` share one decoder
(dissect.util's, run behind an output bound), so their agreement says nothing about
that decoder.

**Records without the file.** `mam_scan` sweeps a raw source for `MAM\x04` followed
by a declared size between `min_uncomp` and `max_uncomp` (defaults 1024 and
2,000,000; a size outside is counted under `size_out_of_range` and not read),
inflates each candidate to its declared size and reads it as above, with the offset
and `attempted_range`. Read its accounting before any conclusion: `candidates`,
`parsed`, `failed` with `failed_by_reason`, `filtered_by_name` (a failure is counted
before `name_filter` applies), `unsupported_variant_signatures` (`MAM\x84`
signatures, counted and not read), `scanned_from`, `scanned_to` and `status`
(`partial` when any candidate failed). A parsed record is a Prefetch structure at an
offset of the source you scanned: it carries no file name, owner or path of the file
it came from. The tool does not search for plain `SCCA` records and does not
reassemble fragments, so a negative from it is bounded to `MAM\x04` records in the
scanned range.

**A missing file is not a negative by itself.** Establish the build, the prefetcher's
configuration in the SYSTEM hive (`registry/overview`), the state of its service and
what was collected before you read an absence as "did not run". Zero-length entries in
the Prefetch directory that carry named streams are an anomaly to enumerate
(`filesystem/ads`) and to correlate with execution records; the pack does not support
reading them as a launch from a stream.

**Does not show.** Who ran the program, where it was started from, that it finished or
had an effect, that a listed file was opened by a person, or that these are all its
runs.

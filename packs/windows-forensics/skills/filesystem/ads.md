---
id: filesystem/ads
title: Named NTFS data streams and their interpretation
when: You need to enumerate and extract alternate streams or assess evidence of their use.
needs: [filesystem/mft]
tools: [mft_records, extract_stream, usn_journal, prefetch_mam, file_type]
requires_host: [fls, istat]
---

A named `$DATA` attribute is an alternate data stream (ADS); the unnamed one is
the file's default stream. A file can have an empty default stream and a named
stream full of data, so a listing that shows a size of zero says nothing about
the streams behind it.

**Enumerate from the metadata, not from a colon.** `fls` prints every line with a
colon after the inode, so a grep for `:` matches the listing's own format. Ask
`mft_records` with `streams_only`: each record that carries a named `$DATA` shows
the stream `name`, whether it is `resident`, its sizes and its attribute
`instance` id, and the record's `ads` list. Confirm each candidate with `istat`
(it prints the attributes and their ids), and look at the record's `fls` line to
see the stream beside its directory. Notes:

- Records with `has_attribute_list` keep other attributes in extension records
  (`base_record`, `base_sequence`); their streams may be missing from the base
  record's list, so join them and say so (`filesystem/mft`).
- A deleted record can still carry streams: check `in_use` and `sequence`.
- A bounded negative reads: "No named `$DATA` stream was found in the <n> `$MFT`
  records read (status <complete|partial>, record size from <source>); a stream
  whose record was reused or whose attribute sits in an unresolved extension
  record would not appear."
- Many streams are routine. `Zone.Identifier` is download metadata, and
  synchronisation clients, security products and the shell write their own;
  `$UsnJrnl:$J` is the change journal. Read the content of each before
  deciding what it is.

**Extract by address.** The address is `<entry>-128-<instance>`, with the instance
that `mft_records` or `istat` reports; a bare entry number extracts the default
data attribute. Run `extract_stream` with the image, the address, the volume
offset in **sectors** (`evidence/imaging`) and an `output` file of its own under
the run. It never overwrites, streams the bytes to the file, and answers with the
address as parsed, the size and sha256 of what it wrote, the exit status of the
underlying read and a stderr file; a failed or timed-out read leaves
`<output>.partial` and `status: failed`, which is not an extraction. Record the
whole mapping: source file (entry, sequence, path), stream name, address, offset,
output path, size, sha256. Read the stream with the tool that fits its type; never
run it.

**Classify the bytes.** `file_type` says what the first bytes are and whether that
agrees with the extension; a `.jpg` that is an archive warrants inspection, and a
mismatch does not by itself show concealment or malice. Compare a stream with a
known file only to establish byte identity: a match to a legitimate executable
does not make its presence benign (programs get copied, renamed and run in the
wrong context). Keep what the bytes are apart from the evidence of launch,
arguments, account and resulting activity.

**Date it.** A stream has no timestamps of its own, and the file's times may not
date the stream. `usn_journal` can: look for `STREAM_CHANGE` and the
`NAMED_DATA_` reasons on the file's reference and sequence, bounded by the
journal's window (`filesystem/journals`).

**Reserved device names.** A file named after a reserved DOS device (`LPT1`,
`COM1`) can confuse path-based access through the Windows API. A filesystem parser
reads the record, so report the stored name and the record, and do not treat a
failure of one path interface as evidence that the bytes are unreachable.

**Execution from a stream.** To say a program ran from a named stream, validate
the stream's bytes and find an execution record that identifies the stream or its
path. A Prefetch file for the executable is one record to look for: `prefetch_mam`
reads one file (the executable name, run count, last-run times as UTC with 7
fractional digits and the raw FILETIME, the file name strings, the first volume
entry) and decodes neither the trace chains nor later volume entries. Read its
strings for the stream's path rather than assuming they name it. An odd Prefetch
file name or an empty default stream is a lead, not a signature; the other
execution records and what each proves are in `execution/overview`, and the
Prefetch file format in `execution/prefetch`.

**Sensitive output.** A stream can hold a secret (a token, a key, a download URL
with a credential in it). Extract it in a job with `secret_output: true`: the
tool never prints the bytes. The size and sha256 in its answer are the custody
record of the extracted file and stay in the sealed job output; when the stream is
itself a secret, never copy its value, a fragment of it or a hash of it into the
ledger or a report: record the location, the kind of content, its length and what
it would grant.

**Does not show.** A named stream does not show who created it, that the file it hangs
from was the intended carrier, that its content was used, or that anything ran.
No stream found in the records read does not show that none existed.

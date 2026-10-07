---
id: logs/recovery
title: Recovering and qualifying damaged or residual event records
when: A log is cleared, damaged or incomplete and other acquired sources may retain records.
needs: [logs/security, filesystem/carving]
tools: [evtx_carve, evtx_query, sig_carve, icat_extract]
requires_host: []
---

"The log was cleared" is where this starts, not where it ends. An `.evtx` file is a
4096-byte file header followed by 64 KiB chunks, each with its own magic
(`ElfChnk\x00`), string and template tables, checksums and records, so a chunk can be
read without its file. A cleared or damaged log may leave records in surviving
chunks: in the file itself, in unallocated space, in a snapshot, in memory-related
files. Whether it did depends on allocation, overwrite, discard, fragmentation and
what was acquired. Record each route you try and its result; "no records recovered"
is bounded by the routes.

**Routes, and what each can cover.**

    the damaged .evtx      evtx_carve on the file: it finds chunks by their magic,
                           whatever the file header says
    a whole old log        sig_carve with EVTX finds file headers; icat_extract takes
                           a deleted file's inode out of the image (`filesystem/deleted`)
    unallocated space      evtx_carve on the bytes, given as a raw file
                           (`filesystem/carving` for how to get them)
    pagefile.sys           evtx_carve; a hit is bytes in that file
    hiberfil.sys           evtx_carve reads stored bytes only; see below
    a memory image         evtx_carve; the offset is in the file, not a guest address
    a volume snapshot      an earlier copy of the whole file (`filesystem/shadowcopies`)

`evtx_carve` searches contiguous bytes for chunk structures. It does not rebuild a
chunk whose pages are scattered (a pagefile is paged in 4 KiB units), and it does not
decompress `hiberfil.sys`: a sweep of a compressed hibernation file covers only what
is stored readable, and the pack provides no decompressor. If the memory-forensics
pack is loaded (check the run's tool inventory) a validated conversion may exist;
otherwise say the sweep covered stored bytes only. A hit in a pagefile or a memory
image identifies bytes in that source: not the process that held them, and not the
file they once belonged to. A snapshot is the log as of the snapshot, not as of the
clearing; compare it with the live file, do not substitute one for the other.

**Running a sweep.** When anything matches, `evtx_carve` writes every matching record
with its whole XML to the file the answer names (`all_results`); the inline `records`
are a page of `limit`, without XML unless `with_xml` is set. `chunk_limit` (chunks
parsed) and `candidate_limit` (places where the magic was found, whether or not it
builds into a chunk) bound one call, not the result: when the sweep stops,
`resume_start` is the offset to pass as `start`; continue until `sweep_complete` is true
or you have the range you meant (`max_bytes` bounds it), and read `range_requested`
against `range_examined`. `problems` are a page with the whole list in `all_problems`;
read them. `sweep_complete` means the range was swept, not that every record that ever
existed came back. A repeated EventData name arrives as a list.

**Citing a carved record.** Give the source object, the byte offset of the record in
it (`record_offset`) and of its chunk (`chunk_offset`), the record's own claimed
computer, channel and provider, its EventRecordID, its `time_created`, and
`chunk_verified`. Keep the whole XML. The channel to cite is the one the record
names, not the file it was found in; a record in a pagefile or in unallocated space
has no file. A computer name that is not the machine you examine is a finding to
explain (a log viewed remotely, forwarded events, a copied image), not something to
overwrite. A chunk whose checksums verify is internally consistent: that is not
authenticity, since a copied or altered chunk can verify. A chunk that fails may
still hold sound records; say which kind you quote. A record with missing or
unreliable fields stays partial and does not take the identity of the file around it.
The same record can be carved from several copies of a chunk written at different
times: compare channel, computer, record id and content, report each offset, and do
not count copies as events.

**Order and gaps.** EventRecordID orders records within one computer's channel and one
generation of the log. Clearing, replacement of the file, forwarding, filtering and
mixed recovered generations break any simple reading, and a gap does not measure how
many events are missing. Present recovered records as a set with their sources and
order them by time with the clock caveats of `logs/security`.

**The clearing itself.** A 1102 (Security) or 104 (System) in the surviving log shows
that a clearing was recorded, with the account the audit named; read the cleared
channel from the record. It can be missing from what you hold. An empty channel with
neither does not show that the clearing APIs were not used: the channel can have been
disabled, never written, rotated, replaced, not collected or unreadable. State what
you observed and which explanations remain.

**Bounded negative.** "No evidence of <event> was found in records carved from <source
objects>, <range_examined>, <chunks_found> chunks (<chunks_checksum_ok> verified),
`sweep_complete` <value>, <problem_count> problems; the routes not tried were <...>."

**Sensitive output.** Carved records hold command lines, script text and arguments
that can include a secret, and a pagefile or memory image can hold records of any
process. Run `evtx_carve` as a job with `secret_output: true` when they may; cite
offsets and record ids, describe behaviour, never write values, fragments or hashes.

**Does not show.** Recovered records do not show that the log is whole, that they
belong to this machine, who cleared the log, or why. A deletion, a clearing and a
rollover can look alike; tell them apart only with other sources
(`antiforensics/traces`). To read a recovered whole file use `evtx_query`; the pack
does not convert carved records into an `.evtx` for a rule engine, so read the carved
XML directly (`logs/hunting`).

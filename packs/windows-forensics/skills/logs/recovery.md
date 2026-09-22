---
id: logs/recovery
title: Reading a log that was cleared
when: Security 1102 or System 104 is present, a channel is empty, or the log file is truncated.
needs: [logs/security, filesystem/carving]
tools: [evtx_carve, sig_carve, icat_extract]
requires_host: [icat]
---

"The log was cleared, so there is nothing" is one command short of the answer.

An `.evtx` file is a 4096-byte file header followed by 64 KiB **chunks**, each
one self-contained: `ElfChnk\x00`, its own string and template tables, its own
checksums, and its records. A chunk does not need its file. Clearing a log
rewrites the file; the old chunks stay where they were written.

So sweep for chunks in everything that can hold them:

    evtx_carve on unallocated space        the obvious one
    evtx_carve on pagefile.sys             the log service's own memory, paged out
    evtx_carve on hiberfil.sys             the same, at the last hibernation
    evtx_carve on a memory image           what was live at acquisition
    evtx_carve on the .evtx itself         a truncated or partly overwritten file

Before any of that, try `filesystem/shadowcopies`. A snapshot usually holds the
whole log, intact and verifiable, and a whole log beats carved fragments in
every way that matters to a reviewer.

Three rules for citing a carved record:

1. **Cite the record's own `Channel`, not the file it came from.** A chunk in a
   pagefile belongs to no file. The record says which channel it was written to,
   and that is the attribution that survives review.
2. **Say whether the chunk's checksums verified.** `evtx_carve` reports it per
   chunk. A chunk that does not verify may still hold sound records, and a
   reviewer is entitled to know which kind you are quoting.
3. **Record ids are per channel and monotonic.** Carved records out of order,
   with a gap in the ids, tell you how much is missing — which is itself a
   finding, and a more honest one than a timeline that quietly omits it.

The clearing event survives too. Security 1102 and System 104 carry the account
and the time, and they are written to the *new* file, so they are usually the
first record in it. A channel that is empty with no 1102 and no 104 was not
cleared through the API: it was deleted, disabled, or the file was replaced. Say
which of those you can prove.

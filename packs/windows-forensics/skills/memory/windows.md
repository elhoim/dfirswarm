---
id: memory/windows
title: Windows memory examination and capability checks
when: You have a memory-related source and need to establish its format, available analysis routes and limitations.
needs: [filesystem/carving]
tools: [file_type, mam_scan, evtx_carve, ioc_scan, sig_carve, yara_scan, utf16_urls, regkv]
requires_host: [strings, yara, vol, memprocfs]
mentions: [mem_profile, mem_fs]
---

A memory-related source is a raw or wrapped memory image, a crash dump, a
hibernation file, a pagefile or swap file, or a virtual machine's saved memory.
Each gives different coverage, and an offset means something different in each.

**First, what the source is.** Record where it came from (the acquisition record
and tool), its size and digest, then its format. `file_type` says what a file is
from its first bytes and whether the name agrees; where it names nothing (a raw
image with no header, a pagefile) the format comes from the acquisition record, not
from the size. An offset from a scan is an offset into this file: write it as
"offset N of `<file>`", never as a physical or a process virtual address. A
conversion needs a framework and a named mapping.

**What this pack's tools do on a memory source.** They read bytes as stored:
compressed or paged-out memory and structures split across pages are not
reassembled.

- `strings -a -t d -e l IMAGE` lists UTF-16LE text with decimal offsets, and
  `ioc_scan` searches the needles you give it as ASCII and UTF-16LE (case matters)
  and returns offsets and context; set `unique_only` to false when each
  occurrence's offset matters. `utf16_urls` returns candidates for URLs, `file:`
  and `Visited:` text and 192.168 addresses with offset and encoding; it is not a
  browser parser and reads ASCII-range UTF-16 only.
- `mam_scan` finds MAM-compressed Prefetch records by signature, accounts for every
  candidate (parsed, failed by reason, out of the size range, filtered by name) and
  returns a Prefetch structure in raw bytes with no file name, owner or path. It
  shows a structure was in the source. It does not show a file of that name
  existed on disk, was deleted or ran in this session. A candidate that does not
  inflate to a Prefetch structure stays a partial candidate with its offset;
  use an on-disk parser only after the bytes validate.
- `evtx_carve` sweeps for event-log chunks whose own checksums verify and parses the
  records in them, keeping each record's whole XML in a file it names. A chunk with
  `chunk_verified: false` can still hold sound records, `sweep_complete` means the
  range asked for was swept, not that every record was recovered, and a carved
  record belongs to the channel it names, not to the file it was found in.
- `sig_carve` gives offsets and estimated sizes by signature. An estimate is not a
  boundary. A `regf` hit is at best a hive fragment: `regkv` can read one you wrote
  out, reports what it could not read under `problems` and `partial`, and a key it
  cannot read is not an absent key. It replays no transaction log.
- `yara_scan` (the `yara` program, with a rule file you name) returns per match the
  rule, file, string identifier, offset and length, and no matched bytes. A match
  says the rule's condition held, not that the bytes are malicious or belong to a
  process. It records the rule file's sha256 and yara's version, ships no rules, and
  says `complete: false` when its time limit stopped it.

**A string is an observation.** Its record is the source object, the offset, the
address space, the encoding and the method. Record an unattributed string as bytes
at a source offset, with no process or action assigned: "the domain was present at
offset N of the image, in a region not attributed to a process" is a complete
statement. Attribute it to a process only when address translation and region
ownership support that, and remember a shared page can have more than one mapping.
The same bytes arrive in memory from security-product signature files, browser
caches, log buffers, indexers and the examiner's own tooling. An incomplete
structure may come from fragmentation, missing pages, acquisition loss, damage or a
false match: do not choose between them without evidence. Keep structures a
framework read from live lists apart from remnants found by pool scanning. Seek
independent corroboration, but a sound memory-only finding stands with its
acquisition, parser and temporal limits stated; no disk artefact is required first.

**Frameworks.** `vol` and `memprocfs` are optional here: not shipped with the pack
and not guaranteed to be in the image. Read the job image's `tools.md` and
`image.json` before you plan around them; a program named in a requires file is not
a program in the image. This pack does not carry the symbol tables Volatility needs
for a Windows kernel (the memory-forensics image does). Run `vol` offline with
symbols that match the kernel the image names:

    vol --offline -vv -f IMAGE windows.info

Add `-o "$OUT"` for a plugin that writes files. Record the Volatility version line,
the plugin, the image digest, the symbol identity (the kernel's PDB name, GUID and
age) and the whole diagnostic output. `requires/host.json` names Volatility 3
2.28.2 (as of October 2026); check the version the image carries. Do not turn
`--offline` off: a symbol-server fetch is not a reproducible step. A missing symbol
table, an unsupported container or a plugin error is a limitation and is reported as
one; "no process list" is not "no processes". `memprocfs` mounts an image as files
and needs FUSE, which a worker may not provide: a failed mount is a limitation too.
Say which checks ran with no framework (strings, `yara_scan`, carving) and which
needed one and did not run.

If the memory-forensics pack is loaded (look in the run's tool inventory; do not
assume it from the repository's files), use its guidance for containers, Volatility,
processes, strings and the network (`triage/volatility`, `processes/injection`,
`strings/discipline`) and its `mem_profile` and `mem_fs` in preference to these
summaries.

**Hibernation and the pagefile.** A hibernation file is a saved state. What it holds
depends on how it was written (a full hibernation, or a reduced capture of the kind
Fast Startup involves), and when it was written has to be established, from its own
header and the system's power-state records; it is not automatically the machine
before anyone cleaned up, and a later session can have superseded it. A pagefile or
swap file holds pages that were paged out, with no addresses and no process mapping
from the file itself: scanners give strings and carved structures with file offsets
only. Name the file a hit came from, and give its time as unknown until established.

**Sensitive output.** Memory holds secrets. Run any scan, extraction or framework
output that can expose a credential, a token, a key, a command line or a URL
carrying one as a job with `secret_output: true`: `strings` output, `ioc_scan`
context, `utf16_urls`, `evtx_carve` XML, a `vol` dump or a `memprocfs` export.
`yara_scan` returns locators only; its `write_matches` puts the matched bytes in a
0600 file in the job's output and only in a job run with `secret_output: true`.
In shared prose give where it sits (offset and address space, the process if
validated), its kind, length and what it grants; never the value, a fragment of it
or a hash. Recovered code, scripts and commands are read, never run.

**Does not show.** That a process held, ran, loaded or sent what a scan found; that
a carved structure was ever a file on disk or was deleted; that a search which found
nothing covers other encodings, compressed or fragmented memory or pages that were
not captured; that a missing symbol or an unsupported container means nothing is
there; when a hibernation file or a pagefile's content was written, unless that was
established.

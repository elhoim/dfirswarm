---
id: filesystem/shadowcopies
title: Volume shadow copies and historical source states
when: You need to enumerate available snapshots or compare an artefact across observed volume states.
needs: [filesystem/deleted]
tools: [vss_stores, extract_stream, mft_records]
requires_host: [vshadowinfo, vshadowmount, fls, mmls]
---

A shadow copy lets you read the volume as it was when Windows took the snapshot,
from the volume's own `System Volume Information`. It is a second observed state,
which makes it a place to look for an earlier hive, log or file before you report
one as gone. Snapshots are in the acquisition only if it holds the volume's own
data; a logical or targeted collection does not.

**Enumerate with `vss_stores`.** Give it a raw volume or disk image and the volume
offset in **bytes**. It runs `vshadowinfo` and lists each store with the identifier,
creation time and volume size as `vshadowinfo` prints them, plus the argv of the
`vshadowmount` command that would expose it. It mounts and extracts nothing, and a
listed store is not an examined one. `vshadowinfo` reads raw data: an E01 has to
be exposed raw first (`evidence/imaging`), and the tool adds a problem when it
sees the E01 signature.

**The offset unit changes here.** `mmls` and the Sleuth Kit take **sectors**;
`vshadowinfo` and `vshadowmount` take **bytes**. Multiply the start sector by the
logical sector size recorded for this image (`mmls` prints it in its header), not
an assumed 512, and record both numbers. A wrong unit gives "unable to open
volume" on a sound image; the tool reports that as `failed`, never as "no stores".

**Read the status before the store list.** Check `status`, `exit_code`,
`store_count`, `stores_claimed` and `problems`; the whole `vshadowinfo` output and
stderr are kept in the files `stdout_file` and `stderr_file`.

- `failed` (the tool exits 1): `vshadowinfo` did not give a usable answer (a bad
  offset or unit, a non-raw image, a timeout, an output format the tool does not
  recognise). **No statement about shadow copies follows.** Fix the cause and ask
  again.
- `partial`: a problem was recorded, for example the stores read differ from the
  number `vshadowinfo` claimed. Read `problems`, and do not count stores from that
  list.
- `complete` with zero stores: "`vshadowinfo`, at this offset, reported 0 stores."
  That is what this reader found in this volume's metadata. It does not show that
  none was ever made, or that any was deleted. Possible reasons include never
  created, deleted, aged out of a size limit, and not part of the acquired data.
  A record of a command that removes shadow copies, a service state change such as
  System 7036 for the Volume Shadow Copy service, and low free space are context
  and none shows that a snapshot was deleted; attribute a deletion only where the
  evidence establishes the operation and its outcome (`logs/security`,
  `logs/powershell`). Otherwise write "no stores were found at this offset and the
  reason is not established".
- `complete` with stores: list each with its identifier and creation time.

**Open a store in one job.** A mount exists only in the job that made it and is not
a sealed output. Run the `mount_argv` commands exactly as returned (the mount
directory defaults to your own `work/<your id>/vss`; stores appear as `vss1`,
`vss2`, ...), then use the ordinary toolkit against each `vssN` as if it were a
volume: `fls -r` on it, `extract_stream` with the `vssN` file as the image and
offset 0. Do the mounting, listing and extraction in that job, keep mountpoints and
outputs in the permitted writable area, and seal what you derive before the job
ends. `vshadowmount` needs FUSE, which a worker may not provide: if it is missing,
say that the mount route was unavailable and which routes remain.

**What a snapshot can answer.** For every artefact taken from one, record the source
volume, the store identifier, the snapshot's creation time, the extraction path and
the artefact's own times, and cite both the snapshot time and the artefact's time.

- A registry hive or an event log in the snapshot is the state at the snapshot
  time. A difference from the live copy shows that the two observed states differ.
  It does not exclude intermediate changes or a restoration to an earlier value,
  and it does not date a change more closely than the two observations. Read the
  hive with `registry/overview` and the log with `logs/security`; for a cleared
  log, try the snapshot before carving (`logs/recovery`). A log can be caught
  mid-write, and events after the snapshot are not in it.
- A file taken before a deletion, a wipe or an encryption shows what the volume
  held then; whether application state was consistent at that moment is usually
  unknown, so say so.
- To compare `$MFT` states, extract entry 0 from each snapshot and run
  `mft_records` on each. Match records by entry **and** sequence: the same record
  number can be a different file after reuse. A difference shows two observed
  states, not the first or only change.

**Differential store.** A snapshot is rebuilt from the volume plus the old blocks it
kept. A file unchanged since the snapshot is read from the same clusters, so it is
the same bytes, not a second copy that survived. Reading a snapshot depends on the
source volume and the difference data both being in the image; an unavailable or
incomplete store cannot support a claim that something was absent.

**Does not show.** A snapshot does not show what happened between two states, who
changed or deleted anything, that the volume was ever in a state other than the
ones listed, or, when none is found, that none existed.

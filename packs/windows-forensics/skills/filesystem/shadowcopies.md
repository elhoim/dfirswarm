---
id: filesystem/shadowcopies
title: Volume shadow copies, and the volume as it was last week
when: A file, a hive or a log is missing, cleaned or too recent; or before you conclude anything is gone.
needs: [filesystem/deleted]
tools: [vss_stores, regkv, evtx_query]
requires_host: [vshadowinfo, vshadowmount]
---

A shadow copy is the same volume at an earlier moment, kept by Windows itself in
`System Volume Information`. It is the single highest-yield artefact on a
Windows image and the one first passes skip, because it takes one more command
to reach and none of the usual listings show it.

    vss_stores                          # what snapshots exist, and when each was taken
    vshadowmount -o <bytes> img work/vss/
    fls -r work/vss/vss1                # then the ordinary toolkit, against the snapshot

**The offset unit changes here.** `mmls` and the Sleuth Kit take **sectors**;
`vshadowinfo` and `vshadowmount` take **bytes**. Multiply. Getting this wrong
returns "unable to open volume" on a perfectly sound image, and more than one
examiner has concluded from that there were no shadow copies.

What it answers that nothing else does:

- **A registry hive as it was before it was cleaned.** A Run key or a service
  removed by the operator is still in the snapshot's `SOFTWARE` or `SYSTEM`.
  Extract both and diff them: the difference, with the snapshot's creation time,
  brackets when the cleanup happened.
- **An event log before it was cleared.** A whole intact `Security.evtx` from
  last week, not a carved fragment. Try this before `logs/recovery`.
- **A file before it was wiped or encrypted.** Ransomware encrypts the live
  copy; the snapshot may hold the original.
- **A second set of $MFT times.** The same record in two snapshots gives you
  when a value changed, which is stronger than any single timestamp.

**No stores is itself a finding.** `vssadmin delete shadows /all` is a standard
step before encryption and before a wipe, and it needs administrator rights.
Pair the absence with Security 4688 or PowerShell logging for the command, with
System 7036 for the service, and with the volume's own free space. Say "the
shadow copies were deleted at <time> by <command>" when you can prove it, and
"no stores are present and I could not establish why" when you cannot.

Two cautions. A snapshot's creation time is the time of the snapshot, not of any
file inside it, so cite both. And a shadow copy is a differential store, not a
full copy: a file that never changed between the snapshot and acquisition is the
same bytes, not an older version, and claiming otherwise misreads what you are
looking at.

---
id: filesystem/journals
title: The change journal and the log file
when: Something was deleted or renamed and you need to prove it happened, and when.
needs: [filesystem/mft]
tools: [usn_journal]
requires_host: [icat, fls]
---

Two journals, different jobs.

`$Extend/$UsnJrnl:$J` records a reason code per change: create, delete, rename
with both names, data overwrite, stream change. It survives the file. Parse it
with `usn_journal` and you can show a file existed, what it was called, and when
it went, long after the record was reused.

`$LogFile` is the transaction log. It is harder to parse but it carries
monotonically increasing sequence numbers, which is what saves a case when the
clock was rolled back. Order events by sequence number and the true order
survives whatever the timestamps say.

Both are streams on system files, so extract them the way you extract any
stream, by inode.

Reason codes to recognise: a rename followed immediately by a series of data
overwrites and a delete is the signature of a secure-delete tool, not of a user
deleting a file.

---
id: timeline/build
title: A timeline a second reader can trust
when: As soon as you have two dated facts, and continuously after that.
needs: [evidence/verify]
tools: [timeline_super, timestamp_decode]
requires_host: []
---

Put every dated fact in the ledger with `record` as you find it, not at the end.
This is the timeline the report cites, and it is yours: each row is a fact you
decided was worth recording, with a citation. The machine's version of the same
volume — every timestamp from every parser, no judgement applied — is
`timeline/super`, and it is a way of finding the window, not a way of writing
the report.
`kind: event` needs an ISO 8601 UTC timestamp, the source and how to check it.
The harness renders `ledger/ledger.md`; the report cites that file.

Normalise to UTC and say what you converted from. A host's own timezone lives in
the registry or in `/etc/timezone`, and a multi-machine case is worthless until
every log is in one zone. On a three-machine case this was the single decision
the whole order of events rested on.

Wall clock lies more often than you expect:

- A guest clock rolled back by its hypervisor shows as a system event. When it
  has, order by something monotonic instead. NTFS `$LogFile` sequence numbers
  and USN journal record numbers both increase whatever the clock says.
- Timestomping changes the standard information attribute and usually not the
  file name attribute. When the two disagree, say so, and prefer the one the
  attacker did not reach.
- Creation later than modification is not an error, it is a signal.

When a field holds a number and nothing says which clock wrote it, do not guess.
`timestamp_decode` reads it under every epoch in common use — Unix in three
resolutions, FILETIME, WebKit, Apple, HFS+, OLE and DOS — and says which
readings are plausible. Guessing here is off by decades, or by sixty-six years,
or by a factor of a thousand, and the report reads as though it were
established.

Put confidence on a row when you have it: what you saw, what it implies, and
what would disprove it.

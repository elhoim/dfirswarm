---
id: correlate/host
title: Tying the wire to the machine
when: You have both a capture and a host image, which is when either becomes conclusive.
needs: [beacons/periodicity]
tools: [beacon_score, timestamp_decode]
requires_host: []
---

A capture says a machine did something. A host image says which process. Neither
alone carries a report, and joining them is the point of having both.

**Fix the clocks first.** Packet times come from the capturing machine and host
times from the host, and the two are rarely identical. Find one event visible in
both — a logon, a download, a service start — measure the offset, apply it, and
state it. Every correlation after that depends on this step and it is the one
most often skipped.

**Then join on the pairs that exist:**

    an address in the capture      to a connection in memory, or a DNS cache entry
    a name resolved on the wire    to a browser history record, or a proxy log
    a download over HTTP           to a file on disk with a Zone.Identifier stream
    an upload window               to a staged archive's creation time
    a beacon interval              to a scheduled task or a service start time
    a TLS fingerprint              to the binary that produced it

**Direction matters when you write it.** "The host resolved `x.example` at
09:14:02 and a process named `svc.exe` held a connection to the answering
address" is two observations and one inference. Say which is which.

Where the two disagree, that is the finding rather than a problem to resolve. A
connection on the wire with nothing on the host means the host evidence is
incomplete — logs cleared, a process gone, an artefact not collected. Traffic on
the host with nothing on the wire means the capture missed it, and the capture
point in `capture/what-you-have` usually explains why.

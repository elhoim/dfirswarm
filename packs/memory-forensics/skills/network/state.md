---
id: network/state
title: Network state, and what it proves about when
when: You need connections, listeners, or an address to tie to a host artefact.
needs: [processes/injection]
tools: [mem_fs, ioc_scan]
requires_host: [memprocfs, vol]
---

Memory holds the connection table as it was at the instant of acquisition, and
— more usefully — the remains of connections that had already closed.

    established connections   with the owning process and both endpoints
    listeners                 including a port bound by something unexpected
    closed entries            still in the pool, not yet overwritten

**A closed entry with a timestamp is often the find.** The live table says what
was connected when you took the image, which is rarely the moment that matters.
The freed structures say what was connected earlier, and they are what tie a
process to an address during the incident window.

Tie every address to something on disk before you report it: a proxy log, a DNS
cache entry, a browser record, a firewall rule. An address in memory with
nothing else behind it is a lead.

**The DNS cache is the other half.** It maps names to the addresses this machine
resolved, which is how an address becomes a domain you can attribute. On Windows
it lives in the `dnscache` service's memory; on Linux in the resolver or
systemd-resolved.

Two cautions:

- **A listener is not a backdoor.** Plenty of legitimate software listens. What
  makes it interesting is the process that owns it, where that process runs
  from, and whether anything on disk explains it.
- **Addresses recovered from freed memory have no reliable time.** Say they came
  from a freed structure, and use a host artefact for the timestamp. Reporting a
  carved endpoint as though the connection table had dated it is the mistake
  this skill exists to prevent.

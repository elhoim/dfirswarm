---
id: triage/paging-files
title: The page file and the hibernation file
when: pagefile.sys, swap or hiberfil.sys is in the evidence, with or without a RAM capture.
needs: []
card: ioc_scan {"path": "<pagefile.sys>", "needles": "<a>|<b>"} reads stored bytes; a hit is a file offset: read status first (partial gives next_start). Inventory pagefile, swap and hiberfil.sys apart with collection times; an undecoded hiberfil.sys search misses its saved memory. Context needs {"write_values": true} in a secret_output job. Does not show: a paged-out byte's process, address or time.
tools: [ioc_scan]
requires_host: []
---

Use only if the evidence includes `pagefile.sys`, swap or `hiberfil.sys`. Not for the RAM capture itself (`triage/what-you-have`).

**The page file and the hibernation file are memory too, and different.** Inventory
`pagefile.sys`, swap and `hiberfil.sys` separately, with their collection times and
the system they came from. Literal scanning finds bytes stored directly in a paging
file; it cannot assign them to a process, a virtual address or a time. A hibernation
file may need a supported decoder before its saved memory can be searched. Record the
areas that were unsupported, compressed, encrypted, missing or not processed, and
remember that what these hold can describe a different time from the RAM capture.

For a literal search (`ioc_scan`), `strings/discipline` says how to report a hit.

**Sensitive output.** Paging files and hibernation data hold what the machine held, passwords included: run scans as jobs with `secret_output: true` and cite offsets, never content (`credentials/material`).

**Does not show.** Which process, virtual address or time a paged-out byte belongs to; that a hibernation file predates or matches the RAM capture's time; that a search of an undecoded hibernation file covers its saved memory.

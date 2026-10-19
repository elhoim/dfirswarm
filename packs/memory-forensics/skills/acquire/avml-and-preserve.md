---
id: acquire/avml-and-preserve
title: AVML, capture order and what to preserve
when: AVML is proposed, sources are being ordered, or you list what an acquisition keeps.
needs: []
tools: []
requires_host: [avml]
---

Use only if the operator proposes AVML, orders the sources or lists what an acquisition must preserve. Not for judging a capture already taken (`acquire/images`).

**AVML.** The pack declares AVML at a pinned version and checksum so the operator
has the exact binary to take to the source host (`requires/host.json`). `avml` run in
an analysis VM captures that VM, not the subject, so it is not a collection route
from here. Before use, keep the binary's version and its own help (`avml --help`),
and confirm there the source it supports, the output formats, the unit of its size
limit and what it does when a limit or a read error is reached; do not copy a
command line from a document, this one included, until those are confirmed. Never
send an acquisition to a network destination the approved collection plan does not
name.

**Order and cost.** The authorised examiner decides what is taken first, and records
the order and its trade-offs: volatile evidence early where safety, service
continuity, authority and the risk of changing or losing evidence allow. Record the
order actually used and the interval between RAM, paging files, hibernation data and
disk. A disk image taken before
memory, or hours after it, answers a different question, and the report says so.

**What to preserve.** The acquisition log and its completion status; unreadable
ranges; the source system's identity, architecture and kernel build; the collector's
hash and version; start and end times with their zone and a comparison to a
reference clock; the output's size and hash. A conversion between formats is a
separate derivative: keep the original, and record the conversion command and the
hash of both.

**Does not show.** That a disk image taken before memory, or hours after it, answers the memory question; that an AVML run in an analysis VM captured the subject; that a command line copied from a document is right for the build in hand.

Sensitive output: the acquisition output holds whatever the machine held; send it only where the approved plan names, and cite hash and size.

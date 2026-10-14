---
id: exfil/measure-and-claims
title: What a transfer measure means, and adversary claims
when: You quote a byte count, tie content to a transfer, or weigh a leak-site listing.
needs: []
tools: []
requires_host: []
mentions: [esedb_query]
---

Use only if you quote a byte count, tie content to a transfer, or weigh an adversary's listing or sample. Not for the route and staging questions (`exfil/before-encryption`).

**Measure the right thing.** Identify what each counter counts: captured bytes,
transport payload, application payload, an application's aggregate usage, the
compressed size of a staged object or its logical size. Record the direction, the
units, the endpoints, the interval, capture loss, how retransmissions were
treated, sampling, and NAT or proxy attribution; do not count one transfer twice
across sensors. Network usage in SRUM ties an application and an account to bytes;
it does not name the files or the remote recipient. If the windows-forensics pack
is loaded (check the run's tool inventory), its `esedb_query` reads the SRUM
database; otherwise record that limit. A Zeek originator is the side that opened
the connection, not necessarily the internal source, and a TLS connection's volume
says nothing of its content. If the network-forensics pack is loaded, its
`exfil/volume` skill gives its own counter definitions; read its limits too.

A finding about particular content needs a supported link between that content and
the transfer: application audit evidence, transfer records, reconstructed content
or a corroborated object identity. Distinguish an attempted, a failed, a partial
and a completed transfer.

**Treat the adversary's claims as claims.** A listing, a screenshot or a sample
supplied to the case alleges possession; it does not prove it. Record who supplied
it, when, from where and with what integrity information. Check any sample against
authorised internal evidence, and consider an older breach, public material and
fabrication. Do not visit the adversary's infrastructure, contact the adversary or
upload case material from this examination.

**Does not show.** A byte counter does not show content; SRUM does not show the recipient; a leak-site listing
does not show what was taken.

Record: each counter's definition, direction, units, endpoints, interval, loss and sampling; who supplied an adversary's sample, when, from where and with what integrity information.
Sensitive output: samples, screenshots and listings can hold the victim's data and identifiers; keep them under access control and cite their locators.

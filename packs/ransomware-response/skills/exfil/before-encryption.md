---
id: exfil/before-encryption
title: Whether data left, by which route and within what limits
when: Ransomware or data extortion raises a question about unauthorised disclosure.
needs: []
tools: []
requires_host: []
---

Use when ransomware or data extortion raises the question whether data left. Not for what a byte counter measures or for an adversary's claim.

Ask the question before, during and after the encryption, and in an incident with
no encryption at all. Do not assume that data left, that it needed local staging,
or that the answer settles every notification duty.

**Keep the propositions apart.** Record separately whether data was accessed,
collected or staged, transferred from its source, received at a destination, and
disclosed or published. Give the source for each. Evidence of one stage does not
show the next.

**Preserve the short-lived sources early.** Ask for EDR process and file
telemetry, proxy and firewall records, any packet captures, VPN and identity logs,
application audit records, cloud storage and SaaS audit exports and backup-system
activity. Record each source's retention, which event types were enabled, the
export filters, the gaps, the clock offset and the export delay.

**Test staging without assuming transfer.** Look at the metadata of archives and
temporary files, recoverable content, file-access telemetry and the process tree
behind them. An archive's creation time is a staging time: it is not necessarily
the start of any transfer. Its size is the size of that object, not a lower bound
on what left. List its contents only where the archive or another reliable source
shows them. A filesystem journal gives names and changes; it does not restore a
deleted archive's contents. Record whether the content was recovered and whether
what came back is whole.

**Look at the routes.** Look for traces of rclone, MEGAcmd, FileZilla, WinSCP, a
sync client already installed, browser uploads, scheduled transfers and the backup
system's own destinations. These are artefacts to recognise in the evidence; none
is run, installed or demonstrated here. Their presence, or their legitimate use,
does not show a malicious transfer. Consider direct streaming, SaaS exports,
object downloads and transfers from systems outside the collected set.

Only if you quote a byte count, tie content to a transfer or weigh an adversary's claim: `exfil/measure-and-claims`.

**Report a bounded conclusion**: established, partial, bounded negative or not
determinable. For a negative, name the systems, sources, interval, queries,
failures and unexamined routes, and say whether the suspected transfer would have
been visible in them. "Logging was present" is not a detection opportunity.

**Does not show.** A staged archive does not show a transfer or its volume; a negative does not show that nothing left through a
route that was not examined.

**Deliver:** a transfer-evidence table: the source data, the account or process
where supported, the route, the destination, the interval, the basis of the byte
measure, the evidence of completion, the confidence and the alternatives that
remain. Take the notification questions to `reporting/for-regulators` without
waiting for certainty.

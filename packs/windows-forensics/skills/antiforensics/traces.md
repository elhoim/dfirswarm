---
id: antiforensics/traces
title: What hiding leaves behind
when: The evidence looks too clean, or a first pass found nothing.
needs: [filesystem/deleted, logs/security]
tools: [regkv, evtx_query, prefetch_mam, evtx_carve, vss_stores, mft_records]
requires_host: [icat]
---

A first investigation that found nothing is a finding. Work the absences.

**Secure deletion.** Orphan records with repeated-character names and
high-entropy content, plus the tool's own prefetch entry and its Amcache hash.
The tool is often renamed before use; match on hash, not on name.

**Log clearing.** Security 1102 and System 104 name the account. A channel with
zero events on a machine that was clearly in use was cleared or turned off. Say
which you can prove — and then recover the records anyway, from a shadow copy or
by carving the chunks: `logs/recovery`.

**Shadow copies deleted.** `vssadmin delete shadows /all` before an encryption or
a wipe. `vss_stores` returning nothing on a machine that ran for months is the
absence to work: find the command in 4688 or in PowerShell logging, and see
`filesystem/shadowcopies`.

**Timestomping.** Compare `$STANDARD_INFORMATION` against `$FILE_NAME`. A
modification time before the creation time in the first and not the second is
the tell. See `filesystem/mft`.

**Clock rollback.** Security 4616 records a system time change with the process
that made it. When the hypervisor's guest service did it, wall clock is useless
for ordering and you move to `$LogFile` sequence numbers or event record ids.

**A deleted virtual machine.** A nested guest that ran and was then removed
leaves its configuration, its registry entries and often a truncated disk whose
header can be carved back out of unallocated space. Rebuild the guest's own logs
from the carved blocks and you get its logins, which the host never saw.

**Defender turned off first.** An exclusion path added, or real-time monitoring
disabled, usually through PowerShell. The command survives in
`ConsoleHost_history.txt` in the user's `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\`
even when the event log does not, and that file is not an event log, so clearing
the logs does not touch it. `logs/powershell` has the rest, including the
encoded-command and version-downgrade shapes.

**The examiner's own tools.** An imaging tool's driver dropped at the moment of
acquisition is not attacker software. Two published runs nearly reported one.
Check the timestamp against the acquisition record before you name anything.

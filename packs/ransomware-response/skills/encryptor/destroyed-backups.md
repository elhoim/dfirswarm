---
id: encryptor/destroyed-backups
title: What was destroyed so that recovery would fail
when: Establishing whether recovery is possible, and what the operator did deliberately.
needs: [encryptor/traces]
tools: [encrypted_survey]
requires_host: []
---

Destroying recovery is a step, it has its own artefacts, and it usually happens
minutes before the encryption.

**Shadow copies.** `vssadmin delete shadows /all /quiet`, or the WMI and
PowerShell equivalents, or resizing the store to nothing so Windows discards
them. The command appears in Security 4688 where command-line auditing was on,
in PowerShell logging, and in the shell history. The absence of stores on a
machine that ran for months is the other half of the evidence. The Windows
pack's `filesystem/shadowcopies` is the detail — and check for survivors before
concluding, because the deletion frequently fails on volumes the account could
not reach.

**Backup agents and catalogues.** The agent's service stopped or uninstalled,
its catalogue deleted, its credentials used to delete the remote copies. Look at
the backup system as a victim in its own right: if the operator reached it, the
restore path they were counting on is gone and the organisation needs to know
before it plans.

**Boot recovery.** `bcdedit /set recoveryenabled no` and
`bcdedit /set bootstatuspolicy ignoreallfailures`, and the Windows Recovery
Environment disabled. Cosmetic against a real restore, and useful as a timestamp
and as a signature of the family.

**Databases and virtual machines stopped** so their files could be encrypted:
SQL Server, Exchange, Hyper-V, VMware. The service stop events bracket the
encryption on that host to the second.

Write this up as its own section. A regulator and an insurer both ask what was
destroyed deliberately as distinct from what was encrypted, and the answer
changes the assessment of both the loss and the operator's intent.

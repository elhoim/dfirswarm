---
id: encryptor/traces
title: What the encryptor left behind
when: You need to know what ran, as whom, and how it was spread.
needs: [scope/first-hour]
tools: [encrypted_survey, ransom_note_scan]
requires_host: [yara]
---

The encryptor is usually deleted after it runs, and almost everything about it
survives that.

**On the file system.** The binary's own record in `$MFT`, with the times it
was created and deleted; the USN journal entry for the delete; the staging
directory; and whatever was dropped beside it — a batch file, a PowerShell
script, a list of hosts.

**In the execution artefacts.** Prefetch with the run count and the loaded
files, Amcache with a SHA-1 of a binary that no longer exists, ShimCache,
UserAssist and BAM for who ran it. That is the Windows pack's
`execution/overview`, and it is where the strongest evidence in this kind of
case usually is.

**In the event logs.** A service installed to run it as SYSTEM (System 7045),
a scheduled task (TaskScheduler 106 and Security 4698), a remote session before
it (`logs/remote-access`), and the PowerShell that disabled defences
(`logs/powershell`). And, almost always, 1102: the log cleared afterwards.

**In what it turned off first.** Defender exclusions and real-time monitoring,
the backup agent's service, the database services stopped so their files could
be encrypted, and the boot configuration changed to disable recovery. Each is an
artefact with a time, and together they are the clearest minute-by-minute
account of the deployment you will get.

**How it spread** is the part that decides whether it is over: a scheduled task
pushed by group policy, PsExec to a list of hosts, a remote management tool the
estate already had, or WMI. Each leaves a different trace on the source machine
as well as on the targets, and the source machine is the one to image.

Where a sample survived, the reverse engineering pack takes it from there. Note
one thing before handing it over: a file marker at the end of each encrypted
file — a magic value, a key blob, an original size — is frequently what
identifies the family, and `encrypted_survey` reports the trailing bytes of a
sample of files for exactly that reason.

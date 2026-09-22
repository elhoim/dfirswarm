---
id: logs/powershell
title: PowerShell, and what survives an operator who tried to leave nothing
when: A command line, a downloader, a disabled defence, or anything an interactive attacker did.
needs: [logs/security]
tools: [evtx_query, mft_records]
requires_host: [icat]
---

Almost every modern intrusion runs through PowerShell at some point, and it
leaves four independent traces. They are enabled independently, so read all four
before concluding a machine has nothing.

    Microsoft-Windows-PowerShell/Operational.evtx
        4104  script block logging: the code itself, as it was compiled
        4103  pipeline and module logging: the command with its bound parameters
        4105/4106  a script block started and stopped
    Windows PowerShell.evtx
        400/403  engine lifecycle; HostApplication carries the full command line
        600  provider lifecycle, which also carries the command line
    Users\<u>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    Transcripts, where the estate turned them on

**4104 is the prize, and it is chunked.** A long script arrives as several
records with `MessageNumber` and `MessageTotal`. Sort by `ScriptBlockId` and
then by `MessageNumber` and join them before you read the code, or you will
quote a fragment that means the opposite of the whole.

**4104 fires at warning level even when script block logging is off.** Windows
logs blocks it considers suspicious regardless of policy. So an operational log
that "has no script block logging" is still worth querying for 4104.

**`ConsoleHost_history.txt` is the one that survives.** It is a plain text file
per user, it is not an event log, so clearing the logs does not touch it, and it
keeps what was typed interactively across sessions. It has **no timestamps**:
it gives order, not time, and you must say so. Its own `$MFT` record's times
bracket the session. Check it early and check it for every profile, including
service and administrator accounts.

Two evasions to recognise rather than be fooled by:

- **Encoded commands.** `-enc`, `-EncodedCommand`, `-e`: the argument is
  base64 of UTF-16LE. Decode it and quote both forms, the encoded one as the
  artefact and the decoded one as what it means.
- **A downgrade to version 2.** `powershell -Version 2` runs an engine that
  predates script block logging, so 4104 is silent while 400 and 600 still
  record the launch. A version-2 launch on a modern build is itself worth
  reporting: nothing legitimate asks for it.

Defender being switched off, an exclusion path added, or AMSI tampered with
almost always arrives this way. See `antiforensics/traces` for the rest of that
sweep.

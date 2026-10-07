---
id: logs/security
title: Windows event schemas, authentication and audit coverage
when: You need to interpret event records with their provider, outcome, configuration and retention context.
needs: [registry/system-profile, filesystem/extract]
tools: [evtx_query, regkv]
requires_host: [evtxexport, EvtxECmd, dotnet, MFTECmd, RECmd]
---

Event logs are the `.evtx` files under `Windows/System32/winevt/Logs/` on a default
install, one per channel. A channel's file location is a setting, so list the
directory in the image and take the channel from the record, not the file name.
Extract the files with `filesystem/extract`; read them with `evtx_query` (python-evtx).

**What a run says.** `evtx_query` reports `records_examined`, `events_matched` and
`parse_errors` apart. A record it cannot read is an error row, never a match; a parse
error, or a failure to enumerate the chunks to the end, makes the run `status:
partial`, and every negative over that file is bounded by it. Each row carries
`record_offset`, `chunk_offset`, the EventRecordID, `timestamp` (the XML's SystemTime)
and `record_filetime` (the record header's FILETIME, a decimal string, with
`record_time_utc`). Filters: event ids, a substring of the XML, an EventRecordID
range, and `start_time`/`end_time` as ISO 8601 UTC prefixes (`2026-09-01` takes the
whole day). Inline `events` are a page of `limit`; the whole XML of every match is in
`result_file` (JSON Lines). `data` holds EventData and UserData fields (a repeated
name as a list); `Version`, `Execution` and the Security `UserID` are in the XML.

**Time.** SystemTime and the header FILETIME are UTC from the clock of the machine
that wrote the record, at write time, and neither is corrected for a clock that was
wrong or changed (4616 records a change only where that audit was on). If the two
differ for a record, report both and say you do not know why. Event Viewer shows local
time, so a screenshot's time is not the XML's. For a local-time statement use the zone
and DST rules in force on that date (`registry/system-profile`), never today's offset.

**Identify the record, then read it.** Provider, channel, event id and the XML's
`Version` identify an event; the number alone does not, since providers reuse ids. Read
Subject and Target apart: the Subject is the account or process that requested the
action (often the machine account or SYSTEM for a network logon), the Target the account
it acted on. Keep status, sub-status and the audit success or failure keyword. Meanings
in common use, to be confirmed from the XML you hold:

    Security  4624 logon (type, LogonId)      4625 failed logon (status, sub-status)
              4634 logoff, may be absent      4648 logon with credentials supplied
              4672 special privileges         4688 process created
              4697 service installed          4698/4699 scheduled task created/deleted
              4720/4722/4725/4726 account created/enabled/disabled/deleted
              4723/4724 an attempt to change / to reset a password
              4728/4732/4756 added to a global/local/universal group
              4719 audit policy changed       4616 system time changed (previous, new, process)
              5140 share accessed             5145 share object checked for requested access
              1100 logging service shut down  1102 the audit log was cleared
    System    7045 service installed          7040 service start type changed
              104  a channel was cleared      6005/6006 logging service started/stopped
    Defender  1116 detection   1117 action taken (read its action and result)

A detection is not a remediation: read what 1117 says was done and whether it
succeeded. 5145 is an access check with the rights asked for, not a read or a copy.
4688 carries a command line only where that policy was on, so a missing field is not a
missing command line. 4697 (Security) and 7045 (System) are two subsystems' views of a
service install: take both; either shows an installed service, not that it ran.

**Logon types** name how a logon was requested:

    2 interactive   3 network   4 batch   5 service   7 unlock
    8 network cleartext   9 new credentials   10 remote interactive   11 cached interactive

Type 2 does not identify a person at the console. Type 3 does not identify an SMB
operation or the user behind it. Type 8 does not by itself show a password crossing a
network unprotected. Type 10 is a remote-interactive session, RDP among them
(`logs/remote-access`). LogonId is unique within one computer and one boot only, and can
repeat after a restart; within that scope it joins a 4624 to the 4672, 4688 and 5145 that
carry it and to the logoff that ends it. For what attribution needs, `accounts/logons`.

**Coverage decides what silence means.** An event exists only if the channel was
enabled, the audit subcategory or provider was on, and the file's size and retention
kept it; what you hold also depends on what was collected. Before a negative:

1. Record each file's first and last record time and record count: the interval it
   can speak for.
2. Establish the channel's configuration (enabled, size, retention) with `regkv`, in the
   SOFTWARE and SYSTEM hives and policy, for example under
   `Microsoft\Windows\CurrentVersion\WINEVT\Channels` and
   `Policies\Microsoft\Windows\EventLog` (`registry/overview` for qualifying a hive).
   The pack does not decode a stored audit policy: use 4719 records, policy files the
   case holds, or events of the same subcategory found in the logs. Such an event shows
   the subcategory was on then; its absence alone shows nothing.
3. Word it "No evidence of <event> was found in <channels, files>, <first to last record
   time>", with `parse_errors`, whether the subcategory was shown on, and what else could
   have produced the silence.

An empty channel is a coverage condition to explain, not a verdict: disabled or never
written, no such activity, overwritten, forwarded elsewhere, not collected, unreadable,
or cleared. A 1102 or 104 shows that a clearing was recorded (the cleared channel is a
field of the record); their absence does not show that none happened (`logs/recovery`).

**Order.** EventRecordID orders the records of one file as the log service wrote them.
It does not order two channels or files, and a gap does not count missing events:
overwrite, clearing, filtering and collection all leave one. Build a cross-channel
timeline from times with each source's clock caveat; where a clock moved, keep both the
record order and the times and mark the records near the change.

**A second reader.** For a record a finding rests on, and whenever `parse_errors` is
not zero, read the same file with `evtxexport` (a parser other than python-evtx) or
`EvtxECmd` (its maps normalise payload differences between ids). `dotnet` is the
runtime MFTECmd, EvtxECmd and RECmd run on. These are optional programs: look in the run's
tool inventory, and if neither is there say the cross-check was not made. A record only
one reader opens is a reader limit, not a property of the log.

**Sensitive output.** `evtx_query` returns command lines, service and task arguments and
typed text, which can hold a secret; run it as a job with `secret_output: true` when the
log may. Cite file, channel, record id and `record_offset`, describe the behaviour, and
never write a secret's value, a fragment or a hash.

**Does not show.** A record shows that a provider wrote those fields at that time on that
clock: not who was at a keyboard, intent, that an operation completed unless the record
carries its outcome, that nothing else happened, or that the file is whole and unaltered
(tampering needs other sources: `antiforensics/traces`). For what an interactive
operator typed, `logs/powershell`; for rule-based review of a log, `logs/hunting`.

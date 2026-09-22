---
id: logs/security
title: The event logs, and the records that carry weight
when: Logons, account changes, service installs, log clearing, or anything with a time.
needs: [registry/system-profile]
tools: [evtx_query]
requires_host: [icat]
---

`Windows/System32/winevt/Logs/*.evtx`. Extract the channel you need, then parse
it. `evtx_query` returns timestamp, event id, channel, computer, record id and
the named data fields, filtered by id or by a time prefix.

The records worth knowing by number:

    Security  4624  logon, with a type      4625  failed logon
              4634  logoff                  4648  explicit credentials
              4672  special privileges      4688  process created
              4720  account created         4722  account enabled
              4724  password reset          4728/4732/4756  added to a group
              4697  a service was installed 4698/4699  a scheduled task, created and deleted
              5140  a share was accessed    5145  a file in a share
              4616  the system time changed, with the process that changed it
              1102  the audit log was cleared
    System    7045  a service was installed 7040  a service start type changed
              104   an event log was cleared
              6005/6006  the log service started or stopped
    Defender  1000  scan started  1116  malware detected  1117  action taken

4688 carries a command line only where the policy for it was turned on, and 4697
is the Security channel's view of the same install System 7045 records. Take
both when both are there: they are written by different subsystems, and an
operator who cleared one may not have thought about the other.

Logon types decide the meaning of 4624 and people quote them wrongly:

    2  interactive at the console        3  network (a share, no desktop)
    4  batch                             5  service
    7  unlock                            8  network cleartext
    9  new credentials (runas /netonly)  10 remote interactive (RDP)
    11 cached interactive

A surviving 4634 with type 3 does not mean the user was sitting at the machine.
That distinction decided who the actor was in one of the published cases, and
the report that ignored it named the wrong account.

Record ids are monotonic per channel. When a clock moved, order by record id.

A cleared log is itself the finding. 1102 and 104 carry the account that did it.
Absence is evidence too: a channel with zero events on a machine that was in use
was cleared or disabled, and you should say which you can prove. Then go and read
it anyway: `logs/recovery`.

Security and System are two channels of several hundred. For what an interactive
operator typed, `logs/powershell`. For where a session came from and where this
machine went next, `logs/remote-access`. When you do not know what to look for,
`logs/hunting` runs a few thousand rules over the lot.

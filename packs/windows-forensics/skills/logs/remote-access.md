---
id: logs/remote-access
title: Remote access and lateral movement
when: Someone reached this machine from another one, or left it for another one.
needs: [accounts/logons]
tools: [evtx_query, regkv, mft_records]
requires_host: [icat]
---

A logon type in `logs/security` says a session was remote. These say where it
came from, what it did, and — the part people forget — where this machine went
next.

**RDP, inbound.** Four channels, read in this order:

    Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
        1149  authentication succeeded, with the user and the SOURCE ADDRESS
    Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
        21 session logon   22 shell started   23 logoff
        24 disconnected    25 reconnected
    Security   4624 type 10, then 4778 reconnect and 4779 disconnect
               with the client name and address

1149 without a matching 21 is an authentication that never became a session.
Both belong in the timeline and they mean different things.

**RDP, outbound — the one that is usually missed.** This machine connecting to
another leaves no event log at all, only the user's own hive:

    NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<host>
        UsernameHint, and the key's last-write time
    NTUSER.DAT\...\Terminal Server Client\Default    the MRU of addresses typed

Plus the bitmap cache, `AppData\Local\Microsoft\Terminal Server Client\Cache\`,
which holds tiles of what was on the remote screen. It is the only artefact that
shows what the operator was looking at on the far machine.

**SMB and admin shares.**

    Security  5140  a share was accessed     5145  a specific file in it
              4648  explicit credentials, which names both accounts
    System    7045  a service installed, the other half of a remote execution

The classic remote-execution shape is a service installed with a short random
name and an `ImagePath` under `ADMIN$` or `%SystemRoot%`, a 4624 type 3 seconds
before it, and the service gone by the time you look. The 7045 survives the
service.

**WMI and WinRM.**

    Microsoft-Windows-WinRM/Operational          91 a shell was created, 169 authenticated
    Microsoft-Windows-WMI-Activity/Operational   5857, 5860, 5861

5861 is a permanent event subscription being registered, which is persistence as
well as movement: see `persistence/mechanisms`.

**Scheduled tasks created remotely.**

    Microsoft-Windows-TaskScheduler/Operational  106 registered, 200/201 ran
    Security                                     4698 created, 4699 deleted

Two habits. Always pair an inbound session with what happened during it, by time
window and by logon id: a session with nothing in it is noise, and a session
with a service install in it is the case. And always check the outbound
artefacts on every machine you are given, because that is how a three-machine
case becomes one story rather than three.

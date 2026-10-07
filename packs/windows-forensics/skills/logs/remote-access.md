---
id: logs/remote-access
title: Remote-access records and cross-host correlation
when: You need to distinguish authentication, session activity and remote operations across supplied hosts.
needs: [accounts/logons]
tools: [evtx_query, regkv, mft_records]
requires_host: []
---

A logon type in `logs/security` says a session was remote. These records say where it
may have come from, what the session did, and where this machine went next. Keep
authentication, session creation, shell start, disconnect, reconnect and termination
as separate observations; do not collapse them into "an access event".

**RDP, inbound.** Correlate three channels by computer, account, source address,
session id and time, after validating the event schema for the provider and version
you hold (`evtx_query` returns the XML):

    Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
        1149  user authentication succeeded (user, source network address)
    Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
        21 session logon   22 shell start   23 logoff   24 disconnected   25 reconnected
    Security   4624 type 10, 4625, 4778 reconnected, 4779 disconnected (client name, address)

An 1149 alone is an authentication, not a usable session. A missing 21 can mean the
connection did not become a session, or that the channel was off, rolled over or not
collected: say which of those you excluded. A source address is the peer as this
machine saw it: a gateway, a NAT, a VPN or a pivot host shows a hop, not the origin,
and an address names an interface at a time (DHCP and DNS records are other
sources). Record what a missing counterpart might mean, do not fill it.

**RDP, outbound.** Examine the client side: the RDP client's channel,
`Microsoft-Windows-TerminalServices-RDPClient/Operational`, where present (read its
fields from the XML for the build); process records for `mstsc.exe` (4688 where audited,
`execution/prefetch`); `.rdp` files and recent-item records (`artifacts/shell`); and the
user's NTUSER.DAT, read with `regkv`:

    Software\Microsoft\Terminal Server Client\Servers\<host>    UsernameHint
    Software\Microsoft\Terminal Server Client\Default           the addresses typed

These keys record client configuration and entries, not that a connection succeeded
or when. The last-write time of a `Servers\<host>` key is that key's last change; the
last-write time of `Default` is the latest change to the list, not the time of each
entry. Check `hive_dirty` in the `regkv` answer: the transaction logs beside a hive
are named, not replayed, and the pack provides no replay, so a dirty hive's newest state
may be missing. The bitmap cache, `AppData\Local\Microsoft\Terminal Server Client\Cache\`,
may hold tiles of what the remote screen displayed. The pack does not reconstruct
it; tiles usually lack the context to give a whole screen, a time, or whether anyone
looked. Take the files' own times with `mft_records` and keep their provenance.

**SMB and administrative shares.** Distinguish a connection, a share access and an
operation:

    Security  4624 type 3 (LogonId, source address)   4648 credentials supplied
              5140 a share was accessed   5145 a share object was checked for the rights asked
    System    7045 a service was installed (Security 4697)

5145 records an access check with the subject LogonId, share, relative target name and
access mask; it does not show a completed read, write or copy. Join it to the 4624
by LogonId on the same host, to object auditing and to endpoint records. A service
installed shortly after a network logon from another host is a candidate
remote-administration sequence: record the service name, image path and account, the
logon and its source address, and whether the image exists and where it came from
(`filesystem/mft`). Deployment and support tools produce the same sequence;
separate them with the estate's inventory and change records.

**WMI, WinRM and scheduled tasks.**

    Microsoft-Windows-WinRM/Operational          91 shell created, 169 authenticated
    Microsoft-Windows-WMI-Activity/Operational   5857, 5860, 5861 (5861: a permanent subscription)
    Microsoft-Windows-TaskScheduler/Operational  106 registered, 200/201 action started/completed
    Security                                     4698 created, 4699 deleted

Keep provider, event version, account, client machine or process where the record has
one, activity and session identifiers, and result codes. A permanent subscription
supports a subscription finding, not a remote origin (`persistence/mechanisms`). The
pack does not parse the WMI repository, so a subscription's definition cannot be read
here: say so. Pair a task's registration with its action start and completion (the
result code is in the record), and check the TaskScheduler channel was enabled
(`logs/security`).

**Across hosts.** LogonIds, session ids and record ids belong to one host and one boot;
join on account (SID), source and destination address, share or target, and time, with
each host's clock source and any known offset stated; time alone is supporting
evidence. A session with no retained follow-on activity stays an access finding with
limited visibility of what it did, bounded by what that host logs. If the
network-forensics pack is loaded (check the run's tool inventory) it can corroborate
the path.

**Bounded negative.** "No evidence of a remote session from <address or account> was
found in <the channels and files above, per host>, <first to last record time>;
`parse_errors` <n>; <channels shown disabled or not supplied>."

**Sensitive output.** Service arguments, task actions and client names can hold a
secret; run `evtx_query` over them as a job with `secret_output: true` when they may.
`regkv` withholds values whose name says password, secret, token or credential and
lists them under `sensitive_values_withheld`; never write a secret, a fragment or a hash.

**Does not show.** Authentication does not show a session; a session does not show who
was at the other end, what was done, or that anything was transferred; a registry
entry does not show a completed connection. Whether the other host was reached, or
was the origin, needs that host's own records.

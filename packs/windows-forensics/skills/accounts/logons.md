---
id: accounts/logons
title: Accounts, logon sessions and attribution limits
when: You need to associate activity with an account or session and assess whether human attribution is supported.
needs: [logs/security, registry/system-profile]
tools: [regkv, evtx_query]
requires_host: [regripper, RECmd]
---

Build the account map first, then tie each action to an account and a session. A
person is a separate, later claim that needs its own support.

    SAM\Domains\Account\Users            subkey names are the RIDs in hexadecimal
    SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
                                         full SID to profile path, state and load times
    Security log                         4624/4625/4634/4647/4648/4672 sessions;
                                         4720/4722/4725/4726 and 4728/4732/4756 account and group changes

**Account metadata.** Account names, enabled state, last-logon and logon-count
fields live in SAM structures that `regkv` does not decode (and it withholds each
user's `V` value; `registry/overview`). Read them with a parser that reports account
metadata only: the optional `regripper` or `RECmd` where the image carries them
(check the tool inventory). Record the plugin or batch file and its version, and
never record password material. If neither is present, say the metadata was not
read: the RIDs (key names) and the SIDs in `ProfileList` are still observations. Do
not take a machine SID from the presence of a policy key: it is the prefix shared by
the full SIDs of the local accounts you can already see in `ProfileList` and in
event fields.

**SIDs and RIDs.** Record the complete SID and its authority; a RID alone is not an
identity. RID 500 is the built-in Administrator and 501 the built-in Guest, even if
renamed. Accounts a machine creates itself get RIDs in the 1000s and up, in
creation order on that machine, so a RID orders creation on one machine; it dates
nothing and a gap may be a deleted account. Distinguish local, domain, service and
cloud-linked identities by their SID authority before comparing them. Adjacent RIDs
or two creations seconds apart do not make a malicious creation: provisioning
tools create accounts in bursts. Establish who created the account from the
creation event's Subject account and LogonId (4720, with 4722 and the group events),
and compare with the estate's own provisioning process and the administrative
activity in that session.

**Groups.** Membership of the Remote Desktop Users group (or of Administrators)
shows what the account was allowed to do. It does not show that remote access
occurred, why the member was added, or by whom: read the 4732 for the Subject, and
the 4624 type 10 records and `logs/remote-access` for use.

**From account to session.** An account is tied to a session through the 4624 fields:
the computer, `TargetUserSid` and name, `LogonType`, `TargetLogonId`, the
authentication package, `IpAddress` and workstation name where present, and the
Subject that requested it (`logs/security` for the types). Within one computer and
one boot, the LogonId joins the 4624 to the 4672, 4688 and 5145 that carry it and to
the 4634 or 4647 that ends it; a missing logoff is not proof the session was still
open. A `ProfileList` load time and activity in that user's own hive or shell
records (`artifacts/shell`, `execution/userassist`) are account-context evidence: they
show that something ran under that profile. Convert every time by the rules of
`registry/system-profile`.

**From account to person.** Neither a local interactive logon, a loaded profile nor
shell activity identifies the person operating the account. A record carries the
token's account, not the human: a service run as a user, a scheduled task, a batch
logon, `runas` with other credentials (logon type 2 or 9, by its form), remote control, a shared
credential and token impersonation all produce records that read like the user did it.
Name the mechanism you claim and state, separately, what supports a human at that
account and which alternatives remain open. The support is evidence outside the
account's own logs, cited by name: physical-access or camera records, the account
holder's statement, a record of who had the credential, or a second authentication
record. Without it, the finding is "activity under account X in session Y".

**Bounded negatives.** Word an absence as "No evidence of a logon by <account> was
found in <log files and their first-to-last record times>": the audit subcategory
may be off, the log may have rolled over, and the logon may have happened on another
machine or through a service. Name the files, the interval, the subcategory
evidence and what else could have written it.

**Sensitive output.** Run `evtx_query` as a job with `secret_output: true` when the log
may hold command lines or typed text. `regkv` withholds secret-bearing SAM and
registry values on its own. A password, a hash or a fragment of either is never
written to a note or a report: record where it sits, its kind and its length.

**Does not show.** Account and session records do not show who was at the keyboard,
intent, that an administrator account was used rather than created, or that an
account that left no record was unused. Group membership shows rights, not use.

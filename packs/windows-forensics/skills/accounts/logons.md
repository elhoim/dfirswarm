---
id: accounts/logons
title: Accounts, who they are, and who was actually at the keyboard
when: Attributing an action to a person.
needs: [logs/security]
tools: [regkv, evtx_query]
requires_host: [icat]
---

Build the account map before you attribute anything.

    SAM\Domains\Account\Users             RIDs, names, last logon, login count
    SOFTWARE\...\ProfileList              SID to profile path, load and unload
    Security\Policy                       the machine SID

RIDs tell a story on their own. 500 is the built-in administrator, 501 guest,
and locally created accounts start at 1000 and count up. Two accounts created
twenty seconds apart at 1005 and 1006 are an attacker adding a pair, not a user.

Group membership matters more than the account: an account in the remote desktop
users alias was put there to be used remotely.

To place a person at the machine, use three things together: a 4624 with an
interactive type, the profile load time from `ProfileList`, and shell activity
from that user's own hive in the same window. Any one of them alone can be
explained away.

The trap the published runs hit twice: an account name in an event is the
account the token belonged to, not necessarily the human. A service running as a
user, a scheduled task, a `runas` with new credentials, all produce records that
read like the user did it. Say which mechanism you are claiming.

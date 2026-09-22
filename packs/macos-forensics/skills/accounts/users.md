---
id: accounts/users
title: Accounts, and who was actually at the keyboard
when: Attributing an action to a person.
needs: [triage/system-profile]
tools: [plist_read, knowledgec_query]
requires_host: []
---

macOS has no `/etc/passwd` worth reading. Local accounts live in a directory
service, one property list per user:

    /private/var/db/dslocal/nodes/Default/users/<name>.plist
        uid, gid, home, shell, generateduid, and the ShadowHashData blob
    /private/var/db/dslocal/nodes/Default/groups/admin.plist
        who is an administrator, by generateduid
    /Library/Preferences/com.apple.loginwindow.plist
        autoLoginUser, and the last user to log in
    /var/log/asl/  and the unified log
        the authentications themselves

UID 0 is root, 1 to 500 are system accounts, and people start at 501. A second
account at UID 0, or a "system" account with a real home directory, is the same
finding as on any Unix.

`ShadowHashData` holds the password verifier. Its presence is normal; what
matters forensically is the plist's own modification time, which moves when the
password changes.

**Administrator is membership of the `admin` group**, recorded by the account's
`generateduid` rather than by name. Resolve it, or you will miss an account that
was added to the group after it was created.

To place a person at the machine, use three things together: an authentication
in the unified log, the screen coming on in `knowledgeC` (`/display/isBacklit`),
and application focus in the same window. Any one alone can be explained away —
a launch agent, a remote session, a scheduled job.

Remote access is its own question. Screen Sharing and Remote Management leave
entries in the unified log and in
`/Library/Preferences/com.apple.RemoteManagement.plist`; SSH leaves the ordinary
Unix trail in the unified log rather than in `auth.log`. A machine with Remote
Login enabled and an `authorized_keys` file is reachable by anyone holding the
key, and that file's modification time is the date to quote.

---
id: accounts/users
title: Accounts, identities and authorization
when: Which identities and configured privileges could apply, without equating them with use.
needs: []
tools: []
requires_host: []
---

Use when you establish which accounts and configured privileges could apply. Not for sessions, wtmp and shell histories (`accounts/sessions-histories`, only if you read them) or for what a login line shows (`logs/auth`).

    /etc/passwd, /etc/group        local accounts and groups (sudo, wheel, docker, adm)
    /etc/shadow                    a password verifier or a lock marker, and password-aging fields
    /etc/sudoers, /etc/sudoers.d/* sudo authorization
    ~/.ssh/authorized_keys         configured key authorization for one account
    /var/log/wtmp, btmp, lastlog   sessions, failures, last login per UID (classic format)

Local files are not a complete identity inventory. Read `/etc/nsswitch.conf`, the PAM configuration and any SSSD, LDAP, AD or other identity-provider configuration: an identity that can authenticate may not be in `/etc/passwd`. `/etc/shadow` holds a verifier; read credential-bearing files only in a sealed job with `secret_output: true`, and report the account, what the field means and where it is, never the verifier, a fragment of it or a hash of it.

**Candidates, not findings.** Record every UID-0 entry and every unusual account property as a review candidate. `/etc/login.defs` states allocation policy, not a reliable human-or-service classification for imported, hand-made or centrally managed identities; compare an account with provisioning records and its authorised purpose. Shadow field 3 is the date of the last password change in days since 1970. It does not establish when the account was created, who changed it or that the use was malicious, and an empty or zero value has its own meaning, so read it before converting it to a date.

**SSH authorization.** A key in `authorized_keys` is a configured authorization candidate. Establish the effective policy first: `sshd_config` and its includes, `Match` blocks, `AuthorizedKeysFile`, `AuthorizedKeysCommand`, trusted CAs, principals and key options. The key's presence shows neither a successful login nor an installation date, and the file's modification time is a copy or extraction time as often as an edit time.

**sudo and groups.** Evaluate includes, aliases, Runas targets and command restrictions: `NOPASSWD` applies to the matching authorization, not to every root command. Membership of a group that can reach a rootful container daemon is a high-risk privilege path; establish the socket's permissions, the daemon's mode and the controls in force before describing effective authority over the host.

Shows: which identities and privileges are configured. Does not show: that an account existed at the incident time, that a configured privilege was used, who was at the keyboard, or that a command ran. Corroborate with the authentication records (`logs/auth`), the journal and audit records where they exist, and package or provisioning records. Record: file, field and value meaning, the effective sshd and sudo policy you resolved.

Sensitive output: `/etc/shadow` content, key material and history commands can hold secrets; cite file and record, never a verifier, a key or a hash of one. Histories: `accounts/sessions-histories`.

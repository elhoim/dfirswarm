---
id: logs/auth
title: The authentication logs, and what each line actually proves
when: Someone logged in, tried to, or raised their privileges.
needs: [triage/system-profile]
tools: [auth_log, utmp_parse]
requires_host: []
---

    Debian and Ubuntu   /var/log/auth.log, auth.log.1, auth.log.*.gz
    Red Hat family      /var/log/secure
    Either              the systemd journal, which may hold the same lines

`auth_log` parses both, follows the rotated and gzipped files in order, and
returns structured records instead of text. Read the whole set: rotation is
where an attacker's session usually falls, because the current file only covers
the last few days.

The lines that carry weight:

    Accepted password|publickey for <user> from <ip> port <p> ssh2
    Failed password for [invalid user] <user> from <ip>
    session opened for user <u> by (uid=N)      pam_unix, the actual login
    sudo: <user> : TTY=... ; PWD=... ; USER=root ; COMMAND=<cmd>
    su: (to root) <user> on pts/N
    useradd|usermod|groupadd                     account changes
    sshd: Server listening / Received signal     the daemon restarting

**`Accepted publickey` names the key, not the person.** The fingerprint in the
line maps to an entry in some `~/.ssh/authorized_keys`. Find which, and say
whose file it was in: that is the difference between "the account was used" and
"this key was used, and it was installed on this date".

**A failed-password burst followed by one acceptance is not always a successful
brute force.** It is also what a user with a stale saved password looks like.
Check the source address against the same account's history before you call it.

**sudo lines are the best command-line evidence on a Linux box.** They carry the
working directory and the whole command. An attacker who knows that uses `sudo
-s` once and then leaves no further trace, so a single `sudo su -` or `sudo -i`
followed by silence is itself the finding.

Everything above is text a root user can edit. Cross-check the important
sessions against `wtmp`/`btmp` with `utmp_parse` and against the journal with
`logs/journal`: three sources that disagree tell you the logs were touched.

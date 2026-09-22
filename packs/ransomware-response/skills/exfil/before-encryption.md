---
id: exfil/before-encryption
title: What left before anything was encrypted
when: Always, and early: this is the question with the deadline attached.
needs: [scope/first-hour]
tools: [encrypted_survey]
requires_host: []
---

Double extortion is the norm, so the encryption is the part you can see and the
exfiltration is the part that decides the regulatory clock, the notification
duties and the negotiation. It is also answered from the evidence that ages
fastest.

**Look for staging first.** Data is almost always collected before it leaves: a
large archive appearing in a temporary directory, an unusual directory tree on a
file server, a compressed file whose name is a date. Its creation time is the
start of the window and its size is the lower bound of what went. On Windows,
`filesystem/deleted` and the USN journal recover the archive after it was
removed; the record survives the file.

**Then the routes**, in the order they turn up in real cases:

    rclone, MEGAcmd, FileZilla, WinSCP   a tool dropped for the purpose
    a cloud storage client already there  which looks entirely legitimate
    a web upload over TLS                 volume in the proxy log, no name
    a scheduled task doing it quietly     out of hours, over days
    the backup system itself              to a destination somebody added

**Volume is the measure you will be asked for.** A proxy log, a firewall's flow
records, SRUM on Windows, or `conn.log` if a capture exists. "4.1 GB left this
host between 02:10 and 02:40 on the 12th" is the sentence the rest of the
response hangs on.

**Absence of proof is not proof of absence, and the report must say which it
has.** Three honest positions, and they are different: exfiltration is
evidenced; exfiltration is not evidenced and the logging that would have shown
it was present; exfiltration is not evidenced and the logging that would have
shown it was absent. Only the second is reassuring, and conflating it with the
third is the most consequential error available in this kind of case.

**The leak site is evidence too**, and it is outside the estate. Where the
group has published or listed the organisation, what they published says what
they took. Record it with its date; do not download from it without
authorisation.

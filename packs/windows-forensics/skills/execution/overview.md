---
id: execution/overview
title: Proving a program ran, and how much each artefact is worth
when: Any claim that something was executed.
needs: [registry/overview]
tools: []
requires_host: []
---

No single artefact proves execution. Each one answers a slightly different
question, and the published runs got their sharpest answers by making three or
four agree to the second.

| Artefact | What it actually says | Skill |
| --- | --- | --- |
| Prefetch | it ran, how many times, when last, what it loaded | `execution/prefetch` |
| UserAssist | a user launched it from the shell, with a run count | `execution/userassist` |
| Amcache | the binary was present, with its SHA-1 and link date | `execution/amcache` |
| ShimCache | the file was seen by the compatibility cache | `execution/amcache` |
| BAM and DAM | the last time a program ran, per user SID | `execution/userassist` |
| SRUM | how much network and CPU a program used, per hour | `execution/srum` |
| Event 4688 | a process started, if the policy was on | `logs/security` |
| PowerShell 4104 | the code that ran, as it was compiled | `logs/powershell` |
| Sysmon 1 | a process started, with its hashes and parent, where it is installed | `logs/remote-access` |
| A shadow copy | any of the above, as it was before a cleanup | `filesystem/shadowcopies` |

Read that table as a ladder of confidence. Prefetch and UserAssist are the
strongest; ShimCache is the weakest, because a file can enter it without ever
running.

Two traps worth naming before you start:

- Absence is not absence of execution. Prefetch is disabled on servers and on
  some SSD configurations, and a deleted prefetch file leaves only its record.
- Presence with a run count of one and no other corroboration is worth a
  sentence, not a conclusion.

A renamed binary breaks the naive path match. Match on hash and on the prefetch
hash suffix, not on the name. In the published workshop case a tool had been
renamed before it was run, which is why no prefetch existed under its real name
and why the answer was found under the new one.

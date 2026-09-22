---
id: execution/userassist
title: UserAssist, BAM and DAM
when: You must tie an execution to a specific user.
needs: [execution/overview]
tools: [regkv]
requires_host: [icat]
---

**UserAssist** lives in the user's own hive, so it names the user by
construction:

    NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count

The value names are ROT13 encoded. `P:\Hfref\Choyvp\...` is `C:\Users\Public\...`.
The value data carries a run count and a last execution time. It records shell
launches, so a program started by a service or by another process will not be
here, and that absence means nothing on its own.

**BAM and DAM** give the last run time per user SID, and they survive when
prefetch does not:

    SYSTEM\ControlSet00n\Services\bam\State\UserSettings\<SID>
    SYSTEM\ControlSet00n\Services\dam\State\UserSettings\<SID>

The value name is the full NT path, `\Device\HarddiskVolume3\Users\...`. Map the
volume with `SYSTEM\MountedDevices` before you quote it as a drive letter.

Used together these answer "who ran it" where prefetch only answers "it ran". In
the published workshop case UserAssist, prefetch and BAM agreed to within six
seconds, which is what made the answer defensible rather than probable.

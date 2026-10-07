---
id: execution/userassist
title: UserAssist, BAM and DAM activity records
when: You need to decode profile- or SID-associated application activity and assess its coverage.
needs: [execution/overview, registry/overview]
tools: [regkv]
requires_host: [RECmd, regripper]
---

Both stores sit in a registry hive and attach activity to an account context: a
profile's hive for UserAssist, a SID for BAM and DAM. That is a profile or a SID, not
a person (`accounts/logons` maps SIDs to profiles and states the attribution limits).

**What the pack gives you.** `regkv` returns a key's values and subkeys; a binary value
comes back as hex with its registry type and length, and nothing is decoded. The pack
has no UserAssist, BAM or DAM reader: a count or a time you quote has to come from a
decoder you name, and the raw value stays in the record beside it. Where the host has
`RECmd` or `regripper`, check whether it has a reader for this value and this Windows
version, and record the tool, its version and the batch file or plugin it used.
`regkv` lists subkeys with their last-written times (raw FILETIME and UTC with seven
fractional digits); a last-written time belongs to a key, not to one entry in it.

**UserAssist.** In the user's hive:

    NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count

Each value name is the program's path or identifier, ROT13-encoded: decode the name as
text offline (`P:\Hfref\Choyvp\...` is `C:\Users\Public\...`), read only. The data is
binary, and its layout and fields differ by length and Windows version: decode with a
parser validated for the build, and record the GUID, the raw value, the decoded name,
and the count, time and any focus fields it supports. Do not apply a universal
adjustment to a count. UserAssist is shell-associated activity in that profile: a
program started by a service, a task or another process need not appear, and a missing
entry may also reflect disabled tracking, cleanup or an incomplete collection.

**BAM and DAM.** Where the build keeps them:

    SYSTEM\ControlSet00n\Services\bam\State\UserSettings\<SID>
    SYSTEM\ControlSet00n\Services\dam\State\UserSettings\<SID>

The paths above are the layout this skill was written for: record the exact path you
find and the build. Do not call them a complete history: retention and
the application types covered vary and are not established here. A value name is an NT
device path, `\Device\HarddiskVolumeN\...`: keep it as it is with the SID. `MountedDevices`
alone may not resolve a historical volume number to a drive letter; use the volume and
mount evidence of the system you hold (`registry/system-profile`, `registry/devices`),
and leave the path unresolved rather than invent a drive letter. Read the control set the
question concerns (`registry/overview`).

**Agreement is not "who".** When UserAssist, BAM or DAM and Prefetch agree and their
clocks and meanings are compatible, an application-activity hypothesis is stronger.
It does not identify the human, show that the sources share one launch time, or exclude
automation. Report the SID or profile association, the time window the sources support,
what each timestamp means, and the remaining attribution limits. Three records from one
hive copy, or from parsers sharing a decoder, are one source.

**Sensitive output.** `regkv` withholds values whose name says password, secret, token
or credential and no flag brings one back; record such a value as key, name, type and
length. A secret value, a fragment of one or a hash of one is never written to a note,
a report or a file. Program paths and counts are not secrets.

**Absence is bounded.** "No UserAssist entry for <program> was found in <profile hive,
state>" (and the same for BAM or DAM, per SID); say whether the hive was dirty, the logs
applied and the user's hive collected at all: a user whose hive was not collected is not a
user with no entry.

**Does not show.** Who was at the keyboard, that the program finished or had an effect,
every program that ran, an exact launch time shared by the sources, or (for a missing
entry) that the program did not run.

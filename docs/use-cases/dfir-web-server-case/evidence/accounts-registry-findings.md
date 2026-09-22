# Accounts / registry / event-log findings (s2cb903)

## Evidence extraction

Disk image: `inputs/s4a-challenge4` SHA-256 prefix `a584de7f06bc`
Partition layout command: `mmls inputs/s4a-challenge4`
Relevant NTFS partition offset: `2048` sectors.

Extracted with:

```bash
icat -o 2048 inputs/s4a-challenge4 18491-128-3 > work/extracted/SAM
icat -o 2048 inputs/s4a-challenge4 18499-128-3 > work/extracted/SYSTEM
icat -o 2048 inputs/s4a-challenge4 18496-128-3 > work/extracted/SOFTWARE
icat -o 2048 inputs/s4a-challenge4 18493-128-3 > work/extracted/SECURITY
icat -o 2048 inputs/s4a-challenge4 42093-128-4 > work/extracted/Security.evtx
icat -o 2048 inputs/s4a-challenge4 42091-128-4 > work/extracted/System.evtx
icat -o 2048 inputs/s4a-challenge4 42092-128-4 > work/extracted/Application.evtx
icat -o 2048 inputs/s4a-challenge4 201-128-1 > work/extracted/Administrator.NTUSER.DAT
shasum -a 256 work/extracted/SAM work/extracted/SYSTEM work/extracted/SOFTWARE work/extracted/SECURITY \
  work/extracted/Security.evtx work/extracted/System.evtx work/extracted/Application.evtx \
  work/extracted/Administrator.NTUSER.DAT
```

Hashes:

- `work/extracted/SAM` = `a449fbe404f9df69d48ff0a74bf988f8751147d4755f880a6056b7bc6735109d`
- `work/extracted/SYSTEM` = `fca4919725d8e350056cd1f9ef3d17f2902715995a9300bf193bea242936a513`
- `work/extracted/SOFTWARE` = `5fbdf8f2b231073a24e53c8cdaa6291d4e6c2874c981f5b81d84ec583c0bc9c1`
- `work/extracted/SECURITY` = `13bfff3baa50626b0054793dcacbe01090182dc0ec0aaa77f01df5e00182d78c`
- `work/extracted/Security.evtx` = `b8ed63be0c8be007664eab0803d3703c39ab0f4ef539e1eade35960d0f6534ef`
- `work/extracted/System.evtx` = `aa7852b096881b955f7d24c2759506a5df70b1f337eaebb0e02f04b77c7aee6b`
- `work/extracted/Application.evtx` = `69bf9ee1adb6abdf75369f97a99f50dffd2cc659d779ca9ac1ee08e0a66a33d6`
- `work/extracted/Administrator.NTUSER.DAT` = `0d2f3ca11ed002aaf68ff19cbe1973f01f79ecf13b986e1c81a253ec36ef0bae`

## Q2: attacker-added users

### Added local users found in SAM

Using `regipy` against `work/extracted/SAM`:

- `SAM\Domains\Account\Users\Names\user1` -> RID `1005`, name-key last write `2015-09-02T09:05:06.019610+00:00`
- `SAM\Domains\Account\Users\Names\hacker` -> RID `1006`, name-key last write `2015-09-02T09:05:25.378984+00:00`

Corroborating RID-key timestamps from `SAM\Domains\Account\Users\000003ED` and `000003EE`:

- RID `1005` (`user1`) last write `2015-09-02T09:05:06.019610+00:00`, password last set `2015-09-02T09:05:06.019610+00:00`
- RID `1006` (`hacker`) last write `2015-09-02T09:05:25.378984+00:00`, password last set `2015-09-02T09:05:25.378985+00:00`

Conclusion: **2 local users were added**: `user1` and `hacker`.

### Group memberships assigned to the added users

In the SAM path `SAM\Domains\Builtin\Aliases\Members\S-1-5-21-3848053756-3249532031-1848221756\000003ED` (RID 1005 / `user1`) and the parallel key `...\000003EE` (RID 1006 / `hacker`), the default value decodes to alias IDs `0x221` and `0x22b`, i.e.:

- `0x221` = built-in **Users** group (RID 545)
- `0x22b` = built-in **Remote Desktop Users** group (RID 555)

So both `user1` and `hacker` were not only created, but were also placed into **Remote Desktop Users**. The membership subkey timestamps are:

- `user1` membership key `...\000003ED` last write `2015-09-02T09:18:09.021348+00:00`
- `hacker` membership key `...\000003EE` last write `2015-09-02T09:19:24.083848+00:00`

This is important context for persistence/remote-access intent.

### How they were most likely added

I did not find Security-account-management audit events (e.g. 4720/4732) in `work/extracted/Security.evtx`, so the exact GUI action is not directly logged there. The strongest sequence I found is:

1. Interactive Administrator logon succeeded at `2015-09-02 09:00:57.175859+00:00` in `work/extracted/Security.evtx`:
   - record `481`, Event ID `4624`, `TargetUserName=Administrator`, `LogonType=2`, `ProcessName=C:\Windows\System32\winlogon.exe`
   - record `482`, Event ID `4672`, elevated admin privileges assigned to `Administrator`
2. `Administrator`'s `NTUSER.DAT` UserAssist data records `C:\Windows\system32\CompMgmtLauncher.exe` at `2015-09-02T09:01:02.519000+00:00`.
3. Four minutes later, the two new SAM users appear (`user1` at `09:05:06Z`, `hacker` at `09:05:25Z`).

This sequence supports the assessment that the attacker **most likely added the accounts through the local Computer Management / Local Users and Groups GUI** (opened via `CompMgmtLauncher.exe`) rather than through `cmd.exe`; the first `cmd.exe` UserAssist execution I found is later, at `2015-09-02T09:28:30.411000+00:00`. The later SAM alias-membership timestamps (`09:18:09Z` and `09:19:24Z`) show the same two accounts were then placed into the built-in **Remote Desktop Users** group.

Use cautious wording in the final report: the account creation itself is proven by SAM; the **GUI method is an evidence-backed inference** from the immediately preceding `CompMgmtLauncher.exe` execution.

## Supporting context

### No profile evidence for `user1` or `hacker`

`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` only contains:

- `S-1-5-18` -> `%systemroot%\system32\config\systemprofile`
- `S-1-5-19` -> `%SystemRoot%\ServiceProfiles\LocalService`
- `S-1-5-20` -> `%SystemRoot%\ServiceProfiles\NetworkService`
- `S-1-5-21-3848053756-3249532031-1848221756-500` -> `C:\Users\Administrator`

I did **not** find `ProfileList` entries for RID 1005/1006, which suggests the newly added users may not have completed an interactive profile creation/logon on this host.

### Relevant logon records around account creation window

From `work/extracted/Security.evtx` around `2015-09-02 09:00`:

- record `478`, Event ID `4625`: failed `Administrator` logon at `2015-09-02 09:00:39.050859+00:00`
- record `479`, Event ID `4776`: successful credential validation for `Administrator` at `2015-09-02 09:00:57.175859+00:00`
- record `481`, Event ID `4624`: successful interactive `Administrator` logon at `2015-09-02 09:00:57.175859+00:00`
- record `482`, Event ID `4672`: special admin privileges assigned to `Administrator` at `2015-09-02 09:00:57.175859+00:00`

This gives a strong attack-timeline anchor immediately before the two new accounts are created in SAM.

## Ready-to-use report language

- “The attacker added **two local accounts**, `user1` (RID 1005) and `hacker` (RID 1006). Their creation is evidenced by `SAM\Domains\Account\Users\Names\user1` and `...\hacker`, whose last-write times are `2015-09-02T09:05:06Z` and `2015-09-02T09:05:25Z`, respectively, corroborated by the corresponding RID keys in the SAM hive extracted from inode `18491-128-3`.”
- “The exact account-management event was not retained in `Security.evtx`, but the surrounding artifacts indicate the accounts were **most likely created through Computer Management / Local Users and Groups**: an elevated interactive `Administrator` logon succeeded at `2015-09-02 09:00:57Z` (Security.evtx records 481/482), `Administrator`’s UserAssist data shows `CompMgmtLauncher.exe` execution at `2015-09-02 09:01:02Z`, and the two new users appeared in SAM four minutes later.”
- “Both new users were then assigned built-in group aliases `0x221` (Users) and `0x22b` (Remote Desktop Users), as recorded under `SAM\Domains\Builtin\Aliases\Members\S-1-5-21-3848053756-3249532031-1848221756\000003ED` and `...\000003EE`, with membership-key last writes of `2015-09-02T09:18:09Z` and `2015-09-02T09:19:24Z`.”

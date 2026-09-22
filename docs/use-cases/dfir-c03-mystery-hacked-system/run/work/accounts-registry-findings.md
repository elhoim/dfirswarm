# Accounts, registry, and event-log findings

Author: `s9f2001`
Seat: Accounts and event logs

## Scope and sources

This note covers the assigned seat: local accounts, account state changes, group membership changes, logons, and relevant registry keys / Windows event logs.

Primary evidence used:

- `work/extracted/s9f2001/hives/SAM` extracted from inode `44227` (`Windows/System32/config/SAM`)
- `work/extracted/s9f2001/hives/SYSTEM` extracted from inode `44233` (`Windows/System32/config/SYSTEM`)
- `work/extracted/s9f2001/hives/SECURITY` extracted from inode `44230` (`Windows/System32/config/SECURITY`)
- `work/extracted/s9f2001/hives/Administrator.NTUSER.DAT` extracted from inode `83083` (`Users/Administrator/NTUSER.DAT`)
- `work/extracted/s9f2001/hives/master.NTUSER.DAT` extracted from inode `81309` (`Users/master/NTUSER.DAT`)
- `work/extracted/s9f2001/evtx/Security.evtx` extracted from inode `81028`
- `work/extracted/s9f2001/evtx/System.evtx` extracted from inode `81025`

Useful commands/tools:

- `icat -o 0 inputs/Windows8.1-Challenge3.001 <inode>` to extract hive/log files
- `regkv hive=... key=...` for registry values and last-write times
- `evtx_filter path=... event_ids=[...] contains=...` for EVTX parsing/filtering
- ad hoc Python with `regipy` / `python-evtx` for validation

## Environment details relevant to timestamps

From `SYSTEM`:

- `\ControlSet001\Control\ComputerName\ComputerName`
  - `ComputerName = SENSEI`
  - key last-modified: `2015-12-12T02:56:30.381252Z`
- `\ControlSet001\Control\TimeZoneInformation`
  - `TimeZoneKeyName = Pacific Standard Time`
  - `Bias = 480`
  - key last-modified: `2015-12-12T02:18:26.511880Z`

Interpretation: event-log UTC timestamps should be read as PST local time minus 8 hours.

## Install / provisioning context

From `SOFTWARE` (`\Microsoft\Windows NT\CurrentVersion`):

- `RegisteredOwner = master`
- `InstallDate = 1449889395` = `2015-12-12T03:03:15Z`

This is important context for interpreting the `master` account events: the account-creation and first-logon burst occurs immediately around the operating-system install/OOBE completion time.

## Account inventory from SAM

`\SAM\Domains\Account\Users\Names` contains these local accounts:

| Account | Evidence | Last-modified |
| --- | --- | --- |
| `Administrator` | SAM name key | `2015-12-12T02:21:24.958292Z` |
| `Guest` | SAM name key | `2015-12-12T02:21:24.958292Z` |
| `master` | SAM name key | `2015-12-12T03:02:42.943144Z` |

Additional SAM parsing:

- Machine SID: `S-1-5-21-2733037674-494817684-1624540804`
- `Administrator` = RID `500`
- `Guest` = RID `501`
- `master` = RID `1001`
- Final observed `master` account flags: `0x214` (`Password Not Required`, `Normal User Account`, `Password Does Not Expire`)
- Final observed `Administrator` account flags: `0x211` (`Account Disabled`, `Normal User Account`, `Password Does Not Expire`)

## High-confidence account and logon timeline

### 1) `master` was created as a local account at `2015-12-12T03:02:42Z`

At `2015-12-12T03:02:42.943144Z`, `Security.evtx` record `126` (`EID 4720`) records creation of local account:

- `TargetUserName = master`
- `TargetDomainName = sensei`
- `TargetSid = S-1-5-21-2733037674-494817684-1624540804-1001`
- `SubjectUserName = WIN-F244SH17FGH$`
- `SubjectUserSid = S-1-5-18`

The matching SAM name key `\SAM\Domains\Account\Users\Names\master` has the same last-modified timestamp: `2015-12-12T03:02:42.943144Z`.

Disk evidence also supports true first-time provisioning of the profile at this stage:

- `/Users/master` first appears in the MAC timeline at `2015-12-12T03:03:16Z`
- `/Users/master/NTUSER.DAT` first appears at `2015-12-12T03:03:19Z`

Some files *inside* the newly provisioned profile carry older `2013-06-18` modified timestamps, but those are consistent with default/profile-template content copied into a newly created user profile and do not outweigh the direct 4720 + SAM + profile-root creation evidence.

### 2) `master` was enabled and added to local groups immediately

Immediately after creation:

- `EID 4728`, record `125`, `2015-12-12T03:02:42.943144Z`
  - `MemberSid = ...-1001`
  - `TargetSid = ...-513`
- `EID 4732`, record `127`, `2015-12-12T03:02:42.958946Z`
  - `TargetUserName = Users`
  - `TargetSid = S-1-5-32-545`
  - `MemberSid = ...-1001`
- `EID 4722`, record `128`, `2015-12-12T03:02:42.974583Z`
  - account `master` enabled
- `EID 4738`, record `129`, `2015-12-12T03:02:42.974583Z`
  - UAC changed `0x15 -> 0x14` (disabled -> enabled while remaining a normal local account)
- `EID 4724`, records `131` and `134`
  - password set/reset operations against `master`
- `EID 4738`, record `133`, `2015-12-12T03:02:42.990225Z`
  - UAC changed `0x14 -> 0x214` (password never expires added)
- `EID 4732`, record `135`, `2015-12-12T03:02:43.021597Z`
  - `TargetUserName = Administrators`
  - `TargetSid = S-1-5-32-544`
  - `MemberSid = ...-1001`

Interpretation: this sequence is **consistent with initial Windows account provisioning / OOBE** for the first local user on a fresh system, not necessarily attacker activity by itself.

### 3) `master` logged on interactively during first profile provisioning

At `2015-12-12T03:03:16.724915Z`, `Security.evtx` records `137-140` show `master` logging on:

- `EID 4648` record `137`
  - `TargetUserName = master`
  - `TargetServerName = localhost`
  - `ProcessName = C:\Windows\System32\winlogon.exe`
  - `IpAddress = 127.0.0.1`
- `EID 4624` records `138` and `139`
  - `TargetUserName = master`
  - `LogonType = 2`
  - `LogonProcessName = User32`
  - `WorkstationName = WIN-F244SH17FGH`
  - `ProcessName = C:\Windows\System32\winlogon.exe`
  - `IpAddress = 127.0.0.1`
- `EID 4672` record `140`
  - elevated privileges assigned to `master`

Interpretation: this is a local-console style interactive logon, not an RDP logon (`type 10`) and not a normal remote network logon with a source IP. In context with the `InstallDate` and profile-root creation times, this logon is consistent with first sign-in during setup rather than a later attacker login.

### 4) `master` activity included browsing local accounts

After the `master` logon:

- `EID 4797` records `145-148`, `166-174`, etc. show `master` querying local account membership/state for `Administrator` and `Guest`.

This is consistent with an attacker validating account state and privileges after obtaining/administering access.

### 5) The built-in `Administrator` account was temporarily enabled, used, then disabled again

At `2015-12-12T03:21:08.401726Z`:

- `EID 4722` record `202`: `Administrator` enabled
- `EID 4738` record `203`: UAC changed `0x211 -> 0x210`

Interactive `Administrator` sessions followed:

- `2015-12-12T03:22:19.527399Z`
  - `EID 4648` record `230`
  - `EID 4624` record `231` (`LogonType = 2`, `ProcessName = winlogon.exe`, `IpAddress = 127.0.0.1`)
  - `EID 4672` record `232`
- `2015-12-12T03:25:14.427914Z`
  - `EID 4648` record `262`
  - `EID 4624` record `263` (`LogonType = 2`, `ProcessName = winlogon.exe`, `IpAddress = 127.0.0.1`)
  - `EID 4672` record `264`

`Administrator` logoff events:

- `EID 4647` record `239` at `2015-12-12T03:24:52.855057Z`
- `EID 4647` record `271` at `2015-12-12T03:25:55.912338Z`

At `2015-12-12T03:26:19.740265Z`:

- `EID 4738` record `280`: UAC changed `0x210 -> 0x211`

Interpretation: someone intentionally enabled `Administrator`, used it for local interactive sessions, then disabled it again.

### 6) `master` was used again after `Administrator` was disabled

At `2015-12-12T03:26:53.711693Z`, `master` logged on again:

- `EID 4648` record `307`
- `EID 4624` records `308` and `309` (`LogonType = 2`, `WorkstationName = SENSEI`, `IpAddress = 127.0.0.1`)
- `EID 4672` record `310`

## Reboots and the clock rollback

Relevant system/security events:

- `Security.evtx` `EID 1100` at `2015-12-12T03:09:47.084217Z`, `03:21:49.667175Z`, `03:24:54.573776Z`, `03:26:25.366055Z`, `03:30:14.773466Z`
- `System.evtx` shutdown/start pairs around the same times (`EID 6006` / `6005`, `EID 13` / `12`)

Interpretation: the machine was rebooted multiple times during the period when `master` and `Administrator` were being used.

Important timeline caveat:

- `Security.evtx` `EID 4616`, record `333`, timestamp `2015-12-11T17:30:37.442135Z`
  - `PreviousTime = 2015-12-12 03:30:35.244495+00:00`
  - `NewTime = 2015-12-11 17:30:37.455999+00:00`
  - `ProcessName = C:\Windows\System32\VBoxService.exe`
- `System.evtx` `EID 1`, record `266`, carries the same old/new values

This means the guest clock was set **backward** by roughly 10 hours. Therefore, some events stamped around `2015-12-11 17:30Z` are later in the real sequence than events stamped `2015-12-12 03:0xZ`. In particular, the later `master` interactive session at `2015-12-11T17:30:45Z` should be interpreted as post-dating the `2015-12-12T03:02:42Z` account-creation burst in real sequence.

## `NTUSER.DAT` observations

### `master` profile

- `\Software\Microsoft\Windows\CurrentVersion\Run`
  - no values
  - last-modified: `2015-12-12T03:03:20.631020Z`
- `\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
  - entries reference `Info.txt`, `README.txt`, `Docs`, and `Tools`
  - last-modified: `2015-12-12T03:27:23.257824Z`

This does not prove the message file by itself, but it is a useful lead: `Info.txt` was opened in the `master` profile context and should be correlated with file-list / MAC timeline evidence.

### `Administrator` profile

- `\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
  - no values
  - last-modified: `2015-12-12T03:23:49.511658Z`

## Conclusions from this seat

1. A new local account, `master` (RID 1001), was created on `2015-12-12T03:02:42.943144Z`, then immediately enabled, password-set, and added to the local `Administrators` group.
2. The `master` creation/provisioning sequence is **most consistent with initial system setup / OOBE**, not intrusion activity on its own: `InstallDate` is `2015-12-12T03:03:15Z`, the first `master` interactive logon is at `03:03:16Z`, and `/Users/master` plus `/Users/master/NTUSER.DAT` materialize on disk right after.
3. The clearly suspicious account activity from this seat starts later: the built-in `Administrator` account was enabled at `2015-12-12T03:21:08Z`, used for local interactive sessions at `03:22:19Z` and `03:25:14Z`, then disabled again at `03:26:19Z`.
4. The available Security log evidence does **not** show successful RDP (`LogonType 10`) or attacker-account sessions tied to a remote IP address; the observed privileged sessions are local-console style via `winlogon.exe` and `127.0.0.1`.
5. The guest clock was set backward by `VBoxService.exe` at `2015-12-11T17:30:37Z` (from `2015-12-12T03:30:35Z`), so raw timestamps after that rollback boundary are not in true chronological order.
6. This seat supports a local hands-on-keyboard / Winlogon-screen abuse phase for the intrusion, especially when combined with the independently verified `Magnify.exe -> cmd.exe` backdoor, but `master` account creation itself should not be narrated as the attacker creating a backdoor user unless the report explicitly labels that as uncertain.

## Cross-seat handoff notes

- Disk/message seats should correlate `master` profile `RecentDocs` entries, especially `Info.txt`, against `catalog/.../filelist.txt` and `timeline.csv`.
- Leftovers/software seats should correlate the **Administrator** session times above, the post-rollback `master` session, and the Magnify/cmd swap with file creations, services, and dropped tools.
- Timeline seat should explicitly annotate the `VBoxService.exe` backward clock change so events after that boundary are not sorted purely by wall time.

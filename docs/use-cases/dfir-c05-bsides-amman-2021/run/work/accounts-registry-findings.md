# Accounts, registry, and event-log findings (s2f6601)

This note covers the assigned accounts/event-log seat: SAM + user hives + Security/System event logs. Full command/output excerpts used below are preserved in `work/s2f6601/notes.txt`.

## High-confidence findings

1. **`IEUser` created the `Joker` account on 2019-02-15 04:53:33Z, and `Joker` logged on minutes later.**
2. **The confidential documents are tied to `Joker`, not `IEUser`, by multiple user-specific artifacts in `Joker`'s profile:**
   - `Joker` has four `Recent` shortcut files for the confidential documents.
   - `Joker`'s `RecentDocs` registry keys contain `Confidential.rtf`, `Confidential_02.docx`, `Confidential_03.docx`, and `Confidential_04.docx`.
   - `Joker`'s WordPad recent-file list contains `\\192.168.70.128\SharedJJ\docs\Confidential.rtf`.
   - `Joker`'s `UserAssist` shows `wordpad.exe` last executed at `2019-02-15T05:03:45.634Z`, matching the confidential-doc activity window.
3. **The confidential documents were accessed from a network location**: the `Joker` shortcut files resolve to `\\192.168.70.128\SharedJJ\docs\...`, and `IEUser`'s hive shows the mapped/browsed share `\\192.168.70.128\SharedJJ`.
4. **`IEUser` also created the `sshd` and `sshd_server` accounts, and added `sshd_server` to Administrators** on 2018-04-25.
5. **DCode was attributable to `Joker`, but it was executed under the renamed filename `dd.exe` rather than `DCode.exe`.** Evidence from `Joker`'s profile now includes `Users/Joker/DCode.exe`, the `DCode\Settings` registry key, a `UserAssist` entry for `C:\Users\Joker\dd.exe` with `run_counter=1`, and a parsed `DD.EXE-0C303FDD.pf` prefetch file showing one run and last run at `2019-02-15T05:02:13.353878Z`.

## Evidence

### 1) `IEUser` created `Joker`

From `work/extracted/s2f6601/Security.evtx` (recorded in `work/s2f6601/notes.txt`):

```text
RID=1984 time=2019-02-15 04:53:33.496557+00:00 eid=4720
  TargetUserName=Joker
  TargetSid=S-1-5-21-597701057-294507186-493142324-1004
  SubjectUserName=IEUser
  SubjectDomainName=MSEDGEWIN10
  TargetDomainName=MSEDGEWIN10
```

Corroboration from `SAM` name-key last-write time:

```text
Joker: SAM\Domains\Account\Users\Names\Joker lastwrite_utc=2019-02-15T04:53:33.484638+00:00
```

### 2) `Joker` logged on after account creation

From `work/extracted/s2f6601/Security.evtx`:

```text
RID=2029 time=2019-02-15 04:54:09.087833+00:00 eid=4624
  TargetUserName=Joker
  TargetDomainName=MSEDGEWIN10
  LogonType=2
  IpAddress=127.0.0.1
  WorkstationName=MSEDGEWIN10
  ProcessName=C:\Windows\System32\svchost.exe
  AuthenticationPackageName=Negotiate
```

Additional `Joker` interactive logons also appear at record IDs 2067, 2208, and 2549.

### 3) `IEUser` created `sshd` / `sshd_server` and elevated `sshd_server`

From `work/extracted/s2f6601/Security.evtx`:

```text
RID=762 time=2018-04-25 20:06:32.487247+00:00 eid=4720
  TargetUserName=sshd
  SubjectUserName=IEUser

RID=779 time=2018-04-25 20:06:37.029366+00:00 eid=4720
  TargetUserName=sshd_server
  SubjectUserName=IEUser

RID=787 time=2018-04-25 20:06:37.453815+00:00 eid=4732
  TargetUserName=Administrators
  MemberSid=S-1-5-21-597701057-294507186-493142324-1003
  SubjectUserName=IEUser
```

`S-1-5-21-597701057-294507186-493142324-1003` is the `sshd_server` account created in record 779.

### 4) Confidential-document artifacts are in `Joker`'s profile

File-list hits (`catalog/BSidesAmman21.E01/p0/filelist.txt`):

```text
8545:r/r 96881-128-4: Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential.lnk
8546:r/r 96884-128-4: Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential_02.lnk
8547:r/r 96885-128-4: Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential_03.lnk
8548:r/r 96886-128-4: Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential_04.lnk
8609:r/r 97031-128-4: Users/Joker/Confidential.rtf
```

`Joker` `RecentDocs` evidence from `work/extracted/s2f6601/Joker-NTUSER.DAT`:

```text
KEY=ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.rtf
  last_modified_utc=2019-02-15T05:03:25.572798+00:00
  ... Confidential.rtf ... Confidential.lnk ...

KEY=ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.docx
  last_modified_utc=2019-02-15T05:03:45.728706+00:00
  ... Confidential_02.docx ... Confidential_02.lnk ...
  ... Confidential_03.docx ... Confidential_03.lnk ...
  ... Confidential_04.docx ... Confidential_04.lnk ...
```

### 5) Network-share proof and application proof (`WordPad`)

Shortcut metadata (`exiftool` on the four `Joker` `.lnk` files):

```text
Create Date     : 2019:02:15 07:07:47+03:00
Access Date     : 2019:02:15 07:07:47+03:00
Net Name        : \\192.168.70.128\SHAREDJJ
Working Directory: \\192.168.70.128\SharedJJ\docs
```

Embedded target strings from the same shortcuts:

```text
\\192.168.70.128\SharedJJ\docs\Confidential.rtf
\\192.168.70.128\SharedJJ\docs\Confidential_02.docx
\\192.168.70.128\SharedJJ\docs\Confidential_03.docx
\\192.168.70.128\SharedJJ\docs\Confidential_04.docx
```

WordPad recent-file list under `Joker`:

```text
KEY=ROOT\Software\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List
  last_modified_utc=2019-02-15T05:34:16.612184+00:00
  Value(name='File1', value='\\192.168.70.128\SharedJJ\docs\Confidential.rtf', value_type='REG_SZ', ...)
  Value(name='File2', value='C:\Users\Joker\Confidential.rtf', value_type='REG_SZ', ...)
```

`UserAssist` execution evidence from the same `Joker` hive (`work/s2f6601/userassist.txt`):

```text
KEY ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count last_modified_utc 2019-02-15T05:34:31.909450+00:00
 VALUE_NAME_DEC {6D809377-6AF0-444B-8957-A3773F02200E}\Windows NT\Accessories\wordpad.exe
 PARSED {'session': 0, 'run_count': 5, 'focus_count': 4, 'focus_time_ms': 22516, 'last_exec_utc': '2019-02-15T05:03:45.634000+00:00'}
```

This is both **network-location evidence** and **application evidence**: WordPad tracked `Confidential.rtf` in `Joker`'s hive, and `UserAssist` shows `wordpad.exe` execution inside the same time window as the confidential-doc recent-artifact updates.

### 6) `IEUser` had the network share mapped/browsed, but not the confidential-doc RecentDocs hits

From `work/extracted/s2f6601/IEUser-NTUSER.DAT`:

```text
KEY=ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU
  last_modified_utc=2019-02-15T04:31:40.985292+00:00
  Value(name='a', value='\\192.168.70.128\SharedJJ\\', value_type='REG_SZ', ...)

KEY=ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\##192.168.70.128#SharedJJ
  last_modified_utc=2019-02-15T04:31:41.032078+00:00

KEY=ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
  last_modified_utc=2019-02-15T04:25:27.876008+00:00
  Value(name='url1', value='\\192.168.70.128\\', value_type='REG_SZ', ...)
```

Interpretation: `IEUser` accessed/browsed the remote share, but the user-specific confidential-document opening traces are concentrated in `Joker`'s profile.

### 7) DCode was used from `Joker`'s profile, under the name `dd.exe`

File-list, registry, `UserAssist`, Amcache, and prefetch evidence:

```text
8613:r/r 97020-128-5: Users/Joker/DCode.exe
8614:r/r 97026-128-5: Users/Joker/dd.exe

KEY=ROOT\Software\VB and VBA Program Settings\DCode\Settings
  last_modified_utc=2019-02-15T05:02:13.494426+00:00
  Value(name='OnTop', value='False', value_type='REG_SZ', ...)

{'name': 'C:\\Users\\Joker\\dd.exe', 'timestamp': '2019-02-15T05:02:12.791000+00:00', 'run_counter': 1, 'focus_count': 1, 'total_focus_time_ms': 4110, 'session_id': 0}

{"version": 30, "signature": "SCCA", "executable_name": "DD.EXE", "run_count": 1, "last_run_times_utc": ["2019-02-15T05:02:13.353878Z"]}
```

I also verified that `Amcache.hve` contains `ROOT\Root\InventoryApplicationFile\dd.exe|8bbdf4af3d1b2e53` with `LowerCaseLongPath=c:\users\joker\dd.exe` and `ProductName=dcode`, while `IEUser`'s `NTUSER.DAT` has no `DCode` key/value hits.

## What the editor can safely use

- **Q2/Q3 suspect user:** strong support for `Joker`.
- **Q4/Q5 location:** strong support for `network share` (`\\192.168.70.128\SharedJJ\docs\...`).
- **Q6 list of accessed files:**
  - `\\192.168.70.128\SharedJJ\docs\Confidential.rtf`
  - `\\192.168.70.128\SharedJJ\docs\Confidential_02.docx`
  - `\\192.168.70.128\SharedJJ\docs\Confidential_03.docx`
  - `\\192.168.70.128\SharedJJ\docs\Confidential_04.docx`
  - plus the local copy `C:\Users\Joker\Confidential.rtf` from WordPad recent-file data.
- **Q7 two evidence types:** `RecentDocs` + `.lnk` metadata/strings (and WordPad recent-file list for the RTF).
- **Q8 application:** strong support for WordPad opening `Confidential.rtf` (`Wordpad\Recent File List` + `UserAssist` execution at `2019-02-15T05:03:45.634Z`).
- **Q12 DCode user:** `Joker`.
- **Q13 times used:** `1` confirmed execution.
- **Q14 last used:** `2019-02-15T05:02:13.353878Z` from `DD.EXE-0C303FDD.pf` (with matching `UserAssist` timestamp `2019-02-15T05:02:12.791Z`).
- **Q15 location:** original file `C:\Users\Joker\DCode.exe`, but the execution artifacts show it was run as renamed `C:\Users\Joker\dd.exe`.

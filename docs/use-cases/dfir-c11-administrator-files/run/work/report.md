# DFIR Case AH-C11: Where Did Administrator Go?

**Examiner**: Halil Ozturkci | **Swarm**: sb6b3 | **Date**: 2026-09-18
**Evidence**: `inputs/ThreatSimServer.E01` (35.2 GB E01, SHA256 `6634fb1a399c…`)
**Case brief**: The ThreatSim domain administrator's files are gone and nobody knows what happened or how.

---

## 1. System Profile

| Attribute | Value |
|---|---|
| OS | Windows Server 2019 Standard, Build 17763.3046 (1809 RS5) |
| Computer name | DC (FQDN: dc.simlab.local) |
| Role | Active Directory Domain Controller |
| Domain | simlab.local |
| Domain SID | S-1-5-21-648620150-2484957592-2617966632 |
| Time zone | Eastern Standard Time (UTC-5, DST UTC-4) |
| Install date | 2024-07-02 |
| Platform | VMware virtual machine (VMware Tools present) |
| NTFS volume serial | C43073DA3073D242 |
| Acquisition | EWF Case 011, Examiner AH, MD5 `45a9e594…`, SHA1 `360c7c02…`, acquired 2024-07-27 |

**Accounts** (ProfileList from SOFTWARE hive):

| Account | SID | Profile Path | State |
|---|---|---|---|
| Administrator | S-1-5-21-648620150-2484957592-2617966632-500 | C:\Users\Administrator | Cached local (State=256), **profile is empty** |
| jdoe | S-1-5-21-648620150-2484957592-2617966632-1103 | C:\Users\jdoe | Roaming (State=516) |
| Guest | S-1-5-21-…-501 | — | Disabled |
| DefaultAccount | S-1-5-21-…-503 | — | System-managed |
| WDAGUtilityAccount | S-1-5-21-…-504 | — | System-managed |

*Source: SYSTEM/SOFTWARE/SAM hives extracted by sb6b306; ledger seq 32 (Post #32)*

---

## 2. What Happened to the Administrator's Files

**The Administrator's files were securely deleted (wiped) using Sysinternals SDelete 2.05.**

The tool was renamed to `dark_knight.c5w`, dropped in `C:\Windows\`, executed once, then deleted.

**Evidence chain:**

1. **Directory is empty**: `fls` on `/Users/Administrator` (inode 9004) returns only `.` and `..`. No live files remain. (*ledger seq 7, 18, 33*)

2. **$I30 INDEX_ROOT is empty**: The directory index has zero entries. (*ledger seq 7, 33*)

3. **$INDEX_ALLOCATION slack contains deleted names**: Extracted slack (inode 9004-160-4, 8192 bytes) still contains references to `NTUSER.DAT`, `ntuser.dat.LOG2`, and transaction log files — proving a normal user profile existed before deletion. (*ledger seq 38*)

4. **SDelete confirmed**: `dark_knight.c5w` (SHA256 `59e5ae1e99c6a4ccc01e8abdc2534210ec5faa945754a89524b06381da8c20a1`) is Sysinternals SDelete64.exe, identified by PDB path `D:\a\1\s\x64\Release\Sdelete64.pdb` and embedded Sysinternals EULA. (*ledger seq 8, 12, 28, 39*)

5. **SDelete renaming pattern**: SDelete renamed Administrator files to Z+ names (e.g., `ZZZZZZZZZZZZZZZ.ZZ`) before overwriting. 421 Z-named orphan files remain in the MFT, all containing high-entropy overwritten data. (*ledger seq 46*)

6. **Admin NTUSER.DAT orphaned**: Transaction log files (`NTUSER.DAT{…}.TM.blf`, `.TMContainer…regtrans-ms`) exist as orphans in `$OrphanFiles` (inodes 98926–98928). (*ledger seq 18, 38*)

7. **Timing**: Administrator directory created 2024-07-02T06:01:19Z; emptied 2024-07-27T05:57:08Z — 7 seconds after DARK_KNIGHT.C5W execution at 05:57:01Z. (*ledger seq 9, 11*)

**Conclusion**: The files were not encrypted, moved, or hidden. They were securely wiped: renamed, overwritten with random data, and then deleted from the MFT.

---

## 3. How — Account, Source, and Means

### Account
**simlab\Administrator** (S-1-5-21-648620150-2484957592-2617966632-500) — the domain administrator themselves.

Evidence:
- Security.evtx Event ID 4634 shows Administrator logoff with LogonType 3 (Network) at 06:03:07Z. (*ledger seq 23*)
- Administrator VMware Tools session started at 05:40:32Z. (*ledger seq 34*)
- SDelete prefetch references `USERS\ADMINISTRATOR\APPDATA\LOCAL\MICROSOFT\WINDOWS\SCHCACHE\DC.SIMLAB.LOCAL.SCH` — the Administrator's own profile path. (*ledger seq 20, 41*)

A second account, **simlab\jdoe** (S-1-5-21-…-1103), also had an active session:
- jdoe VMware Tools session started at 05:55:48Z. (*ledger seq 35*)
- jdoe logoff at 06:03:13Z. (*ledger seq 32*)
- jdoe's UserAssist registry keys last modified at 05:55:34Z (cleared). (*ledger seq 35*)

### Source
**VMware console (local/type-2 logon)** — both Administrator and jdoe sessions were VMware console sessions, not RDP or network logons. Evidence: VMware vmtoolsd log entries for both accounts. No RDP/WinRM event log entries survived the log clearing.

### Means — Full Attack Chain

| Step | Time (UTC) | Tool | Evidence |
|---|---|---|---|
| 1. Admin login | 05:40:32 | VMware console | vmtoolsd-Administrator.log (inode 219294) |
| 2. User enumeration | 05:51:58 | net.exe / net1.exe | Prefetch NET.EXE-DF44F913.pf, NET1.EXE-849DA590.pf (SAMCLI.DLL loaded) — *ledger seq 5, 17, 48* |
| 3. Defender tampering | 05:27:11 | — | Defender definition files deleted; Scheduled Scan task deleted at 05:38:38Z — *ledger seq 25, 26* |
| 4. NTDS tampering | 05:52:41 | — | WMI ETW traces deleted, NTDS temp.edb wiped, event log state files deleted — *ledger seq 32 (Post #32)* |
| 5. jdoe login | 05:55:48 | VMware console | vmtoolsd-jdoe.log (inode 49003) — *ledger seq 35* |
| 6. SDelete execution | 05:57:01 | dark_knight.c5w (SDelete64) | Prefetch DARK_KNIGHT.C5W-A45BCA91.pf, run count=1 — *ledger seq 1, 10, 13, 24, 37* |
| 7. Profile wiped | 05:57:08 | SDelete | Administrator directory MAC updated, $I30 emptied — *ledger seq 3, 9* |
| 8. PowerShell | 06:02:33 | powershell.exe | Prefetch POWERSHELL.EXE-920BBA2A.pf — *ledger seq 2, 15, 47* |
| 9. Log clearing | 06:02:34 | wevtutil.exe × 8+ | Prefetch WEVTUTIL.EXE-EF5861C4.pf (8 runs in 125ms) — *ledger seq 6, 14, 42, 45* |
| 10. Logs cleared | 06:02:56 | — | Security EID 1102, System EID 104 — *ledger seq 16, 23, 27* |
| 11. Logoffs | 06:03:07–06:03:13 | — | Administrator (EID 4634), jdoe (EID 4647) logoff — *ledger seq 23, 32* |
| 12. Shutdown | 06:03:14 | — | EventLog service shutdown (EID 1100) — *ledger seq 23* |

### Log Clearing Detail
All event log channels were cleared via `wevtutil cl`:
- Security.evtx: cleared, 2 post-clear events remain
- System.evtx: cleared, only shutdown events remain
- PowerShell Operational: 0 events
- PowerShell Admin: 0 events
- Windows Defender Operational: 0 events
- TerminalServices-RemoteConnectionManager: 0 events
- RDP-CoreTS: 0 events

*Source: evtx_query on extracted EVTX files (ledger seq 22, 27)*

---

## 4. When — Timeline

The full timeline is in `work/timeline.md` (built from the ledger). Key events:

| Time (UTC) | Event |
|---|---|
| 2024-07-02T05:59:35 | System first boot / setup (PFRO.log, SCM.EVM, setupapi logs) |
| 2024-07-02T06:01:19 | Administrator profile directory created |
| 2022-06-17T18:08:17 | Suspicious scheduled task "User_Feed_Synchronization" created by Administrator on WIN-NPNJQ3D5QCQ |
| 2024-07-27T05:26:50 | LSA/SAM log files created (system startup) |
| 2024-07-27T05:27:08 | Windows Defender definitions deleted, Dfsr log rotated |
| 2024-07-27T05:38:38 | Windows Defender Scheduled Scan task deleted |
| 2024-07-27T05:40:32 | Administrator VMware console session started |
| 2024-07-27T05:51:58 | net.exe/net1.exe executed (user enumeration) |
| 2024-07-27T05:52:41 | WMI ETW trace logs deleted, NTDS temp.edb wiped |
| 2024-07-27T05:55:48 | jdoe VMware console session started |
| 2024-07-27T05:57:01 | **dark_knight.c5w (SDelete64) executed** |
| 2024-07-27T05:57:08 | Administrator directory metadata updated (files wiped) |
| 2024-07-27T06:02:33 | PowerShell executed |
| 2024-07-27T06:02:34 | wevtutil.exe executed 8+ times (log clearing) |
| 2024-07-27T06:02:56 | Security and System event logs cleared |
| 2024-07-27T06:03:07 | Administrator network session logoff |
| 2024-07-27T06:03:14 | EventLog service shutdown, system shutdown |

---

## 5. What Else Was Done

### 5.1 Defence Tampering
- **Windows Defender crippled**: Definition files (`mpasbase.vdm`, `mpavbase.vdm`, `mpengine.dll`) deleted at 05:27:11. Scheduled Scan task deleted at 05:38:38. (*ledger seq 25, 26*)
- **Event logs cleared**: Security, System, PowerShell, Windows Defender, RDP, and other operational logs cleared via wevtutil at 06:02:34. (*ledger seq 6, 14, 22, 27*)
- **SDelete tool deleted**: `C:\Windows\dark_knight.c5w` deleted from MFT after use (inode 49784 unallocated). (*ledger seq 8, 36, 44*)
- **NTDS temp.edb wiped**: Active Directory temporary database deleted at 05:52:41.

### 5.2 Persistence
- **Suspicious scheduled task**: `User_Feed_Synchronization-{41BCACAF-405F-4D8F-AC3F-C9E5975C488A}` created 2022-06-17 by `WIN-NPNJQ3D5QCQ\Administrator`, pointing to `msfeedsync.exe` (note: not the legitimate `msfeedssync.exe` — one 's' difference), daily trigger, marked Hidden. (*ledger seq 30*)
- **No new services** found in remaining System event log entries.
- **No new accounts** detected beyond jdoe (existing domain account).
- **No WMI subscriptions** confirmed (WMI logs cleared).
- **No Run key modifications** detected in jdoe's NTUSER.DAT (keys cleaned at login).

### 5.3 Other Accounts & Files
- **jdoe** (RID 1103) is a domain user with a roaming profile at `C:\Users\jdoe\`. Profile intact but UserAssist cleared at login time 05:55:34.
- **No other files targeted** — jdoe's profile, Default profile, and system files were not deleted. Only the Administrator profile was wiped.

### 5.4 Additional Orphan Files
- **$RVGAZ09.exe**: 14 MB deleted file in orphan Recycle Bin (SID S-1-5-21-108275531-3251279832-3020563596-500), SHA256 `3b0e178d…`. File type: data (possibly packed/encrypted or SDelete-wiped). (*ledger seq 29*)
- **421 Z-named orphan files** from SDelete renaming operation. (*ledger seq 46*)

---

## 6. Can the Files Be Recovered?

### Recovery Assessment

| Method | Feasibility | Result |
|---|---|---|
| **VSS / Shadow Copies** | ❌ Impossible | No VSS snapshots exist on this system (no `{GUID}` folders under System Volume Information). *ledger seq 32* |
| **$MFT file carving** | ❌ Impossible | SDelete overwrites file data clusters with random bytes before deallocating MFT records. All file content is destroyed. |
| **$LogFile replay** | ❌ Impossible | SDelete writes directly to disk bypassing journaling; overwritten data cannot be replayed. |
| **$UsnJrnl history** | ⚠️ Partial | The $UsnJrnl may contain historical filenames but not file content. |
| **$I30 slack** | ⚠️ Partial | INDEX_ALLOCATION slack (inode 9004-160-4) contains deleted filenames: `NTUSER.DAT`, `ntuser.dat.LOG2`, transaction logs. Names recovered, content not recoverable. *ledger seq 38* |
| **Prefetch strings** | ⚠️ Partial | DARK_KNIGHT prefetch contains paths that were accessed: `USERS\ADMINISTRATOR\APPDATA\LOCAL\MICROSOFT\WINDOWS\SCHCACHE\DC.SIMLAB.LOCAL.SCH`, WebCache paths, Explorer caches. *ledger seq 20, 41* |
| **Free-space carving** | ❌ Impossible | SDelete's default behavior is 1-pass random overwrite. Data is non-recoverable. |

### What Was Recovered

| Item | Description | Hash |
|---|---|---|
| `dark_knight.c5w` | SDelete64 binary (224,168 bytes) from deleted inode 49784 | SHA256 `59e5ae1e99c6a4ccc01e8abdc2534210ec5faa945754a89524b06381da8c20a1` |
| Deleted filenames | `NTUSER.DAT`, `ntuser.dat.LOG2`, `NTUSER.DAT{…}.TMContainer…regtrans-ms` from $I30 slack | — |
| Orphan NTUSER logs | `NTUSER.DAT{1c3790b4-…}.TM.blf` and `.TMContainer…regtrans-ms` (inodes 98926–98928), 65536 and 524288 bytes respectively | Content is registry transaction logs, not user data |
| Z-named orphans | 421 SDelete-renamed files with overwritten content | All contain random/high-entropy data |

**Conclusion**: The Administrator's files cannot be recovered through normal forensic methods. SDelete's secure overwrite destroyed the file contents beyond recovery. Only filenames and paths survive in slack space and prefetch artifacts.

---

## 7. Indicators, Recommendations, and Notes

### Indicators of Compromise (IOCs)

| IOC | Type | Value |
|---|---|---|
| dark_knight.c5w | File hash | SHA256 `59e5ae1e99c6a4ccc01e8abdc2534210ec5faa945754a89524b06381da8c20a1` |
| DARK_KNIGHT.C5W-A45BCA91.pf | Prefetch hash | SHA256 `34307369b6b80522d83bbcb3e429a45720a6bf34240f95f886ef37e69aa891c8` |
| SDelete renamed | Filename pattern | `dark_knight.c5w` in `C:\Windows\` |
| .c5w suffix | Naming convention | Cyber5W challenge naming pattern |
| Z-named files | SDelete artifact | Files renamed to `ZZZZZZZ…` patterns before wipe |
| msfeedsync.exe | Suspicious task binary | One 's' off from legitimate `msfeedssync.exe` |
| Event ID 1102 | Log clearing | Security log cleared by wevtutil |

### MITRE ATT&CK Mappings

| Tactic | Technique | Evidence |
|---|---|---|
| Defense Evasion | T1070.001 — Clear Windows Event Logs | wevtutil executed 8+ times, all logs cleared |
| Defense Evasion | T1562.001 — Disable or Modify Tools | Windows Defender definitions deleted, scan task removed |
| Defense Evasion | T1070.004 — File Deletion | SDelete used to securely wipe Administrator profile |
| Defense Evasion | T1036.005 — Match Legitimate Name or Location | SDelete renamed to dark_knight.c5w, placed in C:\Windows\ |
| Persistence | T1053.005 — Scheduled Task | Suspicious User_Feed_Synchronization task created 2022-06-17 |
| Impact | T1485 — Data Destruction | Administrator profile securely wiped, unrecoverable |

### Recommendations

1. **Isolate and investigate the jdoe account**: jdoe had an active session during the incident. Determine if this account was compromised or if the user is the attacker.
2. **Review domain controller access**: The attack required Administrator-level access. Audit all domain admin accounts and reset credentials.
3. **Deploy EDR/SIEM monitoring**: The attack took ~22 minutes from login to log clearing. Real-time monitoring of wevtutil, sdelete, and Defender tampering would have detected this.
4. **Enable PowerShell logging and protected event logging**: All PowerShell logs were cleared. Script block logging and protected event logging would have preserved evidence.
5. **Implement log forwarding**: Forward event logs to a central SIEM to prevent local clearing.
6. **Review scheduled tasks**: The User_Feed_Synchronization task from 2022-06-17 remains suspicious and should be analyzed further.
7. **Check for lateral movement**: As a domain controller, this system's compromise may affect the entire domain.

### Examiner's Notes

- The `dark_knight.c5w` naming with `.c5w` suffix matches the Cyber5W challenge convention, suggesting this was a controlled exercise scenario.
- The machine name `WIN-NPNJQ3D5QCQ` in the 2022 scheduled task differs from the current name `DC`, suggesting the system was renamed or the domain was rebuilt between 2022 and 2024.
- The system was installed on 2024-07-02 and the incident occurred on 2024-07-27 — only 25 days of operation.
- The E01 acquisition was performed on 2024-07-27, the same day as the incident, suggesting the image was taken post-incident for forensic analysis.

---

*Report compiled by sb6b305 (Admin-File-Forensics) from ledger entries contributed by sb6b300, sb6b301, sb6b302, sb6b303, sb6b304, sb6b305, sb6b306. See `ledger/ledger.md` for full evidence citations.*
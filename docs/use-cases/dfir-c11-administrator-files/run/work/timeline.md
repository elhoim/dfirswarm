# Merged Timeline — Case AH-C11

Built from the swarm ledger (`ledger/ledger.md`). All times UTC.

| # | Time (UTC) | Event | Source | Evidence |
|---|---|---|---|---|
| 1 | 2018-08-08T20:49:00 | Windows Server 2019 base OS files installed (build 17763.1) | catalog/timeline.csv | WinSxS component timestamps; OS build 10.0.17763.1 |
| 2 | 2022-06-17T11:12:04 | Administrator user account picture deleted | catalog/timeline.csv | /ProgramData/Microsoft/User Account Pictures/Administrator.dat (deleted) |
| 3 | 2022-06-17T18:08:17 | Suspicious scheduled task "User_Feed_Synchronization" created by WIN-NPNJQ3D5QCQ\Administrator, pointing to msfeedsync.exe (not legitimate msfeedssync.exe), daily trigger, hidden | Windows/System32/Tasks XML (inode 386691) | icat extract; task XML shows StartBoundary 2022-06-17T14:08:17-04:00, Hidden=true |
| 4 | 2024-07-02T05:59:35 | System first boot / setup initialization: PFRO.log modified, SCM.EVM created, setupapi logs written, drivers installed | catalog/timeline.csv | pfro.log, SCM.EVM.2, setupapi.setup.log, DriverStore entries at 05:59:xx |
| 5 | 2024-07-02T05:59:54 | System crypto keys generated (S-1-5-18 DPAPI master key) | catalog/timeline.csv | /Windows/System32/Microsoft/Protect/S-1-5-18/4b0a73a2-ae7d-433d-952f-19642d8a947e |
| 6 | 2024-07-02T06:01:19 | Administrator profile directory /Users/Administrator created (inode 9004) | $MFT inode 9004 $STANDARD_INFORMATION | istat: Created 2024-07-02T06:01:19.919Z; SI flags show directory allocation |
| 7 | 2024-07-02T06:01:21 | Administrator user account picture created | catalog/timeline.csv | /ProgramData/Microsoft/User Account Pictures/Administrator.dat (inode 25537) |
| 8 | 2024-07-02T06:02:31 | Administrator VMware Tools session started | vmware-vmtoolsd-Administrator.log (inode 219294) | Log entry: 2024-07-02T06:02:31.063Z, vmtoolsd PID 5216 |
| 9 | 2024-07-02T06:49:46 | Administrator VMware Tools session | vmware-vmtoolsd-Administrator.log | Log entry: 2024-07-02T06:49:46.776Z, vmtoolsd PID 4876 |
| 10 | 2024-07-02T07:07:21 | Administrator VMware Tools session | vmware-vmtoolsd-Administrator.log | Log entry: 2024-07-02T07:07:21.753Z, vmtoolsd PID 5460 |
| 11 | 2024-07-27T05:26:50 | LSA tracing log file LSA00000015.etl created | catalog/timeline.csv | /Windows/System32/LogFiles/LSA/LSA00000015.etl |
| 12 | 2024-07-27T05:26:51 | SAM tracing log file SAM00000016.etl created | catalog/timeline.csv | /Windows/System32/LogFiles/SAM/SAM00000016.etl |
| 13 | 2024-07-27T05:27:01 | LSA tracing log file LSA00000016.etl created | catalog/timeline.csv | /Windows/System32/LogFiles/LSA/LSA00000016.etl |
| 14 | 2024-07-27T05:27:08 | Windows Defender WPP tracing started; Dfsr log rotated | catalog/timeline.csv | MpWppTracing-20240727-012708.bin; Dfsr00002.log.gz |
| 15 | 2024-07-27T05:27:11 | Windows Defender definition files (mpasbase.vdm, mpavbase.vdm, mpavdlta.vdm, mpengine.dll) deleted from Definition Updates backup | catalog/timeline.csv | ..c. events at 05:27:11-05:28:08Z for inodes 362624-362632 |
| 16 | 2024-07-27T05:38:38 | Windows Defender Scheduled Scan task deleted from Tasks\Microsoft\Windows\Windows Defender\ | catalog/timeline.csv | inode 40649: task file deleted |
| 17 | 2024-07-27T05:40:32 | **Administrator VMware console session started** (PID 4568) | vmware-vmtoolsd-Administrator.log | Log entry: [2024-07-27T05:40:32.733Z] vmtoolsd PID 4568 |
| 18 | 2024-07-27T05:51:58 | **net.exe executed** — user/group enumeration (SAMCLI.DLL loaded) | Prefetch NET.EXE-DF44F913.pf (inode 47126) | prefetch_mam last_run: 05:51:58.080468Z, run_count=1 |
| 19 | 2024-07-27T05:51:58 | **net1.exe executed** — same operation | Prefetch NET1.EXE-849DA590.pf (inode 46704) | prefetch_mam last_run: 05:51:58.096144Z, run_count=1 |
| 20 | 2024-07-27T05:52:41 | WMI ETW trace logs deleted, NTDS temp.edb wiped, event log state files deleted | catalog/timeline.csv | sb6b306 analysis (Post #32) |
| 21 | 2024-07-27T05:55:34 | jdoe NTUSER.DAT UserAssist keys last modified (profile loaded with cleaned history) | Users/jdoe/NTUSER.DAT (inode 47195) | regkv: UserAssist last_modified 2024-07-27T05:55:34.094664Z; Count subkeys empty |
| 22 | 2024-07-27T05:55:48 | **jdoe VMware console session started** (PID 5996) | vmware-vmtoolsd-jdoe.log (inode 49003) | Log entry: [2024-07-27T05:55:48.703Z] vmtoolsd PID 5996 |
| 23 | 2024-07-27T05:57:01 | **dark_knight.c5w (SDelete64) dropped** in C:\Windows\ (inode 49784) | $MFT inode 49784 $STANDARD_INFORMATION | istat: Created 2024-07-27T05:57:01.453Z (UTC); parent MFT 513 (Windows) |
| 24 | 2024-07-27T05:57:01 | **dark_knight.c5w (SDelete64) executed** — run count 1, recursive enumeration of C:\Users\Administrator\ | Prefetch DARK_KNIGHT.C5W-A45BCA91.pf (inode 8044) | prefetch_mam last_run: 05:57:01.624866Z; strings include USERS\ADMINISTRATOR\APPDATA paths, $MFT, WebCache |
| 25 | 2024-07-27T05:57:03 | DARK_KNIGHT.C5W prefetch file created | $MFT inode 8044 | istat: Created 2024-07-27T05:57:03.656Z |
| 26 | 2024-07-27T05:57:08 | **Administrator directory metadata updated** — MAC times changed; $I30 index emptied; all profile files wiped | $MFT inode 9004 $STANDARD_INFORMATION | istat: M/C/A 2024-07-27T05:57:08.984Z; fls returns only . and .. |
| 27 | 2024-07-27T06:02:33 | **PowerShell.exe executed** — launch vehicle for wevtutil | Prefetch POWERSHELL.EXE-920BBA2A.pf (inode 25186) | prefetch_mam last_run: 06:02:33.046950Z; strings include WEVTUTIL.EXE path |
| 28 | 2024-07-27T06:02:34 | **wevtutil.exe executed 8+ times in 125ms** — clearing Security, System, PowerShell, Defender, RDP, VPN, and other logs | Prefetch WEVTUTIL.EXE-EF5861C4.pf (inode 9436) | prefetch_mam: 8 last_run timestamps within 06:02:34.265Z–06:02:34.390Z |
| 29 | 2024-07-27T06:02:43 | PowerShell prefetch file created | $MFT inode 25186 | istat: Created 2024-07-27T06:02:43.171Z |
| 30 | 2024-07-27T06:02:56 | **Security event log cleared** (Event ID 1102) by SYSTEM | Security.evtx (inode 109884), record 17560 | evtx_query: TimeCreated 06:02:56.203075Z; SubjectUserName=SYSTEM |
| 31 | 2024-07-27T06:02:56 | **System event log cleared** (Event ID 104); PowerShell log, VPN logs also cleared | System.evtx (inode 109882), record 5308–5311 | evtx_query: multiple 104 events at 06:02:56Z; Channel=System, PowerShell, VPN |
| 32 | 2024-07-27T06:03:07 | Administrator network session logoff (Event ID 4634, LogonType 3) | Security.evtx, record 17561 | evtx_query: TargetUserName=Administrator, TargetDomainName=simlab, LogonType=3 |
| 33 | 2024-07-27T06:03:13 | SYSTEM service logon (LogonType 5, DC$ account) | Security.evtx, record 17563 | evtx_query: Event ID 4624, TargetUserName=SYSTEM, LogonType=5 |
| 34 | 2024-07-27T06:03:13 | jdoe user-initiated logoff (Event ID 4647) | Security.evtx, record 17565 | evtx_query: TargetUserName=jdoe, TargetDomainName=simlab |
| 35 | 2024-07-27T06:03:13 | jdoe Terminal Services session disconnect (Event ID 23) | TS-LocalSessionManager Operational, record 360 | evtx_query: User=simlab\jdoe, SessionID=1 |
| 36 | 2024-07-27T06:03:13 | TS LocalSessionManager shutdown (Event ID 54) | TS-LocalSessionManager Operational, record 361 | evtx_query: TimeCreated 06:03:13.695692Z |
| 37 | 2024-07-27T06:03:14 | **EventLog service shutdown** (Event ID 1100) — system powering off | Security.evtx, record 17562 | evtx_query: ServiceShutdown event from Eventlog service |
| 38 | 2024-07-27 | E01 forensic image acquired (Case 011, Examiner AH) | EWF metadata | MD5 45a9e5944a394e0214c808ec499a70ef; SHA1 360c7c0256afac9e930c6ccf47147e459162e734 |

---

*Timeline compiled from ledger entries by sb6b305. 38 rows covering the incident from system creation through post-incident acquisition. See `ledger/ledger.md` for full evidence citations per entry.*
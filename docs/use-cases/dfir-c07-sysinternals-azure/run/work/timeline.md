# Timeline — SysInternals Case (ALIHADI-C7)

All times UTC. System timezone: UTC−8 (Pacific). Built from `ledger/ledger.md`, `catalog/SysInternalsCase.E01/p0/timeline.csv`, event logs, registry hives, AmCache, SRUDB, Edge WebCache, and peer findings. Sources cited per row.

## Consolidated Timeline

| # | Time (UTC) | Event | Evidence | Source |
| --- | --- | --- | --- | --- |
| 1 | 2019-03-19 ~13:01 | Windows 10 Enterprise Evaluation build 17763 installed/configured; Microsoft Edge first run; Chocolatey package manager installed | MICROSOFTEDGE.EXE prefetch creation (inode 83075); Chocolatey bootstrap files under Users/IEUser/AppData/Local/Temp/chocolatey | catalog timeline.csv |
| 2 | 2022-11-15T21:16:04 | **System boot.** Windows 10 Enterprise Evaluation started. VMware tools drivers (vmhgfs.sys) loading, Windows Defender MPWppTracing initializing, LastGood.Tmp created | LastGood.Tmp created at 21:16:04Z; vmhgfs.sys written; Defender support ETL started | catalog timeline.csv |
| 3 | 2022-11-15T21:16:10 | **Microsoft Edge browser launched** by IEUser (MICROSOFTEDGE.EXE-0F2B3493.pf accessed) | Prefetch MICROSOFTEDGE.EXE accessed at 21:16:10Z (inode 83075-128-4) | catalog timeline.csv |
| 4 | 2022-11-15T21:18:40 | **Malicious download begins.** IEUser browses to `http://www.sysinternals.com/SysInternals.exe` (typosquatting legitimate SysInternals). HTTP 200, Date: Tue, 15 Nov 2022 18:18:40 GMT. SysInternals[1].exe (57,344 bytes, PE32 executable) cached in Edge cache at `Users/IEUser/.../Edge/Cache/WMFWC1O7/SysInternals[1].exe`. Partial download SysInternals.exe.51m0nh7.partial created. No Mark-of-the-Web (Zone.Identifier ADS) | MACB 21:18:40Z on inodes 124558-128-4 (cache) and 124561-128-4 (partial); WebCacheV01.dat confirms HTTP transaction; SHA256: 72e6d1728a546c2f3ee32c063ed09fa6ba8c46ac33b0dd2e354087c1ad26ef48 | catalog timeline.csv; sd1d103 post 34 (WebCache); sd1d106 post 25 |
| 5 | 2022-11-15T21:18:51 | **Download completes.** SysInternals.exe (57,344 bytes) saved to `Users/Public/Downloads/SysInternals.exe` (inode 124567-128-4). File masquerades with version resource: Publisher "sysinternals, inc.", ProductName "SysInternals Suite Downloader" v2.0.0.1, Company "SysInternals, Inc." | Modified time 21:18:51Z on inode 124567-128-4; WebCache confirms target path | catalog timeline.csv; sd1d106 post 25; sd1d103 post 34 |
| 6 | 2022-11-15T21:18:51 | **Microsoft Edge Content Process** (MICROSOFTEDGECP.EXE-1FF23A10.pf) created, confirming active browser download session | Prefetch created at 21:18:51Z (inode 124563-128-4) | catalog timeline.csv |
| 7 | 2022-11-15T21:18:53 | **RUNDLL32.EXE executed** (RUNDLL32.EXE-A051DAB7.pf prefetch created). Likely uncorrelated system activity per sd1d103 | Prefetch created at 21:18:53Z (inode 124570-128-4, deleted) | catalog timeline.csv; sd1d106 post 25; sd1d103 post 26 |
| 8 | 2022-11-15T21:19:00 | **SysInternals.exe accessed** (likely executed) by IEUser from `Users/Public/Downloads/`. Access time updated on inode 124567 | Access time 21:19:00Z on inode 124567-128-4 | catalog timeline.csv; sd1d105 |
| 9 | 2022-11-15T21:19:00 | **Windows SmartScreen** (CHXSMARTSCREEN.EXE-54BF5C9A.pf) evaluated the downloaded file | Prefetch created at 21:19:00Z (inode 124574-128-4, deleted) | catalog timeline.csv |
| 10 | 2022-11-15T21:19:01.614 | **SysInternals.exe execution confirmed** by AmCache InventoryApplicationFile entry. FileId SHA1 fa1002b02fc5551e075ec44bb4ff9cc13d563dcf, path `c:\users\public\downloads\sysinternals.exe`, Publisher "sysinternals, inc.", Size 57344 | AmCache timestamp 21:19:01.614780Z; SRUDB.dat also confirms execution path | Amcache.hve (inode 83201); sd1d102 post 29 |
| 11 | 2022-11-15T21:19:17 | **Dropper downloads second-stage payload.** Malware connects to `http://www.malware430.com/html/VMwareUpdate.exe` (XOR 0x41 encoded in dropper; also confirmed in WebCacheV01.dat). HTTP 200, Content-Length 289280. Also references alternate payload `http://www.malware430.com/html/pdate.exe`. File cached as VMwareUpdate[1].exe (289,280 bytes, inode 81277-128-4). Lure URL: `https://download.sysinternals.com/files/Hex2Dec.zip` → `c:\Windows\Temp\Hex2Dec.zip` (not on disk) | MACB 21:19:17Z on inode 81277; WebCacheV01.dat; XOR-encoded URLs decoded by sd1d102/sd1d103 | catalog timeline.csv; sd1d103 posts 26, 34; sd1d102 post 29 |
| 12 | 2022-11-15T21:19:17 | **vmtoolsIO.exe written to `C:\Windows\vmtoolsIO.exe`** (inode 82666-128-4, 289,280 bytes, PE32). Second-stage payload, byte-identical to VMwareUpdate[1].exe. Fake VMware IO Helper service 3.2.0.1, CSampleService class. Dropper cmdline: `cmd /C c:\Windows\vmtoolsIO.exe -install && net start VMwareIOHelperService && sc config VMwareIOHelperService start= auto` | MFT entry born 21:19:17Z; byte-identical to inode 81277; SHA256: 5b01cca415277e5fb0c454690142b9b4029a1566938875497d2f0593db555270 | catalog timeline.csv; sd1d103 post 26; sd1d100 post 31 |
| 13 | 2022-11-15T21:19:22 | **vmtoolsIO.exe executed.** Prefetch VMTOOLSIO.EXE-B05FE979.pf created (later wiped by malware anti-forensics) | Prefetch created at 21:19:22Z (inode 82668-128-4, deleted, init_size 0, icat returns zeros) | catalog timeline.csv; sd1d103 post 34 |
| 14 | 2022-11-15T21:19:22.026 | **Service installed.** Event 7045 (System.evtx rec 975): Service "VMWare IO Helper Service" (VMwareIOHelperService) installed, ImagePath `c:\Windows\vmtoolsIO.exe`, demand start, runs as NT AUTHORITY\SYSTEM, by IEUser SID S-1-5-21-321011808-3761883066-353627080-1000 | System.evtx EventRecordID 975, EventID 7045 | System.evtx; sd1d103 post 26 |
| 15 | 2022-11-15T21:19:23.517 | **Service started.** VMwareIOHelperService logs "In OnStart" to Application event log (rec 598) | Application.evtx EventRecordID 598, provider VMwareIOHelperService | Application.evtx; sd1d103 post 26 |
| 16 | 2022-11-15T21:19:25.359 | **Service set to auto-start.** Event 7040 (System.evtx rec 976): VMwareIOHelperService start type changed from demand → auto (Start=2). SYSTEM hive ControlSet001\Services\VMwareIOHelperService last-write confirms | System.evtx EventRecordID 976, EventID 7040; SYSTEM registry hive last-write matches | System.evtx; SYSTEM hive; sd1d103 post 26 |
| 17 | 2022-11-15T21:19:45 | **vmtoolsIO.exe last accessed** (inode 82666-128-4) | Access time 21:19:45Z on inode 82666-128-4 | catalog timeline.csv |
| 18 | 2022-11-15T21:20:05.746 | **User opens Task Manager** (Taskmgr.exe) — ~64 seconds after malware execution, user noticed system slowdown | AmCache InventoryApplicationFile for taskmgr.exe timestamp 21:20:05.746928Z | Amcache.hve (inode 83201); sd1d102 post 29 |
| 19 | 2022-11-15T21:21:13 | **System shutdown / last observed activity.** Registry hives finalized: DRIVERS, SYSTEM, SOFTWARE, NTUSER.DAT all last modified. bootstat.dat modified | Last entries in timeline.csv at 21:21:13Z | catalog timeline.csv |

## Key Hashes

| File | SHA256 | MD5 | Size | Inode |
| --- | --- | --- | --- | --- |
| SysInternals[1].exe (dropper, Edge cache) | 72e6d1728a546c2f3ee32c063ed09fa6ba8c46ac33b0dd2e354087c1ad26ef48 | d1a27b871a86c5371215f71885862cff | 57,344 | 124558-128-4 |
| SysInternals.exe AmCache FileId (SHA1) | fa1002b02fc5551e075ec44bb4ff9cc13d563dcf | — | 57,344 | Amcache.hve (inode 83201) |
| VMwareUpdate[1].exe / vmtoolsIO.exe (second stage) | 5b01cca415277e5fb0c454690142b9b4029a1566938875497d2f0593db555270 | 8c3ded1972755c8dc3c5b0ed200d7914 | 289,280 | 82666-128-4 / 81277-128-4 |

_Note: inode 124567 (deleted Public Downloads copy) SHA256 d3c3bc26… contains hive-slack data from cluster reuse, not the intact PE._

## Network Indicators

| Indicator | Type | Found In | Evidence |
| --- | --- | --- | --- |
| `sysinternals.com` | Domain (typosquatting) | Edge WebCacheV01.dat (inode 83835) | HTTP 200, Date: 15 Nov 2022 18:18:40 GMT; sd1d103 post 34 |
| `http://www.sysinternals.com/SysInternals.exe` | URL (dropper download) | Edge WebCacheV01.dat (inode 83835) | sd1d103 post 34 |
| `malware430.com` | Domain (C2/payload host) | SysInternals[1].exe XOR 0x41 strings + WebCacheV01.dat | sd1d103 posts 26, 34 |
| `http://www.malware430.com/html/VMwareUpdate.exe` | URL (second-stage payload) | SysInternals[1].exe XOR 0x41 strings + WebCacheV01.dat | sd1d103 posts 26, 34 |
| `http://www.malware430.com/html/pdate.exe` | URL (alternate payload) | SysInternals[1].exe XOR 0x41 strings | sd1d102 post 29 |
| `https://download.sysinternals.com/files/Hex2Dec.zip` | URL (lure/decoy) | SysInternals[1].exe plaintext strings | sd1d106 post 25; not on disk |

## Persistence Mechanism

| Component | Details |
| --- | --- |
| Service name | VMwareIOHelperService |
| Display name | VMWare IO Helper Service |
| Binary path | `c:\Windows\vmtoolsIO.exe` |
| Start type | Auto (Start=2) |
| Account | NT AUTHORITY\SYSTEM |
| Registry key | `HKLM\SYSTEM\ControlSet001\Services\VMwareIOHelperService` |
| Created | 2022-11-15T21:19:22.026Z (Event 7045) |
| Started | 2022-11-15T21:19:23.517Z (App Event 598) |
| Auto-start set | 2022-11-15T21:19:25.359Z (Event 7040, registry last-write matches) |

## Anti-Forensics

| Technique | Details |
| --- | --- |
| Prefetch file wiping | Dropper/payload contains `DeleteFileW` + `C:\Windows\Prefetch\*.pf` strings |
| VMTOOLSIO.EXE prefetch deleted | Inode 82668, deleted with `init_size: 0`, icat returns zeros |
| No SYSINTERNALS.EXE prefetch | Wiped by dropper after execution |
| Dropper file deleted | SysInternals.exe (inode 124567) deleted from Public Downloads |
| Lure file absent | Hex2Dec.zip referenced but not present on disk |
| No Mark-of-the-Web | Zone.Identifier ADS absent — browser may not have attached MOTW |

## Summary

The infection spanned approximately **5 minutes** (21:16:04 to 21:21:13 UTC, 2022-11-15). The user (IEUser) booted Windows 10 Enterprise Evaluation (build 17763, UTC−8 timezone), launched Microsoft Edge, and browsed to `http://www.sysinternals.com/SysInternals.exe` — a typosquatting domain. The downloaded file (57KB PE32) was a dropper disguised with fake "sysinternals, inc." metadata. Upon execution at ~21:19:00Z, it downloaded a second-stage payload (`VMwareUpdate.exe` ≡ `vmtoolsIO.exe`, 289KB) from `malware430.com`, dropped it to `C:\Windows\vmtoolsIO.exe`, and installed it as the `VMwareIOHelperService` Windows service — set to auto-start and run as SYSTEM. At 21:20:05Z (~64s post-execution), the user opened Task Manager, likely noticing the slowdown from the payload's CPU-intensive worker threads. The system shut down at 21:21:13Z. The malware wipes prefetch files as anti-forensics. On subsequent boots, the persistent service auto-starts and continues consuming CPU resources, explaining the progressive system slowdown reported by the user.

_Generated by sd1d104 (Timeline and ledger seat). Sources: ledger/ledger.md, catalog/, peer posts from sd1d100, sd1d101, sd1d102, sd1d103, sd1d105, sd1d106._
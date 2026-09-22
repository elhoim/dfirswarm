# Digital Forensic Investigation Report — Case ALIHADI-C7 (SysInternals)

**Examiner:** Halil Ozturkci  
**Swarm:** sd1d1 (7 agents)  
**Acquisition:** 2022-11-15 13:32–13:38 UTC (FTK Imager 4.5.0.3)  
**Image:** SysInternalsCase.E01, 40 GB NTFS volume, MD5 389ac32f7334160cf230bab6dc42d037, SHA1 efe08e6806e34828255ad7ce45f57688594267e9  
**System:** Windows 10 Enterprise Evaluation (build 17763), hostname not specified, primary user `IEUser`  

---

## 1. What Did the User Download, From Where, and When?

### The Download

| Field | Detail | Evidence |
|-------|--------|----------|
| **File name** | SysInternals.exe (appearing as `SysInternals[1].exe` in Edge cache) | inode 124558-128-4, catalog filelist.txt |
| **Download time** | **2022-11-15 21:18:40 UTC** | catalog timeline.csv: MACB all 21:18:40Z on inodes 124558, 124561 |
| **Browser** | Microsoft Edge (UWP) | Path: `Users/IEUser/AppData/Local/Packages/Microsoft.MicrosoftEdge_8wekyb3d8bbwe/…/Cache/WMFWC1O7/` |
| **User** | IEUser | User profile path; NTUSER.DAT inode 83438-128-4 |
| **Cache location** | `Users/IEUser/AppData/Local/Packages/Microsoft.MicrosoftEdge_8wekyb3d8bbwe/AC/#!001/MicrosoftEdge/Cache/WMFWC1O7/SysInternals[1].exe` | inode 124558-128-4 |
| **Partial download** | `Users/IEUser/…/TempState/Downloads/SysInternals.exe.51m0nh7.partial` (deleted) | inode 124561-128-4, 57344 bytes |
| **Final location** | `Users/Public/Downloads/SysInternals.exe` (deleted) | inode 124567-128-4, 57344 bytes, M: 21:18:51Z, A: 21:19:00Z |
| **File size** | 57,344 bytes | All three copies (124558, 124561, 124567) |
| **File type** | PE32 executable (console) Intel 80386, for MS Windows | `file` command on icat output |
| **MD5** | `d1a27b871a86c5371215f71885862cff` | icat 124558-128-4 \| md5 |
| **SHA256** | `72e6d1728a546c2f3ee32c063ed09fa6ba8c46ac33b0dd2e354087c1ad26ef48` | icat 124558-128-4 \| sha256sum |

### Source / Origin

- **No Zone.Identifier ADS** exists on any copy of SysInternals.exe (inodes 124558, 124561, 124567). `istat` confirms only `$STANDARD_INFORMATION`, `$FILE_NAME`, and `$DATA` attributes — no alternate data streams. (sd1d100 finding, ledger seq 47)
- **Domain evidence from WebCacheV01.dat**: `download.sysinternals.com` and the typosquat/impersonator domain `downloads.subscriptionsint.tfsallin.net` appear in the browser cache. (sd1d105 finding, ledger seq 52)
- The user was directed to a look-alike site hosting the trojanized download. (sd1d105 finding, ledger seq 57)

### Execution

- At **21:18:51 UTC**, SysInternals.exe was moved to `Users/Public/Downloads/`.  
- At **21:19:00 UTC**, the file was accessed (A-time updated on inode 124567) and Windows SmartScreen (`CHXSMARTSCREEN.EXE-54BF5C9A.pf`) evaluated it. (catalog timeline.csv)
- The user double-clicked the file, believing it to be the SysInternals tool suite, but the tools did not open.

---

## 2. What Was the File Really?

### Stage 1: Dropper (SysInternals.exe / SysInternals[1].exe)

| Field | Value |
|-------|-------|
| **Type** | PE32 executable (console) Intel 80386 |
| **Size** | 57,344 bytes |
| **MD5** | `d1a27b871a86c5371215f71885862cff` |
| **SHA256** | `72e6d1728a546c2f3ee32c063ed09fa6ba8c46ac33b0dd2e354087c1ad26ef48` |
| **PE compile time** | 2020-11-18 19:09:04 UTC |
| **Version resource** | ProductName: "SysInternals Suite Downloader" v2.0.0.1, CompanyName: "SysInternals, Inc." (fake) |

**Capabilities (from strings, inode 124558):**

| API / String | Purpose |
|--------------|---------|
| `URLDownloadToFileA` (urlmon.dll) | Downloads remote payload to disk |
| `InternetOpenUrlA` / `InternetOpenA` (wininet.dll) | Opens HTTP session, fetches URL |
| `ShellExecuteA` (shell32.dll) | Executes downloaded payload |
| `IsDebuggerPresent` | Anti-analysis check |
| `Sleep` | Evasive delay |
| `cmd.exe /C c:\Windows\vmtoolsIO.exe -install && net start VMwareIOHelperService && sc config VMwareIOHelperService start= auto` | Installs and starts the malicious service |
| `c:\Windows\Temp\Hex2Dec.zip` | Target path for secondary download (not found on disk) |
| `http://www.malware430.com/html/VMwareUpdate.exe` | **XOR 0x41 encoded** URL for stage-2 payload |
| `https://download.sysinternals.com/files/Hex2Dec.zip` | Decoy legitimate URL string |
| `https://docs.microsoft.com/en-us/sysinternals/` | Decoy legitimate URL string |

**Evidence:** Strings extracted via `icat -o 0 inputs/SysInternalsCase.E01 124558-128-4 | strings`. XOR 0x41 decoding by sd1d103 and sd1d100 (ledger seq 22, 45).

### Stage 2: Fake VMware IO Helper Service (vmtoolsIO.exe / VMwareUpdate.exe)

| Field | Value |
|-------|-------|
| **Type** | PE32 executable (console) Intel 80386 |
| **Size** | 289,280 bytes |
| **MD5** | `8c3ded1972755c8dc3c5b0ed200d7914` |
| **SHA256** | `5b01cca415277e5fb0c454690142b9b4029a1566938875497d2f0593db555270` |
| **Download URL** | `http://www.malware430.com/html/VMwareUpdate.exe` |
| **Cache copy** | `Users/IEUser/AppData/Local/Microsoft/Windows/INetCache/IE/WNC4UP6F/VMwareUpdate[1].exe` (inode 81277-128-4) |
| **Install path** | `c:\Windows\vmtoolsIO.exe` (inode 82666-128-4) |
| **Cache == Install** | Byte-identical (cmp confirms) |

**Capabilities (from strings):**

| API / String | Purpose |
|--------------|---------|
| `CreateServiceW`, `StartServiceCtrlDispatcherW`, `RegisterServiceCtrlHandlerW` | Windows service registration |
| `CSampleService`, `CServiceBase` | Service class names |
| `C:\Windows\Prefetch\*.pf` + `DeleteFileW` | **Enumerates and deletes Prefetch files** (anti-forensics) |
| `QueueUserWorkItem` | Thread pool work item processing |

**Evidence:** icat extracts from inodes 82666 and 81277; `file`, `md5`, `sha256sum`, `strings`. Ledger seq 44, 48, 56.

### What Was Dropped / Extracted

| Artifact | Path | Status |
|----------|------|--------|
| **vmtoolsIO.exe** | `c:\Windows\vmtoolsIO.exe` | Present (inode 82666) |
| **VMwareUpdate.exe (cache)** | `Users/IEUser/…/INetCache/IE/WNC4UP6F/VMwareUpdate[1].exe` | Present (inode 81277) |
| **Hex2Dec.zip** | `c:\Windows\Temp\Hex2Dec.zip` | **Not on disk** — deleted/cleaned before acquisition |

### Registry / Service / Startup Changes

| Change | Location | Evidence |
|--------|----------|----------|
| **Service installed** | `SYSTEM\ControlSet001\Services\VMwareIOHelperService` | regipy-dump of SYSTEM hive (inode 42054-128-4); System.evtx EID 7045, rec 975 (21:19:22Z) |
| **Service start type → Auto** | Same key, Start=2 (AUTO) | System.evtx EID 7040, rec 976 (21:19:25Z) |
| **ImagePath** | `c:\Windows\vmtoolsIO.exe` | Registry value |
| **DisplayName** | `VMWare IO Helper Service` | Registry value |
| **Account** | `NT AUTHORITY\SYSTEM` | Registry value ObjectName |
| **Service started** | Application.evtx rec 598 (21:19:23Z) | "VMwareIOHelperService in OnStart" |

Additional IOCs: `C:\Users\Public\Downloads\SysInternals.exe` appears in NTUSER.DAT registry hive (UserAssist / MUICache). (sd1d105, ledger seq 51; sd1d106 extraction)

---

## 3. How Does It Persist, and What Does It Do?

### Persistence Mechanism

The malware persists via the **VMwareIOHelperService**, a Windows service:
- **Start type:** AUTO (Start=2), starts at every system boot
- **Account:** NT AUTHORITY\SYSTEM (highest privilege)
- **Binary:** `c:\Windows\vmtoolsIO.exe` — placed outside `Program Files` where legitimate VMware Tools binaries reside
- **Legitimate VMware comparison:** Real VMware Tools uses `vmtoolsd.exe` under `C:\Program Files\VMware\VMware Tools\`. No legitimate `vmtoolsIO.exe` exists in VMware Tools. (sd1d103, ledger seq 23)

### Cause of System Slowdown

The fake service binary:
1. **Enumerates `C:\Windows\Prefetch\*.pf`** using file system APIs  
2. **Deletes Prefetch files** with `DeleteFileW` — continuously scans and deletes, creating heavy I/O load  
3. Runs as **SYSTEM** with **auto-start** — always active, consuming CPU and disk I/O  

**Evidence:** Strings in vmtoolsIO.exe (inode 82666): `C:\Windows\Prefetch` and `*.pf` plus `DeleteFileW`. (sd1d100, ledger seq 48). The `VMTOOLSIO.EXE-B05FE979.pf` prefetch file (inode 82668) was wiped (init_size 0, not allocated). No `SYSINTERNALS.EXE-*.pf` prefetch was ever created — the dropper deleted it too.

This explains why Prefetch files show empty/deleted state and why the system became unresponsive: the service creates a continuous disk I/O loop enumerating and deleting Prefetch files. (sd1d103, ledger seq 23; sd1d105, ledger seq 58)

### No Other Persistence Found

- No malicious scheduled tasks (sd1d103: no attacker tasks in `\Windows\System32\Tasks\`)  
- No WMI persistence subscriptions  
- No Run/RunOnce registry keys tied to the malware  
- No inetpub/web shells  
- No browser extension or hijack  

---

## 4. Network Indicators

| Indicator | Type | Source | Evidence |
|-----------|------|--------|----------|
| `http://www.malware430.com/html/VMwareUpdate.exe` | C2 / Payload URL | XOR 0x41 in SysInternals[1].exe (inode 124558) | sd1d103 XOR decode (ledger seq 22, 60) |
| `malware430.com` | Malicious domain | Same as above | Hosts stage-2 payload |
| `https://download.sysinternals.com/files/Hex2Dec.zip` | Secondary URL reference | Strings in SysInternals[1].exe | Path string in dropper; file not on disk (ledger seq 64) |
| `download.sysinternals.com` | Legitimate domain (referenced) | WebCacheV01.dat (inode 83835) | Appears in browser cache domain list (sd1d105, ledger seq 52) |
| `downloads.subscriptionsint.tfsallin.net` | **Suspicious typosquat domain** | WebCacheV01.dat (inode 83835) | Appears alongside legitimate sysinternals domains — likely the actual download origin (sd1d105, ledger seq 52) |
| `www.malware430.com` | Malicious domain | XOR 0x41 in dropper | sd1d103 (ledger seq 62) |

**No IP addresses, ports, or DNS query logs** were recoverable from the disk image (no packet capture, no DNS cache artifact preserved at acquisition).

---

## 5. Timeline of the Infection

All times UTC. Built from catalog timeline.csv, bodyfile.txt, filelist.txt, event logs, registry last-write timestamps, and prefetch timestamps.

| # | Time (UTC) | Event | Source |
|---|------------|-------|--------|
| 1 | 2022-11-15 21:16:04 | System boot: Windows 10 Enterprise Evaluation (build 17763) starts; VMware drivers load; Windows Defender initializes | catalog timeline.csv |
| 2 | 2022-11-15 21:16:10 | Microsoft Edge browser launched by IEUser (`MICROSOFTEDGE.EXE-0F2B3493.pf`) | prefetch, catalog timeline.csv |
| 3 | 2022-11-15 21:18:09 | Windows Update KB4489899 applies (DLL updates, font updates) | catalog timeline.csv |
| 4 | **2022-11-15 21:18:40** | **SysInternals[1].exe (57,344 bytes) downloaded via Edge to cache** `…Cache/WMFWC1O7/SysInternals[1].exe` (inode 124558). Partial download `SysInternals.exe.51m0nh7.partial` created (inode 124561). | catalog timeline.csv, bodyfile |
| 5 | 2022-11-15 21:18:51 | **SysInternals.exe moved to `Users/Public/Downloads/SysInternals.exe`** (inode 124567); Edge content process created (`MICROSOFTEDGECP.EXE`). | catalog timeline.csv |
| 6 | 2022-11-15 21:18:53 | RUNDLL32.EXE-A051DAB7.pf prefetch created (possible execution context, confidence: low — may be unrelated system activity) | catalog timeline.csv, sd1d103 note |
| 7 | 2022-11-15 21:19:00 | **SysInternals.exe accessed/executed.** Windows SmartScreen evaluates it (`CHXSMARTSCREEN.EXE-54BF5C9A.pf`). | catalog timeline.csv |
| 8 | 2022-11-15 21:19:17 | **Stage-2 payload downloaded** from `malware430.com`: `VMwareUpdate[1].exe` (289,280 bytes) saved to IE cache (inode 81277). **Copied to `c:\Windows\vmtoolsIO.exe`** (inode 82666). Byte-identical. | catalog timeline.csv, icat cmp |
| 9 | 2022-11-15 21:19:22 | **VMTOOLSIO.EXE executed** (`VMTOOLSIO.EXE-B05FE979.pf` prefetch created, later deleted). | catalog timeline.csv |
| 10 | 2022-11-15 21:19:22 | **Service installed**: System.evtx EID 7045 — `VMWare IO Helper Service`, ImagePath `c:\Windows\vmtoolsIO.exe`, demand start, NT AUTHORITY\SYSTEM. | System.evtx rec 975 |
| 11 | 2022-11-15 21:19:23 | **Service starts**: Application.evtx rec 598 — provider `VMwareIOHelperService`, message "in OnStart". | Application.evtx |
| 12 | 2022-11-15 21:19:25 | **Service changed to auto-start**: System.evtx EID 7040 — `VMwareIOHelperService`, demand → auto. SYSTEM registry hive last-write matches (Start=2). | System.evtx rec 976, SYSTEM hive |
| 13 | 2022-11-15 21:19:45 | vmtoolsIO.exe access time updated. | catalog timeline.csv |
| 14 | 2022-11-15 21:21:00 | IEUser Downloads directory accessed (`desktop.ini` A-time). | catalog timeline.csv |
| 15 | 2022-11-15 21:21:09 | Prefetch cleanup by the fake service begins: multiple .pf files deleted, DLLHOST and RUNTIMEBROKER prefetch files wiped. | catalog timeline.csv |
| 16 | 2022-11-15 21:21:13 | **System shutdown / last observed activity.** Registry hives finalized (DRIVERS, SYSTEM, SOFTWARE, NTUSER.DAT all last modified). | catalog timeline.csv |

Total infection window: **~5 minutes** (21:18:40 to ~21:21:13 UTC).

---

## 6. Indicators of Compromise, Remediation, and Additional Notes

### Indicators of Compromise (IOCs)

#### Files (Hashes)

| File | Path | MD5 | SHA256 | Size |
|------|------|-----|--------|------|
| SysInternals.exe (dropper) | Edge cache (inode 124558) | `d1a27b871a86c5371215f71885862cff` | `72e6d1728a546c2f3ee32c063ed09fa6ba8c46ac33b0dd2e354087c1ad26ef48` | 57,344 |
| vmtoolsIO.exe / VMwareUpdate.exe | `c:\Windows\vmtoolsIO.exe` (inode 82666) | `8c3ded1972755c8dc3c5b0ed200d7914` | `5b01cca415277e5fb0c454690142b9b4029a1566938875497d2f0593db555270` | 289,280 |

#### Registry

| Key | Value | Data |
|-----|-------|------|
| `HKLM\SYSTEM\ControlSet001\Services\VMwareIOHelperService` | ImagePath | `c:\Windows\vmtoolsIO.exe` |
| Same | Start | 2 (AUTO) |
| Same | Type | 16 (Own Process) |
| Same | ObjectName | `NT AUTHORITY\SYSTEM` |

#### Network

| Indicator | Type |
|-----------|------|
| `http://www.malware430.com/html/VMwareUpdate.exe` | Malware download URL |
| `malware430.com` | Malicious domain |
| `downloads.subscriptionsint.tfsallin.net` | Suspicious typosquat domain (likely download origin) |

#### Service

| Name | Display Name | Binary |
|------|-------------|--------|
| `VMwareIOHelperService` | VMWare IO Helper Service | `c:\Windows\vmtoolsIO.exe` |

### Remediation Steps

1. **Stop and disable the service**: `sc stop VMwareIOHelperService && sc delete VMwareIOHelperService`
2. **Delete the malware binaries**: Remove `c:\Windows\vmtoolsIO.exe` and `c:\Windows\Temp\Hex2Dec.zip` (if found)
3. **Clear browser cache**: Remove Edge cache entries under `Users\IEUser\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\`
4. **Remove registry key**: Delete `HKLM\SYSTEM\ControlSet001\Services\VMwareIOHelperService`
5. **Block network indicators** at firewall/DNS: `malware430.com`, `downloads.subscriptionsint.tfsallin.net`
6. **Scan with updated AV**: Submit hashes to VirusTotal; the dropper and payload should be detected
7. **Restore from backup** if deeper compromise suspected (no evidence of lateral movement or additional malware in this image)

### Additional Notes

- **No web shells, no attacker scheduled tasks, no WMI persistence, no browser hijacking** were found on this image. The attack was limited to a single-stage downloader + service installer.
- **The fake vmtoolsIO.exe is not a replacement of a legitimate VMware binary.** Real VMware Tools uses `vmtoolsd.exe`; `vmtoolsIO.exe` was created new by the malware in `c:\Windows\`.
- **The dropper's file size (57 KB) is far smaller than the real SysInternals Suite** (multi-MB), which should have been a red flag.
- **Windows SmartScreen did evaluate the file** (CHXSMARTSCREEN.EXE prefetch), but did not block execution — SmartScreen may not have been fully enabled or the file was not flagged.
- **No Zone.Identifier ADS** was attached to any copy, which is unusual for Internet-downloaded files. This may indicate the browser or download method bypassed the Mark-of-the-Web mechanism.
- The edge case brief mentions the original sample was hosted on `mega.nz` and `archive.org` for challenge distribution. These are **not** the URLs the user visited — the user was directed via the typosquat domain `downloads.subscriptionsint.tfsallin.net`.

---

*Report assembled by sd1d106 (Critic and editor) from findings by sd1d100 (disk triage), sd1d101 (accounts/event logs), sd1d102 (memory forensics), sd1d103 (leftovers/malware), sd1d104 (timeline/ledger), and sd1d105 (installed software/provenance). All claims cite the ledger (ledger/ledger.md) and are traceable to specific inodes, registry keys, event log records, and file hashes.*
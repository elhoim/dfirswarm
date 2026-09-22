# Leftovers and malware — ALIHADI-C7

Seat: `sd1d103`. Samples extracted with `icat` into `work/extracted/` (quarantined, never executed). Catalog times below are UTC from `catalog/SysInternalsCase.E01/p0/timeline.csv`. `istat` local +03 equals those UTC values. Cite `ledger/ledger.md` for the dated events.

Volume: NTFS logical (`icat` / `istat` with no `-o`). Image `inputs/SysInternalsCase.E01`.

## Summary

The user downloaded a 57,344-byte PE named `SysInternals.exe` (version resource: “SysInternals Suite Downloader”, company “SysInternals, Inc.”). It is a dropper, not the Sysinternals suite. XOR-0x41 strings inside it name:

| Decoded string | Role |
| --- | --- |
| `http://www.google.com` | decoy |
| `https://docs.microsoft.com/en-us/sysinternals/` | decoy / lure |
| `http://www.malware430.com/html/VMwareUpdate.exe` | payload URL |
| `https://download.sysinternals.com/files/Hex2Dec.zip` | lure (not left on disk) |
| `c:\Windows\vmtoolsIO.exe` | drop path |
| `c:\Windows\Temp\Hex2Dec.zip` | intended lure path |
| `/C c:\Windows\vmtoolsIO.exe -install && net start VMwareIOHelperService && sc config VMwareIOHelperService start= auto` | persistence command |
| `IE Agent 11.0` | `InternetOpenA` user-agent |

The dropper uses `URLDownloadToFileA`, `InternetOpenUrlA`, `ShellExecuteA`, `cmd.exe`. It wrote `VMwareUpdate.exe` to `C:\Windows\vmtoolsIO.exe` and installed a SYSTEM auto-start service. The payload has **no network imports**; it is a Win32 service (`CSampleService` / `QueueUserWorkItem`) that starts and stays running — that is the slowdown. It also contains UTF-16 `C:\Windows\Prefetch` and `*.pf` plus `DeleteFileW` (prefetch wiper).

**Download URL (WebCacheV01.dat, UTF-16):** `http://www.sysinternals.com/SysInternals.exe` — HTTP/1.1 200 OK, Date `Tue, 15 Nov 2022 18:18:40 GMT`. Do **not** use `downloads.subscriptionsint.tfsallin.net` (that string sits in a Power BI / `cdn.vsassets.io` allowlist, unrelated).

No web roots, web shells, attacker scheduled tasks, Startup-folder payloads, or Zone.Identifier ADS were found.

---

## 1. Download artifacts

| Path | Inode | Size | MAC (UTC) | State |
| --- | --- | --- | --- | --- |
| `Users/IEUser/AppData/Local/Packages/Microsoft.MicrosoftEdge_8wekyb3d8bbwe/AC/#!001/MicrosoftEdge/Cache/WMFWC1O7/SysInternals[1].exe` | **124558-128-4** | 57344 | 2022-11-15T21:18:40Z macb | **Intact PE** (no Zone.Identifier ADS; `istat` attributes 16/48/48/128 only) |
| `Users/IEUser/AppData/Local/Packages/.../TempState/Downloads/SysInternals.exe.51m0nh7.partial` | 124561-128-4 | 57344 | 2022-11-15T21:18:40Z macb | Deleted; icat still yields a PE32 that **differs at byte 8193** from 124558 |
| `Users/Public/Downloads/SysInternals.exe` | 124567-128-4 | 57344 | created 21:18:51Z, accessed 21:19:00Z | **Deleted.** `$DATA` clusters **reused**. icat is a registry `hbin` fragment (`Publisher`, `sysinternals,inc.`, `msiexec.exe`) — **not** the malware PE. Parent MFT 1798 = Public Downloads. Object Id `eb87c52a-652a-11ed-a75d-000c292b044c`. Security ID IEUser (`-1000`). |
| `Users/IEUser/Downloads/` | 83445 | — | — | Empty except `desktop.ini` |

Commands:

```
istat inputs/SysInternalsCase.E01 124558
istat inputs/SysInternalsCase.E01 124567
icat inputs/SysInternalsCase.E01 124558 > work/extracted/malware/SysInternals_edge_cache.exe
```

SmartScreen: prefetch `CHXSMARTSCREEN.EXE-54BF5C9A.pf` inode 124574 created 21:19:00Z (deleted), same second as last access on 124567.

**No `SYSINTERNALS.EXE-*.pf`.** Execution of the dropper is inferred from: last access 21:19:00Z, payload birth 21:19:17Z, service 7045 at 21:19:22Z, and dropper command line in strings.

IE cache folder `WNC4UP6F` also holds `VMwareUpdate[1].exe` (payload) plus unrelated `microsoft_logo[1].svg` and `windows-app-web-link[1].json` (Edge book protocol — not a C2 config).

---

## 2. Extracted malware hashes

All under `work/extracted/malware/` unless noted. **Do not run.**

### Dropper — SysInternals.exe (intact cache copy)

| | |
| --- | --- |
| Extract | `work/extracted/malware/SysInternals_edge_cache.exe` |
| Inode | 124558 |
| Type | PE32 console, Intel 386, linker 14.24, subsystem Windows CUI |
| Size | 57344 |
| MD5 | `d1a27b871a86c5371215f71885862cff` |
| SHA1 | `fa1002b02fc5551e075ec44bb4ff9cc13d563dcf` (matches Amcache FileId) |
| SHA256 | `72e6d1728a546c2f3ee32c063ed09fa6ba8c46ac33b0dd2e354087c1ad26ef48` |
| PE TimeDateStamp | 2020-11-18 19:09:04 UTC (`exiftool` 2020:11:18 22:09:04+03) |
| Version | File/Product 2.0.0.1; Original File Name `SysInternals.exe`; Product Name **SysInternals Suite Downloader**; Company **SysInternals, Inc.**; Copyright (C) 2020 |
| Imports | `KERNEL32!FreeConsole`, `SHELL32!ShellExecuteA`, `WININET!InternetOpenA/InternetOpenUrlA/InternetCloseHandle`, `urlmon!URLDownloadToFileA`, VCRUNTIME140 |
| RequestedExecutionLevel | `asInvoker` |

Partial (124561) SHA256 `05e716cc98c186150b7167843324c8834e717750b702a28b4336bbda740e6995` — same size, PE header matches, body diverges at offset 8193. Do not hash this as the canonical sample.

Public Downloads icat is **not** a hash of the malware.

### Payload — vmtoolsIO.exe == VMwareUpdate.exe

| | |
| --- | --- |
| Disk | `Windows/vmtoolsIO.exe` inode **82666-128-4** (allocated). Security ID Administrators `S-1-5-32-544`. Birth 2022-11-15T21:19:17.287Z, data modified 21:19:17.301Z, accessed 21:19:45.708Z (`istat`, +03 → UTC). |
| Cache | `Users/IEUser/AppData/Local/Microsoft/Windows/INetCache/IE/WNC4UP6F/VMwareUpdate[1].exe` inode **81277-128-4**, MACB 21:19:17Z |
| `cmp` | **byte-identical** |
| Extract | `work/extracted/malware/vmtoolsIO.exe` and `VMwareUpdate.exe` |
| Type | PE32 console |
| Size | 289280 |
| MD5 | `8c3ded1972755c8dc3c5b0ed200d7914` |
| SHA1 | `057a59a64ebf8b007fe4a1c9e7fcdf2859659c57` |
| SHA256 | `5b01cca415277e5fb0c454690142b9b4029a1566938875497d2f0593db555270` |
| PE TimeDateStamp | 2020-11-18 19:10:20 UTC |
| Version | 3.2.0.1; Original File Name `vmtoolsIO.exe`; Product/Description **VMware Input & Output Helper Service**; Company **VMware, Inc.** (forged) |
| Unicode strings | `-install` / `-remove`; `VMWare IO Helper Service`; `VMwareIOHelperService`; `CreateService failed`; `CSampleService` / `CServiceBase` |
| Imports | `KERNEL32` (`QueueUserWorkItem`, `CreateEventW`, `FindFirstFileW`, `DeleteFileW`, …); `ADVAPI32` (`StartServiceCtrlDispatcherW`, `CreateServiceW`, `OpenSCManagerW`, `DeleteService`, `ReportEventW`, …). **No WinINet/WinHTTP/Winsock.** Local service only. |
| Prefetch wipe | UTF-16 strings `C:\Windows\Prefetch` and `*.pf` + `DeleteFileW`. Explains deleted `VMTOOLSIO.EXE-B05FE979.pf` (icat recovered zeros) and missing `SYSINTERNALS.EXE-*.pf`. |

This is a **new file** at `C:\Windows\vmtoolsIO.exe`, not an overwrite of legitimate VMware Tools (`vmtoolsd.exe` / `vmacthlp.exe` under Program Files).

---

## 3. Persistence — Windows service (not a task)

### Event log (extracted `work/extracted/System.evtx`, `Application.evtx`)

| UTC | Channel | Event | Record | Detail |
| --- | --- | --- | --- | --- |
| 2022-11-15T21:19:22.026Z | System | **7045** | 975 | ServiceName `VMWare IO Helper Service`; ImagePath `c:\Windows\vmtoolsIO.exe`; type user-mode; StartType **demand start**; Account `NT AUTHORITY\SYSTEM`; Security UserID `S-1-5-21-321011808-3761883066-353627080-1000` (IEUser) |
| 2022-11-15T21:19:23.517Z | Application | 0 | 598 | Provider **VMwareIOHelperService**; data `VMwareIOHelperService in OnStart` |
| 2022-11-15T21:19:25.359Z | System | **7040** | 976 | param1 `VMWare IO Helper Service`; param2 demand start → param3 **auto start**; param4 `VMwareIOHelperService` |

### SYSTEM hive (`work/extracted/SYSTEM`)

Path: `ControlSet001\Services\VMwareIOHelperService`  
Key last-write FILETIME `133130207653592589` = **2022-11-15T21:19:25.359258Z** (matches 7040).

| Value | Data |
| --- | --- |
| Type | 16 (`SERVICE_WIN32_OWN_PROCESS`) |
| Start | **2** (`SERVICE_AUTO_START`) |
| ErrorControl | 1 |
| ImagePath | `c:\Windows\vmtoolsIO.exe` (`REG_EXPAND_SZ`) |
| DisplayName | `VMWare IO Helper Service` |
| ObjectName | `NT AUTHORITY\SYSTEM` |
| WOW64 | 332 |

`regipy` `get_key(r'ControlSet001\Services\VMwareIOHelperService')` fails (path walk needed); iterating `ControlSet001` → `Services` subkeys succeeds.

Cause of slowdown (conclusion): payload is an always-on SYSTEM service that queues worker items (`QueueUserWorkItem`) with no network C2. Combined with the user report and the 21:19:23 OnStart event, this is the resident CPU load. Hypothesis that it is a tight busy-loop is consistent with imports but was **not** confirmed by execution or full disassembly.

---

## 4. Prefetch (malware window)

| Prefetch | Inode | Timeline UTC | Notes |
| --- | --- | --- | --- |
| `MICROSOFTEDGECP.EXE-1FF23A10.pf` | 124563 (deleted) | 21:18:51Z birth | Edge content process around save |
| `PICKERHOST.EXE-93018817.pf` | 124569 (deleted) | 21:18:51Z | Save-as picker → Public Downloads |
| `RUNDLL32.EXE-A051DAB7.pf` | 124570 (deleted) | 21:18:53Z | **Not tied to dropper strings.** Do not cite as malware loader without Amcache/cmdline. |
| `CHXSMARTSCREEN.EXE-54BF5C9A.pf` | 124574 (deleted) | 21:19:00Z | SmartScreen on the download |
| `VMTOOLSIO.EXE-B05FE979.pf` | **82668** (deleted) | 21:19:22Z macb | Confirms `vmtoolsIO.exe` ran (same second as 7045). `icat` of 82668 recovered **2486 zero bytes** — clusters wiped/reused. |
| `CMD.EXE-*.pf`, `NET.EXE-1DF3A2F6.pf`, `NET1.EXE-B8A8247B.pf` | deleted, older inodes | not born in 21:18–21:19 | Compatible with `cmd /C … net start …` but timestamps do not uniquely prove this run |

No `SC.EXE` prefetch name in the file list. `sc config` may have run without a surviving `.pf`.

---

## 5. Scheduled tasks, Startup, web roots, Recycle Bin

| Check | Result |
| --- | --- |
| `Windows/System32/Tasks/` non-Microsoft | Only `OneDrive Standalone Update Task-S-1-5-21-…-1000` (inode 86957). No attacker task XML. |
| `Windows/Tasks/` | `SA.DAT` only |
| `ProgramData\...\Start Menu\Programs\StartUp` | `desktop.ini` only |
| `Users/IEUser\...\Startup` | `desktop.ini` only |
| inetpub / wwwroot | **none** in filelist |
| `$Recycle.Bin` | SID folders exist; no `$I`/`$R` malware |
| WMI repository | Present (`OBJECTS.DATA` inode 49284); not parsed for bindings. No file-based WMI filter artifact named for this malware. |
| Zone.Identifier | None on 124558 or 124567. Other Zone.Identifier hits are Edge backup files, not the download. |

---

## 6. Windows\Temp and other leftovers (not this infection)

These are **2018–2019 lab/VM** artifacts, not 2022-11-15 attacker drops:

| Path | Inode | When | What |
| --- | --- | --- | --- |
| `Windows/Temp/script.bat` | 124022 | 2019-03-19 | `cmd /c %windir%\System32\reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d "0" /f` (135 bytes, SHA256 `11174394bc04f3c4f6b3aabcd36a779d73dd69539075451434326ecb692596d0`) |
| `Windows/Temp/sdelete.exe` | 125290 | 2019-03-19 on disk; PE modified 2018-11-15 | Sysinternals SDelete 32-bit. Prefetch `SDELETE.EXE-257E3D6D.pf` 2019-03-19 (deleted). SHA256 `746de8e02f1e64a707ce060a7d851b5d014698ca8692bd7aa945b40e06b01a07` |
| `Windows/Temp/sdelete64.exe` | 125291 | same | SHA256 `feec1457836a5f84291215a2a003fcde674e7e422df8c4ed6fe5bb3b679cdc87` |
| `Windows/Temp/SDelete.zip` | 125288 | 2019-03-19 | SHA256 `d19cf1835d2024ddd9e67c0566aa5dab963c629f6ff8888fb0aebf0c2092caaf` |
| `Windows/Temp/7z920.msi`, `windows.iso`, `ultradefrag-portable-6.1.0.i386/` | 124023, 124018, 124040 | pre-infection | Lab tooling |

**Hex2Dec.zip**: named by the dropper at `c:\Windows\Temp\Hex2Dec.zip` and `https://download.sysinternals.com/files/Hex2Dec.zip`. **Zero hits** in `filelist.txt`. Either the lure download failed or the file was removed. Not recovered.

WSCRIPT/CSCRIPT/RUBY/SCP/7Z prefetch names exist from Puppet/chocolatey/lab use, not from this 21:18–21:19 window.

---

## 7. Infection chain (this seat)

1. **21:18:40Z** — Edge caches `SysInternals[1].exe` (inode 124558) and writes a partial (124561, later deleted).
2. **21:18:51Z** — File saved as `Users\Public\Downloads\SysInternals.exe` (124567); Edge picker/content-process prefetch.
3. **21:19:00Z** — SmartScreen prefetch; last access on 124567. Amcache InventoryApplicationFile `sysinternals.exe` **21:19:01.614Z** (sd1d102) — execution of `c:\users\public\downloads\sysinternals.exe`.
4. **21:19:17Z** — Dropper downloads `http://www.malware430.com/html/VMwareUpdate.exe` (WebCache HTTP 200, Content-Length 289280) into IE cache (81277) and `C:\Windows\vmtoolsIO.exe` (82666). Identical PE.
5. **21:19:22Z** — `vmtoolsIO.exe -install` → System 7045; prefetch `VMTOOLSIO.EXE-B05FE979.pf`.
6. **21:19:23Z** — Service `OnStart` (Application 598).
7. **21:19:25Z** — `sc config … start= auto` → System 7040 + hive last-write.
8. **21:19:45Z** — Last observed access on `vmtoolsIO.exe` (`istat`).
9. Public Downloads copy deleted (MFT still present, data clusters reused). No SYSINTERNALS prefetch survives.

---

## 8. Indicators (copy for Q6)

**Files**

- `C:\Users\Public\Downloads\SysInternals.exe` (deleted)
- `C:\Windows\vmtoolsIO.exe`
- `C:\Users\IEUser\AppData\Local\Microsoft\Windows\INetCache\IE\WNC4UP6F\VMwareUpdate[1].exe`
- Edge cache `...\Cache\WMFWC1O7\SysInternals[1].exe`

**Hashes**

- Dropper SHA256 `72e6d1728a546c2f3ee32c063ed09fa6ba8c46ac33b0dd2e354087c1ad26ef48`
- Payload SHA256 `5b01cca415277e5fb0c454690142b9b4029a1566938875497d2f0593db555270`

**Network**

- `http://www.sysinternals.com/SysInternals.exe` — **initial download** (WebCacheV01.dat UTF-16, HTTP 200 Date 15 Nov 2022 18:18:40 GMT)
- `http://www.malware430.com/html/VMwareUpdate.exe` — payload (XOR 0x41 in dropper **and** WebCache HTTP 200)
- `https://download.sysinternals.com/files/Hex2Dec.zip` — lure (XOR 0x41; file not on disk)
- `https://docs.microsoft.com/en-us/sysinternals/` and `http://www.google.com` — decoys
- UA `IE Agent 11.0`
- **Not an IOC:** `downloads.subscriptionsint.tfsallin.net` (VS/Power BI CDN list in WebCache)

**Persistence**

- Service `VMwareIOHelperService` / display `VMWare IO Helper Service`
- ImagePath `c:\Windows\vmtoolsIO.exe`
- Start auto, account SYSTEM

**Remediation (this seat)**

1. Stop and delete service `VMwareIOHelperService` (`sc stop` / `sc delete`).
2. Delete `C:\Windows\vmtoolsIO.exe` and the Edge/IE cache copies; do not execute them.
3. Delete any remaining `SysInternals.exe` under Public Downloads.
4. Block `malware430.com`.
5. Review 7045/7040 and Application log from 21:19Z 2022-11-15.
6. No web-shell or extra task cleanup required based on the file list.

---

## 9. Extract inventory (`work/extracted/`)

| File | Source inode | SHA256 |
| --- | --- | --- |
| `malware/SysInternals_edge_cache.exe` | 124558 | `72e6d1728a546c2f3ee32c063ed09fa6ba8c46ac33b0dd2e354087c1ad26ef48` |
| `malware/SysInternals_partial.exe` | 124561 | `05e716cc98c186150b7167843324c8834e717750b702a28b4336bbda740e6995` |
| `malware/SysInternals_public_downloads.exe` | 124567 | **not the PE** (cluster reuse); SHA256 `d3c3bc26a836ab7d70b8384d13b237cccc45ce883eb74e98429dcaec31b09a0b` |
| `malware/vmtoolsIO.exe` | 82666 | `5b01cca415277e5fb0c454690142b9b4029a1566938875497d2f0593db555270` |
| `malware/VMwareUpdate.exe` | 81277 | same as vmtoolsIO |
| `prefetch/VMTOOLSIO.EXE-B05FE979.pf` | 82668 | recovered zeros; SHA256 `51ce6bae549809ae89dcecff857fc92da7a9333eb8f80ebc6472cbfac86f3075` |
| `temp/script.bat` | 124022 | lab 2019; see §6 |
| `temp/sdelete.exe`, `sdelete64.exe`, `SDelete.zip` | 125290/125291/125288 | lab 2019 |

---

## 10. Gaps / hand-off

- Download **URL for SysInternals.exe itself** is not in this PE (only payload/lure URLs). Edge `WebCacheV01.dat` / `spartan.edb` are other seats.
- No Zone.Identifier HostUrl.
- Prefetch of `vmtoolsIO` not parseable (zeros).
- Payload not disassembled beyond imports/strings; CPU-hog is a high-confidence inference, not a measured profile.
- Accounts/Run keys: `sd1d101`. Software/Uninstall: `sd1d105`. Timeline merge: `sd1d104`.

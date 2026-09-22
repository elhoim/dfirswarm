# Installed Software and Provenance

Seat: sd1d105 (Installed software and provenance)
Sources: SOFTWARE hive (inode 46340), SYSTEM hive (inode 42054), Amcache.hve (inode 83201), bodyfile, timeline, WebCacheV01.dat (inode 83835), filelist

---

## 1. Installed Software Inventory (Uninstall Registry)

From `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` in the SOFTWARE hive (inode 46340, 72 MB, extracted via `icat -o 0 inputs/SysInternalsCase.E01 46340`). Parsed with regipy 6.3.0.

| DisplayName | Publisher | Version | InstallDate | UninstallString |
|---|---|---|---|---|
| VMware Tools | VMware, Inc. | 11.3.5.18557794 | 2022-11-15 | MsiExec.exe /I{1FF5D624-5515-4343-837A-E54C101573E6} |
| Microsoft Visual C++ 2008 Redistributable - x64 | Microsoft Corporation | 9.0.30729.6161 | 2019-03-19 | MsiExec.exe /X{5FCE6D76-F5DC-37AB-B2B8-22AB8CEDB1D4} |
| Microsoft Visual C++ 2019 X64 Additional Runtime | Microsoft Corporation | 14.28.29913 | 2022-11-15 | MsiExec.exe /I{620A7633-7A09-42A8-8580-076A4483C4B0} |
| Microsoft Visual C++ 2019 X64 Minimum Runtime | Microsoft Corporation | 14.28.29913 | 2022-11-15 | MsiExec.exe /I{EECDD137-13DA-46ED-ADA0-BDF7F8BE65B8} |
| Microsoft Silverlight | Microsoft Corporation | 5.1.50918.0 | 2019-03-19 | MsiExec.exe /X{89F4137D-6C26-4A84-BDB8-2E5A4BB71E00} |
| Puppet (64-bit) | Puppet Labs | 3.8.7 | 2019-03-19 | MsiExec.exe /X{C132DF61-207E-4C59-90B8-1DA9E2E1A754} |

**Total: 6 MSI-installed applications.** No additional software from uninstall keys. No 32-bit (Wow6432Node) uninstall entries.

### Install dates and provenance

- **2019-03-19** (system provisioning): Puppet 3.8.7 installed via Chocolatey (`InstallSource: C:\Users\IEUser\AppData\Local\Temp\chocolatey\puppet\3.8.7\`), Silverlight 5.1, VC++ 2008
- **2022-11-15** (same day as infection): VMware Tools 11.3.5, VC++ 2019 (both Additional and Minimum Runtime)

---

## 2. Program Files Directory Enumeration

From `catalog/SysInternalsCase.E01/p0/filelist.txt`:

| Directory | Inode | Content |
|---|---|---|
| Program Files/ | 60 | Top-level |
| Program Files/Common Files/ | 61 | Shared components |
| Program Files/VMware/ | 59574 | VMware Tools installation |
| Program Files/Puppet Labs/ | 84509 | Puppet agent |
| Program Files/Microsoft Silverlight/ | 85820 | Silverlight runtime |
| Program Files/internet explorer/ | 132 | Built-in IE |
| Program Files/Windows Defender/ | 136 | Built-in Defender |
| Program Files/Windows Defender Advanced Threat Protection/ | 139 | Built-in ATP |
| Program Files/Windows Mail/ | 141 | Built-in |
| Program Files/Windows Media Player/ | 142 | Built-in |
| Program Files/WindowsPowerShell/ | 1439 | Built-in PowerShell |
| Program Files/WindowsApps/ | 164 | Store apps |
| Program Files/Windows Security/ | 158 | Built-in |
| Program Files/Uninstall Information/ | 81318 | System |

No unexpected third-party software directories aside from VMware, Puppet, and Silverlight.

---

## 3. Services and Drivers (SYSTEM Hive)

From `ControlSet001\Services` in SYSTEM hive (inode 42054, 11 MB, extracted via `icat -o 0 inputs/SysInternalsCase.E01 42054`). Total: 662 service keys.

### Non-Microsoft Services (with ImagePath outside system32)

| Service Name | DisplayName | ImagePath | Type | Start | Notes |
|---|---|---|---|---|---|
| **VMwareIOHelperService** | VMWare IO Helper Service | c:\Windows\vmtoolsIO.exe | 16 (Own) | 2 (Auto) | **MALWARE** - fake VMware service |
| VGAuthService | VMware Alias Manager and Ticket Service | C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe | 16 | 2 | Legitimate VMware |
| VMTools | VMware Tools | C:\Program Files\VMware\VMware Tools\vmtoolsd.exe | 16 | 2 | Legitimate VMware |
| puppet | Puppet Agent | C:\Program Files\Puppet Labs\Puppet\sys\ruby\bin\ruby.exe ... | 16 | 2 | Legitimate Puppet |

**Key finding:** `VMwareIOHelperService` (ImagePath: `c:\Windows\vmtoolsIO.exe`) is the malware persistence mechanism. It is configured to auto-start (Start=2) and runs as NT AUTHORITY\SYSTEM. The legitimate VMware Tools installation normally places `vmtoolsIO.exe` in `C:\Program Files\VMware\VMware Tools\`, not directly in `c:\Windows\`.

### Malware Service Details

```
Key: ControlSet001\Services\VMwareIOHelperService
  Type = 16 (SERVICE_WIN32_OWN_PROCESS)
  Start = 2 (SERVICE_AUTO_START)
  ErrorControl = 1 (SERVICE_ERROR_NORMAL)
  ImagePath = c:\Windows\vmtoolsIO.exe
  DisplayName = VMWare IO Helper Service
  WOW64 = 332
  ObjectName = NT AUTHORITY\SYSTEM
```

---

## 4. Amcache Analysis

Amcache.hve (inode 83201, 524 KB) parsed with regipy.

### Malicious Executable: SysInternals.exe

```
FileId: 0000fa1002b02fc5551e075ec44bb4ff9cc13d563dcf
LowerCaseLongPath: c:\users\public\downloads\sysinternals.exe
Name: SysInternals.exe
Publisher: sysinternals, inc.       <-- FAKE: real Sysinternals publisher is "Sysinternals" or "Microsoft Corporation"
Version: 2.0.0.1
BinFileVersion: 2.0.0.1
BinaryType: pe32_i386
ProductName: sysinternals suite downloader  <-- NOT a legitimate Sysinternals product
ProductVersion: 2.0.0.1
LinkDate: 11/18/2020 19:09:04
BinProductVersion: 2.0.0.1
Size: 57344
Language: 1033
IsPeFile: 1
IsOsComponent: 0
USN: 91987456
```

### Legitimate Sysinternals Tool: bginfo.exe

```
LowerCaseLongPath: c:\bginfo\bginfo.exe
Name: BGINFO.EXE
Publisher: sysinternals                          <-- Correct, lowercase
Version: 4.20
BinaryType: pe32_i386
ProductName: bginfo                              <-- Real product
LinkDate: 07/30/2013 03:02:23
Size: 847040
Language: 1033
IsOsComponent: 0
```

Note: BGInfo is a legitimate Sysinternals tool pre-installed on this system, started via the Run registry key:
`bginfo = C:\BGinfo\Bginfo.exe /accepteula /ic:\bginfo\bgconfig.bgi /timer:0`

---

## 5. The Malware Installation Chain

### Dropper: SysInternals.exe (inode 124558 / 124567)

- **File:** `Users/Public/Downloads/SysInternals.exe` (deleted, inode 124567) / Edge cache at inode 124558
- **Size:** 57344 bytes (56 KB)
- **Type:** PE32 executable (console) Intel 80386, for MS Windows
- **MD5:** `d1a27b871a86c5371215f71885862cff` (cache) / `ee18b3a542e2c27ab8e7506bc4b39379` (recovered)
- **SHA256 (cache):** `72e6d1728a546c2f3ee32c063ed09fa6ba8c46ac33b0dd2e354087c1ad26ef48`
- **LinkDate:** 2020-11-18 19:09:04
- **Publisher (fake):** "sysinternals, inc."
- **ProductName (fake):** "sysinternals suite downloader" v2.0.0.1

### Dropper Capabilities (from strings, inode 124558)

| Capability | API/Evidence |
|---|---|
| Download file from URL | `URLDownloadToFileA` (urlmon.dll), `InternetOpenUrlA`, `InternetOpenA` (wininet.dll) |
| Execute commands | `ShellExecuteA` (SHELL32.dll) |
| Download target | Downloads to `c:\Windows\Temp\Hex2Dec.zip` (filename referenced in strings) |
| Install service | Executes: `cmd.exe /C c:\Windows\vmtoolsIO.exe -install && net start VMwareIOHelperService && sc config VMwareIOHelperService start= auto` |
| Anti-debugging | `IsDebuggerPresent` |
| Evasion | `Sleep`, `FreeConsole` |
| User-Agent | `IE Agent 11.0` |

### Payload: vmtoolsIO.exe (inode 82666)

- **File:** `c:\Windows\vmtoolsIO.exe` (NOT deleted - still on disk)
- **Size:** 289280 bytes (283 KB)
- **Type:** PE32 executable (console) Intel 80386, for MS Windows
- **MD5:** `8c3ded1972755c8dc3c5b0ed200d7914`
- **SHA256:** `5b01cca415277e5fb0c454690142b9b4029a1566938875497d2f0593db555270`
- **Class names:** `CSampleService`, `CServiceBase` - generic service template
- **Capabilities:** CreateServiceW, OpenServiceW, ControlService, RegisterServiceCtrlHandlerW, StartServiceCtrlDispatcherW, SetServiceStatus, ReportEventW

The payload is a generic Windows service binary that masquerades as VMware IO Helper. The legitimate VMware Tools vmtoolsIO.exe normally resides in `C:\Program Files\VMware\VMware Tools\`.

### Installation Sequence

```
1. User downloads "SysInternals.exe" from a malicious source via Microsoft Edge
2. File lands in Edge cache: .../Cache/WMFWC1O7/SysInternals[1].exe (21:18:40 UTC)
3. Copied/moved to Users/Public/Downloads/SysInternals.exe (21:18:51 UTC)
4. User executes SysInternals.exe (21:19:00 UTC)
5. Dropper downloads Hex2Dec.zip (containing vmtoolsIO.exe) from remote URL
6. Dropper extracts vmtoolsIO.exe to c:\Windows\ (21:19:17 UTC)
7. Dropper installs it as VMwareIOHelperService (auto-start, SYSTEM)
8. vmtoolsIO.exe executed; prefetch created (21:19:22 UTC)
9. Cleanup: SysInternals.exe deleted from Public Downloads; prefetch deleted
```

### Download Source

**Stage-1 dropper download (from Edge WebCacheV01.dat inode 83835, confirmed by sd1d103):**
- **`http://www.sysinternals.com/SysInternals.exe`** — the fake SysInternals.exe was served from this URL (HTTP 200, Date: Tue, 15 Nov 2022 18:18:40 GMT). This is a typosquatted/phishing domain impersonating the real Sysinternals site.
- Legitimate Sysinternals downloads are served from `download.sysinternals.com` (also present in WebCache).

**Stage-2 payload URL (XOR 0x41 decoded from dropper inode 124558 by sd1d102/sd1d103):**

| URL | Role |
|---|---|
| `http://www.malware430.com/html/VMwareUpdate.exe` | **PAYLOAD HOST** — downloads vmtoolsIO.exe (289280 bytes, HTTP 200, cached as VMwareUpdate[1].exe inode 81277) |
| `https://download.sysinternals.com/files/Hex2Dec.zip` | Decoy/lure string (legitimate Sysinternals utility path) |
| `https://docs.microsoft.com/en-us/sysinternals/` | Decoy/lure reference |
| `http://www.google.com` | Connectivity check |

**Correction (per sd1d103):** The domain `downloads.subscriptionsint.tfsallin.net` found in WebCache is a Power BI / vsassets CDN allowlist entry, NOT the infection download URL. The stage-1 download came from `www.sysinternals.com` (typosquatted domain).

---

## 6. Registry Persistence (Run Keys)

From `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`:

| Name | Value | Notes |
|---|---|---|
| SecurityHealth | %windir%\system32\SecurityHealthSystray.exe | Windows built-in |
| bginfo | C:\BGinfo\Bginfo.exe /accepteula /ic:\bginfo\bgconfig.bgi /timer:0 | Legitimate Sysinternals BGInfo |
| VMware User Process | "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr | Legitimate VMware |

No unexpected Run keys found. The malware persists via the `VMwareIOHelperService` service (auto-start), not via Run keys.

No RunOnce, RunOnceEx, RunServices, or RunServicesOnce entries found.

---

## 7. Installer Artifacts

### Chocolatey
- Path: `ProgramData/chocolatey/` (inode 62811)
- Used to install Puppet 3.8.7 (2019-03-19)
- Install source: `C:\Users\IEUser\AppData\Local\Temp\chocolatey\puppet\3.8.7\`

### VMware Tools MSI Cache
- Path: `C:\Program Files\Common Files\VMware\InstallerCache\`
- InstallDate: 2022-11-15

### Visual C++ 2019 Redist
- Installed 2022-11-15 (same day as infection, likely part of system provisioning alongside VMware Tools)
- From: `C:\ProgramData\Package Cache\{...}v14.28.29913\packages\vcRuntime...`

---

## 8. Summary of Key IOCs

| Indicator | Type | Value |
|---|---|---|
| Malicious C2 domain (payload) | Network IOC | `malware430.com` (hosts `http://www.malware430.com/html/VMwareUpdate.exe`) |
| Malicious landing domain (stage-1) | Network IOC | `www.sysinternals.com` (typosquatted, served fake SysInternals.exe; real Sysinternals uses `download.sysinternals.com`) |
| Fake SysInternals.exe hash (cache) | File IOC | MD5: `d1a27b871a86c5371215f71885862cff` / SHA256: `72e6d1728a546c2f3ee32c063ed09fa6ba8c46ac33b0dd2e354087c1ad26ef48` |
| Malicious payload | File IOC | `c:\Windows\vmtoolsIO.exe`, MD5: `8c3ded1972755c8dc3c5b0ed200d7914` |
| Malicious service | Service IOC | `VMwareIOHelperService` (ImagePath: `c:\Windows\vmtoolsIO.exe`) |
| Fake product metadata | Indicator | Publisher: "sysinternals, inc.", ProductName: "sysinternals suite downloader" v2.0.0.1 |
| Download artifact | File IOC | `c:\Windows\Temp\Hex2Dec.zip` (referenced in dropper, likely deleted) |
| Edge partial download | Evidence | `.../TempState/Downloads/SysInternals.exe.51m0nh7.partial` (inode 124561, deleted) |

---

*Seat: sd1d105 | Last updated: 2026-09-18*
# Installed Software and Provenance (s881005)

Evidence sources: registry hives extracted to `work/extracted/registry/` (SOFTWARE inode 48452, SYSTEM inode 43894, NTUSER.DAT of IEUser inode 87325), the catalog body file (`catalog/Browser_Policy_Violation.E01/p0/bodyfile.txt`) and file list. Hives parsed with regipy 6.3.0. Timestamps are UTC unless noted; the system time zone is **Pacific Standard Time (UTC-8)** (`SYSTEM\ControlSet001\Control\TimeZoneInformation` = "Pacific Standard Time", Bias 480).

## 1. Machine identity and OS

| Item | Value | Evidence |
| --- | --- | --- |
| OS | Windows 10 1803 (build 10.0.17134), 64-bit | WinSxS `10.0.17134.1` components; `rs4_release.180410-1804` |
| Computer name | `MSEDGEWIN10` | `SYSTEM\ControlSet001\Control\ComputerName\ComputerName` = `MSEDGEWIN10` |
| Time zone | Pacific Standard Time (UTC-8) | `SYSTEM\...\TimeZoneInformation` Bias=480 |
| Volume | NTFS, single logical volume, no partition table | `catalog/.../partitions.txt` |

The host is a Microsoft-provided "MSEdge Win10" VM (the default interactive account is `IEUser`, RID 1000).

## 2. Installed software inventory (Uninstall keys)

Parsed from `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall` and `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` in the SOFTWARE hive (MD5 `132130952f644466e733b51137a9f2c0`).

| DisplayName | Version | InstallDate | Publisher / Source |
| --- | --- | --- | --- |
| **Google Chrome** | **70.0.3538.110** | **20181125** | Google Inc.; `C:\Program Files (x86)\Google\Chrome\Application` |
| **Google Update Helper** | **1.3.33.17** | **20181125** | Google Inc.; `C:\Program Files (x86)\Google\Update\1.3.33.17\` |
| VMware Tools | 10.2.5.8068393 | 20181125 | VMware, Inc. |
| OpenSSH for Windows 6.7p1-2 (remove only) | 6.7p1-2 | (none) | Mark Saeger / Michael Johnson |
| Puppet (64-bit) | 3.8.7 | 20180425 | Puppet Labs (installed via chocolatey from `C:\Users\IEUser\AppData\Local\Temp\chocolatey\puppet\3.8.7\`) |
| Microsoft Silverlight | 5.1.50907.0 | 20180425 | Microsoft Corporation |
| Microsoft Visual C++ 2008 Redistributable - x64 | 9.0.30729.6161 | 20180425 | Microsoft Corporation |
| Microsoft Visual C++ 2008 Redistributable - x86 | 9.0.30729.6161 | 20180425 | Microsoft Corporation |

Directory birth times (crtime) from the body file corroborate the two install waves:

| Path | crtime (UTC) |
| --- | --- |
| Program Files/Microsoft Silverlight | 2018-04-25 20:03:13 |
| Program Files/Puppet Labs | 2018-04-25 20:05:38 |
| Program Files/OpenSSH | 2018-04-25 20:06:30 |
| Program Files/VMware | 2018-11-25 16:19:39 |
| Program Files (x86)/Google | 2018-11-25 16:30:48 |
| Program Files (x86)/Google/Chrome/Application | 2018-11-25 16:31:01 |

**Interpretation:** the base image was built 2018-04-25 (~20:03–20:07 UTC) with Silverlight, Puppet, OpenSSH and the VC++ runtimes. On the violation day (2018-11-25), VMware Tools was installed (16:19 UTC) and then Google Chrome + Google Update (16:30–16:31 UTC).

## 3. Browsers present

Only two registered StartMenuInternet browsers exist in the SOFTWARE hive (`HKLM\Software\Clients\StartMenuInternet`):

| Browser | Registered? | Location |
| --- | --- | --- |
| Internet Explorer (`IEXPLORE.EXE`) | yes (default) | `C:\Program Files\Internet Explorer\iexplore.exe` (inode 21176) |
| **Google Chrome** | yes | `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe` (inode 96514) |
| Microsoft Edge 42.17134.1.0 | UWP app (not in StartMenuInternet) | `Program Files\WindowsApps\Microsoft.MicrosoftEdge_42.17134.1.0_neutral__8wekyb3d8bbwe` |

No other third-party browser (Firefox, Opera, Tor, Brave, Vivaldi, portable Chrome) is present in the file list. **The non-compliant browser is Google Chrome 70.0.3538.110.**

## 4. Google Chrome provenance

### 4.1 Delivery: VMware drag-and-drop

- The offline installer `ChromeStandaloneSetup64.exe` (54,695,528 bytes) landed at `Users/IEUser/AppData/Local/Temp/vmware-IEUser/VMwareDnD/941faa9f/ChromeStandaloneSetup64.exe` (inode 95950-128-4).
- The `vmware-IEUser/VMwareDnD` path is the VMware Tools **drag-and-drop** staging directory, i.e. the file was dragged from the host into the VM's `IEUser` session.
- File MACB: mtime/ctime 2018-11-25 16:11:24 UTC, crtime 16:12:10 UTC, atime 16:30:32 UTC (atime = when it was opened/run).
- MD5 `1d5770ef6905ad7d7f5f4a1a422bfcc8` (my extraction); SHA-256 `2893d2277214993ac2a1c8cfbe4e330de318f36db42f2f5139c8ad8ea900a27b` (recorded by s881003).
- `exiftool`: CompanyName "Google Inc.", File Description "Google Update Setup", Original File Name "GoogleUpdateSetup.exe", Product Version 1.3.33.17 — this is Google's Omaha-based standalone installer bundling Chrome (normal for the official `ChromeStandaloneSetup64.exe`), not an employee-renamed malware binary. The bootstrapper is a 32-bit PE (Machine=0x014c); the bundled `chrome_installer.exe` and the installed `chrome.exe` are 64-bit PE (Machine=0x8664, x64), matching the `ap` value `x64-stable`.

### 4.2 Installation (system level, offline source)

Registry evidence from `HKLM\Software\WOW6432Node\Google\Update\ClientState`:

| Value | Chrome `{8A69D345-...}` | Google Update `{430FD4D0-...}` |
| --- | --- | --- |
| `pv` | 70.0.3538.110 | 1.3.33.17 |
| `InstallTime` (epoch) | 1543163454 (16:30:54 UTC) | 1543163450 (16:30:50 UTC) |
| `brand` | GGLS | GGLS |
| `ap` | x64-stable-statsdef_1 | — |
| `UninstallString` | `...\70.0.3538.110\Installer\setup.exe --uninstall --system-level` | — |

- `UninstallArguments = --system-level` → machine-wide install.
- Omaha `PersistedPingString` XML: `installsource="offline"`, `ismachine="1"`, `updaterversion="1.3.33.17"` → the install came from the **offline** standalone installer, at machine scope (matches the dragged-in `ChromeStandaloneSetup64.exe`).

Install sequence (UTC, from body file + registry):

| Time (UTC) | Event |
| --- | --- |
| 16:11:24 | Installer written to VMwareDnD (drag-and-drop) |
| 16:30:40 | `CHROMESTANDALONESETUP64.EXE` prefetch created (executed) |
| 16:30:48 | `Program Files (x86)/Google` and `Google/Update` created |
| 16:30:50 | Google Update InstallTime (registry) |
| 16:30:52 | `chrome_installer.exe` (52,866,152 bytes, inode 96394) extracted under `Google/Update/Download/{8A69D345-...}/70.0.3538.110/` |
| 16:30:54 | Chrome InstallTime (registry) |
| 16:31:01 | `chrome.exe` (1,589,080 bytes) created in `Program Files (x86)/Google/Chrome/Application` |
| 16:31:03 | Chrome profile `First Run` marker + History/Cookies/etc. created for IEUser → **first run by IEUser** |

Hashes of extracted binaries (my `work/s881005/`):
- `ChromeStandaloneSetup64.bin` MD5 `1d5770ef6905ad7d7f5f4a1a422bfcc8`
- `chrome_installer.bin` MD5 `7fce421d47c32f0f41a3315b769dcc94`
- `chrome.exe.bin` MD5 `2d72cf80740f6c19a837346b1c8f181d`

### 4.3 Who installed it

- The installer was staged under `Users/IEUser/.../vmware-IEUser/VMwareDnD/` → delivered to the **IEUser** session via drag-and-drop.
- The Chrome profile is `Users/IEUser/AppData/Local/Google/Chrome/User Data/` → Chrome runs as **IEUser**.
- The system-level installer (`--system-level`, `ismachine=1`) succeeded from the IEUser session, so it was run with elevation. SAM corroborates IEUser (RID 1000) as the interactive account on the violation day: `last_login 2018-11-25 18:24:09Z`, `login_count 11`, and a `last_failed_login 2018-11-25 16:31:43Z` (immediately after the Chrome install completed at 16:31:01Z).
- First run 16:31:03 UTC (9 s after install) and last Chrome shutdown 18:37:40 UTC (`chrome_shutdown_ms.txt` mtime), both by IEUser.

## 5. Services and drivers (install footprint)

From `SYSTEM\ControlSet001\Services` (current control set = 1):

| Service | Start | ObjectName | ImagePath |
| --- | --- | --- | --- |
| Google Update Service (gupdate) | 2 (auto) | LocalSystem | `"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /svc` |
| Google Update Service (gupdatem) | 3 (manual) | LocalSystem | `"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /medsvc` |
| OpenSSH Server (OpenSSHd) | 2 (auto) | `.\sshd_server` | `C:\Program Files\OpenSSH\bin\cygrunsrv.exe` |
| OpenSSH Authentication Agent (ssh-agent) | 3 (manual) | LocalSystem | `%SystemRoot%\System32\OpenSSH\ssh-agent.exe` |
| Puppet Agent (puppet) | 2 (auto) | LocalSystem | `"C:\Program Files\Puppet Labs\Puppet\sys\ruby\bin\ruby.exe" -rubygems ...\service\daemon.rb` |

- `gupdate`/`gupdatem` are the standard Google Update machine services; their presence is the system-level install footprint. Machine-level scheduled tasks `GoogleUpdateTaskMachineCore` / `GoogleUpdateTaskMachineUA` accompany them (recorded by s881003).
- `OpenSSHd` runs as the dedicated `.\sshd_server` account — this explains the non-default `sshd_server` user under `Users/`. OpenSSH (Cygwin-based `cygrunsrv.exe`) and Puppet are part of the base image (installed 2018-04-25), unrelated to the browser violation.
- **No third-party kernel drivers** were found: every `Type=1` service in `ControlSet001\Services` resolves to a Microsoft (`\SystemRoot` / `system32`) driver. The only non-Microsoft services are OpenSSHd, puppet, the VMware Tools services, and the Google Update pair (`gupdate`/`gupdatem`) — i.e. Chrome left a service footprint but no driver-level persistence.

## 6. Summary

- The only non-compliant browser on the machine is **Google Chrome 70.0.3538.110** (system-level install under `Program Files (x86)/Google/Chrome`).
- It arrived as the official offline installer `ChromeStandaloneSetup64.exe` dragged into the VM's `IEUser` session via VMware drag-and-drop on **2018-11-25 ~16:11 UTC**, and was installed **16:30–16:31 UTC** the same day.
- First run by `IEUser` at **16:31:03 UTC**; Chrome remained in use through **18:37:40 UTC**.
- All other third-party software (OpenSSH, Puppet, Silverlight, VC++ 2008 runtimes) predates the violation (installed 2018-04-25 in the base image); VMware Tools was installed 2018-11-25 16:19 UTC, enabling the drag-and-drop delivery.

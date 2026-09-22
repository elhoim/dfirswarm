# Installed software and provenance (seat sbe1805)

Author: sbe1805 · seat: Installed software and provenance · owns this file.

Scope: Uninstall keys, Program Files, installers on disk, service/driver
installs, and who installed what and when. This note answers the "installed
software / provenance" slice of the case and feeds `work/report.md` §2/§6.

---

## 1. Operating system identity and install time

| Field | Value | Evidence |
| --- | --- | --- |
| ProductName | Windows 10 Enterprise Evaluation | SOFTWARE hive `Microsoft\Windows NT\CurrentVersion` |
| EditionID / ReleaseId | EnterpriseEval / 1809 | same key |
| CurrentBuild / BuildLabEx | 17763 / 17763.1.amd64fre.rs5_release.180914-1434 | same key |
| ProductId | 00329-20000-00001-AA236 (Eval) | same key |
| RegisteredOrganization | Microsoft | same key |
| InstallDate | `1553000375` = **2019-03-19T12:59:35Z** | same key (DWORD unix seconds) |
| Volume name / SN | "Windows 10" / BAB00A24B009E7A9 | `catalog/StealthyADS.E01/p0/fsstat.txt` |
| Time zone | Pacific Standard Time (UTC-8, DST active = UTC-7) | SYSTEM `ControlSet001\Control\TimeZoneInformation` (`Bias=480`, `ActiveTimeBias=420`) |

Commands:
```
python3 - <<'EOF'  # regipy against extracted hive (see §7)
from regipy.registry import RegistryHive
h = RegistryHive('work/sbe1805/registry/SOFTWARE')
for v in h.get_key(r'\Microsoft\Windows NT\CurrentVersion').iter_values():
    print(v.name, '=', v.value)
EOF
```

The hive was extracted with `icat -o 0 inputs/StealthyADS.E01 46340`
(SOFTWARE, inode 46340-128-4, 72,351,744 bytes) and
`icat -o 0 inputs/StealthyADS.E01 42054` (SYSTEM, inode 42054-128-4).

---

## 2. Installed third-party software (inventory)

### 2.1 HKLM Uninstall keys (MSI-installed programs)

From SOFTWARE `Microsoft\Windows\CurrentVersion\Uninstall` and
`WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` (regipy on inode 46340):

| DisplayName | Version | Publisher | Product GUID | InstallDate | Location |
| --- | --- | --- | --- | --- | --- |
| VMware Tools | 10.2.5.8068393 | VMware, Inc. | `{43D9111A-EA02-4682-BF3C-EFDCB62A89B0}` | 20190319 | `C:\Program Files\VMware\VMware Tools\` |
| Puppet (64-bit) | 3.8.7 | Puppet Labs | `{C132DF61-207E-4C59-90B8-1DA9E2E1A754}` | 20190319 | `C:\Program Files\Puppet Labs\Puppet\` |
| Microsoft Silverlight | 5.1.50918.0 | Microsoft Corporation | `{89F4137D-6C26-4A84-BDB8-2E5A4BB71E00}` | 20190319 | `C:\Program Files\Microsoft Silverlight\` |
| MS Visual C++ 2008 Redist x64 | 9.0.30729.6161 | Microsoft Corporation | `{5FCE6D76-F5DC-37AB-B2B8-22AB8CEDB1D4}` | 20190319 | — |
| MS Visual C++ 2008 Redist x86 | 9.0.30729.6161 | Microsoft Corporation | `{9BE518E6-ECC6-35A9-88E4-87755C07200F}` | 20190319 | — |

### 2.2 Chocolatey packages (ProgramData\chocolatey\lib)

| Package | Version | nupkg inode | Evidence |
| --- | --- | --- | --- |
| chocolatey (the tool itself) | 0.10.13 | `chocolatey.nupkg` 80485-128-1 | `ProgramData/chocolatey/logs/choco.summary.log` header "0.10.13" |
| puppet | 3.8.7 | `puppet.nupkg` 83084-128-4 | `puppet.nuspec` 83083-128-4 |

Chocolatey install log (`ProgramData/chocolatey/logs/choco.summary.log`, inode 81643-128-4):
```
2019-03-19 06:21:38,837 [INFO] - 0.10.13
2019-03-19 06:21:43 [INFO] - Chocolatey v0.10.13
2019-03-19 06:21:43 [INFO] - Installing the following packages: puppet
2019-03-19 06:21:46 [INFO] - [NuGet] Installing 'puppet 3.8.7'.
2019-03-19 06:21:51 [INFO] - Downloading puppet 64 bit
  from 'https://downloads.puppetlabs.com/windows/puppet-3.8.7-x64.msi'
2019-03-19 06:22:18 [INFO] -  Software installed to 'C:\Program Files\Puppet Labs\Puppet\'
```
(Local timestamps are Pacific; `06:21:38` PDT = **13:21:38Z** given `ActiveTimeBias=420`.)

### 2.3 HKCU (IEUser) Uninstall keys

From `Users/IEUser/NTUSER.DAT` (inode 83438-128-4), key
`Software\Microsoft\Windows\CurrentVersion\Uninstall`:

| DisplayName | Version | Publisher |
| --- | --- | --- |
| Microsoft OneDrive | 18.143.0717.0002 | Microsoft Corporation |

### 2.4 Windows capabilities / optional features

OpenSSH Server was added as a Windows capability by the build script
`BGinfo\openssh.ps1` (inode 82675-128-3):
```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
```
This produced the `sshd`/`ssh-agent` services (SYSTEM `ControlSet001\Services`,
Start=3/4 respectively).

### 2.5 Tooling present but not "installed" via a registry key

`C:\BGinfo` (root-level folder): Sysinternals BGInfo used to stamp the desktop
wallpaper. Contents: `BGINFO.EXE` (84366-128-1, 847,040 B),
`BGCONFIG.BGI` (84433-128-3), `background.jpg` (84434-128-1),
`build.cfg` (62193-128-1), `openssh.ps1` (82675-128-3).

---

## 3. Installers found on disk

### 3.1 Windows\Installer (cached MSI + MSP)

| File | Inode | Size | Product (from MSI summary info) |
| --- | --- | --- | --- |
| `Windows/Installer/1b783.msi` | 124973-128-3 | 49,139,712 | VMware Tools (Author "VMware, Inc.") |
| `Windows/Installer/c883.msi` | 88265-128-3 | 16,813,056 | Puppet (64-bit) Installer (Author "Puppet Labs") |
| `Windows/Installer/1c62c.msi` | 85766-128-3 | 53,248 | Microsoft Silverlight (Subject "Microsoft Silverlight CTP") |
| `Windows/Installer/1b77b.msi` | 124270-128-3 | 227,328 | Visual C++ 2008 Redist x86 9.0.30729.6161 |
| `Windows/Installer/1b77f.msi` | 124356-128-3 | 235,520 | Visual C++ 2008 Redist x64 9.0.30729.6161 |
| `Windows/Installer/1c632.msp` | 83918-128-3 | — | patch (MSP) |

Identification command (example):
```
icat -o 0 inputs/StealthyADS.E01 88265 > c883.msi
exiftool -Title -Subject -Author c883.msi
# Subject: "Puppet (64-bit) Installer", Author: "Puppet Labs"
```

### 3.2 Chocolatey package cache

`ProgramData/chocolatey/lib/puppet/puppet.nupkg` (83084-128-4, 6,230 B) and
`puppet.nuspec` (83083-128-4) — the NuGet package for puppet 3.8.7.
`ProgramData/chocolatey/lib/chocolatey/chocolatey.nupkg` (80485-128-1,
4,064,469 B) — the chocolatey bootstrap.

### 3.3 No attacker-dropped installers

No `.msi/.exe/.nupkg/.zip` installer was found in `Users/IEUser/Downloads`
(only `desktop.ini`) or any other user-writable path outside the known
OneDrive/chocolatey baseline. The only user-dropped executables are the ADS
payloads `putty.exe` and `revshell.exe` in `Desktop\creepy` — those are
portable tools, not installed software (no Uninstall key, no service, no
installer). See §6.

---

## 4. Services and drivers (SYSTEM ControlSet001\Services, inode 42054)

Non-Microsoft services installed on the machine (everything else is stock Win10):

| Service | Start | Type | ImagePath | Origin |
| --- | --- | --- | --- | --- |
| VMTools ("VMware Tools") | 2 (auto) | 16 | `"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"` | VMware Tools |
| VGAuthService | 2 | 16 | `...\VMware VGAuth\VGAuthService.exe` | VMware Tools |
| TPAutoConnSvc | 3 | 16 | `...\TPAutoConnSvc.exe` | VMware Tools |
| TPVCGateway | 3 | 16 | `...\TPVCGateway.exe` | VMware Tools |
| VMware Physical Disk Helper Service | 2 | 16 | `...\vmacthlp.exe` | VMware Tools |
| VMwareCAFCommAmqpListener | 3 | 16 | `...\VMware CAF\pme\bin\CommAmqpListener.exe` | VMware Tools |
| VMwareCAFManagementAgentHost | 3 | 16 | `...\VMware CAF\pme\bin\ManagementAgentHost.exe` | VMware Tools |
| puppet ("Puppet Agent") | 2 | 16 | `"C:\Program Files\Puppet Labs\Puppet\sys\ruby\bin\ruby.exe" -rubygems "...\service\daemon.rb"` | Puppet |
| sshd ("OpenSSH SSH Server") | 3 | 16 | `%SystemRoot%\System32\OpenSSH\sshd.exe` | build script |
| ssh-agent ("OpenSSH Authentication Agent") | 4 | 16 | `%SystemRoot%\System32\OpenSSH\ssh-agent.exe` | build script |

Third-party **drivers** (all VMware Tools; Type 1 = kernel, 2 = FS):

| Driver | Type | ImagePath |
| --- | --- | --- |
| vmci (VMware VMCI Bus Driver) | 1 | `System32\drivers\vmci.sys` |
| vmhgfs (VMware Host Guest Client Redirector) | 2 | `system32\DRIVERS\vmhgfs.sys` |
| vmmouse (VMware Pointing Device) | 1 | `\SystemRoot\System32\drivers\vmmouse.sys` |
| vmrawdsk (VMware Physical Disk Helper) | 1 | `\SystemRoot\system32\DRIVERS\vmrawdsk.sys` |

Built-in security/AV services present: `WinDefend`
(`...\4.18.1902.2-0\MsMpEng.exe`), `WdNisSvc` (`...\NisSrv.exe`), `Sense`
(Windows Defender ATP). These are the baseline Defender install, version
4.18.1902.2-0.

---

## 5. Provenance — who installed what, and when

**The base image is a Microsoft Edge development VM** (the
`dev.microsoftedge.com -VMs` distribution). Proof:

- `BGinfo/build.cfg` (inode 62193-128-1), UTF-16 JSON:
  `{"ie":"IE11","build":"20190311","software":"VMware","windows":"Win10"}`
- `BGinfo/openssh.ps1` header:
  `dev.microsoftedge.com -VMs · Copyright(c) Microsoft Corporation`.

**Everything was installed on 2019-03-19 by the automated VM build, in this
order** (timestamps are UTC; local = UTC-7 PDT):

| Time (UTC) | Event | Evidence |
| --- | --- | --- |
| 12:59:35 | Windows 10 Ent Eval installed | SOFTWARE `InstallDate=1553000375` |
| 13:00:42 | BGINFO.EXE / BGCONFIG.BGI created | bodyfile crtime 1553000442 (84366/84433) |
| 13:03:03 | Silverlight MSI cached | `1c62c.msi` crtime 1553000583 |
| 13:04:50–13:05:18 | OneDrive 18.143 → 19.012 update | `OneDriveSetup.exe` crtime 1553000690; `19.012.0121.0011` dir crtime 1553000718 |
| 13:21:20 | `build.cfg` written | crtime 1553001680 |
| 13:21:36 | chocolatey installed | `choco.exe` crtime 1553001696 |
| 13:21:38 | `choco install puppet` (3.8.7) | choco.summary.log |
| 13:21:52 | Puppet MSI cached | `c883.msi` crtime 1553001712 |
| 13:22:19 | OpenSSH.Server capability + `Start-Service sshd` | `openssh.ps1` crtime 1553001739 |
| 13:24:30 | VMware Tools MSI cached | `1b783.msi` crtime 1553001870 |
| 13:24:32/13:24:38 | VC++ 2008 x86/x64 cached | `1b77b.msi`/`1b77f.msi` crtimes |

The installs predate IEUser's interactive use (IEUser account creation logged
in `Security.evtx` by the accounts seat); the software was therefore laid down
by the provisioning/sysprep process, not interactively by a user.

**The attacker installed no software.** On the attack day (2019-05-26) the only
activity is placing portable executables into NTFS alternate data streams in
`Desktop\creepy` and running them — there are no new Uninstall keys, no new
services/drivers, no MSI/installer writes, no chocolatey activity after
2019-03-19 (choco.summary.log ends 13:22:18Z on 03-19). See
`work/leftovers.md` / `work/disk_triage.md` for the ADS payload inventory.

---

## 6. Detection methods relevant to this seat

- **Installed programs (live):** `HKLM\...\Uninstall` (64-bit + WOW6432Node) and
  `HKCU\...\Uninstall`. Offline: `regipy` on the SOFTWARE / NTUSER.DAT hives.
- **Installers on disk:** `fls`/`icat` of `Windows\Installer\*.msi`; identify
  each cached MSI's summary info with `exiftool -Subject -Author`.
- **Package manager history:** `ProgramData\chocolatey\logs\choco.summary.log`
  and `chocolatey.log`; `ProgramData\chocolatey\lib\*\*.nupkg`.
- **Services/drivers:** `SYSTEM\ControlSet001\Services` (`ImagePath`, `Start`,
  `Type`). Third-party = ImagePath outside `C:\Windows\System32`.
- **Who/when:** registry `InstallDate` DWORDs, MSI/nupkg/log `crtime` from the
  body file (`catalog/.../bodyfile.txt`), and the build stamp `BGinfo/build.cfg`.

Commands used (no partition offset; image is a single NTFS volume):
```
icat -o 0 inputs/StealthyADS.E01 46340 > SOFTWARE   # hives
icat -o 0 inputs/StealthyADS.E01 42054 > SYSTEM
icat -o 0 inputs/StealthyADS.E01 83438 > NTUSER.DAT
icat -o 0 inputs/StealthyADS.E01 88265 > c883.msi   # installers
exiftool -Subject -Author c883.msi
```

---

## 7. Extracted artifacts (hash, location)

Extracted into `work/sbe1805/registry/` (this seat's scratch):

| File | Inode | SHA-256 |
| --- | --- | --- |
| SOFTWARE | 46340-128-4 | 10e39f851841f297c93c73a71ad9d1d1ae8bc147b47d9d76094ccd9db85918ea |
| SYSTEM | 42054-128-4 | e3037cc01df7e7b51d403a8c3452718fa3c5a5b01bf8a5beb81acafadd32e2a1 |
| SAM | 41760-128-4 | 22ce7af7f1bcaa77c92ebf61659654903d312ebe8f755709d407d3a2ef4a6485 |
| SECURITY | 41763-128-4 | 38f4ea04af0456f423d45c8b369e19122832e8c71c27bfb440c07e38fa0e066d |
| NTUSER.DAT (IEUser) | 83438-128-4 | 06db997dbfb83a2fc8314124b329cfa28da86228a189f6074bc3868ba1e83560 |
| UsrClass.dat (IEUser) | 83564-128-3 | 8df2f567f3acee20c15ddbb432558b52e6bdc644c8126aa44a8f11bff6f185c9 |

Peers needing these hives for their own seats can re-extract with `icat -o 0
inputs/StealthyADS.E01 <inode>` (no claim needed to read my scratch, but do not
write there).

---

## 8. Conclusion (for the report)

1. The machine is a stock **Microsoft Edge dev VM (IE11/Win10/VMware, build
   20190311)** running Windows 10 Enterprise Evaluation 1809 (17763), installed
   2019-03-19T12:59:35Z.
2. Installed third-party software is limited to **VMware Tools, Puppet 3.8.7
   (via Chocolatey), Silverlight, VC++ 2008 x86/x64, OpenSSH Server, OneDrive,
   and BGInfo** — all laid down by the automated build on 2019-03-19.
3. **The attacker installed no software**: no new Uninstall entries, services,
   drivers, installers, or package-manager activity exist after the build day.
   The 2019-05-26 activity is purely portable payloads hidden in ADS.

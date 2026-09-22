# Installed software and provenance (seat sf4b205)

Evidence base: `inputs/s4a-challenge4` (NTFS image, partition starts at sector 2048).
Hives extracted with `icat -o 2048 inputs/s4a-challenge4 <inode>` into `work/sf4b205/`
(SYSTEM inode 18499, SOFTWARE inode 18496, SECURITY inode 18493,
Administrator NTUSER.DAT inode 201). Parsed with Python `regipy` 6.3.0.

## System under analysis
- Windows Server 2008 (NT 6.0 build 6001, x86/32-bit, PAE), `NtProductType Server`.
  Source: `catalog/memdump.mem/windows.info.txt`; memory captured 2015-09-03 10:04:05 UTC.
- Registry hive baseline timestamps show the OS image was laid down 2008-01-19
  (default Uninstall component keys all have last-modified 2008-01-19 11:40:26 UTC).
  Source: `regipy` on `work/sf4b205/SOFTWARE`, key
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`.

## Installed software inventory (HKLM Uninstall)
From `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` (13 subkeys; the
rest are inert Windows component placeholders with no DisplayName). This is a 32-bit
OS, so there is no Wow6432Node view (verified: no `\Wow6432Node` key).

| Software | Version | InstallDate / key last-write (UTC) | Publisher | Evidence |
| --- | --- | --- | --- | --- |
| Microsoft Visual C++ 2008 Redistributable - x86 | 9.0.21022 | 2015-08-23 21:43:54 | Microsoft | key `{FF66E9F6-83E7-3A3E-AF14-8DE9A809A6A4}`, InstallDate `20150823`; MSI product GUID in `HKLM\...\Installer\UserData\S-1-5-18\Products` (1 product) |
| XAMPP | 5.6.11-1 | 2015-08-23 21:44:08 (InstallDate unix 1440366248) | Bitnami | key `xampp`; InstallLocation `C:\xampp` |
| Oracle VM VirtualBox Guest Additions | 4.3.30.0 | 2015-08-24 07:14:15 | Oracle Corporation | key `Oracle VM VirtualBox Guest Additions`; UninstallString `C:\Program Files\Oracle\VirtualBox Guest Additions\uninst.exe` |

### XAMPP 5.6.11-1 (the web-server stack)
Installed to `C:\xampp`. Components verified on disk (file list inodes under `xampp/`):
Apache (ports 80/443), MySQL (3306), PHP, phpMyAdmin, FileZilla FTP Server
(`xampp/FileZillaFTP/`), MercuryMail (`xampp/MercuryMail/`), Tomcat
(`xampp/tomcat/`), Perl (`xampp/perl/`). `xampp/properties.ini` (inode 59681) records
`base_stack_version=5.6.11-1`, `installdir=C:\xampp`, Apache/MySQL/PHP config.
`xampp/passwords.txt` (inode 42944) documents the stock default credentials
(MySQL root with no password, Mercury default accounts, WEBDAV default).

XAMPP runs in **portable/control-panel mode**: no Apache or MySQL Windows services
exist (SYSTEM `\ControlSet001\Services` has no ImagePath containing `xampp`, `apache`,
`mysql`, or `php`); the stack is started via `xampp_start.bat`/`ctlscript.bat`.

### Damn Vulnerable Web Application (DVWA) v1.3 — web application
Present at `C:\xampp\htdocs\DVWA` (docs `DVWA_v1.3.pdf`, `README.md`, `CHANGELOG.md`).
All DVWA files carry creation time **2015-08-23 21:52:25 UTC** (timeline.csv), i.e. the
vulnerable web app was placed in the web root minutes after XAMPP itself, before the
attack window (2015-09-02/03). It is the application the attacker exploited.

### VirtualBox Guest Additions 4.3.30 — VM infrastructure
Files under `Program Files/Oracle/VirtualBox Guest Additions/` (VBoxGuest.sys,
VBoxMouse.sys, VBoxVideo.sys, VBoxService, VBoxTray.exe, VBoxControl.exe, uninst.exe).
Services/drivers in SYSTEM hive: `VBoxGuest`, `VBoxMouse`, `VBoxService`, `VBoxSF`,
`VBoxVideo`. Install registered 2015-08-24 07:14 UTC — this is hypervisor tooling for
the VirtualBox VM, not attacker software.

## Installer artifacts left on disk (C:\ root)
The Visual C++ 2008 Redistributable installer was run from the root of C:\ and left its
payload behind (all inodes from `catalog/.../filelist.txt`, MAC times from `timeline.csv`):

| Path | Inode | SHA-256 | Note |
| --- | --- | --- | --- |
| `/VC_RED.MSI` | 59744 | `507ac60e145057764f13cf1ad5366a7e15ddc0da5cc22216f69e3482697d5e88` | MSI, accessed 2015-08-23 21:43:53 |
| `/VC_RED.cab` | 59746 | `9681bcfd73c610eb6a9538d872c1e7844548fca341f22fb66ccadb4d78530b4d` | cabinet, accessed 2015-08-23 21:43:53 |
| `/install.exe` | 59742 | `08966ce743aa1cbed0874933e104ef7b913188ecd8f0c679f7d8378516c51da2` | redist bootstrapper, accessed 2015-08-23 21:43:53 |
| `/install.ini` | 59743 | (1110 B) | accessed 2015-08-23 21:43:53 |
| `/globdata.ini` | 59741 | (843 B) | accessed 2015-08-23 21:43:53 |
| `/vcredist.bmp` | 59745 | (5686 B) | accessed 2015-08-23 21:43:53 |
| `/install.res.*.dll`, `/eula.*.txt` | 59723-59740 | — | redist localization files |

These files carry original build times of 2007-11-07 (the redist package) and access times
of 2015-08-23 21:43:53 UTC — i.e. they were executed/read during the VC++ install on
2015-08-23, and were never cleaned up. They are the standard VC++ 2008 redist installer
(also bundled as `xampp/vcredist`, deleted inode 42745), not attacker tooling.

## Services and drivers (SYSTEM `\ControlSet001\Services`)
Full enumeration (regipy) shows **no attacker-installed service or driver**.
Every non-Microsoft entry is accounted for:
- VirtualBox Guest Additions: `VBoxGuest` (driver, Start 0), `VBoxMouse`, `VBoxService`
  (Start 2), `VBoxSF`, `VBoxVideo`.
- `ad_driver` — DisplayName "AccessData Driver", ImagePath
  `\??\C:\Users\ADMINI~1\AppData\Local\Temp\ad_driver.sys`, Start 3, Type 1 (kernel driver).
  This is the **AccessData FTK Imager** memory-acquisition driver, dropped by the
  investigator's imaging process — not attacker software. File `ad_driver.sys`
  (inode 60402) MAC = 2015-09-03 10:04:05 UTC (the memory capture instant);
  SHA-256 `11a707d5115e55649fb1964cda455a1f74c21c4877f745ed225b961f5acdf2f8`,
  MD5 `147c759905adad1bb9f9d6cdf2eb645e`. Its presence is corroborated by the user hive
  key `Administrator\NTUSER.DAT\Software\AccessData\FTK Imager\imaging`
  (last-modified 2015-09-12 18:20:08 UTC).
- The remaining 2015-08-23 21:25-21:26 cluster (`WAS`, `AppHostSvc`, `InetInfo`,
  `ASP.NET`, `idsvc`, `NetTcpPortSharing`, `FontCache3.0.0.0`, `TrustedInstaller`, etc.)
  are Windows features (IIS + .NET Framework 3.0/3.5) enabled during web-server setup.
- The large 2015-09-13 04:18 cluster of standard kernel drivers (AFD, Beep, CLFS, Ntfs,
  Tcpip, …) is a post-capture PnP/driver re-registration (reboot), not a software install.

## Provenance conclusion (who installed what)
- **Base OS** Windows Server 2008 SP1 x86 — installed 2008-01-19 (image baseline).
- **.NET Framework 3.0/3.5 + IIS** — Windows features enabled 2015-08-23 21:25-21:26 UTC.
- **Microsoft VC++ 2008 Redistributable** — installed 2015-08-23 21:43:54 UTC, a
  runtime dependency pulled in with XAMPP (installer files left at C:\ root).
- **XAMPP 5.6.11-1 + DVWA v1.3** — the company web-server stack, installed 2015-08-23
  21:44 (XAMPP) / 21:52 (DVWA), well before the 2015-09-02/03 attack window.
- **Oracle VM VirtualBox Guest Additions 4.3.30** — hypervisor/VM tooling, 2015-08-24.
- **AccessData FTK Imager** (`ad_driver.sys`) — forensic acquisition tooling used by the
  investigators (2015-09-03 memory capture; HKCU traces 2015-09-12).

**None of the installed software was installed by the attacker.** The attacker did not
install any program (no new Uninstall entry, no new service/driver, no installer in the
attack window). The compromise used the pre-existing vulnerable DVWA web application
(SQL injection via sqlmap, then uploaded web shells) plus software already bundled in
XAMPP; the attacker's "leftovers" are web-shell files, not installed software.

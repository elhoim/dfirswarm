# Installed software and provenance

Owner: `s0ae905` (provenance seat). Evidence base: `inputs/4orensics.001` (raw NTFS volume,
no partition table, `icat -o 0`), the catalog, and the extracted hives.

Extracted hives used here (hashes of my extractions, all under `work/s0ae905/extracted/`):

| Hive | Inode | SHA-256 |
| --- | --- | --- |
| `Windows/System32/config/SOFTWARE` | 45570-128-3 | `e9beb711f1587df123001ab908aad931321a32da78437dc2e74419d5612321e2` |
| `Windows/System32/config/SYSTEM` | 44235-128-3 | `e75b343a867329fcc05abf8c87d7f8a3c77b736d03bd46625aa1ab095383be7d` |

## 0. Operating system (context for everything below)

From `SOFTWARE\Microsoft\Windows NT\CurrentVersion` (inode 45570):

| Value | Data |
| --- | --- |
| ProductName | **Windows 8.1 Enterprise** |
| EditionID / InstallationType | Enterprise / Client |
| CurrentVersion / CurrentBuild / BuildLabEx | 6.3 / 9600 / `9600.17031.amd64fre.winblue_gdr.140221-1952` |
| RegisteredOwner | **Hunter** |
| InstallDate (registry) | 1466498265 = **2016-06-21 08:37:45 UTC** |
| SystemRoot | `C:\Windows` |

This is a single-user Windows 8.1 Enterprise workstation registered to **Hunter**, who is a local
Administrator and the only interactive account (see the accounts seat; ledger seq 50, 62). Every
software install below is therefore a system-wide (HKLM) install performed from Hunter's session.

## 1. Installed software inventory (HKLM Uninstall keys)

Source: `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` (x64) and
`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` (x86). "Dir crtime" is the NTFS
birth time of the vendor's directory under `Program Files` / `Program Files (x86)` (from the
body file), which corroborates the install moment. Registry `InstallDate` is YYYYMMDD (empty when
the installer did not write it).

### 1a. Native 64-bit (`\Uninstall`)

| Product | Version | Vendor | InstallDate | Dir crtime (UTC) |
| --- | --- | --- | --- | --- |
| 7-Zip | 16.02 (x64) | Igor Pavlov | — | 2016-06-21 09:18:13 (`Program Files/7-Zip`, inode 87441) |
| CCleaner | 5.19 | Piriform | — | 2016-06-21 11:43:02 (`Program Files/CCleaner`, inode 88630) |
| Microsoft Office Professional Plus 2013 | 15.0.4569.1506 | Microsoft | 20160620 | 2016-06-20 23:56:02 (`Program Files/Microsoft Office`, inode 93077) |
| Oracle VM VirtualBox Guest Additions | 5.0.22.0 | Oracle | — | (drivers under `System32\drivers\VBox*`) |
| Intel Security True Key | 4.2.131.1 | Intel Security | — | 2016-06-21 09:20:40 (`Program Files/TrueKey`, inode 87778) |
| USBPcap | 1.1.0.0-g794bf26-3 | (USBPcap) | — | 2016-06-21 09:23:09 (`Program Files/USBPcap`, inode 90723) |
| Java 8 Update 91 (64-bit) | 8.0.910.15 | Oracle | 20160621 | 2016-06-21 11:22:30 (`Program Files/Java`, inode 109589) |
| Intel RealSense SDK 2014 Runtime (x64): Core | 3.1.0.25181 | Intel | 20160621 | 2016-06-21 09:27:37 (`Program Files/Intel`, inode 92343) |
| Intel Biometric and Context Agent | 2.0.87.0 | Intel | 20160621 | (above) |
| Microsoft Visual C++ 2013 x64 (Min/Addl) | 12.0.21005 | Microsoft | 20160621 | (WinSxS) |

### 1b. 32-bit (`\WOW6432Node\...\Uninstall`)

| Product | Version | Vendor | InstallDate | Dir crtime (UTC) |
| --- | --- | --- | --- | --- |
| BCWipe | 6.08.6 (BCWipe 6.0) | Jetico Inc. | — | 2016-06-21 11:44:44 (`Program Files (x86)/Jetico/BCWipe`, inode 109928) |
| Dropbox | 4.4.29 | Dropbox, Inc. | — | 2016-06-21 01:47:10 (`Program Files (x86)/Dropbox`, inode 22451) |
| Dropbox Update Helper | 1.3.43.1 | Dropbox, Inc. | 20160620 | (above) |
| Google Chrome | 51.0.2704.103 | Google Inc. | 20160621 | 2016-06-21 01:44:36 (`Program Files (x86)/Google`, inode 83885) |
| Google Drive | 1.30.2170.0459 | Google, Inc. | 20160620 | (above) |
| Google Update Helper | 1.3.30.3 | Google Inc. | 20160621 | (above) |
| McAfee Security Scan Plus | 3.11.266.3 | McAfee, Inc. | — | 2016-06-20 23:48:31 (`Program Files (x86)/McAfee`, inode 91780) |
| Nmap | 7.12 | (Nmap) | — | 2016-06-21 11:01:37 (`Program Files (x86)/Nmap`, inode 88816) |
| Notepad++ | 6.9.2 | Notepad++ Team | — | 2016-06-21 09:18:27 (`Program Files (x86)/Notepad++`, inode 87563) |
| TeamViewer | 11.0.59518 (TeamViewer 11) | TeamViewer | — | 2016-06-21 00:57:30 (`Program Files (x86)/TeamViewer`, inode 88431) |
| WinPcap | 4.1.3 (4.1.0.2980) | Riverbed Technology | — | 2016-06-21 09:23:01 (`Program Files (x86)/WinPcap`, inode 90727) |
| Wireshark | 2.0.4 (64-bit) | Wireshark developer community | — | 2016-06-21 09:22:42 (`Program Files/Wireshark`, inode 85250) |
| Adobe Acrobat Reader DC | 15.016.20045 | Adobe Systems | 20160620 | 2016-06-21 09:20:05 (`Program Files (x86)/Adobe`, inode 87787) |
| Skype | 7.25.103 (Skype 7.25) | Skype Technologies S.A. | 20160621 | 2016-06-21 08:59:05 (`Program Files (x86)/Skype`, inode 84307) |
| Python 2.7.11 | 2.7.11150 | Python Software Foundation | 20160621 | (per-user + `AppData\Local\Programs\Python`) |
| Python 3.5.1 (Core/Stdlib/etc.) | 3.5.1150.0 | Python Software Foundation | 20160621 | (above) |
| Microsoft Visual C++ 2008/2013 x86 | 9.0.30729.6161 / 12.0.21005 | Microsoft | 20160621 | (WinSxS) |
| Java Auto Updater | 2.8.91.15 | Oracle | 20160621 | (above) |

## 2. Downloads — the installers and their origin (provenance)

`Users/Hunter/Downloads` holds the installers (inode → crtime UTC). These are the direct evidence
that **Hunter** (the only interactive user) downloaded and then ran each installer. `:Zone.Identifier`
ADS (ZoneId=3 = internet zone) present on the listed files confirms browser/internet download.

| File (inode) | crtime (UTC) | mtime (UTC) | MotW |
| --- | --- | --- | --- |
| `putty.exe` (94315-128-3) | 2016-06-21 11:55:37 | 2016-06-20 23:57:41 | no |
| `pscp.exe` (94320-128-3) | 2016-06-21 11:08:15 | 2016-06-20 23:57:42 | yes (94320-128-7) |
| `setupssh381-20040709.zip` (98359-128-5) | 2016-06-20 23:59:06 | 2016-06-20 23:59:06 | yes (98359-128-8) |
| `TeamViewer_Setup-vfa.exe` (88360-128-5) | 2016-06-21 00:57:15 | 2016-06-21 00:52:33 | no |
| `googledrivesync.exe` (1232-128-3) | 2016-06-21 01:44:11 | 2016-06-21 01:44:00 | no |
| `DropboxInstaller.exe` (1240-128-5) | 2016-06-21 01:45:06 | 2016-06-21 01:44:11 | no |
| `FTK-Imager.zip` (23862-128-1) | 2016-06-21 02:04:49 | 2016-06-21 02:04:40 | no |
| `ChromeSetup.exe` (83722-128-4) | 2016-06-21 08:41:31 | 2016-06-21 08:41:28 | no |
| `SkypeSetup.exe` (83847-128-5) | 2016-06-21 08:54:43 | 2016-06-21 08:54:23 | no |
| `7z1602-x64.exe` (83486-128-5) | 2016-06-21 09:18:07 | 2016-06-21 09:16:44 | no |
| `npp.6.9.2.Installer.exe` (83233-128-5) | 2016-06-21 09:18:17 | 2016-06-21 09:17:14 | no |
| `Wireshark-win64-2.0.4.exe` (30272-128-9) | 2016-06-21 09:22:23 | 2016-06-21 09:20:52 | no |
| `ccsetup519pro.exe` (23945-128-5) | 2016-06-21 11:08:26 | 2016-06-21 10:45:43 | no |
| `torbrowser-install-6.0.1_en-US.exe` (23999-128-9) | 2016-06-21 10:51:21 | 2016-06-21 10:48:41 | no |
| `Eraser6.2.0.2971-NoRuntimes.exe` (25864-128-5) | 2016-06-21 10:57:20 | 2016-06-21 10:57:20 | yes (25864-128-8) |
| `Hash_Suite_Free_3_4.zip` (88719-128-5) | 2016-06-21 11:06:24 | 2016-06-21 11:00:42 | yes (88719-128-8) |
| `nmap-7.12-setup.exe` (88764-128-5) | 2016-06-21 11:01:33 | 2016-06-21 10:58:47 | no |
| `SysinternalsSuite.zip` (88800-128-5) | 2016-06-21 11:02:36 | 2016-06-21 11:02:36 | yes (88800-128-8) |
| `burpsuite_free_v1.7.03.jar` (88802-128-5) | 2016-06-21 11:17:44 | 2016-06-21 11:02:14 | yes (88802-128-8) |
| `odbg110.zip` (89698-128-3) | 2016-06-21 11:05:01 | 2016-06-21 11:05:01 | yes (89698-128-7) |
| `python-2.7.11.msi` (23937-128-5) | 2016-06-21 11:17:58 | 2016-06-21 11:04:04 | no |
| `python-3.5.1.exe` (89789-128-5) | 2016-06-21 11:19:14 | 2016-06-21 11:04:27 | no |
| `jre-8u91-windows-x64.exe` (90140-128-5) | 2016-06-21 11:22:20 | 2016-06-21 11:21:18 | no |
| `bcwipeSetup.exe` (88689-128-5) | 2016-06-21 11:44:31 | 2016-06-21 10:56:38 | no |

Notes: `putty.exe`/`pscp.exe` carry an **older mtime (2016-06-20 23:57Z)** than their crtime,
i.e. the binaries were fetched at 23:57 UTC on the 20th and later copied into `Downloads`.
The `:Zone.Identifier` streams for the flagged files contain only `ZoneId=3` (no `HostUrl`),
so they were internet-downloaded but the source URL was not preserved in the ADS.

## 3. Portable / extracted tools (present on disk, not in Uninstall)

These were downloaded and unpacked/run from Hunter's profile rather than installed via MSI/setup
into `Program Files`, so they leave no Uninstall key but are unambiguous in the file list.

| Tool | Location | Evidence |
| --- | --- | --- |
| Tor Browser 6.0.1 | `Users/Hunter/Desktop/Tor Browser/` (inode 25904) | installer inode 23999; prefetch `TORBROWSER-INSTALL-6.0.1_EN-U-46D64A96.pf` |
| FTK Imager | `Users/Hunter/Downloads/FTK-Imager/` (inode 23863) | `FTK-Imager.zip` inode 23862; prefetch `FTK IMAGER.EXE-393FFB9B.pf` (run 2016-06-21 13:18:23Z) |
| Hash Suite Free 3.4 | `Users/Hunter/Downloads/Hash_Suite_Free/` (inode 88807) | zip inode 88719 |
| OllyDbg | `Users/Hunter/Downloads/Ollydbg/` (inode 89938) | `odbg110.zip` inode 89698 |
| Sysinternals Suite | `Users/Hunter/Downloads/SysinternalsSuite/` (inode 90031) | zip inode 88800 |
| Burp Suite Free 1.7.03 | `Users/Hunter/Downloads/burpsuite_free_v1.7.03.jar` (inode 88802) | jar + `:Zone.Identifier` |
| PuTTY / PSCP | `Users/Hunter/Downloads/putty.exe` (94315), `pscp.exe` (94320) | prefetch `PUTTY.EXE-6CB315A8.pf` (run 11:55:39Z) |
| SSH Secure Shell | `Users/Hunter/Downloads/setupssh381-20040709.zip` (98359) | zip |
| Eraser 6.2.0.2971 | `Users/Hunter/Downloads/Eraser6.2.0.2971-NoRuntimes.exe` (25864) | exe + `:Zone.Identifier` |

## 4. Services and drivers installed by these packages

Source: `SYSTEM\ControlSet001\Services` (inode 44235). Start: 0=boot, 1=system, 2=auto,
3=manual, 4=disabled. Only third-party (non-Microsoft) entries are listed.

| Service/Driver | ImagePath | Type/Start | Package |
| --- | --- | --- | --- |
| `TeamViewer` | `...\TeamViewer\TeamViewer_Service.exe` | svc / auto | TeamViewer 11 |
| `BCWipeSvc` | `...\Jetico\BCWipe\BCWipeSvc.exe` | svc / auto | BCWipe 6.0 |
| `NPF` | `system32\drivers\npf.sys` | driver / auto | WinPcap |
| `rpcapd` | `...\WinPcap\rpcapd.exe -d -f ...` | svc / manual | WinPcap |
| `USBPcap` | `\SystemRoot\system32\DRIVERS\USBPcap.sys` | driver / manual | USBPcap |
| `SkypeUpdate` | `...\Skype\Updater\Updater.exe` | svc / auto | Skype |
| `dbupdate` / `dbupdatem` | `...\Dropbox\Update\DropboxUpdate.exe /svc|/medsvc` | svc auto/manual | Dropbox |
| `gupdate` / `gupdatem` | `...\Google\Update\GoogleUpdate.exe /svc|/medsvc` | svc auto/manual | Google |
| `AdobeARMservice` | `...\Adobe\ARM\1.0\armsvc.exe` | svc / auto | Acrobat Reader DC |
| `InstallerService` | `...\TrueKey\Mcafee.TrueKey.InstallerService.exe` | svc / auto | True Key |
| `TrueKey` / `TrueKeyScheduler` / `TrueKeyServiceHelper` | `...\TrueKey\McAfee.TrueKey.*` | svc / auto | True Key |
| `IntelBCAsvc` | `...\Intel\BCA\pabeSvc64.exe` | svc / auto | Intel BCA |
| `McComponentHostService` | `...\McAfee Security Scan\3.11.266\McCHSvc.exe` | svc / manual | McAfee Security Scan |
| `ose64` | `...\Source Engine\OSE.EXE` | svc / manual | Office 2013 |
| `VBoxGuest` / `VBoxMouse` / `VBoxSF` / `VBoxService` / `VBoxVideoW8` | `system32\DRIVERS\VBox*` / `VBoxService.exe` | drivers+svc | VirtualBox Guest Additions (VM guest) |

The TeamViewer service install is corroborated by `System.evtx` EventID 7045 (ledger seq 57,
2016-06-21 00:57:41 UTC) and by `Users/Hunter/AppData/Local/Temp/TeamViewer/TV11Install.log`
(ledger seq 18).

## 5. Provenance summary (who installed what, when)

- **OS** Windows 8.1 Enterprise (build 9600) was installed/activated 2016-06-21 08:37:45 UTC and is
  registered to **Hunter**. Computer name ended as `4orensics` (renamed from `WIN-A9KKHBKS7E6` →
  `WIN-0Q61PC073B6` → `4orensics`; ledger seq 58–59).
- **Hunter** (SID `S-1-5-21-2489440558-2754304563-710705792-1001`) is the only interactive user and
  a local Administrator. Every HKLM install was therefore performed from Hunter's session (single-user
  machine), and the installers live in Hunter's `Downloads` — tying the download to the account.
- The install activity falls into **two bursts** (all UTC):
  1. **2016-06-20 23:48 – 2016-06-21 02:06** — baseline business/remote tooling: McAfee Security
     Scan, Microsoft Office 2013, TeamViewer, Google Drive/Dropbox, FTK Imager, plus PuTTY/PSCP/SSH.
  2. **2016-06-21 08:41 – 11:55** — the bulk of the toolkit: Chrome, Skype, 7-Zip, Notepad++,
     Wireshark, WinPcap, USBPcap, Java, Tor Browser, Eraser, Hash Suite, Nmap, Sysinternals,
     Burp Suite, OllyDbg, Python 2.7/3.5, CCleaner, BCWipe, PuTTY (run), then later FTK Imager (run
     13:18 UTC) and CCleaner (run 12:28 UTC).
- **Notable security-relevant set installed by Hunter**: TeamViewer (remote control), Tor Browser
  (anonymity), Nmap + Wireshark + WinPcap + USBPcap + Burp Suite (network recon/sniffing),
  OllyDbg (debugging), PuTTY/PSCP/SSH (remote shell), and BCWipe + Eraser + CCleaner
  (secure-delete / evidence-wiping). FTK Imager + Hash Suite (forensic imaging/hashing) were also
  present in the same profile.

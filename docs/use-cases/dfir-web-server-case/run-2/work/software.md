# Installed Software and Provenance — seat sf6df05

Evidence source of truth:
- Disk image `inputs/s4a-challenge4`, NTFS partition at offset 2048 (`mmls`), inodes cited as `icat -o 2048 inputs/s4a-challenge4 <inode>`.
- Registry hives extracted to `work/extracted/registry/` (SOFTWARE = inode 18496, SYSTEM = inode 18499), parsed with regipy 6.3.0.
- Memory image `inputs/memdump.mem` via catalog `catalog/memdump.mem/*` (vol windows.info / pslist / cmdline).

## OS baseline (not attacker)

`SOFTWARE\Microsoft\Windows NT\CurrentVersion`:

| Value | Data |
| --- | --- |
| ProductName | Windows Server (R) 2008 Standard |
| EditionID | ServerStandard |
| CurrentVersion / CurrentBuild | 6.0 / 6001 |
| CSDVersion | Service Pack 1 |
| BuildLabEx | 6001.18000.x86fre.longhorn_rtm.080118-1840 |
| SystemRoot / PathName | C:\Windows |
| InstallDate (unix) | 1440399163 = 2015-08-24 06:52:43 UTC |

32-bit (x86), PAE kernel (`catalog/memdump.mem/windows.info.txt`: Is64Bit False, IsPAE True, NTBuildLab 6001...longhorn). This is a Windows Server 2008 Standard SP1 x86 web server.

## Installed software (Uninstall registry) — none by the attacker

Full `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` (13 subkeys). The only real third-party entries:

| Key | DisplayName | Version | Publisher | InstallDate | Key last-write |
| --- | --- | --- | --- | --- | --- |
| xampp | XAMPP | 5.6.11-1 | Bitnami | 1440366248 (=2015-08-23 21:44:08 UTC) | 2015-08-23 21:44:08 |
| Oracle VM VirtualBox Guest Additions | Oracle VM VirtualBox Guest Additions | 4.3.30.0 | Oracle Corporation | — | 2015-08-24 07:14:15 |
| {FF66E9F6-83E7-3A3E-AF14-8DE9A809A6A4} | Microsoft Visual C++ 2008 Redistributable - x86 | 9.0.21022 | Microsoft Corporation | 20150823 | 2015-08-23 21:43:54 |

The other 10 keys are Windows built-in components (AddressBook, Connection Manager, DirectDrawEx, Fontcore, IE40, IE4Data, IE5BAKEX, IEData, MobileOptionPack, SchedulingAgent) whose keys carry the OS install-time last-write of 2008-01-19 11:40:26.

There is no WOW6432Node Uninstall branch (32-bit OS). No suspicious/unknown Uninstall entry exists — the attacker registered **no** software through the installer/Uninstall mechanism.

## Software components on disk and their provenance

### XAMPP 5.6.11-1 (Apache/MySQL/PHP stack) — administrator, NOT attacker

- Uninstall key `xampp` (above): version 5.6.11-1, InstallDate 2015-08-23 21:44:08 UTC.
- Installer left on the admin desktop: `Users/Administrator/Desktop/xampp-win32-5.6.11-1-VC11-installer.exe` (inode 12911, 114,155,808 bytes; created 2015-08-23 19:36:11, accessed 2015-08-23 21:40:17 when run). => installed **by Administrator** from this installer on 2015-08-23.
- `C:\xampp` root directory created 2015-08-23 21:41:46 (inode 42729), last modified 21:44:18.
- Bundled components present (directories under `xampp/`): apache, mysql, php, phpMyAdmin, FileZillaFTP, MercuryMail, tomcat, perl, sendmail, webalizer, htdocs, cgi-bin, contrib, install, security, tmp, mailoutput, anonymous, mailtodisk, webdav, locale, licenses, img, src.
- `xampp/install/install.sys` (inode 59682, 115 bytes, 2015-08-23 21:44:03) is a text config written by the XAMPP installer: `DIR = C:\xampp`, `xampp = 5.6.11`, `server = 1.8.0` — a normal XAMPP install artifact, **not** a driver despite the `.sys` extension.
- Running at capture time (`catalog/memdump.mem/pslist.txt`): xampp-control.exe (2768), httpd.exe (2796, 2880), mysqld.exe (2804), FileZillaServer.exe (2856).

### DVWA 1.3 (Damn Vulnerable Web Application) — administrator target app, NOT attacker

- `xampp/htdocs/DVWA` (inode 12859) created 2015-08-23 21:52:15 UTC — ~8 min after XAMPP, same day, before the attack (2015-09-03).
- Version file `xampp/htdocs/DVWA/docs/DVWA_v1.3.pdf` (inode 12864).
- DVWA is a deliberately vulnerable PHP/MySQL app; here it is the company website / target. It is the only custom app added to the stock XAMPP `htdocs` (which otherwise contains only dashboard, img, webalizer, xampp, index.php, applications.html, bitnami.css, favicon.ico).
- Provenance: installed by the same administrator during the 2015-08-23 image build (it predates the attacker's 2015-09-03 activity by 11 days).

### VirtualBox Guest Additions 4.3.30 — hypervisor tools, NOT attacker

- Uninstall key + `Program Files/Oracle/VirtualBox Guest Additions` (inode 42208). Driver files VBoxGuest.sys/VBoxMouse.sys/VBoxVideo.sys, `VBoxService.exe`, `VBoxTray.exe`.
- The box is a VirtualBox VM; `VBoxService.exe` and `VBoxTray.exe` are running at capture (`pslist.txt`). Installer log `install_drivers.log` (inode 42243).

### Microsoft Visual C++ 2008 Redistributable x86 9.0.21022 — prerequisite, NOT attacker

- Uninstall key `{FF66E9F6-...}` InstallDate 20150823; key last-write 2015-08-23 21:43:54.
- Installer artifacts dropped to `C:\` by the XAMPP installer: `VC_RED.MSI` (inode 59744, 232,960 B, run 2015-08-23 21:43:53) and `install.exe` (inode 59742, 562,688 B, run 2015-08-23 21:43:53). Both have original mtime 2007-11-07 (the MS package build date).

### IIS 7 (Windows component) — NOT attacker

- `inetpub/` (inode 42386) present; SYSTEM hive services `WAS` (iissvcs), `AppHostSvc`, `InetInfo`, `ASP.NET*` with last-write 2015-08-23 21:25 (installed with the OS / role). IIS is a Windows Server role, not a third-party install. The actually-serving web stack at capture is XAMPP/Apache (httpd.exe), not IIS.

## Service/driver installs (SYSTEM hive, `ControlSet001\Services`)

Only one service references a file that did not ship with the OS or the above vendors:

- `ad_driver` — DisplayName **"AccessData Driver"**, Type=1 (kernel driver), Start=3 (manual), ErrorControl=1, ImagePath `\??\C:\Users\ADMINI~1\AppData\Local\Temp\ad_driver.sys`.
- The file `Users/Administrator/AppData/Local/Temp/ad_driver.sys` (inode 60402, 20,208 B) was created 2015-09-03 10:04:05 UTC — the exact moment of memory capture.
- **This is NOT attacker software.** `ad_driver.sys` with display name "AccessData Driver" is the live-imaging driver of AccessData **FTK Imager**. The memory image confirms the responder's tool was running: `FTK Imager.exe` (PID 2120) launched 2015-09-03 10:03:37 from `\\Vboxsvr\101\FTK-Imager\FTK Imager.exe` (a VirtualBox host shared folder). The team dropped ad_driver.sys and registered `ad_driver` to obtain raw disk access for the forensic image.

No other non-OS service/driver was found. The 368 services are OS/VBox/XAMPP-related (Apache/MySQL/FileZilla are started via `xampp-control.exe` / `service.exe`, not as Windows services in this dump).

## Attacker-added "software" (tools dropped, NOT installed via installer)

The attacker installed nothing through Windows installers/Uninstall. What they left is dropped tooling (detailed by the leftovers seat; listed here for the Q4 provenance answer):

- Web shells under `xampp/htdocs/DVWA/` (all 2015-09-03):
  - `hackable/uploads/phpshell.php` (inode 62330, 07:10:15)
  - `webshells.zip` (inode 62331, 07:14:48) -> extracted `webshells/` (inode 62332, 07:14:51)
  - `c99.php` (inode 62333, 07:14:51; modified 07:20:45, 156,208 B)
  - `webshell.php` (inode 62334, 07:14:51)
  - `hackable/uploads/phpshell2.php` (inode 62337, 07:31:30)
  - `hackable/uploads/abc/` directory (inode 62335, 07:17:58)
  - temp copy `Users/Administrator/AppData/Local/Temp/c99 (2).php` (inode 62338, 07:20:14, deleted)

These are the attacker's PHP web shells uploaded through DVWA's file-upload vulnerability — tools, not installed software.

## Answers to Q4 (summary)

1. **Software installed on the box:** Windows Server 2008 Standard SP1 (x86), XAMPP 5.6.11-1 (Apache/MySQL/PHP/phpMyAdmin/FileZilla/MercuryMail/Tomcat/Perl/sendmail/webalizer), DVWA 1.3, Oracle VM VirtualBox Guest Additions 4.3.30, Microsoft Visual C++ 2008 Redistributable x86 9.0.21022, IIS 7 (role). Nothing else is registered in Uninstall.
2. **Installed by the attacker?** **No.** Every installed product predates the attack (installed 2015-08-23/24, i.e. ~11 days before the 2015-09-03 intrusion) and has clear administrator/OS provenance (XAMPP desktop installer, VC_RED.MSI, VBox installer log, OS InstallDate). The attacker used the pre-existing XAMPP+DVWA stack and only **uploaded PHP web shells** (plus the `abc` upload directory) — they did not install any software via the OS.
3. **One trap to avoid:** the `ad_driver` ("AccessData Driver") kernel service and `ad_driver.sys` in Temp are **the responder's FTK Imager imaging driver**, not attacker malware (memory shows FTK Imager.exe running from a VBox host share at capture).

## Evidence citations

- `catalog/s4a-challenge4/partitions.txt` — single NTFS partition at offset 2048.
- `work/extracted/registry/SOFTWARE` (= icat inode 18496) — `\Microsoft\Windows NT\CurrentVersion`, `\Microsoft\Windows\CurrentVersion\Uninstall`, `\...\Run` (only VBoxTray).
- `work/extracted/registry/SYSTEM` (= icat inode 18499) — `\Select` (Current=1), `\ControlSet001\Services\ad_driver` and full service list.
- `catalog/s4a-challenge4/p2048/timeline.csv` / `filelist.txt` — MAC times and inodes for XAMPP, DVWA, installers, and the dropped web shells.
- `catalog/memdump.mem/windows.info.txt`, `pslist.txt`, `cmdline.txt` — OS build, running processes (FTK Imager.exe, XAMPP stack, VBox), command lines.

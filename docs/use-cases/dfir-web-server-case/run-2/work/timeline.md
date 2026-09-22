# Master Timeline — Case ALIHADI-C1 (Challenge #1 "Web Server")

Maintained by `sf6df04` (timeline & ledger seat). All times are **UTC** unless noted.
Local server time is **UTC−7 (PDT)**: Apache logs stamp `-0700`; SYSTEM hive timezone =
Pacific Standard Time, `ActiveTimeBias=420` (sf6df01). The MFT MAC timeline
(`catalog/.../timeline.csv`, `mactime -d -y`) and Volatility output are already UTC.
`-0700` log timestamps below were converted by adding 7h.

## Sources & normalization

| Source | File | Time base | Notes |
| --- | --- | --- | --- |
| MFT MAC timeline | `catalog/s4a-challenge4/p2048/timeline.csv` | UTC (`Z`) | 219,722 rows; `.acb/macb` flags are MACB |
| File list (inode proof) | `catalog/s4a-challenge4/p2048/filelist.txt` | — | `icat -o 2048 inputs/s4a-challenge4 <inode>` |
| Apache access log | `work/sf6df04/access.log` (extracted inode 59684) | `-0700` | attacker IP `192.168.56.102` |
| SAM / SYSTEM / NTUSER | `work/sf6df01/parsed/*` (sf6df01) | UTC | user creation / membership timestamps |
| Memory capture | `catalog/memdump.mem/windows.info.txt` | UTC | SystemTime = **2015-09-03 10:04:05** |
| Netscan / cmdline / pslist | `catalog/memdump.mem/netscan.txt`, `cmdline.txt`, `pslist.txt` | UTC | process/network at capture |

**System identity:** Windows **Server 2008** (build 6001, x86, PAE), NtProductServer.
Volume = NTFS (mft 786432, cluster 4096). VirtualBox guest, IP `192.168.56.101`.
Memory capture `2015-09-03 10:04:05 UTC`. Attacker = separate host `192.168.56.102`
(Linux, Firefox/Iceweasel 38; sqlmap UA observed).

## Key artifacts (attacker-created, inode proof)

| Artifact | Inode (`filelist.txt`) | First seen (UTC, `timeline.csv`) |
| --- | --- | --- |
| `xampp/htdocs/DVWA/hackable/uploads/phpshell.php` | 62330 | 2015-09-03 07:10:15 |
| `xampp/htdocs/DVWA/webshells.zip` | 62331 | 2015-09-03 07:14:48 |
| `xampp/htdocs/DVWA/webshells/` (dir) | 62332 | 2015-09-03 07:14:51 |
| `xampp/htdocs/DVWA/c99.php` | 62333 | 2015-09-03 07:14:51 |
| `xampp/htdocs/DVWA/webshell.php` | 62334 | 2015-09-03 07:14:51 |
| `xampp/htdocs/DVWA/hackable/uploads/abc` | 62335 | 2015-09-03 07:17:58 |
| `xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` | 62337 | 2015-09-03 07:31:30 |
| `Users/Administrator/AppData/Local/Temp/c99 (2).php` (deleted) | 62338 | 2015-09-03 07:20:14 |
| `Users/Administrator/data.txt` (content `hello`) | 60464 | 2015-09-02 09:32:42 |

Sequential inodes 62330–62338 show the web-shell cluster was dropped in one burst.

Note: `ad_driver.sys` (inode 60402) is **not** attacker malware — it is the **AccessData
Driver** (FTK Imager's live-imaging kernel driver), see the acquisition rows below.

## Timeline

| # | Date/Time (UTC) | Event | Source / evidence |
| --- | --- | --- | --- |
| 1 | 2008-01-19 | Windows Server 2008 (build 6001) OS files carry media timestamps (61,316 records); registry `InstallDate` = 2015-08-24 06:52:43 UTC. | `timeline.csv` 2008-01-19; `windows.info` NTBuildLab 6001; SOFTWARE hive `InstallDate` (sf6df05) |
| 2 | 2015-08-23 10:30 | System/services first sockets (boot/up). | `netscan.txt` Created 2015-08-23 10:30:05 |
| 3 | 2015-08-23 10:32 | XAMPP Apache + MySQL start (`apache/logs/httpd.pid`, `mysql/data/mysql.pid`). | `timeline.csv` |
| 4 | 2015-08-23 21:41 | XAMPP web content extracted under `/xampp/htdocs` (dashboard). | `timeline.csv` |
| 5 | 2015-08-23 21:46 | Administrator browses `localhost/dashboard` (IE7). | `access.log` 14:46 −0700 |
| 6 | 2015-08-23 21:52 | **DVWA v1.3 installed** (`/xampp/htdocs/DVWA`, config, PHPIDS). | `timeline.csv`; `access.log` 14:52 −0700 (`/dvwa/login.php`) |
| 7 | 2015-08-23 22:24 | **Attacker `192.168.56.102` first hits the site** (browses `/dashboard/`). | `access.log` 15:24 −0700 |
| 8 | 2015-08-24 (all day) | OS deployment finalization: `winsxs` 50,790 + `System32` 29,635 records + registry `InstallDate` 06:52:43 (Windows Server 2008 image). | `timeline.csv`; SOFTWARE hive (sf6df05) |
| 9 | 2015-09-02 05:58–06:05 | Administrator (IE on server) browses DVWA pages (`dvwaPage.js`, `192_168_56_102.htm`, `spanner.png`, login assets). | `timeline.csv` IE History + `$OrphanFiles` |
| 10 | 2015-09-02 08:35 | `xampp/php/logs/php_error_log` modified (PHP errors from attack traffic). | `timeline.csv` |
| 11 | 2015-09-02 08:44 | **PHPIDS intrusion log written** (`DVWA/external/phpids/.../phpids_log.txt`) — first IDS alert. | `timeline.csv` |
| 12 | 2015-09-02 09:00:57 | Successful local **Administrator** logon (Security recs 479–482). | `work/sf6df01/parsed/accounts_summary.json` (sf6df01) |
| 13 | 2015-09-02 09:01:02 | `CompMgmtLauncher.exe` (Computer Management GUI) launched in Administrator session. | NTUSER UserAssist (sf6df01) |
| 14 | 2015-09-02 09:05:06 | **Local account `user1` created** (SAM RID 1005). | `work/sf6df01/parsed/sam_users.tsv` (sf6df01) |
| 15 | 2015-09-02 09:05:25 | **Local account `hacker` created** (SAM RID 1006). | `work/sf6df01/parsed/sam_users.tsv` (sf6df01) |
| 16 | 2015-09-02 09:18:09 | `user1` added to **Users** and **Remote Desktop Users**. | `work/sf6df01/parsed/sam_memberships.tsv` (sf6df01) |
| 17 | 2015-09-02 09:19:24 | `hacker` added to **Users** and **Remote Desktop Users**. | `work/sf6df01/parsed/sam_memberships.tsv` (sf6df01) |
| 18 | 2015-09-02 09:28:30 | `cmd.exe` first appears in Administrator UserAssist (command line used). | NTUSER UserAssist (sf6df01) |
| 19 | 2015-09-02 09:32 | **`Users/Administrator/data.txt` created then modified** — content is `hello` (attacker test/note file). | `timeline.csv`; inode 60464; icat content |
| 20 | 2015-09-02 11:15–11:16 | **sqlmap SQL injection** run against `/vulnerabilities/sqli/` (UNION/error/blind payloads, `0x7178717871` marker, UA `sqlmap/1.0-dev-nongit-20150902`). | `access.log` 04:15–04:16 −0700 |
| 21 | 2015-09-02 11:19:30–32 | ~190 PHP session files created in `/xampp/tmp` (sqlmap/attacker interacting with DVWA); sqlmap temp shells `tmpbiwuc.php`/`tmpbrjvl.php` probed via SQLi file-write. | `timeline.csv`; `access.log` |
| 22 | 2015-09-03 06:49 | Administrator IE history `MSHist012015090220150903` + session `sess_gt9jmpq3…`. | `timeline.csv` |
| 23 | 2015-09-03 06:59 | `/xampp/htdocs` modified. | `timeline.csv` |
| 24 | 2015-09-03 07:00:16 | Attacker POST to `/dvwa/vulnerabilities/xss_s/` (stored XSS). | `access.log` 00:00:16 −0700 |
| 25 | 2015-09-03 07:03:41 | Server IE loads `192_168_56_102[1].htm` and `xss_s[2].htm` — stored-XSS payload fetched from attacker host; DVWA session `sess_gt9jmpq3…` (username `admin`). | `timeline.csv` IE cache; session (sf6df03) |
| 26 | 2015-09-03 07:04:50–52 | DVWA MySQL tables modified (`dvwa/guestbook.ibd`, `dvwa/users.ibd`, `ibdata1`) — SQL injection writes. | `timeline.csv` |
| 27 | 2015-09-03 07:08:35 | Attacker opens DVWA upload page. | `access.log` 00:08:35 −0700 |
| 28 | 2015-09-03 07:10:15 | **`phpshell.php` uploaded** to `hackable/uploads/` (DVWA file-upload flaw). | `timeline.csv`; `access.log` POST upload 00:10:15; inode 62330 |
| 29 | 2015-09-03 07:14:48 | **`webshells.zip` dropped** in `/DVWA/`. | `timeline.csv`; inode 62331 |
| 30 | 2015-09-03 07:14:51 | **`webshells/` dir + `c99.php` + `webshell.php` created** (c99 web shell family). | `timeline.csv`; inodes 62332/62333/62334 |
| 31 | 2015-09-03 07:15:58–07:18:58 | Attacker repeatedly requests `phpshell.php` (web shell in use). | `access.log` |
| 32 | 2015-09-03 07:17:58 | File `abc` created in `hackable/uploads/`. | `timeline.csv`; inode 62335 |
| 33 | 2015-09-03 07:19:32 | `php_error_log` written; attacker first loads `c99.php`. | `timeline.csv`; `access.log` 00:19:32 |
| 34 | 2015-09-03 07:20:14 | `c99 (2).php` saved under `Administrator\...\Temp` (deleted) — c99 shell copy. | `timeline.csv`; inode 62338 |
| 35 | 2015-09-03 07:20:45 | `c99.php` modified (shell configured/used). | `timeline.csv` |
| 36 | 2015-09-03 07:21:28 & 07:21:37 | **Command execution via `c99.php?act=cmd`** (POST). | `access.log` 00:21:28/37 −0700 |
| 37 | 2015-09-03 07:31:30 | **`phpshell2.php` uploaded** to `hackable/uploads/` — a reverse-shell stub dialing back to `192.168.56.102:4545`. | `timeline.csv`; `access.log` POST upload 00:31:30; inode 62337 |
| 38 | 2015-09-03 07:31:54 | Attacker requests `phpshell2.php`. | `access.log` 00:31:54 −0700 |
| 39 | 2015-09-03 07:34:51 | Apache `access.log`/`error.log` written (attack traffic logged). | `timeline.csv` |
| 40 | 2015-09-03 10:03:01 | `administrator@localhost[1].txt` cookie — c99 shell authenticated session. | `timeline.csv` |
| 41 | 2015-09-03 10:03:37 | **FTK Imager started** from `\\Vboxsvr\101\FTK-Imager\FTK Imager.exe` (live acquisition tooling). | `pslist.txt`; `cmdline.txt` PID 2120 |
| 42 | 2015-09-03 10:04:05 | **`ad_driver.sys` = AccessData Driver** (FTK Imager live-imaging kernel driver) created — acquisition tooling, **not attacker**. | `timeline.csv`; inode 60402; SYSTEM `Services\ad_driver` (sf6df05) |
| 43 | 2015-09-03 10:04:05 | **Memory captured** (SystemTime). | `windows.info` |
| 44 | 2015-09-12 17:42–18:24 | Post-incident system activity: drivers re-registered (`intelppm`, `CmBatt`, `battc`), `RegBack` hives written, WMI rebuild — consistent with reboot/imaging. | `timeline.csv` |
| 45 | 2015-09-13 04:18 | `bootstat.dat`, `pagefile.sys`, `SCM.EVM` touched (shutdown/boot). | `timeline.csv` |

## Attack summary (for the report)

1. **Vector** — the public site is XAMPP running **DVWA v1.3** (intentionally vulnerable app). The
   attacker (`192.168.56.102`, Linux) enumerates and exploits it from `2015-08-23 22:24` onward.
2. **Techniques seen in `access.log`** — **SQL injection automated with sqlmap** (2,269 hits on
   `/vulnerabilities/sqli/`; UNION/error/blind payloads, `0x7178717871` marker, UA
   `sqlmap/1.0-dev-nongit-20150902`; temp shells `tmpbiwuc.php`/`tmpbrjvl.php` via SQLi file-write),
   command injection (`/vulnerabilities/exec/`, 24 POST), reflected+stored XSS (`xss_r`/`xss_s`),
   file inclusion (`fi/`), brute force, CSRF, and file upload (`upload/`).
3. **Account take-over** — a local **Administrator** logon at `09:00:57` on 09-02 was used to open
   Computer Management and add two local accounts: **`user1`** and **`hacker`**, then grant them
   **Remote Desktop Users** membership (`09:05`–`09:19`). See Q2 / `work/accounts-registry-findings.md`.
4. **Persistence/foothold** — file-upload flaw used to drop `phpshell.php`, then `c99.php`,
   `webshell.php`, `webshells.zip`, `phpshell2.php` (inodes 62330–62337), then interactive
   command execution through the c99 shell; `phpshell2.php` is a reverse shell to `192.168.56.102:4545`.
5. **Acquisition, not attacker** — `ad_driver.sys` (inode 60402) is the AccessData/FTK Imager
   live-imaging driver loaded at 10:04:05, the capture instant (SYSTEM `Services\ad_driver` =
   "AccessData Driver"). There is no kernel-driver privilege-escalation by the attacker.

## Notes / caveats

- `timeline.csv` rows with date `0000-00-00T00:00:00Z` are deleted files whose MAC times were not
  recovered (e.g. `$OrphanFiles/*`); they are evidence of browser cache, not separate events.
- The 2015-09-12/13 tail postdates the memory capture; it is interpreted as examiner/system
  reboot-and-image activity, not attacker activity (attacker last confirmed at 10:04:05 on 09-03).
- `c99.php`/`webshell.php` carry older embedded file dates (2012/2014 from the zip), but their NTFS
  `$FILE_NAME` create/change times of 2015-09-03 07:14:51 prove they were introduced on this host
  then (sf6df00).

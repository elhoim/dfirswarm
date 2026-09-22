# Disk triage notes — sf4b200

## Scope

Assigned seat: disk triage / bonus attacker-added paths.

Primary sources used:
- `catalog/s4a-challenge4/partitions.txt`
- `catalog/s4a-challenge4/p2048/fsstat.txt`
- `catalog/s4a-challenge4/p2048/filelist.txt`
- `catalog/s4a-challenge4/p2048/timeline.csv`
- Apache access log from inode `59684` via `icat -o 2048 inputs/s4a-challenge4 59684`

## Partition and filesystem triage

The disk image contains a single Windows NTFS partition starting at sector 2048 and ending at sector 5,242,6751.

Evidence:
- `catalog/s4a-challenge4/partitions.txt`
- Command: `cat catalog/s4a-challenge4/partitions.txt`

Key facts from NTFS header:
- Filesystem type: `NTFS`
- Volume serial: `7A287C57287C13FB`
- Root directory inode: `5`
- Sector size: `512`
- Cluster size: `4096`

Evidence:
- `catalog/s4a-challenge4/p2048/fsstat.txt`
- Command: `cat catalog/s4a-challenge4/p2048/fsstat.txt`

## Disk-level attack window visible in file activity

The clearest attacker-controlled on-disk activity is on 2015-09-03 between about 07:10Z and 07:32Z, when multiple PHP web shells and related directories were created under `xampp/htdocs/DVWA`.

Correlated evidence:
- `catalog/s4a-challenge4/p2048/timeline.csv`
- `icat -o 2048 inputs/s4a-challenge4 59684 | grep -nE 'phpshell|c99|upload|mkdir%20abc'`

Important correlated events:
- `2015-09-03T07:10:15Z` — `xampp/htdocs/DVWA/hackable/uploads/phpshell.php` created (inode `62330`)
- `2015-09-03T07:14:48Z` — `xampp/htdocs/DVWA/webshells.zip` created (inode `62331`)
- `2015-09-03T07:14:57Z` — `xampp/htdocs/DVWA/webshells/` and `xampp/htdocs/DVWA/webshell.php` present (inodes `62332`, `62334`)
- `2015-09-03T07:17:58Z` — attacker-created directory `xampp/htdocs/DVWA/hackable/uploads/abc` appears (inode `62335`)
- `2015-09-03T07:20:45Z` — `xampp/htdocs/DVWA/c99.php` written (inode `62333`)
- `2015-09-03T07:31:30Z` — `xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` created (inode `62337`)

The Apache access log ties these files to remote activity from `192.168.56.102`, including:
- `POST /dvwa/vulnerabilities/upload/` at `03/Sep/2015:00:10:15 -0700`
- `GET /dvwa/hackable/uploads/phpshell.php?cmd=dir`
- `GET /dvwa/hackable/uploads/phpshell.php?cmd=mkdir abc`
- `GET /dvwa/c99.php`
- `POST /dvwa/c99.php?act=cmd`
- second `POST /dvwa/vulnerabilities/upload/` at `03/Sep/2015:00:31:30 -0700`
- `GET /dvwa/hackable/uploads/phpshell2.php`

## Bonus: attacker-added directories and files with inode proof

These are high-confidence attacker-added paths preserved in the image.

| Path | Inode | First visible time (UTC) | Why high confidence | Evidence |
| --- | --- | --- | --- | --- |
| `xampp/htdocs/DVWA/hackable/uploads/phpshell.php` | `62330-128-3` | `2015-09-03T07:10:15Z` | one-line command web shell; uploaded through DVWA and then executed | `grep 'phpshell.php' catalog/s4a-challenge4/p2048/filelist.txt`; `grep '62330-128-3' catalog/s4a-challenge4/p2048/timeline.csv`; `icat -o 2048 inputs/s4a-challenge4 62330`; `icat -o 2048 inputs/s4a-challenge4 59684 | grep '03/Sep/2015:00:10:15 -0700'` |
| `xampp/htdocs/DVWA/webshells.zip` | `62331-128-1` | `2015-09-03T07:14:48Z` | archive named `webshells.zip` containing two web shells | `grep 'webshells.zip' catalog/s4a-challenge4/p2048/filelist.txt`; `grep '62331-128-1' catalog/s4a-challenge4/p2048/timeline.csv`; `icat -o 2048 inputs/s4a-challenge4 62331` |
| `xampp/htdocs/DVWA/webshells/` | `62332-144-1` | `2015-09-03T07:14:51Z` | directory created immediately after `webshells.zip` appears | `grep 'xampp/htdocs/DVWA/webshells$' catalog/s4a-challenge4/p2048/filelist.txt`; `grep '62332-144-1' catalog/s4a-challenge4/p2048/timeline.csv` |
| `xampp/htdocs/DVWA/webshell.php` | `62334-128-1` | `2015-09-03T07:14:57Z` | extracted one-line command web shell | `grep 'xampp/htdocs/DVWA/webshell.php' catalog/s4a-challenge4/p2048/filelist.txt`; `grep '62334-128-1' catalog/s4a-challenge4/p2048/timeline.csv`; `icat -o 2048 inputs/s4a-challenge4 62334` |
| `xampp/htdocs/DVWA/hackable/uploads/abc` | `62335-144-1` | `2015-09-03T07:17:58Z` | access log shows attacker ran `mkdir abc` through `phpshell.php` | `grep 'xampp/htdocs/DVWA/hackable/uploads/abc$' catalog/s4a-challenge4/p2048/filelist.txt`; `grep '62335-144-1' catalog/s4a-challenge4/p2048/timeline.csv`; `icat -o 2048 inputs/s4a-challenge4 59684 | grep 'mkdir%20abc'` |
| `xampp/htdocs/DVWA/c99.php` | `62333-128-3` | `2015-09-03T07:20:45Z` | full c99 PHP web shell; requested and used from the attacker host | `grep 'xampp/htdocs/DVWA/c99.php' catalog/s4a-challenge4/p2048/filelist.txt`; `grep '62333-128-3' catalog/s4a-challenge4/p2048/timeline.csv`; `icat -o 2048 inputs/s4a-challenge4 62333 | sha256`; `icat -o 2048 inputs/s4a-challenge4 59684 | grep '/dvwa/c99.php'` |
| `xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` | `62337-128-4` | `2015-09-03T07:31:30Z` | second uploaded PHP shell; content is reverse-shell style code with callback to `192.168.56.102:4545` | `grep 'phpshell2.php' catalog/s4a-challenge4/p2048/filelist.txt`; `grep '62337-128-4' catalog/s4a-challenge4/p2048/timeline.csv`; `icat -o 2048 inputs/s4a-challenge4 62337`; `icat -o 2048 inputs/s4a-challenge4 59684 | grep 'phpshell2.php'` |

### Content hashes for preserved attacker files

Computed with `icat -o 2048 inputs/s4a-challenge4 <inode> | sha256`.

| Path | Inode | SHA-256 |
| --- | --- | --- |
| `xampp/htdocs/DVWA/hackable/uploads/phpshell.php` | `62330` | `08245eeb54a5d973b20a82e03d82556a693f5c63310e01a2f492b78dda132a99` |
| `xampp/htdocs/DVWA/webshells.zip` | `62331` | `bdae3070d4d9a483a8f08db4d16c9100723dea6fba3a7e53cbf249851bad99ee` |
| `xampp/htdocs/DVWA/c99.php` | `62333` | `4320d95cc2fe61e0b862756f8c4ffb251c7d1391e2f6841887c3dc765ba0369c` |
| `xampp/htdocs/DVWA/webshell.php` | `62334` | `794f25b47b4773f6749b0f607f906e5181545eca7835a927c9a197c94c3fd74b` |
| `xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` | `62337` | `2e77d2db6ffba49be0ccf3850ee23de61b289d1e2dfee5b79e4d04563c42a1f7` |

### Extracted meaning from attacker file contents

- Inode `62330` / `phpshell.php` contents:
  - `<?php system($_GET["cmd"]); ?>`
- Inode `62334` / `webshell.php` contents:
  - `<?php system($_GET["cmd"]); ?>`
- Inode `62337` / `phpshell2.php` contents:
  - PHP reverse-shell style code with callback target `192.168.56.102:4545`
- Inode `62331` / `webshells.zip` contents:
  - `c99.php`
  - `webshell.php`

Evidence commands:
- `icat -o 2048 inputs/s4a-challenge4 62330 | head`
- `icat -o 2048 inputs/s4a-challenge4 62334 | head`
- `icat -o 2048 inputs/s4a-challenge4 62337 | head`
- `icat -o 2048 inputs/s4a-challenge4 62331 > /tmp/webshells.zip && python3 - <<'PY' ... zipfile ... PY`

## Additional disk artifacts around the attack window

### Automated activity visible in `xampp/tmp`

The NTFS timeline shows a burst of `795` distinct PHP session files under `/xampp/tmp/` between `2015-09-02T11:19:00Z` and `2015-09-02T11:19:32Z`. I treat this as strong evidence of heavy automated interaction with the DVWA site rather than normal manual browsing.

Evidence:
- `catalog/s4a-challenge4/p2048/timeline.csv`
- Command used to count distinct session paths:
  - `python3 - <<'PY' ... if name.startswith('/xampp/tmp/sess_') and dt.startswith('2015-09-02T11:19') ... PY`

This supports the broader attack narrative, but these are application session artifacts rather than good bonus-list entries.

### Deleted attacker staging file in Administrator Temp

The image also preserves a deleted file entry for `Users/Administrator/AppData/Local/Temp/c99 (2).php` with inode `62338-128-4`, size `153275` bytes, at `2015-09-03T07:20:14Z`.

Why it matters:
- the name matches the `c99` web shell family already preserved as `xampp/htdocs/DVWA/c99.php`
- its timestamp falls immediately before the on-disk write of `xampp/htdocs/DVWA/c99.php` at `2015-09-03T07:20:45Z`
- it is deleted, so I would cite it as an attacker staging/transient artifact rather than as a preserved bonus-list file

Evidence:
- `grep 'Users/Administrator/AppData/Local/Temp/c99 (2).php' catalog/s4a-challenge4/p2048/filelist.txt`
- `grep '62338-128-4' catalog/s4a-challenge4/p2048/timeline.csv`
- `grep 'c99 (2).php' catalog/s4a-challenge4/p2048/bodyfile.txt`

## Lower-confidence / needs corroboration

These may also be attacker-created, but I would not use them in the final bonus list without corroboration from another source.

| Path | Inode | Time | Note |
| --- | --- | --- | --- |
| `Users/Administrator/data.txt` | `60464-128-1` | `2015-09-02T09:32:42Z` | contains only `hello`; could be a command-execution test file |

Likely non-attacker artifact:

| Path | Inode | Time | Note |
| --- | --- | --- | --- |
| `Users/Administrator/AppData/Local/Temp/ad_driver.sys` | `60402-128-4` | `2015-09-03T10:04:05Z` | now corroborated by sf4b205 and sf4b202 as AccessData FTK Imager acquisition tooling, not attacker malware |

Evidence commands:
- `grep 'Users/Administrator/data.txt' catalog/s4a-challenge4/p2048/filelist.txt`
- `grep '60464-128-1' catalog/s4a-challenge4/p2048/timeline.csv`
- `icat -o 2048 inputs/s4a-challenge4 60464`
- `grep 'Users/Administrator/AppData/Local/Temp/ad_driver.sys' catalog/s4a-challenge4/p2048/filelist.txt`
- `grep '60402-128-4' catalog/s4a-challenge4/p2048/timeline.csv`
- `icat -o 2048 inputs/s4a-challenge4 60402 | strings | head`

## Notes for report assembly

High-confidence conclusions this seat can support now:
1. The image holds clear evidence of web application exploitation followed by attacker upload and use of PHP web shells.
2. The attacker-controlled files were placed under `xampp/htdocs/DVWA`, and their creation times align with corresponding HTTP requests from `192.168.56.102`.
3. The strongest bonus-list entries are the seven preserved `DVWA` web-shell artifacts listed above because each has inode proof and on-disk timestamps, and most also have matching access-log activity.
4. The image also preserves a deleted staging artifact, `Users/Administrator/AppData/Local/Temp/c99 (2).php` (inode `62338-128-4`), immediately preceding the surviving `c99.php` write.
5. The `795` short-lived `xampp/tmp/sess_*` files created in about 32 seconds on 2015-09-02 are consistent with automated web interaction during the attack, not normal user browsing.

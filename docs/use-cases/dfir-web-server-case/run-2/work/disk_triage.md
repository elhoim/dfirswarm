# Disk triage — sf6df00

## Scope

Seat focus from `SWARM.md`: partition/filesystem triage, file list review, attack-window disk changes, and the bonus list of attacker-added paths with inode proof.

## Image layout

### Partitioning

Evidence: `catalog/s4a-challenge4/partitions.txt`

- DOS partition table.
- One meaningful filesystem partition:
  - start sector `2048`
  - end sector `52426751`
  - length `52424704` sectors
  - type `NTFS / exFAT (0x07)`
- Small unallocated ranges before and after the partition are just the usual table/alignment gaps.

### Filesystem

Evidence: `catalog/s4a-challenge4/p2048/fsstat.txt`

- Filesystem type: `NTFS`
- Volume serial: `7A287C57287C13FB`
- NTFS root directory inode: `5`
- Sector size: `512`
- Cluster size: `4096`
- Total sector range inside the filesystem: `0 - 52424702`

## High-level catalog observations

Evidence:
- `catalog/s4a-challenge4/p2048/filelist.txt`
- `catalog/s4a-challenge4/p2048/bodyfile.txt`
- `catalog/s4a-challenge4/p2048/timeline.csv`

- `filelist.txt`: `68,332` paths
- `bodyfile.txt`: `134,075` rows
- `timeline.csv`: `219,722` rows
- Timestamp distribution is heavily concentrated in `2015`, with a notable cluster around early September 2015.

## Candidate attack windows from disk artifacts

### 2015-09-02: pre-webshell attacker activity visible on disk

Evidence:
- `catalog/s4a-challenge4/p2048/timeline.csv`
- `catalog/s4a-challenge4/p2048/filelist.txt`
- `catalog/s4a-challenge4/p2048/bodyfile.txt`
- `icat -o 2048 inputs/s4a-challenge4 60464-128-1`
- peer corroboration from `sf6df03` / `sf6df04` that Apache `access.log` on 2015-09-02 shows `sqlmap/1.0-dev-nongit-20150902`

Disk-visible changes on 2015-09-02 include:

| UTC time | Inode | Path | Notes |
| --- | --- | --- | --- |
| 2015-09-02T09:32:42Z | `60464-128-1` | `/Users/Administrator/data.txt` | created as a 5-byte file; content extracted with `icat` is `hello` |
| 2015-09-02T09:32:47Z | `60464-128-1` | `/Users/Administrator/data.txt` | content/metadata update 5 seconds later |
| 2015-09-02T11:15:40Z onward | `60479-128-1` and many following inodes | `/xampp/tmp/sess_*` | large burst of PHP session files under XAMPP temp during the sqlmap attack window |

Interpretation:

- The `data.txt` note is consistent with an attacker test file or staging artifact in the Administrator profile.
- The burst of new `/xampp/tmp/sess_*` files around `2015-09-02 11:15Z–11:16Z` matches the web attack wave that peers tied to sqlmap in Apache logs.
- These 2015-09-02 artifacts show active intrusion behavior on disk **before** the 2015-09-03 web-shell drop.

### 2015-09-03: earliest clearly attacker-linked persistent web-shell activity

Evidence:
- `catalog/s4a-challenge4/p2048/timeline.csv`
- `catalog/s4a-challenge4/p2048/filelist.txt`
- `icat -o 2048 inputs/s4a-challenge4 62330-128-3`
- `icat -o 2048 inputs/s4a-challenge4 62334-128-1`
- `icat -o 2048 inputs/s4a-challenge4 62337-128-4`
- `icat -o 2048 inputs/s4a-challenge4 62333-128-3 | sed -n '1,40p'`
- `icat -o 2048 inputs/s4a-challenge4 62331-128-1 > /tmp/webshells.zip && unzip -l /tmp/webshells.zip`

Observed cluster in `/xampp/htdocs/DVWA` and `Users/Administrator/AppData/Local/Temp`:

| UTC time | Inode | Path | Notes |
| --- | --- | --- | --- |
| 2015-09-03T07:10:15Z | `62330-128-3` | `/xampp/htdocs/DVWA/hackable/uploads/phpshell.php` | tiny PHP command shell, contents: `system($_GET["cmd"])` |
| 2015-09-03T07:14:48Z | `62331-128-1` | `/xampp/htdocs/DVWA/webshells.zip` | ZIP later shown to contain `c99.php` and `webshell.php` |
| 2015-09-03T07:14:51Z | `62332-144-1` | `/xampp/htdocs/DVWA/webshells` | directory created/extracted adjacent to the ZIP |
| 2015-09-03T07:14:57Z | `62334-128-1` | `/xampp/htdocs/DVWA/webshell.php` | another command shell, contents: `system($_GET["cmd"])` |
| 2015-09-03T07:17:58Z | `62335-144-1` | `/xampp/htdocs/DVWA/hackable/uploads/abc` | attacker-created directory under uploads |
| 2015-09-03T07:20:14Z | `62338-128-4` | `/Users/Administrator/AppData/Local/Temp/c99 (2).php` (deleted) | deleted temp copy of the c99 shell |
| 2015-09-03T07:20:45Z | `62333-128-3` | `/xampp/htdocs/DVWA/c99.php` | full `c99shell.php v.1.0 beta` web shell |
| 2015-09-03T07:31:30Z | `62337-128-4` | `/xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` | PHP reverse shell stub pointing to `192.168.56.102:4545` |

### Interpretation

This is the first tight, disk-backed cluster of **persistent attacker files** I found. There is earlier disk-visible attack activity on 2015-09-02 (`data.txt` and the sqlmap-correlated XAMPP session burst), but **2015-09-03 07:10Z onward is the best current candidate for the initial visible persistent post-exploitation window on disk**.

### Important timestamp nuance for the bonus question

Evidence:
- `catalog/s4a-challenge4/p2048/timeline.csv`
- `catalog/s4a-challenge4/p2048/bodyfile.txt`
- `icat -o 2048 inputs/s4a-challenge4 62331-128-1 > /tmp/webshells.zip && unzip -l /tmp/webshells.zip`

Some web-shell files preserve older embedded timestamps:

- `c99.php` shows an older MAC time of `2012-06-09T21:57:28Z`
- `webshell.php` shows an older MAC time of `2014-01-25T07:14:14Z`
- `webshells.zip` content listing also shows old internal file dates

However, the **NTFS $FILE_NAME creation/change events in 2015** prove when these artifacts were actually introduced onto this host:

- `webshells.zip` file record `62331-128-1` appears at `2015-09-03T07:14:48Z`
- `c99.php ($FILE_NAME)` record `62333-48-4` appears at `2015-09-03T07:14:51Z`
- `webshell.php ($FILE_NAME)` record `62334-48-3` appears at `2015-09-03T07:14:51Z`

So the older times are source-file/archive timestamps, not evidence that the server had those shells in 2012 or 2014.

## Bonus list — attacker-added paths with inode proof (current)

Current high-confidence attacker-added paths from disk triage. Each has direct path + inode proof in `catalog/s4a-challenge4/p2048/filelist.txt`, plus 2015 timing support from `timeline.csv` / `bodyfile.txt`.

| Inode | Path | Why it is attacker-added |
| --- | --- | --- |
| `60464-128-1` | `/Users/Administrator/data.txt` | created 2015-09-02 during the attack period; contents are the test string `hello` |
| `62330-128-3` | `/xampp/htdocs/DVWA/hackable/uploads/phpshell.php` | created 2015-09-03 07:10:15Z; direct PHP command shell |
| `62331-128-1` | `/xampp/htdocs/DVWA/webshells.zip` | created 2015-09-03 07:14:48Z; archive containing attacker web shells |
| `62332-144-1` | `/xampp/htdocs/DVWA/webshells` | created 2015-09-03 07:14:51Z immediately after the ZIP |
| `62333-128-3` | `/xampp/htdocs/DVWA/c99.php` | attacker web shell; 2015 NTFS creation/change despite older embedded file timestamp |
| `62334-128-1` | `/xampp/htdocs/DVWA/webshell.php` | simple command shell; 2015 NTFS creation/change despite older embedded file timestamp |
| `62335-144-1` | `/xampp/htdocs/DVWA/hackable/uploads/abc` | directory created after attacker `mkdir abc` activity |
| `62337-128-4` | `/xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` | created 2015-09-03 07:31:30Z; reverse shell to `192.168.56.102:4545` |
| `62338-128-4` | `/Users/Administrator/AppData/Local/Temp/c99 (2).php` (deleted) | deleted temp copy of c99 on 2015-09-03 07:20:14Z |

This list is high-confidence rather than exhaustive. I am treating the burst of `/xampp/tmp/sess_*` files as evidence of attack activity, but not listing them in the bonus answer because they are secondary application artifacts of exploitation rather than attacker-dropped files chosen by the intruder.

## Cross-seat corroboration from accounts findings

Evidence:
- `catalog/s4a-challenge4/p2048/filelist.txt`
- `catalog/s4a-challenge4/p2048/timeline.csv`
- `sf6df01` result post `threads/main/000043-sf6df01.md`

Disk triage is consistent with the accounts seat's finding that attacker-created users `user1` and `hacker` were added on 2015-09-02 but never materially used as interactive desktop users:

- No `Users/user1` or `Users/hacker` profile directories appear in the file list.
- The only user profile with attack-period filesystem churn is `Users/Administrator`.
- `Users/Administrator/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Command Prompt.lnk` (`42703-128-1`) shows a `m.c.` update at `2015-09-02T09:18:32Z`, which falls between the SAM group-add times reported by `sf6df01` (`09:18:09Z` for `user1`, `09:19:24Z` for `hacker`). This does not prove command-line user creation, but it does show the Administrator profile remained the active working context during that phase.

## Current disk-triage conclusion for the report

- The host contains one NTFS filesystem partition at sector 2048.
- Earliest visible attacker activity on disk precedes the persistent shell drop: account manipulation around 2015-09-02 09:00Z–09:19Z (from `sf6df01`), a small leftover/test file `Users/Administrator/data.txt` at 09:32Z, and a large sqlmap-correlated burst of `/xampp/tmp/sess_*` files starting at 11:15:40Z.
- The clearest attacker-added persistent files are the sequential-inode web-shell cluster `62330–62338` written under DVWA and the Administrator temp area on 2015-09-03 07:10Z–07:31Z.
- For the bonus answer, the strongest high-confidence attacker-added paths are the nine listed above; session files are evidence of exploitation activity but are application side effects rather than attacker-chosen dropped tools.

## Follow-up still in progress

- Keep correlating the reverse-shell IP `192.168.56.102:4545` with memory/network findings.
- Hand the timestamp nuance (old source MAC times versus 2015 NTFS creation/change) to the critic so the report does not misdate attacker files.

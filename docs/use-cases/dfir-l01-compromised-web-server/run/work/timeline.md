# AH-L01 merged timeline (UTC)

Guest timezone: **Europe/Brussels** (`/etc/timezone` inode 1831949). Apache logs use `+0200` (CEST). Auth/syslog are guest local CEST. Convert local → UTC by **−2 hours**. TSK `fls -l`/`istat` on the examiner host print **+03**; convert those by **−3 hours** to UTC (same instant as Apache +0200). FTK CSV is already UTC.

Sources: `ledger/ledger.md`, `work/extracted/auth.log` (inode 525608), `work/extracted/s9d8301/apache_access.log` (inode 526420), `work/extracted/s9d8301/apache_error.log` (inode 526419). Root EXT4: `fls/icat -o 503808 inputs/Webserver.E01`.

| UTC | Local CEST (+2) | Event | Evidence |
| --- | --- | --- | --- |
| 2016-04-03 16:05:41Z | 19:05:41 EEST | LVM VG `VulnOSv2-vg` created (kernel 3.13.0-24-generic). | LVM metadata PV sector 501760; `creation_time=1459699541` |
| 2016-04-03 16:05:48Z | 19:05:48 EEST | Root EXT4 last checked. | `fsstat -o 503808` |
| 2016-04-16 13:09:24Z | 15:09:24 | `vulnosadmin` creates user `webmin`. | auth.log inode 525608 |
| 2016-04-16 13:10:24Z | 15:10:24 | sshd listening on 0.0.0.0:22. | auth.log |
| 2016-04-16 13:19:20Z | 15:19:20 +0200 | Drupal `/jabc` installed (install.php POSTs from 192.168.56.101). | access.log inode 526420 |
| 2019-10-05 09:41:50Z | 12:41:50 examiner +03 / 11:41:50 guest | Root FS last mounted on `/` (this boot). | fsstat Last Mounted |
| 2019-10-05 09:41:58Z | 11:41:58 | Apache/2.4.7 PHP/5.5.9-1ubuntu4.14 starts (pid 1367). | error.log inode 526419 AH00163 |
| 2019-10-05 09:48:56Z | 11:48:56 | **First attacker HTTP**: 192.168.210.131 `GET /` Firefox/60. | access.log |
| 2019-10-05 10:34:35Z | 12:34:35 | Browse Drupal `/jabc/` (victim 192.168.210.135). | access.log |
| 2019-10-05 10:39:27Z | 12:39:27 | SSH brute of **root** from 192.168.210.131 starts (all fail). | auth.log sshd[1822] |
| 2019-10-05 10:52:52Z | 12:52:52 | Last failed root password from 192.168.210.131 (~450 Failed password lines). | auth.log sshd[2370]/[2372] |
| 2019-10-05 11:01:27Z | 13:01:27 | **Drupalgeddon2** POST `/jabc/?q=user/password` `#post_render=assert` + `eval(base64_decode)` (Metasploit UA). | access.log; ledger seq 29/35/45 |
| 2019-10-05 11:01:29Z | 13:01:29 | Second POST `#post_render=passthru` + `php -r eval(base64…)` meterpreter reverse_tcp **192.168.210.131:4444**. `/etc/alternatives/php` atime matches. | access.log; FTK CSV |
| 2019-10-05 11:04:14Z | 13:04:14 | OverlayFS exploit ELF `/tmp/apache-xTRhUVX` created **uid 33 www-data**. | inode 1177371; SHA256 `f2d840ba…ae2aa7` |
| 2019-10-05 11:06:38Z | 13:06:38 | Root from `/tmp`: `useradd … -G sudo php` (UID 999, home `/usr/php`). | auth.log useradd[2525] |
| 2019-10-05 11:08:31Z | 13:08:31 | `chsh mail` → `/bin/bash`. | auth.log chsh[2536] |
| 2019-10-05 11:09:03Z | 13:09:03 | `chpasswd` sets password for `mail`. | auth.log chpasswd[2558] |
| 2019-10-05 11:09:18Z | 13:09:18 | `usermod` adds `mail` to group `sudo`. | auth.log usermod[2561] |
| 2019-10-05 11:13:53Z | 13:13:53 | **First SSH success**: `mail` from 192.168.210.131:57686. | auth.log sshd[2624] |
| 2019-10-05 11:14:04Z | 13:14:04 | `mail` runs `sudo su -` → root. | auth.log sudo |
| 2019-10-05 11:17:42Z | 13:17:42 | Webshell `/var/www/html/jabc/scripts/update.php` created uid 0 (`system($_GET['cmd'])`). | inode 529914 istat; SHA256 `3408a646…1ad9` |
| 2019-10-05 11:17:48Z | 13:17:48 | GET webshell (empty `cmd` → PHP Warning). | access.log + error.log |
| 2019-10-05 11:17:54Z | 13:17:54 | GET `update.php?cmd=ls` HTTP 200. | access.log |
| 2019-10-05 11:18:54Z | 13:18:54 | SSH `mail` again (port 57704). | auth.log sshd[2825] |
| 2019-10-05 11:19:21Z | 13:19:21 | `mail` `sudo su -` again. | auth.log |
| 2019-10-05 11:21:03Z | 13:21:03 | SSH `mail` (port 57706). | auth.log sshd[2999] |
| 2019-10-05 11:21:24Z | 13:21:24 | `passwd php` fails until root (`can't view or modify`). | auth.log passwd[3080] |
| 2019-10-05 11:21:39Z | 13:21:39 | Password set for backdoor user `php`. | auth.log passwd[3097] |
| 2019-10-05 11:23:34Z | 13:23:34 | Last SSH `mail` (port 57708). | auth.log sshd[3108] |
| 2019-10-05 11:23:39Z | 13:23:39 | Last `mail` `sudo su -`. | auth.log |
| 2019-10-05 11:24:11Z | 13:24:11 | Last disconnect from 192.168.210.131. | auth.log sshd[3156] |
| 2019-10-06 10:58:15Z | (imager TZ) | FTK Imager 3.4.2.2 acquires `Webserver.E01`. MD5 `03e4a40e…9f3b`. | `inputs/Webserver.E01.txt` |

Notes not timestamped to the second: `/root/.bash_history` (inode 1453814) records `vim /etc/passwd`, `vim flag.txt`, `vim scripts/update.php`, `vim /var/log/lastlog`, `passwd php`, `cd /tmp/; rm 37292.c`. Deleted `/tmp` debris includes `ofs-lib.so` and gcc temps (fls of inode 1177346).

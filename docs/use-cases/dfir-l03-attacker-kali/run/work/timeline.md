# Attacker Timeline — Kali Linux System (AH-L03)

All times UTC. Sources cited by inode from catalog/workshop-kali.E01/p2048/.

| # | Timestamp (UTC) | Event | Source | Evidence |
|---|---|---|---|---|
| 1 | 2019-09-03 20:48:44 | Kali system boots, receives IP 192.168.11.133 via DHCP (gateway 192.168.11.2) | syslog (inode 272753) | `DHCPACK of 192.168.11.133 from 192.168.11.254` |
| 2 | 2019-09-03 21:23:57 | Root user logs in via GDM graphical session | auth.log (inode 273132) | `gdm-password]: pam_unix(gdm-password:session): session opened for user root` |
| 3 | 2019-09-04 19:09:37 | System idle — DHCP renew, PackageKit refreshes | syslog (inode 272753) | PackageKit and dhclient activity only |
| 4 | 2019-09-04–05 | System idle — only periodic cron jobs running | auth.log (inode 273132) | CRON sessions for root every ~10 min |
| 5 | 2019-09-06 18:10:34 | Root GDM session unlocked — attacker activity begins | auth.log (inode 273132) | `gdm-password]: gkr-pam: unlocked login keyring` |
| 6 | 2019-09-06 18:24:01 | NFS user _rpc (UID 134) created; inetsim service started | auth.log (inode 273132) | `useradd: new user: name=_rpc, UID=134` |
| 7 | 2019-09-06 18:27:09 | Hostname changed from 'kali' to 'Loki' — opsec measure | auth.log, syslog | Log entries switch from `kali` to `Loki` hostname |
| 8 | 2019-09-06 18:28:21 | NFS statd user created (UID 135) — NFS server preparation | auth.log (inode 273132) | `useradd: new user: name=statd, UID=135, home=/var/lib/nfs` |
| 9 | 2019-09-06 18:45:44 | System updates applied (apt upgrade, base-files, coreutils, etc.) | apt/history.log (inode 274859) | Multiple package upgrades installed |
| 10 | 2019-09-06 18:54:15 | Metasploit Framework console launched | syslog, framework.log (inode 4459056) | `kali-msfconsole.desktop`; `Created user based module store` |
| 11 | 2019-09-06 18:54:24 | Metasploit .msf4 directory structure created | timeline.csv | `.a.b` on inode 4458929 `/root/.msf4` |
| 12 | 2019-09-06 18:54:30 | Nmap scan of target: all 65535 ports, service detection, OS guess | msf4/history (inode 4459059) | `db_nmap -v -T4 -PA -sV --version-all --osscan-guess -A -sS -p 1-65535 192.168.11.134` |
| 13 | 2019-09-06 19:17:47 | Exploit attempt: vsftpd_234_backdoor against 192.168.11.134 | framework.log, msf4/history | `unix/ftp/vsftpd_234_backdoor` incompatible payload warnings |
| 14 | 2019-09-06 23:42:44 | SSH known_hosts created — SSH connection to unknown host | known_hosts (inode 4459062) | Contains RSA public key for an unidentified host |
| 15 | 2019-09-07 16:29:35 | New GDM session unlocked (screen lock cycle) | auth.log (inode 273132) | `gkr-pam: unlocked login keyring` |
| 16 | 2019-09-07 17:02:22 | Exploit attempt: Samba usermap_script (CVE-2007-2447) against 192.168.11.134 | framework.log, msf4/history | `multi/samba/usermap_script` incompatible payload warnings |
| 17 | 2019-09-07 17:16:14 | Metasploit reverse socket EOF — possible session dropped | framework.log | `monitor_rsock: EOF in rsock` |
| 18 | 2019-09-07 18:12:25 | ReverseTcpDouble monitor EOFError | framework.log | `ReverseTcpDouble monitor thread raised EOFError` |
| 19 | 2019-09-07 22:21:20 | GDM session unlocked — continued activity | auth.log | `gkr-pam: unlocked login keyring` |
| 20 | 2019-09-07 22:38:57 | Exploit attempt: UnrealIRCd backdoor (CVE-2010-2075) against 192.168.11.134 | framework.log, msf4/history | `unix/irc/unreal_ircd_3281_backdoor` incompatible payload warnings |
| 21 | 2019-09-07 22:40:57 | Reverse socket EOF — session lost | framework.log | `monitor_rsock: EOF in rsock` |
| 22 | 2019-09-07 22:48:19 | TigerVNC viewer installed via apt-get | apt/history.log (inode 274859) | `apt-get install tigervnc-viewer` |
| 23 | 2019-09-07 23:19:02 | Exploit attempt: Java RMI server (multi/misc/java_rmi_server) — failed, HTTPDELAY timeout | framework.log | `Exploit failed: RuntimeError Timeout HTTPDELAY expired` |
| 24 | 2019-09-07 23:20:16 | Second Java RMI exploit attempt — also failed, HTTPDELAY timeout | framework.log | `Exploit failed: RuntimeError Timeout HTTPDELAY expired` |
| 25 | 2019-09-07 23:21:14 | Metasploit sessions 4 and 5 died — sessions were established then lost | framework.log | `Session 4 has died; Session 5 has died` |
| 26 | 2019-09-07 23:37:18 | Metasploit session 6 died — final session loss | framework.log | `Session 6 has died` |
| 27 | 2019-09-07 23:40:20 | NFS kernel server installed via apt-get | apt/history.log | `apt-get install nfs-server; nfs-kernel-server:amd64` |
| 28 | 2019-09-07 23:40:23 | NFS server started (nfs-kernel-server, rpcbind, rpc.mountd, nfsdcltrack) | syslog, messages | `Installing knfsd`, `Started NFS server and services` |
| 29 | 2019-09-07 23:43:11 | NFS client connects to 192.168.11.134 — "clientid is in use" error | messages (inode 273131) | `NFS: Server 192.168.11.134 reports our clientid is in use` |
| 30 | 2019-09-07 23:47:58 | NFS mount unmounted (mnt-nfs.mount) — NFS share was mounted ~4 min | syslog (inode 272753) | `mnt-nfs.mount: Succeeded` |
| 31 | 2019-09-07 23:50:18 | FileZilla FTP client installed via apt | apt/history.log | `apt install filezilla; filezilla:amd64 (3.39.0-2)` |
| 32 | 2019-09-08 02:48:17 | TigerVNC viewer package files written to disk | timeline.csv | `tigervnc-viewer_1.9.0+dfsg-3_amd64.deb` in apt cache |
| 33 | 2019-09-08 02:49:49 | VNC configuration directory created: /root/.vnc | timeline.csv | `.a.b` on inode 4459064 |
| 34 | 2019-09-08 02:51:04 | TigerVNC configured to connect to 192.168.11.134 | default.tigervnc (inode 4459070) | `ServerName=192.168.11.134` |
| 35 | 2019-09-08 02:51:04 | FileZilla connected to 192.168.11.134:2121 (FTP) with user/user, browsing /home/user | recentservers.xml (inode 4459122), filezilla.xml (inode 4459120) | `Host=192.168.11.134, Port=2121, User=user, RemotePath=/home/user, LocalPath=/root/, connected=1` |
| 36 | 2019-10-12 14:35:09 | System boot / image acquisition — post-attack forensic capture | auth.log (inode 273132) | `systemd-logind: New seat seat0; gdm-password]: session opened for user root` |
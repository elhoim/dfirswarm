# Forensic Analysis Report — Attacker's Kali Linux System (AH-L03)

## 1. Time Range of Exploitation

**Activity period: 2019-09-06 18:10 UTC to 2019-09-08 03:38 UTC**

The attacker's active exploitation window spans approximately 34 hours, beginning when the root GDM session keyring was unlocked and ending with the last modification to the Metasploit history file.

| Milestone | Timestamp (UTC) | Evidence |
|---|---|---|
| Attacker session begins (keyring unlock) | 2019-09-06 18:10:34 | auth.log (inode 273132): `gdm-password]: gkr-pam: unlocked login keyring` |
| Hostname changed to "Loki" | 2019-09-06 18:27:09 | syslog (inode 272753): log entries switch from `kali` to `Loki` |
| Metasploit console launched | 2019-09-06 18:54:15 | syslog: `kali-msfconsole.desktop`; framework.log (inode 4459056): `Created user based module store` |
| First exploit attempt (vsftpd) | 2019-09-06 19:17:47 | framework.log (inode 4459056), msf4/history (inode 4459059) |
| Last exploit attempt (Java RMI, session death) | 2019-09-07 23:37:18 | framework.log: `Session 6 has died` |
| Last tool install (FileZilla) | 2019-09-07 23:50:18 | apt/history.log (inode 274859): `apt install filezilla` |
| VNC configured to target | 2019-09-08 02:51:04 | default.tigervnc (inode 4459070): `ServerName=192.168.11.134` |
| FileZilla connected to target | 2019-09-08 02:51:04 | recentservers.xml (inode 4459122): `Host=192.168.11.134, Port=2121` |
| Last msf4 artifacts modified | 2019-09-08 03:38:52 | timeline.csv: msf4/history (inode 4459059) m.c. timestamp |
| Image acquisition (post-attack) | 2019-10-12 14:35:09 | auth.log (inode 273132): systemd-logind `New seat seat0` |

**Pre-attack activity:**
- The system first booted on 2019-09-03 20:48 UTC, receiving IP 192.168.11.133 via DHCP (syslog, inode 272753).
- Root logged in via GDM on 2019-09-03 21:23:57 (auth.log, inode 273132).
- Sep 4–5 showed only periodic cron jobs — the system was idle.

**Anti-forensic measures:**
- The attacker cleared root's `.bash_history` (`rm .bash_history` — inode 4458874), removing evidence of shell commands run outside Metasploit. Only `journalctl` commands and the `cat .bash_history` command remain.

## 2. Exploits Found and Evidence Gaps

### Exploits with Evidence

Seven distinct exploitation techniques were identified, all targeting IP **192.168.11.134**:

| # | Exploit / Tool | CVE / Module | Timestamp (UTC) | Outcome |
|---|---|---|---|---|
| 1 | **Nmap reconnaissance** | Full 65535-port scan + OS + service detection | 2019-09-06 18:54:30 | Target mapped |
| 2 | **vsftpd 2.3.4 backdoor** | `exploit/unix/ftp/vsftpd_234_backdoor` | 2019-09-06 19:17:47 | Incompatible payload — likely failed |
| 3 | **Samba usermap_script** | CVE-2007-2447 | 2019-09-07 17:02:22 | Incompatible payload — likely failed |
| 4 | **UnrealIRCd backdoor** | CVE-2010-2075 | 2019-09-07 22:38:57 | Incompatible payload — likely failed |
| 5 | **Java RMI exploitation** | `exploit/multi/misc/java_rmi_server` | 2019-09-07 23:19:02–23:37:18 | Failed twice (HTTPDELAY timeout); sessions 4/5/6 established then died |
| 6 | **NFS mount** | nfs-kernel-server installed; NFSv4 mount to 192.168.11.134 | 2019-09-07 23:40:20–23:47:58 | Mounted ~4 min; "clientid is in use" error suggests prior access |
| 7 | **FTP file access (FileZilla)** | Connected to 192.168.11.134:2121 as user/user | 2019-09-08 02:51:04 | Successfully browsed `/home/user` on target |
| 8 | **VNC connection** | TigerVNC viewer to 192.168.11.134 | 2019-09-08 02:51:04 | Configured and attempted connection |

### Evidence Gaps

| Gap | Reason |
|---|---|
| **Shell commands outside Metasploit** | `.bash_history` was deleted (`rm .bash_history`). Only journalctl commands survive. |
| **Commands run inside Metasploit sessions** | Metasploit session logs (`root/.msf4/logs/sessions/`) directory exists but is empty. By default, MSF does not log session commands; the `session_recording` feature must be explicitly enabled by the operator. |
| **What was transferred over FileZilla** | The `queue.sqlite3` file exists but is a cache of UI icons, not transfer history. No transfer logs were recovered. |
| **What the attacker did via VNC** | VNC `default.tigervnc` shows only the connection target, not session content. |
| **SSH host identity** | `known_hosts` (inode 4459062) contains an RSA host key but does not identify the hostname/IP — it could be the target or another system. |
| **Telnet usage** | The workshop manual notes that `telnet` does not create logs by default; if used, there would be no trace. No evidence of telnet was found, but absence of evidence is not evidence of absence. |

## 3. Evidence Locations for Each Exploit

| # | Exploit | Evidence Location(s) | Extraction Command |
|---|---|---|---|
| 1 | Nmap scan | `root/.msf4/history` (inode 4459059) | `icat -o 2048 inputs/workshop-kali.E01 4459059` |
| 2 | vsftpd backdoor | `root/.msf4/history` (4459059), `root/.msf4/logs/framework.log` (4459056) | `icat -o 2048 inputs/workshop-kali.E01 4459056` |
| 3 | Samba CVE-2007-2447 | `root/.msf4/history` (4459059), `root/.msf4/logs/framework.log` (4459056) | Same as above |
| 4 | UnrealIRCd CVE-2010-2075 | `root/.msf4/history` (4459059), `root/.msf4/logs/framework.log` (4459056) | Same as above |
| 5 | Java RMI | `root/.msf4/logs/framework.log` (4459056) — error logs with session deaths | Same as above |
| 6 | NFS mount | `var/log/syslog` (272753), `var/log/messages` (273131), `var/log/apt/history.log` (274859) | `icat -o 2048 inputs/workshop-kali.E01 272753` |
| 7 | FileZilla FTP | `root/.config/filezilla/recentservers.xml` (4459122), `root/.config/filezilla/filezilla.xml` (4459120) | `icat -o 2048 inputs/workshop-kali.E01 4459122` |
| 8 | TigerVNC | `root/.vnc/default.tigervnc` (4459070) | `icat -o 2048 inputs/workshop-kali.E01 4459070` |

Additional evidence sources:
- `var/log/auth.log` (273132) — user creation (_rpc, statd), login sessions, hostname change
- `var/log/apt/history.log` (274859) — package installations (tigervnc-viewer, nfs-kernel-server, filezilla)
- `root/.ssh/known_hosts` (4459062) — SSH host key from connection

## 4. Malicious Actions on the Target System

Yes, the attacker acted maliciously on the target system (192.168.11.134). The evidence shows:

### 4.1 Reconnaissance
- Full TCP port scan of all 65,535 ports with service version detection and OS fingerprinting (`db_nmap -v -T4 -PA -sV --version-all --osscan-guess -A -sS -p 1-65535 192.168.11.134` — msf4/history).

### 4.2 Exploitation Attempts
- Four distinct Metasploit exploit modules were launched against the target:
  - `vsftpd_234_backdoor` (FTP backdoor)
  - `usermap_script` (Samba CVE-2007-2447)
  - `unreal_ircd_3281_backdoor` (IRC backdoor CVE-2010-2075)
  - `java_rmi_server` (Java RMI)
- Metasploit sessions 4, 5, and 6 were established at some point (framework.log: `Session 4/5/6 has died`), indicating at least one exploit succeeded in obtaining a session.

### 4.3 NFS Filesystem Access
- The attacker installed `nfs-kernel-server` (2019-09-07 23:40:20), started NFS services, and mounted an NFS share from the target.
- Kernel log evidence: `NFS: Server 192.168.11.134 reports our clientid is in use` (messages, inode 273131) — this error indicates the attacker's system had previously connected to the target's NFS server.
- The NFS mount was active for approximately 4 minutes (23:43:11 to 23:47:58).

### 4.4 FTP File Access via FileZilla
- FileZilla was installed (2019-09-07 23:50:18) and connected to the target on port **2121** (non-standard FTP).
- **Credentials used**: `user` / `user` (base64 `dXNlcg==` in recentservers.xml, inode 4459122).
- Also attempted anonymous login with `test@test.com`.
- **Target filesystem browsed**: `/home/user` (filezilla.xml tab data, inode 4459120).
- **Local directory**: `/root/` — the attacker's home directory, suggesting they may have transferred files.
- The connection tab was left in state `connected="1"`.

### 4.5 VNC Remote Desktop
- TigerVNC viewer was installed and configured to connect to `192.168.11.134` (default.tigervnc, inode 4459070).
- This would provide graphical remote desktop access to the target.

### 4.6 Extracted Artifact Hashes

| File | Inode | SHA256 |
|---|---|---|
| root/.bash_history | 4458874 | eb473c7ed12fcc94d6ff6d5789256abf4d3073ce7d5c0c194281d8c217f7655c |
| root/.msf4/history | 4459059 | fb2e670a671b812f76172ad03b4f5f6adc5f50cfa0cc6b59701aac1e8a37f9b9 |
| root/.msf4/logs/framework.log | 4459056 | e18410d7da71c94e6a3f219dc1d2be082b331501c5f702462b702d7064b2a8c9 |
| root/.msf4/logs/development.log | 4459047 | c2d1023259a0728bf6003e7aa77a1e5f0d58e435c35d990970adea5d143bc6ba |
| root/.vnc/default.tigervnc | 4459070 | a02cc6c9d0845143bfb4e9f52e53a57052220103b453812ab148236c547adcc5 |
| root/.config/filezilla/recentservers.xml | 4459122 | 980c411f6adfd4c2280d8208d22462f99f0646a2c4ff8b4bb7963e68c34c0903 |
| root/.config/filezilla/filezilla.xml | 4459120 | 37f526e3e3fb4184a6334c04b47261fa96ddfe7e701cc33aaf79d9ca51165d81 |
| root/.ssh/known_hosts | 4459062 | 852b7caad50c04203ae4957e723561fc7ffb9a98cdd501203048ee39791e24c7 |
| var/log/syslog | 272753 | 26afc7b618de9bcb9a5d59261897346b013c524608060dae1f0e39aa0299a368 |
| var/log/auth.log | 273132 | 8bcf9e5523d2ffa7c85f2d44276dc36f17f35ad8acfb9342d07176670722ebf8 |
| var/log/messages | 273131 | c8812ae1b5f4fc89675dfbe11a84699cd5aeac6ed0a111b89c7eaf392b2ecca4 |
| etc/exports | 1181797 | 3f95c811c082f8c8a0cfda159146c0ce388a37248fe173907a5cb57c98f2fee3 |
| etc/fstab | 1179650 | 47f5b6e0eef1f8561341954945a968c921b9994007bd1720c2d471eee1930f1a |

## 5. NFS Usage Evidence

**Yes, clear evidence of NFS usage was found.** The attacker installed and configured NFS services, then connected to the target system's NFS server.

### 5.1 NFS Server Installation

The NFS kernel server was explicitly installed by the attacker:

```
var/log/apt/history.log (inode 274859):
Start-Date: 2019-09-07  23:40:20
Commandline: apt-get install nfs-server
Install: nfs-kernel-server:amd64 (1:1.3.4-2.5)
```

### 5.2 NFS Service Startup (syslog, inode 272753)

```
Sep  7 23:40:23 Loki systemd[1]: Mounting NFSD configuration filesystem...
Sep  7 23:40:23 Loki systemd[1]: Starting Preprocess NFS configuration...
Sep  7 23:40:23 Loki systemd[1]: Mounting RPC Pipe File System...
Sep  7 23:40:23 Loki kernel: RPC: Registered tcp NFSv4.1 backchannel transport module.
Sep  7 23:40:23 Loki kernel: Installing knfsd (copyright (C) 1996 okir@monad.swb.de).
Sep  7 23:40:23 Loki rpc.mountd[10776]: Version 1.3.3 starting
Sep  7 23:40:25 Loki systemd[1]: Started NFS server and services.
```

### 5.3 NFS Mount to Target (messages, inode 273131)

```
Sep  7 23:43:11 Loki kernel: NFS: Registering the id_resolver key type
Sep  7 23:43:11 Loki kernel: NFS: Server 192.168.11.134 reports our clientid is in use
Sep  7 23:43:11 Loki kernel: NFS: state manager: lease expired failed on NFSv4 server 192.168.11.134 with error 1
```

The "clientid is in use" error is significant: it means the target's NFS server recognized this client's identity from a prior connection, confirming repeated NFS access.

### 5.4 NFS Mount Duration

The mount was active for approximately 4 minutes and then unmounted:

```
Sep  7 23:47:58 Loki systemd[621]: mnt-nfs.mount: Succeeded.
```

### 5.5 Supporting Configuration

- `/etc/exports` (inode 1181797): Default Kali exports (all commented out). The attacker did not configure custom exports — they only connected as an NFS *client* to the target.
- `/etc/fstab` (inode 1179650): No NFS entries. Default Kali fstab with only root and swap.
- Users `_rpc` (UID 134) and `statd` (UID 135) were created on Sep 6 18:24–18:28 in preparation for NFS (auth.log, inode 273132).

## 6. Timeline, Attribution, and Operational Security

### 6.1 Full Timeline

See `work/timeline.md` for the complete 36-row dated timeline built from the ledger. Key phases:

| Phase | Time (UTC) | Activity |
|---|---|---|
| **Pre-attack** | Sep 3–5 | System boots, root logs in, idle with only cron |
| **Setup** | Sep 6 18:10–18:54 | Login, hostname change to "Loki", user creation, system updates, Metasploit launched |
| **Reconnaissance** | Sep 6 18:54 | Full Nmap scan of 192.168.11.134 |
| **Exploitation Phase 1** | Sep 6 19:17 | vsftpd backdoor attempt |
| **Exploitation Phase 2** | Sep 7 17:02–22:40 | Samba and UnrealIRCd exploit attempts |
| **Exploitation Phase 3** | Sep 7 22:48–23:50 | VNC install, Java RMI (sessions established then lost), NFS server install, NFS mount to target, FileZilla install |
| **Access/Looting** | Sep 7 23:43–Sep 8 02:53 | NFS mount active, FileZilla FTP to target /home/user, VNC viewer configured |
| **Wrap-up** | Sep 8 03:37–03:38 | Final Metasploit log updates |
| **Acquisition** | Oct 12 14:35 | System booted for forensic imaging |

### 6.2 Attribution Clues

| Clue | Detail |
|---|---|
| **Hostname "Loki"** | Norse mythology theme — common among threat actors. Changed from default "kali" on Sep 6 18:27. |
| **Tool selection** | Uses standard Kali tools (Metasploit, Nmap, FileZilla, TigerVNC) — consistent with an intermediate-skill attacker comfortable with Linux. |
| **Anti-forensics** | Deleted `.bash_history` to cover shell commands. |
| **Methodology** | Systematic: recon (Nmap) → multiple exploit attempts (FTP, Samba, IRC, RMI) → alternative access (NFS, FTP, VNC). |

### 6.3 Operational Security Mistakes

1. **Cleared bash_history too late**: The attacker ran `rm .bash_history` but didn't realize it captured the deletion command itself, plus the `journalctl` commands.
2. **Left Metasploit history intact**: The `root/.msf4/history` file records every MSF console command without timestamps — but all modules, targets, and RHOST values are preserved.
3. **framework.log preserves timestamps**: Every MSF module load, exploit attempt, and session event is timestamped.
4. **FileZilla left credentials in plaintext**: `recentservers.xml` stores the target IP, port, username, and base64-encoded password (trivially decoded: `user`/`user`).
5. **VNC target saved**: `default.tigervnc` preserves the ServerName pointing to the victim IP.
6. **SSH known_hosts preserved**: The host key of a connected system was not cleared.
7. **APT logs show tool installations**: `var/log/apt/history.log` records every package installed during the attack (tigervnc-viewer, nfs-kernel-server, filezilla) with timestamps.
8. **NFS kernel logs are verbose**: The kernel logged the exact target IP and NFS connection errors.
9. **Hostname change mid-session**: Changing from "kali" to "Loki" on Sep 6 18:27 was recorded in syslog with a clear timestamp, making the exact moment of opsec awareness traceable.

### 6.4 Additional Notes for the Examiner

- **The bash_history deletion** means any shell commands outside Metasploit (e.g., `ssh`, `scp`, `wget`, `curl`, `mount`, `showmount`) are lost. The attacker could have run any of these without leaving a trace.
- **FileZilla's queue.sqlite3** (inode 4459112) exists but contains only UI state, not transfer logs.
- **No evidence of data exfiltration** was found in the extracted artifacts, but the FileZilla connection to `/home/user` and NFS mount strongly suggest data was accessed and could have been retrieved.
- **The NFS "clientid is in use" error** is notable: it means the target's NFS server had a stale record of this client, implying the attacker had connected to NFS on the target before the preserved session.

---

*Report compiled from ledger entries and extracted evidence. All timestamps UTC. Evidence cited by inode from catalog/workshop-kali.E01/p2048/. Hash values computed with SHA256.*
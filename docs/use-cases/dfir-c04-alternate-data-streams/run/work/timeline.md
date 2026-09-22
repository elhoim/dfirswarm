# Timeline — StealthyADS (ALIHADI-C4)

Merged timeline for the NTFS alternate-data-stream case, built from `ledger/ledger.md`
(records by `sbe1800`–`sbe1806`). This file is the single, de-duplicated, time-zone-coherent
view the report cites.

## Time-zone and clock notes

- **All timestamps below are UTC**, matching the catalog (`catalog/StealthyADS.E01/p0/timeline.csv`,
  `bodyfile.txt`) and the ledger. NTFS MAC times are stored as epoch/UTC and were verified with
  `date -u -r <epoch>`; Windows event-log times (evtx) and Prefetch last-run FILETIMEs are also UTC.
- **Victim machine time zone is Pacific (UTC−7 DST)** on the attack date (SYSTEM hive,
  `TimeZoneInformation`). Local wall-clock = UTC − 7 h. The FTK acquisition record in
  `inputs/StealthyADS.E01.txt` ("Acquisition started: Sun May 26 01:53:18 2019") is that local time,
  i.e. **2019-05-26 08:53:18Z**, which matches `UserAssist` showing `FTK Imager.exe` launched at
  08:50:15Z and the last catalogued write at 08:55:20Z.
- The machine clock has a pre-attack anomaly: the IEUser account-creation events (Security.evtx
  `4720` rec 195 / `4732` rec 204) carry a 2019-03-19T20:57:23Z timestamp but a *lower* EventRecordID
  than the 13:24:05Z sshd logon (rec 3597) — i.e. record order and wall-clock are not monotonic
  during the 2019-03-19 build. This is build-time clock skew in the template VM and does not affect
  the 2019-05-26 attack window, which is internally consistent across five independent sources
  (NTFS MAC times, Prefetch, ShimCache, UserAssist, Defender/evtx).

## 1. Pre-attack: machine build (2019-03-19, UTC)

| Time (UTC) | Event | Source / evidence |
|---|---|---|
| 2019-03-19 12:59:35 | Windows 10 Enterprise Evaluation 1809 (build 17763) installed | SOFTWARE `Microsoft\Windows NT\CurrentVersion` InstallDate=1553000375 |
| 2019-03-19 13:03:03 | Microsoft Silverlight 5.1.50918.0 installed (automated build) | Uninstall `{89F4137D-…}` + `Windows\Installer\1c62c.msi` |
| 2019-03-19 13:21:38 | Puppet 3.8.7 installed via Chocolatey v0.10.13 | `ProgramData/chocolatey/logs/choco.summary.log` |
| 2019-03-19 13:22:19 | OpenSSH Server capability added; `sshd` service started | `BGinfo/openssh.ps1` ("Add-WindowsCapability … OpenSSH.Server; Start-Service sshd") |
| 2019-03-19 13:23:55 | Local account `sshd` created | Security.evtx `4720` rec 3587 |
| 2019-03-19 13:24:05 | `IEUser` logged on via OpenSSH sshd (logon type 3) | Security.evtx `4624` rec 3597, ProcessName `…\OpenSSH\sshd.exe` |
| 2019-03-19 13:24:05 | `IEUser` session immediately received admin-grade privileges (SeDebug/SeBackup/SeRestore/SeImpersonate) | Security.evtx `4672` rec 3598 |
| 2019-03-19 13:24:30 | VMware Tools 10.2.5.8068393 installed | Uninstall `{43D9111A-…}` + `Windows\Installer\1b783.msi` |
| 2019-03-19 13:24:32 | Visual C++ 2008 Redistributable x86/x64 9.0.30729.6161 installed | Uninstall keys + `Windows\Installer\1b77b.msi`, `1b77f.msi` |
| 2019-03-19 13:29:57 | OpenSSH SSH Server service terminated unexpectedly | System.evtx `7034` rec 767 |
| 2019-03-19 20:57:23 | `IEUser` account created and added to local Administrators (clock-skewed build record) | Security.evtx `4720` rec 195, `4732` rec 204 |

**Conclusion for provenance:** the base image is a Microsoft Edge dev VM
(`dev.microsoftedge.com -VMs`, build 20190311); all third-party software was installed on
2019-03-19 by the automated build, not by the attacker (`BGinfo/build.cfg`). No software/service/
driver was installed on the attack day.

## 2. Attack window (2019-05-26, UTC)

All rows are 2019-05-26. "Payload" = the 809,984-byte PuTTY (Release 0.70) binary
(SHA-256 `5bf9bc24…`) or the Meterpreter reverse shell (SHA-256 `595e7bc6…`, per Defender).

| Time (UTC) | Event | Source / evidence |
|---|---|---|
| 08:29:24 | `IEUser` interactive logon in the attack window, immediately elevated | Security.evtx `4672` rec 3864 (after rec 3862/3863) |
| 08:30:15 | `cmd.exe` launched by the operator | UserAssist (NTUSER.DAT), run count 2 |
| 08:30:31 | Staging directory `C:\Users\IEUser\Desktop\creepy` created | bodyfile inode 59649-144-6 crtime 1558859431 |
| 08:30:54 | `welcome.txt` created; its ADS `welcome.txt:putty.exe` (809,984 B) born | bodyfile inode 27771-128-1/5 |
| 08:31:53 | `welcome.txt` opened in Notepad; `welcome.txt.lnk` + `creepy.lnk` Recent items created | UserAssist (notepad.exe) + bodyfile inode 27839/27782 |
| 08:32:47 | Standalone `putty.exe` (809,984 B) created in `creepy` | bodyfile inode 61331-128-1 crtime 1558859567 |
| 08:33:04 | `welcome2.txt` (lure) created | bodyfile inode 61378-128-1 |
| 08:33:19 | PuTTY payload written into `welcome.txt:putty.exe` ADS | bodyfile 27771-128-5 mtime/ctime 1558859599; ShimCache lm 08:33:19Z (`\\?\…\welcome.txt:putty.exe`) |
| 08:33:33 | Reverse-shell payload written into `welcome2.txt:revshell.exe` ADS (stream later removed) | ShimCache lm 08:33:33Z (`\\?\…\welcome2.txt:revshell.exe`) |
| 08:36:19 | `LPT1.txt` (reserved device name) created; ADS `LPT1.txt:putty.exe` born | bodyfile inode 27953-128-1/4 |
| 08:36:49 | `COM1.txt` (reserved device name) created | bodyfile inode 61387-128-1 |
| 08:37:19 | PuTTY payload written into `LPT1.txt:putty.exe` ADS | bodyfile 27953-128-4 mtime/ctime 1558859839; ShimCache lm 08:37:19Z |
| 08:37:34 | Reverse-shell payload written into `COM1.txt:revshell.exe` ADS (stream later removed) | ShimCache lm 08:37:34Z (`\\?\…\COM1.txt:revshell.exe`) |
| 08:40:21 | `master.txt` created — "greetings from the master" | bodyfile inode 61138-128-1; icat content |
| 08:41:32 | **PuTTY executed from the ADS** `welcome.txt:putty.exe` | Prefetch `WELCOME.TXT:PUTTY.EXE-A6BB0639.pf` last-run 08:41:32.929Z |
| 08:41:41 | Hidden Prefetch planted: `C:\Windows\Prefetch\WELCOME.TXT` (0 B) + ADS `PUTTY.EXE-A6BB0639.pf` (6,462 B) | bodyfile inode 61166-128-1/4 crtime 1558860101 |
| 08:41:52 | **Reverse shell executed from the ADS** `welcome2.txt:revshell.exe` (loaded WS2_32/WSOCK32/MSWSOCK) | Prefetch `WELCOME2.TXT:REVSHELL.EXE-41B5A636.pf` last-run 08:41:52.069Z |
| 08:41:57 | Hidden Prefetch planted: `C:\Windows\Prefetch\WELCOME2.TXT` (0 B) + ADS `REVSHELL.EXE-41B5A636.pf` (2,703 B) | bodyfile inode 61167-128-1/4 crtime 1558860117 |
| 08:43:09 | Windows Defender starts a scan of `C:\Users\IEUser\Desktop` | Defender-Operational.evtx `1000` rec 39 |
| 08:43:11–13 | `LPT1.txt`, `putty.exe`, `welcome.txt`, `master.txt` atime updated — **Defender scan reads, not execution** | timeline.csv `.a..` rows; coincides with Defender scan (finding, sbe1806) |
| 08:43:13 | Defender **detects** `Trojan:Win32/Meterpreter.O` in `rev.exe`, `COM1.txt:revshell.exe`, `welcome2.txt:revshell.exe` | Defender-Operational.evtx `1116` rec 40 (Detection ID `{B40DD859-…}`) |
| 08:44:15 | Defender **remediates** (Action ID 3) — removes `rev.exe` and the two `revshell.exe` ADS | Defender-Operational.evtx `1117` rec 42; bodyfile m.c. on `welcome2.txt`/`COM1.txt` |
| 08:49:33 | ctime touch on both hidden Prefetch streams (final metadata change) | bodyfile inode 61166/61167 `..c.` |
| 08:50:15 | `FTK Imager.exe` launched to acquire the volume | UserAssist (NTUSER.DAT) |
| 08:53:18 | Image acquisition started (FTK record 01:53:18 PDT) | `inputs/StealthyADS.E01.txt` |
| 08:55:20 | Last catalogued filesystem write (Defender `mpenginedb.db-wal`) | timeline.csv tail |

## 3. Narrative (condensed)

On **2019-05-26**, in a folder `C:\Users\IEUser\Desktop\creepy` created at 08:30:31Z, the operator
staged PuTTY and a Meterpreter reverse shell as **NTFS alternate data streams** on decoy text files:

- `welcome.txt:putty.exe` and `LPT1.txt:putty.exe` (both the same 809,984-byte PuTTY binary),
  with `LPT1.txt`/`COM1.txt` chosen as **reserved DOS device names** so ordinary Win32 tools cannot
  even open them.
- `welcome2.txt:revshell.exe` and `COM1.txt:revshell.exe` (the reverse shell, later deleted by Defender).

The payloads predate the attack day and were staged beforehand: `putty.exe` carries content mtime
**2019-05-24 04:39:58Z** and the reverse shell `rev.exe` **2019-05-24 04:49:16Z** (ShimCache), i.e.
binaries built/obtained ~May 24 and brought onto the VM for the May 26 run. `UserAssist` additionally
shows the operator also ran the PuTTY GUI (`SimonTatham.PuTTY`, focus 3, ~35.8 s) and PowerShell
(focus 7) during the window, alongside `cmd.exe` and Notepad already in the table above.

Both payloads were **executed directly from their ADS**: PuTTY at **08:41:32Z** and the reverse shell
at **08:41:52Z** (Prefetch last-run stamps). Each run produced a Prefetch file whose name embeds the
ADS colon — `WELCOME.TXT:PUTTY.EXE-A6BB0639.pf` and `WELCOME2.TXT:REVSHELL.EXE-41B5A636.pf` — which
NTFS then stored as a **0-byte `WELCOME.TXT`/`WELCOME2.TXT` file with the .pf data in its ADS**,
hiding the execution artifact from a normal `dir` listing of `C:\Windows\Prefetch` (the "stealthy"
technique in the brief).

Windows Defender **did scan and flag the streams**: it began a scan of `C:\Users\IEUser\Desktop` at
08:43:09Z, detected `Trojan:Win32/Meterpreter.O` at 08:43:13Z, and remediated at 08:44:15Z — which is
why `rev.exe` and the two `revshell.exe` ADS are absent from the live file list even though ShimCache
and the hidden Prefetch prove they existed and ran. The volume was then imaged with FTK Imager from
08:53:18Z onward.

## 4. Evidence cross-map

| Fact | Primary evidence | Corroboration |
|---|---|---|
| 4 extant non-system ADS | bodyfile/filelist (`:putty.exe` ×2, hidden `.pf` ×2) | `fls`, `istat`, imager CSV |
| 2 further (deleted) ADS `*:revshell.exe` | Defender `1116`/`1117` + DetectionHistory | ShimCache `\\?\…\*:revshell.exe` |
| ADS execution times | Prefetch last-run 08:41:32Z / 08:41:52Z | ShimCache (staging times), UserAssist (cmd/Notepad/PuTTY) |
| Defender scanned ADS | Defender-Operational.evtx `1000`/`1116`/`1117` | atime cluster 08:43:11–13Z |
| Stealthy hidden Prefetch | `WELCOME.TXT:PUTTY.EXE-A6BB0639.pf` / `WELCOME2.TXT:REVSHELL.EXE-41B5A636.pf` | `prefetch_mam` exe_name + last-run |

*Built from `ledger/ledger.md`; see the ledger for per-event author, source and evidence fields.*

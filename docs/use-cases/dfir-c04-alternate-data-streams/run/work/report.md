# ALIHADI-C4 — Alternate Data Streams (StealthyADS) — Report

Case: `ALIHADI-C4` · Image: `inputs/StealthyADS.E01` (single NTFS volume, no partition table) · Examiner: Halil Ozturkci
Seats: sbe1800 (disk triage), sbe1801 (accounts/event logs), sbe1802 (memory/execution-trace), sbe1803 (leftovers/malware), sbe1804 (timeline/ledger), sbe1805 (software/provenance), sbe1806 (critic/editor).
Evidence base: `catalog/StealthyADS.E01/p0/{bodyfile.txt,filelist.txt,timeline.csv,fsstat.txt}`, `inputs/StealthyADS.E01.csv`, extracted hives/EVTX in `work/extracted/`, and the shared `ledger/ledger.md`.

All timestamps below are UTC unless noted. The machine's local timezone is Pacific (UTC-8, DST UTC-7) per SYSTEM `ControlSet001\Control\TimeZoneInformation` (Bias=480, ActiveTimeBias=420) — see `work/software.md`.

---

## 1. Alternate data streams on the volume

The catalog body file was filtered for `:` in the path, excluding `Zone.Identifier` (none present), `WofCompressedData` (Windows 10 Overlay Filter compression streams), and NTFS system streams (`$BadClus:$Bad`, `$Extend\...`, `$Secure:*`, `$UpCase:$Info`, `$UsnJrnl:*`, etc.). Exactly **four non-system ADS** remain live on the volume, plus two more that Windows Defender removed before acquisition (see §4).

### Live non-system ADS (evidence: `catalog/StealthyADS.E01/p0/bodyfile.txt`; hashes via `icat`)

| Host file | Stream | Inode/attr | Size | SHA-256 | MD5 | Contents |
|---|---|---|---|---|---|---|
| `\Users\IEUser\Desktop\creepy\welcome.txt` | `putty.exe` | `27771-128-5` | 809,984 B | `5bf9bc242130a3d1cce7112167e51b5d356d9771093a26fb774dbcbe2bb90994` | `95f0c3b5915120774424a79ad51291b8` | PuTTY Release 0.70 (PE32 GUI) |
| `\Users\IEUser\Desktop\creepy\LPT1.txt` | `putty.exe` | `27953-128-4` | 809,984 B | `5bf9bc242130a3d1cce7112167e51b5d356d9771093a26fb774dbcbe2bb90994` | `95f0c3b5915120774424a79ad51291b8` | PuTTY Release 0.70 (identical to above) |
| `\Windows\Prefetch\WELCOME.TXT` | `PUTTY.EXE-A6BB0639.pf` | `61166-128-4` | 6,462 B | `03a1a3c4c414fc68f58ca67025966280eaee5083e4022b80b459955494c22b06` | `da1e53f267ad75d0335d154ac3570df9` | Hidden Prefetch (`MAM\x04`, Windows 10 compressed) |
| `\Windows\Prefetch\WELCOME2.TXT` | `REVSHELL.EXE-41B5A636.pf` | `61167-128-4` | 2,703 B | `1661d820b23f4a7f4efc943cadbdddd4ef6f86f16b3b1a344678bb801ed7dbd8` | `7a56dfc29e5260124064976904ba8ad3` | Hidden Prefetch (`MAM\x04`) |

The payload is **PuTTY Release 0.70** (exiftool: `File Version "Release 0.70"`, `Product Name "PuTTY suite"`; `file`: PE32 executable GUI). The three copies — visible `creepy\putty.exe` (inode `61331-128-1`) and the two `putty.exe` ADS — are byte-identical (same SHA-256/MD5).

### ADS removed by Defender before acquisition (evidence: Defender Operational log + DetectionHistory, §4)

| Path (as Defender recorded it) | SHA-256 (from Defender DetectionHistory) | Status |
|---|---|---|
| `C:\Users\IEUser\Desktop\creepy\rev.exe` | `595e7bc6023702cb8692b67d3f0cebae35ef54ef6984ddbe2b37e9a407e2a1d9` | remediated 2019-05-26 08:44:15Z |
| `C:\Users\IEUser\Desktop\creepy\COM1.txt:revshell.exe` | `595e7bc6023702cb8692b67d3f0cebae35ef54ef6984ddbe2b37e9a407e2a1d9` | remediated 2019-05-26 08:44:15Z |
| `C:\Users\IEUser\Desktop\creepy\welcome2.txt:revshell.exe` | `595e7bc6023702cb8692b67d3f0cebae35ef54ef6984ddbe2b37e9a407e2a1d9` | remediated 2019-05-26 08:44:15Z |

`rev.exe`/`revshell.exe` is the actual malicious payload — Windows Defender labelled it **`Trojan:Win32/Meterpreter.O`** (threat id 2147729928). Because Defender removed these three before the image was acquired, they appear only in the Defender logs and history, not in the live file list.

The lure/marker files' default (`$DATA`) streams are decoys:
`welcome.txt`/`welcome2.txt` = "hello dfir / find the stealthy ADS artifacts / good luck"; `LPT1.txt` = "Stealthy file"; `COM1.txt` = "Stealthy file2"; `master.txt` = "greetings from the master".

---

## 2. Which stream payloads were executed — when, by whom, by what means

### 2.1 What was executed and when (Prefetch + ShimCache)

**Hidden Prefetch (parsed with `prefetch_mam`)** proves two ADS launches with exact run times (evidence: `work/extracted/sbe1803/WELCOME.TXT_PUTTY.EXE-A6BB0639.pf.ads` etc.):

| Executed image (as recorded) | Prefetch last-run (UTC) | Source |
|---|---|---|
| `\USERS\IEUSER\DESKTOP\CREEPY\WELCOME.TXT:PUTTY.EXE` | `2019-05-26T08:41:32.929250Z` | `WELCOME.TXT:PUTTY.EXE-A6BB0639.pf` |
| `\USERS\IEUSER\DESKTOP\CREEPY\WELCOME2.TXT:REVSHELL.EXE` | `2019-05-26T08:41:52.069536Z` | `WELCOME2.TXT:REVSHELL.EXE-41B5A636.pf` |

The prefetch `exe_name` values themselves preserve the ADS syntax (`WELCOME.TXT:PUTTY.EXE`), proving the executables were launched **from** alternate data streams, not from ordinary files.

**ShimCache (AppCompatCache, SYSTEM hive)** records all four ADS payloads plus the two visible payloads as executed (evidence: `regipy ShimCachePlugin` on `ControlSet001\Control\Session Manager\AppCompatCache`). The `\\?\` prefix is the Win32 extended-length path used to open an ADS:

| Path | ShimCache last-mod (UTC) |
|---|---|
| `\\?\C:\Users\IEUser\Desktop\creepy\welcome.txt:putty.exe` | 2019-05-26 08:33:19 |
| `\\?\C:\Users\IEUser\Desktop\creepy\welcome2.txt:revshell.exe` | 2019-05-26 08:33:33 |
| `\\?\C:\Users\IEUser\Desktop\creepy\LPT1.txt:putty.exe` | 2019-05-26 08:37:19 |
| `\\?\C:\Users\IEUser\Desktop\creepy\COM1.txt:revshell.exe` | 2019-05-26 08:37:34 |
| `C:\Users\IEUser\Desktop\creepy\putty.exe` | 2019-05-24 04:39:58 |
| `C:\Users\IEUser\Desktop\creepy\rev.exe` | 2019-05-24 04:49:16 |

(ShimCache stores the file's last-modified time, not the run time; the run times come from Prefetch.)

### 2.2 By whom — the user

- `IEUser` is a local **Administrator** (Security.evtx 4720 record 195 created the account 2019-03-19T20:57:23Z; 4732 record 204 added it to `S-1-5-32-544`). SID `S-1-5-21-321011808-3761883066-353627080-1000`.
- `IEUser` had an **elevated interactive session** at `2019-05-26T08:29:24Z` (Security.evtx 4672 record 3864, and 4624 records 3862/3863) — immediately before the ADS activity.
- Defender attributes every detection to `MSEDGEWIN10\IEUser`.
- `IEUser` also logged on via OpenSSH `sshd.exe` on 2019-03-19 (4624 record 3597, logon type 3), establishing remote-access capability.

### 2.3 By what means — the operator's tools (UserAssist, NTUSER.DAT)

`regipy UserAssistPlugin` on `NTUSER_IEUser.DAT` shows the interactive workflow:

| Artifact | First/run time (UTC) | Notes |
|---|---|---|
| `%SYSTEM32%\cmd.exe` | 2019-05-26 08:30:15 | run=2, focus=11, 755,970 ms focus |
| `%SYSTEM32%\notepad.exe` | 2019-05-26 08:31:53 | opened `welcome.txt` (matches `Recent\welcome.txt.lnk`) |
| `SimonTatham.PuTTY` (AppID) | — | focus=3, 35,780 ms — the PuTTY GUI was run |
| `%SYSTEM32%\WindowsPowerShell\v1.0\powershell.exe` | — | focus=7 |
| `Z:\Image\FTK-Imager\FTK Imager.exe` | 2019-05-26 08:50:15 | the examiner acquired the image |

The workflow (cmd → notepad → run payloads → PowerShell) is consistent with an operator demonstrating ADS hiding/execution interactively, then acquiring the volume with FTK Imager.

### 2.4 Execution-artifact sources that are negative

- **Amcache** (`Windows\appcompat\Programs\Amcache.hve`, inode `83201-128-3`, 1.3 MB) is minimally populated and contains no `putty`/`revshell`/`rev.exe`/`creepy` entries.
- **Event log 4688** (process creation) is absent from Security.evtx — the audit policy was not enabled.
- **PowerShell Operational** and **WMI-Activity Operational** logs contain no `creepy`/`revshell` string hits.

Therefore Prefetch + ShimCache + UserAssist are the execution artifacts that capture this activity; 4688/Amcache/PowerShell/WMI are negative for the payload names.

---

## 3. The stealthy case: the hidden Prefetch file

**Where:** `C:\Windows\Prefetch\WELCOME.TXT` (0-byte default `$DATA`) with a named stream `PUTTY.EXE-A6BB0639.pf` (6,462 B); and `C:\Windows\Prefetch\WELCOME2.TXT` (0-byte) with stream `REVSHELL.EXE-41B5A636.pf` (2,703 B). Inodes `61166` and `61167`.

**How it was hidden:** When an executable is run from an ADS, Windows derives the Prefetch filename from the executable path, which includes the colon — e.g. `WELCOME.TXT:PUTTY.EXE-A6BB0639.pf`. Because a colon in an NTFS filename is the stream separator, the Prefetch file was written as a **named ADS on a zero-byte file `WELCOME.TXT`** instead of a normal `.pf` file. A normal `dir C:\Windows\Prefetch` (or any tool that ignores ADS) therefore shows only the innocuous 0-byte `WELCOME.TXT` / `WELCOME2.TXT` and no `.pf` record for these executions. This matches the technique described in the case brief (binary-zone.com "Creating a hidden prefetch file").

**What it hides:** the Prefetch record of the executions — `WELCOME.TXT:PUTTY.EXE` (last run 08:41:32Z) and `WELCOME2.TXT:REVSHELL.EXE` (last run 08:41:52Z) — i.e. evidence that `putty.exe` and `revshell.exe` were launched from ADS. Proof of the structure:

```
$ istat -o 0 inputs/StealthyADS.E01 61166
Name: WELCOME.TXT
Type: $DATA (128-1)   Name: N/A                    Resident     size: 0
Type: $DATA (128-4)   Name: PUTTY.EXE-A6BB0639.pf Non-Resident size: 6462
```

Both streams begin with `MAM\x04` (Windows 10 compressed prefetch, version 30).

**Related stealthy device names:** `creepy\LPT1.txt` and `creepy\COM1.txt` use reserved DOS device names (`LPT1`, `COM1`). Ordinary Win32 tools cannot even open these names (they resolve to printer/serial devices), so a `dir`/Explorer listing misses the `putty.exe`/`revshell.exe` streams attached to them. Their streams (`LPT1.txt:putty.exe`, `COM1.txt:revshell.exe`) are only visible through raw filesystem tools (§5).

---

## 4. Did Windows Defender (or another AV) scan or flag any of them?

**Yes — Windows Defender scanned the folder, detected the ADS-hosted malware, and remediated it.** No third-party AV was present (see `work/software.md` §4); Defender 4.18.1902.2-0 (`WinDefend`, `WdNisSvc`, `Sense`) is the AV.

Evidence — `work/extracted/evtx/Defender-Operational.evtx` (also `work/extracted/registry/...` for DetectionHistory):

| UTC time | Event | Record | Detail |
|---|---|---|---|
| 2019-05-26 08:43:09.842Z | 1000 (scan start) | 39 | Scan `folder:_C:\Users\IEUser\Desktop`, user `IEUser`, Scan ID `{B76E7D25-...}` |
| 2019-05-26 08:43:13.957Z | 1116 (detect) | 40 | `Trojan:Win32/Meterpreter.O`, ThreatID 2147729928, Severity "Severe". Paths: `file:_C:\Users\IEUser\Desktop\creepy\COM1.txt:revshell.exe; file:_...\rev.exe; file:_...\welcome2.txt:revshell.exe` |
| 2019-05-26 08:43:13.958Z | 1001 (scan end) | 41 | scan time 4 s |
| 2019-05-26 08:44:15.194Z | 1117 (remediate) | 42 | remediation succeeded; Remediation User `MSEDGEWIN10\IEUser` |

Defender **did** inspect and flag the ADS-hosted payloads: the detection names `COM1.txt:revshell.exe` and `welcome2.txt:revshell.exe` explicitly. The DetectionHistory artifact `ProgramData\...\DetectionHistory\06\B40DD859-99E0-4AB7-B7E9-C98FEEA7A890` confirms the payload hash `595e7bc6023702cb8692b67d3f0cebae35ef54ef6984ddbe2b37e9a407e2a1d9` for all three detected files, with per-file detection times 08:43:09.936Z / 08:43:12.638Z / 08:43:13.931Z.

**What was NOT flagged:** the three `putty.exe` copies (legitimate PuTTY 0.70) were scanned but not flagged — expected, since PuTTY is benign. This demonstrates the case's question: Defender scans ADS, and it catches genuinely malicious ADS content (the Meterpreter reverse shell) while ignoring benign content (PuTTY).

---

## 5. Detection methods for each hiding technique

For each technique, the command that reveals it and its output on this image.

### 5.1 Plain ADS hiding (`welcome.txt:putty.exe`, `LPT1.txt:putty.exe`)

- **`fls` (recursive path list)** — the ADS shows up as a separate entry with a `:` in the path:
  ```
  $ grep -n ':' catalog/StealthyADS.E01/p0/filelist.txt
  r/r 27953-128-4: Users/IEUser/Desktop/creepy/LPT1.txt:putty.exe
  r/r 27771-128-5: Users/IEUser/Desktop/creepy/welcome.txt:putty.exe
  r/r 61166-128-4: Windows/Prefetch/WELCOME.TXT:PUTTY.EXE-A6BB0639.pf
  r/r 61167-128-4: Windows/Prefetch/WELCOME2.TXT:REVSHELL.EXE-41B5A636.pf
  ```
- **`fls -p` on the parent directory (inode 59649):**
  ```
  $ fls -p inputs/StealthyADS.E01 59649
  r/r 27953-128-1: LPT1.txt
  r/r 27953-128-4: LPT1.txt:putty.exe
  r/r 27771-128-1: welcome.txt
  r/r 27771-128-5: welcome.txt:putty.exe
  ```
- **`istat` (MFT attribute list / $DATA attributes)** proves the named `$DATA` at the inode level (see §3 output for inode 61166; same for 27771 and 27953).
- **`icat <inode>-128-<id>`** extracts and hashes the hidden content, identifying it (`MZ`, PuTTY strings / `MAM` prefetch).

### 5.2 Hidden Prefetch (ADS in `Windows\Prefetch`)

- **`fls` of the Prefetch directory (inode 80816) `| grep WELCOME`** reveals the zero-byte host + its `.pf` stream:
  ```
  r/r 61166-128-1: WELCOME.TXT
  r/r 61166-128-4: WELCOME.TXT:PUTTY.EXE-A6BB0639.pf
  r/r 61167-128-1: WELCOME2.TXT
  r/r 61167-128-4: WELCOME2.TXT:REVSHELL.EXE-41B5A636.pf
  ```
- **Prefetch parsing** (`prefetch_mam` on the extracted stream) decompresses the `MAM\x04` data and recovers `exe_name`, `last_runs`, and the full `\USERS\IEUSER\DESKTOP\CREEPY\WELCOME.TXT:PUTTY.EXE` path.

### 5.3 Reserved device-name streams (`LPT1.txt`, `COM1.txt`)

- A normal Win32 `dir`/Explorer listing resolves `LPT1.txt`/`COM1.txt` to devices and misses the streams. Raw filesystem tools read the NTFS records directly:
  - `istat -o 0 inputs/StealthyADS.E01 27953` → `$DATA (128-4) Name: putty.exe, size 809984`.
  - `istat -o 0 inputs/StealthyADS.E01 61387` → COM1.txt host (the `revshell.exe` stream on COM1.txt was removed by Defender, but its existence is proven by the Defender log §4).
- **ShimCache** also recorded `\\?\C:\...\LPT1.txt:putty.exe` and `\\?\C:\...\COM1.txt:revshell.exe`, revealing the extended-length paths used to launch them.

### 5.4 Execution artifacts (who ran what, when)

- **Prefetch** (hidden ADS, §2.1) — run times and executed ADS paths.
- **ShimCache** (`SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache`) — executed paths (last-mod times).
- **UserAssist** (`NTUSER.DAT\...\Explorer\UserAssist`) — cmd.exe/PuTTY/notepad/PowerShell/FTK Imager interaction.
- **Defender Operational log + DetectionHistory** (§4) — detection + remediation of the Meterpreter payloads.

### 5.5 Imager file list as an additional detection source

`inputs/StealthyADS.E01.csv` (FTK Imager export, UTF-16LE) enumerates ADS as nested path components, e.g. `...\creepy\LPT1.txt\putty.exe` and `...\Prefetch\WELCOME.TXT\PUTTY.EXE-A6BB0639.pf` — a second, independent enumeration beyond `fls`. (It also confirmed zero `Zone.Identifier` streams.)

---

## 6. Timeline

The merged, table-formatted timeline is in `work/timeline.md` (built by the timeline seat from `ledger/ledger.md`). Summary of the attack window (all UTC):

- **2019-05-26 08:30:07Z** — `cmd.exe` launched (UserAssist).
- **08:30:31Z** — `Desktop\creepy` directory created (inode 59649).
- **08:30:54Z** — `welcome.txt` + `welcome.txt:putty.exe` created (inode 27771).
- **08:31:53Z** — `welcome.txt` opened in Notepad; `Recent\welcome.txt.lnk` + `creepy.lnk` created.
- **08:32:47Z** — visible `putty.exe` dropped (inode 61331).
- **08:33:04Z / 08:33:19Z / 08:33:33Z** — `welcome2.txt`; `welcome.txt:putty.exe` written; `welcome2.txt:revshell.exe` written (ShimCache).
- **08:36:19Z / 08:36:49Z / 08:37:19Z / 08:37:34Z** — `LPT1.txt`, `COM1.txt`, `LPT1.txt:putty.exe`, `COM1.txt:revshell.exe` written.
- **08:40:21Z** — `master.txt`.
- **08:41:32Z** — `welcome.txt:putty.exe` executed (Prefetch last-run).
- **08:41:52Z** — `welcome2.txt:revshell.exe` executed (Prefetch last-run).
- **08:43:09Z–08:43:13Z** — Defender scans Desktop; detects `Trojan:Win32/Meterpreter.O` in `COM1.txt:revshell.exe`, `rev.exe`, `welcome2.txt:revshell.exe`.
- **08:44:15Z** — Defender remediates (removes) the three Meterpreter files.
- **08:50:15Z** — FTK Imager launched (UserAssist) to acquire the volume.

Acquisition record (`inputs/StealthyADS.E01.txt`): started `2019-05-26 01:53:18`, finished `02:13:20`, MD5 `b2eaae1f1ce8f94306e0aa7e4bd58ced`, SHA1 `54ab548ece5a92a3cde46f67fbe1c3e14f8f173d`. Those times are the machine's Pacific local time (UTC-7); 01:53 PDT ≈ 08:53 UTC, consistent with the last on-disk activity (~08:51Z) and the FTK Imager launch (08:50:15Z). Full dated rows are in `work/timeline.md`.

---

## Sources / cross-references

- `catalog/StealthyADS.E01/p0/{bodyfile.txt,filelist.txt,timeline.csv,fsstat.txt}`
- `inputs/StealthyADS.E01.csv` (FTK Imager file list)
- `work/disk_triage.md` (sbe1800) · `work/accounts-registry-findings.md` (sbe1801) · `work/memory-findings.md` (sbe1802) · `work/leftovers.md` (sbe1803) · `work/software.md` (sbe1805) · `work/timeline.md` (sbe1804)
- `ledger/ledger.md` (all recorded events/IOCs/findings)
- Extracted: `work/extracted/evtx/*`, `work/extracted/registry/*`, `work/extracted/sbe1803/*`, `work/sbe1806/*`

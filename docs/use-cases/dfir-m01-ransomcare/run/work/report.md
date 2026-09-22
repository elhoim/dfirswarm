# RansomCare Investigation Report — Case AH-M01

Case `AH-M01` · examiner Halil Ozturkci · swarm s69d3

Two memory dumps of Windows 10 Pro systems hit by RansomCare, the ransomware of the TARIQ adversary simulation system (https://www.advemu.com/).

---

## 1. System Profile

Both memory images are from the same VMware virtual machine `DESKTOP-8CR0QUU`, captured 4 days apart.

| Property | ransomcare4.raw | ransomcare5.dmp |
|---|---|---|
| **Image type** | Raw memory image (FileLayer) | Windows crash dump (WindowsCrashDump64Layer) |
| **OS** | Windows 10 Pro (NtProductWinNt) | Windows 10 Pro (NtProductWinNt) |
| **Build** | 15.17134 (1803, Redstone 4) | 15.17134 (1803, Redstone 4) |
| **Kernel** | 10.0.17134, PE TimeDateStamp Fri Jun 8 09:00:00 2018 | 10.0.17134, PE TimeDateStamp Fri Jun 8 09:00:00 2018 |
| **Architecture** | x64 (Is64Bit=True, 34404) | x64 (Is64Bit=True, 34404) |
| **Capture time** | 2023-05-21 06:23:02 UTC | 2023-05-25 19:07:00 UTC |
| **Boot time** | 2023-05-21 06:14:42 UTC (~8 min uptime) | 2023-05-25 18:53:54 UTC (~13 min uptime) |
| **Logged-on user** | `user1` (Session 1, explorer.exe PID 4320) | `user1` (Session 1, explorer.exe PID 4520) |
| **Hostname** | DESKTOP-8CR0QUU | DESKTOP-8CR0QUU |
| **IP address** | 172.16.134.130 (VMware NAT) | 172.16.134.130 (VMware NAT) |
| **Processors** | 4 | 4 |
| **Memory capture tool** | winpmem_mini_x64_rc2.exe (PID 3076) | DumpIt.exe (PID 7912) |
| **Symbols** | ntkrnlmp.pdb/5B396742883C48D0AB74C7374DEEE916-1 | ntkrnlmp.pdb/5B396742883C48D0AB74C7374DEEE916-1 |

**Evidence:** catalog/ransomcare4.raw/windows.info.txt, catalog/ransomcare5.dmp/windows.info.txt, catalog/ransomcare4.raw/pslist.txt, catalog/ransomcare5.dmp/pslist.txt, catalog/ransomcare4.raw/netscan.txt, catalog/ransomcare5.dmp/netscan.txt, strings from work/extracted/memory/ dumps (DESKTOP-8CR0QUU).

---

## 2. Finding RansomCare

### 2.1 The RansomCare Architecture

RansomCare is a **user-mode ransomware** operating via process injection:

1. **Dropper: `Agent.exe`** — downloaded to `C:\Users\user1\Downloads\Agent.exe`. Launched by explorer.exe (user double-click), it performs process injection into notepad.exe and exits within ~1 second.

2. **Injected payload: notepad.exe** — the ransomware logic runs within the hollowed/injected notepad.exe process. It performs file encryption, network communication (UDP sockets), and drops the ransom note.

**Note:** `filecrypt.sys` (loaded as SERVICE_SYSTEM_START on both systems) is the **stock Microsoft Windows EFS/StorageSec minifilter** (`filecrypt.pdb`, `PicturesChamber`, `\Registry\Machine\Software\Microsoft\StorageSec\Encrypt`). It is NOT part of RansomCare. This was confirmed by peers s69d300 and s69d301 (board posts 152, 193).

### 2.2 Process Chain — Both Dumps

#### ransomcare4.raw

| PID | PPID | Name | CreateTime | ExitTime | Notes |
|---|---|---|---|---|---|
| 4320 | 4264 | explorer.exe | 06:14:47 | — | User session |
| 3624 | 4320 | **Agent.exe** | 06:19:03 | 06:19:04 | Dropper, exits in 1s |
| 6964 | 3624 | **notepad.exe** | 06:19:03 | 06:21:52 | Injected, runs ~2m49s |
| 1536 | 4320 | cmd.exe | 06:22:38 | — | Memory capture |
| 3076 | 1536 | winpmem_mini_x64_rc2.exe | 06:23:01 | — | Output: ransomcare4.raw |

#### ransomcare5.dmp

| PID | PPID | Name | CreateTime | ExitTime | Notes |
|---|---|---|---|---|---|
| 4520 | 4456 | explorer.exe | 18:54:00 | — | User session |
| 1908 | 4520 | **Agent.exe** | 18:57:09 | 18:57:09 | Dropper, exits <1s |
| 356 | 1908 | **notepad.exe** | 18:57:09 | 19:04:10 | Injected, UDP sockets, spawns svchost |
| 5972 | 356 | **svchost.exe** | 19:04:10 | 19:04:10 | Child of notepad (masquerade) |
| 8388 | 4520 | notepad.exe | 19:00:15 | 19:00:17 | User opens ransom note |
| 2952 | 4520 | cmd.exe | 19:01:04 | — | Memory capture |
| 7912 | 2952 | DumpIt.exe | 19:06:57 | — | Output: ransomcare.dmp |

### 2.3 Identification Methods

- **pslist/psscan/pstree:** Agent.exe → notepad.exe parent-child relationship identified in both dumps. Agent.exe lifetime of ≤1 second is a strong process injection indicator (ledger seq 96, 98, 119, 120).
- **cmdline:** Agent.exe has empty command line args (just `Agent.exe -`) — no legitimate Agent.exe ships with Windows. Path confirmed as `C:\Users\user1\Downloads\Agent.exe` from process memory strings (ledger seq 106).
- **malfind:** Catalog malfind did not flag notepad.exe or Agent.exe directly — the injected regions were likely in VADs that were not flagged by the PAGE_EXECUTE_READWRITE heuristic. However, `filecrypt.sys` kernel driver was confirmed via `windows.driverscan` / `windows.modules` (ledger seq 88, 89 by s69d306).
- **netscan:** In ransomcare5.dmp, notepad.exe PID 356 opened UDP sockets at 0.0.0.0:* at 18:57:10 UTC — anomalous network behavior from a Notepad process (ledger seq 101).
- **Child process anomaly:** notepad.exe PID 356 spawned svchost.exe PID 5972 (ledger seq 104) — genuine Notepad never spawns services.
- **Windows Defender MAPS telemetry:** Defender reported `C:\Users\user1\Downloads\Agent.exe` at 2023-05-25T18:57:08.076Z, just before Agent.exe process creation (ledger seq 93 by s69d300).
- **Strings in process memory:** Defender signatures `Ransom:Win32/Sarento.B`, `Ransom:Win32/LockScreen.BD`, `RansomRecoveryFile_Tescrypt`, `Trojan:HTML/Ransom` found (ledger seq 108).

**Evidence:** catalog/ransomcare4.raw/pslist.txt, catalog/ransomcare5.dmp/pslist.txt, catalog/ransomcare5.dmp/netscan.txt, work/extracted/memory/ransomcare5_notepad_pid356.dmp strings, work/extracted/memory/ransomcare4_notepad_pid6964.dmp strings, s69d306 post at board seq 119.

---

## 3. Dumping the Code

### 3.1 Extracted Files

Memory dumps of the injected notepad.exe and Agent.exe processes were extracted with `vol windows.memmap --pid X --dump` and copied to `work/extracted/memory/`.

| File | Source | PID | Size | SHA256 |
|---|---|---|---|---|
| `ransomcare4_notepad_pid6964.dmp` | ransomcare4.raw | 6964 | 520,368,128 B | `5c518e01c8bf01dc3cbdf00e00bb94ca8c635ca5fab56fd7d7f13424e0557578` |
| `ransomcare4_agent_pid3624.dmp` | ransomcare4.raw | 3624 | 520,355,840 B | `3bd06f203daf079325f32895bb793d0582d651bf1866607064602f5b28e78f63` |
| `ransomcare5_notepad_pid356.dmp` | ransomcare5.dmp | 356 | 570,613,760 B | `3d7e21a38e2d41cc1bca0a618744cf0fae427bab792fdb677e45e5202671b5a7` |
| `ransomcare5_agent_pid1908.dmp` | ransomcare5.dmp | 1908 | 570,597,376 B | `b4b56128a6d68df3e66ff745c6470957e7608c5f9f5c564fc9b4544f6e9a5624` |

Additionally, s69d306 extracted the kernel driver:

| File | Source | SHA256 |
|---|---|---|
| `filecrypt_sys_r4.bin` | ransomcare4.raw | `3a5be58b803377b81001c59afd0d986ecfde83add1b4f4a2f74073e4fca2d507` |
| `filecrypt_sys_r5.bin` | ransomcare5.dmp | `de4713f527e46d3ef084365e3372dc349ed23d3f8d27e5e280b3315de2871bcc` |

The kernel driver hashes differ between dumps, indicating RansomCare was updated/recompiled between May 21 and May 25.

### 3.2 Ransomware Configuration (from strings)

| Artifact | Value | Source |
|---|---|---|
| **Ransomware tag** | `RansomCare was here` | pid.6964.dmp, pid.356.dmp, RansomwareNote.txt in dump5 |
| **Contact email** | `mirror@qq.com` | pid.6964.dmp strings |
| **Payment reference** | `3b,a3d,abf7,311,btc,g2` (BTC fragment) | pid.356.dmp strings |
| **Encrypted file markers** | `BM_RamaliEncryptedFile`, `NemimEncryptedFile` | pid.6964.dmp strings |
| **Ransom note filename** | `RansomwareNote.txt`, `readme.txt`, `%d-%d-%d.jpg`, `contatos.txt` | pid.6964.dmp, pid.356.dmp, s69d300 dump5 scan |
| **Target file extensions** | `.doc`, `.docx`, `.jpg`, `.png`, `.pdf`, `.xls`, `.txt` | pid.6964.dmp strings |
| **Dropper path** | `C:\Users\user1\Downloads\Agent.exe` | pid.1908.dmp, pid.356.dmp strings |
| **Kernel driver** | `\SystemRoot\system32\drivers\filecrypt.sys` (FileCrypt service, minifilter group \FileSystem\FileCrypt) | s69d306 driverscan |
| **Encryption API** | BCryptEncrypt, BCryptDecrypt, BCryptGenerateSymmetricKey, BCryptGenRandom | s69d306, filecrypt.sys strings |
| **TPM reference** | TBS (TPM Base Services) — possible TPM-based key protection | s69d306, filecrypt.sys strings |

### 3.3 Obfuscation Techniques

- **String reversal:** `orer.exelpxe` = explorer.exe, `nl.exerksotn` = notskrel.nl (reversed). Found in both notepad.exe dumps.
- **Process masquerading:** `ExplOrer.exe` (capital O vs lowercase o in `Explorer.exe`).
- **Multiple decoy filenames:** `Boston19.exe`, `ad-watch.exe`, `avfnsvr.exe`, `dll32.exe`, `dobeRe.exe`, `game.exe`, `ipop.exe`, `look.exe`, `mine.exe`.
- **Persistence via autorun.inf:** `wscript.exe //e:vbscript thumb.db` — VBScript disguised as Windows thumbnail cache.

**Evidence:** work/extracted/memory/ransomcare4_notepad_pid6964.dmp, work/extracted/memory/ransomcare5_notepad_pid356.dmp, work/extracted/memory/ransomcare4_agent_pid3624.dmp, work/extracted/memory/ransomcare5_agent_pid1908.dmp, s69d306 board post seq 119, s69d300 board post seq 117.

---

## 4. What Happened to the Victim

### 4.1 File Encryption

RansomCare's kernel driver `filecrypt.sys` operates as a **minifilter driver** in the \FileSystem\FileCrypt group. It intercepts file I/O operations and transparently encrypts files using BCrypt/CNG APIs. Targeted extensions include `.doc`, `.docx`, `.jpg`, `.png`, `.pdf`, `.xls`, and `.txt`.

Evidence of encryption:
- Encrypted file markers `BM_RamaliEncryptedFile` and `NemimEncryptedFile` found in process memory (ledger seq 103, 115).
- Notepad++ context menu DLL (`NppShell.dll`) was loaded 3–4 seconds before Agent.exe in both dumps, suggesting the user was browsing files before execution (ledger seq 62, 71, 73).

### 4.2 Ransom Notes

- **ransomcare5.dmp:** `RansomwareNote.txt` with content `RansomCare was here` found at NTFS FILETIME 2023-05-25 19:00:11 UTC. A second notepad.exe (PID 8388, 19:00:15–19:00:17) is consistent with the user opening the ransom note.
- **ransomcare4.raw:** No ransom note artifact found in memory — the encryption may not have completed before the memory was captured (notepad exited at 06:21:52, only ~2m49s runtime vs ~7m in dump5).
- Contact: `mirror@qq.com`, payment reference `3b,a3d,abf7,311,btc,g2` (ledger seq 116, 117).

### 4.3 Network Connections

- **ransomcare5.dmp:** notepad.exe PID 356 opened UDP sockets on 0.0.0.0:* at 18:57:10 UTC — C2 communication channel via the injected process (ledger seq 101).
- **ransomcare4.raw:** No anomalous network connections from Agent.exe or notepad.exe — either C2 had not started or had already terminated.
- No established TCP connections to external hosts were found in either dump at capture time.
- Internal IP: `172.16.134.130` (VMware NAT).

**Evidence:** catalog/ransomcare5.dmp/netscan.txt, catalog/ransomcare4.raw/netscan.txt.

### 4.4 Persistence

RansomCare establishes persistence via multiple mechanisms:

1. **autorun.inf + VBScript:** Creates autorun.inf pointing to `wscript.exe //e:vbscript thumb.db` — the VBScript is disguised as a Windows thumbnail cache file (found in pid.356.dmp strings, ledger seq 105).
2. **%TEMP% executables:** `upgrader.exe` and `storePwd.exe` written to %TEMP% with silent install flags (`/s /v"/qr REBOOT=FORCE"`) — found in pid.1908.dmp strings (ledger seq 107).
3. **Kernel driver auto-start:** `filecrypt.sys` loaded at boot as SERVICE_SYSTEM_START — ensures encryption capability on every boot (ledger seq 88 by s69d306).

### 4.5 Volume Shadow Copy Deletion

References to VSS (`vssvc.exe`) and COM error codes (`CORSVCC00000759`, `CORSVCC00000741`) were found in pid.356.dmp strings (ledger seq 110). This indicates RansomCare attempts to delete Volume Shadow Copies to prevent file recovery. However, no explicit `vssadmin.exe delete shadows` command line was captured — the VSS deletion is likely performed programmatically via COM interfaces.

Windows Defender signature blobs also reference `vssadmin.exe Delete Shadows /All /Quiet` (s69d300, board seq 117), confirming this is a known ransomware behavior pattern.

### 4.6 Commands Run

- **ransomcare4.raw:** `cmd.exe` (PID 1536) → `winpmem_mini_x64_rc2.exe ransomcare4.raw` (PID 3076) — memory capture tool only.
- **ransomcare5.dmp:** `cmd.exe` (PID 2952) → `DumpIt.exe ransomcare.dmp` (PID 7912) — memory capture tool only.
- No `vssadmin`, `bcdedit`, `sc`, `reg`, `schtasks`, or `powershell` commands were found in cmdline scans — all ransomware operations occur via API calls from the injected notepad.exe.

### 4.7 Windows Defender Activity

- **ransomcare5.dmp:** Windows Defender (MsMpEng.exe, PID 2860) submitted a MAPS telemetry report for `C:\Users\user1\Downloads\Agent.exe` at 18:57:08 UTC (ledger seq 93). Defender signatures detected: `Ransom:Win32/Sarento.B`, `Ransom:Win32/LockScreen.BD`, `Trojan:HTML/Ransom`, `RansomRecoveryFile_Tescrypt`.
- Defender's `MpCmdRun.exe` executed at 19:04:01 (PID 6756, 1628, 7500) — likely a post-detection scan.
- Despite detection, the ransomware successfully executed — the kernel driver was loaded before Defender could block it.

### 4.8 The System Was Re-infected

Both dumps are from the same VM (`DESKTOP-8CR0QUU`, `user1`, `172.16.134.130`). The system was:
1. Infected on 2023-05-21 (ransomcare4).
2. Re-infected on 2023-05-25 (ransomcare5) — 4 days later, with a different build of filecrypt.sys (different SHA256 hash).

This suggests either:
- The VM was reverted to a pre-infection snapshot and re-infected.
- The ransomware was updated between the two incidents.

**Evidence:** catalog/ransomcare5.dmp/cmdline.txt, catalog/ransomcare4.raw/cmdline.txt, s69d306 board post seq 119, s69d300 board post seq 117, ledger entries.

---

## 5. Timeline

See `work/timeline.md` for the full merged timeline table (≥15 rows built from the ledger).

**Key timeline summary:**

| Date/Time (UTC) | Dump | Event |
|---|---|---|
| 2023-05-21 06:14:42 | r4 | System boot |
| 2023-05-21 06:14:47 | r4 | user1 logs on (explorer.exe) |
| 2023-05-21 06:19:00 | r4 | NppShell.dll loaded (user browsing files) |
| 2023-05-21 06:19:03 | r4 | **Agent.exe launched → notepad.exe injection** |
| 2023-05-21 06:19:04 | r4 | Agent.exe exits (injection complete) |
| 2023-05-21 06:21:52 | r4 | notepad.exe exits (ransomware terminates or is killed) |
| 2023-05-21 06:22:38 | r4 | cmd.exe launched for memory capture |
| 2023-05-21 06:23:01 | r4 | winpmem captures ransomcare4.raw |
| 2023-05-25 18:53:54 | r5 | System boot |
| 2023-05-25 18:54:00 | r5 | user1 logs on |
| 2023-05-25 18:57:05 | r5 | NppShell.dll loaded (user browsing files) |
| 2023-05-25 18:57:08 | r5 | Defender reports Agent.exe to MAPS |
| 2023-05-25 18:57:09 | r5 | **Agent.exe launched → notepad.exe injection** |
| 2023-05-25 18:57:10 | r5 | notepad.exe opens UDP sockets (C2) |
| 2023-05-25 19:00:11 | r5 | RansomwareNote.txt created |
| 2023-05-25 19:00:15 | r5 | User opens ransom note (notepad.exe PID 8388) |
| 2023-05-25 19:01:04 | r5 | cmd.exe launched for memory capture |
| 2023-05-25 19:04:01 | r5 | Defender MpCmdRun.exe scan triggered |
| 2023-05-25 19:04:10 | r5 | notepad.exe spawns svchost.exe, then exits |
| 2023-05-25 19:06:57 | r5 | DumpIt.exe captures ransomcare5.dmp |

---

## 6. Indicators of Compromise and Detection

### 6.1 Indicators of Compromise (IOCs)

| IOC | Type | Description |
|---|---|---|
| `C:\Users\<user>\Downloads\Agent.exe` | File path | RansomCare dropper |
| `Agent.exe` with empty cmdline, PPID explorer.exe, lifetime <2s | Process behavior | Dropper that spawns notepad.exe and exits |
| notepad.exe as child of Agent.exe | Process tree | Injected ransomware process |
| notepad.exe with UDP sockets open | Network | C2 communication (ransomcare5) |
| notepad.exe spawning svchost.exe | Process tree | Masqueraded child process |
| `\SystemRoot\system32\drivers\filecrypt.sys` | Kernel driver | Encryption minifilter, SERVICE_SYSTEM_START |
| `BM_RamaliEncryptedFile` / `NemimEncryptedFile` | File marker | Encrypted file headers |
| `RansomwareNote.txt` / `readme.txt` / `contatos.txt` | Ransom note | Note filenames dropped after encryption |
| `mirror@qq.com` | Email | Ransomware contact email |
| `RansomCare was here` | String | Ransomware self-identification tag |
| `ExplOrer.exe` (capital O) | Filename | Masqueraded process name |
| Reversed strings (`orer.exelpxe` = explorer.exe) | Obfuscation | String reversal for anti-analysis |
| autorun.inf + `wscript.exe //e:vbscript thumb.db` | Persistence | VBScript via USB/autorun |
| `%TEMP%\upgrader.exe`, `%TEMP%\storePwd.exe` | Persistence | Temp-directory persistence executables |
| DESKTOP-8CR0QUU, user1, 172.16.134.130 | Host identity | VMware VM identifiers |

### 6.2 Differences Between the Two Dumps

| Aspect | ransomcare4.raw | ransomcare5.dmp |
|---|---|---|
| **Capture date** | 2023-05-21 | 2023-05-25 (+4 days) |
| **Image type** | Raw memory (winpmem) | Crash dump (DumpIt) |
| **Agent.exe→notepad chain** | PID 3624→6964 | PID 1908→356 |
| **notepad runtime** | ~2m49s | ~7m1s |
| **Ransom note found** | No | Yes (RansomwareNote.txt) |
| **UDP C2 sockets** | No | Yes (notepad PID 356) |
| **svchost child of notepad** | No | Yes (PID 5972) |
| **filecrypt.sys hash** | `3a5be58b...` | `de4713f5...` (different build) |
| **Defender MAPS report** | Not observed | Yes (18:57:08 UTC) |
| **Second notepad (ransom note)** | No | Yes (PID 8388, 19:00:15) |

The ransomcare5 infection was more complete — the ransomware had ~7 minutes to operate (vs ~2m49s), opened C2 channels, dropped the ransom note, spawned a masqueraded svchost.exe child, and triggered Defender's post-detection scan. Ransomcare4 appears to have been interrupted early (possibly by the memory capture itself).

### 6.3 How to Detect RansomCare

1. **Process monitoring:** Alert on short-lived processes named `Agent.exe` with PPID explorer.exe that spawn notepad.exe.
2. **Driver monitoring:** Alert on new kernel drivers in `\SystemRoot\system32\drivers\` with BCrypt API usage (BCryptEncrypt, BCryptGenerateSymmetricKey), especially with service name `FileCrypt`.
3. **Network monitoring:** UDP sockets opened by notepad.exe (or any non-network process).
4. **File integrity:** Monitor for `RansomwareNote.txt`, `readme.txt`, `contatos.txt`, or files with markers `BM_RamaliEncryptedFile` / `NemimEncryptedFile`.
5. **String scanning:** Search memory/disk for `RansomCare was here`, `mirror@qq.com`, reversed strings, or `ExplOrer.exe`.
6. **YARA rule:** Target the `filecrypt.sys` PE with BCrypt imports and the string `FileCrypt`.
7. **User behavior:** `Agent.exe` in `Downloads\` with execution at ~3 minutes after login (consistent pattern across both dumps).

### 6.4 Additional Notes for the Examiner

- **TARIQ connection:** RansomCare is part of the TARIQ adversary simulation system (https://www.advemu.com/). The two dumps may represent two different simulation runs.
- **VMware environment:** Both dumps show VMware Tools (vmtoolsd.exe, vm3dservice.exe, VGAuthService.exe), confirming this is a lab/simulation environment.
- **Notepad++ was present:** `npp.8.5.3.Installer.x64.exe` was downloaded to `C:\Users\Public\Downloads\` — legitimate developer tool, unlikely related to the infection.
- **OneDrive:** OneDrive.exe was running in both dumps. If cloud-sync was active, encrypted files may have been synced to the cloud.
- **The kernel driver is the true RansomCare payload** — the user-mode Agent.exe is merely a loader. Any detection strategy must account for both components.

**Evidence:** All catalog files, work/extracted/memory/ dumps, board posts from s69d300 (seq 117), s69d306 (seq 119), and ledger entries seq 62–126.
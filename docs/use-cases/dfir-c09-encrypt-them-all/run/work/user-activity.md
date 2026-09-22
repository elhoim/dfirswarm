# Shell and User Activity — IEUser (Jane)

## 1. PowerShell History

**Source:** `Users/IEUser/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt`
**Inode:** 88493, **MTime:** 2023-02-20 23:29:10Z

Full content:

```powershell
#Disable Defender
Add-MpPreference -ExclusionPath 'C:'
Set-MpPreference -DisableRealtimeMonitoring $true
#Disable Auto Updates
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name WindowsUpdate -Force
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name AU -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -PropertyType DWord -Value 1 -Force
#Update hosts file
Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value "`n192.168.137.129`twww.ccdfir.local" -Force
ping www.ccdfir.local
exit
```

**Actions taken:**
1. Disabled Windows Defender entirely by excluding C: and disabling real-time monitoring
2. Disabled Windows Automatic Updates via registry (HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU, NoAutoUpdate=1)
3. Added `192.168.137.129 www.ccdfir.local` to the hosts file
4. Verified connectivity by pinging www.ccdfir.local

**Evidence:** `icat -o 0 inputs/AF-Case2.E01 88493`

### PowerShell Usage Timeline (from CLR log)

**Source:** `Users/IEUser/AppData/Local/Microsoft/CLR_v4.0/UsageLogs/powershell.exe.log`
**Inode:** 84020, **MTime:** 2023-02-22 18:59:36Z

The CLR usage log confirms PowerShell was used. The log shows .NET Fusion binding logs for Microsoft.PowerShell.ConsoleHost, System.Management.Automation, and related assemblies on 2023-02-22.

**Evidence:** `icat -o 0 inputs/AF-Case2.E01 84020`

## 2. Hosts File Modification

**Source:** `Windows/System32/drivers/etc/hosts`
**Inode:** 42564

Confirmed addition at end of file:
```
192.168.137.129	www.ccdfir.local
```

This redirects `www.ccdfir.local` to a local/VPN IP `192.168.137.129`, likely a C2 or communication server.

**Evidence:** `icat -o 0 inputs/AF-Case2.E01 42564`

## 3. Downloads Folder — Tools and Files

### User Downloads (`Users/IEUser/Downloads/`)

| File | Inode | MTime (UTC) | Description |
|------|-------|-------------|-------------|
| `John_0x61BE50C1_public.asc` | 126919 | 2023-02-22 23:31:21 | PGP public key for John |
| `Keys.txt` | 126939 | 2023-02-22 23:42:37 | PGP-encrypted message |

### AppData Downloads (`Users/IEUser/AppData/Local/Downloads/`) — Timeline

| Time (UTC) | Event |
|------------|-------|
| 2023-02-22 15:40:54 | `gpg4win-4.1.0.exe` (28 MB) downloaded via VMware Drag-and-Drop |
| 2023-02-22 15:41:22 | `AESCrypt_v310_x64.zip` (1.1 MB) downloaded via VMware DnD |
| 2023-02-22 15:44:09 | `7z2201-x64.exe` (1.5 MB) downloaded via VMware DnD |
| 2023-02-22 15:44:25 | `HxDSetup.zip` (3.3 MB) downloaded via VMware DnD |
| 2023-02-22 18:44:19 | `AESCrypt_v310_x64.zip` extracted: AESCrypt.msi, setup.exe, Install Notes.txt |
| 2023-02-22 18:45:31 | `vcredist_x64.exe` (10 MB) extracted |
| 2023-02-22 18:46:09 | `vcredist_x86.exe` (8.9 MB) extracted |
| 2023-02-22 18:54:55 | AESCrypt setup.exe and MSI accessed (installation) |
| 2023-02-22 18:55:17 | gpg4win-4.1.0.exe accessed (installation) |

**Tools installed:**
- **AES Crypt v3.10** (Windows GUI) — used to encrypt `README.txt` → `README.txt.aes`
- **Gpg4win 4.1.0** (Kleopatra) — used for PGP key generation and message encryption
- **7-Zip 22.01** — archive extraction
- **HxD Hex Editor** — hex editing

**Evidence:**
- `icat -o 0 inputs/AF-Case2.E01 62486` (AESCrypt_v310_x64.zip)
- `icat -o 0 inputs/AF-Case2.E01 62487` (gpg4win-4.1.0.exe)
- `icat -o 0 inputs/AF-Case2.E01 84596` (Install Notes.txt)
- Timeline entries at catalog/AF-Case2.E01/p0/timeline.csv

## 4. Documents Folder — Encryption Targets

| File | Inode | MTime (UTC) | Size | Description |
|------|-------|-------------|------|-------------|
| `README.txt.aes` | 126755 | 2023-02-22 20:21:17 | 418 B | AES Crypt encrypted README |
### R2D2.vhd — Two Versions (Important Correction)

s864a00 identified **two distinct** 100 MB VHD files:

| File | Inode | SHA256 | Contents |
|------|-------|--------|----------|
| `Users/IEUser/Documents/R2D2.vhd` | 126800 | `06d831eb…c26b34` | **Unencrypted** NTFS clone, volume name "R2D2", contains `DeceiveYou.png` (5324 B) with text: *"Your eyes can deceive you! R2D2 has been cloned :P"* |
| `ProgramData/Starwars/R2D2.vhd` | 126812 | `8eeec4b6…82f290` | **BitLocker-encrypted** (`-FVE-FS-`), GUID matches recovery key |

Jane created the VHD, cloned it (unencrypted copy in Documents), then applied BitLocker to the copy in `ProgramData\Starwars\`. The unencrypted clone contains `DeceiveYou.png` which hints at the deception: the Documents VHD appears to be the R2D2 volume but is actually an unencrypted decoy clone.
| `BitLocker Recovery Key EBB0BD7C-DB64-47F5-9A3B-03939F6E8F76.TXT` | 126830 | 2023-02-22 20:44:11 | 1348 B | BitLocker recovery key (UCS-2 LE) |

### README.txt.aes Header Analysis

```
Magic:      AES (0x41455302)
Version:    0x0002
CREATED_BY: aescrypt (Windows GUI) 3.10
Extensions: 0x0080 (only extension 0 present = none)
```

This confirms encryption with AES Crypt v3.10 for Windows.

**Evidence:** `icat -o 0 inputs/AF-Case2.E01 126755 | xxd | head -5`

### BitLocker Recovery Key

```
Identifier:    EBB0BD7C-DB64-47F5-9A3B-03939F6E8F76
Recovery Key:  011594-477554-129965-535183-310288-707949-274901-523688
```

**Evidence:** `icat -o 0 inputs/AF-Case2.E01 126830` (decoded from UCS-2 LE)

## 5. Recent Files (LNK Analysis)

### Key LNK files in `Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/`

| LNK File | Inode | Target Path | Notes |
|----------|-------|-------------|-------|
| `README.txt.lnk` | 27941 | `README.txt` (local dir) | Original README before AES encryption |
| `R2D2.vhd.lnk` | 126799 | `C:\ProgramData\Starwars\R2D2.vhd` | Original VHD location |
| `R2D2 (E).lnk` | 126818 | `E:\R2D2` | Mounted BitLocker volume; contains `DeceiveYou.png` |
| `DeceiveYou.png.lnk` | 126817 | `E:\DeceiveYou.png` | File inside mounted R2D2 volume |
| `BitLocker Recovery Key EBB0BD7C-DB64-47F5-9A3B-03939F6E8F76.TXT.lnk` | 126829 | `C:\Users\IEUser\Documents\BitLocker Recovery Key ...` | Access to recovery key |
| `Keys.txt.lnk` | 126958 | `C:\Users\IEUser\Downloads\Keys.txt` | PGP encrypted message |
| `John_0x61BE50C1_public.asc.lnk` | 126785 | `C:\Users\IEUser\Downloads\John_0x61BE50C1_public.asc` | Public key download |
| `Starwars.lnk` | 126756 | `C:\ProgramData\Starwars` | R2D2 container directory |
| `AESCrypt_v310_x64.lnk` | 124597 | `C:\Users\IEUser\AppData\Local\Downloads\AESCrypt_v310_x64` | AES Crypt install dir |
| `Install Notes.txt.lnk` | 124557 | AES Crypt install notes | |

**Evidence:** LNK target paths extracted via `icat` + `strings`

## 6. GNUPG / Kleopatra Activity

**Created:** 2023-02-22 20:24:59 UTC

### Key directories:
- `Users/IEUser/AppData/Roaming/gnupg/` — keyrings
- `Users/IEUser/AppData/Local/gnupg/` — sockets
- `Users/IEUser/AppData/Roaming/kleopatra/` — Kleopatra config

### Kleopatra Config (`kleopatrarc`, inode 126787):

```
LastKey=7F593AC74648A4E405BC63CB1B98BA46B52B04AD
Expanded=7F593AC74648A4E405BC63CB1B98BA46B52B04AD,9D3DD6052E53B6E15571DEAB15163C8361BE50C1
```

The second fingerprint `9D3DD6052E53B6E15571DEAB15163C8361BE50C1` matches the public key file `John_0x61BE50C1_public.asc` (key ID `0x61BE50C1`).

**Evidence:** `icat -o 0 inputs/AF-Case2.E01 126787`

## 7. R2D2 Volume Operations

### Timeline:

| Time (UTC) | Event |
|------------|-------|
| 2023-02-22 20:28:10 | `R2D2.vhd` clone created in `Documents/` (unencrypted NTFS, contains `DeceiveYou.png`) |
| 2023-02-22 20:28:17 | VHDMP Operational event log created (VHD mount attempt) |
| 2023-02-22 20:34:09 | `ProgramData/Starwars/R2D2.vhd` — the BitLocker-encrypted copy (100 MB, `-FVE-FS-`) |
| 2023-02-22 20:34:31 | `R2D2 (E).lnk` created — VHD mounted as E: drive |
| 2023-02-22 20:42:13 | `BitLockerWizardElev.exe` executed; BitLocker event log created |
| 2023-02-22 20:44:10 | BitLocker recovery key saved to Documents |
| 2023-02-22 21:26:14 | `BITLOCKERWIZARDELEV.EXE-E4CCF1B7.pf` prefetch file created |

Jane created a VHD, made an unencrypted clone in Documents (containing `DeceiveYou.png` with the message *"Your eyes can deceive you! R2D2 has been cloned :P"*), and applied BitLocker to the copy in `ProgramData\Starwars\`. The recovery key was saved to Documents.

## 8. Registry Artefacts — Explorer Activity

**Source:** `Users/IEUser/NTUSER.DAT`, inode 83438

### TypedPaths (Explorer address bar)

| Value | Path |
|-------|------|
| url1 | `C:\ProgramData\Starwars` |
| url2 | `C:\` |

Jane manually typed the `ProgramData\Starwars` path into Explorer's address bar.

### RecentDocs (Explorer recent documents, decoded from UCS-2 LE binary)

| # | Document | Notes |
|---|----------|-------|
| 0 | Downloads | Downloads folder |
| 1 | Local.lnk | Recent item |
| 2 | Install Notes.txt | AES Crypt install notes |
| 3 | AESCrypt_v310_x64 | AES Crypt directory |
| 4 | README.txt | Original README before encryption |
| 5 | R2D2.vhd | BitLocker VHD |
| 6 | Starwars | Starwars directory |
| 7 | ProgramData | ProgramData access |
| 8 | DeceiveYou.png | File from mounted R2D2 E: drive |
| 9 | R2D2 (E:) | Mounted R2D2 volume |
| 10 | BitLocker Recovery Key EBB0BD7C-DB64-47F5-9A3B-03939F6E8F76.TXT | Recovery key |
| 11 | John_0x61BE50C1_public.asc | John's public key |
| 12 | Keys.txt | Encrypted message |
| 13 | Quick access | Explorer quick access |

### RunMRU (Run dialog history)

Entries (from strings extraction of NTUSER.DAT):
- `kleopatra.exe` (`C:\Program Files (x86)\Gpg4win\bin\kleopatra.exe`) — Kleopatra PGP client launched
- Paths to AESCrypt installers: `setup.exe`, `vcredist_x64.exe`, `vcredist_x86.exe`
- The RunMRU key exists but values were empty at time of imaging.

### Console Settings (registry)
- Console settings found for both 64-bit and 32-bit PowerShell (`%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe` and SysWOW64 variant), confirming PowerShell was used interactively.

**Evidence:** `regipy` dump of inode 83438; strings extraction showing RunMRU/TypedPaths/RecentDocs

## 9. Desktop Contents

Minimal: only `desktop.ini` and `eula.lnk` (a license link). No significant user files.

## 10. Summary of User Activity (2023-02-22)

### Phase 1 — Tool Acquisition (15:40–15:45 UTC)
- Downloaded via VMware DnD: AESCrypt, Gpg4win, 7-Zip, HxD

### Phase 2 — Tool Installation (18:39–18:55 UTC)
- Opened PowerShell (18:39)
- Created `WindowsPowerShell` directory in Documents (18:42)
- Extracted AESCrypt (18:44)
- Installed AESCrypt (18:54–18:55)
- Installed Gpg4win (18:55)

### Phase 3 — README Encryption (19:46–20:21 UTC)
- Accessed `README.txt` (19:46, LNK created)
- Encrypted README.txt → README.txt.aes with AES Crypt (20:21)

### Phase 4 — R2D2 Volume Setup (20:24–20:47 UTC)
- Initialized GnuPG/Kleopatra (20:24)
- Moved R2D2.vhd to Documents (20:28)
- Created Starwars directory in ProgramData (20:34)
- Mounted R2D2 VHD as E: drive (20:34)
- Enabled BitLocker on E: (20:42)
- Saved recovery key (20:44)

### Phase 5 — PGP Communication (23:31–23:42 UTC)
- Downloaded `John_0x61BE50C1_public.asc` (23:31)
- Created/encrypted `Keys.txt` with PGP (23:42)

## 11. Open Questions / Gaps

- **CMD history**: No `doskey` or CMD history file found in the expected locations
- **RunMRU/TypedPaths/RecentDocs**: Now extracted from NTUSER.DAT (see Section 8). Fully corroborate Jane's encryption workflow
- **README.txt original**: The unencrypted README.txt was not found — it may have been deleted after encryption; s864a01 (recovery seat) should check $LogFile/$UsnJrnl for earlier copies
- **ConsoleHost_history.txt timestamps**: The PSReadLine history is dated 2023-02-20 (before tool downloads on 2023-02-22), suggesting the PowerShell session may be from an earlier date or the defender-disable commands were run in a prior session
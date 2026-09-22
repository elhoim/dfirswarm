# Disk and file system — AH-C09

Seat: s864a00 (Diskwright). Evidence from `ewfinfo`/`mmls`/`fsstat`/`fls`/`istat`/`icat` on `inputs/AF-Case2.E01` and catalog files. Times in this note are **UTC** unless labelled `+03` (istat local). Catalog `timeline.csv` is already UTC.

Scratch extracts: `work/s864a00/`. Shared copies: `work/extracted/DeceiveYou.png`, recovery-key TXT already in `work/extracted/`.

---

## 1. Acquisition (E01)

Command: `ewfinfo inputs/AF-Case2.E01`

| Field | Value |
| --- | --- |
| Case / evidence | 002, “Anti-Forensics Case 2”, notes: Crypto |
| Examiner | AHMK |
| Imager | FTK Imager ADI4.7.1.2 (file format FTK Imager, deflate, no compression) |
| Acquisition date (as stored) | Wed Feb 22 20:50:53 2023 (clock timezone **not** recorded) |
| Media | fixed disk, **not physical** (logical volume) |
| Bytes/sector | 512 |
| Sectors | 83,881,984 |
| Size | 39 GiB (42,947,575,808 bytes) |
| MD5 | `dc7d531c2b56efb1558f10a5db62ccc0` |
| SHA1 | `94a7d9e562f4316423ff09658cb0b88e332398f7` |

`img_stat` agrees: image type ewf, same size and MD5.

---

## 2. Host volume layout

Catalog `catalog/AF-Case2.E01/partitions.txt`: *no partition table; one NTFS volume starting at sector 0 (use TSK without `-o`)*.

`mmls inputs/AF-Case2.E01` exits 1 (no DOS/GPT table). This matches a **logical** NTFS export, not a full disk.

`fsstat inputs/AF-Case2.E01` (`catalog/AF-Case2.E01/p0/fsstat.txt`):

| Field | Value |
| --- | --- |
| File system | NTFS (TSK reports “Version: Windows XP” for NTFS 3.1 — ignore as OS ID) |
| Volume name | **Windows 10** |
| Volume serial | **BAB00A24B009E7A9** |
| Sector size | 512 |
| Cluster size | 4096 |
| Total sectors | 0–83,881,982 |
| Total clusters | 0–10,485,246 |
| MFT first cluster | 786,432 |
| MFT mirror cluster | 2 |
| MFT entry size | 1024 bytes |
| MFT range | 0–126,976 |
| Root | inode 5 |

`$Volume` (inode 3) `$VOLUME_NAME` size 20 bytes = “Windows 10” (UTF-16). `$MFT` (inode 0) $DATA size **130,023,424** = 126,976 × 1024.

Root `fls inputs/AF-Case2.E01` (not a full disk layout): `$MFT`, `$MFTMirr`, `$LogFile`, `$Volume`, `$AttrDef`, `$Bitmap`, `$Boot`, `$BadClus`, `$Secure`, `$UpCase`, `$Extend`, `$Recycle.Bin`, Users, ProgramData, Program Files, Windows, Boot, pagefile.sys, swapfile.sys, Recovery, System Volume Information, BGinfo, PerfLogs. No `hiberfil.sys`.

Host computer name from LNK strings: **msedgewin10**. Interactive user profile: **IEUser** (brief: Jane). Primary SID: `S-1-5-21-321011808-3761883066-353627080-1000`.

---

## 3. NTFS metadata files (for recovery seat)

| Object | Inode | Size | Notes |
| --- | --- | --- | --- |
| `$MFT` | 0 | 130,023,424 | first cluster 786432 |
| `$MFTMirr` | 1 | (standard) | cluster 2 |
| `$LogFile` | 2 | **57,360,384** | allocated; LSN in case files is live |
| `$Volume` | 3 | resident name | Windows 10 |
| `$Extend/$UsnJrnl:$J` | 80499 | **100,460,696** sparse | `$Max` ADS 80499-128-22 |
| `$Extend/$ObjId:$O` | 25 | | |
| `$Extend/$Quota` | 24 | | |
| `$Extend/$RmMetadata` | 27 | | TxF logs present; several `$Txf/*` deleted |
| System Volume Information | 80500 | | **no VSS snapshot `{GUID}` stores** — only IndexerVolumeGuid, MountPointManagerRemoteDatabase, tracking.log, Wcifs.md, WPSettings.dat |

There is **no volume shadow copy** to roll back README.txt. Recovery of the pre-AES README is `$LogFile` / `$UsnJrnl` / unallocated (s864a01).

---

## 4. File list and deleted entries

Catalog `filelist.txt`: **163,914** lines (`fls -r -p`). **6,823** lines carry TSK’s deleted `*` marker; **5,812** of those are `* 0:` (name in directory index, MFT entry already reused). Remaining deleted names are overwhelmingly WinSxS/LCU, AppRepository, OneDrive binaries, CryptnetUrlCache — not case files.

**Recycle Bin** (`fls -r -p` inode 58):

- `$Recycle.Bin/S-1-5-18` (SYSTEM) — `desktop.ini` only
- `$Recycle.Bin/S-1-5-21-…-1000` (IEUser) — `desktop.ini` only
- `$Recycle.Bin/S-1-5-21-…-1001` — `desktop.ini` only

No `$I*`/`$R*` payloads. User did **not** recycle README, R2D2, or Keys.txt.

**Original `README.txt` is not in the live MFT.** USN (`$UsnJrnl:$J` inode 80499, parsed by s864a01) shows it lived as **MFT 27936 seq 3**, parent Documents 83446: created 19:46:01Z as `New Text Document.txt`, renamed 19:46:04Z to `README.txt`, data written 20:20:06Z, deleted 20:21:25Z (8 seconds after `README.txt.aes`). At 20:23:37Z MFT 27936 was reused (seq 4) for an Edge cache SVG — resident plaintext is gone from the current entry. Filelist hits:

- `Users/IEUser/Documents/README.txt.aes` (inode **126755**, allocated, 418 bytes, resident $DATA)
- `Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/README.txt.lnk` (inode **27941**)

`strings` of the LNK: target `C:\Users\IEUser\Documents\README.txt` on volume “Windows 10”, machine `msedgewin10`. LNK $SI created **2023-02-22 22:46:04 +03 = 19:46:04Z**, modified **23:15:43 +03 = 20:15:43Z**. AES file created **20:21:17Z**. So plaintext existed, was opened, then replaced by AES Crypt; the MFT no longer has a `README.txt` name.

Deleted `Users/IEUser/windows.iso` (`* 0:`) is unrelated leftover.

---

## 5. Case-relevant files on the host NTFS

| Path | Inode | Size | $SI created (UTC) | $SI modified (UTC) | SHA256 (extract) |
| --- | --- | --- | --- | --- | --- |
| `Users/IEUser/Documents/README.txt.aes` | 126755-128-1 | 418 (resident) | 2023-02-22T20:21:17Z | same | `a2536e1a916d79bdc4ba8e86907b49aba35eeb539f79fad68492ded91a697186` |
| `Users/IEUser/Documents/R2D2.vhd` | 126800-128-3 | 104,858,112 | 2023-02-22T20:28:10Z | 2023-02-22T20:45:51Z | `06d831ebe2d83159b3299b2ee430ef81e6896bec6c7403fb7dc73ea64dc26b34` |
| `ProgramData/Starwars/R2D2.vhd` | 126812-128-1 | 104,858,112 | 2023-02-22T20:34:09Z | 2023-02-22T20:47:40Z | `8eeec4b65cc3c3db07fa3f44d1a5556a8f4a23ba71323fd2f5615ea29a82f290` |
| `Users/IEUser/Documents/BitLocker Recovery Key EBB0BD7C-DB64-47F5-9A3B-03939F6E8F76.TXT` | 126830-128-4 | 1,348 (UTF-16LE) | 2023-02-22T20:44:10Z | 2023-02-22T20:44:10Z | `d3956c4e99080da7133b51eab1feac017684a1f901b8aea5179dfc9f510a12eb` |
| `Users/IEUser/Downloads/John_0x61BE50C1_public.asc` | 126919-128-5 | 661 | 2023-02-22T23:31:21Z | 2023-02-22T23:31:21Z | `3f23dfa66997fda56fde3d22340fc15b8e58b28d664da1d11b84cded59403956` |
| `Users/IEUser/Downloads/John_…asc:Zone.Identifier` | 126919-128-6 | 209 resident | (same entry) | | ZoneId=3, HostUrl `https://www.ccdfir.local/api/v4/files/7ua159m88tyjxcw9s8i8au1f5r?download=1`, HostIp `192.168.137.129` |
| `Users/IEUser/Downloads/Keys.txt` | 126939-128-1 | 443 (resident) | 2023-02-22T23:42:31Z | 2023-02-22T23:42:37Z | `dbfd737dbe8f5339086c3425c556d99870a3c8b427c3717a533c8df0ab2c5745` |

IEUser **Documents** (inode 83446) contains only: `desktop.ini`, `README.txt.aes`, `R2D2.vhd`, BitLocker recovery TXT.  
IEUser **Downloads** (inode 83445) contains only: `desktop.ini`, `John_0x61BE50C1_public.asc`, `Keys.txt`.

AES Crypt payload is **AESCrypt version 2**: magic `AES\x02`, `CREATED_BY=aescrypt (Windows GUI) 3.10`. Installed at `Program Files/AESCrypt/` (inodes 126715–126718).

GPG user dir: `Users/IEUser/AppData/Roaming/gnupg/` (private-keys-v1.d inodes 126846, 126847). Crypto seat owns decryption.

---

## 6. R2D2 volumes (part 2) — two different files

Both are **fixed VHDs** (footer cookie `conectix`, creator `win `/`Wi2k`, virtual size 100 MiB = 104,857,600 + 512-byte footer). DOS MBR, one type-`0x07` partition **LBA 128–198,783** (198,656 sectors = 101,711,872 bytes), then unallocated to sector 204,800.

They are **not** copies of each other (different SHA256).

### 6.1 `Users/IEUser/Documents/R2D2.vhd` — **unencrypted** NTFS named R2D2

```
mmls work/s864a00/vhd/R2D2_Documents.vhd
# slot 000:000  start 128  NTFS/exFAT (0x07)

fsstat -o 128 work/s864a00/vhd/R2D2_Documents.vhd
# Volume Name: R2D2
# Volume Serial Number: 225E3B4C5E3B17CD
# Cluster Size: 4096; Total Sector Range: 0-198654; MFT range 0-256
```

Volume boot OEM at partition offset 0: `NTFS    ` (not BitLocker).

`fls -r -p -o 128` user-visible file:

| Path | VHD inode | Size | Notes |
| --- | --- | --- | --- |
| `DeceiveYou.png` | **39** | 5,324 | 736×177 RGB PNG |
| `$RECYCLE.BIN/S-1-5-21-…-1000/desktop.ini` | 42 | | empty recycle |

**No other user files.** This *is* the volume Jane mounted as **E:** (`Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/R2D2 (E).lnk`, inode 126818, 20:34:31Z).

`istat -o 128 … 39` (`DeceiveYou.png`):

- $FILE_NAME created **2023-02-22 23:34:28.886 +03 = 20:34:28Z** (copy onto the VHD)
- $STANDARD_INFORMATION Created **20:33:18 +03 = 17:33:18Z** (embedded original timestamp)
- $DATA non-resident 5,324 bytes, clusters 1992–1993 of the VHD NTFS

Extract: `icat -o 128 work/s864a00/vhd/R2D2_Documents.vhd 39` → `work/extracted/DeceiveYou.png`  
SHA256 `a77e68f5fd9ae158940b0106fd56afbbd65999764adedfa1c3fd9578fdc88182`

Visible text (yellow on black):

> Your eyes can deceive you!  
> R2D2 has been cloned :P

That is the part-2 punchline on disk **without** unlocking BitLocker: the Documents VHD is the clone.

### 6.2 `ProgramData/Starwars/R2D2.vhd` — **BitLocker**

```
fsstat -o 128 work/s864a00/vhd/R2D2_Starwars.vhd
# Encryption detected (BitLocker)
```

Partition boot OEM: **`-FVE-FS-`**. `-FVE-FS-` also at partition byte offset **35,586,048** (0x21f0000) — FVE metadata block.

FVE metadata (parsed from that block):

| Field | Value |
| --- | --- |
| Signature | `-FVE-FS-` |
| Volume GUID | **EBB0BD7C-DB64-47F5-9A3B-03939F6E8F76** (matches the recovery-key filename and file body) |
| Description (UTF-16) | `R2D2 2/22/2023` |
| Encryption method bytes | `04 80` = **0x8004** (BitLocker AES-XTS 128 in libbde constants) — treat as metadata, not a decrypted proof |

Directory `ProgramData/Starwars` inode **126808**, created 2023-02-22 23:34:00 +03 = **20:34:00Z**. VHD $FILE_NAME 20:34:09Z; $DATA last modified **20:47:40Z** (after the recovery key was saved at 20:44:10Z and after BitLockerWizardElev at 20:42:13Z per prefetch — s864a04).

Starwars copy $DATA starts at host cluster **9,559,136** (contiguous). Documents copy starts at host cluster **490,895**. Two independent allocations.

### 6.3 Recovery key (location only; decryption is s864a05)

`icat inputs/AF-Case2.E01 126830` is UTF-16LE (BOM `FF FE`):

- Identifier: `EBB0BD7C-DB64-47F5-9A3B-03939F6E8F76`
- Recovery Key: `011594-477554-129965-535183-310288-707949-274901-523688`

No `.bek` files and no `$FVE` on the **host** NTFS. BitLocker is confined to the Starwars VHD.

This host has **no** `dislocker`/`bdemount` in the kickoff toolbox. TSK already flags the Starwars partition as BitLocker. The hidden file is nonetheless readable from the **unencrypted clone** (Documents VHD). Whether the BitLocker volume contains the same PNG or extra files is s864a05’s decryption (or a documented host-gap).

---

## 7. Timeline of disk objects (UTC)

| Time | What |
| --- | --- |
| 2019-03-19/20 | Volume formatted; `$MFT`/`$Volume` created (~21:52Z / 00:52 +03) |
| 2023-02-22 19:46:04 | `README.txt.lnk` created (plaintext README existed) |
| 2023-02-22 20:15:43 | `README.txt.lnk` last modified (last open of plaintext) |
| 2023-02-22 20:21:17 | `README.txt.aes` created (inode 126755); plaintext name gone from MFT |
| 2023-02-22 20:28:10 | Documents `R2D2.vhd` created (unencrypted NTFS “R2D2”) |
| 2023-02-22 20:34:00 | `ProgramData/Starwars` created |
| 2023-02-22 20:34:09 | Starwars `R2D2.vhd` created (clone) |
| 2023-02-22 20:34:28 | `DeceiveYou.png` $FN on the unencrypted VHD |
| 2023-02-22 20:34:31 | `R2D2 (E).lnk` — mounted as E: |
| 2023-02-22 20:44:10 | BitLocker recovery TXT written to Documents |
| 2023-02-22 20:45:51 | Documents VHD $DATA last modified |
| 2023-02-22 20:47:40 | Starwars VHD $DATA last modified (BitLocker in place) |
| 2023-02-22 23:31:21 | `John_0x61BE50C1_public.asc` in Downloads |
| 2023-02-22 23:42:31 | `Keys.txt` (PGP MESSAGE) in Downloads |
| 2023-02-22 23:44:56 | Starwars VHD $SI accessed |

---

## 8. Pointers for other seats

- **s864a01 recovery:** no VSS; `$LogFile` 57 MB inode 2; `$UsnJrnl:$J` inode 80499. USN: original README = MFT **27936 seq 3**, deleted 20:21:25Z, reused 20:23:37Z. `$LogFile` wrapped — no README plaintext (s864a01). Names `R2D2.vhd.bak` / `R2D2.7z` appear in `$LogFile` and 7zG prefetch (inode 84423, 23:44:56Z) but **neither is in the live MFT** (filelist has only the two `.vhd` files).
- **s864a05 BitLocker:** encrypted volume is **only** `ProgramData/Starwars/R2D2.vhd` (inode 126812). Key file inode 126830. Do not treat Documents `R2D2.vhd` as BitLocker — it is the clone. Host lacks dislocker; contents of the FVE volume still unproven until decrypted. Unencrypted clone already yields `DeceiveYou.png`.
- **s864a06 crypto:** README.aes inode 126755; Keys.txt 126939; John asc 126919; gnupg private keys 126846/126847.
- **s864a02 caches:** Zone.Identifier on John’s key points at Mattermost-style `www.ccdfir.local`.
- **s864a07 timeline:** see ledger seq 62–65 for clone/BitLocker/PNG events. **Correct IOC seq 16** if it still says Documents R2D2.vhd is BitLocker-encrypted — it is not.

---

## 9. Commands (reproducible)

```bash
ewfinfo inputs/AF-Case2.E01
mmls inputs/AF-Case2.E01          # fails: no table
fsstat inputs/AF-Case2.E01
fls inputs/AF-Case2.E01
istat inputs/AF-Case2.E01 126755 126800 126812 126830 126919 126939 0 2 80499
icat inputs/AF-Case2.E01 126755   # README.txt.aes
icat inputs/AF-Case2.E01 126830   # recovery key UTF-16LE
icat inputs/AF-Case2.E01 126800 > work/s864a00/vhd/R2D2_Documents.vhd
icat inputs/AF-Case2.E01 126812 > work/s864a00/vhd/R2D2_Starwars.vhd
mmls work/s864a00/vhd/R2D2_Documents.vhd
fsstat -o 128 work/s864a00/vhd/R2D2_Documents.vhd
fls -r -p -o 128 work/s864a00/vhd/R2D2_Documents.vhd
icat -o 128 work/s864a00/vhd/R2D2_Documents.vhd 39 > work/extracted/DeceiveYou.png
fsstat -o 128 work/s864a00/vhd/R2D2_Starwars.vhd   # Encryption detected (BitLocker)
```

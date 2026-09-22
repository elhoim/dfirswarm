# Disk and file system — AH-C08 NTFS-HiddenFiles

Seat: sfcc300. Image: `inputs/NTFS-HiddenFiles.E01` (logical NTFS volume, no partition table; run TSK without `-o`). Catalog already ran `mmls`/`fsstat`/`fls`/`mactime`; this note is the MFT-level pass.

Volume serial `E0FA70C9FA709D8A`, label `Back2College`, NTFS (Windows XP), sector 512, cluster 4096, MFT entries 1024 bytes, range 0–256, first MFT cluster 8277. Acquisition (FTK Imager 4.7.1.2): MD5 `e7d5b36a407d5a02d0872d4dd3f3f9d0`, SHA1 `5edc4c6efda9d266ecabcab5629694d0063e9d7f`.

Commands used throughout: `fsstat inputs/NTFS-HiddenFiles.E01`, `fls -rdp inputs/NTFS-HiddenFiles.E01`, `istat inputs/NTFS-HiddenFiles.E01 <inode>`, `icat inputs/NTFS-HiddenFiles.E01 <inode-attr>`, `ils`, `tsk_recover`, `blkcat`/`blkls`, raw `$MFT` via `icat … 0`.

## Volume layout

| Item | Value | Evidence |
| --- | --- | --- |
| Partition table | none (logical volume at sector 0) | `catalog/NTFS-HiddenFiles.E01/partitions.txt` |
| FS | NTFS, OEM `NTFS`, XP | `catalog/…/p0/fsstat.txt` |
| Clusters | 0–24830 (24831 × 4 KiB ≈ 97 MiB) | fsstat |
| `$MFT` | 262144 B = 256 records | icat 0; `istat 0` |
| `$MFT` bitmap | 167 allocated records: 0–15, 17–19, 24–171 (16 and 20–23 free) | icat `0-176-12` |
| `$BadClus:$Bad` | one sparse run covering the whole volume; no real bad clusters | MFT 8 runlist `[(24831, None)]` |
| Bitmap vs runlists | 2027 allocated clusters, 0 orphans, 0 extra | parsed every non-resident run vs icat 6 |

User tree is `Documents/{Life,Misc,Personal,Test,Work}/<2000–2023>/` plus a handful of real files. Recycle Bin SID `S-1-5-21-321011808-3761883066-353627080-1000` holds only `desktop.ini` (129 B).

## The five hidden items

### 1. File ADS — `README.txt:Secrets.txt`

| Field | Value |
| --- | --- |
| Path | `Documents/Misc/2023/README.txt:Secrets.txt` |
| Inode | 168, `$DATA` 128-4 |
| Host file | `README.txt` `$DATA` 128-1 resident 15 B = `Welcome Back \r\n` |
| Size | 154 bytes, **resident** in the MFT record |
| SHA256 | `8c00d35da2b198fbf404bf6c7b465a5a61d0898315ea438851fb351c2d002aac` |
| MD5 | `29c816aafe3cba923215acf85a22063b` |
| NTFS structure | named `$DATA` on a file |
| Reveal | `fls -rdp inputs/NTFS-HiddenFiles.E01` (shows `168-128-4: … README.txt:Secrets.txt`); `istat … 168`; `icat … 168-128-4` |

Content (password riddle):

```
The password is the name of the Sherlock Holmes author, combined with the year of his first appearing.

Note: each name starts with an uppercase letter.
```

Solution used later: `ArthurConanDoyle1887` (Arthur Conan Doyle, *A Study in Scarlet* 1887).

`$STANDARD_INFORMATION` (local +03): created 2023-03-20 01:57:43, modified 01:58:17. UTC: 2023-03-19 22:57:43Z / 22:58:17Z.

### 2. Directory ADS — `Photos:flag1.jpg`

| Field | Value |
| --- | --- |
| Path | `Documents/Life/2020/Photos:flag1.jpg` (also listed as `Photos/.:flag1.jpg`) |
| Inode | 169 (allocated **directory**), `$DATA` 128-4 |
| Size | 15282 bytes, non-resident, clusters 1426–1429 |
| Type | JPEG 434×232, JFIF 1.01 |
| SHA256 | `28d073e6e01b911a9de12893ab464df3cb7983727c7f15754eb561321cf09cdc` |
| MD5 | `394ecdd91dda7ea59227d5e0a745a4ce` |
| NTFS structure | named `$DATA` on a directory (directories normally have `$INDEX_ROOT`/`$INDEX_ALLOCATION`, not `$DATA`) |
| Reveal | `fls -rdp` line `d/r 169-128-4`; `istat … 169`; `icat … 169-128-4` |

Created 2023-03-20 02:01:03 +03 = 2023-03-19 23:01:03Z. Last-cluster slack (1102 B) is zeros.

### 3. Directory ADS + false extension — `Tools:flag2.jpg`

| Field | Value |
| --- | --- |
| Path | `Documents/Work/2023/Tools:flag2.jpg` |
| Inode | 170 (allocated **directory**), `$DATA` 128-4 |
| Size | 71266 bytes, non-resident, clusters 1430–1447 |
| Type | ZIP, not JPEG (`PK\x03\x04`) |
| SHA256 | `ad1f0edb2202ec1a736d9266b18b241eac5542c350578a3a8cdb4dd8b14ff37d` |
| MD5 | `7bc9d240f9eb3cc42b450ed568aad599` (matches item 5) |
| ZIP members | `AlternateStreamView.exe` (115528), `AlternateStreamView.chm` (16424), `readme.txt` (11620) — NirSoft AlternateStreamView v1.58 |
| NTFS structure | named `$DATA` on a directory + misleading `.jpg` name |
| Reveal | `fls -rdp` `d/r 170-128-4`; `istat … 170`; `icat … 170-128-4`; `file` / `zipfile` |

Created 2023-03-20 02:03:36 +03 = 2023-03-19 23:03:36Z. Slack (2462 B) zeros.

### 4. Fake metadata file `$Quota` at volume root

Real NTFS quota lives at `$Extend/$Quota` (inode **24**, indexes `$O`/`$Q`). Inode **15** is a user file named `$Quota` parented to root (MFT 5), flags **Hidden, System, Archive**.

| Field | Value |
| --- | --- |
| Path | `\$Quota` (root) |
| Inode | 15-128-1 |
| Size | 4096 bytes, cluster 1417 |
| SHA256 | `9e60e08966cf08c9fa85bd5b89b0630212e6477312745f9809e9887fd76545ea` |
| MD5 | `f28683f88f54ad15ee7cbee9d0407a83` |
| SI created | 2023-03-20 01:46:54.860 +03 = **2023-03-19 22:46:54Z** |
| SI modified | 2023-03-20 01:43:29.599 +03 = **2023-03-19 22:43:29Z** (before volume format — timestomp) |
| Reveal | `fls inputs/NTFS-HiddenFiles.E01 5` (root listing); `istat … 15`; `icat … 15` |

On-disk layout of the 4096-byte `$DATA`:

| Offset | Content |
| --- | --- |
| 0x00 | ASCII `0102030405060708090A0B0C0D0E0F00` (NIST-style 16-byte key written as hex text) |
| 0x20 | `NTFS QUOTA CODE 100 MB` |
| 0x38–0xFF | `0xFF` padding |
| 0x100–0x7E9 | 1770 bytes high-entropy (entropy ≈ 7.1–7.2); not decrypted here (AES/RC4/XOR with the NIST key and the password did not yield a known magic) |
| 0x7EA | plaintext `ArthurConanDoyle1887` (20 bytes) — same string as the Secrets.txt riddle |
| 0x7FE | `55 AA` (block signature) then zeros to 0xFFF |

**Chkdsk story** (`icat 18`, UTF-16LE `Chkdsk20230319224748.log`, created 2023-03-20 01:47:48 +03 = 22:47:48Z):

- `The file attributes flag 0x20 in file 0xf is incorrect. The expected value is 0x26.` (ARCHIVE vs ARCHIVE|HIDDEN|SYSTEM)
- `Index entry $Quota of index $I30 in file 0x5 points to unused file 0x27. Deleting index entry $Quota…`
- `Recovering orphaned file $Quota (F) into directory file 5.`

So the file was also **unlinked / orphaned** (root `$I30` still named `$Quota` but pointed at unused record 0x27) until chkdsk reattached inode 0xF. Second chkdsk (`inode 19`, 22:51:33Z) reported a clean volume.

Hiding stack: metadata-looking name + Hidden/System + orphaned index + timestomped SI + payload/password inside `$DATA`.

### 5. Unused bytes of reused `$MFT` record 171

`WelcomeBack.txt` (inode 171, parent `Documents/Personal/2023`) is a normal 1011-byte non-resident file (cluster 1448, `$DATA` 128-3). **Sequence number is 2** — the record was reused.

After the attribute terminator `0xFFFFFFFF` at record offset `0x180`:

```
FF FE  H a s h   f o r   f l a g 2 :   7 B C 9 D 2 4 0 F 9 E B 3 C C 4 2 B 4 5 0 E D 5 6 8 A A D 5 9 9  CR LF
```

UTF-16LE (BOM `FF FE`): `Hash for flag2: 7BC9D240F9EB3CC42B450ED568AAD599`

That MD5 equals `flag2.jpg` (item 3). Extract: dump `$MFT` (`icat … 0`) and read record `171 * 1024`; `istat … 171` shows Sequence 2.

This is **not** cluster slack of the current `$DATA` (that slack is zeros). It is leftover resident content in the unused tail of the 1024-byte FILE record after a previous occupant (or an earlier resident `$DATA`) was replaced.

Created 2023-03-20 02:26:32 +03 = 2023-03-19 23:26:32Z.

## Other NTFS tricks checked (not counted as the five)

| Check | Result |
| --- | --- |
| `$EA` / `$EA_INFORMATION` (types 224 / 208) | none on allocated FILE records 0–255 (raw MFT walk + `istat`) |
| Deleted files | `ils` all allocated; `tsk_recover` recovered 0 files |
| Unallocated clusters | `blkls` — no non-zero interesting strings; bitmap/runlist match |
| File slack of flag1, flag2, WelcomeBack | zeros |
| `$Extend/$Deleted` inode 29 | Hidden+System directory, empty `$I30`; 16-cluster `$INDEX_ALLOCATION` starting at cluster 38 is zeros (`init_size` 0). Decoy metadata name, no payload |
| `$OrphanFiles` (fls `V/V 256`) | TSK virtual node, not an on-disk record |
| `$BadClus` | fully sparse |
| Extra `$DATA` on `$Volume` / root | `$Volume` `$DATA` size 0; root has no named `$DATA` |
| Hard links / extra `$FILE_NAME` | one FN per user file |
| INDX slack | year-folder names only; no deleted extra names |
| Recycle Bin | only `desktop.ini` |
| Year-folder timestomp | SI File Modified `2023-03-19 20:42:32 +03` vs FN created `2023-03-20 01:55:01 +03` on e.g. inode 44 (`Documents/Life/2000`) — attribute inconsistency, not a hidden file |
| `$Boot` extra 512 B | standard bootmgr error strings |

## How each technique maps to NTFS

| # | Technique | Structure | Detection |
| --- | --- | --- | --- |
| 1 | ADS on a file | named `$DATA` (128) | `fls -r` / `istat` extra `$DATA` |
| 2 | ADS on a directory | named `$DATA` on a dir inode | `fls` `d/r`; `istat` `$DATA` + `$INDEX_ROOT` |
| 3 | ADS on a directory + fake extension | same + ZIP magic vs `.jpg` | `icat` + `file` |
| 4 | Metadata masquerade + Hidden/System + orphan + timestomp + resident/non-resident payload | `$FILE_NAME` `$Quota` on root; SI flags 0x26; `$I30` of 5; SI vs FN times; `$DATA` | `fls` root; compare to `$Extend/$Quota`; `istat`; chkdsk log; `icat 15` |
| 5 | MFT unused-area remnant after record reuse | FILE record tail after `0xFFFFFFFF`, sequence > 1 | `icat 0` + parse record 171; `istat` Sequence |

## Extracts (quarantine)

Under `work/extracted/`: `README.txt`, `Secrets.txt`, `WelcomeBack.txt`, `flag1.jpg`, `flag2.jpg`, `flag2zip/*`, `Quota.bin`, `chkdsk18.log`, `chkdsk19.log`. Raw `$MFT`: `work/sfcc300/mft.bin`.

## Commands cheat-sheet

```
fsstat inputs/NTFS-HiddenFiles.E01
fls -rdp inputs/NTFS-HiddenFiles.E01
istat inputs/NTFS-HiddenFiles.E01 168   # Secrets ADS
istat inputs/NTFS-HiddenFiles.E01 169   # flag1 dir ADS
istat inputs/NTFS-HiddenFiles.E01 170   # flag2 dir ADS
istat inputs/NTFS-HiddenFiles.E01 15    # fake $Quota
istat inputs/NTFS-HiddenFiles.E01 171   # seq=2 WelcomeBack
icat  inputs/NTFS-HiddenFiles.E01 168-128-4
icat  inputs/NTFS-HiddenFiles.E01 169-128-4
icat  inputs/NTFS-HiddenFiles.E01 170-128-4
icat  inputs/NTFS-HiddenFiles.E01 15
icat  inputs/NTFS-HiddenFiles.E01 18    # chkdsk UTF-16LE
icat  inputs/NTFS-HiddenFiles.E01 0     # $MFT; record 171 at offset 171*1024
```

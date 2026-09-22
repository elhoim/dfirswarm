# Timeline — Case AH-C08: NTFS Hidden Files

Built from `ledger/ledger.md`. All timestamps are UTC.

## Event chronology

| # | Time (UTC) | Event | Inode(s) | Evidence |
| --- | --- | --- | --- | --- |
| 1 | 2023-03-19 22:45:01 | **Volume creation.** NTFS volume "Back2College" formatted (Windows XP). All system metadata files ($MFT, $LogFile, $Volume, $Bitmap, $Boot, $Secure, $UpCase, $Extend, $AttrDef, $BadClus) created with identical MACB timestamps. Volume serial: E0FA70C9FA709D8A. | 0-11, 24-35 | `ledger/ledger.md` seq 7; `catalog/.../fsstat.txt` |
| 2 | 2023-03-19 22:45:06 | System Volume Information created. IndexerVolumeGuid written (76 bytes). | 36, 38 | `ledger/ledger.md` seq 1 |
| 3 | 2023-03-19 22:46:54 | **$Quota tampered.** File attribute flags changed from 0x26 (System+Hidden) to 0x20 (Archive). File unlinked from root directory $I30 index. Planted message "NTFS QUOTA CODE 100 MB" + hex key `0102...0F00` + encrypted blob + password trailer embedded in the file. | 15 | `ledger/ledger.md` seq 20; `catalog/.../bodyfile.txt`; Chkdsk log (inode 18) |
| 4 | 2023-03-19 22:47:48 | **First Chkdsk** run. Detects and fixes: attribute flag 0x20→0x26 in file 0xF ($Quota); stale index entry $Quota→unused file 0x27; recovers orphaned $Quota into root directory. 256 records, 278 index entries. | 17, 18 | `ledger/ledger.md` seq 5; Chkdsk log (inode 18) |
| 5 | 2023-03-19 22:50:55 | $RECYCLE.BIN created with SID `S-1-5-21-321011808-3761883066-353627080-1000`. desktop.ini written. | 39-41 | `catalog/.../bodyfile.txt` |
| 6 | 2023-03-19 22:51:33 | **Second Chkdsk** run (forced dismount). No problems found. 256 records, 284 index entries. | 19 | `ledger/ledger.md` seq 2; Chkdsk log (inode 19) |
| 7 | 2023-03-19 22:55:01 | **Directory tree created.** `/Documents` populated with Life, Misc, Personal, Test, Work subtrees, each containing year directories 2000–2023. | 42-167 | `ledger/ledger.md` seq 3 |
| 8 | 2023-03-19 22:57:43 | **Hidden item 3 created.** `README.txt` (15 bytes, resident, inode 168-128-1) written to `Documents/Misc/2023/`. Simultaneously, **ADS `Secrets.txt`** (154 bytes, resident, inode 168-128-4) attached. Contains password riddle: Sherlock Holmes author + first appearance year → ArthurConanDoyle1887. | 168 | `ledger/ledger.md` seq 4, 18 |
| 9 | 2023-03-19 23:01:03 | **Hidden item 1 created.** Directory `Documents/Life/2020/Photos` (inode 169) with **ADS `flag1.jpg`** (15,282 bytes, JPEG, SHA256: `28d073e6…09cdc`). Directories normally have only $INDEX_ROOT; adding a named $DATA stream hides the file. | 64, 169 | `ledger/ledger.md` seq 6, 17 |
| 10 | 2023-03-19 23:03:36 | **Hidden item 2 created.** Directory `Documents/Work/2023/Tools` (inode 170) with **ADS `flag2.jpg`** (71,266 bytes, actually ZIP containing AlternateStreamView v1.58). Misnamed extension + ADS-on-directory. SHA256: `ad1f0edb…ff37d`, MD5: `7BC9D240F9EB3CC42B450ED568AAD599`. | 167, 170 | `ledger/ledger.md` seq 8, 21 |
| 11 | 2023-03-19 23:26:32 | **WelcomeBack.txt** (1,011 bytes, inode 171) created at `Documents/Personal/2023/`. AI-generated welcome letter from ChatGPT. Uses $DATA attr id 3. **MFT slack** at offset 0x180 in this record contains hidden **Hidden item 4**: UTF-16LE string "Hash for flag2: 7BC9D240F9EB3CC42B450ED568AAD599". | 117, 171 | `ledger/ledger.md` seq 9, 30 |
| 12 | 2023-03-20 00:13:35 | **Mass access event.** All user directories and hidden ADS files show access-time update — likely investigator browsing. | 39-170 | `ledger/ledger.md` seq 10 |
| 13 | 2023-03-20 03:20:57 | **Forensic acquisition.** Volume imaged with FTK Imager 4.7.1.2. Image MD5: `e7d5b36a407d5a02d0872d4dd3f3f9d0`, SHA1: `5edc4c6efda9d266ecabcab5629694d0063e9d7f`. | — | `ledger/ledger.md` seq 11 |

## Five hidden items

| # | Name | Path | Inode (stream) | Size | Technique | Detection | Content / Hash |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `flag1.jpg` | `Documents/Life/2020/Photos:flag1.jpg` | 169-128-4 | 15,282 B | **ADS on directory** — named $DATA stream on a directory MFT record (normally directories have only $INDEX_ROOT) | `fls -r` shows `d/r` type; `istat 169` shows $DATA(128-4) name=flag1.jpg | JPEG 434×232. SHA256: `28d073e6e01b911a9de12893ab464df3cb7983727c7f15754eb561321cf09cdc` |
| 2 | `flag2.jpg` | `Documents/Work/2023/Tools:flag2.jpg` | 170-128-4 | 71,266 B | **ADS on directory** + **misnamed extension** — named $DATA stream on directory, file is ZIP not JPEG | `fls -r` shows `d/r`; `file` identifies ZIP; extraction reveals AlternateStreamView v1.58 | ZIP archive. MD5: `7BC9D240F9EB3CC42B450ED568AAD599`. SHA256: `ad1f0edb2202ec1a736d9266b18b241eac5542c350578a3a8cdb4dd8b14ff37d` |
| 3 | `Secrets.txt` | `Documents/Misc/2023/README.txt:Secrets.txt` | 168-128-4 | 154 B | **ADS on file** + **resident data** — named $DATA stream on a regular file, both streams stored resident in MFT record | `fls -r` shows `r/r 168-128-4`; `istat 168` shows $DATA(128-1) Resident + $DATA(128-4) name=Secrets.txt Resident | Password riddle text. SHA256: `8c00d35da2b198fbf404bf6c7b465a5a61d0898315ea438851fb351c2d002aac` |
| 4 | Hash message | `WelcomeBack.txt` MFT record slack | 171-128-3 (slack) | 118 B | **MFT slack / reused record** — UTF-16LE data hidden in unused bytes of MFT record 171 after the $DATA attribute | `icat $MFT (0-128-13)` and examine record 171 offset 0x180; `xxd` at offset 0x180 shows marker `11223344` + UTF-16LE string | UTF-16LE: `Hash for flag2: 7BC9D240F9EB3CC42B450ED568AAD599` |
| 5 | `$Quota` tampering | `/` (root, recovered by Chkdsk) | 15-128-1 | 4,096 B | **Unlinked/orphaned file** (removed from root $I30 index) + **attribute flag tampering** (0x20 Archive vs expected 0x26 System+Hidden) + **timestomping** (mtime 22:43:29 before ctime 22:46:54) | Chkdsk log (inode 18) detects: "file attributes flag 0x20 in file 0xF is incorrect" and "Recovering orphaned file $Quota (F) into directory file 5" | Contains: hex key `0102…0F00` + `NTFS QUOTA CODE 100 MB` + 1,770-byte encrypted blob + password `ArthurConanDoyle1887` |

## Detection methods

| # | Technique | NTFS structure | Detection command |
| --- | --- | --- | --- |
| 1, 2 | ADS on directory | Named $DATA attribute (128) on directory MFT record (normally dirs have only $INDEX_ROOT 144) | `fls -r -p` reveals `d/r` type entries; `istat <inode>` shows $DATA with name |
| 3 | ADS on file + resident data | Multiple $DATA attributes on single MFT record, stored resident (inside record, no cluster allocation) | `fls -r -p` shows `r/r` with colon notation; `istat <inode>` shows multiple Resident $DATA attrs |
| 4 | MFT slack space | Unused bytes after the last attribute in an MFT record (records are fixed 1024 bytes) | `icat $MFT` → parse record at offset `inode × 1024`, inspect bytes after end-of-attributes marker `0xFFFFFFFF` |
| 5 | Unlinked file + attribute flag tampering | Orphaned MFT record (no $FILE_NAME in directory index) + altered $STANDARD_INFORMATION flags | Chkdsk log (`Chkdsk*.log` in `System Volume Information/Chkdsk/`) reports flag corrections and orphan recovery |

*Last updated by sfcc303. Source: `ledger/ledger.md`, catalog, peer findings.*
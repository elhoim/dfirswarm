# NTFS Hidden Files — Investigation Report

Case `AH-C08` · Examiner Halil Ozturkci · Swarm `sfcc3`

**Source:** `inputs/NTFS-HiddenFiles.E01` (97 MB NTFS logical volume, no partition table, volume serial `E0FA70C9FA709D8A`, label `Back2College`, Windows XP).

**Acquisition:** FTK Imager 4.7.1.2, 2023-03-20 03:20:57 UTC. MD5: `e7d5b36a407d5a02d0872d4dd3f3f9d0`, SHA1: `5edc4c6efda9d266ecabcab5629694d0063e9d7f` — both verified.

**Timeline:** See `work/timeline.md` and `ledger/ledger.md` for the complete event chronology.

---

## 1. Hidden item 1: Secrets.txt (Alternate Data Stream on a file)

| Field | Value |
|-------|-------|
| **Name** | `Documents/Misc/2023/README.txt:Secrets.txt` |
| **Inode / Stream** | 168-128-4 |
| **Size** | 154 bytes (resident in MFT) |
| **SHA256** | `8c00d35da2b198fbf404bf6c7b465a5a61d0898315ea438851fb351c2d002aac` |
| **Content** | "The password is the name of the Sherlock Holmes author, combined with the year of his first appearing. Note: each name starts with an uppercase letter." |
| **Hiding technique** | Alternate Data Stream (ADS) on a file |
| **NTFS structure** | `$DATA` attribute type 128, named "Secrets.txt", attribute ID 4, resident in MFT entry 168 |
| **Detection command** | `fls -r inputs/NTFS-HiddenFiles.E01` shows `r/r 168-128-4: README.txt:Secrets.txt`; `icat inputs/NTFS-HiddenFiles.E01 168-128-4` reads the content |

The host file `README.txt` (inode 168-128-1) contains only the text "Welcome Back" (15 bytes, resident). The ADS is not visible in standard directory listings (`dir`) and requires `dir /r` or forensic tools to reveal.

**Evidence:** `istat inputs/NTFS-HiddenFiles.E01 168` shows two `$DATA` attributes: unnamed 128-1 (15 bytes) and named "Secrets.txt" at 128-4 (154 bytes). Ledger record seq 34.

---

## 2. Hidden item 2: flag1.jpg (Alternate Data Stream on a directory)

| Field | Value |
|-------|-------|
| **Name** | `Documents/Life/2020/Photos:flag1.jpg` |
| **Inode / Stream** | 169-128-4 |
| **Size** | 15,282 bytes (non-resident, 4 clusters at 1426-1429) |
| **SHA256** | `28d073e6e01b911a9de12893ab464df3cb7983727c7f15754eb561321cf09cdc` |
| **Content** | JPEG image, JFIF 1.01, 434×232, 96 DPI. Pixels show a pointing-hand graphic and the token `{F3E7A015C1D541528085D3F9581AB41F}` (this is **not** the file MD5; file MD5 is `394ecdd91dda7ea59227d5e0a745a4ce`). |
| **Hiding technique** | Alternate Data Stream on a directory |
| **NTFS structure** | `$DATA` attribute type 128, named "flag1.jpg", attribute ID 4, non-resident. The directory has only `$INDEX_ROOT` ($I30, 48 bytes resident) and no `$INDEX_ALLOCATION` — it is an empty directory whose sole purpose is hosting the hidden ADS. |
| **Detection command** | `fls -r inputs/NTFS-HiddenFiles.E01` shows `d/r 169-128-4: Photos:flag1.jpg` (note `d/r` = directory with named data stream); `icat inputs/NTFS-HiddenFiles.E01 169-128-4 > flag1.jpg` |

The `Photos` directory appears empty in normal file browsing (no files inside), yet carries a 15 KB JPEG in a named data stream. This is unique to NTFS: directories, like files, can host alternate data streams, but standard tools never enumerate them.

**Evidence:** `istat inputs/NTFS-HiddenFiles.E01 169` — directory with `$STANDARD_INFORMATION`, `$FILE_NAME`, `$DATA (flag1.jpg)` at 128-4, and `$INDEX_ROOT`. No unnamed `$DATA`. Ledger record seq 31.

---

## 3. Hidden item 3: flag2.jpg (Alternate Data Stream on a directory, with binary obfuscation)

| Field | Value |
|-------|-------|
| **Name** | `Documents/Work/2023/Tools:flag2.jpg` |
| **Inode / Stream** | 170-128-4 |
| **Size** | 71,266 bytes (non-resident, 18 clusters at 1430-1447) |
| **SHA256** | `ad1f0edb2202ec1a736d9266b18b241eac5542c350578a3a8cdb4dd8b14ff37d` |
| **MD5** | `7bc9d240f9eb3cc42b450ed568aad599` |
| **Content** | ZIP archive (not a JPEG despite the `.jpg` name). Contains: `AlternateStreamView.exe` (115,528 bytes, PE32 executable), `AlternateStreamView.chm` (16,424 bytes, compiled HTML help), `readme.txt` (11,620 bytes). |
| **Hiding technique** | Alternate Data Stream on a directory, with binary content disguised as a JPEG by filename |
| **NTFS structure** | `$DATA` attribute type 128, named "flag2.jpg", attribute ID 4, non-resident. Directory has only `$INDEX_ROOT` — empty directory hosting only the ADS. |
| **Detection command** | `fls -r inputs/NTFS-HiddenFiles.E01` shows `d/r 170-128-4: Tools:flag2.jpg`; `icat inputs/NTFS-HiddenFiles.E01 170-128-4 | file -` identifies it as Zip archive data |

The `.jpg` extension is deceptive — the stream contains a ZIP archive holding the NirSoft AlternateStreamView utility, a tool specifically designed to discover NTFS alternate data streams. This is a meta-commentary: the tool for finding hidden streams is itself hidden in a stream, inside a directory-stream disguised as a JPEG.

**Evidence:** `istat inputs/NTFS-HiddenFiles.E01 170`; `icat 170-128-4 | file -` returns "Zip archive data". Unzipping reveals the three files. Ledger record seq 35.

---

## 4. Hidden item 4: $Quota (MFT attribute manipulation + index entry deletion)

| Field | Value |
|-------|-------|
| **Name** | `\$Quota` at **volume root** (inode 15). This is **not** the real NTFS quota file. Real quota is `$Extend/$Quota` inode **24** (`$O`/`$Q` indexes). |
| **Inode** | 15-128-1, parent MFT 5 |
| **Size** | 4,096 bytes (non-resident, cluster 1417) |
| **SHA256** | `9e60e08966cf08c9fa85bd5b89b0630212e6477312745f9809e9887fd76545ea` |
| **MD5** | `f28683f88f54ad15ee7cbee9d0407a83` |
| **Content** | 0x00 ASCII key `0102030405060708090A0B0C0D0E0F00`; 0x20 `NTFS QUOTA CODE 100 MB`; 0x38–0xFF `0xFF` fill; 0x100–0x7E9 high-entropy 1770 bytes (not decrypted); 0x7EA plaintext `ArthurConanDoyle1887` (Secrets.txt riddle); 0x7FE `55 AA`. |
| **Hiding technique** | Metadata-looking name + Hidden/System + **orphaned `$I30` entry** + **timestomp** (SI modified before created) + payload inside `$DATA` |
| **NTFS structure** | User `$FILE_NAME` `$Quota` on root. Chkdsk: SI flags were `0x20` (Archive) vs expected `0x26` (Archive\|Hidden\|System). Root `$I30` had a `$Quota` name pointing at **unused** record `0x27`; chkdsk deleted that stale entry and recovered **orphaned file `$Quota` (F=15)** into directory 5. |
| **Detection command** | `fls inputs/NTFS-HiddenFiles.E01 5`; `istat inputs/NTFS-HiddenFiles.E01 15`; `icat … 15`; `icat … 18` (UTF-16LE chkdsk). Compare with `istat 24` (`$Extend/$Quota`). |

Chkdsk (`Chkdsk20230319224748.log`, inode 18, 2023-03-19 22:47:48Z): *"The file attributes flag 0x20 in file 0xf is incorrect. The expected value is 0x26."* *"Index entry $Quota of index $I30 in file 0x5 points to unused file 0x27."* *"Recovering orphaned file $Quota (F) into directory file 5."*

SI timestamps (`istat 15`, +03): created 2023-03-20 01:46:54, **modified 2023-03-20 01:43:29** — modified **before** created and **before** volume format (01:45:01). That is timestomping.

**Evidence:** `work/disk.md`; `work/extracted/Quota.bin`; `icat 15`; `icat 18`; `istat 15` vs `istat 24`. Ledger records for inode 15 / chkdsk.

---

## 5. Hidden item 5: Hash for flag2 (MFT entry slack space + attribute ID manipulation)

| Field | Value |
|-------|-------|
| **Name** | Embedded in `Documents/Personal/2023/WelcomeBack.txt` MFT slack space |
| **Inode** | 171 |
| **Visible content** | ChatGPT welcome letter, 1,011 bytes (SHA256: `6cbca84037523e04e76c9db6c9c8a4fa0275070a13b7a1408613ea61d44b2205`) |
| **Hidden content** | "Hash for flag2: 7BC9D240F9EB3CC42B450ED568AAD599" (UTF-16LE, 112 bytes) at MFT byte offset 0x194–0x1F9 |
| **Size of hidden data** | ~112 bytes |
| **Hiding technique** | Leftover UTF-16LE text in the **unused tail of a reused `$MFT` FILE record** (sequence **2**). Not cluster slack of the current `$DATA` (that slack is zeros). |
| **NTFS structure** | Record 171 is 1024 bytes. Attribute terminator `0xFFFFFFFF` at offset 0x180; UTF-16LE BOM + `Hash for flag2: 7BC9…` follows. Sequence 2 means the record was reused; `WelcomeBack.txt` `$DATA` is non-resident 128-3 (attribute ids increment — not an independent hide). |
| **Detection command** | `icat inputs/NTFS-HiddenFiles.E01 0 | dd bs=1024 skip=171 count=1 | xxd -s 0x190` reveals the hidden string. Not visible via `icat 171` or `istat 171` — requires raw MFT analysis. |

**Verification:** MD5 of `flag2.jpg` (extracted from inode 170-128-4) = `7bc9d240f9eb3cc42b450ed568aad599` — matches the hidden hash exactly. This cross-links hidden item 5 directly to hidden item 3.

The `WelcomeBack.txt` file appears perfectly normal: visible in directory listing, readable content (a ChatGPT welcome letter), standard timestamps. Only raw MFT inspection reveals the hidden payload in its slack space.

**Evidence:** Raw MFT extraction: `icat 0 | dd bs=1024 skip=171 count=1`; `md5 work/extracted/flag2.jpg` confirms the hash. Ledger record seq 33.

---

## 6. The five hiding techniques

| # | Technique | Item | NTFS structure involved | Detection method |
|---|-----------|------|-------------------------|------------------|
| 1 | **Alternate Data Stream on a file** | Secrets.txt on README.txt | Named `$DATA` attribute (type 128, named "Secrets.txt") in MFT entry 168 | `fls -r` shows `r/r` type with named stream; `icat <inode>-128-<id>` extracts |
| 2 | **Alternate Data Stream on a directory** | flag1.jpg on Photos dir | Named `$DATA` attribute (type 128, named "flag1.jpg") in directory MFT entry 169; directory has `$INDEX_ROOT` but no `$INDEX_ALLOCATION` | `fls -r` shows `d/r` type (directory with named stream); `icat <inode>-128-4` extracts |
| 3 | **Alternate Data Stream on a directory with binary obfuscation** | flag2.jpg (ZIP) on Tools dir | Named `$DATA` attribute (type 128, named "flag2.jpg") in directory MFT entry 170; filename misleads about content type | `fls -r` shows `d/r`; `file` command on extracted content reveals true type (ZIP, not JPEG) |
| 4 | **Fake metadata name + Hidden/System + orphaned index + timestomp + `$DATA` payload** | root `$Quota` (inode 15), distinct from `$Extend/$Quota` inode 24 | `$FILE_NAME` `$Quota` parented to 5; SI flags 0x20 vs 0x26; root `$I30` pointed at unused 0x27; SI mtime before crtime; 4096 B `$DATA` holds key, ciphertext, password | `fls` root; `istat 15` vs `istat 24`; `icat 15`; chkdsk log inode 18 |
| 5 | **Data hidden in MFT entry slack space + non-standard attribute ID numbering** | Hash in WelcomeBack.txt MFT slack | Unused bytes (0x194–0x1F9) in MFT entry 171 beyond last legitimate attribute; `$DATA` at attribute ID 128-3 (gap from expected 128-1) | Raw MFT dump: `icat 0 \| dd bs=1024 skip=171`; `xxd` at slack offset reveals hidden UTF-16 string |

### Additional observations beyond the five

- **Cross-item linkage:** Hidden item 5 contains the MD5 hash of hidden item 3 (flag2.jpg), deliberately linking the hiding techniques together.
- **Meta-commentary:** Hidden item 3 (flag2.jpg ZIP) contains `AlternateStreamView.exe` — a tool made by NirSoft specifically for viewing and enumerating NTFS alternate data streams. The tool for finding the hidden streams is itself hidden in a stream.
- **Timestomping is present on `$Quota` (inode 15):** SI modified 2023-03-19 22:43:29Z **before** created 22:46:54Z and before volume format 22:45:01Z. Inodes 168–171 SI/FN times are consistent with each other. Year-folder example inode 44: SI mtime 2023-03-19 20:42:32 +03 vs FN created 2023-03-20 01:55:01 +03.
- **No `$EA` attributes** (type 224) on MFT records 0–255.
- **No deleted files** recoverable (`tsk_recover` 0; `ils` all allocated).
- **Cluster slack** of flag1/flag2/WelcomeBack is zeros. **MFT unused area** of record 171 is item 5, not cluster slack.
- **`$Extend/$Deleted`** (inode 29) is an empty Hidden+System decoy directory; `$INDEX_ALLOCATION` clusters 38+ are zeros.
- **Two Chkdsk runs:** first (22:47:48Z) repaired `$Quota` flags/orphan; second (22:51:33Z) clean. ADS items 1–3 and WelcomeBack were created later (22:57–23:26Z).
- **Password chain:** Secrets.txt riddle → `ArthurConanDoyle1887` stored at `$Quota` offset 0x7EA.
- **flag1.jpg token:** `{F3E7A015C1D541528085D3F9581AB41F}` in the JPEG pixels (not a hash of our extract).
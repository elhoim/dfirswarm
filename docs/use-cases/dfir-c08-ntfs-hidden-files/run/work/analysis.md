# Recovery and Analysis — Hidden Items on NTFS Volume

**Analyst:** sfcc302  
**Image:** `inputs/NTFS-HiddenFiles.E01` (Back2College, NTFS, 97 MB logical)  
**Volume Serial:** E0FA70C9FA709D8A

---

## Summary

Five items were hidden on this NTFS volume using file-system capabilities. Below are the findings for each.

---

## Hidden Item 1: README.txt:Secrets.txt (ADS on a file)

| Field | Value |
|-------|-------|
| Path | `Documents/Misc/2023/README.txt:Secrets.txt` |
| Inode:Attribute | 168-128-4 |
| Size | 154 bytes |
| Location | Resident in MFT (in $DATA named "Secrets.txt" of MFT entry 168) |
| SHA-256 | `8c00d35da2b198fbf404bf6c7b465a5a61d0898315ea438851fb351c2d002aac` |
| Content | Password clue (see below) |

**Content:**
```
The password is the name of the Sherlock Holmes author, combined with the year of his first appearing.

Note: each name starts with an uppercase letter.
```

**Detection command:**
```bash
fls -o 0 -r inputs/NTFS-HiddenFiles.E01 | grep ":"
icat -o 0 inputs/NTFS-HiddenFiles.E01 168-128-4
```

**Technique:** Alternate Data Stream (ADS) — The file `README.txt` (15 bytes, "Welcome Back") has a second `$DATA` attribute named "Secrets.txt" (attribute type 128, id 4). Windows Explorer and standard `dir` commands show only the unnamed stream. The MFT entry reveals the hidden stream via `istat`.

**Answer to clue:** The Sherlock Holmes author is Sir Arthur Conan Doyle. His first Sherlock Holmes story, "A Study in Scarlet," was published in 1887. Password: `ArthurConanDoyle1887`.

---

## Hidden Item 2: Photos:flag1.jpg (ADS on a directory)

| Field | Value |
|-------|-------|
| Path | `Documents/Life/2020/Photos:flag1.jpg` |
| Inode:Attribute | 169-128-4 |
| Size | 15,282 bytes |
| Location | Non-resident, clusters 1426–1429 |
| SHA-256 | `28d073e6e01b911a9de12893ab464df3cb7983727c7f15754eb561321cf09cdc` |
| Type | JPEG image, 434×232 pixels |

**MFT structure (istat 169):**
```
Type: $STANDARD_INFORMATION (16-0)  Resident
Type: $FILE_NAME (48-2)             Resident   Name: Photos  (Directory flag)
Type: $DATA (128-4)                 Non-Resident  Name: flag1.jpg  → 15282 bytes
Type: $INDEX_ROOT (144-1)           Resident   Name: $I30
```

This directory has a `$DATA` attribute (type 128) — directories normally have only `$INDEX_ROOT` and `$INDEX_ALLOCATION`. The `$DATA` attribute makes the stream invisible to directory listings and file managers.

**Detection command:**
```bash
fls -o 0 -r inputs/NTFS-HiddenFiles.E01 | grep "Photos:"
icat -o 0 inputs/NTFS-HiddenFiles.E01 169-128-4 > flag1.jpg
```

**Technique:** ADS on a directory — Directories in NTFS are not expected to carry `$DATA` attributes. Placing a named `$DATA` stream on a directory entry hides data from Explorer, `dir`, and most enumeration tools. The stream is visible only via forensic tools (`fls`, `istat`) or by directly referencing the path with the colon syntax.

---

## Hidden Item 3: Tools:flag2.jpg (ADS on a directory + file-type disguise)

| Field | Value |
|-------|-------|
| Path | `Documents/Work/2023/Tools:flag2.jpg` |
| Inode:Attribute | 170-128-4 |
| Size | 71,266 bytes |
| Location | Non-resident, clusters 1430–1447 |
| SHA-256 | `ad1f0edb2202ec1a736d9266b18b241eac5542c350578a3a8cdb4dd8b14ff37d` |
| Actual Type | ZIP archive (disguised as .jpg) |

**MFT structure (istat 170):**
```
Type: $STANDARD_INFORMATION (16-0)  Resident
Type: $FILE_NAME (48-2)             Resident   Name: Tools  (Directory flag)
Type: $DATA (128-4)                 Non-Resident  Name: flag2.jpg  → 71266 bytes
Type: $INDEX_ROOT (144-1)           Resident   Name: $I30
```

**ZIP contents:**
```
AlternateStreamView.exe   (115,528 bytes) — NirSoft NTFS ADS scanner v1.58
AlternateStreamView.chm   (16,424 bytes)  — Help file
readme.txt                (11,620 bytes)  — Documentation
```

The `.jpg` extension is false — the file is a ZIP archive. The irony: the tool used to detect Alternate Data Streams is itself hidden inside an ADS on a directory.

**Detection command:**
```bash
fls -o 0 -r inputs/NTFS-HiddenFiles.E01 | grep "Tools:"
icat -o 0 inputs/NTFS-HiddenFiles.E01 170-128-4 > flag2.jpg
file flag2.jpg  # reports "Zip archive data"
```

**Technique:** ADS on a directory combined with file-type obfuscation (ZIP renamed to .jpg, though `file` command reveals the truth).

---

## Hidden Item 4: Hash for flag2 in MFT entry slack space

| Field | Value |
|-------|-------|
| Location | MFT record 171 (WelcomeBack.txt), unused bytes at offset 0x194–0x1F9 |
| Size | 118 bytes (UTF-16LE encoded) |
| Content | `Hash for flag2: 7BC9D240F9EB3CC42B450ED568AAD599` |

**MFT structure (record 171, 1024 bytes):**
- The MFT record for `WelcomeBack.txt` (inode 171, sequence 2) has a 1011-byte `$DATA` attribute at stream ID 128-3 (unusual — normal is 128-1).
- The legitimate `$DATA` attribute ends at offset 0x178 in the MFT record.
- Bytes at offset 0x194–0x1F9 contain a UTF-16LE string: `Hash for flag2: 7BC9D240F9EB3CC42B450ED568AAD599`.
- These bytes lie in the **slack space** of the MFT record — unused after the last attribute's end marker (0xFFFFFFFF).

**Verification:**
```
$ md5 work/extracted/Tools_flag2.jpg
MD5 = 7bc9d240f9eb3cc42b450ed568aad599  ✅ matches
```

**Detection command:**
```bash
icat -o 0 inputs/NTFS-HiddenFiles.E01 0 | dd bs=1024 skip=171 count=1 | xxd -s 0x180
```

**Technique:** MFT entry slack space. Each MFT record is fixed at 1024 bytes. When the attributes don't fill the entire record, the remaining space is "slack" — invisible to normal file I/O but readable via raw MFT extraction. The `$DATA` attribute ID 128-3 (instead of 128-1) is also suspicious — suggesting prior attribute manipulation.

**Attribution:** Discovered by sfcc301, verified by sfcc300 and sfcc304.

---

## Hidden Item 5: $Quota system file (orphaned + attribute manipulation)

| Field | Value |
|-------|-------|
| Path | `$Quota` (inode 15) |
| Size | 4,096 bytes (1 cluster) |
| SHA-256 | `(binary, 4096 bytes)` |

**The hiding technique — three layers:**

### Layer 1: Orphaning
The `$Quota` file was removed from the root directory index (`$I30` of inode 5) but its MFT record (entry 15) remained allocated. A file that exists in the MFT but has no directory entry is "orphaned" — it won't appear in directory listings or `fls` output (unless Chkdsk recovers it).

Evidence from Chkdsk log (`System Volume Information/Chkdsk/Chkdsk20230319224748.log`, inode 18):
```
Index entry $Quota of index $I30 in file 0x5 points to unused file 0x27.
Deleting index entry $Quota in index $I30 of file 5.
...
Recovering orphaned file $Quota (F) into directory file 5.
1 unindexed files recovered to original directory.
```

### Layer 2: Attribute flag manipulation
The `$STANDARD_INFORMATION` attribute flags were changed from the expected `0x26` (Hidden + System + Archive) to `0x20` (Archive only). The Chkdsk log confirms:

```
The file attributes flag 0x20 in file 0xf is incorrect.
The expected value is 0x26.
Fixing incorrect information in file record segment F.
```

### Layer 3: Timestomping
The `$STANDARD_INFORMATION` Modified time (2023-03-19 22:43:29 UTC) is **before** the Created time (2023-03-19 22:46:54 UTC). Normally mtime ≥ crtime. This is classic anti-forensic timestomping.

**After Chkdsk fixed the issues, the current MFT shows correct flags (Hidden, System, Archive) and the file is properly linked in the root directory.**

### Content of $Quota after recovery:

| Offset | Content |
|--------|---------|
| 0x00–0x1F | `0102030405060708090A0B0C0D0E0F00` (32-byte ASCII hex string, decodes to 16 bytes: 01 02 … 0F 00) |
| 0x20–0x35 | `NTFS QUOTA CODE 100 MB` (22-byte header/label) |
| 0x36–0xFF | 0xFF padding (202 bytes) |
| 0x100–0x7E9 | Encrypted/obfuscated binary payload (1,770 bytes, full entropy) |
| 0x7EA–0x7FD | `ArthurConanDoyle1887` (password, from clue in Item 1) |
| 0x7FE–0x7FF | `55 AA` (boot-sector style end marker) |

The password at offset 0x7EA is the answer to the riddle in Item 1: Sherlock Holmes author = Sir Arthur Conan Doyle, first appearance in "A Study in Scarlet" (1887) → `ArthurConanDoyle1887`.

**Detection commands:**
```bash
# Check the Chkdsk logs for evidence of orphaning:
icat -o 0 inputs/NTFS-HiddenFiles.E01 18 | strings | grep -i "orphan\|unindexed\|Quota"
# Examine the MFT entry:
istat -o 0 inputs/NTFS-HiddenFiles.E01 15
# Extract and examine the payload:
icat -o 0 inputs/NTFS-HiddenFiles.E01 15 | xxd | head -40
```

**Technique:** Orphaned file (unindexed from directory, MFT record intact) + attribute flag manipulation (system+hidden flags removed) + timestomping (SI mtime < crtime). The fake `$Quota` at root (real NTFS quota is `$Extend/$Quota` at inode 24) was repurposed to carry a hidden payload.

---

## Technique Summary (for Question 6)

| # | Hidden Item | Technique | NTFS Structure | Detection Method |
|---|-------------|-----------|----------------|------------------|
| 1 | README.txt:Secrets.txt | ADS on file + resident data | `$DATA` attribute (type 128, named, id 4) in MFT entry 168; BOTH streams resident | `fls -r`, `istat 168`, path with `:` syntax |
| 2 | Photos:flag1.jpg | ADS on directory | `$DATA` attribute (type 128, named, id 4) on directory MFT entry 169 | `fls -r` shows `d/r` type; `istat 169` shows $DATA on dir |
| 3 | Tools:flag2.jpg | ADS on directory + file-type disguise | `$DATA` attribute (type 128, named, id 4) on directory MFT entry 170; ZIP masked as .jpg | Same as #2; `file` command reveals ZIP; `md5` matches slack hash |
| 4 | Hash for flag2 | MFT entry slack space | Unused bytes in MFT record 171 after attribute end marker 0xFFFFFFFF | Raw MFT extraction at `inode×1024`; `xxd` at offset 0x180 |
| 5 | $Quota system file | Orphaned file + attribute manipulation + timestomping | MFT entry 15; flag 0x20 vs expected 0x26; missing from root `$I30`; SI mtime < crtime | Chkdsk logs (inode 18); `istat 15`; `strings` on extracted data |

---

## Extracted Artifacts

All extracted files are in `work/extracted/`:

| File | Description | SHA-256 |
|------|-------------|---------|
| `README.txt` | Main file (15 bytes, "Welcome Back") | `3cbe173ee15859a9fcc826e1c28235429e596564adab568aacd3eb7e5ba0d3d5` |
| `Secrets.txt` / `README.txt_Secrets.txt` | ADS with password clue (154 bytes) | `8c00d35da2b198fbf404bf6c7b465a5a61d0898315ea438851fb351c2d002aac` |
| `flag1.jpg` / `Photos_flag1.jpg` | JPEG image from directory ADS (15,282 bytes) | `28d073e6e01b911a9de12893ab464df3cb7983727c7f15754eb561321cf09cdc` |
| `flag2.jpg` / `Tools_flag2.jpg` | ZIP archive from directory ADS (71,266 bytes) | `ad1f0edb2202ec1a736d9266b18b241eac5542c350578a3a8cdb4dd8b14ff37d` |
| `quota.bin` | Full $Quota file with hidden payload (4,096 bytes) | (binary) |
| `flag2_contents/` | Extracted ZIP: AlternateStreamView.exe, .chm, readme.txt | — |
| `WelcomeBack.txt` | ChatGPT welcome letter (1,011 bytes, inode 171) | `6cbca84037523e04e76c9db6c9c8a4fa0275070a13b7a1408613ea61d44b2205` |

---

*Analysis ongoing: the encrypted Quota payload may require additional cryptanalysis or tools.*
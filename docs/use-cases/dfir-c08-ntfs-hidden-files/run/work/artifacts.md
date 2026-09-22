# Artifacts and execution — AH-C08 (NTFS Hidden Files)

Seat: sfcc301 (`work/artifacts.md`). Image: `inputs/NTFS-HiddenFiles.E01` (logical NTFS, no partition table, volume **Back2College**, serial **E0FA70C9FA709D8A**, OEM NTFS, “Windows XP”). Commands use sector offset 0.

This is a 97 MB planted NTFS volume, not a full Windows install. The “execution artifacts” seat therefore reports a **negative inventory** of registry/prefetch/LNK/EVTX, then the NTFS attribute tricks that actually hide the five items.

Hashes below are of `icat` extracts in `work/sfcc301/`. Cite `ledger/ledger.md` for dated events.

---

## 0. Execution-artifact inventory (negative)

Searched `catalog/NTFS-HiddenFiles.E01/p0/filelist.txt`, `fls -r -p`, `ils`, and MFT records 0–255.

| Class | Present? | Notes |
| --- | --- | --- |
| Registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass) | **No** | No `Windows/System32/config`, no user profiles |
| Prefetch (`*.pf`) | **No** | |
| LNK / Automatic Destinations / Custom Destinations | **No** | |
| Event logs (`*.evtx` / `*.evt`) | **No** | |
| Shimcache / Amcache / SRUM / BAM/DAM | **No** | |
| Browser (History, places.sqlite, WebCache) | **No** | |
| UserAssist / RunMRU / RecentDocs | **No** | no NTUSER |
| $UsnJrnl | **No** | not in `$Extend` |
| Recycle Bin | Empty except `desktop.ini` | see §0.1 |
| $EA / $EA_INFORMATION | **None** | raw MFT walk, attribute type 0xE0/0xD0 not used as EA on any record |
| Unallocated (`blkls`) | 93,405,184 bytes, **all zero** | `work/sfcc301/unalloc.bin` |
| $BadClus:$Bad | Sparse hole covering the whole volume (24,831 clusters) | not a data hide |
| $OrphanFiles (inode 256, V/V) | Empty | `fls` on 256 yields nothing; `ils -e` shows no unallocated MFT file records with data |

**User SID** (from `$RECYCLE.BIN` path and `istat` Security ID 269 on user files):

`S-1-5-21-321011808-3761883066-353627080-1000`

**Host-ish names from metadata:** volume label `Back2College`; FTK Imager examiner `AHMK`; chkdsk ran against drive letter **H:**.

### 0.1 Recycle Bin

| Inode | Path | Size | Role |
| --- | --- | --- | --- |
| 39 | `$RECYCLE.BIN` | dir, Hidden+System | created 2023-03-20 01:50:55 +03 |
| 40 | `…/S-1-5-21-321011808-3761883066-353627080-1000` | dir | |
| 41 | `…/desktop.ini` | 129 B | standard `{645FF040-5081-101B-9F08-00AA002F954E}` |

No `$I` / `$R` pairs. Recycle Bin is **not** one of the five hides.

### 0.2 Chkdsk logs (system artifact that exposes item 5)

| Inode | Path | Size | Encoding |
| --- | --- | --- | --- |
| 18 | `System Volume Information/Chkdsk/Chkdsk20230319224748.log` | 8192 | UTF-16LE |
| 19 | `System Volume Information/Chkdsk/Chkdsk20230319225133.log` | 7168 | UTF-16LE |

First log (UTC 2023-03-19 22:47:48, ledger seq 25) is the detection method for `$Quota`:

- `The file attributes flag 0x20 in file 0xf is incorrect. The expected value is 0x26.`
- `Index entry $Quota of index $I30 in file 0x5 points to unused file 0x27. Deleting index entry $Quota in index $I30 of file 5.`
- `Recovering orphaned file $Quota (F) into directory file 5.`

Second log: chkdsk could not run until the volume was dismounted; no further corruption.

---

## The five hidden items

Numbering below is **technique order** (ADS-on-dir, ADS-on-dir, ADS-on-file, MFT slack, orphaned `$Quota`). Report editor should map these to `## 1.`–`## 5.` consistently with `work/disk.md` / `work/analysis.md`.

### Item A — `flag1.jpg` (ADS on a directory)

| Field | Value |
| --- | --- |
| Name | `flag1.jpg` |
| Host | Directory `Documents/Life/2020/Photos` (inode **169**, allocated directory, `$INDEX_ROOT $I30` empty) |
| Stream | `$DATA` **128-4** named `flag1.jpg`, non-resident, clusters **1426–1429** |
| Size | 15,282 bytes |
| Type | JPEG JFIF 1.01, 434×232, Exif Orientation=Horizontal |
| MD5 | `394ecdd91dda7ea59227d5e0a745a4ce` |
| SHA256 | `28d073e6e01b911a9de12893ab464df3cb7983727c7f15754eb561321cf09cdc` |
| Content | Blue graphic, thumbs-down hand, token **`{F3E7A015C1D541528085D3F9581AB41F}`**. No trailer after JPEG EOI. Token is **not** MD5 of the JPEG or of Secrets.txt (hypothesis: challenge token). |
| Created (SI) | 2023-03-20 02:01:03.081835700 +03 |
| Reveal | `fls -r -p inputs/NTFS-HiddenFiles.E01` → `d/r 169-128-4: Documents/Life/2020/Photos:flag1.jpg` ; `icat inputs/NTFS-HiddenFiles.E01 169-128-4` |
| Technique | Named `$DATA` on a **directory**. Explorer / `dir` hide directory streams; TSK `fls` shows `d/r`. |

### Item B — `flag2.jpg` (ADS on a directory + misleading extension)

| Field | Value |
| --- | --- |
| Name | `flag2.jpg` (content is a ZIP) |
| Host | Directory `Documents/Work/2023/Tools` (inode **170**) |
| Stream | `$DATA` **128-4** named `flag2.jpg`, non-resident, clusters **1430–1447** |
| Size | 71,266 bytes |
| Type | `PK\x03\x04` Zip; **not** JPEG |
| MD5 | `7bc9d240f9eb3cc42b450ed568aad599` (matches MFT-slack text, item D) |
| SHA256 | `ad1f0edb2202ec1a736d9266b18b241eac5542c350578a3a8cdb4dd8b14ff37d` |
| ZIP members | `AlternateStreamView.exe` (115,528 B, MD5 `4919765eaf5f03cd4f95f0888ae46807`) ; `AlternateStreamView.chm` ; `readme.txt` (NirSoft AlternateStreamView **v1.58**). Not encrypted. |
| Created (SI) | 2023-03-20 02:03:36.367824300 +03 |
| Reveal | `icat inputs/NTFS-HiddenFiles.E01 170-128-4` ; `file` / `python3 zipfile` |
| Technique | Named `$DATA` on a **directory**, plus extension masquerade (`.jpg` over a ZIP of the ADS-viewing tool). |

### Item C — `Secrets.txt` (ADS on a file, resident)

| Field | Value |
| --- | --- |
| Name | `Secrets.txt` |
| Host | File `Documents/Misc/2023/README.txt` (inode **168**). Default `$DATA` **128-1** is resident 15 bytes: `Welcome Back \r\n`. |
| Stream | `$DATA` **128-4** named `Secrets.txt`, **resident** size 154 |
| MD5 | `29c816aafe3cba923215acf85a22063b` |
| SHA256 | `8c00d35da2b198fbf404bf6c7b465a5a61d0898315ea438851fb351c2d002aac` |
| Content | `The password is the name of the Sherlock Holmes author, combined with the year of his first appearing.\r\n\r\nNote: each name starts with an uppercase letter.` |
| Password | **ArthurConanDoyle1887** (Arthur Conan Doyle; *A Study in Scarlet* 1887). Same ASCII string at **offset 2026** of `$Quota` (item E). |
| Created (SI) | 2023-03-20 01:57:43.079271900 +03 ; stream mtime 01:58:17 +03 |
| Reveal | `icat inputs/NTFS-HiddenFiles.E01 168-128-4` ; `istat inputs/NTFS-HiddenFiles.E01 168` |
| Technique | Classic **file ADS**, stored entirely in the MFT record (resident). |

### Item D — hash leftover in MFT unused bytes (record 171)

| Field | Value |
| --- | --- |
| Current file | `Documents/Personal/2023/WelcomeBack.txt` inode **171** sequence **2** (record reused) |
| Current `$DATA` | **128-3** (id 3, not 1), non-resident 1,011 bytes, cluster **1448**, ChatGPT “Dear Students…” decoy. SHA256 `6cbca84037523e04e76c9db6c9c8a4fa0275070a13b7a1408613ea61d44b2205`. Cluster slack after 1011 bytes is zeros. |
| Hidden remnant | After attribute terminator `FF FF FF FF` in MFT record 171 (used=392): magic `11 22 33 44`, then UTF-16LE `Hash for flag2: 7BC9D240F9EB3CC42B450ED568AAD599\r\n` |
| Offset | `$MFT` byte `171*1024 + 0x180` (`work/sfcc301/mft.bin`) |
| Meaning | MD5 of item B (`flag2.jpg`) |
| Reveal | `icat inputs/NTFS-HiddenFiles.E01 0-128-13` then dump record 171; or `istat 171` (does **not** print slack — must parse unused). |
| Technique | **Resident data left in MFT unused/slack** after the record was reused for a larger non-resident file. `fls -d` / `ils -e` do not list it. |

`WelcomeBack.txt` default stream is **not** a hide; it is the decoy that overwrote the resident hash file.

### Item E — planted `$Quota` (orphaned metadata-named file)

| Field | Value |
| --- | --- |
| Name | `$Quota` inode **15** (root, parent 5) — **distinct** from real `$Extend/$Quota` inode 24 |
| `$DATA` | 128-1, non-resident 4,096 bytes, cluster **1417** |
| SI flags | Hidden, System, Archive (0x26 after chkdsk; log said it was 0x20) |
| Timestamps | Created 2023-03-20 01:46:54 +03 ; **modified 01:43:29 +03 (before create)** |
| Head of cluster | ASCII `0102030405060708090A0B0C0D0E0F00NTFS QUOTA CODE 100 MB` then `0xFF` fill, then binary; password `ArthurConanDoyle1887` at offset **2026** |
| MD5 (4096 B) | `f28683f88f54ad15ee7cbee9d0407a83` |
| SHA256 | `9e60e08966cf08c9fa85bd5b89b0630212e6477312745f9809e9887fd76545ea` |
| How hidden | Unlinked from `$I30` of root (chkdsk: index entry pointed at unused 0x27); Hidden+System; metadata-looking name `$Quota`. Chkdsk recovered it into directory 5. |
| Reveal | `istat 15` ; `icat inputs/NTFS-HiddenFiles.E01 15` ; `icat … 18-128-3` for the chkdsk narrative |

---

## Techniques summary (question 6 input)

| # | Technique | NTFS structure | Detection |
| --- | --- | --- | --- |
| A | ADS on a **directory** | `$DATA` named `flag1.jpg` on inode 169 (dir) | `fls -r -p` (`d/r`); `istat` |
| B | ADS on a **directory** + fake extension | `$DATA` named `flag2.jpg` on inode 170 (dir); ZIP payload | `fls`; `file`; unzip |
| C | ADS on a **file** (resident) | `$DATA` named `Secrets.txt` on inode 168 | `fls`; `istat`; `icat 168-128-4` |
| D | Resident remnant / MFT unused | Unused bytes of MFT record 171 after 0xFFFFFFFF | Parse `$MFT`; not visible to `fls`/`istat` |
| E | Orphaned / flag-tampered metadata file | `$Quota` inode 15 `$FILE_NAME` + `$DATA`; `$I30` of root | `istat 15`; chkdsk log inode 18; `icat 15` |
| — | $EA | **Not used** | MFT type 0xE0 absent |
| — | Unallocated / cluster slack of user files | Unalloc all-zero; WelcomeBack/flag1/flag2 cluster slack zero or ZIP padding | `blkls`; `blkcat` |
| — | Recycle Bin | Empty | `fls $RECYCLE.BIN` |
| — | $BadClus | Sparse only | runlist `02 ff 60` hole 24831 clusters |
| — | Timestomp | `$Quota` mtime before crtime; year-folders M 2023-03-19 19:49:12 UTC vs volume create 22:45:01 UTC (copy, not a hide) | `istat` / bodyfile |

**Beyond the five:** NirSoft AlternateStreamView inside the ZIP is a hint tool, not a sixth hide. `$LogFile` contains the string `AlternateStreamView.exe` from the ZIP write. Object IDs exist on 168/171/root (GUIDs `3a6b78xx-c673-11ed-a782-000c2914a162`) — filesystem IDs, not payload.

---

## Commands (reproducible)

```bash
# catalog already has fls -r -p / fsstat / bodyfile
istat inputs/NTFS-HiddenFiles.E01 168   # README + Secrets.txt
istat inputs/NTFS-HiddenFiles.E01 169   # Photos:flag1.jpg
istat inputs/NTFS-HiddenFiles.E01 170   # Tools:flag2.jpg
istat inputs/NTFS-HiddenFiles.E01 171   # WelcomeBack (look at seq=2, $DATA 128-3)
istat inputs/NTFS-HiddenFiles.E01 15    # planted $Quota
icat  inputs/NTFS-HiddenFiles.E01 168-128-4   # Secrets.txt
icat  inputs/NTFS-HiddenFiles.E01 169-128-4   # flag1.jpg
icat  inputs/NTFS-HiddenFiles.E01 170-128-4   # flag2.zip-as-jpg
icat  inputs/NTFS-HiddenFiles.E01 15          # NTFS QUOTA CODE 100 MB
icat  inputs/NTFS-HiddenFiles.E01 18-128-3    # chkdsk UTF-16LE
icat  inputs/NTFS-HiddenFiles.E01 0-128-13    # $MFT → record 171 slack
blkls inputs/NTFS-HiddenFiles.E01 | wc -c     # 93405184 zeros
```

Extracts: `work/sfcc301/{README.txt,Secrets.txt,flag1.jpg,flag2.jpg,WelcomeBack.txt,mft.bin}` and `work/extracted/quota_raw.bin`, `work/extracted/chkdsk18.log`.

---

## Notes for critic / timeline

- Do **not** treat `WelcomeBack.txt` body (ChatGPT letter) as a hidden item.
- Do **not** treat `$OrphanFiles` inode 256 as a hide (empty).
- Item D has no independent MAC time; it is leftover inside record 171 (WelcomeBack, 2023-03-20 02:26:32 +03 / 2023-03-19 23:26:32 UTC).
- Password `ArthurConanDoyle1887` is recovered from the riddle **and** from `$Quota+2026`; the ZIP is not password-protected.
- Visual token in flag1 `{F3E7A015C1D541528085D3F9581AB41F}` did not match MD5/SHA1/SHA256 of extracted files tested (Secrets, README, WelcomeBack, flag1, flag2, $Quota). Label as **content of flag1**, not as a verified file hash.
- Ledger: seq 22–29 (sfcc301) plus earlier seq 12–21 (sfcc303).

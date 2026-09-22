# Recovery: $LogFile, $UsnJrnl, VSS, unallocated (s864a01)

Seat goal: earlier copies of files that were later encrypted. Image `inputs/AF-Case2.E01` (logical NTFS at sector 0, volume “Windows 10”, serial `BAB00A24B009E7A9`). TSK `istat`/`usnjls` print local examiner TZ **+03**; UTC below is that clock minus 3 hours. NTFS FILETIME is UTC.

Extracts:

| Item | Inode / ADS | Path on disk | Extract | SHA256 / size |
| --- | --- | --- | --- | --- |
| `$LogFile` | 2-128-1 | `$LogFile` | `work/extracted/$LogFile` | 57 360 384 B |
| `$UsnJrnl:$J` | 80499-128-3 | `$Extend/$UsnJrnl:$J` | `work/extracted/UsnJrnl_J.bin` | 100 460 696 B (sparse; first nonzero @ 58 720 256) |
| USN parse | `usnjls -l inputs/AF-Case2.E01` | — | `work/s864a01/usnjls.txt` (312 959 records) | — |
| `README.txt.lnk` | 27941-128-4 | `Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/README.txt.lnk` | `work/extracted/README.txt.lnk` | `610e715c6e23c4a6e04aebf5061cc4af1f696b889d745d91e6eb78663623478a` |
| `README.txt.aes` | 126755-128-1 (resident) | `Users/IEUser/Documents/README.txt.aes` | `work/extracted/README.txt.aes` | `a2536e1a916d79bdc4ba8e86907b49aba35eeb539f79fad68492ded91a697186` (418 B, AES Crypt v2) |

Commands: `istat inputs/AF-Case2.E01 <inode>`; `icat inputs/AF-Case2.E01 <inode>`; `usnjls -l inputs/AF-Case2.E01`; USA fixup of `$LogFile` 4096-byte `RCRD` pages (14 002 data pages + 2 `RSTR`). TSK `jls`/`jcat`: **“NTFS Journal is not yet supported”**.

---

## 1. Lost in Space — original README.txt

The live MFT has **no** `Users/IEUser/Documents/README.txt`. Only the ciphertext and a Recent LNK remain.

### USN lifecycle (inode **27936**, sequence **3**, parent Documents **83446-1**)

From `usnjls -l` (see `work/s864a01/usn_interesting.txt` and ledger seq 100–103):

| UTC | Local (+03) | USN | Reason | Name |
| --- | --- | --- | --- | --- |
| 2023-02-22 19:46:01.983Z | 22:46:01.983 | 95826928 | FILE_CREATE | `New Text Document.txt` |
| 2023-02-22 19:46:04.459Z | 22:46:04.459 | 95827640 / 95827744 | RENAME_OLD / RENAME_NEW | → `README.txt` |
| 2023-02-22 19:46:04.473Z | 22:46:04.473 | 95828520 | FILE_CREATE | `README.txt.lnk` (27941-3) |
| 2023-02-22 20:15:43.821Z | 23:15:43.821 | 96046272 / 96046360 | LNK delete + recreate | `README.txt.lnk` (27941-4) — Explorer refresh |
| 2023-02-22 20:20:06.541Z | 23:20:06.541 | 96092512 | **DATA_EXTEND** | first (only) content write |
| 2023-02-22 20:21:17.218Z | 23:21:17.218 | 96233680 | FILE_CREATE | `README.txt.aes` (**126755-14**) |
| 2023-02-22 20:21:25.297Z | 23:21:25.297 | 96240192 | FILE_DELETE CLOSE | `README.txt` |
| 2023-02-22 20:23:37.299Z | 23:23:37.299 | 96315936 | FILE_CREATE seq **4** | Edge cache SVG reuses MFT 27936 |

Do not confuse USN hits on `README.txt` at 21:47:12 +03 — that is **`/Program Files (x86)/GnuPG/README.txt`** (inode 125223-3, parent 125222 GnuPG).

### What the LNK still names

`README.txt.lnk` (640 B) contains ASCII target:

`C:\Users\IEUser\Documents\README.txt`

Volume label `Windows 10`, machine `msedgewin10`. Created 19:46:04Z (empty notepad file), updated 20:15:43Z (before the 20:20 content write).

`istat` 126755: `$DATA` **resident** 418 bytes; SI/FN timestamps all 2023-02-22 23:21:17.218 (+03) = **20:21:17Z**. Header: `AES\x02` + `CREATED_BY=aescrypt (Windows GUI) 3.10`.

### Why the plaintext is gone from the MFT

`istat` 27936 **now** is sequence **4**, allocated, name `a4fadb2ea03436fed81305eaf9565713[1].svg` under Edge cache `W800YVVL` (ffind). Resident `$DATA` of the deleted README (almost certainly still resident: 418-byte AES Crypt file implies ~100–250 B plaintext, well under the ~700 B resident limit) was overwritten **~2 minutes** after delete. Documents `$I30` (icat `83446-160-4`, 4096 B) still has `README.txt.aes` / `README~1.AES` and `R2D2.vhd`; **no** leftover `README.txt` or `New Text Document.txt` in the index.

### $LogFile (inode 2, 57 MiB circular)

- USA fixups applied on all 14 004 pages (`fixup_applied=14004`).
- **0** hits for UTF-16/ASCII `README.txt`, `README.txt.aes`, `AES\x02`, `CREATED_BY`, `aescrypt`, `StarWars!`, `Lost in Space`.
- 8 hits for UTF-16 `New Text Document.txt` — timestamps in those redo records match the **later** Downloads file that became `Keys.txt` (inode 126939-9, 23:42:31 +03), not the Documents README. The circular log has **wrapped past** the 20:20–20:21Z README `$DATA` undo/redo.
- Names that **are** still in the log (UTF-16): `R2D2.vhd.bak`, `R2D2.7z`, `ccdfir` (GPG/Mattermost artefacts from later in the evening).

### VSS / Recycle Bin / Search / pagefile

| Source | Result |
| --- | --- |
| System Volume Information | No `{GUID}` snapshot dirs, no RP## restore points. Only `IndexerVolumeGuid`, `MountPointManagerRemoteDatabase`, `tracking.log`, `Wcifs.md`, `WPSettings.dat` (catalog filelist 24244–24249). **No VSS.** |
| `$Recycle.Bin/S-1-5-21-321011808-3761883066-353627080-1000` | `desktop.ini` only (`fls` 84074). README was deleted, not recycled. |
| `Windows.edb` inode 82816 (sparse, 8 388 608 B extracted) | No `README.txt` / `StarWars!`. |
| Gather logs `SystemIndex.*.gthr` | No README strings. |
| `pagefile.sys` inode 80513 (runlist ~1.4–3 GiB) | Streamed via `icat`; **0** hits for `README.txt`, `aescrypt`, `StarWars!`, `Lost in Space`, `AES\x02`. |
| Documents `$I30` | Ciphertext name only. |

### Unallocated

A full `blkls` of ~40 GiB unallocated was **not** run to completion (resident file + MFT reuse + log wrap make cluster carving of this object low-yield). Targeted searches that **were** completed:

- Entire `$LogFile` after USA fixup (57 MiB).
- Entire `$UsnJrnl:$J` via `usnjls` (content is names/reasons only — USN never stores file bytes).
- `pagefile.sys`, `Windows.edb`, Gather logs, Recycle Bin, Documents `$I30`.
- Extracted Edge/Mattermost caches, `WebCacheV01.dat`, `IndexedDB.edb`, `spartan.edb` for `StarWars!` and post id `wx5cwg49kj8utkd1kjme1nfarh`.

**Conclusion (Part 1):** journals prove the file existed and pin the encrypt/delete window to **8 seconds** (20:21:17–20:21:25Z). They do **not** yield plaintext.

Plaintext was obtained by **s864a00** decrypting inode 126755 with password `StarWars!` (UTF-16LE, AES Crypt v2, both HMACs verify), saved as `work/extracted/README.txt` (97 bytes, SHA256 `32282626340f368f0143a280b7ced586dddd7d82bf8e33a30642a4a2e505200a`):

```
It is a very well known quote and can be found here:
https://www.youtube.com/watch?v=66Ux1D9MDOk
```

Cross-check: `$LogFile` (USA-fixed), `Windows.edb`, and Documents `$I30` contain **neither** `66Ux1D9MDOk` nor `very well known quote` (ASCII or UTF-16LE). Password source remains Edge cache inode **126728** (`work/caches.md`). Ledger findings seq 104, 106.

---

## 2. Other encrypted / replaced objects

### R2D2.vhd / BitLocker clone

USN (parent 83446 Documents and 126808 `ProgramData/Starwars`):

| UTC | Event |
| --- | --- |
| 2023-02-22 20:28:10Z | `Documents\R2D2.vhd` created (126798-3) then immediately deleted; LNK `R2D2.vhd.lnk` |
| 2023-02-22 20:28:16Z | `Documents\R2D2.vhd` created again (126800-3) and grown (plain NTFS clone — see `work/disk.md`) |
| 2023-02-22 20:34:09Z | Copy `ProgramData\Starwars\R2D2.vhd` (126812-2) — this is the **BitLocker** VHD |
| 2023-02-22 20:44:10Z | BitLocker recovery key TXT created in Documents (126830-6); a 60223-21 instance was created and deleted the same second |
| 2023-02-22 20:45:27Z | `Starwars\R2D2.vhd.bak` (126837-6) |
| 2023-02-22 23:44:47Z | `R2D2.vhd.bak` FILE_DELETE; MFT 126837 reused |
| 2023-02-22 23:44:56Z | `Starwars\R2D2.7z` created (126837-7), deleted 23:45:06Z |
| 2023-02-22 23:45:31Z | MFT 126837 seq 8 reused for Edge `channels[2].json` |

`$LogFile` still contains UTF-16 `R2D2.vhd.bak` / `R2D2.7z` FILE_NAME redo (offsets ~11 078 978 and ~11 196 898 in the extracted log). The `.bak` and `.7z` **bodies** are not in the log. Both 100 MiB VHDs remain allocated (inodes 126800 and 126812) — no need to carve them. Deleted `.7z`/`.bak` were overwritten at the MFT; cluster carving of a 100 MiB object was not attempted.

### Keys.txt (Part 3) — USN only

Inode **126939-9**, parent Downloads **83445-1**:

- 2023-02-23 02:42:31.228 (+03) = **2023-02-22 23:42:31Z** FILE_CREATE `New Text Document.txt`
- 23:42:36Z rename → `Keys.txt`
- 23:42:37Z DATA_EXTEND (PGP message written)

`$LogFile` still has this `New Text Document.txt` (eight UTF-16 hits) because it is **newer** than the README window. The PGP ciphertext is live at inode 126939 (443 B); recovery is decryption (s864a06), not carving.

---

## 3. Mattermost post / DM bodies (request from s864a02)

| Object | Recovered? | Where |
| --- | --- | --- |
| Town Square unread posts (incl. `StarWars!`, README.txt.aes upload) | **Yes (cache, not journals)** | inode 126728 `unread[3].json` — s864a02 |
| Later Town Square post `wx5cwg49kj8utkd1kjme1nfarh` | **Metadata only** | Edge DOM store `www.ccdfir_DOMStore.xml`: Rudder `api_posts_create` at `2023-02-22T23:43:19.369Z`, channel `5nf8d9oa9pg4zn6bqru9emsmsr`, user `funsjjmhypgstmj8osdrbj43me`. **No message body** in that XML, `$LogFile`, `WebCacheV01.dat`, `IndexedDB.edb`, `spartan.edb`. |
| Jane↔John DM `iw9rfd3s4i8pimq57f8nic9ahy` (31 msgs, last 2023-02-09T00:26:16Z) | **Not in journals or named cache files** | Channel id appears in `channels_cache.json` / `categories_cache.json` only (counts, no bodies). |

---

## 4. Host gaps

- TSK `jls`/`jcat` do not parse NTFS `$LogFile`; parsed with a USA-fixup scanner instead of a full LSN/redo decoder. A specialised NTFS log parser (e.g. `ntfs-log-tracker`) might still pull resident `$DATA` from wrapped pages we treated as non-matching strings — **hypothesis**, not tested here.
- No `dislocker`, no VSS tools needed (no snapshots).
- Full unallocated `blkls` not finished; residual risk is low for the resident README, higher for the deleted `R2D2.7z` (not required: both VHDs still allocated).

---

## 5. What other seats should use

- **s864a06:** Do not wait on journals for README plaintext. Password `StarWars!` (cache inode 126728). File is AES Crypt v2, 418 B, inode 126755.
- **s864a07:** README events in ledger seq 100–103 (UTC). Encrypt+delete window 20:21:17–20:21:25Z. Mattermost upload of README.txt.aes at 17:24:32Z (caches.md) is **three hours earlier** than the Documents file’s NTFS create — treat as a separate copy/upload vs local recreate, or as a clock-interpretation issue; USN has no earlier `README.txt.aes`.
- **s864a05 / s864a00:** `$LogFile` confirms `.bak`/`.7z` names around Starwars; live evidence is the two VHDs, not journal copies.
- **s864a02:** DM bodies and post `wx5cwg49` body were **not** in `$LogFile` / pagefile / Search. Unallocated JSON carving for `wx5cwg49` was not exhaustively run.

Cite this file plus `ledger/ledger.md` (events 100–103, 105; findings 104, 106) and `work/caches.md` for the password.

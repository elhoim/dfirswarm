# ALIHADI-C5 — BSides Amman 2021 Windows Forensics Workshop — Report

Case: `ALIHADI-C5` · Examiner: Halil Ozturkci · Swarm: `s2f66` · Editor/critic: `s2f6606`

Evidence set: `inputs/BSidesAmman21.E01` (single NTFS volume at sector 0), `inputs/CASE.md`, `inputs/README.rtf`. All times below are UTC (ISO 8601). Commands + output are quoted per the workshop's "screenshot or it did not happen" rule. Every claim cites its command-level evidence and, where applicable, the `ledger/ledger.md` entry.

Key identifiers used throughout:

| Item | Value |
| --- | --- |
| NTFS volume serial (fsstat, 64-bit) | `EE68D66268D628DB` |
| Windows/DOS volume serial (from `.lnk` `Drive Serial Number`) | `68D6-28DB` |
| Confidential share | `\\192.168.70.128\SharedJJ\docs` |
| Suspect accounts | `joker` (SID `...-1004`), `IEUser` (SID `...-1000`) |

---

## 1. Hash value of the forensic image

Three values, stated separately as the brief requires.

**(a) Acquisition record inside the E01 (and `ewfinfo`).** `ewfinfo` reads the EWF header and reports the digests that the acquisition tool stored, plus the acquisition metadata:

```text
$ ewfinfo inputs/BSidesAmman21.E01

Acquiry information
	Case number:		Case#3
	Description:		Case for Exam #1 FOR340 SP1
	Examiner name:		Ali Hadi
	Evidence number:	0001
	Acquisition date:	Fri Feb 15 14:14:59 2019
	System date:		Fri Feb 15 14:14:59 2019
	Operating system used:	Win 201x
	Software version used:	ADI3.4.2.2
	Password:		N/A

EWF information
	File format:		FTK Imager
	Sectors per chunk:	64
	Compression method:	deflate
	Compression level:	no compression

Media information
	Media type:		fixed disk
	Is physical:		no
	Bytes per sector:	512
	Number of sectors:	82595840
	Media size:		39 GiB (42289070080 bytes)

Digest hash information
	MD5:			634ed59c1cf60ef0a7f62e06529b2b2d
	SHA1:			4e4bd40d4cb8527bcd7ab8a1b77f658f6721970c
```

**Acquisition-record / ewfinfo digests:**
- MD5 = `634ed59c1cf60ef0a7f62e06529b2b2d`
- SHA1 = `4e4bd40d4cb8527bcd7ab8a1b77f658f6721970c`

**(b) Hash computed of the E01 image file itself** (the container as shipped in `inputs/`):

```text
$ md5 inputs/BSidesAmman21.E01
MD5 (inputs/BSidesAmman21.E01) = 1a0a748249f6b39c2aa81af531fb7730

$ shasum -a 256 inputs/BSidesAmman21.E01
2b830de50a198b50bdd677098331270956ba41633710629923131cf8e1fbd02a  inputs/BSidesAmman21.E01
```

- Computed MD5 (E01 container file) = `1a0a748249f6b39c2aa81af531fb7730`
- Computed SHA-256 (E01 container file) = `2b830de50a198b50bdd677098331270956ba41633710629923131cf8e1fbd02a`

The two sets differ because the `ewfinfo` digests hash the **raw (uncompressed) evidence stream**, while the computed digests hash the **E01 container** (which wraps that stream with EWF metadata/compression). Both are correct for what they describe.

---

## 2. Which user account accessed the confidential documents?

**`Joker`** (the local account `Joker`, SID `S-1-5-21-597701057-294507186-493142324-1004`).

---

## 3. Detailed proof supporting that answer

1. **The confidential-document artifacts live in `Joker`'s profile, not `IEUser`'s.** `Joker`'s `Recent` folder holds four shortcuts for the confidential files (filelist):

   ```text
   r/r 96881-128-4: Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential.lnk
   r/r 96884-128-4: Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential_02.lnk
   r/r 96885-128-4: Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential_03.lnk
   r/r 96886-128-4: Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential_04.lnk
   r/r 97031-128-4: Users/Joker/Confidential.rtf
   ```

2. **`Joker`'s `RecentDocs` registry MRU lists the confidential files.** From `Joker`'s `NTUSER.DAT`:

   ```text
   KEY=ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.rtf
     last_modified_utc=2019-02-15T05:03:25.572798+00:00  -> Confidential.rtf / Confidential.lnk
   KEY=ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.docx
     last_modified_utc=2019-02-15T05:03:45.728706+00:00  -> Confidential_02.docx / Confidential_03.docx / Confidential_04.docx (+ .lnk)
   ```

3. **`Joker`'s WordPad recent-file list contains the confidential RTF** (application-level proof tied to the user):

   ```text
   KEY=ROOT\Software\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List
     last_modified_utc=2019-02-15T05:34:16.612184+00:00
     File1 = \\192.168.70.128\SharedJJ\docs\Confidential.rtf
     File2 = C:\Users\Joker\Confidential.rtf
   ```

4. **`Joker` ran WordPad inside the exact access window.** `Joker` `UserAssist`:

   ```text
   {6D809377-6AF0-444B-8957-A3773F02200E}\Windows NT\Accessories\wordpad.exe
     run_count=5  focus_count=4  last_exec_utc=2019-02-15T05:03:45.634000+00:00
   ```

5. **Account/login context.** `IEUser` created `Joker` and `Joker` logged on immediately before the activity (Security.evtx):

   ```text
   RID=1984 time=2019-02-15 04:53:33.496557+00:00 eid=4720  TargetUserName=Joker  SubjectUserName=IEUser
   RID=2029 time=2019-02-15 04:54:09.087833+00:00 eid=4624  TargetUserName=Joker  LogonType=2  WorkstationName=MSEDGEWIN10
   ```

6. **`IEUser` browsed/mapped the share but does not carry the confidential-document MRU hits.** `IEUser` `NTUSER.DAT` shows `Map Network Drive MRU` = `\\192.168.70.128\SharedJJ\` and `MountPoints2\##192.168.70.128#SharedJJ`, but no `RecentDocs`/WordPad entries for the confidential files.

Conclusion: `Joker` is the account that opened the confidential documents; `IEUser` is the account that created `Joker` and had earlier accessed the same share.

---

## 4. Local drive or network location?

**Network location** — an SMB share, `\\192.168.70.128\SharedJJ\docs`.

---

## 5. Proof supporting that answer

The four `Joker` `Recent` shortcuts embed a UNC target and network metadata:

```text
$ exiftool Confidential.lnk Confidential_02.lnk Confidential_03.lnk Confidential_04.lnk
Net Name         : \\192.168.70.128\SHAREDJJ
Working Directory: \\192.168.70.128\SharedJJ\docs
```

```text
$ strings -a Confidential.lnk     -> \\192.168.70.128\SharedJJ\docs\Confidential.rtf
$ strings -a Confidential_02.lnk  -> \\192.168.70.128\SharedJJ\docs\Confidential_02.docx
$ strings -a Confidential_03.lnk  -> \\192.168.70.128\SharedJJ\docs\Confidential_03.docx
$ strings -a Confidential_04.lnk  -> \\192.168.70.128\SharedJJ\docs\Confidential_04.docx
```

A `\\host\share\path` UNC path is by definition a network (SMB) location, not a local drive. `IEUser`'s hive independently confirms the share was reachable and mapped (`Map Network Drive MRU` = `\\192.168.70.128\SharedJJ\`, `MountPoints2\##192.168.70.128#SharedJJ`).

---

## 6. Every file that was accessed (full paths)

Confidential documents (the four files the brief's questions target):

```text
\\192.168.70.128\SharedJJ\docs\Confidential.rtf
\\192.168.70.128\SharedJJ\docs\Confidential_02.docx
\\192.168.70.128\SharedJJ\docs\Confidential_03.docx
\\192.168.70.128\SharedJJ\docs\Confidential_04.docx
```

Related, from the same share/burst (context for the examiner):

```text
\\192.168.70.128\SharedJJ\docs\mandiant-apt1-report.pdf        (mandiant-apt1-report.lnk, 05:03:52Z)
\\192.168.70.128\SharedJJ\docs\TheMeaningofLIFE.pdf            (TheMeaningofLIFE.lnk, 05:04:00Z)
\\192.168.70.128\SharedJJ\docs\The-ProjectSauron.pdf           (The-ProjectSauron.lnk, 05:04:10Z)
\\192.168.70.128\SharedJJ\docs\windows_command_line_sheet_v1.pdf (windows_command_line_sheet_v1.lnk, 05:04:19Z)
\\192.168.70.128\SharedJJ\docs                                 (docs.lnk)
```

Local copy made by `Joker` (evidenced by WordPad's recent-file list, `File2`):

```text
C:\Users\Joker\Confidential.rtf    (inode 97031-128-4, 439 bytes)
```

---

## 7. Two different kinds of evidence that the files were truly accessed

**Evidence type A — `Recent` shortcut (`.lnk`) files.** Windows creates a `.lnk` in `%APPDATA%\Microsoft\Windows\Recent\` when a user opens a document. Four such files exist for the confidential docs, each carrying the full UNC target and a creation timestamp in the 05:02:56–05:03:45Z window (inodes `96881`, `96884`, `96885`, `96886`).

**Evidence type B — `RecentDocs` registry MRU.** `Joker`'s `NTUSER.DAT` `RecentDocs\.rtf` and `RecentDocs\.docx` keys list the confidential filenames and were last modified at `05:03:25.572798Z` and `05:03:45.728706Z` respectively — an independent, user-specific record of the same opens.

(Third, corroborating: `Joker`'s WordPad `Recent File List` records `\\192.168.70.128\SharedJJ\docs\Confidential.rtf` as `File1`.)

---

## 8. Which application opened a confidential document

**WordPad** (`C:\Program Files\Windows NT\Accessories\wordpad.exe`) opened `Confidential.rtf`.

Proof:

```text
# Joker NTUSER.DAT — WordPad recent-file list
KEY=ROOT\Software\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List
  File1 = \\192.168.70.128\SharedJJ\docs\Confidential.rtf
  File2 = C:\Users\Joker\Confidential.rtf

# Joker NTUSER.DAT — UserAssist (execution, decoded)
{6D809377-6AF0-444B-8957-A3773F02200E}\Windows NT\Accessories\wordpad.exe
  run_count=5  focus_count=4  focus_time_ms=22516  last_exec_utc=2019-02-15T05:03:45.634000+00:00
```

The `wordpad.exe` last-execution time (05:03:45.634Z) matches the creation of the `Confidential_04.lnk` (05:03:45Z). The `.docx` files are Office Word documents; WordPad can also open `.docx`, but the direct, timestamped app-level artifact is the WordPad RTF entry, so WordPad is the solidly-evidenced application.

---

## 9. The image with the text "AnotherPassword4U" — full path

The image (a small 377×126 PNG whose visible text reads `AnotherPassword4U`) exists in **two byte-identical copies**:

```text
C:\Users\Joker\haha.png                       (inode 97027-128-5)
C:\Users\IEUser\Pictures\pics\whoami4.png     (inode 98748-128-3)
```

The copy **directly in the user's home-directory root** is `C:\Users\Joker\haha.png` (this is the "home directory" copy the question refers to). Both files are identical:

```text
MD5     = 16c9f7a14da9b3cfe5807111b032b893
SHA-256 = c3b50a8bc1ba7cf2b87400e9d8cca93ca0291f42f11cfea5dda4dad9399e9a20
```

OCR proof:

```text
$ tesseract haha.png stdout
AnotherPassword4U
```

---

## 10. Volume Serial Number of the volume where that file exists

```text
$ fsstat inputs/BSidesAmman21.E01
Volume Serial Number: EE68D66268D628DB
```

The `.lnk` for the image (`whoami4.png.lnk`, inode `95047`) records the same serial in the short Windows/DOS form:

```text
$ exiftool whoami4.png.lnk
Drive Serial Number : 68D6-28DB
```

- Full NTFS 64-bit volume serial (`fsstat`): `EE68D66268D628DB`
- Windows/`.lnk` 32-bit form: `68D6-28DB` (= low 32 bits `68D628DB` of the same value)

---

## 11. MAC timestamps of that file, in UTC

For `C:\Users\Joker\haha.png` (inode `97027`, `$STANDARD_INFORMATION`):

```text
$ istat -o 0 inputs/BSidesAmman21.E01 97027
Created:      2019-02-15 08:00:21.681932000 (+03)  -> 2019-02-15 05:00:21.681932 UTC
File Modified:2019-02-15 08:00:21.681932000 (+03)  -> 2019-02-15 05:00:21.681932 UTC
Accessed:     2019-02-15 08:00:22.697704900 (+03)  -> 2019-02-15 05:00:22.697705 UTC
MFT Modified: 2019-02-15 08:01:53.526052800 (+03)  -> 2019-02-15 05:01:53.526053 UTC
```

| Timestamp | UTC |
| --- | --- |
| Modified | `2019-02-15 05:00:21.681932` |
| Accessed | `2019-02-15 05:00:22.697705` |
| Created | `2019-02-15 05:00:21.681932` |

(For reference, the IEUser copy `whoami4.png` carries different MAC times: Modified `2018-03-06 16:33:54`, Accessed `2019-02-15 05:06:53`, Created `2019-02-15 05:07:07`.)

---

## 12. Which user ran DCode.exe, and the evidence

**`Joker` ran it — but under the renamed filename `dd.exe`** (this is the "tricky" part).

Evidence chain:

1. `C:\Users\Joker\DCode.exe` (inode `97020-128-5`) and `C:\Users\Joker\dd.exe` (inode `97026-128-5`) are **byte-identical**:

   ```text
   $ md5 DCode.exe dd.exe
   MD5 = b534d93d94f86a052f398a44928247d9   (both files)
   ```

2. `Joker`'s `NTUSER.DAT` holds DCode's VB6 settings key (only `Joker`, not `IEUser`):

   ```text
   KEY=ROOT\Software\VB and VBA Program Settings\DCode\Settings
     last_modified_utc=2019-02-15T05:02:13.494426+00:00
     OnTop = False
   ```

   (`DCode.exe` is a VB6 app — it imports `msvbvm60.dll` — so it writes this key when it runs and saves settings.)

3. `Joker`'s `UserAssist` shows the tool executed under the name `dd.exe`:

   ```text
   C:\Users\Joker\dd.exe
     run_count=1  focus_count=1  last_exec_utc=2019-02-15T05:02:12.791000+00:00
   ```

4. Only `Windows\Prefetch\DD.EXE-0C303FDD.pf` exists — there is **no** `DCODE.EXE-*.pf`. Because `DCode.exe` was copied/renamed to `dd.exe` before execution, Windows recorded the run under `dd.exe`.

---

## 13. How many times DCode.exe was used

**One (1) time.**

`Joker`'s `UserAssist` `C:\Users\Joker\dd.exe` has `run_count=1` (and `focus_count=1`), and the DCode settings key was written a single time (`OnTop=False`, last write `05:02:13.494Z`). The absence of a `DCODE.EXE` prefetch and the presence of a single `DD.EXE` prefetch are consistent with exactly one execution under the `dd.exe` name.

---

## 14. When DCode.exe was last used

**`2019-02-15 05:02:12.791 UTC`** (UserAssist `last_exec_utc` for `C:\Users\Joker\dd.exe`), corroborated by the DCode settings-key write at **`2019-02-15 05:02:13.494 UTC`**.

(Note: the `DCode.exe` file's NTFS "Accessed" time of `05:01:40` is earlier and is not authoritative here — Windows 10 build 17134 disables last-access time updates by default, and the reliable execution markers are the registry timestamps.)

---

## 15. Where the application was located (full path)

```text
C:\Users\Joker\DCode.exe
```

with the byte-identical renamed execution copy:

```text
C:\Users\Joker\dd.exe
```

(`DCode.exe` is Digital Detective's DCode timestamp decoder v4.2.0.9306, PE32 GUI, 2009 — a forensic-analysis utility, which is why its presence as an executed tool is notable in a suspect's home directory.)

---

## 16. Timeline (confidential-file access, DCode activity, and examiner notes)

Merged timeline is maintained in `work/timeline.md` (41 dated rows). Summary of the decisive sequence, all UTC 2019-02-15:

| Time (UTC) | Event |
| --- | --- |
| 04:53:33 | `IEUser` creates local account `Joker` (Security 4720, record 1984) |
| 04:54:09 | `Joker` logs on interactively (Security 4624, record 2029) |
| 04:59:22 | `DCode.exe` created at `C:\Users\Joker\DCode.exe` |
| 04:59:52 | `dd.exe` created at `C:\Users\Joker\dd.exe` (byte-identical to DCode.exe) |
| 05:00:21 | `haha.png` created at `C:\Users\Joker\haha.png` (image "AnotherPassword4U") |
| 05:00:49 | `Confidential.rtf` created at `C:\Users\Joker\Confidential.rtf` |
| 05:02:12.791 | `Joker` executes the DCode tool as `dd.exe` (UserAssist run_count=1) |
| 05:02:13.494 | DCode settings key written in `Joker`'s NTUSER.DAT |
| 05:02:56 | `Confidential.lnk` created → `\\192.168.70.128\SharedJJ\docs\Confidential.rtf` |
| 05:03:25 | `RecentDocs\.rtf` updated (Confidential.rtf); `Confidential.lnk` re-opened |
| 05:03:34 | `Confidential_02.lnk` created → `Confidential_02.docx` |
| 05:03:39 | `Confidential_03.lnk` created → `Confidential_03.docx` |
| 05:03:45 | `Confidential_04.lnk` created → `Confidential_04.docx`; `wordpad.exe` last executed (run_count=5) |
| 05:03:52–05:04:19 | Additional share docs opened (`mandiant-apt1-report.pdf`, `TheMeaningofLIFE.pdf`, `The-ProjectSauron.pdf`, `windows_command_line_sheet_v1.pdf`) |
| 05:05:06 | `Joker` runs `\\192.168.70.128\SharedJJ\tools\putty.exe` (UserAssist run_count=2) |
| 05:06:52–05:07:07 | `whoami4.png` copy created/accessed in `IEUser`'s Pictures, and its `.lnk` created |

**Other things the examiner should know:**

- `IEUser` is the operator behind the scene: it created `Joker`, and on 2018-04-25 it also created `sshd`/`sshd_server` and added `sshd_server` to **Administrators** (Security 4720/4732, records 762/779/787).
- `IEUser` ran anti-forensics/tooling: `SetMace.exe` (timestamp manipulation; prefetch `SETMACE.EXE-A69E1686.pf`), `sync64.exe`, `putty.exe`, and mapped the `\\192.168.70.128\SharedJJ` share (`Map Network Drive MRU`, `MountPoints2`). `IEUser` also accessed pictures (`FindMeIfYouCan.jpg`, `forensics.jpg`) from the same share via a `O:\pics` mapping.
- The "AnotherPassword4U" image is duplicated: `C:\Users\Joker\haha.png` and `C:\Users\IEUser\Pictures\pics\whoami4.png` (same MD5/SHA-256), so any answer about it must name the specific path.
- No standalone memory image was supplied; classic Volatility analysis is not possible. `pagefile.sys` (`83404-128-1`) and `swapfile.sys` (`83405-128-1`) are the only memory-adjacent artifacts.
- `DCode.exe` and `dd.exe` being byte-identical (and only `DD.EXE` prefetch existing) is the intended "trick": the tool was renamed before execution, so searches for `DCODE.EXE` prefetch come up empty.

---

*Report assembled by s2f6606 (critic/editor) from the seat notes (`work/disk_triage.md`, `work/accounts-registry-findings.md`, `work/memory-findings.md`, `work/leftovers.md`) and the shared ledger (`ledger/ledger.md`). Every citation above was verified against the extracted artifact or catalog/ledger record.*

# Disk triage — s2f6600

## Scope

Assigned seat: filesystem / path-list triage, attack-window file additions and changes, and attacker-added paths with inode proof.

## Filesystem layout

Source: `catalog/BSidesAmman21.E01/partitions.txt`

> No partition table: inputs/BSidesAmman21.E01 is one NTFS volume starting at sector 0 (use the tools without -o).

Source: `catalog/BSidesAmman21.E01/p0/fsstat.txt`

> File System Type: NTFS
>
> Volume Serial Number: EE68D66268D628DB
>
> Version: Windows XP

Working conclusion: the E01 is a single NTFS logical volume starting at sector 0; commands should be run without `-o`.

## High-signal Joker paths added/changed in the attack window

The strongest burst of user-created / user-touched artifacts in `catalog/BSidesAmman21.E01/p0/timeline.csv` is on **2019-02-15 04:59Z–05:04Z**, concentrated in `Users/Joker/`.

### Attacker-added or attacker-staged files in `Users/Joker/`

Source: `catalog/BSidesAmman21.E01/p0/filelist.txt`

> r/r 97020-128-5:\tUsers/Joker/DCode.exe
> r/r 97023-128-5:\tUsers/Joker/putty.exe
> r/r 97026-128-5:\tUsers/Joker/dd.exe
> r/r 97027-128-5:\tUsers/Joker/haha.png
> r/r 97031-128-4:\tUsers/Joker/Confidential.rtf

Source: `catalog/BSidesAmman21.E01/p0/timeline.csv`

> 2019-02-15T04:59:22Z,461952,...b,...,97020-128-5,"/Users/Joker/DCode.exe"
> 2019-02-15T04:59:34Z,854072,m.cb,...,97023-128-5,"/Users/Joker/putty.exe"
> 2019-02-15T04:59:52Z,461952,...b,...,97026-128-5,"/Users/Joker/dd.exe"
> 2019-02-15T05:00:21Z,2084,m..b,...,97027-128-5,"/Users/Joker/haha.png"
> 2019-02-15T05:00:49Z,439,m..b,...,97031-128-4,"/Users/Joker/Confidential.rtf"

These five files appear in a tight sequence and are likely central to the activity.

## Network-share documents evidenced by Recent LNK files

I extracted the `Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/*.lnk` files with `icat` and read printable strings from each.

Command pattern used:

> icat inputs/BSidesAmman21.E01 <inode> | strings -a

### Confidential document set

Source inode `96881-128-4` (`Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential.lnk`)

> \\192.168.70.128\SharedJJ\docs\Confidential.rtf

Source inode `96884-128-4` (`.../Confidential_02.lnk`)

> \\192.168.70.128\SharedJJ\docs\Confidential_02.docx

Source inode `96885-128-4` (`.../Confidential_03.lnk`)

> \\192.168.70.128\SharedJJ\docs\Confidential_03.docx

Source inode `96886-128-4` (`.../Confidential_04.lnk`)

> \\192.168.70.128\SharedJJ\docs\Confidential_04.docx

### Other network-share documents opened in the same burst

Source inode `97147-128-4` (`.../mandiant-apt1-report.lnk`)

> \\192.168.70.128\SharedJJ\docs\mandiant-apt1-report.pdf

Source inode `97684-128-4` (`.../TheMeaningofLIFE.lnk`)

> \\192.168.70.128\SharedJJ\docs\TheMeaningofLIFE.pdf

Source inode `97703-128-4` (`.../The-ProjectSauron.lnk`)

> \\192.168.70.128\SharedJJ\docs\The-ProjectSauron.pdf

Source inode `98352-128-4` (`.../windows_command_line_sheet_v1.lnk`)

> \\192.168.70.128\SharedJJ\docs\windows_command_line_sheet_v1.pdf

Source inode `97152-128-3` (`.../docs.lnk`)

> \\192.168.70.128\SharedJJ\docs

### Timing of the confidential-document access artifacts

Source: `catalog/BSidesAmman21.E01/p0/timeline.csv`

> 2019-02-15T05:02:56Z,...,96881-128-4,"/Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential.lnk"
> 2019-02-15T05:03:34Z,...,96884-128-4,"/Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential_02.lnk"
> 2019-02-15T05:03:39Z,...,96885-128-4,"/Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential_03.lnk"
> 2019-02-15T05:03:45Z,...,96886-128-4,"/Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential_04.lnk"
> 2019-02-15T05:03:52Z,...,97147-128-4,"/Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/mandiant-apt1-report.lnk"
> 2019-02-15T05:04:00Z,...,97684-128-4,"/Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/TheMeaningofLIFE.lnk"
> 2019-02-15T05:04:10Z,...,97703-128-4,"/Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/The-ProjectSauron.lnk"
> 2019-02-15T05:04:19Z,...,98352-128-4,"/Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/windows_command_line_sheet_v1.lnk"

Working conclusion: the confidential files were accessed from a **network location**, not from a local drive, because the Recent-item shortcuts resolve to the UNC path `\\192.168.70.128\SharedJJ\docs\...`.

## `AnotherPassword4U` image paths verified on disk

I verified **two on-disk PNG files with the same visible content** (`AnotherPassword4U`):

Filelist proof:

> r/r 97027-128-5:\tUsers/Joker/haha.png
> r/r 98748-128-3:\tUsers/IEUser/Pictures/pics/whoami4.png
> r/r 95047-128-4:\tUsers/IEUser/AppData/Roaming/Microsoft/Windows/Recent/whoami4.png.lnk

Both extracted images (`work/s2f6600/haha.png` and `work/s2f6600/whoami4.png`) visibly contain the text `AnotherPassword4U`.

### Joker copy: `C:\Users\Joker\haha.png`

`istat` evidence for inode `97027`:

> Created:\t2019-02-15 08:00:21.681932000 (+03)
> File Modified:\t2019-02-15 08:00:21.681932000 (+03)
> MFT Modified:\t2019-02-15 08:01:53.526052800 (+03)
> Accessed:\t2019-02-15 08:00:22.697704900 (+03)

UTC conversion:

- Created: `2019-02-15T05:00:21.681932Z`
- Modified: `2019-02-15T05:00:21.681932Z`
- Accessed: `2019-02-15T05:00:22.697705Z`
- MFT changed: `2019-02-15T05:01:53.526053Z`

### IEUser copy: `C:\Users\IEUser\Pictures\pics\whoami4.png`

Recent-LNK evidence (inode `95047-128-4`, extracted and parsed with `exiftool`):

> Local Base Path : C:\Users\IEUser\Pictures\pics\whoami4.png
> Drive Serial Number : 68D6-28DB
> Working Directory : C:\Users\IEUser\Pictures\pics

Timeline evidence:

> 2018-03-06T16:33:54Z,2084,m...,...,98748-128-3,"/Users/IEUser/Pictures/pics/whoami4.png"
> 2019-02-15T05:06:53Z,2084,.a..,...,98748-128-3,"/Users/IEUser/Pictures/pics/whoami4.png"
> 2019-02-15T05:07:07Z,2084,..c.,...,98748-128-3,"/Users/IEUser/Pictures/pics/whoami4.png"

Volume Serial Number for the containing NTFS volume from `fsstat`: `EE68D66268D628DB` (same volume; LNK shows DOS format `68D6-28DB`).

Working conclusion: the report should treat the `AnotherPassword4U` question carefully because the same image content exists in both a Joker path and an IEUser path. The IEUser copy also has a Recent LNK that conveniently preserves the DOS-form serial and full local path.

## Prefetch corroboration: WordPad and the DCode/dd.exe trick

I extracted the relevant prefetch files and parsed them with the forged tool `mam_pf_parse`.

Command pattern used:

> icat inputs/BSidesAmman21.E01 <inode> > work/s2f6600/<name>.pf
> mam_pf_parse {"path":"work/s2f6600/<name>.pf"}

### `DD.EXE-0C303FDD.pf`

Filelist proof:

> r/r 96361-128-4:\tWindows/Prefetch/DD.EXE-0C303FDD.pf

Parsed result:

> executable_name: DD.EXE
> run_count: 1
> last_run_times_utc: 2019-02-15T05:02:13.353878Z

This is important because `Users/Joker/dd.exe` and `Users/Joker/DCode.exe` were staged together in Joker’s profile during the same burst. I independently extracted both files and hashed them:

> MD5 (work/s2f6600/DCode.exe) = b534d93d94f86a052f398a44928247d9
> MD5 (work/s2f6600/dd.exe) = b534d93d94f86a052f398a44928247d9
> SHA256 work/s2f6600/DCode.exe = 02b59b7ff4a5cd7a80f2c9c7d743af12850847c5a7448857e1a354490a8250b9
> SHA256 work/s2f6600/dd.exe = 02b59b7ff4a5cd7a80f2c9c7d743af12850847c5a7448857e1a354490a8250b9

Combined with the fact that only **DD.EXE** has prefetch and there is no `DCODE.EXE-*.pf` path in the file list, the safest disk-level conclusion is that the DCode program was actually run under the filename **`dd.exe`**, and it was run **once**.

### `WORDPAD.EXE-942EAA71.pf`

Filelist proof:

> r/r 97044-128-4:\tWindows/Prefetch/WORDPAD.EXE-942EAA71.pf

Parsed result:

> executable_name: WORDPAD.EXE
> run_count: 5
> last_run_times_utc: 2019-02-15T05:03:39.525588Z; 2019-02-15T05:03:45.634965Z; 2019-02-15T05:03:34.134967Z; 2019-02-15T05:03:25.494339Z; 2019-02-15T05:02:56.650702Z

These times line up closely with the Joker `Recent` LNK burst for `Confidential.rtf`, `Confidential_02.docx`, `Confidential_03.docx`, and `Confidential_04.docx`, and with s2f6601’s registry-side WordPad/UserAssist evidence.

## Provisional conclusions for the report

1. The filesystem is a single NTFS volume at sector 0 with serial `EE68D66268D628DB`.
2. A concentrated artifact burst under `Users/Joker/` occurs from `2019-02-15T04:59:22Z` through `2019-02-15T05:04:19Z`.
3. The core staged files in Joker’s home are `DCode.exe`, `putty.exe`, `dd.exe`, `haha.png`, and `Confidential.rtf`.
4. The confidential documents evidenced so far were opened from the UNC share `\\192.168.70.128\SharedJJ\docs`, not from a local path.
5. The image containing `AnotherPassword4U` exists in at least two verified local paths: `C:\Users\Joker\haha.png` (inode `97027-128-5`) and `C:\Users\IEUser\Pictures\pics\whoami4.png` (inode `98748-128-3`), with a Recent LNK for the IEUser copy at inode `95047-128-4`.
6. The "tricky" DCode answer appears to be: the DCode program present as `C:\Users\Joker\DCode.exe` was used via the renamed copy `C:\Users\Joker\dd.exe`; prefetch supports **1 run** with latest run `2019-02-15T05:02:13.353878Z`.
7. WordPad is strongly evidenced for `Confidential.rtf`; its prefetch records 5 runs with timestamps overlapping the confidential-document access burst.

## To verify next

- Correlate these disk artifacts with per-user registry / event-log evidence from s2f6601.
- Confirm whether `Users/Joker/Confidential.rtf` is a local copy derived from `\\192.168.70.128\SharedJJ\docs\Confidential.rtf`.
- If needed for the final report, independently hash `Users/Joker/DCode.exe` and `Users/Joker/dd.exe` in the same note so the dd.exe/DCode identity is cited from a file, not only from a board post.

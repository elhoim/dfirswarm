# Disk triage

Agent: s9f2000
Status: drafted; update only if new corroboration arrives

## Filesystem overview

- Evidence file `inputs/Windows8.1-Challenge3.001` is a single NTFS volume with **no partition table** and starts at sector 0.
  - Evidence: `catalog/Windows8.1-Challenge3.001/partitions.txt`
- NTFS details from `fsstat`:
  - Volume serial: `16049E12049DF4C9`
  - Sector size: `512`
  - Cluster size: `4096`
  - MFT entry size: `1024`
  - Root directory inode: `5`
  - Evidence: `catalog/Windows8.1-Challenge3.001/p0/fsstat.txt`

## Early attack-window observations

**Timezone note:** the UTC timestamps in this note come from `catalog/.../timeline.csv`. Where I quote `istat`, I preserve the local time string exactly as the tool rendered it on the analysis host, but that rendered local zone should **not** be assumed to equal the guest OS timezone. Per s9f2001's registry work (`SYSTEM\ControlSet001\Control\TimeZoneInformation`), the guest timezone key was `Pacific Standard Time`. For report writing, prefer UTC or explicitly distinguish host-rendered forensic-tool output from guest-configured timezone.

A likely attacker activity cluster appears between **2015-12-12 03:21Z and 03:27Z**.

Cross-seat corroboration from s9f2001 / s9f2005 (event logs / registry):
- The `master` account / profile activity at `2015-12-12T03:02:42Z`–`03:03:19Z` is now best read as **setup/OOBE-consistent new-user provisioning**, not standalone intrusion proof.
- The clearly suspicious account activity starts later: built-in `Administrator` was enabled at `2015-12-12T03:21:08.401726Z`, logged on interactively at `2015-12-12T03:22:19Z`, logged on again at `2015-12-12T03:25:14Z`, and was disabled again at `2015-12-12T03:26:19Z`.
- That suspicious event-log sequence aligns tightly with the disk artifacts below: `Administrator` profile initialization, browsing of `master`'s `Docs` folder, creation of `C:\Tools`, and the taunt-file drops.
- Evidence provenance for those account/logon facts: `threads/main/000024-s9f2001.md`, `threads/main/000039-s9f2005.md`, `threads/main/000043-s9f2001.md`, and especially the report-writing correction in `threads/main/000046-s9f2001.md` plus the cited `Security.evtx` / registry records from those seats.

### 1) Administrator profile initialization

- The built-in `Administrator` profile tree first appears on disk at **2015-12-12T03:22:19Z**.
- This is consistent with the `Administrator` account being initialized/logged on around that time.
- Evidence:
  - `catalog/Windows8.1-Challenge3.001/p0/timeline.csv`
  - Example rows for `/Users/Administrator`, `NTUSER.DAT`, and profile artifacts at `2015-12-12T03:22:19Z`

### 2) User-visible taunt dropped in master's Desktop docs

- Path: `C:\Users\master\Desktop\Docs\README.txt`
- Inode: `84603-128-1`
- Content: `Your admin says hi to you ;)`
- MAC times from `istat`:
  - Created: `2015-12-12 05:23:31.121150100 (EET)` = `2015-12-12T03:23:31Z`
  - File Modified: `2015-12-12 05:23:44.589367400 (EET)` = `2015-12-12T03:23:44Z`
  - MFT Modified: `2015-12-12 05:23:44.589367400 (EET)` = `2015-12-12T03:23:44Z`
  - Accessed: `2015-12-12 05:23:31.121150100 (EET)` = `2015-12-12T03:23:31Z`
- Ownership/security from `istat`:
  - Security ID: `1331 (S-1-5-32-544)`
  - This maps to the local Administrators group SID, not the normal `master` user SID seen on `Info.txt` in the same directory.
- Evidence:
  - `icat inputs/Windows8.1-Challenge3.001 84603-128-1`
  - `istat inputs/Windows8.1-Challenge3.001 84603-128-1`
  - `catalog/Windows8.1-Challenge3.001/p0/filelist.txt`
  - `catalog/Windows8.1-Challenge3.001/p0/timeline.csv`

### 3) Administrator-context browsing of master's Docs folder

- The Administrator profile contains `Recent\Docs.lnk`, created at **2015-12-12T03:23:34Z**.
- Strings from that LNK show target path `C:\Users\master\Desktop\Docs`.
- This is strong evidence that an Administrator-context session browsed the victim user's `Docs` folder just after the taunt file was created there.
- Inode: `84608-128-3`
- Evidence:
  - `icat inputs/Windows8.1-Challenge3.001 84608-128-3 > work/s9f2000/admin-Docs.lnk`
  - `strings -a work/s9f2000/admin-Docs.lnk`
  - `istat inputs/Windows8.1-Challenge3.001 84608-128-3`

### 4) User-visible taunt dropped at C:\Tools

- Path: `C:\Tools\README.txt`
- Parent directory: `C:\Tools` (inode `84609-144-1`), created at **2015-12-12T03:23:52Z**
- File inode: `84614-128-1`
- Content:

  `Hello master,`

  `Catch me if you can!`

  `Best regards,`
  `Your Admin ;)`

- MAC times from `istat`:
  - Created: `2015-12-12 05:24:04.871001500 (EET)` = `2015-12-12T03:24:04Z`
  - File Modified: `2015-12-12 05:24:39.964740500 (EET)` = `2015-12-12T03:24:39Z`
  - MFT Modified: `2015-12-12 05:24:39.964740500 (EET)` = `2015-12-12T03:24:39Z`
  - Accessed: `2015-12-12 05:24:04.871001500 (EET)` = `2015-12-12T03:24:04Z`
- Ownership/security from `istat`:
  - Security ID: `1333 (S-1-5-32-544)`
- Evidence:
  - `icat inputs/Windows8.1-Challenge3.001 84614-128-1`
  - `istat inputs/Windows8.1-Challenge3.001 84614-128-1`
  - `catalog/Windows8.1-Challenge3.001/p0/timeline.csv`

### 5) The employee likely opened C:\Tools\README.txt after it was dropped

- The `master` profile contains `Recent\README.lnk`, created at **2015-12-12T03:27:14Z**.
- Strings from the LNK show target path `C:\Tools\README.txt`.
- Inode: `81247-128-1`
- Evidence:
  - `icat inputs/Windows8.1-Challenge3.001 81247-128-1 > work/s9f2000/master-README.lnk`
  - `strings -a work/s9f2000/master-README.lnk`
  - `catalog/Windows8.1-Challenge3.001/p0/timeline.csv`

### 6) The Administrator profile also recorded C:\Tools as a Recent item

- `Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\Tools.lnk` was created at **2015-12-12T03:24:09Z**.
- Strings from the LNK show target path `C:\Tools`.
- This lines up with the creation of `C:\Tools` at `2015-12-12T03:23:52Z` and `C:\Tools\README.txt` at `2015-12-12T03:24:04Z`.
- Inode: `84615-128-1`
- Evidence:
  - `icat inputs/Windows8.1-Challenge3.001 84615-128-1 > work/s9f2000/admin-Tools.lnk`
  - `strings -a work/s9f2000/admin-Tools.lnk`
  - `istat inputs/Windows8.1-Challenge3.001 84615-128-1`

## Current interpretation

- Cross-seat evidence now makes the leading intrusion hypothesis much stronger: the attacker likely used the `Magnify.exe`→`cmd.exe` accessibility backdoor from the Winlogon screen to obtain a pre-auth or Winlogon-context SYSTEM shell, then used local commands to enable `Administrator`, interact locally, and leave the taunting files.
  - Provenance: `threads/main/000029-s9f2001.md`, `threads/main/000031-s9f2005.md`, `threads/main/000046-s9f2001.md`, and the disk evidence above.
- Two taunting files were placed on disk within ~33 seconds of each other:
  - `C:\Users\master\Desktop\Docs\README.txt`
  - `C:\Tools\README.txt`
- Both taunt files carry Administrators-group security SIDs in `istat` output.
- The `Administrator` profile was initialized minutes before the taunts and its Recent items show browsing of `C:\Users\master\Desktop\Docs` and `C:\Tools`.
- The victim user `master` later opened `C:\Tools\README.txt` and also browsed `C:\Tools` itself (`Users/master/.../Recent/Tools.lnk`, inode `83399-128-1`, created `2015-12-12T03:27:23Z`).
- Based on the Recent-item evidence, `C:\Tools\README.txt` is presently the strongest candidate for the file the employee reported finding, though `C:\Users\master\Desktop\Docs\README.txt` is also an attacker-created taunt and should remain in scope until event-log / shell-item evidence narrows it further.

## Broad system-servicing metadata wave before the user-visible intrusion artifacts

There is a large filesystem-wide metadata burst on **2015-12-12 between about 02:05Z and 02:15Z**.

- In a 15-second slice around `2015-12-12T02:05:40Z`–`02:05:55Z`, the timeline contains **20,607** rows:
  - `19,217 macb`
  - `1,386 ..c.`
  - `3 .a.b`
  - `1 ...b`
- The paths are dominated by system/component-store areas, especially:
  - `/Windows/WinSxS`
  - `/Program Files/WindowsApps`
  - `/Windows/System32`
  - `/Windows/Microsoft.NET`
- A clear anchor appears at `2015-12-12T02:10:20Z` in `/Windows/servicing/Packages/` with many package rows for KBs such as `KB2919355` and `KB2932046`, plus `Sessions.xml` and `Version/6.3.9600.17031/*`.
- Follow-on rows hit classic servicing executables:
  - `2015-12-12T02:11:20Z` — `/Windows/System32/msiexec.exe`
  - `2015-12-12T02:11:49Z` — `/Windows/System32/poqexec.exe`
  - `2015-12-12T02:12:30Z` — `/Windows/System32/wusa.exe`

Current interpretation: this looks like a **Windows servicing / update metadata wave**, not a focused attacker write burst. It should stay in the timeline because it is close to the intrusion window, but disk evidence presently points to it being system activity distinct from the later `Administrator` profile activity and taunt-file drops.

Evidence:
- `catalog/Windows8.1-Challenge3.001/p0/timeline.csv`
- See rows for `/Windows/servicing/Packages/Package_*KB2919355*`, `*KB2932046*`, `msiexec.exe`, `poqexec.exe`, and `wusa.exe`

## Accessibility backdoor / file replacement notes

The report already has a strong lead from s9f2006 that `Magnify.exe` was replaced with a copy of `cmd.exe`. I verified the disk-level part of that claim:

- `catalog/.../filelist.txt` shows both:
  - `42335-128-3(realloc): Windows/System32/Magnify.exe`
  - `2043-128-2: Windows/System32/Magnify.exe`
- `catalog/.../timeline.csv` shows the swap window:
  - `2015-12-11T19:18:48Z` — `42335-128-3` (`Magnify.exe`) gets `..c.` as a deleted/reallocated file.
  - `2015-12-11T19:18:54Z` — `2043-128-2` (`Magnify.exe`) appears with `macb`.
- Hashes I verified by extraction:
  - current `Magnify.exe` inode `2043` MD5 `fc0b4a626881d7c5980d757214db2d25`
  - `cmd.exe` inode `41024` MD5 `fc0b4a626881d7c5980d757214db2d25`
  - deleted/realloc original `Magnify.exe` inode `42335` MD5 `7ccdf6ad04920d691263a02e97fcdee2`
- I checked adjacent/common Ease-of-Access executables and do **not** see the same replacement pattern for them:
  - `DisplaySwitch.exe` inode `41386` MD5 `c4c0663a7b097a75c3d474f3b83a2b06`
  - `Narrator.exe` inode `42603` MD5 `ea5a04b79580eba6ebd813f5d51d3f3e`
  - `osk.exe` inode `42858` MD5 `d795ddee95839688808e5a74dc0d540d`
  - `sethc.exe` inode `43268` MD5 `eaa24f098158f46f97d8f4ede3e2b753`
  - `Utilman.exe` inode `43655` MD5 `2e509f13b0cd255bef8baf34b5849b4a`

This supports a specific accessibility-backdoor swap of `Magnify.exe`, not a broad overwrite of multiple Ease-of-Access binaries.

### Important timestamp caveat: VBoxService rolled the guest clock backward

Per s9f2001's event-log work, `VBoxService.exe` changed the guest clock from `2015-12-12T03:30:35Z` back to `2015-12-11T17:30:37Z` (`Security.evtx` EID 4616 / `System.evtx` EID 1; see `threads/main/000025-s9f2001.md`).

This matters for disk interpretation:
- Raw filesystem timestamps **after** that rollback point can look earlier than events that really happened before the rollback.
- Therefore, the raw `Magnify.exe` replacement times (`2015-12-11T19:18:48Z` deleted/realloc old file and `2015-12-11T19:18:54Z` new current file) should not be sequenced against the `2015-12-12T03:xxZ` taunt/account activity by raw clock alone.
- Cross-seat resolution from s9f2004: monotonic NTFS `$LogFile` LSN ordering (unaffected by the guest clock rollback) places the `cmd.exe`/`Magnify.exe` work **before** the taunt-file creation and before `master` later opened `C:\Tools\README.txt`; see `threads/main/000049-s9f2004.md` and `work/timeline.md`.
- Safe phrasing for the report: raw timestamps cross a rollback boundary, but the combined disk + ledger/timeline evidence still supports `Magnify.exe` backdoor installation as an earlier step in the intrusion than the later `Administrator`/taunt activity.

## Remaining questions / limits

- Current `filelist.txt` and `bodyfile.txt` show only one live child under `C:\Tools`: `README.txt`. I did not find another current file there, but I have **not** proved the directory never briefly held an additional file that was later deleted.
- Disk evidence strongly supports the taunts, the `Administrator`-context browsing, and the `Magnify.exe` replacement, but exact ordering across the VBoxService clock rollback boundary must come from event-log sequence context, not raw timestamp sorting alone.
- If more deleted-file carving or pagefile corroboration appears from other seats, I may add a short addendum; otherwise this note is ready for the report.
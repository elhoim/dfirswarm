# Leftovers and malware findings (`s9f2003`)

## Scope

Seat focus: web roots, temp/profile directories, prefetch, scheduled tasks, services, dropped tools, and possible web shells.

Primary evidence used:

- `catalog/Windows8.1-Challenge3.001/p0/filelist.txt`
- `catalog/Windows8.1-Challenge3.001/p0/timeline.csv`
- `icat -o 0 inputs/Windows8.1-Challenge3.001 <inode>`
- `istat -o 0 inputs/Windows8.1-Challenge3.001 <inode>`
- `strings -a` on extracted `.lnk` and PE files
- `shasum -a 256` on extracted binaries

## 1. Root-level taunt left for the victim

A root-level directory and text file were created during the main intruder activity cluster:

- `C:\Tools` — inode `84609-144-1`
- `C:\Tools\README.txt` — inode `84614-128-1`

### Content of `C:\Tools\README.txt`

Extracted with:

```bash
icat -o 0 inputs/Windows8.1-Challenge3.001 84614-128-1
```

Content:

> Hello master,
>
> Catch me if you can!
>
> Best regards,
> Your Admin ;)

### MAC / ownership evidence

`istat -o 0 inputs/Windows8.1-Challenge3.001 84614`

- Created: `2015-12-12 05:24:04.871001500` in `istat` rendering, corresponding to `2015-12-12T03:24:04Z` in the UTC catalog timeline
- File Modified: `2015-12-12 05:24:39.964740500` in `istat` rendering
- MFT Modified: `2015-12-12 05:24:39.964740500` in `istat` rendering
- Accessed: `2015-12-12 05:24:04.871001500` in `istat` rendering
- Security ID: `1333 (S-1-5-32-544)` = `BUILTIN\Administrators`

`istat -o 0 inputs/Windows8.1-Challenge3.001 84609`

- `C:\Tools` created: `2015-12-12 05:23:52.792823300` in `istat` rendering, corresponding to `2015-12-12T03:23:52Z` in the UTC catalog timeline
- Security ID: `1332 (S-1-5-32-544)` = `BUILTIN\Administrators`

This shows the root-level taunt was created by an Administrator-context process, not by the normal `master` user.

### User interaction artifacts

I extracted and string-searched the Recent-item shortcuts:

```bash
icat -o 0 inputs/Windows8.1-Challenge3.001 84615-128-1 > work/s9f2003/84615-128-1.lnk
icat -o 0 inputs/Windows8.1-Challenge3.001 81294-128-1 > work/s9f2003/81294-128-1.lnk
icat -o 0 inputs/Windows8.1-Challenge3.001 83399-128-1 > work/s9f2003/83399-128-1.lnk
icat -o 0 inputs/Windows8.1-Challenge3.001 81247-128-1 > work/s9f2003/81247-128-1.lnk
strings -a work/s9f2003/*.lnk
```

The LNKs resolve to:

- `C:\Tools`
- `C:\Tools\README.txt`

Affected Recent-item artifacts:

- `Users/Administrator/AppData/Roaming/Microsoft/Windows/Recent/Tools.lnk` (`84615-128-1`)
- `Users/Administrator/AppData/Roaming/Microsoft/Windows/Recent/README.lnk` (`81294-128-1`)
- `Users/master/AppData/Roaming/Microsoft/Windows/Recent/Tools.lnk` (`83399-128-1`)
- `Users/master/AppData/Roaming/Microsoft/Windows/Recent/README.lnk` (`81247-128-1`)

This is consistent with both the Administrator-context session and the victim user opening or browsing the taunt shortly after it was dropped.

## 2. Accessibility-binary backdoor: `Magnify.exe` replaced with `cmd.exe`

The strongest malware/persistence finding in my slice is replacement of the Windows Ease-of-Access binary `C:\Windows\System32\Magnify.exe` with a byte-identical copy of `cmd.exe`.

### Timeline evidence

Relevant timeline rows:

- Original `Magnify.exe` (deleted/reallocated) inode `42335-128-3`
  - `2015-12-11T19:18:48Z` — `..c.` on `/Windows/System32/Magnify.exe (deleted-realloc)`
- New `Magnify.exe` inode `2043-128-2`
  - `2015-12-11T19:18:54Z` — `macb` on `/Windows/System32/Magnify.exe`
- `cmd.exe` inode `41024-128-3`
  - `2015-12-12T02:10:44Z` — `..c.` on `/Windows/System32/cmd.exe`
- Additional accessibility binaries had ctime changes in the same window:
  - `Narrator.exe` — `2015-12-12T02:11:24Z`
  - `osk.exe` — `2015-12-12T02:11:48Z`
  - `sethc.exe` — `2015-12-12T02:12:02Z`
  - `Utilman.exe` — `2015-12-12T02:12:07Z`

Important chronology note: per `s9f2001`'s verified event-log and registry work, the guest OS timezone key was `Pacific Standard Time`, while some analyst-side tools such as `istat` appear to have rendered timestamps in the examiner host timezone. Separately, `VBoxService.exe` rolled the guest clock back at `2015-12-11T17:30:37Z`, changing the system time from `2015-12-12 03:30:35 UTC` to `2015-12-11 17:30:37 UTC` (`Security.evtx` EID 4616 record 333; `System.evtx` EID 1 record 266). That means the raw on-disk times stamped `2015-12-11 17:30Z` and later may actually be *later in real sequence* than some `2015-12-12 03:xxZ` events.

However, `s9f2004`'s timeline work used monotonic NTFS `$LogFile` LSN ordering to resolve this ambiguity: the `cmd.exe` touch and `Magnify.exe` replacement occur earlier in LSN order than the later `Info.txt`, `README.txt`, and `C:\Tools` creation events. So the safest combined phrasing is: the clock rollback complicates raw timestamp order, but the backdoor installation still appears to precede the taunt-file creation when ordered by NTFS transaction sequence rather than wall-clock strings alone.

### File comparison and hashes

Extracted with:

```bash
icat -o 0 inputs/Windows8.1-Challenge3.001 41024-128-3 > work/s9f2003/41024-128-3.bin
icat -o 0 inputs/Windows8.1-Challenge3.001 2043-128-2 > work/s9f2003/2043-128-2.bin
shasum -a 256 work/s9f2003/41024-128-3.bin work/s9f2003/2043-128-2.bin
```

SHA-256 for both files:

- `0b9bc863e2807b6886760480083e51ba8a66118659f4ff274e7b73944d2219f5`

Sizes from NTFS metadata:

- `C:\Windows\System32\cmd.exe` (inode `41024-128-3`): `355840` bytes
- current `C:\Windows\System32\Magnify.exe` (inode `2043-128-2`): `355840` bytes
- original deleted/reallocated `Magnify.exe` (inode `42335-128-3`): `837632` bytes

This is strong evidence that the attacker replaced Magnifier with Command Prompt so that launching the Ease-of-Access feature at the logon screen would provide a SYSTEM shell.

### Metadata details

`istat -o 0 inputs/Windows8.1-Challenge3.001 2043`

- Path: `C:\Windows\System32\Magnify.exe`
- Created: `2015-12-11 21:18:54.192340500` in `istat` rendering
- File Modified: `2015-12-11 21:18:54.230183200` in `istat` rendering
- MFT Modified: `2015-12-11 21:18:54.230183200` in `istat` rendering
- Non-resident data size: `355840`

`istat -o 0 inputs/Windows8.1-Challenge3.001 42335`

- Original deleted/reallocated `Magnify.exe`
- Security ID: `536` (`NT SERVICE\TrustedInstaller`-style SID)
- Data size: `837632`
- MFT Modified: `2015-12-11 21:18:48.509136900` in `istat` rendering

## 3. Related execution artifacts from Prefetch

The Prefetch timeline shows execution of tools consistent with tampering and account/service administration:

- `UTILMAN.EXE` — `2015-12-12T03:26:03Z`
- `MAGNIFY.EXE` — `2015-12-12T03:26:13Z`
- `NET1.EXE` — `2015-12-12T03:26:19Z`
- `NET.EXE` — `2015-12-12T03:26:19Z`
- `SC.EXE` — `2015-12-12T03:27:51Z`
- `TAKEOWN.EXE` — `2015-12-12T03:28:23Z`

Source: `catalog/Windows8.1-Challenge3.001/p0/timeline.csv`

Cross-seat corroboration from `s9f2006`'s parsed `.pf` files strengthens the sequence:

- `NET1.EXE` last run: `2015-12-12 03:05:50 UTC`
- `SC.EXE` last run: `2015-12-12 03:26:03 UTC`
- `TAKEOWN.EXE` last run: `2015-12-12 03:28:24 UTC`

Cross-seat corroboration from `s9f2001`'s Security.evtx work:

- local account `master` was created at `2015-12-12T03:02:42.943144Z`
- `master` was added to `Administrators`
- built-in `Administrator` was enabled at `2015-12-12T03:21:08.401726Z`
- `Administrator` logged on interactively at `2015-12-12T03:22:19Z`
- built-in `Administrator` was disabled again at `2015-12-12T03:26:19Z`

Interpretation:

- The early `NET1.EXE` execution aligns well with account creation / enablement activity.
- `MAGNIFY.EXE` / `UTILMAN.EXE` execution shortly before the taunt strongly supports use or testing of the logon-screen accessibility backdoor.
- `SC.EXE` indicates service-control activity during the same window.
- `TAKEOWN.EXE` is consistent with taking ownership of protected system files before replacement or cleanup.
- The interactive `Administrator` session overlaps the period when `C:\Tools` and `C:\Tools\README.txt` were created.

## 4. Scheduled tasks / web roots / dropped tools

### Scheduled tasks

I reviewed task paths in `catalog/.../filelist.txt`.

Observed task files were overwhelmingly stock Microsoft tasks plus expected per-user tasks such as:

- `Windows/System32/Tasks/Optimize Start Menu Cache Files-S-1-5-21-...-1001`
- `Windows/System32/Tasks/WPD/SqmUpload_S-1-5-21-...-1001`
- `Windows/System32/Tasks/WPD/SqmUpload_S-1-5-21-...-500`

I did **not** identify an obviously attacker-created scheduled task file in the catalog.

### Web roots / web shells

Searches for likely web-root and web-shell paths/names in `filelist.txt` did not produce evidence of a live web root such as `inetpub\wwwroot`, XAMPP/WAMP directories, or obvious ASPX/PHP/JSP shell names under user-writable locations.

At present I have **no file-system evidence for a web-shell-based intrusion path**.

### Dropped tools

A notable file in temp was:

- `Users/master/AppData/Local/Temp/ad_driver.sys` — inode `81252-128-4`

However `exiftool` identifies it as:

- Company: `AccessData Corporation`
- Description: `AccessData Memory and Disk driver`
- Product: `AccessData Memory and Disk driver`
- SHA-256: `2e837fd06ee1a1dabb022f3a90e125183974a74ee8b9d0b001f1d15a2b28e3c3`

This appears to be an FTK/AccessData artifact rather than attacker malware.

## 5. Working conclusion for this seat

The most important leftovers/malware evidence is:

1. An Administrator-context taunt dropped under `C:\Tools\README.txt`.
2. A classic accessibility backdoor where `Magnify.exe` was replaced with `cmd.exe`.
3. Supporting Prefetch evidence for `MAGNIFY.EXE`, `UTILMAN.EXE`, `NET.EXE`, `SC.EXE`, and `TAKEOWN.EXE` during the attack window.
4. A guest clock rollback by `VBoxService.exe` complicates raw timestamp ordering across `2015-12-12T03:30Z`; the report should explain this before presenting event order, and should rely on the timeline seat's NTFS LSN ordering where needed.
5. No persuasive evidence from my slice for a web shell or malicious scheduled task.

## 6. Items for cross-check by other seats

- `s9f2001`: correlate `NET.EXE` / `SC.EXE` timeframe with account creation, group changes, and event log records for the new `Administrator` profile activity.
- `s9f2004`: include the `Magnify.exe` replacement and `C:\Tools\README.txt` creation in the merged timeline.
- `s9f2006`: use this note alongside the ledger entries for report sections on message delivery, persistence, and attacker actions after access.

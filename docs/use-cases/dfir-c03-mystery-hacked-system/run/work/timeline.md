# Timeline — ALIHADI-C3 "Mystery Hacked System"

Author: s9f2004 (Timeline & ledger seat). Built from `ledger/ledger.md` (see that file for full evidence strings). Times below are raw values from the NTFS MAC timeline / event logs; clock-rollback consequences are flagged.

## Timezone and clock integrity (read first)

- The guest OS timezone is **Pacific Standard Time (PST, UTC-8)** per `SYSTEM\ControlSet001\Control\TimeZoneInformation` (`TimeZoneKeyName=Pacific Standard Time`, `Bias=480`). Security 4738's localized `PasswordLastSet = 12/11/2015 7:02:42 PM` confirms UTC-8. (TSK `istat` rendered some MAC times as "EET" because the analyst host is in that zone — that is a tool-rendering artifact, not the guest zone.)
- **Guest clock rollback:** `Security.evtx` record 333 (`EID 4616`) and `System.evtx` record 266 (`EID 1`) show `VBoxService.exe` set the guest clock **backward** from `2015-12-12T03:30:35Z` to `2015-12-11T17:30:37Z`. Events/file-times stamped `2015-12-11 17:30Z` and later are therefore **not** chronologically before the `2015-12-12 03:2xZ` artifacts in real sequence — they occurred after the rollback.
- **Authoritative ordering** comes from the monotonic NTFS `$LogFile` sequence number (LSN) in each MFT entry, which is unaffected by wall-clock changes. By LSN the true order is:

| LSN (MFT entry) | Object | Raw timestamp | Real position |
| --- | --- | --- | --- |
| 61,728,638 (`41024` cmd.exe) | cmd.exe MFT-touched (copy source) | 2015-12-12 02:10:44Z | backdoor phase (earliest) |
| 62,563,932 (`42335` orig Magnify.exe) | original Magnify.exe deleted/reallocated | 2015-12-11 21:18:48 EET (host-rendered) | backdoor phase |
| `2043` (replacement Magnify.exe) | Magnify.exe now = cmd.exe | 2015-12-11 21:18:54 EET (host-rendered) | backdoor phase |
| 154,577,384 (`83074`) | Info.txt | 2015-12-12 03:08:54Z | later |
| 186,670,800 (`84608`) | Administrator "Docs.lnk" | 2015-12-12 03:23:34Z | later |
| 186,675,608 (`84603`) | `\Users\master\Desktop\Docs\README.txt` | 2015-12-12 03:23:31Z | later |
| 186,717,000 (`84614`) | `\Tools\README.txt` | 2015-12-12 03:24:04Z | later |
| 218,177,810 (`81247`) | master "README.lnk" (opens message) | 2015-12-12 03:27:14Z | later |
| 235,088,351 (`81252`) | `ad_driver.sys` (AccessData FTK driver) | 2015-12-11 19:32:51 EET (host-rendered) | **latest (imaging)** |

Net reading: the **Magnify→cmd.exe backdoor was installed first**, the account/taunt activity came next, and the AccessData (FTK) imaging driver was loaded last (post-intrusion image acquisition).

## Timeline (raw UTC; local = PST/UTC-8)

| # | UTC | PST (local) | Event | Evidence / source | Conf |
| --- | --- | --- | --- | --- | --- |
| 1 | 2013-08-22 | — | Original Windows 8.1 binaries present (incl. original Magnify.exe inode 42335, cmd.exe inode 41024). | MFT; istat 42335/41024 | high |
| 2 | 2014-03-18 10:23:59 | — | Early boot/stop record (install-era event in System log). | System.evtx EID 13 | high |
| 3 | 2015-11-10 16:59 | — | Oracle VM VirtualBox Guest Additions 5.0.10 installed (baseline, non-attacker). | MFT; SOFTWARE Uninstall | high |
| 4 | 2015-12-11 19:18:54 | 11:18:54 | **Magnify.exe replaced with a copy of cmd.exe** (accessibility backdoor). | istat 2043/42335; MD5 fc0b4a62… | high |
| 5 | 2015-12-12 02:05–02:15 | 18:05–18:15 (12-11) | Broad Windows servicing/update metadata wave (KB2919355/KB2932046, WinSxS, WindowsApps, msiexec/poqexec/wusa). System churn, not attacker content. | timeline.csv | medium |
| 6 | 2015-12-12 02:18:43 | 18:18:43 (12-11) | Boot; Security log (re)starts at record 1 (EID 4608). Host WIN-A9KKHBKS7E6. | Security.evtx rec 1 | high |
| 7 | 2015-12-12 02:20:39 | 18:20:39 (12-11) | Sysprep/upgrade restart (EID 1074 "Operating System: Upgrade (Planned)"); host renamed toward "sensei". | System.evtx 1074 | high |
| 8 | 2015-12-12 03:02:42 | 19:02:42 (12-11) | Local account "master" (RID 1001) created/enabled/password-set and added to BUILTIN\Administrators by SYSTEM — **now read as OOBE/new-user provisioning** (InstallDate 03:03:15Z, profile materializes 03:03:16–19Z), not standalone intrusion proof. | Security 4720/4722/4724/4732/4733 | high (event); mechanism uncertain |
| 9 | 2015-12-12 03:03:16 | 19:03:16 (12-11) | "master" logs on interactively (local console, LogonType=2). | Security 4624; TS-LSM 21/22 LOCAL | high |
| 10 | 2015-12-12 03:05:50 | 19:05:50 (12-11) | `NET.EXE`/`NET1.EXE` run (account/password command). | Prefetch NET1.EXE last-run | high |
| 11 | 2015-12-12 03:08:54 | 19:08:54 (12-11) | `\Users\master\Desktop\Docs\Info.txt` created (owner = master SID -1001); "Nothing really interesting, just practicing some type writing :)". | istat/icat 83074 | high |
| 12 | 2015-12-12 03:09:17 | 19:09:17 (12-11) | Info.txt last-write. | istat 83074 | high |
| 13 | 2015-12-12 03:09:45 | 19:09:45 (12-11) | "master" logs off; power-off (EID 1074 by sensei\master). | Security 4647; System 1074 | high |
| 14 | 2015-12-12 03:20:11 | 19:20:11 (12-11) | Reboot (host SENSEI). | System EID 12 | high |
| 15 | 2015-12-12 03:21:08 | 19:21:08 (12-11) | **Built-in Administrator (RID 500) enabled** (UAC 0x211→0x210) — suspicious cluster begins. | Security 4722/4738 | high |
| 16 | 2015-12-12 03:22:19 | 19:22:19 (12-11) | **Administrator logs on** interactively (local console); Administrator profile materializes on disk. | Security 4624; TS-LSM LOCAL | high |
| 17 | 2015-12-12 03:23:31 | 19:23:31 (12-11) | `\Users\master\Desktop\Docs\README.txt` created (owner = BUILTIN\Administrators); "Your admin says hi to you ;)". | istat/icat 84603 | high |
| 18 | 2015-12-12 03:23:34 | 19:23:34 (12-11) | Administrator profile records Recent link to `C:\Users\master\Desktop\Docs`. | icat 84608 (Docs.lnk) | high |
| 19 | 2015-12-12 03:23:44 | 19:23:44 (12-11) | README.txt (Docs) last-write. | istat 84603 | high |
| 20 | 2015-12-12 03:23:52 | 19:23:52 (12-11) | `C:\Tools` directory created (owner = BUILTIN\Administrators). | istat 84609 | high |
| 21 | 2015-12-12 03:24:04 | 19:24:04 (12-11) | `C:\Tools\README.txt` created; "Hello master, Catch me if you can! Best regards, Your Admin ;)". | istat/icat 84614 | high |
| 22 | 2015-12-12 03:24:09 | 19:24:09 (12-11) | Administrator profile Recent link to `C:\Tools`. | icat 84615 (Tools.lnk) | high |
| 23 | 2015-12-12 03:24:39 | 19:24:39 (12-11) | `C:\Tools\README.txt` last-write. | istat 84614 | high |
| 24 | 2015-12-12 03:24:52 | 19:24:52 (12-11) | Administrator logs off; restart (EID 1074 by sensei\Administrator). | Security 4647; System 1074 | high |
| 25 | 2015-12-12 03:25:14 | 19:25:14 (12-11) | Administrator logs on again (local console). | Security 4624; SAM LastLogon | high |
| 26 | 2015-12-12 03:26:03 | 19:26:03 (12-11) | `SC.EXE` run (`sc create`/`sc config`). | Prefetch SC.EXE last-run | high |
| 27 | 2015-12-12 03:26:13 | 19:26:13 (12-11) | `MAGNIFY.EXE`/`UTILMAN.EXE` run — accessibility-backdoor trigger. | Prefetch MAGNIFY.EXE/UTILMAN.EXE | high |
| 28 | 2015-12-12 03:26:19 | 19:26:19 (12-11) | **Administrator disabled again** (UAC 0x210→0x211) — cleanup. | Security 4725/4738 | high |
| 29 | 2015-12-12 03:26:53 | 19:26:53 (12-11) | "master" logs on again (local console). | Security 4624; TS-LSM LOCAL | high |
| 30 | 2015-12-12 03:27:14 | 19:27:14 (12-11) | **master opens `C:\Tools\README.txt`** (Recent item) — the employee finds the message. | icat 81247 (README.lnk) | high |
| 31 | 2015-12-12 03:27:23 | 19:27:23 (12-11) | master Recent link to `C:\Tools`. | icat 83399 (Tools.lnk) | high |
| 32 | 2015-12-12 03:28:24 | 19:28:24 (12-11) | `TAKEOWN.EXE` run (`takeown /f ...`). | Prefetch TAKEOWN.EXE last-run | high |
| 33 | 2015-12-12 03:30:16 | 19:30:16 (12-11) | Final shutdown (image acquisition point); master was the logged-on user. | System 1074/13; Security 4647 | high |
| 34 | 2015-12-12 03:30:35 | 19:30:35 (12-11) | **VBoxService rolls guest clock back** 03:30:35Z → 2015-12-11 17:30:37Z. | Security 4616 rec 333; System 1 rec 266 | high |
| 35 | 2015-12-11 17:32:51 (stamped) | (post-rollback) | **AccessData Driver (FTK Imager) service installed** (`C:\Users\master\AppData\Local\Temp\ad_driver.sys`). By LSN (235M) this is the latest real event — post-intrusion imaging. | System 7045; icat 81252 | high |

## Key takeaways

- The intrusion's persistence/entry mechanism is the **Magnify.exe → cmd.exe accessibility ("Ease of Access") backdoor**, installed before the account/taunt activity (LSN order).
- The suspicious post-exploitation cluster is: enable built-in `Administrator` → interactive Administrator session → drop `Info.txt` + the two `README.txt` taunt files → disable `Administrator` (cleanup) → `master` opens the message. (`master` creation itself is OOBE/new-user-provisioning-consistent and should not be used as standalone intrusion proof.)
- All interactive logons in the surviving logs are **local console** (LogonType=2, TS-LSM Address=LOCAL); no RDP/type-10 or remote-IP logon is evidenced, so remote access is not proven by the event logs.
- The AccessData (FTK) driver load marks forensic image acquisition, which happened after the intrusion (highest LSN).

## Remaining uncertainty

- How write access to `System32\Magnify.exe` was first obtained (physical/console access to the VM, offline NTFS mount, or a credential we cannot see in the cleared log) is inferred, not directly observed.
- Whether the `4720`/profile-provisioning at 03:02–03:03Z was OOBE-driven vs. backdoor-driven is a mechanism question; the timing is certain, the trigger is not.

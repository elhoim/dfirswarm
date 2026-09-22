# Registry and execution artifacts

Seat: **s864a03** (regexec). Host image `inputs/AF-Case2.E01` (logical NTFS, offset 0). Extracts under `work/extracted/hives/`, `work/extracted/prefetch/`, `work/extracted/lnk/`, `work/extracted/jumplists/`. Parser dumps under `work/s864a03/`.

Hives were pulled with `icat inputs/AF-Case2.E01 <inode>` (no `-o`; volume starts at sector 0).

| Hive | Path on image | Inode | Size | SHA256 of extract |
| --- | --- | --- | --- | --- |
| SYSTEM | `Windows/System32/config/SYSTEM` | 42054 | 11 010 048 | `0893e469640a381140bec5b19bc8e714c38f980c34ea114518c2001fd775babd` |
| SOFTWARE | `Windows/System32/config/SOFTWARE` | 46340 | 72 351 744 | `48c2501a66aa5cffa4636a0d0b993bc8a572fa55806dff0576711875d64f54e5` |
| SAM | `Windows/System32/config/SAM` | 41760 | 65 536 | `4cd95071600bb3736cfbf831bb2325e013f7e3670dd79c4acbb1b6060818e5ef` |
| SECURITY | `Windows/System32/config/SECURITY` | 41763 | 65 536 | `cd711d28eb052e2ada1d8a19a1ca6283a99c019c0e5cbeb9d665230c4cb61de4` |
| NTUSER | `Users/IEUser/NTUSER.DAT` | 83438 | 1 310 720 | `46f425b721654c3dd1138b8186b33b728d51abea3a241d08c8cc2bef85ad6fde` |
| UsrClass | `Users/IEUser/AppData/Local/Microsoft/Windows/UsrClass.dat` | 83564 | 3 407 872 | `40f8a9c5e858e45537f9cfbb80f611cf90042bcec151a46e40c607c2ed47703e` |
| Amcache | `Windows/appcompat/Programs/Amcache.hve` | 83201 | 1 310 720 | `e5946e424eb6b11634f4c62427bc97a5b87c004e3c7a8fe3189a91ae0e5d13d2` |

Parsers: `regipy` 6.3.0 (SAM/SOFTWARE/SYSTEM/NTUSER/Amcache plugins), Win10 prefetch decompressed with `dissect.util.compression.lzxpress_huffman` (MAM\x04), LNK FILETIME/path fields parsed from the Shell Link binary.

---

## 1. Host, user, timezone

| Fact | Value | Evidence |
| --- | --- | --- |
| Computer name | `MSEDGEWIN10` | `SYSTEM\ControlSet001\Control\ComputerName\ComputerName` |
| OS | Windows 10 Enterprise Evaluation, build 17763 (1809) | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` ProductName/CurrentBuild/ReleaseId |
| InstallDate (Unix) | 1553000375 = 2019-03-19T13:00:00Z | same key, `InstallDate` |
| Time zone | Pacific Standard Time, Bias 480 min (UTC−8), ActiveTimeBias 480 | `SYSTEM\ControlSet001\Control\TimeZoneInformation` |
| CurrentControlSet | 1 | `SYSTEM\Select` Current=1 |
| Interactive user | **IEUser** (no `Jane` profile) | SAM `Names\IEUser`; ProfileList |
| SID | `S-1-5-21-321011808-3761883066-353627080-1000` | ProfileList + BAM |
| RID | 1000 (`000003E8`) | SAM `\SAM\Domains\Account\Users` |
| Other SAM names | Administrator, DefaultAccount, Guest, sshd, WDAGUtilityAccount | SAM Names |
| Profile path | `C:\Users\IEUser` | ProfileList |

Jane in the brief is this IEUser account (Mattermost identity `jane@ccdfir.local` is a separate web account — see caches seat). Prefetch FILETIMEs below are UTC.

---

## 2. What was installed (Uninstall + Amcache)

`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` and WOW6432Node, last-write of the uninstall key:

| Product | Version | Install location | Uninstall key last write (UTC) |
| --- | --- | --- | --- |
| 7-Zip | 22.01 (x64) | `C:\Program Files\7-Zip\` | 2023-02-22T18:44:09.039938Z |
| HxD Hex Editor | 2.5 | `C:\Program Files\HxD\` | 2023-02-22T18:46:54.969212Z (InstallDate 20230222) |
| GNU Privacy Guard | 2.4.0 | `C:\Program Files (x86)\GnuPG` | 2023-02-22T18:47:12.988354Z |
| Gpg4win | 4.1.0 | `C:\Program Files (x86)\Gpg4win` | 2023-02-22T18:47:18.908868Z |
| AES Crypt | 3.10 | `C:\Program Files\AESCrypt\` | 2023-02-22T18:54:54.683686Z (InstallDate 20230222) |

Amcache (inode 83201) first-seen timestamps match the same window. SHA1 of `gpg.exe`: `3f0dac462119f87acf0523ce90b4c886c651d95f`. SHA1 of `BitLockerWizardElev.exe`: `59f735dbf95bf182c6da1ad4ca17abcc3a6ad2c0`. SHA1 of `bdeunlock.exe`: `2798e3af9d6e47b438c1c0fa4ddf5e31b18ad0f9`.

AES Crypt file association (SOFTWARE last write 2023-02-22T18:54:54.655542Z):

- `HKCR\.aes` → `aesfile`, Content Type `application/aes`
- `HKCR\aesfile\shell\open\command` = `"C:\Program Files\AESCrypt\AESCrypt32.exe" "%1"`
- `HKCR\*\shellex\ContextMenuHandlers\AESCrypt` (Explorer context menu; this is how README was encrypted — **no `AESCRYPT.EXE` / `AESCRYPT32.EXE` prefetch exists**)
- `HKCR\*\shellex\ContextMenuHandlers\GpgEX` (Gpg4win Explorer extension)

Installers were run from `C:\Users\IEUser\AppData\Local\Downloads\` (not the user Downloads folder): `7z2201-x64.exe`, `AESCrypt_v310_x64.zip` / `setup.exe` / `AESCrypt.msi`, `gpg4win-4.1.0.exe`, `HxDSetup.exe`.

---

## 3. Execution timeline (prefetch + BAM + UserAssist)

Win10 prefetch is MAM/Xpress-Huffman. Last-run FILETIME array at offset 0x80, run count at 0xD0. BAM: `SYSTEM\ControlSet001\Services\bam\State\UserSettings\<IEUser SID>` (first 8 bytes of each value = last-start FILETIME). UserAssist: `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-…}\Count` (ROT13 names, run count at +4, FILETIME at +60).

Dump: `work/s864a03/prefetch.json`, `bam.json`, `userassist.json`.

### Tool install / prep — 2023-02-22 18:44–18:54 UTC

| UTC last run | Exe | Runs (pf) | Corroboration |
| --- | --- | --- | --- |
| 18:44:06.848 | `…\Local\Downloads\7z2201-x64.exe` | UA 1; pf 1 at 18:44:08 | BAM 18:44:10 |
| 18:45:32.987 | `vcredist_x64.exe` (AESCrypt payload) | UA 1 | BAM 18:45:55 |
| 18:46:14.393 | `vcredist_x86.exe` | UA 1 | BAM 18:46:34 |
| 18:46:45.304 | `HxDSetup.exe` | UA 1; pf 2 last 18:46:46 | Amcache 18:46:46 |
| 18:47:03.449 | `gpg4win-4.1.0.exe` | UA 1; pf 1 at 18:47:04 | BAM 18:47:18; nested `GNUPG-W32-2.4.0_…` pf 18:47:12 |
| 18:53:20.399 | `AESCrypt_v310_x64\setup.exe` | UA **4**; pf 4 last 18:53:20 | BAM 18:53:25 |
| 18:54:48.953 | `msiexec.exe` | UA 1; pf 5 last 18:54:49 | BAM 18:54:56; pf referenced `AESCrypt.msi` and `Program Files\AESCrypt\AESCrypt.dll` |

PowerShell (pf `POWERSHELL.EXE-59FC8F3D.pf`) last run **2023-02-20T23:22:56Z**, 8 runs, referenced `C:\Windows\Temp\sdelete.zip` and `C:\Windows\Temp\7z920.msi` — image-prep / lab bootstrap, not the 22 Feb encryption chain. `SDELETE.EXE` prefetch last run **2019-03-19T13:28:16Z** (1 run, `C:\Windows\Temp\sdelete.exe`). NTUSER `\Software\Sysinternals\SDelete\EulaAccepted=1` last write 2019-03-19T13:28:16Z. **SDelete was not re-run on 2023-02-22.**

`CMD.EXE` prefetch last run 2023-02-22T21:46:25Z (19 runs). UserAssist cmd.exe last 2023-02-20T23:21:33Z only — later cmd use was not through the Start-menu shortcut path UserAssist tracks the same way.

### Part 2 — VHD / BitLocker — 20:26–20:47 UTC

| UTC | Exe | Runs | Notes |
| --- | --- | --- | --- |
| 20:26:50 | `compmgmtlauncher.exe` / `mmc.exe` | 1 / 1 | Computer Management; pf also referenced `AESCrypt.dll` and `gpgex.dll` (Explorer-loaded extensions present) |
| 20:26:52 | `vdsldr.exe` / `vds.exe` | 1 / 1 | Virtual Disk Service — VHD attach |
| 20:33:37 / 20:33:46 | `rundll32.exe` (two pf) | 1 / 1 | volume/shell helpers around mount |
| 20:42:12.830 | **`BitLockerWizardElev.exe`** | **1** | inode 126823, SHA256 `d7fc41317ab440b4fe180dcc2bc51e191c9a1e9f01bc001077a6f75b094ff160`. BAM 20:44:18. Amcache first-seen 20:42:13. UserAssist run_count=0 / last=None (wizard elevated, not a normal UA GUI launch). MuiCache: “BitLocker Drive Encryption Wizard”. |
| 20:47:03 | `BdeUISrv.exe` | 3 | BitLocker UI server |
| 20:47:26.675 | **`bdeunlock.exe`** | **2** | inode 126839. UserAssist last 20:47:26.673, runs=1. BAM 20:47:34. MuiCache: “BitLocker Unlock”. |
| 20:47:26.694 | `rundll32.exe` | 1 | same second as unlock |
| 20:47:33.932 | `fvenotify.exe` | 2 | FVE notification after encryption/unlock |
| 20:46:20 | `HxD.exe` | 3 (pf) / UA 2 | hex editor while dealing with the volume |

TypedPaths (`NTUSER\…\Explorer\TypedPaths`, last write **2023-02-22T20:45:06.063204Z**):

- `url1` = `C:\ProgramData\Starwars`
- `url2` = `C:\`

No FVE auto-unlock keys in NTUSER (`FVEAutoUnlock` absent). `SYSTEM\ControlSet001\Control\FVE` key does not exist. Recovery material is the Documents TXT (inode 126830), not the registry.

`SYSTEM\MountedDevices`: `\DosDevices\E:` present (binary disk-signature form, distinct from C:). Matches LNK target `E:\` and `E:\DeceiveYou.png`.

### Part 3 — GPG / Kleopatra — 20:25 then 23:29–23:46 UTC

| UTC last run | Exe | Runs (pf) | Notes |
| --- | --- | --- | --- |
| 20:25:00 | `keyboxd.exe` | 2 | GnuPG keybox daemon at first key-ring init |
| 23:29:13 | `gpg-agent.exe` / `gpg-connect-agent.exe` | 6 / 3 | agent start |
| 23:34:12.511 | **`kleopatra.exe`** | **4** | UA last 23:37:28.518, **runs=5**. BAM last 23:46:04.970 (process still alive at shutdown) |
| 23:34:12 | `gpgconf.exe` (13), `dirmngr.exe` (6) | | Kleopatra spawning GnuPG |
| 23:37:35 | `scdaemon.exe` | 6 | |
| 23:39:25 | `gpgsm.exe` | 12 | |
| 23:40:03.609 | **`pinentry.exe`** | **10** | passphrase prompts (keygen / decrypt / encrypt). BAM last 23:40:19. UA run_count=0 (Qt helper). |
| 23:42:16.585 | **`gpg.exe`** | **19** | inode 126766, SHA256 `9d749152349ccb59342e6206c61237f1fe108f281945a7118c433210aab2a18b`. Prior runs in the FILETIME slot: 23:37:41 (five clustered), 23:34:08, 23:31:29. Referenced `Users\IEUser\AppData\Roaming\gnupg\pubring.kbx` and `trustdb.gpg`. |
| 23:42:16.579 | `gpgme-w32spawn.exe` | 21 | Kleopatra/GpgME worker (temp dirs `GPGME-*` under Local\Temp) |
| 23:42:36.474 | `notepad.exe` | 5 (pf) / UA 11 | opened `AESCrypt_v310_x64\Install Notes.txt` per pf; UA last matches pf |
| 23:42:42.882 | `PickerHost.exe` | 1 | file picker (BAM 23:42:47) — likely attaching Keys.txt |
| 23:44:56.647 | **`7zG.exe`** | **3** | referenced **`\PROGRAMDATA\STARWARS\R2D2.7Z`** and the AESCrypt zip. BAM 23:45:02. UA last not in the 23:44 slot for 7zG (7zG UA not listed — GUI from Explorer). |

**Hypothesis (labelled):** 7zG at 23:44:56 packing `ProgramData\Starwars\R2D2.vhd` into `R2D2.7z` is post-BitLocker archival. Disk/recovery seats should treat `R2D2.7z` as an additional copy of the encrypted VHD if the file still exists or is in $LogFile (s864a01 already reported the name in $LogFile).

Explorer UserAssist last 2023-02-22T23:42:23.338Z, 10 runs. Edge UA last 23:37:22.695Z, 6 runs (Mattermost in the browser — caches seat).

---

## 4. Shimcache (AppCompatCache)

`SYSTEM` ShimCachePlugin, 285 entries, dump `work/s864a03/shimcache.json`. Last-mod dates are **PE compile / file-system last write**, not execute time. Presence still proves the path was seen by the loader:

- `C:\Program Files (x86)\GnuPG\bin\gpg.exe` (PE 2022-12-16)
- `kleopatra.exe`, `pinentry.exe`, `gpgme-w32spawn.exe`
- `C:\Windows\System32\BitLockerWizardElev.exe`, `bdeunlock.exe`
- `C:\Program Files\7-Zip\7zG.exe`, `7zFM.exe`
- `C:\Program Files\HxD\HxD.exe`
- AESCrypt **installer** `setup.exe` / vcredist under Local\Downloads — **not** `C:\Program Files\AESCrypt\aescrypt.exe` or `AESCrypt32.exe` (those were not recorded in Shimcache; consistent with context-menu DLL use)
- `C:\Windows\Temp\sdelete.exe` (2018-11-15 last-mod) — 2019 lab image, not 2023

---

## 5. LNK Recent + jump lists + RecentDocs

Extracts: `work/extracted/lnk/`. Target times are the **target file** MAC in the LNK, not the shortcut’s own MFT times.

| LNK (inode) | Local path | Target mtime (UTC) | SHA256 of LNK |
| --- | --- | --- | --- |
| README.txt.lnk (27941) | `C:\Users\IEUser\Documents\README.txt` | 2023-02-22T19:46:01.983776Z | `610e715c6e23c4a6e04aebf5061cc4af1f696b889d745d91e6eb78663623478a` |
| AESCrypt_v310_x64.lnk (124597) | `C:\Users\IEUser\AppData\Local\Downloads\AESCrypt_v310_x64` | 18:46:09.921058Z (ctime 18:44:19) | `38bb6244…` |
| R2D2.vhd.lnk (126799) | **`C:\ProgramData\Starwars\R2D2.vhd`** | 20:45:27.147974Z (ctime 20:34:09.340286Z) | `3b8dd83d…` |
| R2D2 (E).lnk (126818) | `E:\` | 20:34:28.943326Z (ctime 20:28:32.124720Z) | `536d1039…` |
| DeceiveYou.png.lnk (126817) | **`E:\DeceiveYou.png`** | 17:34:45.810596Z (ctime 17:33:18.000000Z) | `b0de3ef5…` |
| BitLocker Recovery Key ….lnk (126829) | `C:\Users\IEUser\Documents\BitLocker Recovery Key EBB0BD7C-DB64-47F5-9A3B-03939F6E8F76.TXT` | (no valid FILETIME in header) | `2f1d71e5…` |
| Starwars.lnk (126756) | `C:\ProgramData\Starwars` | 20:45:27.039518Z | `feabc342…` |
| John_0x61BE50C1_public.asc.lnk (126785) | `C:\Users\IEUser\Downloads\John_0x61BE50C1_public.asc` | 23:31:21.204616Z | `88e3ecab…` |
| Keys.txt.lnk (126958) | `C:\Users\IEUser\Downloads\Keys.txt` | 23:42:31.228744Z | `e0c3697c…` |

**README.txt.lnk still names the plaintext** `README.txt`, not `README.txt.aes`. Combined with USN (s864a01): created 19:46:01, encrypted 20:21:17, plaintext deleted 20:21:25.

**DeceiveYou.png was opened from the mounted R2D2 volume `E:`**, not from Documents. Target ctime 17:33:18Z is the file’s creation inside the VHD (pre-mount). Explorer Photos UserAssist 20:34:31.066Z matches the `.png` RecentDocs last write 20:34:31.263524Z.

RecentDocs (`NTUSER\…\Explorer\RecentDocs`, last write 23:43:54.235824Z):

- `.txt` MRU (last write 23:42:36.080476Z): `Install Notes.txt`, `README.txt`, `BitLocker Recovery Key EBB0BD7C-….TXT`, `Keys.txt`
- `.vhd`: `R2D2.vhd` (20:46:02)
- `.png`: `DeceiveYou.png` (20:34:31)
- `.asc`: `John_0x61BE50C1_public.asc` (23:40:09)
- Folder MRU: `Local`, `AESCrypt_v310_x64`, `ProgramData`, **`R2D2 (E:)`**, `Starwars`, `Downloads`

Jump list `5f7b5f1e01b83767.automaticDestinations-ms` (Explorer, inode 84057) strings include all of the above plus `E:\DeceiveYou.png` and `C:\ProgramData\Starwars\R2D2.vhd`. AppId `9b9cdc69c1c24e2b` (Notepad) includes `README.txt` and `Keys.txt`. AppId `1b4dd67f29cb1962` includes both `Documents\R2D2.vhd` and `Starwars\R2D2.vhd`.

RunMRU key exists (last write 2023-02-22T18:42:47.092240Z) but **has no values** — Jane did not use Win+R for these tools.

---

## 6. Persistence, tasks, services

- NTUSER `…\CurrentVersion\Run`: only `OneDrive` (2019-03-19). No crypto tool Run keys.
- Scheduled tasks of interest: `Windows/System32/Tasks/OneDrive Standalone Update Task-S-1-5-21-…-1000` (inode 86957). No extra BitLocker/GPG tasks.
- Services: `BDESVC` (BitLocker Drive Encryption Service) and `fvevol` present as inbox Windows components; Start type not modified for the case. No extra third-party crypto service.
- Sysinternals BGInfo EulaAccepted 2019-03-19 (VM wallpaper; pf last 23:28:12, 8 runs — wallpaper refresh, not the puzzle).

---

## 7. How the three parts show up in execution artifacts

**Part 1 — Lost in Space (README / AES Crypt)**  
AES Crypt 3.10 installed 18:54:54Z. Encryption of `Documents\README.txt` was **not** a standalone `aescrypt.exe` process (no prefetch, no BAM, no Shimcache of `Program Files\AESCrypt\aescrypt.exe`). It was the **Explorer context-menu handler** `AESCrypt.dll` / open verb `AESCrypt32.exe`. LNK + RecentDocs still remember `README.txt` at 19:46:01Z. Password is not in the registry (no AESCrypt NTUSER key). Caches seat recovered `StarWars!` from Mattermost.

**Part 2 — Do Not Be Deceived (R2D2 / BitLocker)**  
Virtual Disk Service + Computer Management at 20:26, BitLocker wizard at 20:42, unlock UI at 20:47. Typed path `C:\ProgramData\Starwars`. LNKs distinguish **`E:\` (mounted volume)** and **`C:\ProgramData\Starwars\R2D2.vhd` (the FVE copy)** from the Documents clone. `DeceiveYou.png` was viewed from **E:** at 20:34 (before the wizard finished — i.e. while the clone/volume was still readable). Recovery key is a Documents file, not a registry protector. 7zG later touched `ProgramData\Starwars\R2D2.7z`.

**Part 3 — Your Focus Determines Your Reality (GPG / Keys.txt)**  
Gpg4win 4.1.0 + GnuPG 2.4.0 installed 18:47. Kleopatra + pinentry + `gpg.exe` (19 runs, last 23:42:16Z) around Keys.txt creation 23:42:31Z (LNK mtime). Pinentry 10 runs = passphrase entry for Jane’s key. No passphrase in RunMRU/TypedPaths/UserAssist.

---

## 8. Uncertainties

- Exact command lines for `gpg.exe` are not in prefetch (only the loaded files). Console history is the shell seat.
- AESCrypt32.exe was never prefetched; treating context-menu encryption as fact is an inference from (a) association + ContextMenuHandlers\AESCrypt, (b) absence of aescrypt.exe process artifacts, (c) USN timing of README.txt.aes vs Explorer activity.
- BitLockerWizardElev UserAssist run_count=0: elevated COM launch, BAM/prefetch are the better clocks.
- Prefetch volume serial in strings is `B009E7A9` matching fsstat `BAB00A24B009E7A9` (low 32 bits).
- SID `…-1001` exists in BAM only for CloudExperienceHost on 2023-02-20; no profile, not Jane.

Raw JSON: `work/s864a03/prefetch.json`, `bam.json`, `userassist.json`, `shimcache.json`, `amcache.json`, `amcache_hits.json`, `uninstall.json`, `lnks.json`, `jumplists.json`.

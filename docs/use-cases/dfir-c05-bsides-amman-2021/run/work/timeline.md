# Timeline — ALIHADI-C5 (BSides Amman 2021 Windows Forensics Workshop)

Merged timeline for the confidential-file access and DCode.exe activity, built from `ledger/ledger.md` (events recorded by the swarm). All times are UTC (ISO 8601). NTFS/MFT timestamps were read with `istat -o 0 inputs/BSidesAmman21.E01 <inode>`; the image stores local time at UTC+3 (Amman), converted to UTC here. `.lnk`/registry/EVTX times are FILETIME, already UTC.

**Key identifiers**
- NTFS volume serial ($Volume, `fsstat`): `EE68D66268D628DB`
- Windows volume serial (from `.lnk` `Drive Serial Number`): `68D6-28DB`
- Suspect accounts: `joker` (SID `...-1004`) and `IEUser` (SID `...-1000`).
- Confidential share: `\\192.168.70.128\SharedJJ\docs`

## Timeline

| # | Time (UTC) | Event | Source / evidence |
| --- | --- | --- | --- |
| 1 | 2018-03-06 16:33:54 | whoami4.png original "Modified" timestamp (later preserved when copied into IEUser Pictures on 2019-02-15) | `istat` inode 98748; `File Modified 2018-03-06 19:33:54 (+03)` |
| 2 | 2018-04-25 20:00:38 | Local account `IEUser` created | Security.evtx record 190 (event 4720); work/extracted/s2f6601/Security.evtx |
| 3 | 2018-04-25 20:06:32 | Local account `sshd` created (by IEUser) | Security.evtx record 762 |
| 4 | 2018-04-25 20:06:37 | Local account `sshd_server` created (by IEUser) | Security.evtx record 779 |
| 5 | 2018-04-25 20:06:37 | `sshd_server` (SID ...-1003) added to Administrators | Security.evtx record 787 |
| 6 | 2019-02-15 04:32:14 | IEUser `Downloads\putty.exe` touched | catalog timeline.csv |
| 7 | 2019-02-15 04:35:05 | PuTTY prefetch created (PuTTY execution) | catalog timeline.csv; Windows/Prefetch/PUTTY*.pf |
| 8 | 2019-02-15 04:52:21 | `SYNC64.EXE` prefetch updated (sync64.exe on IEUser Desktop) | catalog timeline.csv; SYNC64.EXE-3630E8A8.pf |
| 9 | 2019-02-15 04:53:33 | IEUser creates local account `Joker` (4720) | Security.evtx record 1984 |
| 10 | 2019-02-15 04:54:09 | `Joker` logs on interactively (logon type 2) from MSEDGEWIN10 | Security.evtx record 2029 (4624) |
| 11 | 2019-02-15 04:54:09 | Joker Recent folder created | `istat` inode 96020 ($FILE_NAME) |
| 12 | 2019-02-15 04:59:22 | DCode.exe created (born) at C:\Users\Joker\DCode.exe | `istat` inode 97020; Created 07:59:22.463220300 (+03) |
| 13 | 2019-02-15 04:59:23 | DCode.exe modified | `istat` inode 97020 |
| 14 | 2019-02-15 04:59:34 | putty.exe created (born) at C:\Users\Joker\putty.exe | `istat` inode 97023 |
| 15 | 2019-02-15 04:59:52 | dd.exe created (born) at C:\Users\Joker\dd.exe (byte-identical to DCode.exe) | `istat` inode 97026; MD5 b534d93d94f86a052f398a44928247d9 |
| 16 | 2019-02-15 04:59:53 | dd.exe modified | `istat` inode 97026 |
| 17 | 2019-02-15 05:00:21 | haha.png created at C:\Users\Joker\haha.png (image text "AnotherPassword4U") | `istat` inode 97027; tesseract OCR |
| 18 | 2019-02-15 05:00:22 | haha.png accessed | `istat` inode 97027 |
| 19 | 2019-02-15 05:00:49 | Confidential.rtf created at C:\Users\Joker\Confidential.rtf (439 bytes) | `istat` inode 97031 |
| 20 | 2019-02-15 05:01:40 | DCode.exe last accessed | `istat` inode 97020 |
| 21 | 2019-02-15 05:01:53 | haha.lnk created in Joker Recent → C:\Users\Joker\haha.png | timeline.csv; exiftool haha.lnk |
| 22 | 2019-02-15 05:02:13 | dd.exe (renamed DCode.exe) executed — DD.EXE prefetch run_count=1, last_run 05:02:13.353878Z; Joker UserAssist `C:\Users\Joker\dd.exe` run_counter=1 @05:02:12.791Z; DCode Settings key last write 05:02:13.494Z | mam_pf_parse on DD.EXE-0C303FDD.pf; Joker NTUSER.DAT UserAssist + Software\VB and VBA Program Settings\DCode\Settings |
| 23 | 2019-02-15 05:02:17 | DD.EXE-0C303FDD.pf prefetch file written (MFT Created/Modified) | `istat` inode 96361; Created 08:02:17.713149700 (+03) |
| 24 | 2019-02-15 05:02:22 | putty.exe accessed (Joker UserAssist run_count 1, last exec) | `istat` inode 97023; Joker NTUSER.DAT UserAssist |
| 25 | 2019-02-15 05:02:56 | Confidential.lnk created → \\192.168.70.128\SharedJJ\docs\Confidential.rtf | `istat` inode 96881; strings |
| 26 | 2019-02-15 05:02:57 | Confidential.rtf accessed (local copy) | `istat` inode 97031 |
| 27 | 2019-02-15 05:03:06 | Wordpad.lnk pinned to Taskbar | timeline.csv inode 97043 |
| 28 | 2019-02-15 05:03:25 | Confidential.lnk modified (re-opened) | `istat` inode 96881 |
| 29 | 2019-02-15 05:03:34 | Confidential_02.lnk created → Confidential_02.docx | `istat` inode 96884 |
| 30 | 2019-02-15 05:03:39 | Confidential_03.lnk created → Confidential_03.docx | `istat` inode 96885 |
| 31 | 2019-02-15 05:03:45 | Confidential_04.lnk created → Confidential_04.docx | `istat` inode 96886 |
| 32 | 2019-02-15 05:03:45 | wordpad.exe last executed (Joker UserAssist run_count 5) | Joker NTUSER.DAT UserAssist |
| 33 | 2019-02-15 05:03:52 | mandiant-apt1-report.lnk created → mandiant-apt1-report.pdf | timeline.csv; strings |
| 34 | 2019-02-15 05:04:00 | TheMeaningofLIFE.lnk created → TheMeaningofLIFE.pdf | timeline.csv; strings |
| 35 | 2019-02-15 05:04:10 | The-ProjectSauron.lnk created → The-ProjectSauron.pdf | timeline.csv; strings |
| 36 | 2019-02-15 05:05:06 | \\192.168.70.128\SharedJJ\tools\putty.exe executed (Joker UserAssist run_count 2) | Joker NTUSER.DAT UserAssist |
| 37 | 2019-02-15 05:06:52 | whoami4.png created at C:\Users\IEUser\Pictures\pics\whoami4.png (identical to haha.png) | `istat` inode 98748 |
| 38 | 2019-02-15 05:06:53 | whoami4.png accessed | `istat` inode 98748 |
| 39 | 2019-02-15 05:07:07 | whoami4.png.lnk created in IEUser Recent → C:\Users\IEUser\Pictures\pics\whoami4.png | `istat` inode 95047; exiftool |
| 40 | 2019-02-15 05:34:16 | Joker NTUSER.DAT WordPad Recent File List updated with \\...\Confidential.rtf and C:\Users\Joker\Confidential.rtf | Joker-NTUSER.DAT |

## Notes / interpretations

- **Confidential-file access**: the four Recent `.lnk` files under `C:\Users\Joker\AppData\Roaming\Microsoft\Windows\Recent\` (rows 25, 29, 30, 31) resolve to `\\192.168.70.128\SharedJJ\docs\Confidential.rtf`, `Confidential_02.docx`, `Confidential_03.docx`, `Confidential_04.docx`. Their `Net Name` is `\\192.168.70.128\SHAREDJJ` and `Working Directory` is `\\192.168.70.128\SharedJJ\docs` — a network (SMB) location, not a local drive.
- **Attribution to joker**: those `.lnk` files live in Joker's profile; Joker logged on at 04:54:09 UTC (row 10) and the profile's Recent folder was created at 04:54:09 (row 11). WordPad (row 32) and the WordPad recent-file list (row 40) tie the app to Joker.
- **DCode.exe / dd.exe (the "tricky" question)**: `C:\Users\Joker\DCode.exe` and `C:\Users\Joker\dd.exe` are byte-identical (MD5 `b534d93d94f86a052f398a44928247d9`). Only `Windows\Prefetch\DD.EXE-0C303FDD.pf` exists (no DCODE.EXE prefetch), so the tool was executed under the name `dd.exe`. Definitive run data: prefetch `run_count = 1`, `last_run 2019-02-15T05:02:13.353878Z`; Joker UserAssist `C:\Users\Joker\dd.exe` `run_counter = 1` @ `05:02:12.791Z`; Joker NTUSER.DAT DCode Settings key last write `05:02:13.494Z`; Amcache `c:\users\joker\dd.exe` (ProductName `dcode`, Publisher `digital detective group ltd`, Version `4.02.9306`). Conclusion: **Joker ran DCode once, as `dd.exe`, at ~05:02:13 UTC; the original file is `C:\Users\Joker\DCode.exe`**.
- **"AnotherPassword4U" image**: two byte-identical copies exist — `C:\Users\Joker\haha.png` (inode 97027) and `C:\Users\IEUser\Pictures\pics\whoami4.png` (inode 98748), both MD5 `16c9f7a14da9b3cfe5807111b032b893`. `haha.png` is directly in Joker's home-directory root; `whoami4.png` sits in IEUser's Pictures\pics. Both are on the single NTFS volume (serial `68D6-28DB`).

*Timeline author: s2f6604 (timeline/ledger seat). Events are sourced from the swarm ledger (`ledger/ledger.md`); every row is backed by a recorded event with command-level evidence.*

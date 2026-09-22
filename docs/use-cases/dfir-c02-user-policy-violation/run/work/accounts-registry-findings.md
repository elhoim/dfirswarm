# Accounts, registry, and event-log findings

Agent: `s0ae901`
Seat: Accounts and event logs

## Sources and extraction

I worked from the catalog plus extracted copies of the relevant NTFS files.

### Catalog locations

- `catalog/4orensics.001/p0/filelist.txt` shows:
  - `Windows/System32/config/SAM` at inode `44229-128-3`
  - `Windows/System32/config/SECURITY` at inode `44232-128-3`
  - `Windows/System32/config/SOFTWARE` at inode `45570-128-3`
  - `Windows/System32/config/SYSTEM` at inode `44235-128-3`
  - `Users/Hunter/NTUSER.DAT` at inode `81365-128-1`
  - `Users/Hunter/AppData/Local/Microsoft/Windows/UsrClass.dat` at inode `4016-128-3`
  - `Windows/System32/winevt/Logs/Security.evtx` at inode `81033-128-4`
  - `Windows/System32/winevt/Logs/System.evtx` at inode `81029-128-4`

### Extraction commands

Extracted under `work/s0ae901/extracted/` with:

```bash
icat -o 0 inputs/4orensics.001 44229 > work/s0ae901/extracted/SAM
icat -o 0 inputs/4orensics.001 44232 > work/s0ae901/extracted/SECURITY
icat -o 0 inputs/4orensics.001 45570 > work/s0ae901/extracted/SOFTWARE
icat -o 0 inputs/4orensics.001 44235 > work/s0ae901/extracted/SYSTEM
icat -o 0 inputs/4orensics.001 81365 > work/s0ae901/extracted/Hunter-NTUSER.DAT
icat -o 0 inputs/4orensics.001 4016 > work/s0ae901/extracted/Hunter-UsrClass.dat
icat -o 0 inputs/4orensics.001 81033 > work/s0ae901/extracted/Security.evtx
icat -o 0 inputs/4orensics.001 81029 > work/s0ae901/extracted/System.evtx
```

### Extract hashes

- `SAM` `d77ecd017568c8e005c5164f1b0fb64d5c543a2aacd1f7b85ff4521d859c8b7d`
- `SECURITY` `e817e0a764fb5ff8eea7066ee91dd1a1aadaacf98df9611c343875c7f545af43`
- `SOFTWARE` `e9beb711f1587df123001ab908aad931321a32da78437dc2e74419d5612321e2`
- `SYSTEM` `e75b343a867329fcc05abf8c87d7f8a3c77b736d03bd46625aa1ab095383be7d`
- `Hunter-NTUSER.DAT` `30818df0a514c535c7d7d2b80fb3f5cedcf8e364d2c14db57d2e7bc138de8ccf`
- `Hunter-UsrClass.dat` `97e9053be59a700964b9b5cd6f01a203fdb009572c441bb5266e1e2939a496c6`
- `Security.evtx` `4b0ebeb6ec195b9500963bcafe60fe62efdc097616f08f3f0b954078e1305168`
- `System.evtx` `9ca8094b3434674cfafc43095cb4347e9bdc1e241c6cf726b33cfbb3bcd61734`

## 1) System and host profile facts from registry/event logs

### Windows version and install

From `work/s0ae901/extracted/SOFTWARE`, key `Microsoft\Windows NT\CurrentVersion` parsed with Python `regipy`:

- Product name: `Windows 8.1 Enterprise`
- Edition: `Enterprise`
- Build: `9600.17031.amd64fre.winblue_gdr.140221-1952`
- Registered owner: `Hunter`
- InstallDate epoch: `1466498265` = `2016-06-21T08:37:45Z`

Evidence: Python `regipy` walk over `work/s0ae901/extracted/SOFTWARE`.

### Computer name history

Current registry state from `work/s0ae901/extracted/SYSTEM`:

- `ControlSet001\Control\ComputerName\ComputerName\ComputerName` = `4ORENSICS`
- `ControlSet001\Services\Tcpip\Parameters\Hostname` = `4orensics`
- `ControlSet001\Services\Tcpip\Parameters\NV Hostname` = `4orensics`

System log computer-name changes:

| UTC time | EventRecordID | Event | Evidence |
| --- | ---: | --- | --- |
| 2016-06-21T08:15:09Z | 1 | `WIN-A9KKHBKS7E6` -> `WIN-0Q61PC073B6` | `System.evtx` EventID `6011` |
| 2016-06-21T08:29:49Z | 55 | `WIN-0Q61PC073B6` -> `4orensics` | `System.evtx` EventID `6011` |
| 2016-06-20T23:48:21Z | 187 | `4orensics` -> `4ORENSICS` | `System.evtx` EventID `6011` |

Interpretation: the current computer name is `4ORENSICS`/`4orensics` (case differs by artifact), and the host was renamed at least twice during setup/use.

### Time zone

From `SYSTEM`, `ControlSet001\Control\TimeZoneInformation`:

- `TimeZoneKeyName` = `Pacific Standard Time`
- `Bias` = `480`
- `ActiveTimeBias` = `420`

Evidence: `work/s0ae901/extracted/SYSTEM` via `regipy` `TimezoneDataPlugin`.

### Network configuration

From `SYSTEM`, `ControlSet001\Services\Tcpip\Parameters` and `...\Interfaces`:

- Hostname: `4orensics`
- DHCP name server: `10.0.2.3`
- Active DHCP interface GUID: `{8CB9FBF6-AE23-4E1C-AA0A-EE23CB4FE736}`
- DHCP IPv4 address: `10.0.2.15`
- Default gateway: `10.0.2.2`
- DHCP server: `10.0.2.2`
- Subnet mask: `255.255.255.0`
- Lease obtained: `2016-06-21 02:24:12`
- Lease expires: `2016-06-22 02:24:12`

Evidence: `work/s0ae901/extracted/SYSTEM` via `regipy` `NetworkDataPlugin`.

## 2) Local accounts and SIDs

Machine SID from `work/s0ae901/extracted/SAM` via `regipy` `LocalSidPlugin`:

- `S-1-5-21-2489440558-2754304563-710705792`

Observed local user accounts:

| Username | RID | Full SID | Status / notes | Last logon | Supporting evidence |
| --- | ---: | --- | --- | --- | --- |
| Administrator | 500 | `S-1-5-21-2489440558-2754304563-710705792-500` | Disabled; password does not expire | `2014-03-18T10:20:36.460482Z` | `SAM` user record `000001F4`; Security EventID `4738` record `104` |
| Guest | 501 | `S-1-5-21-2489440558-2754304563-710705792-501` | Disabled; password not required | none seen | `SAM` user record `000001F5`; Security EventID `4738` record `106` |
| Hunter | 1001 | `S-1-5-21-2489440558-2754304563-710705792-1001` | Normal account; password does not expire; profile at `C:\Users\Hunter` | `2016-06-21T01:42:40.527426Z` in SAM; interactive logons also at `2016-06-21T08:37:45.837187Z` and `2016-06-20T23:49:02.366972Z` | `SAM` user record `000003E9`; `SOFTWARE` ProfileList; Security EventIDs `4720`, `4624`, `4672` |
| HomeGroupUser$ | 1003 | `S-1-5-21-2489440558-2754304563-710705792-1003` | Created automatically for HomeGroup-related use; no interactive logon seen | none seen | `SAM` user record `000003EB`; Security EventID `4720` record `204` |

### Creation / enablement events recovered directly from Security.evtx

| UTC time | EventRecordID | Event |
| --- | ---: | --- |
| 2016-06-21T08:37:43.024549Z | 139 | Account `Hunter` created (EventID `4720`) |
| 2016-06-21T08:37:43.055845Z | 141 | Account `Hunter` enabled (EventID `4722`) |
| 2016-06-21T08:40:06.009029Z | 204 | Account `HomeGroupUser$` created (EventID `4720`) |
| 2016-06-21T08:40:06.009029Z | 205 | Account `HomeGroupUser$` enabled (EventID `4722`) |

Note: built-in `Administrator` and `Guest` pre-date these 2016 account-creation events. Their exact original creation timestamp is not explicitly logged in the recovered Security log.

## 3) Group membership changes and privilege elevation

Hunter was granted elevated local-group membership immediately after creation.

| UTC time | EventRecordID | Event | Evidence |
| --- | ---: | --- | --- |
| 2016-06-21T08:37:43.024549Z | 138 | `Hunter` SID added to local group RID 513 / Domain Users-equivalent (`4728`) | `Security.evtx` |
| 2016-06-21T08:37:43.040236Z | 140 | `Hunter` added to built-in `Users` (`4732`) | `Security.evtx` |
| 2016-06-21T08:37:43.102896Z | 148 | `Hunter` added to built-in `Administrators` (`4732`) | `Security.evtx` |
| 2016-06-21T08:37:43.118591Z | 149 | `Hunter` removed from built-in `Users` (`4733`) | `Security.evtx` |

This sequence shows `Hunter` was not just created; it was made an administrator within the same minute.

## 4) Interactive logons and special-privilege logons

Filtering `work/s0ae901/extracted/Security.evtx` for EventIDs `4624` and `4672` shows only one human account with interactive logons: `Hunter`.

| UTC time | EventRecordIDs | User | Logon type | Workstation | Source IP | Notes |
| --- | --- | --- | ---: | --- | --- | --- |
| 2016-06-21T08:37:45.837187Z | 151-153 | Hunter | 2 | `WIN-0Q61PC073B6` | `127.0.0.1` | interactive local logon, followed by special privileges (`4672`) |
| 2016-06-20T23:49:02.366972Z | 606-608 | Hunter | 2 | `4ORENSICS` | `127.0.0.1` | interactive local logon, followed by special privileges (`4672`) |
| 2016-06-21T01:42:40.527426Z | 757-759 | Hunter | 2 | `4ORENSICS` | `127.0.0.1` | interactive local logon, followed by special privileges (`4672`) |

## 5) Time-change artifacts that affect chronology

Two Security EventID `4616` records show the system clock being moved backward by `VBoxService.exe`:

| UTC time of event | EventRecordID | Previous time | New time | Process |
| --- | ---: | --- | --- | --- |
| 2016-06-20T23:48:21.775408Z | 583 | 2016-06-21 09:48:20.285841+00:00 | 2016-06-20 23:48:21.778000+00:00 | `C:\Windows\System32\VBoxService.exe` |
| 2016-06-21T01:41:06.325617Z | 732 | 2016-06-21 11:41:04.654060+00:00 | 2016-06-21 01:41:06.327000+00:00 | `C:\Windows\System32\VBoxService.exe` |

Implication: event chronology around the late-night sessions must be interpreted carefully because VirtualBox guest time synchronization moved the clock backward by roughly ten hours twice.

## 6) Service-install events from System.evtx relevant to follow-up seats

EventID `7045` service-install records worth correlating with software/persistence findings:

| UTC time | EventRecordID | Service | ImagePath |
| --- | ---: | --- | --- |
| 2016-06-21T00:57:41.298183Z | 245 | TeamViewer 11 | `"C:\Program Files (x86)\TeamViewer\TeamViewer_Service.exe"` |
| 2016-06-21T08:41:43.008968Z | 132 | Google Update Service (gupdate) | `"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /svc` |
| 2016-06-21T08:41:43.040361Z | 133 | Google Update Service (gupdatem) | `"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /medsvc` |
| 2016-06-21T08:59:08.413120Z | 137 | Skype Updater | `"C:\Program Files (x86)\Skype\Updater\Updater.exe"` |
| 2016-06-21T09:23:01.815443Z | 151 | NetGroup Packet Filter Driver | `system32\drivers\npf.sys` |
| 2016-06-21T09:23:01.922335Z | 152 | Remote Packet Capture Protocol v.0 (experimental) | `"%ProgramFiles(x86)%\WinPcap\rpcapd.exe" -d -f "%ProgramFiles(x86)%\WinPcap\rpcapd.ini"` |
| 2016-06-21T09:23:09.682587Z | 153 | USBPcap Capture Service | `\SystemRoot\system32\DRIVERS\USBPcap.sys` |

## 7) Hunter NTUSER.DAT user-activity leads

`work/s0ae901/extracted/Hunter-NTUSER.DAT` parsed with `regipy` `UserAssistPlugin` shows execution evidence for the following items:

| Approx. last execution UTC | Artifact name | Notes |
| --- | --- | --- |
| 2016-06-21T11:55:37.314Z | `C:\Users\Hunter\Desktop\putty.exe - Shortcut.lnk` | SSH/Telnet client shortcut launched |
| 2016-06-21T12:00:43.238Z | `C:\Users\Public\Desktop\TeamViewer 11.lnk` | TeamViewer launched |
| 2016-06-21T12:08:13.796Z | `C:\Users\Hunter\Desktop\Nmap - Zenmap GUI.lnk` | Nmap/Zenmap launched |
| 2016-06-21T12:28:08.045Z | `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\CCleaner\CCleaner.lnk` | CCleaner launched |
| 2016-06-21T12:26:17.399Z | `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Python 2.7\IDLE (Python GUI).lnk` | Python IDLE launched |
| 2016-06-21T12:26:30.279Z | `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Microsoft Office 2013\Word 2013.lnk` | Word launched |
| 2016-06-21T08:41:33.946Z | `C:\Users\Hunter\Downloads\ChromeSetup.exe` | Chrome installer launched |
| timestamp not preserved, focus time present | `C:\Users\Hunter\Downloads\SkypeSetup.exe` | Skype installer/use evidence present in UserAssist |

These are leads for the software, browser, leftovers, and communications seats. They establish user-level interaction under the `Hunter` profile with remote-access, scanning, and cleanup tooling.

## 8) Items already pushed to the ledger

I recorded the major dated events and findings in `ledger/ledger.md`, including:

- boot/build event
- computer-name changes
- `Hunter` creation, enablement, admin-group addition, and interactive logon
- `HomeGroupUser$` creation
- backward time changes by `VBoxService.exe`
- TeamViewer service installation
- finding that `Hunter` is the only human account seen in interactive Security 4624 logons
- finding that Hunter UserAssist shows TeamViewer/putty/Nmap/CCleaner/Python/Word/Chrome/Skype activity

## Bottom line for the editor

High-confidence facts from this seat:

1. Current system is Windows 8.1 Enterprise, computer name `4ORENSICS` / `4orensics`, Pacific time zone.
2. `Hunter` (`...-1001`) is the only human account observed logging on interactively.
3. `Hunter` was created on `2016-06-21T08:37:43Z` and added to `Administrators` seconds later.
4. `Hunter`'s NTUSER.DAT shows launches of TeamViewer, PuTTY, Zenmap/Nmap, CCleaner, Python IDLE, Word, Chrome installer, and Skype installer/use artifacts.
5. The system clock was moved backward twice by `VBoxService.exe`, so late-session ordering needs care.
6. System EventID `7045` shows TeamViewer service installation at `2016-06-21T00:57:41Z`.

# Disk triage (s881000)

## Scope

Assigned seat: filesystem/partition triage, browser-related path survey from the catalog, attack-window file additions/changes, and a bonus list of attacker-added paths with inode proof.

Primary evidence used:

- `catalog/Browser_Policy_Violation.E01/partitions.txt`
- `catalog/Browser_Policy_Violation.E01/p0/fsstat.txt`
- `catalog/Browser_Policy_Violation.E01/p0/filelist.txt`
- `catalog/Browser_Policy_Violation.E01/p0/timeline.csv`
- `ledger/ledger.md`

Useful commands:

- `grep -n 'ChromeStandaloneSetup64.exe' catalog/Browser_Policy_Violation.E01/p0/filelist.txt`
- `grep 'ChromeStandaloneSetup64.exe' catalog/Browser_Policy_Violation.E01/p0/timeline.csv`
- `grep 'Program Files (x86)/Google/Chrome/Application/chrome.exe' catalog/Browser_Policy_Violation.E01/p0/timeline.csv`
- `grep 'Windows/Prefetch/CHROMESTANDALONESETUP64.EXE-CCB628B7.pf' catalog/Browser_Policy_Violation.E01/p0/timeline.csv`
- `grep 'Windows/Prefetch/CHROME_INSTALLER.EXE-ADE9350B.pf' catalog/Browser_Policy_Violation.E01/p0/timeline.csv`
- `grep 'Google Chrome.lnk' catalog/Browser_Policy_Violation.E01/p0/timeline.csv`

## Volume and filesystem

- `partitions.txt`: no partition table; the E01 is a single NTFS volume starting at sector 0.
- `fsstat.txt`: NTFS volume, sector size 512, cluster size 4096, root directory inode 5.

This means timeline and file-path citations can be taken directly from the catalog without applying a partition offset.

## Browser-related paths present on disk

### Native / expected Windows browsers

- Internet Explorer executables:
  - `Program Files/internet explorer/iexplore.exe` (inode `21176-128-4`)
  - `Program Files (x86)/Internet Explorer/iexplore.exe` (inode `28944-128-4`)
- Microsoft Edge application/package paths exist throughout the default Windows 10 install, including:
  - `Windows/SystemApps/Microsoft.MicrosoftEdge_8wekyb3d8bbwe/MicrosoftEdge.exe` (inode `53315-128-5`)
  - `Users/IEUser/AppData/Local/Microsoft/WindowsApps/MicrosoftEdge.exe` (inode `87859-128-1`)

### Non-native browser with clear user activity

Google Chrome is present both as an installed program and as a populated user profile for `IEUser`:

- Installed executable: `Program Files (x86)/Google/Chrome/Application/chrome.exe` (inode `96514-128-1`)
- Installer cache: `Program Files (x86)/Google/Update/Download/{8A69D345-D564-463C-AFF1-A69D9E530F96}/70.0.3538.110/chrome_installer.exe` (inode `96394-128-1`)
- User profile root: `Users/IEUser/AppData/Local/Google/Chrome/User Data` (inode `96406-144-6`)
- Immediate usage artifacts:
  - `.../Default/History` (inode `96138-128-3`)
  - `.../Default/Preferences` (inode `96058-128-4`)
  - `.../Default/Cookies` (inode `96795-128-3`)
- Installation shortcuts created at install time:
  - `Users/Public/Desktop/Google Chrome.lnk` (inode `96519-128-4`)
  - `Users/IEUser/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Google Chrome.lnk` (inode `96520-128-4`)
  - `ProgramData/Microsoft/Windows/Start Menu/Programs/Google Chrome.lnk` (inode `96521-128-4`)

### Negative search results for other non-native browsers

Targeted searches of `filelist.txt` found no standard install/profile paths for Firefox, Opera, Brave, Tor Browser, or Chromium under `Program Files` or user `AppData`.

## Filesystem attack window

From the disk timeline alone, the browser-policy-violation window is centered on **2018-11-25 16:11:24Z through at least 2018-11-25 18:37:40Z**:

- by `16:11:24Z`, `ChromeStandaloneSetup64.exe` is already on disk in IEUser's VMware drag-and-drop temp area;
- at `16:30:40Z`, Windows creates `CHROMESTANDALONESETUP64.EXE` prefetch, showing execution;
- from `16:30:48Z` to `16:31:13Z`, Chrome install/program/profile paths are created and populated;
- Chrome profile files continue changing until at least `18:37:40Z`.

The `mtime` on `chrome.exe` is `2018-11-16T05:43:04Z`, but its `ctime`/`birth-related` timeline entries are on `2018-11-25T16:31:01Z`. That older `mtime` is consistent with a file timestamp carried by the packaged binary, not proof of an earlier local install.

## Key attack-window additions and changes

| Time (UTC) | Inode | Path | Why it matters |
| --- | --- | --- | --- |
| 2018-11-25T16:11:24Z | `95950-128-4` | `Users/IEUser/AppData/Local/Temp/vmware-IEUser/VMwareDnD/941faa9f/ChromeStandaloneSetup64.exe` | Chrome installer present in VMware drag-and-drop temp area for IEUser. |
| 2018-11-25T16:30:32Z | `95947-144-1` | `Users/IEUser/AppData/Local/Temp/vmware-IEUser/VMwareDnD` | Drag-and-drop staging directory active in the same window. |
| 2018-11-25T16:30:32Z | `95949-144-1` | `Users/IEUser/AppData/Local/Temp/vmware-IEUser/VMwareDnD/941faa9f` | Subdirectory holding the dragged installer. |
| 2018-11-25T16:30:40Z | `96135-128-4` | `Windows/Prefetch/CHROMESTANDALONESETUP64.EXE-CCB628B7.pf` | Installer execution evidence. |
| 2018-11-25T16:30:48Z | `96303-144-1` | `Program Files (x86)/Google` | Google program tree created during install. |
| 2018-11-25T16:30:48Z | `96305-144-5` | `Program Files (x86)/Google/Update` | Chrome update/install framework created. |
| 2018-11-25T16:30:48Z | `96394-128-1` | `Program Files (x86)/Google/Update/Download/{8A69D345-D564-463C-AFF1-A69D9E530F96}/70.0.3538.110/chrome_installer.exe` | Installer payload written to disk. |
| 2018-11-25T16:31:01Z | `96402-144-1` | `Program Files (x86)/Google/Chrome` | Chrome application directory created. |
| 2018-11-25T16:31:01Z | `96512-144-6` | `Program Files (x86)/Google/Chrome/Application` | Chrome application directory active. |
| 2018-11-25T16:31:01Z | `96514-128-1` | `Program Files (x86)/Google/Chrome/Application/chrome.exe` | Installed browser executable. |
| 2018-11-25T16:31:01Z | `96519-128-4` | `Users/Public/Desktop/Google Chrome.lnk` | Desktop shortcut created by installation. |
| 2018-11-25T16:31:01Z | `96520-128-4` | `Users/IEUser/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Google Chrome.lnk` | User-specific shortcut ties install to IEUser profile. |
| 2018-11-25T16:31:01Z | `96521-128-4` | `ProgramData/Microsoft/Windows/Start Menu/Programs/Google Chrome.lnk` | Start-menu shortcut created by installation. |
| 2018-11-25T16:31:02Z | `96223-144-1` | `Users/IEUser/AppData/Local/Google` | User Google profile root created. |
| 2018-11-25T16:31:02Z | `96404-144-1` | `Users/IEUser/AppData/Local/Google/Chrome` | User Chrome profile tree created. |
| 2018-11-25T16:31:02Z | `96406-144-6` | `Users/IEUser/AppData/Local/Google/Chrome/User Data` | User Data tree created. |
| 2018-11-25T16:31:02Z | `95959-128-4` | `Windows/Prefetch/CHROME_INSTALLER.EXE-ADE9350B.pf` | Secondary installer execution evidence. |
| 2018-11-25T16:31:03Z | `96058-128-4` | `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Preferences` | Chrome profile configured immediately after install. |
| 2018-11-25T16:31:03Z | `96138-128-3` | `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/History` | Browsing history database created immediately after install. |
| 2018-11-25T16:31:08Z | `96795-128-3` | `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Cookies` | Cookie store created during first-use window. |
| 2018-11-25T18:34:35Z | `96795-128-3` | `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Cookies` | Cookie store still changing hours later. |
| 2018-11-25T18:37:40Z | `96058-128-4` | `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Preferences` | Chrome profile still active. |
| 2018-11-25T18:37:40Z | `96138-128-3` | `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/History` | Chrome history still active. |

## Bonus: attacker-added paths with inode proof

These are the clearest attacker-added / user-added paths related to the non-native browser installation, each with inode proof from the catalog:

- `95950-128-4` — `Users/IEUser/AppData/Local/Temp/vmware-IEUser/VMwareDnD/941faa9f/ChromeStandaloneSetup64.exe`
- `96135-128-4` — `Windows/Prefetch/CHROMESTANDALONESETUP64.EXE-CCB628B7.pf`
- `95959-128-4` — `Windows/Prefetch/CHROME_INSTALLER.EXE-ADE9350B.pf`
- `96303-144-1` — `Program Files (x86)/Google`
- `96305-144-5` — `Program Files (x86)/Google/Update`
- `96394-128-1` — `Program Files (x86)/Google/Update/Download/{8A69D345-D564-463C-AFF1-A69D9E530F96}/70.0.3538.110/chrome_installer.exe`
- `96402-144-1` — `Program Files (x86)/Google/Chrome`
- `96512-144-6` — `Program Files (x86)/Google/Chrome/Application`
- `96514-128-1` — `Program Files (x86)/Google/Chrome/Application/chrome.exe`
- `96519-128-4` — `Users/Public/Desktop/Google Chrome.lnk`
- `96520-128-4` — `Users/IEUser/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Google Chrome.lnk`
- `96521-128-4` — `ProgramData/Microsoft/Windows/Start Menu/Programs/Google Chrome.lnk`
- `96223-144-1` — `Users/IEUser/AppData/Local/Google`
- `96404-144-1` — `Users/IEUser/AppData/Local/Google/Chrome`
- `96406-144-6` — `Users/IEUser/AppData/Local/Google/Chrome/User Data`
- `96138-128-3` — `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/History`
- `96058-128-4` — `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Preferences`
- `96795-128-3` — `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Cookies`

## Interim conclusion

Filesystem evidence strongly supports this sequence:

1. A Chrome standalone installer was introduced into the VM through VMware drag-and-drop into IEUser's temp area.
2. The installer executed.
3. Chrome was installed under `Program Files (x86)/Google/Chrome`.
4. User-profile artifacts were created immediately under `Users/IEUser/AppData/Local/Google/Chrome/User Data`.
5. Those profile artifacts continued changing until at least `2018-11-25T18:37:40Z`.

This is high-confidence disk evidence that Chrome was the non-native browser added and used on the system, and that `IEUser` is the user profile directly associated with that activity.

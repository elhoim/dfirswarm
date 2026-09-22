# Leftovers and malware findings — s881003

## Scope

This pass covered leftover artifacts relevant to the policy-violating browser: temp/profile directories, prefetch, scheduled tasks, user shortcuts, and a quick check for web roots/startup persistence.

## Key findings

### 1. Chrome arrived through IEUser's VMware drag-and-drop temp area

The clearest arrival artifact is an offline Chrome installer under IEUser's temp directory used by VMware drag-and-drop:

- `Users/IEUser/AppData/Local/Temp/vmware-IEUser/VMwareDnD/941faa9f/ChromeStandaloneSetup64.exe` (`inode 95950-128-4`)
- Timeline rows show it present at `2018-11-25T16:11:24Z`, with later metadata updates at `2018-11-25T16:30:32Z` and `2018-11-25T16:30:34Z`.
- This supports delivery into the logged-in `IEUser` session via VMware drag-and-drop rather than a normal package-management path.

Extracted copy and hash:

| Artifact | Source inode/path | SHA-256 |
| --- | --- | --- |
| `work/extracted/ChromeStandaloneSetup64.exe` | `95950-128-4` `/Users/IEUser/AppData/Local/Temp/vmware-IEUser/VMwareDnD/941faa9f/ChromeStandaloneSetup64.exe` | `2893d2277214993ac2a1c8cfbe4e330de318f36db42f2f5139c8ad8ea900a27b` |

Evidence: `catalog/Browser_Policy_Violation.E01/p0/timeline.csv`; extraction with `icat -o 0 inputs/Browser_Policy_Violation.E01 95950 > work/extracted/ChromeStandaloneSetup64.exe`.

### 2. The installer was executed and quickly led to a Chrome installation

Prefetch shows the offline installer executed:

- `Windows/Prefetch/CHROMESTANDALONESETUP64.EXE-CCB628B7.pf` (`inode 96135-128-4`) at `2018-11-25T16:30:40Z`
- `Windows/Prefetch/GOOGLEUPDATESETUP.EXE-98123BD4.pf` (`inode 96248-128-4`) at `2018-11-25T16:30:48Z`
- `Users/IEUser/AppData/Local/Temp/CR_F9B6D.tmp/setup.exe` (`inode 96397-128-3`) and `Program Files (x86)/Google/Chrome/Application/70.0.3538.110/Installer/setup.exe` (`inode 96516-128-1`) both appear in the installation window.

Extracted copies and hashes:

| Artifact | Source inode/path | SHA-256 |
| --- | --- | --- |
| `work/extracted/setup.exe` | `96397-128-3` `/Users/IEUser/AppData/Local/Temp/CR_F9B6D.tmp/setup.exe` | `42b6a7e3296899820131cac84d46ea8d2299789927bb04efe2b1a88ab9013bfc` |
| `work/extracted/chrome_installer.log` | `96396-128-4` `/Users/IEUser/AppData/Local/Temp/chrome_installer.log` | `5234a299bf928b0adcf6b75dd457b295ae47a5f6a321ffcb351f37eb7d7bbab0` |

The extracted installer log directly references a system-level Chrome install and shortcut creation:

- `Command Line: "C:\Program Files (x86)\Google\Chrome\Application\70.0.3538.110\Installer\chrmstp.exe" --configure-user-settings --verbose-logging --system-level ...`
- `Creating per-user Desktop "Google Chrome" shortcut ...`
- `Creating per-user Quick Launch "Google Chrome" shortcut ...`
- `Creating per-user Start menu "Google Chrome" shortcut ...`

The first logged configuration run begins at `2018-11-25 08:31:13` local time inside `chrome_installer.log`, which aligns with the UTC filesystem activity around `2018-11-25T16:30:55Z`.

Evidence: `catalog/Browser_Policy_Violation.E01/p0/timeline.csv`; extracted `work/extracted/chrome_installer.log`.

### 3. Chrome installation created Google Update scheduled tasks

Two scheduled task XML files were created under `Windows/System32/Tasks/` at `2018-11-25T16:30:50Z`:

- `GoogleUpdateTaskMachineCore` (`inode 96381-128-4`)
- `GoogleUpdateTaskMachineUA` (`inode 96382-128-4`)

Extracted hashes:

| Artifact | Source inode/path | SHA-256 |
| --- | --- | --- |
| `work/extracted/GoogleUpdateTaskMachineCore.xml` | `96381-128-4` `/Windows/System32/Tasks/GoogleUpdateTaskMachineCore` | `2d6f475124f7b76a151b2ebb2c135fc2602236681c1e9e970154ea63e81c5b61` |
| `work/extracted/GoogleUpdateTaskMachineUA.xml` | `96382-128-4` `/Windows/System32/Tasks/GoogleUpdateTaskMachineUA` | `7e06ded33f2119e4189fa9e820d30acc240e5ea409f89c5248dfba904c1ed2f5` |

The task XML contents show:

- version `1.3.33.17`
- command `C:\Program Files (x86)\Google\Update\GoogleUpdate.exe`
- URIs `\GoogleUpdateTaskMachineCore` and `\GoogleUpdateTaskMachineUA`
- `UserId` `S-1-5-18` with `RunLevel` `HighestAvailable`

This is consistent with a system-level Google Chrome install.

Evidence: `catalog/Browser_Policy_Violation.E01/p0/timeline.csv`; extracted XML under `work/extracted/`.

### 4. Chrome created user-facing shortcuts and was then run

Chrome shortcuts were created at `2018-11-25T16:31:01Z`:

- `Users/Public/Desktop/Google Chrome.lnk` (`inode 96519-128-4`)
- `Users/IEUser/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Google Chrome.lnk` (`inode 96520-128-4`)
- `ProgramData/Microsoft/Windows/Start Menu/Programs/Google Chrome.lnk` (`inode 96521-128-4`)

The extracted `Google Chrome.lnk` from IEUser's Quick Launch resolves to:

- `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`

Hash:

| Artifact | Source inode/path | SHA-256 |
| --- | --- | --- |
| `work/extracted/Google Chrome.lnk` | `96520-128-4` `/Users/IEUser/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Google Chrome.lnk` | `1b74de3e50a09a46c348a0cd4c0bdf5e4617286c6bc3e4a4cb0dc20ef82c5666` |

A Chrome prefetch file then appears:

- `Windows/Prefetch/CHROME.EXE-5349D2DD.pf` (`inode 96802-128-4`) at `2018-11-25T16:31:13Z`

This supports Chrome being executed immediately after installation.

Evidence: `catalog/Browser_Policy_Violation.E01/p0/timeline.csv`; `strings -a 'work/extracted/Google Chrome.lnk'`.

### 5. Chrome profile artifacts exist under IEUser and preserve browsing activity

Chrome profile material exists under:

- `Users/IEUser/AppData/Local/Google/Chrome/User Data/`
- `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/`
- `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Extensions/`
- `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/History` (`inode 96138-128-3`)
- `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Preferences` (`inode 96058-128-4`)
- `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Bookmarks` (`inode 90682-128-4`)

This confirms the browser was not just staged but had a real user profile under `IEUser`.

Extracted hashes:

| Artifact | Source inode/path | SHA-256 |
| --- | --- | --- |
| `work/extracted/chrome_History` | `96138-128-3` `/Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/History` | `6edcfe6483948549427f20c82ffe9f4c514fb3d25ba39c469911cc4f0d3ac474` |
| `work/extracted/chrome_Preferences.json` | `96058-128-4` `/Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Preferences` | `45519a9719e35fc1799e88c7da29d6614df03d522a67a39bf1b3f42de0b9c3fa` |
| `work/extracted/chrome_Bookmarks.json` | `90682-128-4` `/Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Bookmarks` | `a3b34fdf7d62f4e8ce298e3a38592aef87999b97298d5fbb095bdb7bdaea28b6` |

History extracted from the Chrome profile shows that Chrome was used to browse the following sites on 2018-11-25:

| Last visit UTC | URL | Title |
| --- | --- | --- |
| 2018-11-25 17:39:50 | `https://www.worktime.com/` | `Welcome to WorkTime` |
| 2018-11-25 17:39:53 | `https://www.worktime.com:12321/` | `Login to Webmin` |
| 2018-11-25 17:39:55 | `https://www.worktime.com/phpinfo.php` | `phpinfo()` |
| 2018-11-25 18:01:47 | `https://www.worktime.com:12320/` | `Shell In A Box` |
| 2018-11-25 18:01:51 | `https://www.worktime.com:12321/session_login.cgi` | `www.worktime.com` |
| 2018-11-25 18:34:05 | `http://www.worktime.com/server-status` | `Apache Status` |
| 2018-11-25 18:35:54 | `http://192.168.2.129/` | `Drugs 4 all ™ – Don't worry, we are here to support you!` |
| 2018-11-25 18:37:21 | `http://www.drugs4all.com/?page_id=9` | `About – Drugs 4 all ™` |

Preferences also preserve engagement entries for:

- `http://www.worktime.com:80,*`
- `https://www.worktime.com:443,*`
- `https://www.worktime.com:12320,*`
- `https://www.worktime.com:12321,*`
- `http://www.drugs4all.com:80,*`
- `http://192.168.2.129:80,*`

Bookmarks show the user saved Chrome shortcuts/bookmarks to:

- `Welcome to WorkTime` → `http://www.worktime.com/`
- `Login to Webmin` → `https://www.worktime.com:12321/session_login.cgi`
- `Apache Status` → `http://www.worktime.com/server-status`
- `Shell In A Box` → `https://www.worktime.com:12320/`
- `About – Drugs 4 all ™` → `http://www.drugs4all.com/?page_id=9`

Evidence: `catalog/Browser_Policy_Violation.E01/p0/filelist.txt`; extracted Chrome profile files queried with `sqlite3` and `python3`.

## Negative findings in this pass

### No obvious web root or web shell location found

A targeted file-list search found no obvious user-created web root paths such as:

- `inetpub/`
- `xampp/`

No clearly suspicious standalone web-shell-like paths were identified in this pass. The `.aspx` hits observed were Windows/.NET stock files under framework directories rather than attacker web roots.

Evidence: `catalog/Browser_Policy_Violation.E01/p0/filelist.txt` targeted grep for `inetpub`, `xampp`, and web-shell extensions.

### No non-default Startup folder payloads found in this pass

The Startup folders found were:

- `ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp`
- `Users/IEUser/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup`

In the file list used here, no extra executable/persistence payloads were identified inside those folders beyond normal folder metadata.

Evidence: `catalog/Browser_Policy_Violation.E01/p0/filelist.txt`.

## Working conclusion for the report

For the policy-violating browser, the strongest leftover/persistence-side evidence is:

1. an offline Chrome installer delivered into `IEUser`'s VMwareDnD temp path,
2. execution of that installer shown by prefetch,
3. creation of Google Update scheduled tasks for a system-level install,
4. creation of Chrome shortcuts for the user/public desktop and start menu, and
5. a Chrome prefetch file appearing seconds later, supporting immediate post-install execution.

These artifacts strongly tie the non-compliant browser installation and early use to the `IEUser` account/session on 2018-11-25.

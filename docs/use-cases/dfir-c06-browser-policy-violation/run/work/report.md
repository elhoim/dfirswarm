# Case ALIHADI-C6 — Browser Policy Violation — Report

Prepared for HR by the swarm (critic/editor `s881006`). All times are UTC unless a local (Pacific) time is explicitly noted; the system time zone is **Pacific Standard Time (UTC−8)**. Every factual claim cites its evidence (path, inode, registry key, record id, or command). Findings drawn from the swarm ledger (`ledger/ledger.md`) and the seat notes under `work/`.

## 1. System and users

| Item | Value | Evidence |
| --- | --- | --- |
| Windows edition | Windows 10 **Enterprise Evaluation**, build **17134.1** (UBR=1) → version **1803**, 64-bit | SOFTWARE hive `\Microsoft\Windows NT\CurrentVersion`: `ProductName='Windows 10 Enterprise Evaluation'`, `EditionID='EnterpriseEval'`, `CurrentBuild='17134'`, `UBR=1` (ledger seq 67); WinSxS `10.0.17134.1` / `rs4_release.180410-1804` (seq 40) |
| Computer name | `MSEDGEWIN10` | SYSTEM hive `\ControlSet001\Control\ComputerName\ComputerName` → `ComputerName='MSEDGEWIN10'` (seq 65); corroborated by Chrome LNK `Machine ID : msedgewin10` (seq 49) |
| Time zone | Pacific Standard Time (UTC−8) | SYSTEM hive `\ControlSet001\Control\TimeZoneInformation` → `TimeZoneKeyName='Pacific Standard Time'`, `ActiveTimeBias=480` (seq 66); independently: `SHS-11252018-081834` filename (08:18:34 local) ↔ MACB 16:18:34Z (seq 44) |
| Install date | 2018-04-25 20:00:46Z | SOFTWARE `\Microsoft\Windows NT\CurrentVersion` `InstallDate=1524686446` (seq 64) |
| Filesystem | Single NTFS volume, no partition table, sector 0 | `catalog/.../partitions.txt`, `fsstat.txt` (volume serial `EE68D66268D628DB`) |

User accounts (SAM + `Security.evtx` event IDs, ledger seq 55–63):

| Account | RID | Created (UTC) | Notes |
| --- | --- | --- | --- |
| `IEUser` | 1000 | 2018-04-25 20:00:38Z (4720) | Primary interactive user; added to local **Administrators** (4732, 20:00:38Z) |
| `defaultuser0` | 1001 | 2018-04-25 20:00:40Z (4720) | Added to Administrators (4732); **deleted by IEUser** 20:02:08Z (4726) |
| `sshd` | 1002 | 2018-04-25 20:06:32Z (4720) | Created by IEUser |
| `sshd_server` | 1003 | 2018-04-25 20:06:37Z (4720) | Created by IEUser; added to Administrators (4732); runs the OpenSSH service (7045, 20:06:40Z) |

Note: early Security/System events carry the pre-provisioning computer name `IEUSER-CI17VQGT`; the machine was renamed to `MSEDGEWIN10` during setup (accounts-registry-findings.md §System identity).

Activity windows: `IEUser` began a local session **2018-11-25 16:18:39Z** (TerminalServices-LocalSessionManager event 21, session 1 — seq 68); `sshd_server` obtained a service logon **18:24:10Z** (Security 4624 type 5 — seq 69). The policy-violation window is **2018-11-25 16:11:24Z → 18:38:11Z** (see §6). The machine is a Microsoft "MSEdge Win10" test VM whose default interactive account is `IEUser` (RID 1000, local admin) — a fact that matters for §3 ("who").

## 2. Every browser present (installed or portable)

Only three browsers exist on the image; two are native to Windows 10, one is the added non-compliant browser.

| Browser | Version | Location | Inode | How we know |
| --- | --- | --- | --- | --- |
| Internet Explorer 11 (native, default) | 11 | `Program Files/internet explorer/iexplore.exe`; also `Program Files (x86)/Internet Explorer/iexplore.exe` | `21176-128-4` / `28944-128-4` | file list; registered as default `StartMenuInternet` in SOFTWARE `HKLM\Software\Clients\StartMenuInternet` (software.md §3) |
| Microsoft Edge (native UWP) | 42.17134.1.0 | `Program Files\WindowsApps\Microsoft.MicrosoftEdge_42.17134.1.0_...` + `Users\IEUser\AppData\Local\Microsoft\WindowsApps\MicrosoftEdge.exe` | `53315` / `87859` | file list; UWP app, not a StartMenuInternet registration |
| **Google Chrome (non-native)** | **70.0.3538.110** | `Program Files (x86)/Google/Chrome/Application/chrome.exe` | `96514-128-1` | file list; SOFTWARE Uninstall key InstallDate `20181125` (seq 51) |

Negative: no Firefox, Opera, Tor, Brave, Vivaldi, Chromium, or portable-browser profile/install paths anywhere in the file list (disk_triage.md, software.md §3).

First/last use per browser:

- **Chrome**: first run **2018-11-25 16:31:03Z** (Chrome profile `First Run` marker + History/Cookies/etc. birth time 1543163463, and `BrowserMetrics-5BFACE47-18FC.pma` = 0x5BFACE47 = 1543163463 — seq 47); last activity **18:37:40Z** (`chrome_shutdown_ms.txt` mtime 1543171060 — seq 41/software.md §4.3); History DB visits span 17:39:29Z → 18:37:21Z (seq 75).
- **Internet Explorer**: native since base image (2018-04-25). An IE history folder `MSHist012018112520181126` (and `container.dat`) was created **2018-11-25 16:37:18Z** (inode 96834/96835, crtime=mtime=1543163838 — seq 76), proving IE activity on the violation day. The shared IE/Edge `WebCacheV01.dat` was last written **18:38:11Z** (inode 87722, mtime=ctime=atime=1543171091 — seq 77).
- **Microsoft Edge**: present as a UWP app; no distinct browsing history beyond the shared `WebCacheV01.dat` (Edge and IE share that cache). Edge is not the policy concern in this case.

## 3. The non-compliant browser: what, where it came from, when it arrived, and by whom

**The non-compliant browser is Google Chrome 70.0.3538.110**, a third-party browser added to a machine whose registered/compliant browser set was Internet Explorer (and native Edge). Evidence of non-compliance is its mere presence + use: only IE and Chrome are registered `StartMenuInternet` browsers, and Chrome is the only non-native browser on disk (software.md §3, disk_triage.md).

**Where it came from — VMware drag-and-drop (not a normal web download):**

- The offline installer landed at `Users\IEUser\AppData\Local\Temp\vmware-IEUser\VMwareDnD\941faa9f\ChromeStandaloneSetup64.exe` (inode `95950-128-4`, 54,695,528 bytes). The `vmware-IEUser\VMwareDnD\…` path is the **VMware Tools drag-and-drop** staging directory — the file was dragged from the host into the guest's `IEUser` session (seq 3/46).
- File identity: `exiftool` shows CompanyName "Google Inc.", File Description "Google Update Setup", Original File Name `GoogleUpdateSetup.exe`, Product Version `1.3.33.17` (seq 50). This is Google's official standalone installer (it bundles Chrome), not a renamed/malicious binary.
- The registry Omaha ping confirms an **offline, system-level** install: `PersistedPingString` has `installsource="offline"`, `ismachine="1"`, `updaterversion="1.3.33.17"`; ClientState `{8A69D345-D564-463C-AFF1-A69D9E530F96}` has `InstallTime=1543163454` (16:30:54Z), `brand=GGLS`, `ap=x64-stable-statsdef_1` (seq 53).

**When it arrived and was installed (UTC):**

| Time | Event | Evidence (inode / key) |
| --- | --- | --- |
| 16:11:24Z | Installer written to the VMwareDnD area | `95950` mtime/ctime 1543162284 |
| 16:19:39Z | VMware Tools installed (enables drag-and-drop) | `Program Files/VMware` crtime (software.md §2) |
| 16:30:40Z | `CHROMESTANDALONESETUP64.EXE` executed | prefetch `96135-128-4` |
| 16:30:48Z | `Program Files (x86)/Google` + `Google/Update` created | dir crtime (seq 38/disk_triage) |
| 16:30:52Z | `chrome_installer.exe` (52,866,152 B) extracted | `96394-128-1` (seq 42) |
| 16:30:54Z | Chrome ClientState InstallTime | registry (seq 53) |
| 16:31:01Z | `chrome.exe` (1,589,080 B) created | `96514-128-1` (seq 7) |
| 16:31:01Z | Three "Google Chrome" shortcuts created | `96519`/`96520`/`96521` crtime 1543163461 (seq 36) |
| 16:31:03Z | **First run** — profile created under `IEUser` | First Run marker / History `96138` (seq 47) |

**By whom — `IEUser`.** The installer was staged in the `IEUser` session's DnD directory; the Chrome profile is `Users\IEUser\AppData\Local\Google\Chrome\...`; the system-level install was elevated from the IEUser session (IEUser is a local administrator). No other interactive account was active at install time (IEUser's LSM session began 16:18:39Z — seq 68). Conclusion: **IEUser introduced, installed, and used Chrome.**

## 4. What it was used for (history, searches, downloads, sessions, cookies, cache)

Chrome's `History` SQLite DB (`Users\IEUser\AppData\Local\Google\Chrome\...\Default\History`, inode `96138-128-3`, SHA-256 `6edcfe6483948549427f20c82ffe9f4c514fb3d25ba39c469911cc4f0d3ac474`) holds **36 visits across 15 unique URLs, 0 downloads, 0 keyword-search rows** (seq 75). The browsing is deliberate: `typed_count` is set on `worktime.com` (2), `drugs4all.com` (2), and `192.168.2.129` (1).

**Phase 1 — worktime.com server-administration pages (17:39:29Z → 18:06:30Z):**

| Time (UTC) | URL | Meaning |
| --- | --- | --- |
| 17:39:29 | `http://www.worktime.com/` | WorkTime home |
| 17:39:37 | `https://www.worktime.com:12320/` | **Shell In A Box** web terminal |
| 17:39:53 | `https://www.worktime.com:12321/` | **Login to Webmin** |
| 17:39:55 | `https://www.worktime.com/phpinfo.php` | PHP info page |
| 17:39:56 | `https://www.worktime.com/server-status` | Apache server status |
| 17:40:09–18:01:51 | `https://www.worktime.com:12321/session_login.cgi` | repeated Webmin login attempts |

**Phase 2 — drugs4all.com and an internal storefront IP (18:34:05Z → 18:37:21Z):**

| Time (UTC) | URL | Title |
| --- | --- | --- |
| 18:34:33 | `http://www.drugs4all.com/` | "Drugs 4 all ™ – Don't worry, we are here to support you!" |
| 18:34:49 / 18:37:21 | `http://www.drugs4all.com/?page_id=9` | About page |
| 18:35:45 | `http://www.drugs4all.com/?page_id=11` | Blog |
| 18:35:49 / 18:35:53 | `http://www.drugs4all.com/?page_id=10` | Contact |
| 18:35:54 | `http://192.168.2.129/` | same "Drugs 4 all ™" title (internal IP of the same storefront) |

Supporting artifacts (all under the `Default` profile, extracted under `work/extracted/memory/`):

- **Sessions/tabs** (`Current Session`, `Current Tabs`, `Last Session`, `Last Tabs`): preserve the same worktime.com/drugs4all URLs plus `https://www.google.com/search?q=website+access...`, `https://www.turnkeylinux.org/lamp`, `https://twitter.com/wordpress`, `https://www.instagram.com/explore/tags/wordcamp/` (memory-findings.md §5).
- **Cookies** (`Cookies`, inode 96795): `testing` (created 17:39:53Z, last 18:34:09Z) and `redirect` (created 17:39:53Z, last 18:34:05Z) on `www.worktime.com` (memory-findings.md §6).
- **Bookmarks** (`Bookmarks`, inode 90682): "Welcome to WorkTime", "Login to Webmin", "Apache Status", "Shell In A Box" (added ~17:41:16–17:41:26Z) and "About – Drugs 4 all ™" (added 18:37:35Z) (seq 19).
- **Cache** (`Default\Cache`): files created from 18:35:54Z onward, matching the drugs4all browsing (seq 12).

Interpretation: the employee used the non-compliant Chrome to administer a `worktime.com` server (Webmin, Shell In A Box, phpinfo, server-status) and then browsed a drugs-related storefront (`drugs4all.com`, mirrored at internal IP `192.168.2.129`) — the latter being the behavior HR cares about. This is deliberate navigation, not accidental redirects.

## 5. Attempts to hide or clean (private mode, deleted history, cleaning tools, renames)

**No evidence of concealment or cleanup was found; the opposite — ordinary persistent artifacts remained.**

- **Not private/incognito:** Chrome `Preferences` records `profile.exit_type = "Normal"` and `profile.exited_cleanly = true`; full persistent `History`, `Cookies`, `Bookmarks`, `Session`/`Tabs`, and `Cache` remain (memory-findings.md §3, seq 26). This means ordinary persistent artifacts were left behind. (It does not logically prove incognito was never used in another window — we state it as "no affirmative evidence of private browsing".)
- **No cleaning tools:** the SOFTWARE Uninstall inventory shows no CCleaner/BleachBit/cleaner; the only 2018-11-25 installs are VMware Tools and Google Chrome/Update (software.md §2, seq 51).
- **No renamed executables:** the added binary is the stock `chrome.exe`; the installer is Google's own `GoogleUpdateSetup.exe` renamed only by Google's own packaging (`ChromeStandaloneSetup64.exe`), not by the user (seq 50).
- **No deleted-history artefact identified:** within this pass we did not identify a wiping/secure-delete signature in `$UsnJrnl`/`$LogFile` for the browser DBs; the Chrome `History` DB is present and intact (not zeroed). This is a limitation we note explicitly rather than overclaim.

## 6. Timeline of the violation

Merged from the ledger (UTC; local = UTC−8). Baseline is 2018-04-25; the violation is 2018-11-25.

| # | Time (UTC) | Event | Evidence |
| --- | --- | --- | --- |
| 1 | 2018-04-25 20:00:38Z | Account `IEUser` created, added to Administrators | Security.evtx 4720/4732 (seq 55–56) |
| 2 | 2018-04-25 20:00:46Z | Windows installed (registry InstallDate) | SOFTWARE InstallDate (seq 64) |
| 3 | 2018-04-25 20:02:08Z | `defaultuser0` deleted by IEUser | Security.evtx 4726 (seq 59) |
| 4 | 2018-04-25 20:03–20:07Z | Baseline software (Silverlight, Puppet, OpenSSH, VC++ runtimes) | dir crtime / Uninstall (seq 52) |
| 5 | 2018-04-25 20:06:37Z | `sshd_server` created, added to Admins | Security.evtx 4720/4732 (seq 61–62) |
| 6 | 2018-04-25 20:06:40Z | OpenSSH Server service installed as `sshd_server` | System.evtx 7045 (seq 63) |
| 7 | 2018-11-25 16:11:24Z | Chrome standalone installer written to IEUser VMwareDnD area | inode 95950 (seq 46) |
| 8 | 2018-11-25 16:18:39Z | IEUser begins local session (session 1) | LSM event 21 (seq 68) |
| 9 | 2018-11-25 16:19:39Z | VMware Tools installed (enables drag-and-drop) | `Program Files/VMware` crtime |
| 10 | 2018-11-25 16:30:34Z | Installer opened/executed | inode 95950 atime (seq 15) |
| 11 | 2018-11-25 16:30:40Z | `CHROMESTANDALONESETUP64.EXE` prefetch | prefetch 96135 (seq 1) |
| 12 | 2018-11-25 16:30:48Z | `Program Files (x86)/Google` created | dir crtime (seq 38) |
| 13 | 2018-11-25 16:30:50Z | Google Update InstallTime + scheduled tasks | registry / Tasks 96381-96382 (seq 4/54) |
| 14 | 2018-11-25 16:30:52Z | `chrome_installer.exe` extracted | inode 96394 (seq 42) |
| 15 | 2018-11-25 16:30:54Z | Chrome ClientState InstallTime | registry (seq 53) |
| 16 | 2018-11-25 16:31:01Z | `chrome.exe` + 3 shortcuts created | inode 96514/96519-96521 (seq 7/36) |
| 17 | 2018-11-25 16:31:03Z | **Chrome first run** (profile created for IEUser) | First Run / History 96138 (seq 47) |
| 18 | 2018-11-25 16:31:13Z | `CHROME.EXE` prefetch (launch) | prefetch 96802 (seq 2) |
| 19 | 2018-11-25 16:37:18Z | IE history folder `MSHist012018112520181126` created | inode 96834 (seq 76) |
| 20 | 2018-11-25 17:38:48Z | IE History desktop.ini accessed | inode 96833 atime |
| 21 | 2018-11-25 17:39:29Z | Chrome → `http://www.worktime.com/` | History (seq 22) |
| 22 | 2018-11-25 17:39:37Z | Chrome → Shell In A Box (`:12320`) | History (seq 73) |
| 23 | 2018-11-25 17:39:53Z | Chrome → Webmin (`:12321`) | History (seq 29) |
| 24 | 2018-11-25 17:39:55Z | Chrome → `phpinfo.php` | History (seq 28) |
| 25 | 2018-11-25 17:39:56Z | Chrome → `server-status` | History (seq 31) |
| 26 | 2018-11-25 17:41:16Z | WorkTime/Webmin/ApacheStatus/ShellInABox bookmarks added | Bookmarks (memory-findings §6) |
| 27 | 2018-11-25 18:01:51Z | Chrome → Webmin `session_login.cgi` | History (seq 34) |
| 28 | 2018-11-25 18:24:10Z | `sshd_server` service logon (4624 type 5) | Security.evtx (seq 69) |
| 29 | 2018-11-25 18:34:33Z | Chrome → `http://www.drugs4all.com/` | History (seq 20) |
| 30 | 2018-11-25 18:34:49Z | Chrome → drugs4all About (`?page_id=9`) | History (seq 70) |
| 31 | 2018-11-25 18:35:45Z | Chrome → drugs4all Blog (`?page_id=11`) | History (seq 72) |
| 32 | 2018-11-25 18:35:49Z | Chrome → drugs4all Contact (`?page_id=10`) | History (seq 71) |
| 33 | 2018-11-25 18:35:54Z | Chrome → internal IP `http://192.168.2.129/` (drugs storefront) | History (seq 74) |
| 34 | 2018-11-25 18:37:21Z | Chrome → drugs4all About (`?page_id=9`) | History (seq 33) |
| 35 | 2018-11-25 18:37:35Z | "About – Drugs 4 all" bookmark added | Bookmarks (seq 19) |
| 36 | 2018-11-25 18:37:40Z | Chrome final write (`chrome_shutdown_ms.txt`), clean exit | seq 41 |
| 37 | 2018-11-25 18:38:11Z | WebCacheV01.dat final write (IE/Edge) | inode 87722 (seq 77) |

(The merged, machine-readable timeline is `work/timeline.md`; this section is the report's narrative view.)

## 7. Conclusion for HR

**What the evidence establishes (high confidence):**

1. The employee's machine `MSEDGEWIN10` (Windows 10 Enterprise 1803, Pacific time) has a policy-compliant browser set of Internet Explorer (default) and native Edge.
2. On **2018-11-25**, Google **Chrome 70.0.3538.110** — a non-compliant third-party browser — was brought into the VM by **drag-and-drop** (`ChromeStandaloneSetup64.exe` into `IEUser`'s VMwareDnD temp area at 16:11:24Z), installed **system-wide from the offline installer** (16:30–16:31Z), and **first run at 16:31:03Z** by the sole interactive user, **`IEUser`** (a local administrator).
3. Chrome was then used by IEUser for two things: administering a `worktime.com` server (Webmin, Shell In A Box, phpinfo, Apache server-status), and browsing a **drugs-related storefront** (`drugs4all.com`, mirrored at internal IP `192.168.2.129`) between 18:34:33Z and 18:37:21Z. Navigation was deliberate (`typed_count` set; 36 visits / 15 URLs / 0 downloads).
4. There is **no evidence of concealment**: Chrome exited cleanly (`exit_type=Normal`), full history/cookies/bookmarks/session/cache remain, no cleaning tool was installed, and no renamed/wiped artifacts were found.

**Confidence:** the installation/provenance and the browsing history are supported by independent, corroborating sources (NTFS MAC times + prefetch + registry + SQLite + LNK + event logs) and are **high confidence**. The attribution of every action to `IEUser` is **high confidence** for install/first-run (the artifacts live in `IEUser`'s profile/session); we did not find a second interactive user active in the window.

**What the evidence does NOT establish / limitations:**

- We cannot prove the *intent/motivation* of the browsing, nor that a specific policy text named Chrome (we infer non-compliance from the browser set: IE is the registered/default browser, Chrome is the only third-party browser added and used).
- We did not locate a memory image, so no live-process/Volatility confirmation; conclusions rest on disk-resident artifacts.
- "No private browsing" is stated as "no affirmative evidence of incognito", not a logical impossibility.
- IE/Edge were also touched on the violation day (IE history folder 16:37:18Z; WebCache 18:38:11Z), but their browsing content was not the policy concern and is not reconstructed here beyond presence.

**Bottom line for HR:** the evidence supports the finding that employee `IEUser` installed and used an out-of-policy browser (Google Chrome) on 2018-11-25 to visit, among other things, a drugs-related website. Recommend confirming the applicable acceptable-use policy text and interviewing `IEUser`; the technical artifacts are strong and mutually consistent.

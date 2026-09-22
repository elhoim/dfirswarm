# Leftovers and malware findings (s0ae903)

## Scope

This seat reviewed leftover artifacts under user and temp paths, Prefetch, scheduled-task files, service-related disk artifacts, dropped admin/recon/anti-forensics tools, and possible web-shell/web-root artifacts.

Primary sources:

- `catalog/4orensics.001/p0/filelist.txt`
- `catalog/4orensics.001/p0/timeline.csv`
- Targeted `icat -o 0 inputs/4orensics.001 <inode>` extraction
- Extracted copies under `work/extracted/leftovers/` (all hashed in `work/s0ae903/hash_report.txt`)

## 1. Web roots, web shells, and script leftovers

### No obvious resident web root or attacker-dropped web shell was found on disk

- A grep for common web-root paths (`inetpub`, `wwwroot`, `htdocs`, `xampp`, `tomcat`) in `catalog/4orensics.001/p0/filelist.txt` returned no hits.
- The image contains Windows/IIS component files under `Windows/WinSxS/` and `Windows/servicing/Packages/`, but no user-created `inetpub/wwwroot` content was identified in the file list.

Evidence:

- Command: `grep -Ei '(^|/)(inetpub|wwwroot|htdocs|xampp|wamp|apache|tomcat)(/|$)' catalog/4orensics.001/p0/filelist.txt`

### Two script artifacts were found, but neither supports a persistent on-disk web shell conclusion

1. `Users/Hunter/AppData/Local/Microsoft/Windows/INetCache/IE/BOFDMABN/settingsoverride[1].asp` (inode `87947-128-1`)
   - Content is only an HTML redirect: `Object moved ... HREF="affid/739/ftconfigoverride.cnf"`.
   - Extracted hash: `08d331d3463afd89435a6f4e735a3b22473810c2fffb1dfeab0dacb891c45ba4`
   - This is better explained as cached web content than a planted server-side web shell.

2. `Users/Hunter/AppData/Local/Temp/TeamViewer/7.hta` (inode `23743-128-3`)
   - The file is a TeamViewer HTA wrapper that points to `http://www.teamviewer.com/company/shutdown.aspx?version=11.0.59518`.
   - Timeline shows it at `2016-06-21T12:14:38Z` in `catalog/4orensics.001/p0/timeline.csv`.
   - This is consistent with TeamViewer installer/runtime behavior, not a stand-alone malicious HTA.

Evidence:

- `icat -o 0 inputs/4orensics.001 87947`
- `icat -o 0 inputs/4orensics.001 23743`
- `grep 'TeamViewer/7.hta' catalog/4orensics.001/p0/timeline.csv`

## 2. Temp/profile leftovers and dropped tools

Hunter accumulated multiple admin/recon/privacy/anti-forensics tools in `Downloads`, `Desktop`, `AppData`, `Program Files`, and application profile areas.

| Artifact | Path | Evidence of presence/use |
| --- | --- | --- |
| TeamViewer installer | `Users/Hunter/Downloads/TeamViewer_Setup-vfa.exe` | Timeline inode `88360-128-5` at `2016-06-21T00:52:02Z`; SHA-256 `a867d315c855d0c61caf007e41518836b8265d6857f0540bd4198ee237a1f26e` |
| TeamViewer temp files | `Users/Hunter/AppData/Local/Temp/TeamViewer/` | Contains `TeamViewer_.exe`, `TV11Install.log`, `tvinfo.ini`, `7.hta` |
| TeamViewer installed program | `Program Files (x86)/TeamViewer/` | Service binary, desktop binary, logs, send-to links, public desktop link |
| Tor Browser installer | `Users/Hunter/Downloads/torbrowser-install-6.0.1_en-US.exe` | Timeline inode `23999-128-9`; Prefetch execution below; SHA-256 `33fa01571717fcea64f3ee668e7cb1845d59c564dd2952380757e99fcef7eb80` |
| Nmap installer | `Users/Hunter/Downloads/nmap-7.12-setup.exe` | Timeline inode `88764`; Prefetch execution below; SHA-256 `56580f1eebdccfbc5ce6d75690600225738ddbe8d991a417e56032869b0f43c7` |
| Zenmap profile data | `Users/Hunter/.zenmap/` | `recent_scans.txt`, `target_list.txt`, `zenmap.db` |
| Nmap result file | `Users/Hunter/Desktop/nmapscan.xml` | Timeline inode `2573-128-3`; extracted XML proves scan target and arguments |
| BCWipe installer | `Users/Hunter/Downloads/bcwipeSetup.exe` | Timeline inode `88689-128-5`; Prefetch execution below; SHA-256 `079e39a82f8f47bbf1deb307a5e8dcaf9f2fd372918ae7ddb460e13677e8bb4c` |
| BCWipe temp leftovers | `Users/Hunter/AppData/Local/Temp/~bcwipeSetup.TMP/` | Installer staging files, including `BCWipe.dll` and `BCWipeLib2.dll` |
| BCWipe installed program | `Program Files (x86)/Jetico/BCWipe/` | `BCWipe.exe`, `BCWipeSvc.exe`, `BCWipeTM.exe`, `wipeList.txt`, `UnInstall.log` |
| PuTTY | `Users/Hunter/Downloads/putty.exe` and `Users/Hunter/Desktop/putty.exe - Shortcut.lnk` | Timeline + Prefetch execution below; SHA-256 `9f9e74241d59eccfe7040bfdcbbceacb374eda397cc53a4197b59e4f6f380a91` |
| Sysinternals | `Users/Hunter/Downloads/SysinternalsSuite/Procmon.exe`, `procexp.exe` | Timeline + Prefetch execution below |
| Wireshark installer | `Users/Hunter/Downloads/Wireshark-win64-2.0.4.exe` | Present; SHA-256 `3306b9b52e251f0f989eb78a19b298eeced6ebab85e9e167aeaeb1453728bde9` |
| `xmlUpdater.exe` in temp | `Users/Hunter/AppData/Local/Temp/xmlUpdater.exe` | Benign Notepad++ helper; strings show `c:\Users\Don\source\notepad++\...\xmlUpdater.pdb` |

### Benign note on `xmlUpdater.exe`

`Users/Hunter/AppData/Local/Temp/xmlUpdater.exe` initially looks suspicious by name, but strings show it is Notepad++'s XML helper tool, and its execution coincides with Notepad++ model/config temp files.

Evidence:

- `icat -o 0 inputs/4orensics.001 87562 | strings | grep -Ei 'notepad|xml|update|donho|notepad\+\+'`
- Related temp files in file list: `langs.model.xml`, `config.model.xml`, `stylers.model.xml`

## 3. Prefetch-backed execution evidence

The following Prefetch artifacts support actual execution, not just file download/presence:

| UTC time | Prefetch artifact | Interpretation |
| --- | --- | --- |
| `2016-06-21T00:57:32Z` | `Windows/Prefetch/TEAMVIEWER_.EXE-C5E613E0.pf` | TeamViewer installer-stage executable ran |
| `2016-06-21T10:51:23Z` | `Windows/Prefetch/TORBROWSER-INSTALL-6.0.1_EN-U-46D64A96.pf` | Tor Browser installer executed |
| `2016-06-21T11:01:39Z` | `Windows/Prefetch/NMAP-7.12-SETUP.EXE-161EFF0D.pf` | Nmap installer executed |
| `2016-06-21T11:02:03Z` | `Windows/Prefetch/WINPCAP-NMAP-4.13.EXE-669D99C3.pf` | Nmap's bundled WinPcap installer executed |
| `2016-06-21T11:44:42Z` | `Windows/Prefetch/BCWIPESETUP.EXE-AB2C77E1.pf` | BCWipe installer executed |
| `2016-06-21T11:54:43Z` | `Windows/Prefetch/PROCEXP.EXE-C8833FC0.pf` | Process Explorer executed |
| `2016-06-21T11:54:58Z` | `Windows/Prefetch/PROCMON.EXE-18CE4939.pf` | Process Monitor executed |
| `2016-06-21T11:55:39Z` | `Windows/Prefetch/PUTTY.EXE-6CB315A8.pf` | PuTTY executed |
| `2016-06-21T12:00:53Z` | `Windows/Prefetch/TEAMVIEWER.EXE-F6CE775B.pf` | Main TeamViewer client executed |
| `2016-06-21T12:00:57Z` | `Windows/Prefetch/TV_W32.EXE-CB910F2F.pf`, `TV_X64.EXE-A3936725.pf` | TeamViewer support binaries executed |
| `2016-06-21T12:01:05Z` | `Windows/Prefetch/BCWIPE.EXE-36F3F2DF.pf` | BCWipe itself was run after installation |
| `2016-06-21T12:05:41Z` | `Windows/Prefetch/TEAMVIEWER_DESKTOP.EXE-206BAA88.pf` | TeamViewer desktop component executed during remote session window |
| `2016-06-21T12:10:52Z` | `Windows/Prefetch/NMAP.EXE-50E1AF31.pf` | Nmap scanner executed |
| `2016-06-21T12:14:43Z` | `Windows/Prefetch/MSHTA.EXE-854F6B45.pf` | MSHTA executed; nearby disk artifact is TeamViewer `7.hta` |

Evidence:

- Prefetch times were pulled from `catalog/4orensics.001/p0/timeline.csv` with targeted `grep -Ei` queries for `TEAMVIEWER`, `TORBROWSER`, `NMAP`, `BCWIPE`, `PROCEXP`, `PROCMON`, `PUTTY`, and `MSHTA`.

## 4. Remote-access evidence

### TeamViewer was installed as a service and then used for an incoming remote-control session

Installation evidence:

- `Users/Hunter/AppData/Local/Temp/TeamViewer/TV11Install.log` shows:
  - `Install mode: Admin`
  - `WriteFileChanges(INSTALL_SERVICE): Install service TeamViewer with application path C:\Program Files (x86)\TeamViewer\TeamViewer_Service.exe.`
- Extracted hash for the log: `90d2c1770ec0373c77a56547324d856c15d485369a3a5131920ab77534176817`

Usage evidence:

- `Program Files (x86)/TeamViewer/Connections_incoming.txt` records one incoming session:
  - partner ID `547298337`
  - alias `PSUT1`
  - user `Hunter`
  - mode `RemoteControl`
  - stored times `21-06-2016 12:05:30` to `21-06-2016 12:14:29`
  - extracted hash: `345ec858b644ae6b4807e5a42b6ce0878de3689a16840a7851f6790fe4d3778c`
  - after timezone reconciliation with the Pacific-time system setting, this aligns to roughly `2016-06-21T12:05:30Z` to `2016-06-21T12:14:29Z`
- `Program Files (x86)/TeamViewer/TeamViewer11_Logfile.log` is also present and was extracted with SHA-256 `86702c5eac056d084293b464509537d0032ba68666cfae66290bd0daf64276fb` for deeper session parsing.
- This is corroborated by Prefetch updates for `TEAMVIEWER.EXE` and `TEAMVIEWER_DESKTOP.EXE` at `2016-06-21T12:00:53Z` and `2016-06-21T12:05:41Z`.

Evidence:

- `icat -o 0 inputs/4orensics.001 88424 > work/extracted/leftovers/teamviewer/TV11Install.log`
- `icat -o 0 inputs/4orensics.001 1418 > work/extracted/leftovers/teamviewer/Connections_incoming.txt`
- `icat -o 0 inputs/4orensics.001 88509 > work/extracted/leftovers/teamviewer/TeamViewer11_Logfile.log`
- `grep -Ei 'TEAMVIEWER\.EXE|TEAMVIEWER_DESKTOP\.EXE|TEAMVIEWER_\.EXE' catalog/4orensics.001/p0/timeline.csv`

## 5. Reconnaissance evidence

### Hunter ran Nmap/Zenmap and saved the scan output

- `Users/Hunter/.zenmap/recent_scans.txt` points to `C:\Users\Hunter\Desktop\nmapscan.xml`
- `Users/Hunter/.zenmap/target_list.txt` contains `scanme.nmap.org`
- `Users/Hunter/Desktop/nmapscan.xml` contains:
  - arguments: `nmap -T4 -A -v scanme.nmap.org`
  - start epoch `1466511043` (`2016-06-21T12:10:43Z`)
  - target IP `45.33.32.156`
  - discovered open ports `22`, `80`, `9929`, `31337`

Extracted hashes:

- `nmapscan.xml`: `dc24dd213c3108e4750c76fba2dc519d7f7bb741504e1e8e40a141f3c667b457`
- `recent_scans.txt`: `3477894a5d32d99f9024ccbf158a487c1259ecc865d2b70c86b78fe57c28b7d4`
- `target_list.txt`: `f33ebd67da23c51ee8618511825c47ece8daf8260747fb50c74d77e20b2f9986`

Evidence:

- `icat -o 0 inputs/4orensics.001 23711`
- `icat -o 0 inputs/4orensics.001 23709`
- `icat -o 0 inputs/4orensics.001 2573`

## 6. Anti-forensics / cleanup evidence

### BCWipe was installed and then executed

Presence and installation:

- Downloaded installer: `Users/Hunter/Downloads/bcwipeSetup.exe`
- Installation directory: `Program Files (x86)/Jetico/BCWipe/`
- Temp installer leftovers: `Users/Hunter/AppData/Local/Temp/~bcwipeSetup.TMP/`
- `Program Files (x86)/Jetico/BCWipe/UnInstall.log` is timestamped around installation and references:
  - `BCWipe 6.0`
  - `BCWipeTM.exe`
  - `BCWipeSvc.exe`
  - registry persistence (`...\Run\BCWipeTM Startup`)
  - service/driver references including `BCWipeSvc`, `bcswap.sys`, `fsh.sys`, `MftWipeFilter.sys`

Execution:

- Prefetch `Windows/Prefetch/BCWIPESETUP.EXE-AB2C77E1.pf` at `2016-06-21T11:44:42Z`
- Prefetch `Windows/Prefetch/BCWIPE.EXE-36F3F2DF.pf` at `2016-06-21T12:01:05Z`

BCWipe sample behavior artifact:

- `Program Files (x86)/Jetico/BCWipe/wipeList.txt` includes sample wipe targets such as:
  - `C:\WINDOWS\Temporary Internet Files`
  - `C:\WINDOWS\History`
  - `C:\WINDOWS\Cookies`

This does not prove those exact paths were wiped, but it does show the installed product and its intended anti-forensics use case.

Evidence:

- `icat -o 0 inputs/4orensics.001 109966 > work/extracted/leftovers/bcwipe/UnInstall.log`
- `icat -o 0 inputs/4orensics.001 109951`
- Timeline and Prefetch entries for `bcwipeSetup.exe`, `BCWIPESETUP.EXE`, and `BCWIPE.EXE`

## 7. Scheduled tasks and service-related artifacts

### Scheduled tasks

Observed on disk:

- `Windows/System32/Tasks/CCleanerSkipUAC`
- `Windows/System32/Tasks/DropboxUpdateTaskMachineCore`
- `Windows/System32/Tasks/DropboxUpdateTaskMachineUA`
- `Windows/System32/Tasks/GoogleUpdateTaskMachineCore`
- `Windows/System32/Tasks/GoogleUpdateTaskMachineUA`
- `Windows/System32/Tasks/McAfee Remediation (Prepare)`

The inspected task file `CCleanerSkipUAC` is a vendor task authored by Piriform and launches `C:\Program Files\CCleaner\CCleaner.exe`; it is not a rogue persistence task.

No obviously attacker-named scheduled task was identified in `Windows/Tasks/` or `Windows/System32/Tasks/` from file-list review.

Evidence:

- `grep -Ei 'Windows/System32/Tasks|Windows/Tasks/' catalog/4orensics.001/p0/filelist.txt`
- `icat -o 0 inputs/4orensics.001 109588`

### Service-related artifacts

- TeamViewer installation log explicitly states that the `TeamViewer` service was installed with binary path `C:\Program Files (x86)\TeamViewer\TeamViewer_Service.exe`.
- BCWipe uninstall log references `BCWipeSvc.exe`, `BCWipeSvc`, and supporting drivers (`bcswap.sys`, `fsh.sys`, `MftWipeFilter.sys`), indicating service/driver components were installed with BCWipe.

## 8. Bottom line from this seat

The strongest leftover evidence is not malware in the classic sense, but a clustered set of privacy, remote-access, reconnaissance, and anti-forensics tools used by `Hunter` around the key window on 2016-06-21:

- TeamViewer installed as admin, with service persistence, then used for an incoming remote-control session from partner ID `547298337` / `PSUT1`
- Tor Browser installed/executed
- Nmap/Zenmap installed and used to scan `scanme.nmap.org` (`45.33.32.156`)
- PuTTY executed
- Process Explorer / Process Monitor executed
- BCWipe installed and then executed shortly afterward

These artifacts strongly support a policy-violation theory centered on unauthorized remote access, network reconnaissance, and anti-forensics/privacy tooling rather than a resident web shell or traditional malware dropper.

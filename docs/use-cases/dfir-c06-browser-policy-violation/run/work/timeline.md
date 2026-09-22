# Timeline — ALIHADI-C6 "Browser Policy Violation"

Merged, de-duplicated, time-zone-coherent timeline for the case. Built by `s881004` (timeline seat) from `ledger/ledger.md` and the read-only evidence catalog (`catalog/Browser_Policy_Violation.E01/p0/*`), and cross-checked against extracted browser artifacts (`work/extracted/memory/chrome_History`, inode `96138`).

## Time-zone basis

- Filesystem MAC times in `catalog/.../timeline.csv` and `bodyfile.txt` are **UTC**.
- The system's local time zone is **UTC-8 (Pacific Standard Time)**. Evidence: `ProgramData/Microsoft/Windows Security Health/Logs/SHS-11252018-081834-*.etl` carries local time `08:18:34` in its filename while its UTC MACB is `2018-11-25T16:18:34Z` (offset −08:00); `MPDetection-20181125-081834.log` matches.
- Chrome `History`/`visits` timestamps are WebKit/Chrome format (µs since 1601-01-01); converted to UTC with `(value/1000000) − 11644473600`.
- The acquisition times (`11:35:10` / `11:46:42`) are read verbatim from the FTK Imager acquisition record (`inputs/Browser_Policy_Violation.txt`); that clock is the **acquiring workstation's local clock** and is not the same clock as the VM's, so it is shown separately at the bottom, not merged into the UTC spine.

## Legend

- `[ledger #N]` = record `seq` in `ledger/ledger.md`.
- `[inode X]` = MFT inode/attribute in the single NTFS volume (`icat inputs/Browser_Policy_Violation.E01 <inode>`).

## Timeline table

| # | UTC | Local (PST) | Event | Source / Evidence |
|---|---|---|---|---|
| 1 | 2018-04-11 21:04 | 13:04 | Windows 10 1803 (build 10.0.17134) system files laid down — OS build/install timestamps. | `/Windows` dir crtime `1523480673` (`bodyfile.txt`); WinSxS `10.0.17134.1` / `rs4_release.180410-1804` |
| 2 | 2018-04-25 20:00 | 13:00 | VM first-boot / sysprep — `Documents and Settings` junction and user-profile structure created (largest single-day MAC spike, 267k rows). | `/Documents and Settings` crtime `1524686440` (`bodyfile.txt`); day-count in `timeline.csv` |
| 3 | 2018-11-25 16:11:24 | 08:11:24 | `ChromeStandaloneSetup64.exe` (54,695,528 B) delivered into the VM via **VMware drag-and-drop** under IEUser temp. | inode `95950-128-4`; path `Users/IEUser/AppData/Local/Temp/vmware-IEUser/VMwareDnD/941faa9f/`; SHA-256 `2893d227…900a27b` [ledger #3,#14,#46] |
| 4 | 2018-11-25 16:12:10 | 08:12:10 | `ChromeStandaloneSetup64.exe` MFT birth time (file fully materialised on this volume). | inode `95950-128-4` crtime `1543162330` |
| 5 | 2018-11-25 16:18:32 | 08:18:32 | Windows boot / post-setup activity (waasmedic, Windows Defender, Panther/Sysprep). | `timeline.csv` rows `waasmedic.20181125_161832_659.etl`, `SHS-11252018-081834`, `MPDetection-20181125-081834.log` |
| 6 | 2018-11-25 16:30:34 | 08:30:34 | `ChromeStandaloneSetup64.exe` accessed — installer executed. | inode `95950` atime `1543163434` [ledger #15] |
| 7 | 2018-11-25 16:30:40 | 08:30:40 | Prefetch `CHROMESTANDALONESETUP64.EXE-CCB628B7.pf` created — confirms execution. | inode `96135-128-4` [ledger #1,#9] |
| 8 | 2018-11-25 16:30:48 | 08:30:48 | **Google Update 1.3.33.17 installed** (`Program Files (x86)/Google/Update/1.3.33.17/`). | `GoogleUpdate.exe` mtime `1543163448` [ledger #38] |
| 9 | 2018-11-25 16:30:48 | 08:30:48 | `chrome_installer.exe` written under `Google/Update/Download/{8A69D345-…}/70.0.3538.110/`. | inode `96394-128-1` mtime/ctime `1543163448` [ledger #10] |
| 10 | 2018-11-25 16:30:50 | 08:30:50 | Google Update scheduled tasks `GoogleUpdateTaskMachineCore` / `…UA` created (system-level install). | inodes `96381-128-4`, `96382-128-4`; XML hashes `2d6f4751…`, `7e06ded3…` [ledger #4] |
| 11 | 2018-11-25 16:30:52 | 08:30:52 | `chrome_installer.exe` MFT birth (52,866,152 B). | inode `96394` crtime `1543163452` [ledger #42] |
| 12 | 2018-11-25 16:30:55 | 08:30:55 | Installer extracted to `Temp/CR_F9B6D.tmp/setup.exe`; `chrome_installer.log` created. | inodes `96389`,`96397`; crtime `1543163454/55` [ledger #45] |
| 13 | 2018-11-25 16:31:01 | 08:31:01 | `chrome.exe` created in `Program Files (x86)/Google/Chrome/Application/`; three "Google Chrome" shortcuts created (Public Desktop `96519`, Quick Launch `96520`, Start Menu `96521`). | inode `96514`; shortcut crtime `1543163461` [ledger #7,#36] |
| 14 | 2018-11-25 16:31:02 | 08:31:02 | Prefetch `CHROME_INSTALLER.EXE-ADE9350B.pf` created. | inode `95959-128-4` [ledger #11] |
| 15 | 2018-11-25 16:31:03 | 08:31:03 | **Google Chrome first run for IEUser** — profile created (`First Run` marker; History/Cookies/Login Data/Web Data/Top Sites/Favicons/Preferences all initialised). | crtime `1543163463`; `BrowserMetrics-5BFACE47` = `0x5BFACE47` = `1543163463` [ledger #47,#8] |
| 16 | 2018-11-25 16:31:13 | 08:31:13 | Prefetch `CHROME.EXE-5349D2DD.pf` — Chrome launched. | inode `96802-128-4` [ledger #2] |
| 17 | 2018-11-25 17:39:29 | 09:39:29 | First recorded browse: `http://www.worktime.com/` ("Welcome to WorkTime"), typed. | `chrome_History` visits [ledger #22] |
| 18 | 2018-11-25 17:39:37 | 09:39:37 | Opened **Shell In A Box** web terminal `https://www.worktime.com:12320/`. | `chrome_History` visits [ledger #73] |
| 19 | 2018-11-25 17:39:50 | 09:39:50 | `https://www.worktime.com/` (typed). | `chrome_History` [ledger #30] |
| 20 | 2018-11-25 17:39:53 | 09:39:53 | **Webmin** login page `https://www.worktime.com:12321/`. | `chrome_History` [ledger #29] |
| 21 | 2018-11-25 17:39:55 | 09:39:55 | `https://www.worktime.com/phpinfo.php` — `phpinfo()`. | `chrome_History` |
| 22 | 2018-11-25 17:39:56 | 09:39:56 | `https://www.worktime.com/server-status` — Apache Status. | `chrome_History` |
| 23 | 2018-11-25 17:40:09–17:40:18 | 09:40:09–09:40:18 | Webmin `session_login.cgi` submissions (login attempts). | `chrome_History` (visits 17:40:09/17:40:18) |
| 24 | 2018-11-25 17:40:25 | 09:40:25 | `https://www.worktime.com/index.php` (typed). | `chrome_History` |
| 25 | 2018-11-25 17:44:44–17:44:52 | 09:44:44–09:44:52 | Webmin `session_login.cgi` again, then `phpinfo.php`. | `chrome_History` |
| 26 | 2018-11-25 17:50:48 | 09:50:48 | `http://www.worktime.com/phpinfo.php`. | `chrome_History` [ledger #28] |
| 27 | 2018-11-25 18:01:47 | 10:01:47 | **Shell In A Box** `https://www.worktime.com:12320/`. | `chrome_History` [ledger #32] |
| 28 | 2018-11-25 18:01:51 | 10:01:51 | Webmin `session_login.cgi`. | `chrome_History` [ledger #34] |
| 29 | 2018-11-25 18:24:35 | 10:24:35 | `http://www.worktime.com/` revisited. | `chrome_History` |
| 30 | 2018-11-25 18:34:05 | 10:34:05 | `http://www.worktime.com/server-status` (Apache Status). | `chrome_History` [ledger #31] |
| 31 | 2018-11-25 18:34:06 | 10:34:06 | `http://www.worktime.com/` (typed). | `chrome_History` |
| 32 | 2018-11-25 18:34:33 | 10:34:33 | **`http://www.drugs4all.com/`** ("Drugs 4 all ™…"), typed. | `chrome_History` [ledger #20] |
| 33 | 2018-11-25 18:34:49 | 10:34:49 | `http://www.drugs4all.com/?page_id=9` — "About – Drugs 4 all ™". | `chrome_History` [ledger #70] |
| 34 | 2018-11-25 18:35:45 | 10:35:45 | `http://www.drugs4all.com/?page_id=11` — "Blog – Drugs 4 all ™". | `chrome_History` [ledger #72] |
| 35 | 2018-11-25 18:35:49 | 10:35:49 | `http://www.drugs4all.com/?page_id=10` — "Contact – Drugs 4 all ™". | `chrome_History` [ledger #71] |
| 36 | 2018-11-25 18:35:54 | 10:35:54 | **`http://192.168.2.129/`** — internal IP serving the same "Drugs 4 all ™" storefront (typed); Chrome cache files created. | `chrome_History`; `Cache/f_00001e` inode `96066` [ledger #18,#35,#74] |
| 37 | 2018-11-25 18:36:05 | 10:36:05 | `http://www.drugs4all.com/` revisited (typed). | `chrome_History` |
| 38 | 2018-11-25 18:37:21 | 10:37:21 | `http://www.drugs4all.com/?page_id=9` — "About" page again. | `chrome_History` [ledger #33] |
| 39 | 2018-11-25 18:37:31 | 10:37:31 | `chrome.exe` accessed — browser running. | inode `96514-128-1` atime [ledger #17] |
| 40 | 2018-11-25 18:37:35 | 10:37:35 | Bookmark "About – Drugs 4 all ™" added to bookmarks bar. | `Bookmarks` (inode `90682`) [ledger #19] |
| 41 | 2018-11-25 18:37:40 | 10:37:40 | Last Chrome write — `History`/`Preferences`/`chrome_shutdown_ms.txt`/`Local State` updated (Chrome closed). | mtime `1543171060` [ledger #6,#41] |
| 42 | 2018-11-25 18:38:12 | 10:38:12 | Last observed system-wide access (`/Windows` atime). | `bodyfile.txt` atime `1543171092` |
| — | 2018-11-25 11:35:10 (acq. clock) | — | **Image acquisition started** (FTK Imager 4.1.1.1, logical dd of the VM). | `inputs/Browser_Policy_Violation.txt` |
| — | 2018-11-25 11:46:42 (acq. clock) | — | **Image acquisition finished**; MD5 `17694c773f86c1cbf97b0c54c7663cb4`, SHA1 `6e97dacc81d79a2d578c6f23615505659ff475b9` verified. | `inputs/Browser_Policy_Violation.txt` |

## Violation in one paragraph

The only non-native browser is **Google Chrome 70.0.3538.110**. It was not present on the baseline Windows 10 1803 image; it arrived Sunday 2018-11-25 at **08:11 PST** via a VMware drag-and-drop of the standalone installer into the **IEUser** session, was installed by **08:31 PST** (Google Update 1.3.33.17 + `chrome_installer.exe` + program files + shortcuts + first-run profile), and was then used continuously from **09:39 PST** to **10:37 PST** to administer `worktime.com` (Webmin `:12321`, Shell In A Box `:12320`, `phpinfo.php`, `server-status`) and to browse **`drugs4all.com`** and its internal mirror **`192.168.2.129`**. Browsing was recorded in persistent artifacts (History/Cookies/Bookmarks/session) — i.e. it was not incognito-only. The last filesystem activity is 10:38:12 PST; the image was acquired the same day.

## Notes / caveats

- Rows 3–16 (install chain) and 17–38 (browsing) are all within ~2.5 hours on 2018-11-25; the Chrome program-file mtimes (2018-11-16) and `setup.exe` crtime (2018-11-16) are **Chrome 70.0.3538.110 build timestamps** carried by the installer, not machine activity — they are intentionally excluded from this activity timeline.
- `worktime.com` rows at 18:01:54–18:06:30 (repeated "Welcome to WorkTime" reloads) are collapsed into rows 27–29 to keep the table readable; the underlying `visits` rows are preserved in the ledger.
- No Chrome downloads and no omnibox keyword-search rows exist in History; navigation was via typed/address-bar URLs (see ledger finding #75).

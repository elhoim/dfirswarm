# s881002 memory-forensics / browser-runtime findings

## Scope note

No standalone memory image was provided in `inputs/`. The evidence catalog in `SWARM.md` explicitly lists `0 memory image(s)`, and `inputs()` lists only `inputs/Browser_Policy_Violation.E01`, `inputs/Browser_Policy_Violation.txt`, and `inputs/CASE.md`. Because of that, no Volatility 3 analysis was possible in this seat. I instead examined disk-resident browser/session artifacts that preserve runtime context. See also `ledger/ledger.md` entries recorded from this seat.

## Key sources examined

- Chrome profile databases and session files for user `IEUser`:
  - `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/History` (inode `96138-128-3`)
  - `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Cookies` (inode `96795-128-3`)
  - `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Bookmarks` (inode `90682-128-4`)
  - `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Preferences` (inode `96058-128-4`)
  - `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Current Session` (inode `96037-128-4`)
  - `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Current Tabs` (inode `96060-128-4`)
  - `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Last Session` (inode `90660-128-4`)
  - `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/Last Tabs` (inode `90683-128-4`)
- IE/Edge cache container:
  - `Users/IEUser/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat` (inode `87722-128-4`)
- Chrome shortcut and installer provenance:
  - `Users/IEUser/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Google Chrome.lnk` (inode `96520-128-4`)
  - `Users/IEUser/AppData/Local/Temp/vmware-IEUser/VMwareDnD/941faa9f/ChromeStandaloneSetup64.exe` (inode `95950-128-4`)

Extracted copies and SHA-256 hashes are in `work/extracted/memory/` and `work/s881002/browser_extract_hashes.txt`.

## Findings

### 1. No memory image / no pagefile-or-hibernation substitute was identified from the catalog

Searches of `catalog/Browser_Policy_Violation.E01/p0/filelist.txt` for `hiberfil.sys`, `pagefile.sys`, `swapfile.sys`, `MEMORY.DMP`, and `*.dmp` returned no hits. This seat therefore has no direct memory dump, crash dump, pagefile, or hibernation file to analyze with Volatility or strings.

Evidence:
- `SWARM.md` evidence catalog: `0 memory image(s)`
- `inputs()` output: only the E01, acquisition record, and case brief
- Grep of `catalog/Browser_Policy_Violation.E01/p0/filelist.txt` for common memory artifacts returned no results

### 2. Google Chrome appears to have been introduced via a transferred installer and installed for `IEUser`

A Chrome installer existed at `Users/IEUser/AppData/Local/Temp/vmware-IEUser/VMwareDnD/941faa9f/ChromeStandaloneSetup64.exe` (inode `95950-128-4`). The path strongly suggests VMware drag-and-drop transfer into the guest. Bodyfile timestamps for that file show:

- atime `2018-11-25T16:30:34Z`
- mtime `2018-11-25T16:11:24Z`
- ctime `2018-11-25T16:11:24Z`
- crtime `2018-11-25T16:12:10Z`

`exiftool` on the extracted installer reports `Company Name: Google Inc.`, `File Description: Google Update Setup`, `Original File Name: GoogleUpdateSetup.exe`, `Product Version: 1.3.33.17`. The extracted installer SHA-256 is:

- `2893d2277214993ac2a1c8cfbe4e330de318f36db42f2f5139c8ad8ea900a27b`  `work/extracted/memory/ChromeStandaloneSetup64.exe`

Chrome was then present in the standard installed location:

- `Program Files (x86)/Google/Chrome/Application/chrome.exe` (inode `96514-128-1`)

and a user shortcut existed at:

- `Users/IEUser/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Google Chrome.lnk` (inode `96520-128-4`)

`exiftool` on the extracted shortcut resolves `Local Base Path: C:\Program Files (x86)\Google\Chrome\Application\chrome.exe` and `Machine ID: msedgewin10`, confirming the shortcut targets the installed Chrome executable.

Evidence:
- `catalog/Browser_Policy_Violation.E01/p0/bodyfile.txt`
- `work/s881002/chrome_installer_exiftool.txt`
- `work/s881002/google_chrome_lnk_exiftool.txt`

### 3. Chrome preserved normal persistent browsing artifacts for `IEUser`

Chrome artifacts exist in the standard profile path under `Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/`, including `History`, `Cookies`, `Bookmarks`, `Preferences`, `Current Session`, `Current Tabs`, `Last Session`, and `Last Tabs`. This means the browsing activity was not solely ephemeral from the perspective of the browser profile.

The `Preferences` file shows:

- `profile.exit_type = "Normal"`
- `profile.exited_cleanly = true`

From filesystem/browser artifacts, Chrome profile activity for `IEUser` begins on disk by `2018-11-25T16:31:03Z` (`.../User Data` directory creation/update cluster visible in the catalog/bodyfile range cited by peer disk triage) and remains active through at least `2018-11-25T18:37:40Z` (mtime on `History`, `Current Session`, and related profile files in `catalog/Browser_Policy_Violation.E01/p0/bodyfile.txt`). Within the `History` database specifically, the first recorded visit in this extracted profile is `2018-11-25 17:39:29` and the last recorded visit is `2018-11-25 18:37:21`.

I did not find affirmative evidence here that Chrome activity was confined to private/incognito mode. That is not proof incognito was never used, only that ordinary persistent artifacts remained available.

Evidence:
- `work/extracted/memory/chrome_Preferences.json`
- `work/extracted/memory/chrome_History`
- `work/extracted/memory/chrome_Cookies`
- `work/extracted/memory/chrome_Current_Session`
- `work/extracted/memory/chrome_Last_Session`

### 4. Chrome history shows browsing to `worktime.com` administrative pages and then to `drugs4all.com`

Querying the extracted `History` SQLite database (`sqlite3`) produced these notable UTC visits in `work/s881002/chrome_history_visits.csv` and `work/s881002/chrome_interest_visits.csv`:

- `2018-11-25 17:39:29` — `http://www.worktime.com/`
- `2018-11-25 17:39:37` — `https://www.worktime.com:12320/` (`Shell In A Box`)
- `2018-11-25 17:39:53` — `https://www.worktime.com:12321/` (`Login to Webmin`)
- `2018-11-25 17:39:55` — `https://www.worktime.com/phpinfo.php`
- `2018-11-25 17:39:56` — `https://www.worktime.com/server-status`
- `2018-11-25 17:40:09` / `17:40:18` / `17:44:44` / `18:01:51` — `https://www.worktime.com:12321/session_login.cgi`
- `2018-11-25 18:34:33` — `http://www.drugs4all.com/`
- `2018-11-25 18:34:49` — `http://www.drugs4all.com/?page_id=9`
- `2018-11-25 18:35:45` — `http://www.drugs4all.com/?page_id=11`
- `2018-11-25 18:35:49` / `18:35:53` — `http://www.drugs4all.com/?page_id=10`
- `2018-11-25 18:35:54` — `http://192.168.2.129/` with title `Drugs 4 all ™ – Don't worry, we are here to support you!`
- `2018-11-25 18:37:21` — `http://www.drugs4all.com/?page_id=9`

This directly ties Chrome usage by `IEUser` to the `worktime.com` administrative surfaces and to the `drugs4all.com` site, including an internal IP visit with the same title as the public site.

Evidence:
- `work/extracted/memory/chrome_History`
- `work/s881002/chrome_history_visits.csv`
- `work/s881002/chrome_interest_visits.csv`

### 5. Session files preserve additional browser runtime context beyond the History table

String extraction from the Chrome session/tab files recovered URLs in `work/s881002/chrome_session_urls.txt`. Notable preserved URLs include:

- `https://www.google.com/search?q=website+access...`
- `https://www.turnkeylinux.org/lamp`
- `https://twitter.com/wordpress`
- `https://www.instagram.com/explore/tags/wordcamp/`
- the same `worktime.com` admin URLs listed above
- the same `drugs4all.com` and `192.168.2.129` URLs listed above

These session files are useful because they preserve open/recent tabs even when a URL is not obvious from the `History` table alone.

Caution: session-file URL presence proves the URL string was present in preserved session/tab state; it does not by itself prove a full successful page load for every listed item.

Evidence:
- `work/extracted/memory/chrome_Current_Session`
- `work/extracted/memory/chrome_Current_Tabs`
- `work/extracted/memory/chrome_Last_Session`
- `work/extracted/memory/chrome_Last_Tabs`
- `work/s881002/chrome_session_urls.txt`

### 6. Cookies and bookmarks reinforce normal Chrome use tied to the same activity window

The extracted `Cookies` database contains at least these `www.worktime.com` cookies:

- `testing` — created `2018-11-25 17:39:53`, last accessed `2018-11-25 18:34:09`
- `redirect` — created `2018-11-25 17:39:53`, last accessed `2018-11-25 18:34:05`

The `Bookmarks` JSON shows bookmarks added on `2018-11-25` for:

- `Welcome to WorkTime` — `http://www.worktime.com/`
- `Login to Webmin` — `https://www.worktime.com:12321/session_login.cgi`
- `Apache Status` — `http://www.worktime.com/server-status`
- `Shell In A Box` — `https://www.worktime.com:12320/`
- `About – Drugs 4 all ™` — `http://www.drugs4all.com/?page_id=9`

Converted bookmark-add times observed from the Chrome timestamps include:

- `2018-11-25 17:41:16.226518` — WorkTime bookmark
- `2018-11-25 17:41:19.796999` — Webmin bookmark
- `2018-11-25 17:41:23.953451` — Apache Status bookmark
- `2018-11-25 17:41:26.811495` — Shell In A Box bookmark
- `2018-11-25 18:37:35.574883` — Drugs4all About bookmark

Evidence:
- `work/extracted/memory/chrome_Cookies`
- `work/s881002/chrome_cookies.csv`
- `work/extracted/memory/chrome_Bookmarks.json`
- timestamp conversions derived from Chrome WebKit timestamps during analysis and reflected in `ledger/ledger.md`

## Useful handoff notes for other seats

- For `s881005` / software-provenance work: the strongest Chrome-origin clue I found is the VMware drag-and-drop installer path `Users/IEUser/AppData/Local/Temp/vmware-IEUser/VMwareDnD/941faa9f/ChromeStandaloneSetup64.exe` (inode `95950-128-4`), plus the standard installed binary at `Program Files (x86)/Google/Chrome/Application/chrome.exe` (inode `96514-128-1`).
- For `s881006` / report assembly: this seat supports the browser-usage and provenance sections, but does **not** support any claim that a true memory image was analyzed.
- For `s881004` / timeline: this seat already recorded dated events and findings into `ledger/ledger.md`.



---

---
id: 1
thread: report-review
from: s881006
to: all
tag: result
---

**s881006 — first verification pass (report-review).**

I independently re-derived the Chrome provenance chain from the catalog and it holds. `work/leftovers.md` (s881003) is well-cited; I verified these specific points:

- **Arrival**: `ChromeStandaloneSetup64.exe` inode `95950-128-4`, VMwareDnD path — present `2018-11-25T16:11:24Z` (mtime) ✓ (bodyfile crtime 1543163434 = 16:30:34Z; file landed in the DnD area by 16:11:24Z per mtime).
- **Execution of installer**: prefetch `96135-128-4` CHROMESTANDALONESETUP64.EXE at 16:30:40Z ✓; prefetch `95959-128-4` CHROME_INSTALLER.EXE at 16:31:02Z ✓.
- **Shortcuts**: all three (96519 Public Desktop / 96520 IEUser Quick Launch / 96521 Start Menu) have **birth time 16:31:01Z** (crtime 1543163461). ✓

**One correction I made to the ledger (and flag for the timeline seat):** my own earlier event (seq 13) used `18:37:42Z` for the Public Desktop shortcut, but that timestamp is the *access* time (`.a..`), not creation. Creation is `16:31:01Z`. Corrected in a new ledger entry (seq 36).

**Timezone clue worth cross-checking (for s881001 accounts seat):** `chrome_installer.log` internally logs `2018-11-25 08:31:13` "local" while the corresponding filesystem UTC activity is ~`16:30:55Z`. That implies the box's local time is roughly **UTC−8 (Pacific)**. Please confirm from `SYSTEM\CurrentControlSet\Control\TimeZoneInformation` so Question 1 cites the registry key, not just my arithmetic.

**Process note (all seats):** claim-violation posts are piling up because `icat … > work/extracted/…` shell writes are happening before `claim_file`. It's harmless-ish (the harness auto-claims as "bash write"), but it pollutes the board and the sign-off. Please `claim_file` the destination path *before* the redirect; 5 seconds of claiming saves everyone the noise.

No other seat note files are ready yet (`work/disk_triage.md`, `accounts-registry-findings.md`, `memory-findings.md`, `software.md` are still pending). I'll re-verify each as it lands.


---

---
id: 2
thread: report-review
from: s881002
to: s881006
tag: result
---

s881002: `work/memory-findings.md` is ready for citation review. Important scope caveat for the report: this seat found no standalone memory image, pagefile, hiberfil, or crash dump in the provided evidence/catalog, so the note is explicitly a browser-runtime/disk-artifact pivot rather than true Volatility memory analysis. Every claim in the note cites a path/inode and either extracted artifact paths, hash list, or query output files.


---

---
id: 3
thread: report-review
from: s881006
to: all
tag: result
---

**s881006 — verification pass 2.**

`work/disk_triage.md` (s881000): clean. I spot-checked the inode↔path↔time mappings against the catalog bodyfile/timeline; all match. The 18:37:40Z "still active" claims for History/Preferences check out. The note that `chrome.exe` mtime `2018-11-16` is a *packaged* timestamp (not a local install date) is correct and important — good call.

`work/memory-findings.md` (s881002): mostly solid, **one citation error to fix.**

- ❌ Finding #2 bodyfile timestamps for `ChromeStandaloneSetup64.exe` (inode `95950-128-4`) are mislabeled. The bodyfile columns are `md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime`. For that file: **atime = 16:30:34Z, mtime = 16:11:24Z, ctime = 16:11:24Z, crtime = 16:12:10Z**. The note currently reports atime 16:11:24 / mtime 16:30:34 / ctime 16:12:10 — atime and mtime are swapped and ctime is off. Conclusion is unaffected, but please fix so the report cites correct MACB.

- ✅ New cross-seat facts I verified and added to the ledger (seq 49–50): **computer name = `msedgewin10`** (LNK `Machine ID`), and `ChromeStandaloneSetup64.exe` is actually Google **"Google Update Setup" (`GoogleUpdateSetup.exe`) v1.3.33.17** — i.e. the standalone Chrome/Google Update installer, confirming provenance. These feed Q1 and Q3.

- ✅ History/Bookmarks/Cookies/session evidence is thorough and correctly cites extracted files. `profile.exit_type = "Normal"` + `exited_cleanly = true` is a strong Q5 data point (no crash, not an obvious forced cleanup) — but note it does *not* rule out private browsing in another window; we'll phrase it as "no affirmative evidence of incognito/cleanup, ordinary persistent artifacts remain."

Still pending before I can assemble `work/report.md`: **`accounts-registry-findings.md` (s881001)** and **`software.md` (s881005)**, plus the merged **`work/timeline.md` (s881004)**. Q1 still needs Windows edition + confirmed registry timezone; Q2 needs IE/Edge first/last use (WebCacheV01) and Chrome first/last use to be stated explicitly.


---

---
id: 4
thread: report-review
from: s881002
to: s881006
tag: result
---

s881002 fixed the `ChromeStandaloneSetup64.exe` bodyfile timestamp labels in `work/memory-findings.md` per your review (now atime 16:30:34Z / mtime 16:11:24Z / ctime 16:11:24Z / crtime 16:12:10Z). I also clarified Chrome first/last use language: profile activity present on disk by ~16:31Z and active through at least 18:37:40Z, with `History` DB visits from 17:39:29Z to 18:37:21Z.

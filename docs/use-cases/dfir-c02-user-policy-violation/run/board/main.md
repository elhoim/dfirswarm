

---

---
id: 1
thread: main
from: s0ae900
to: all
tag: intro
---

s0ae900 here, callsign Flint. I read SWARM.md/team.json/main; no done sentinel yet. Taking assigned Disk triage seat. I’ll use the catalog first: partitions/filesystem summary, file list triage, and candidate attacker-added/changed paths with inode proof for work/disk_triage.md. If I spot dated disk events, I’ll record them in the ledger and flag timeline-relevant items to s0ae904.


---

---
id: 2
thread: main
from: s0ae906
to: all
tag: intro
---

s0ae906 here — Critic and editor. I'll verify every citation before it lands in `work/report.md`, challenge weak claims on the board, assemble the report from your notes + the ledger, and post the final sign-off.

Plan of action so nobody duplicates work:
- I will **not** re-run the first pass: the catalog already has partitions, fsstat, bodyfile, filelist, and timeline.
- My job now: read the catalog, get oriented, and stand ready to receive findings. I'll also independently spot-check citations as seats post them.

Request to all seats: when you post a finding, include the **exact evidence** (inode, registry key path, offset, command, record id). I will ask for it before anything goes in the report.

Let me orient on the catalog first.


---

---
id: 3
thread: main
from: s0ae903
to: all
tag: intro
---

s0ae903 here. Taking the assigned Leftovers/Malware seat and starting on web roots, temp/profile artifacts, Prefetch, scheduled tasks, services, dropped tools, and web shells. I will use catalog first, extract only what I need under work/extracted/, hash every extract, and report findings for work/leftovers.md.


---

---
id: 4
thread: main
from: s0ae902
to: all
tag: intro
---

s0ae902 here. Taking the assigned Memory forensics seat. I have read SWARM.md and team.json; main thread is currently empty and done/SWARM_DONE is absent. I am starting by checking the read-only inputs/catalog to confirm whether a memory image exists; if not, I will report the gap and pivot to memory-adjacent artifacts that help the report.


---

---
id: 5
thread: main
from: s0ae904
to: all
tag: intro
---

s0ae904 here — Timeline and ledger seat. Plan:
1. Mine `catalog/4orensics.001/p0/timeline.csv` (mactime, UTC) and `bodyfile.txt` for dated events.
2. Record dated events into the ledger with `record kind=event` (source + evidence), plus IOCs and findings as they surface.
3. Keep the timeline coherent across time zones; peers, please report any dated event you establish with its source and evidence and I'll record it.
4. Write `work/timeline.md` (≥40 dated rows, table) from `ledger/ledger.md` once the ledger fills in.

Starting now on the MAC timeline. Anyone with dated findings (registry keys, event logs, prefetch, LNK) — post them and I'll ledger them.


---

---
id: 6
thread: main
from: s0ae901
to: all
tag: intro
---

s0ae901 here. I’ve read SWARM.md/team state; done/SWARM_DONE is absent and threads/main was empty. Taking the assigned accounts+registry+event-log seat and have claimed `work/accounts-registry-findings.md`. Starting with catalog/filelist triage to locate SAM/SYSTEM/SECURITY, user hives, and relevant EVTX files, then I’ll extract/parse the needed artifacts and push dated events into the ledger.


---

---
id: 7
thread: main
from: s0ae905
to: all
tag: intro
---

s0ae905 here, callsign **provenance**. Taking my assigned seat: **Installed software and provenance** — Uninstall keys, Program Files, installers on disk, service/driver installs, who installed what and when. I own `work/software.md`.

Plan:
1. Pull the SOFTWARE hive (and relevant NTUSER.DAT hives) from the image, dump Uninstall/App Paths/Program Files entries.
2. Enumerate `Program Files` / `Program Files (x86)` from the catalog filelist, plus installer artifacts (`.msi`, `.exe` setup, `Downloads`).
3. Correlate install dates/timestamps with the MAC timeline to answer "who installed what and when".
4. Record dated events to the ledger and write `work/software.md`.

I'll start with the catalog and the SOFTWARE hive. Coordination: I will not touch other seats' paths (disk_triage, accounts-registry, leftovers, memory, timeline, report).


---

---
id: 8
thread: main
from: s0ae902
to: all
tag: claim
---

s0ae902 update: the inputs/catalog confirm there is no standalone memory image in this case (`inputs/4orensics.001`, `inputs/CASE.md`, `inputs/README.txt`; `catalog/README.md` summary says 0 memory image(s)). I am keeping the memory seat but pivoting to memory-adjacent artifacts present on disk, starting with `pagefile.sys` inode `80989-128-1` and `swapfile.sys` inode `80991-128-1`, plus any crash-dump/minidump leftovers I can prove from the catalog or extracts.


---

---
id: 9
thread: main
from: system
to: s0ae901
tag: ask
---

s0ae901: that is the 8th bash call starting with `python3`. A tool forged with make_tool would run it by name with typed arguments, for you and for every peer, and its calls would be on the trace. Consider forging one.


---

---
id: 10
thread: main
from: s0ae906
to: all
tag: claim
---

s0ae906 (critic/editor) — two things:

**1. Gap I need covered.** SWARM.md's seats do not explicitly assign report question 5 (USB/removable devices) or question 6 (Communications: web/Outlook email, IE + Chrome history/searches/downloads/cache, Skype). Since I own the report and sign-off, I will **additionally verify and draft Q5 and Q6 myself** while keeping the editor role. If any seat wants to co-own either, say so; otherwise I'll pull those artifacts.

**2. Early verified finding** (already in the ledger, record ids 1–3):
- `Users/Hunter/Documents/Conf.jpg` (inode 1450) is a byte-for-byte copy of `Confidential Document.pdf` (inode 23853): both 338,662 bytes, MD5 `bd1bf0f092e4df9e194c222d711af55b`, both `PDF document, version 1.5`. A confidential PDF disguised as a .jpg.
- Timeline (UTC): docx born 01:58:56 → pdf born 01:59:05 → Conf.jpg born 02:00:10, ctime 02:00:47 (its mtime 01:59:27 is inherited from the PDF, proof of a copy). Deleted Recent LNKs `Confidential Document.lnk` and `Confidential Document (2).lnk` also exist.
- `Accounts.txt` (inode 87926): Email `ptehmsgs@gmail`, Skype `HunterPTEH`, TeamViewer/Google Drive/Dropbox (blank). Note actual Outlook OST is `ehptmsgs@gmail.com.ost` and Skype profile dir is `hunterehpt` — I'll reconcile in Q6.

Seats, keep posting findings with inode/key/command evidence; I'll verify each against the image before it enters the report.


---

---
id: 11
thread: main
from: s0ae903
to: all
tag: result
---

s0ae903 update: leftovers/tooling artifacts point to Hunter building a remote-access / recon / anti-forensics toolset on 2016-06-21. I recorded events/findings in ledger/ledger.md and extracted supporting files under work/extracted/leftovers (all hashed). Highlights: TeamViewer_Setup-vfa.exe downloaded 2016-06-21T00:52:02Z, TeamViewer 11 installed as admin and service added at ~00:57Z (TV11Install.log); Tor Browser installer executed 2016-06-21T10:51:23Z; BCWipe installed 2016-06-21T11:44:42Z and BCWipe.exe run 2016-06-21T12:01:05Z; PuTTY executed 2016-06-21T11:55:39Z; Nmap scan of scanme.nmap.org / 45.33.32.156 started 2016-06-21T12:10:43Z from Users/Hunter/Desktop/nmapscan.xml. Note: xmlUpdater.exe in Temp is benign Notepad++ xmlUpdater (strings show c:\Users\Don\source\notepad++...).


---

---
id: 12
thread: main
from: system
to: s0ae905
tag: ask
---

s0ae905: that is the 8th bash call starting with `python3`. A tool forged with make_tool would run it by name with typed arguments, for you and for every peer, and its calls would be on the trace. Consider forging one.


---

---
id: 13
thread: main
from: system
to: s0ae904
tag: ask
---

s0ae904: that is the 8th bash call starting with `python3`. A tool forged with make_tool would run it by name with typed arguments, for you and for every peer, and its calls would be on the trace. Consider forging one.


---

---
id: 14
thread: main
from: s0ae900
to: all
tag: result
---

s0ae900 disk triage update: wrote `work/disk_triage.md` and added ledger events/findings. Strong path-level sequence under `Users/Hunter`: (1) `Documents/Accounts.txt` / `tools.txt` plus matching copies in Dropbox and Google Drive around 2016-06-21 01:46-01:56 UTC; `Accounts.txt` contains `ptehmsgs @ gmail` and `HunterPTEH`. (2) `Dropbox/Pictures.7z` at 01:52 UTC. (3) `Documents/Confidential Document.docx` and `.pdf` at 01:58-01:59 UTC. (4) Tor Browser installer at 10:48 UTC, CCleaner install at 11:43 UTC, BCWipe install at 11:44 UTC. (5) deleted Recent link `fakeporn.7z.lnk` at 11:48 UTC. (6) `Dropbox/Info/TechnialInfo.txt` at 11:52 UTC containing “Some Exfil videos you might want to check”. (7) `Documents/Outlook Files/backup.pst` at 13:13:43 UTC, then `Dropbox/Outlook/backup.pst` at 13:14:59 UTC. Important nuance: the two PSTs are same-named and same-sized (10,429,440 bytes) but not byte-identical by SHA-256, so I phrased this as local PST creation followed by a same-named/same-sized PST being placed into Dropbox ~76s later, not a proven exact copy. Editor/timeline seat: please pull from ledger/ledger.md and my note file.


---

---
id: 15
thread: main
from: s0ae903
to: all
tag: result
---

Important addendum from s0ae903: TeamViewer was not only installed; Program Files (x86)/TeamViewer/Connections_incoming.txt records an incoming remote-control session for user Hunter from partner ID 547298337 / alias PSUT1: `21-06-2016 12:05:30` to `21-06-2016 12:14:29` (time format as stored). This is corroborated by TEAMVIEWER.EXE and TEAMVIEWER_DESKTOP.EXE prefetch updates at 2016-06-21T12:00:53Z and 2016-06-21T12:05:41Z. I added an event and IOC to ledger/ledger.md.


---

---
id: 16
thread: main
from: s0ae902
to: all
tag: result
---

s0ae902 result: despite no standalone RAM image, the TeamViewer artifacts are strong and likely central.

I wrote `work/memory-findings.md` with citations.

High-value findings:
1. `Program Files (x86)/TeamViewer/Connections_incoming.txt` inode `1418-128-1` records an incoming TeamViewer session:
   `547298337\tPSUT1\t21-06-2016 12:05:30\t21-06-2016 12:14:29\tHunter\tRemoteControl\t{DFB7FCA2-0F07-4468-BE01-67D73CD83B3A}`
   Extract hash: `345ec858b644ae6b4807e5a42b6ce0878de3689a16840a7851f6790fe4d3778c`

2. `Program Files (x86)/TeamViewer/TeamViewer11_Logfile.log` inode `88429-128-4` corroborates the same session and host/partner IDs:
   - host GUI started for `4orensics\\hunter`
   - local TeamViewer ClientID `543055371`
   - incoming session `456742019`
   - `client hello received from 547298337`
   - `AuthOk with SRP(DynamicPassword)`
   - participant `PSUT1`
   - session ended at `2016/06/21 05:14:29.054` local
   Full extract hash: `eaccf594b5daeb04a3c76028311bb3964d62018dbd4e35d2b24ec62f31f11c94`
   Focused excerpt hash: `67dd3a378dddb90def42dea49301aebcf81d63eb5a675ad1ee768ad47a427571`

3. Same TeamViewer log proves enabled capabilities during the live session:
   - `StreamType_Clipboard`
   - `StreamType_File`
   - access control line shows `RemoteControl='Allowed', FileTransfer='Allowed', AllowVPN='Allowed'` etc.

4. During that incoming session, TeamViewer hook/shared-memory components touched active user apps:
   `explorer.exe`, `googledrivesync.exe`, `chrome.exe`, `skype.exe`, `firefox.exe`, `dropbox.exe`, `ccleaner64.exe`, `zenmap.exe`.
   Excerpt hash: `635368fbbf0177ffeed609fd4fa9767b752b3bcf78cc229df9d4b214730b9e52`

5. Installation evidence:
   `Users/Hunter/AppData/Local/Temp/TeamViewer/TV11Install.log` inode `88424-128-4` shows TeamViewer install under Hunter SID, service install, firewall exceptions, and Outlook add-in registration.
   Extract hash: `90d2c1770ec0373c77a56547324d856c15d485369a3a5131920ab77534176817`

I also recorded ledger items for the PSUT1 IOC and TeamViewer session start/end. Editor/timeline seat: please pull from `work/memory-findings.md` and `ledger/ledger.md`. Leftovers/software seats: this likely overlaps your TeamViewer angle; feel free to reuse/cross-check my cited extracts.


---

---
id: 17
thread: main
from: s0ae903
to: s0ae906
tag: result
---

s0ae903 finished first pass on work/leftovers.md and claimed evidence is backed by filelist/timeline plus targeted icat extracts. Strongest citations: TeamViewer install/service from Users/Hunter/AppData/Local/Temp/TeamViewer/TV11Install.log; incoming remote-control session from Program Files (x86)/TeamViewer/Connections_incoming.txt; Nmap activity from Users/Hunter/Desktop/nmapscan.xml and Users/Hunter/.zenmap/target_list.txt; BCWipe install/use from Program Files (x86)/Jetico/BCWipe/UnInstall.log plus BCWIPE*.pf. I also note no obvious resident web root/web shell in filelist, and xmlUpdater.exe is benign Notepad++ helper.


---

---
id: 18
thread: main
from: system
to: s0ae906
tag: ask
---

s0ae906: that is the 8th bash call starting with `python3`. A tool forged with make_tool would run it by name with typed arguments, for you and for every peer, and its calls would be on the trace. Consider forging one.


---

---
id: 19
thread: main
from: s0ae901
to: all
tag: result
---

s0ae901 update: `work/accounts-registry-findings.md` now has a full evidence-backed registry/event-log writeup. High-confidence points: (1) current host is Windows 8.1 Enterprise, computer name `4ORENSICS`/`4orensics`, Pacific time; (2) `Hunter` (`S-1-5-21-2489440558-2754304563-710705792-1001`) is the only human account seen in interactive 4624 logons; (3) `Hunter` was created at 2016-06-21T08:37:43Z and added to local Administrators seconds later (Security 4720/4732); (4) System 7045 shows `TeamViewer 11` service install at 2016-06-21T00:57:41Z; (5) Hunter `NTUSER.DAT` UserAssist shows launches of TeamViewer, PuTTY, Nmap/Zenmap, CCleaner, Python IDLE, Word, ChromeSetup, and SkypeSetup; (6) Security 4616 shows VBoxService moved the clock backward twice, so chronology around the late sessions needs care. I pushed the key dated events/findings into `ledger/ledger.md` already. Suggest s0ae903/s0ae905 correlate TeamViewer/Nmap/PuTTY/CCleaner artifacts and s0ae904 account for the 4616 time jumps in the merged timeline.


---

---
id: 20
thread: main
from: s0ae902
to: all
tag: result
---

s0ae902 follow-up: s0ae901's timezone confirmation (Pacific time) resolves the TeamViewer local-vs-UTC issue. On the June dates in question that is UTC-7, which matches the TeamViewer router-clock drift I observed. So the TeamViewer log's `2016/06/21 05:05:31` incoming-session line corresponds to about `2016-06-21T12:05:31Z`, consistent with `Connections_incoming.txt` start `2016-06-21 12:05:30` and end `12:14:29`.


---

---
id: 21
thread: main
from: s0ae903
to: s0ae904
tag: result
---

Timing note from s0ae903 for timeline merge: my TeamViewer `Connections_incoming.txt` entry (`21-06-2016 12:05:30` to `12:14:29`) is recorded exactly as stored in the file, but I only rated the UTC ledger conversion medium confidence because TeamViewer/local timestamps may need reconciliation with s0ae901's Security 4616 clock-change findings. The corroborating Prefetch anchors are `TEAMVIEWER.EXE` 2016-06-21T12:00:53Z and `TEAMVIEWER_DESKTOP.EXE` 2016-06-21T12:05:41Z.


---

---
id: 22
thread: main
from: s0ae901
to: all
tag: result
---

Forged tool `evtx_filter` v1 (python3): Parse a Windows EVTX file and return JSON records filtered by event IDs and optional text match. Params: path?: string, event_ids?: array, contains?: string, limit?: integer. Example: {"path":"work/s0ae901/extracted/Security.evtx","event_ids":[4624,4672],"contains":"Hunter","limit":10} It is in your tool list after your next inbox or wait.


---

---
id: 23
thread: main
from: s0ae901
to: s0ae906
tag: result
---

Editor note from s0ae901: for attribution, my strongest seat-specific statement is not just that `Hunter` exists, but that `Hunter` is the *only* human account seen in interactive Security 4624 logons, with special-privilege 4672 events attached to those sessions. Combined with your confidential-document artifact chain and the TeamViewer evidence from s0ae902/s0ae903, that makes `Hunter` the defensible actor account in the report. Use my note’s EventRecordIDs 139/148/151-153/606-608/757-759 plus the 4616 clock-back events when you draft Q2/Q7.


---

---
id: 24
thread: main
from: s0ae905
to: all
tag: result
---

**s0ae905 (provenance) — `work/software.md` written.**

OS: **Windows 8.1 Enterprise** (build 9600, x64), registered to **Hunter**, installed 2016-06-21 08:37:45 UTC, single interactive admin user (SID ...-1001).

Installed-software inventory is now documented from the SOFTWARE hive Uninstall keys (x64 + WOW6432Node), on-disk dir birth-times, the `Users/Hunter/Downloads` installers, and SYSTEM services. Highlights:

| Category | Software |
| --- | --- |
| Remote access | TeamViewer 11 (service auto, partner PSUT1 session 12:05–12:14Z) |
| Anonymity | Tor Browser 6.0.1 |
| Network recon/sniff | Nmap 7.12, Wireshark 2.0.4, WinPcap 4.1.3, USBPcap 1.1, Burp Suite 1.7.03, PuTTY/PSCP/SSH |
| Secure-delete / wiping | BCWipe 6.0 (BCWipeSvc auto), Eraser 6.2, CCleaner 5.19 |
| Forensic | FTK Imager, Hash Suite 3.4, Sysinternals Suite, OllyDbg 1.10 |
| Cloud / sync | Dropbox 4.4.29, Google Drive 1.30 |
| Dev / runtime | Python 2.7.11 & 3.5.1, Java 8u91, VS C++ 2008/2013 |
| Office / business | MS Office Pro Plus 2013, Adobe Reader DC, Chrome 51, Skype 7.25, Notepad++, 7-Zip, McAfee, TrueKey |

Provenance: everything was installed system-wide from Hunter's session in **two bursts** — 2016-06-20 23:48–02:06 UTC (McAfee, Office, TeamViewer, Drive/Dropbox, FTK Imager, PuTTY/PSCP/SSH) and 2016-06-21 08:41–11:55 UTC (the bulk toolkit), with CCleaner run 12:28Z and FTK Imager run 13:18Z. Installers sit in `Users/Hunter/Downloads`; several carry `:Zone.Identifier` (ZoneId=3, internet).

**Correction note for the timeline seat:** my ledger record for the BCWipe install (seq 81) has a typo in the raw epoch — the correct dir crtime is **1466509484** (= 2016-06-21 11:44:44 UTC), not 1466473484. `work/software.md` has it right.

Evidence: hives in `work/s0ae905/extracted/` (SOFTWARE sha256 e9beb711…, SYSTEM sha256 e75b343a…); full tables in `work/software.md`.


---

---
id: 25
thread: main
from: s0ae904
to: all
tag: result
---

s0ae904 timeline/ledger seat — `work/timeline.md` is written and passes its check (64 table rows, ≥40 required; ledger now has 62 dated events, ≥10 required).

What I did:
- Mined the MAC timeline + bodyfile for the violation window (2016-06-20/21) and recorded dated events into the ledger (downloads, tool installs/executions, document creation, USB connections, clock changes) with inode/registry/event-log evidence.
- System profile (from hives): Windows 8.1 Enterprise (build 9600), computer `4ORENSICS`, owner `Hunter`, time zone **Pacific (PDT, UTC-7)**, SAM users Administrator/Guest/HomeGroupUser$/Hunter (RID 1001).
- Reconstructed execution timeline from Prefetch (.pf mtimes): putty/pscp → TeamViewer → Google Drive/Dropbox → FTK Imager → Chrome → Skype → Wireshark/WinPcap → Tor → Nmap/Zenmap → Python → CCleaner/BCWipe → TeamViewer remote session → Outlook → FTK Imager.
- **Clock coherence:** Security.evtx EventID 4616 shows VBoxService rolled the guest clock back ~10h TWICE (ER 583: 09:48:20→23:48:21Z; ER 732: 11:41:04→01:41:06Z), so wall-clock timestamps are non-monotonic — the event-log record order and artifact sequence are the reliable ordering. Flagged in the timeline header.

`work/timeline.md` is a merged table (UTC + local PDT) built from `ledger/ledger.md`. I'll keep re-rendering it as peers add events. Critic (s0ae906): feel free to pull from it for report question 7.


---

---
id: 26
thread: main
from: s0ae904
to: all
tag: result
---

Forged tool `inputs_check` v1 (python3): Verify inputs/ is byte-for-byte unchanged: computes SHA256 of every file under inputs/ and compares to the expected hashes recorded in inputs.json. Returns JSON {ok, files:[{path,bytes,sha256,match}]}. Params: quick?: boolean. It is in your tool list after your next inbox or wait.


---

---
id: 27
thread: main
from: s0ae902
to: all
tag: result
---

s0ae902 ran forged tool `inputs_check` (full run, not quick). Result: `ok: true`; all three read-only inputs match expected hashes, including `inputs/4orensics.001` SHA-256 `44d7e017fc023490c19729a63e25ce79ad2fdc0c69b31a765fb1a737cc5e1eea`. This should satisfy the `inputs_check` trace requirement in SWARM.md's checks.


---

---
id: 28
thread: main
from: s0ae900
to: all
tag: result
---

s0ae900 ran forged tool `inputs_check` (full, not quick). `inputs/` matches expected hashes byte-for-byte: `inputs/4orensics.001` sha256 `44d7e017fc023490c19729a63e25ce79ad2fdc0c69b31a765fb1a737cc5e1eea`, `inputs/CASE.md` sha256 `11219efd24923afe7bd551384543f8489183e66ca0c46ec6dc6d05efd67cb69c`, `inputs/README.txt` sha256 `9dee2f0374c00b51e6da05c8b606676a87c596cfa4f1ce2f5b8a97b9d6829d2a`. This should satisfy the `inputs_check` trace requirement in SWARM.md.


---

---
id: 29
thread: main
from: s0ae906
to: all
tag: result
---

**SIGN-OFF — s0ae906 (critic & editor).**

`work/report.md` is assembled from all six seats' notes + the ledger, and answers questions 1–8 under the required headings (`## 1.` … `## 8.`). Every claim carries a path/inode, registry key, hash, command, or ledger record id.

**What I independently verified against the image before signing:**

- **Conf.jpg = Confidential Document.pdf** — `icat` inodes 1450 and 23853, both 338,662 B, MD5 `bd1bf0f092e4df9e194c222d711af55b`, both `PDF document, version 1.5` (§2/§4).
- **Skype smoking gun** — `main.db` (inode 85279) Messages: `hunterehpt` ↔ `linux-rul3z` "Data Exfiltration" chat 00:36:28Z, TeamViewer request 00:47:17Z, `fakeporn.7z` share 11:48:37Z "Nice pics;)" (§2/§6).
- **USB** — `SYSTEM\Enum\USBSTOR` (inode 44235): Imation Nano Pro (`0718:063D`/`07B20C03C80830A9`, 01:53:14Z) and Lexar JumpDrive (`05DC:A202`/`AAI6UXDKZDV8E9OU`, 02:01:59Z, `\DosDevices\E:`); `MountedDevices` + Hunter `MountPoints2` (§5).
- **TeamViewer remote session** — `Connections_incoming.txt` (inode 1418) `547298337 PSUT1 … 12:05:30 → 12:14:29 RemoteControl`, corroborated by `TeamViewer11_Logfile.log` (§2/§3).
- **Cross-seat consistency** — disk_triage, accounts-registry, memory, leftovers, software, and timeline notes all agree with the ledger (62 events, 84+ records); no conflicting claims found.

**Definition-of-done checks (all pass):**
- `work/report.md` present, `## 1.`–`## 8.` all present.
- `work/timeline.md` present with **64** `| ` rows (≥40); merged from the ledger.
- `ledger/entries.jsonl` has **62** `"kind":"event"` entries (≥10).
- `inputs/` unchanged — `inputs_check` returns `match: true` for all 3 files (SHA-256 of `4orensics.001` = `44d7e017…c5e1eea`).

Caveats I preserved in the report (not hidden): the VBoxService clock rollback (~10h twice), the "ptehmsgs/HunterPTEH" vs "ehptmsgs/hunterehpt" note-file discrepancy, the two `backup.pst` being same-size-but-not-byte-identical, and the absence of a memory image.

Ready for the harness sentinel.


---

---
id: 30
thread: main
from: system
to: all
tag: stop
---

done/SWARM_DONE written by s0ae900: completed_assigned_disk_triage_and_editor_signoff_posted_definition_of_done_met. Output: `work/report.md`. Everyone else: call done and stop.

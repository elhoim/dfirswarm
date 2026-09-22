# Case ALIHADI-C2 — User Policy Violation Case

Examiner: Halil Ozturkci · Evidence: `inputs/4orensics.001` (single NTFS volume, no partition table,
MD5 `688cf22a83c290ba55fa08fbce69027d`). All times UTC unless noted. Citations are
**path + inode / registry key / command / ledger record** so every claim is checkable.

---

## 1. System profile

| Field | Value | Evidence |
| --- | --- | --- |
| OS | Windows 8.1 **Enterprise**, build `9600.17031.amd64fre.winblue_gdr.140221-1952` (x64) | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` (inode `45570-128-3`), ProductName/BuildLabEx |
| Install date | 2016-06-21 08:37:45 UTC | registry `InstallDate` = epoch `1466498265` (inode `45570`) |
| Registered owner | `Hunter` | `SOFTWARE\...\CurrentVersion\RegisteredOwner` |
| Computer name | `4ORENSICS` / `4orensics` (renamed `WIN-A9KKHBKS7E6` → `WIN-0Q61PC073B6` → `4orensics`) | `SYSTEM\ControlSet001\Control\ComputerName`; System.evtx EventID 6011 (ER 1, 55, 187) |
| Time zone | Pacific Standard Time (UTC-8; PDT UTC-7 in June 2016), Bias 480, ActiveBias 420 | `SYSTEM\ControlSet001\Control\TimeZoneInformation` |
| Network | DHCP `10.0.2.15/24`, gateway `10.0.2.2`, DNS `10.0.2.3` (VirtualBox NAT); public IP `188.247.76.33` (Jordan) observed as SMTP source | `SYSTEM\...\Tcpip\Parameters` + `Interfaces\{8CB9FBF6-...}`; Outlook SMTP log (inode `87292`) |
| Virtualization | VirtualBox guest | drivers `VBoxGuest/VBoxMouse/VBoxSF/VBoxService` (`SYSTEM\ControlSet001\Services`); USB input VID_80EE PID_0021 (VirtualBox tablet) |

### User accounts (SAM + Security.evtx)

| Account | RID | SID | Status | Creation | Last interactive logon |
| --- | ---: | --- | --- | --- | --- |
| Administrator | 500 | `S-1-5-21-2489440558-2754304563-710705792-500` | disabled | (pre-image) | 2014-03-18 |
| Guest | 501 | `...-501` | disabled | (pre-image) | — |
| **Hunter** | 1001 | `S-1-5-21-2489440558-2754304563-710705792-1001` | **local Administrator** | 2016-06-21 08:37:43Z (Security ER 139, Evt 4720) | 2016-06-21 08:37:45Z, 01:42:40Z, 23:49:02Z (Evt 4624/4672) |
| HomeGroupUser$ | 1003 | `...-1003` | service account | 2016-06-21 08:40:06Z (Evt 4720) | — |

Machine SID: `S-1-5-21-2489440558-2754304563-710705792` (SAM). Hunter was added to the **Administrators**
group seconds after creation (Security ER 148, Evt 4732, 08:37:43Z). Hunter is the only human account
with interactive 4624 logons.

---

## 2. What is the policy violation?

**Hypothesis (now proven): unauthorized data exfiltration.** The sole interactive user `Hunter`
conspired with an external party to move confidential pictures and documents **outside** a monitored
network, bypassing controls and covering tracks.

**Who:** `Hunter` (Skype `hunterehpt`, Gmail `ehptmsgs@gmail.com`, Jordan/Amman) ↔ external contact
`linux-rul3z` ("Linux rul3z", Iraq), and a TeamViewer remote partner `PSUT1` (ID `547298337`).

**What/When — the smoking gun (Skype chat, `Users/Hunter/AppData/Roaming/Skype/hunterehpt/main.db`, inode `85279`):**

- 2016-06-21 00:36:28Z — Hunter's contact request to `linux-rul3z`: *"I need your help with Data Exfiltration."*
- 00:37–00:40Z — Hunter: *"I have some pics that need to send outside my network … our network is monitored …
  I need to bypass their censorships … I need to get access to documents and send them."*
- 00:47:17Z — `linux-rul3z`: *"can you install team viewer?"*; Hunter agrees and says he will email the Hotmail
  account (same as the Skype name).
- 11:48:37Z — Hunter shares a file named **`fakeporn.7z`** via Skype (docid `0-weu-d2-a958c1f0bec3eaa30bcef8d795c8ff63`),
  then 11:48:46Z *"Nice pics;)"*.

**Corroborating artifacts (who did what):**

- `Users/Hunter/Documents/Conf.jpg` (inode `1450-128-1`) is a **byte-for-byte copy** of
  `Confidential Document.pdf` (inode `23853-128-4`) — both 338,662 B, MD5 `bd1bf0f092e4df9e194c222d711af55b`,
  both "PDF document, version 1.5". A confidential PDF disguised with a `.jpg` extension.
- `Users/Hunter/Dropbox/Pictures.7z` (inode `986-128-1`) is a 7-Zip archive with **encrypted header**
  (contents hidden), staged in Dropbox at 2016-06-21 01:52:17Z.
- `Users/Hunter/AppData/Roaming/Microsoft/Windows/Recent/fakeporn.7z.lnk` (inode `89547-128-4`, deleted)
  proves `fakeporn.7z` was opened/created; created 11:48:37Z, deleted ~12:01:46Z.
- TeamViewer was installed (00:57:41Z, service 7045) and an **incoming RemoteControl session** from
  `PSUT1` / `547298337` ran 12:05:30Z → 12:14:29Z with remote control, file transfer, clipboard, chat
  and VPN all **Allowed** (`Program Files (x86)/TeamViewer/Connections_incoming.txt` inode `1418`;
  `TeamViewer11_Logfile.log` inode `88429`).
- An Outlook `backup.pst` was created locally (inode `87318-128-3`, 13:13:43Z) and a same-named,
  same-sized copy placed in `Users/Hunter/Dropbox/Outlook/backup.pst` (inode `87323-128-3`, 13:14:59Z).

**Conclusion:** Hunter intentionally planned and carried out exfiltration of confidential data, used a
confidential PDF disguised as an image and encrypted/disguised 7z archives, enlisted an outside party
over Skype, granted remote access via TeamViewer, and staged/exported data to Dropbox/Google Drive —
a clear user policy violation.

---

## 3. Program execution

Execution is proven by Prefetch (`.pf`), UserAssist (Hunter NTUSER.DAT), and installer/service artifacts.
All runs are Hunter's (single interactive, admin user).

| UTC | Program | Evidence |
| --- | --- | --- |
| 00:57:32Z | TeamViewer installer stage | `Windows/Prefetch/TEAMVIEWER_.EXE-C5E613E0.pf` |
| 10:51:23Z | Tor Browser installer | `TORBROWSER-INSTALL-6.0.1_EN-U-46D64A96.pf` |
| 11:01:39Z | Nmap 7.12 setup | `NMAP-7.12-SETUP.EXE-161EFF0D.pf`; `WINPCAP-NMAP-4.13.EXE-669D99C3.pf` |
| 11:44:42Z | BCWipe setup | `BCWIPESETUP.EXE-AB2C77E1.pf` |
| 11:54:43Z / 11:54:58Z | Process Explorer / Process Monitor | `PROCEXP.EXE-C8833FC0.pf`, `PROCMON.EXE-18CE4939.pf` |
| 11:55:39Z | PuTTY | `PUTTY.EXE-6CB315A8.pf` (UserAssist 11:55:37Z shortcut) |
| 12:00:53Z | TeamViewer client | `TEAMVIEWER.EXE-F6CE775B.pf` |
| 12:01:05Z | BCWipe | `BCWIPE.EXE-36F3F2DF.pf` |
| 12:05:41Z | TeamViewer desktop (session) | `TEAMVIEWER_DESKTOP.EXE-206BAA88.pf` |
| 12:08:21Z / 12:11:01Z | Zenmap / Nmap | `ZENMAP.EXE-56B17C4C.pf`, `NMAP.EXE-50E1AF31.pf`; scan args `nmap -T4 -A -v scanme.nmap.org` in `Desktop/nmapscan.xml` (inode `2573`) |
| 12:14:43Z | MSHTA (TeamViewer 7.hta) | `MSHTA.EXE-854F6B45.pf` |
| 12:26:45Z | Word 2013 | `WINWORD.EXE-CECBA770.pf` |
| 12:28:08Z / 12:28:17Z | CCleaner | `CCLEANER.EXE-D4D76A60.pf`, `CCLEANER64.EXE-779BD542.pf` |
| 12:58:27Z | Outlook | `OUTLOOK.EXE-1DF422BF.pf` |
| 13:18:23Z | FTK Imager | `FTK IMAGER.EXE-393FFB9B.pf` |

UserAssist (Hunter NTUSER.DAT, inode `81365`) additionally shows launches of Chrome installer,
Skype installer/use, and Python IDLE (see accounts seat, ledger seq 64). Software inventory (Uninstall
keys) confirms the installed set: TeamViewer 11, Nmap 7.12, Wireshark 2.0.4 + WinPcap/USBPcap, Tor
Browser 6.0.1, CCleaner 5.19, BCWipe 6.0, Eraser 6.2, OllyDbg, Burp Suite, Sysinternals, Python 2.7/3.5.

---

## 4. Files of interest

| File (inode) | Why it matters | Evidence |
| --- | --- | --- |
| `Documents/Confidential Document.docx` (`23834-128-3`) | confidential doc authored 01:58:56Z | bodyfile crtime 1466474336; docx text "Confidential Document … PRIVATE … Hunter" |
| `Documents/Confidential Document.pdf` (`23853-128-4`) | PDF export 01:59:05Z | bodyfile crtime 1466474345 |
| `Documents/Conf.jpg` (`1450-128-1`) | **renamed copy of the PDF** (MD5 `bd1bf0f092e4df9e194c222d711af55b`) | icat inode 1450 vs 23853 → identical |
| `Dropbox/Pictures.7z` (`986-128-1`) | 7z with **encrypted header** (contents hidden) | `file` = "7-zip archive data"; `tar` = "archive header is encrypted" |
| `Recent/fakeporn.7z.lnk` (`89547-128-4`, deleted) | disguised archive opened | istat 89547; timeline 11:48:37Z |
| `Dropbox/Accounts.txt` (`1233-128-1`), `Dropbox/tools.txt` (`341-128-1`), `Documents/Accounts.txt` (`87926`), `Documents/tools.txt` (`87753`) | account notes + tool checklist | icat → "Email: ptehmsgs @ gmail", "Skype: HunterPTEH"; tools list |
| `Dropbox/Info/TechnialInfo.txt` (`110199-128-1`) | "Some Exfil videos you might want to check" | icat 110199 |
| `Dropbox/Outlook/backup.pst` (`87323-128-3`) + `Documents/Outlook Files/backup.pst` (`87318-128-3`) | Outlook mailbox export to Dropbox (10,429,440 B each; SHA-256 not identical → same-named export, not byte copy) | icat + shasum |
| `Google Drive/proposal.pdf` (`23855-128-5`) | file staged in Google Drive 02:03:42Z | timeline |
| DEFCON PDFs in `Documents/` (`92588`, `96260`, `92546`, `92585`, `92575`) | exfil/security research (all with `:Zone.Identifier`) | filelist + bodyfile |
| `$OrphanFiles/$IP1H3FM.7z` and `$IYNWCRM.7z` | deleted 7z archives (recoverable orphans) | filelist |

Deleted/recycled evidence: Recent LNKs `Confidential Document.lnk` (inode `22505`) and
`Confidential Document (2).lnk` (inode `23836`) were deleted; `fakeporn.7z.lnk` (inode `89547`) was
deleted ~12:01:46Z — consistent with cleanup by CCleaner/BCWipe.

---

## 5. USB and removable devices

Two USB mass-storage devices (`SYSTEM\ControlSet001\Enum\USBSTOR`, inode `44235`):

| Device | VID/PID | Serial | First connected (UTC) | Volume / drive |
| --- | --- | --- | --- | --- |
| **Imation Nano Pro** | `0718:063D` | `07B20C03C80830A9` | 2016-06-21 **01:53:14Z** | `{fb7f938e-37a4-11e6-8254-080027d269d7}`, mounted 01:59:52Z, no persistent letter |
| **Lexar JumpDrive** | `05DC:A202` | `AAI6UXDKZDV8E9OU` | 2016-06-21 **02:01:59Z** | `{fb7f93ec-37a4-11e6-8254-080027d269d7}`, **drive E:**, MountPoints2 last-write 02:02:04Z |

Evidence: `USBSTOR` first-install FILETIMEs (Properties `{83da6326-...}` values 0064/0065);
`SYSTEM\MountedDevices` maps `\DosDevices\E:` → Lexar USBSTOR path; `NTUSER.DAT\...\MountPoints2`
(inode `81365`) shows `{fb7f93ec-...}` with removable Autoplay shell. Context: the Lexar was connected
at 02:01:59Z, immediately after `Conf.jpg` was finalized (02:00:10–02:00:47Z) — consistent with copying
the disguised confidential document to removable media. (The CD-ROM `D:` is the VirtualBox `VBOX CD-ROM`.)

---

## 6. Communications

### Skype (inode `85279` main.db)

- Account: `hunterehpt` ("EHPT Msgs", `ehptmsgs@gmail.com`, jo/Amman). `config.xml` (inode `2433`) → `LastIpCountry jo`.
- Contact: `linux-rul3z` ("Linux rul3z", IQ).
- Chat (see §2) is the exfiltration smoking gun; `fakeporn.7z` shared 11:48:37Z, "Nice pics;)" 11:48:46Z.
- No calls/transfers rows in main.db (exfil used the cloud-share link, not P2P transfer).

### Email (Outlook + Gmail)

- Outlook configured for `ehptmsgs@gmail.com`; OST `ehptmsgs@gmail.com.ost` (inode `759`).
- Outgoing SMTP log (inode `87292`, 06:12:21 local = 13:12:21Z): EHLO `4orensics`, Gmail SMTP accepted
  (`250 OK 1466514743`), client IP `188.247.76.33` (Jordan). MAIL FROM/RCPT TO masked in log.
- Chrome history shows Gmail compose activity 11:30–11:32Z, 11:49–11:50Z, 12:18–12:19Z; "Sign-in attempt
  prevented" at 13:00:44Z; "Less secure apps" enabled 13:12:11Z (Google account settings) to allow the
  Outlook/Gmail access.

### Browsers (Chrome, `History` inode `83740`)

- 11:45:35–11:47:26Z: searches for "animals" / "cute animals" and image views — **cover images** for the
  disguised "pics" archives.
- 11:50:20Z: YouTube "DEFCON 16: New Tool for SQL Injection with DNS Exfiltration"; 11:57:11Z Gmail
  "DNS Exfil Videos".
- 12:18:12Z: "home-network-design-…jpg" image (the "products"/"misc docs" cover).
- 13:12:11Z: Google "Less secure apps" enabled for `ehptmsgs@gmail.com`.
- Internet Explorer: cached `settingsoverride[1].asp` (inode `87947`) is benign cached redirect content
  (see leftovers seat), no planted web shell.

### Cloud staging

- Dropbox (`Dropbox/` + `ProgramData/Dropbox`) and Google Drive (`Google Drive/`) were installed
  01:44–01:47Z and used to stage `Accounts.txt`, `tools.txt`, `Pictures.7z`, `proposal.pdf`,
  `Info/TechnialInfo.txt`, and the exported `Outlook/backup.pst`.

---

## 7. Timeline

Merged in `work/timeline.md` (58 dated rows, built from the ledger). Core sequence (UTC):

1. 23:48:21Z (06-20) clock rollback by VBoxService (Security 4616).
2. 00:36–00:48Z Skype chat soliciting data exfiltration from `linux-rul3z`.
3. 00:52–00:57Z TeamViewer downloaded and installed (service 7045).
4. 01:44–01:53Z Google Drive/Dropbox installed; `Accounts.txt`/`tools.txt`/`Pictures.7z` staged; Imation USB connected.
5. 01:58–02:03Z `Confidential Document.docx` → `.pdf` → `Conf.jpg` (rename); Lexar USB (E:) connected; `proposal.pdf` to Google Drive.
6. 08:37–08:40Z (re)install marker: Hunter account created + made admin; HomeGroupUser$ created.
7. 08:41–11:55Z toolkit installs: Chrome, Skype, 7-Zip, Notepad++, Wireshark/WinPcap/USBPcap, Java, Tor, Eraser, Hash Suite, Nmap, Sysinternals, Burp, OllyDbg, Python, CCleaner, BCWipe.
8. 11:45–11:52Z cover-image searches; `fakeporn.7z` created and shared over Skype; `TechnialInfo.txt`.
9. 12:05:30–12:14:29Z incoming TeamViewer RemoteControl session from `PSUT1` / `547298337` (file transfer/clipboard/VPN allowed).
10. 12:28Z CCleaner; 12:58Z Outlook; 13:13–13:15Z `backup.pst` exported to Dropbox; 13:18Z FTK Imager (last activity).

**Clock caveat:** two EventID 4616 records show VBoxService set the guest clock **back ~10 h** (09:48:20Z→23:48:21Z
and 11:41:04Z→01:41:06Z). Early-burst timestamps (23:48–02:06Z) therefore reflect a rolled-back guest clock;
the real chronological order is preserved but absolute wall-clock of that burst is ~10 h later than recorded.

---

## 8. Hypothesis, approach, and examiner notes

**Approach:** catalog-first (partitions/fsstat/bodyfile/filelist/mactime), then targeted `icat` extraction
of hives, EVTX, Prefetch, LNK, browser/Skype/Outlook databases, and USB keys; each finding recorded to the
ledger with source+evidence and cross-checked across at least two seats.

**Conclusion:** `Hunter` (the only interactive user, a local admin) solicited an external party
(`linux-rul3z`) to exfiltrate confidential documents/pictures, disguised a confidential PDF as
`Conf.jpg`, staged encrypted `Pictures.7z` and disguised `fakeporn.7z` archives, shared them via
Skype/Dropbox/Google Drive, granted a TeamViewer remote-control session (`PSUT1`), and ran anti-forensics
tooling (BCWipe, CCleaner, Eraser, Tor) to cover tracks — a clear **user policy violation**.

**Examiner notes:**

- `Accounts.txt` lists the email as "ptehmsgs @ gmail" and Skype "HunterPTEH" while the live artifacts are
  `ehptmsgs@gmail.com` and `hunterehpt` — a transcription discrepancy in the note file; the live DB/OST values are authoritative.
- The two `backup.pst` files are same-name/same-size but **not** byte-identical (different SHA-256), so they are a re-export/placement, not a proven copy.
- No standalone memory image exists (0 memory images in catalog); memory-adjacent conclusions derive from
  disk logs (TeamViewer), which are strong.
- No resident web shell was found; cached `.asp`/`.hta` files are benign (IE cache + TeamViewer wrapper).
- The VM clock was rolled back twice (~10 h) by VBoxService — see §7 caveat before interpreting absolute times.

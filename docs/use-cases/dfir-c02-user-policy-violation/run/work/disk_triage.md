# Disk triage (`s0ae900`)

## Scope

This note covers the on-disk layout, the main user-visible path set, and a path/timeline triage of likely attacker-added or attacker-touched files. All times below are **UTC** unless stated otherwise.

## Filesystem / partition summary

- `inputs/4orensics.001` has **no partition table**; it is a **single NTFS volume starting at sector 0**.
  - Evidence: `catalog/4orensics.001/partitions.txt`
- `fsstat` reports:
  - File system type: **NTFS**
  - OEM name: **NTFS**
  - Volume serial: `3C669B61669B1B2A`
  - NTFS version string: **Windows XP**
  - Sector size: **512**
  - Cluster size: **4096**
  - Root directory inode: **5**
  - Total sector range: `0 - 51707902`
  - Total cluster range: `0 - 6463486`
  - Evidence: `catalog/4orensics.001/p0/fsstat.txt`

## High-level user/profile triage

Top-level user profile paths visible in the catalog:

- `Users/Hunter`
- `Users/Public`
- `Users/Default`
- `Users/Default User`
- `Users/All Users`

The active user profile of interest is clearly **`Users/Hunter`**.

Evidence:
- `rg '^d/d .*\tUsers/[^/]+$' catalog/4orensics.001/p0/filelist.txt`

## Notable disk activity windows

### 1. Early cloud-staging activity: 2016-06-21 01:46-02:05

Hunter's profile contains both **Dropbox** and **Google Drive** staging areas with account notes and tool lists:

- `Users/Hunter/Documents/Accounts.txt` (inode `87926-128-1`)
- `Users/Hunter/Documents/tools.txt` (inode `87753-128-5`)
- `Users/Hunter/Dropbox/Accounts.txt` (inode `1233-128-1`)
- `Users/Hunter/Dropbox/tools.txt` (inode `341-128-1`)
- `Users/Hunter/Google Drive/Accounts.txt` (inode `1765-128-1`)
- `Users/Hunter/Google Drive/tools.txt` (inode `465-128-1`)

Content recovered with `icat`:

- `Accounts.txt` lists:
  - `Email: ptehmsgs @ gmail`
  - `Skype: HunterPTEH`
- `tools.txt` lists tools to install:
  - Chrome
  - Skype
  - Outlook / MS Office
  - Notepad++
  - 7zip
  - Wireshark
  - Adobe Reader

Also in this window:

- `Users/Hunter/Dropbox/Pictures.7z` (inode `986-128-1`, 1,849,480 bytes) appears at `2016-06-21T01:52:17Z`.
- `Users/Hunter/Documents/Confidential Document.docx` (inode `23834-128-3`) appears at `2016-06-21T01:58:56Z`.
- `Users/Hunter/Documents/Confidential Document.pdf` (inode `23853-128-4`) appears at `2016-06-21T01:59:05Z`.
- `Users/Hunter/Documents/Conf.jpg` (inode `1450-128-1`) is touched at `2016-06-21T01:59:27Z`.
- `Users/Hunter/Google Drive/proposal.pdf` (inode `23855-128-5`) appears at `2016-06-21T02:03:42Z`.
- `Users/Hunter/Google Drive/FTK-Imager.zip` (inode `1336-128-5`) appears at `2016-06-21T02:04:40Z`.

This window is strong evidence of cloud-storage setup and file staging under Hunter's account.

Primary evidence:
- `catalog/4orensics.001/p0/filelist.txt`
- `catalog/4orensics.001/p0/timeline.csv`
- `icat inputs/4orensics.001 1233-128-1`
- `icat inputs/4orensics.001 341-128-1`
- `icat inputs/4orensics.001 87926-128-1`
- `icat inputs/4orensics.001 87753-128-5`
- `istat inputs/4orensics.001 986`
- `istat inputs/4orensics.001 23834`
- `istat inputs/4orensics.001 23853`

### 2. Tool download / install burst: 2016-06-21 10:45-11:45

Within Hunter's profile and program directories, a late-morning burst shows privacy, remote-access, and anti-forensics tooling being added or installed:

- `Users/Hunter/Downloads/ccsetup519pro.exe` (inode `23945-128-5`) is touched at `2016-06-21T10:45:34Z`.
- `Users/Hunter/Downloads/torbrowser-install-6.0.1_en-US.exe` (inode `23999-128-9`) is touched at `2016-06-21T10:48:23Z`.
- `Users/Hunter/Desktop/Start Tor Browser.lnk` (inode `88611-128-4`) and `Users/Hunter/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Start Tor Browser.lnk` (inode `88610-128-4`) are created at `2016-06-21T10:54:03Z`.
- `Program Files/CCleaner` and its executables are created at `2016-06-21T11:43:02Z-11:43:08Z`.
- `Users/Hunter/Downloads/bcwipeSetup.exe` (inode `88689-128-5`) is touched at `2016-06-21T11:44:31Z`.
- `Program Files (x86)/Jetico/BCWipe` and related files are created at `2016-06-21T11:44:44Z-11:44:55Z`.

This is a clear on-disk tooling wave immediately before later suspicious path activity.

Primary evidence:
- `rg 'ccsetup519pro\.exe|torbrowser-install-6\.0\.1_en-US\.exe|Start Tor Browser\.lnk' catalog/4orensics.001/p0/filelist.txt`
- `rg 'ccsetup519pro\.exe|torbrowser-install-6\.0\.1_en-US\.exe|Start Tor Browser\.lnk' catalog/4orensics.001/p0/timeline.csv`
- `awk -F, '$1 >= "2016-06-21T11:43:00Z" && $1 <= "2016-06-21T11:45:01Z" {print}' catalog/4orensics.001/p0/timeline.csv | rg '/Program Files/CCleaner|/Program Files \(x86\)/Jetico/BCWipe|BCWIPESVC|BCWIPETM|bcwipeSetup'`

### 3. Suspicious file-use / exfil note window: 2016-06-21 11:46-11:52

This window contains notable user-path artifacts:

- A deleted Recent link for `fakeporn.7z`:
  - `Users/Hunter/AppData/Roaming/Microsoft/Windows/Recent/fakeporn.7z.lnk`
  - inode `89547-128-4`
  - created `2016-06-21T11:48:37Z`
  - later deleted, with MFT change at `2016-06-21T12:01:46Z`
- `Users/Hunter/Dropbox/Info/TechnialInfo.txt` (inode `110199-128-1`) is written at `2016-06-21T11:52:08Z`.
  - Recovered content includes: `Some Exfil videos you might want to check:` followed by several YouTube links and `Happy hunting Hunter :)`

Primary evidence:
- `rg 'fakeporn\.7z\.lnk|TechnialInfo.txt' catalog/4orensics.001/p0/filelist.txt`
- `rg 'fakeporn\.7z\.lnk|TechnialInfo.txt' catalog/4orensics.001/p0/timeline.csv`
- `istat inputs/4orensics.001 89547`
- `icat inputs/4orensics.001 110199-128-1`

### 4. Outlook export into Dropbox: 2016-06-21 13:13-13:15

This is one of the strongest discrete on-disk sequences in the image:

1. `Users/Hunter/Documents/Outlook Files/backup.pst` (inode `87318-128-3`) is created at `2016-06-21T13:13:43Z`.
2. `Users/Hunter/Dropbox/Outlook/backup.pst` (inode `87323-128-3`) is created at `2016-06-21T13:14:59Z`.
3. `Users/Hunter/AppData/Roaming/Microsoft/Windows/Recent/backup.pst.lnk` (inode `87321-128-4`) appears at `2016-06-21T13:15:00Z`.

Important nuance:
- The two PSTs have the **same size** (`10,429,440` bytes) and near-adjacent creation times.
- Their SHA-256 values are **not identical**:
  - `Documents/Outlook Files/backup.pst` (`87318`): `75fd7146b68c187acc16d51d93881fceabd76098148c637567286c57eef65be1`
  - `Dropbox/Outlook/backup.pst` (`87323`): `360ea985c749220df9b5bd5556b8831c6075a6a2d418220fe931960dccfbfed7`
- So I would phrase this as **a same-named, same-sized Outlook backup being created locally and then another same-named backup being placed into Dropbox about 76 seconds later**, not as a proven byte-for-byte copy.

Primary evidence:
- `rg 'backup\.pst' catalog/4orensics.001/p0/filelist.txt`
- `awk -F, '$1 >= "2016-06-21T13:10:00Z" && $1 <= "2016-06-21T13:16:59Z" {print}' catalog/4orensics.001/p0/timeline.csv | rg 'backup\.pst|Outlook'`
- `istat inputs/4orensics.001 87318`
- `istat inputs/4orensics.001 87323`
- `icat inputs/4orensics.001 87318 | shasum -a 256`
- `icat inputs/4orensics.001 87323 | shasum -a 256`

## Bonus: likely attacker-added or attacker-staged paths (inode proof)

| First seen (UTC) | Inode | Path | Why it matters |
| --- | --- | --- | --- |
| 2016-06-21T01:46:16Z | `1233-128-1` | `Users/Hunter/Dropbox/Accounts.txt` | Cloud-staging note with account identifiers (`ptehmsgs @ gmail`, `HunterPTEH`). |
| 2016-06-21T01:51:50Z | `341-128-1` | `Users/Hunter/Dropbox/tools.txt` | Tool-install checklist for Chrome, Skype, Outlook, 7zip, Wireshark, etc. |
| 2016-06-21T01:52:17Z | `986-128-1` | `Users/Hunter/Dropbox/Pictures.7z` | Archive staged directly in Dropbox. |
| 2016-06-21T01:58:56Z | `23834-128-3` | `Users/Hunter/Documents/Confidential Document.docx` | Sensitive-looking document created in user docs. |
| 2016-06-21T01:59:05Z | `23853-128-4` | `Users/Hunter/Documents/Confidential Document.pdf` | Sensitive-looking document created in user docs. |
| 2016-06-21T02:03:42Z | `23855-128-5` | `Users/Hunter/Google Drive/proposal.pdf` | File staged in Google Drive. |
| 2016-06-21T10:48:23Z | `23999-128-9` | `Users/Hunter/Downloads/torbrowser-install-6.0.1_en-US.exe` | Tor Browser installer in Downloads. |
| 2016-06-21T11:43:02Z | `88630-144-5` | `Program Files/CCleaner` | CCleaner installed on disk. |
| 2016-06-21T11:44:44Z | `109928-144-5` | `Program Files (x86)/Jetico/BCWipe` | BCWipe installed on disk. |
| 2016-06-21T11:48:37Z | `89547-128-4` | `Users/Hunter/AppData/Roaming/Microsoft/Windows/Recent/fakeporn.7z.lnk` | Deleted Recent link shows use/opening of `fakeporn.7z`. |
| 2016-06-21T11:52:08Z | `110199-128-1` | `Users/Hunter/Dropbox/Info/TechnialInfo.txt` | Dropbox note explicitly mentions “Exfil” videos. |
| 2016-06-21T13:13:43Z | `87318-128-3` | `Users/Hunter/Documents/Outlook Files/backup.pst` | Local Outlook backup export. |
| 2016-06-21T13:14:59Z | `87323-128-3` | `Users/Hunter/Dropbox/Outlook/backup.pst` | Same-named/same-sized Outlook backup placed in Dropbox. |

## Bottom line for the editor

From disk triage alone, the strongest path-based story is:

- Hunter set up **Dropbox** and **Google Drive** staging areas.
- Hunter stored **account notes** and a **tool-install checklist** under those cloud folders.
- Sensitive-looking user files were created (`Confidential Document.*`).
- A **Pictures.7z** archive was placed in Dropbox.
- Later, a same-named/same-sized **Outlook `backup.pst`** was created locally and then placed into **Dropbox/Outlook** within about a minute.
- The profile also shows a same-day install burst of **Tor Browser**, **CCleaner**, and **BCWipe**, plus a deleted Recent link for `fakeporn.7z` and a Dropbox note that explicitly references **“Exfil”** videos.

That combination makes cloud exfiltration / policy-violation activity a strong working hypothesis, with the disk artifacts above providing the path-level proof.
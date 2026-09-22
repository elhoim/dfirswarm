# ALIHADI-C3 — Mystery Hacked System — Final Report

**Assembled by:** `s9f2006` (critic/editor) from the seat notes and the swarm ledger.
**Case:** Windows 8.1 workstation image, single NTFS volume (`inputs/Windows8.1-Challenge3.001`, MD5 `9a737b6a21ecbe979126c5661ca7b8db`, no partition table — `catalog/.../partitions.txt`).
**Sources of truth:** `catalog/Windows8.1-Challenge3.001/p0/` (file list, body file, MAC timeline), the seat notes under `work/`, and `ledger/ledger.md` (all timestamps below are UTC unless noted).

> Confidence labels: **fact** = directly evidenced and cross-checked; **hypothesis** = interpretation requiring inference. Hypotheses are labelled as such.

---

## 1. The message

The employee ("master") reported finding a message written in a file. There are **two** attacker-written taunt text files; the one the employee demonstrably opened is **`C:\Tools\README.txt`**.

### `C:\Tools\README.txt` (the file the employee opened and reported)

| Field | Value |
| --- | --- |
| Path | `C:\Tools\README.txt` |
| Inode | `84614-128-1` (parent `C:\Tools`, inode `84609-144-1`, created `2015-12-12T03:23:52Z`) |
| Content | `Hello master,` `Catch me if you can!` `Best regards,` `Your Admin ;)` (69 bytes, CRLF) |
| Created | `2015-12-12T03:24:04Z` (05:24:04 guest-local) |
| Modified | `2015-12-12T03:24:39Z` |
| Accessed | `2015-12-12T03:24:04Z` |
| Owner (Security ID) | `S-1-5-32-544` (`BUILTIN\Administrators`) |

Evidence: `icat -o 0 inputs/Windows8.1-Challenge3.001 84614-128-1`; `istat` inode `84614`; `ledger/ledger.md` seq 5, 21.

How it got there: the employee opened it. `Users\master\AppData\Roaming\Microsoft\Windows\Recent\README.lnk` (inode `81247-128-1`, created `2015-12-12T03:27:14Z`) resolves to `C:\Tools\README.txt`, and a second LNK (inode `83399-128-1`, `03:27:23Z`) resolves to `C:\Tools`. This proves the "master" account opened/browsed the taunt after it was dropped (ledger seq 2, 28; `work/disk_triage.md` §5).

### Second copy: `C:\Users\master\Desktop\Docs\README.txt`

| Field | Value |
| --- | --- |
| Path | `C:\Users\master\Desktop\Docs\README.txt` |
| Inode | `84603-128-1` (parent `50988`) |
| Content | `Your admin says hi to you ;)` (28 bytes) |
| Created | `2015-12-12T03:23:31Z` |
| Modified | `2015-12-12T03:23:44Z` |
| Owner (Security ID) | `S-1-5-32-544` (`BUILTIN\Administrators`) |

Evidence: `icat -o 0 inputs/Windows8.1-Challenge3.001 84603-128-1`; `istat` inode `84603`; ledger seq 3, 13.

Both taunt files carry the **Administrators** group SID, not the `master` user SID — they were written by an Administrator/SYSTEM-level process, not the interactive `master` account (ledger finding #14).

### Not the message (context)

`C:\Users\master\Desktop\Docs\Info.txt` (inode `83074-128-1`, `64` bytes) contains `Nothing really interesting, just practicing some type writing :)`, created `2015-12-12T03:08:54Z` and owned by `S-1-5-21-2733037674-494817684-1624540804-1001` (the `master` user, not Administrators). It is a different file created in the `master` session and is a red herring / the employee's own note, not the reported message (ledger seq 14, 16).

---

## 2. How the system was hacked

**Hypothesis (high confidence):** the attacker installed the classic **"Ease of Access" accessibility backdoor** — they replaced `C:\Windows\System32\Magnify.exe` with a byte-for-byte copy of `cmd.exe` — and then used it to obtain a **SYSTEM command prompt from the Winlogon (login) screen**, with **no credentials**. Initial access was **physical / local-console access** to the (VirtualBox) machine, not a network, service, or credential-exploitation path.

### The backdoor (fact)

- Current `C:\Windows\System32\Magnify.exe` (inode `2043-128-2`) is **byte-identical** to `C:\Windows\System32\cmd.exe` (inode `41024-128-3`):
  - MD5 `fc0b4a626881d7c5980d757214db2d25` (both)
  - SHA-256 `0b9bc863e2807b6886760480083e51ba8a66118659f4ff274e7b73944d2219f5` (both)
  - Size `355840` bytes (both)
- The original Magnifier was `837632` bytes and survives as the deleted/reallocated inode `42335-128-3` (MFT-modified `2015-12-11T19:18:48Z`); the replacement was created `2015-12-11T19:18:54Z` (`istat` inode 2043).

Evidence: `icat ... 2043` == `icat ... 41024`; `cmp`/`md5`/`shasum`; ledger seq 8, 9, 22; `work/leftovers.md` §2; independently re-verified by `s9f2001`.

**Mechanism (fact + well-known technique):** on the Windows login screen, `Win+U` / the Ease-of-Access (Magnifier) button runs `Magnify.exe` as **SYSTEM** without authentication. With `Magnify.exe` being `cmd.exe`, that action opens a SYSTEM shell. This is why the account manipulation below could occur **before any account logged on**.

### Why this fits the observed account activity (fact)

- The local account `master` was created **in SYSTEM context** at `2015-12-12T03:02:42Z` — Security.evtx `4720` record 126 shows `SubjectUserSid = S-1-5-18` (SYSTEM) and the machine account as subject — **before** any `master` logon. It was immediately added to `Users` (`4732` rec 127) and `Administrators` (`4732` rec 135), enabled, and had its password set (`4724` recs 131/134) in under one second.
- The first `master` interactive logon follows at `2015-12-12T03:03:16Z` (logon type 2, `winlogon.exe`, `127.0.0.1`).
- Prefetch shows `NET.EXE`/`NET1.EXE`, `SC.EXE`, `TAKEOWN.EXE`, `MAGNIFY.EXE`, `UTILMAN.EXE` executed in the intrusion window.

Evidence: `evtx_filter` on `Security.evtx`; ledger seq 32, 33, 34, 35, 39; `work/accounts-registry-findings.md`; `work/leftovers.md` §3.

### Initial access: physical / local console (hypothesis)

- **No** successful RDP-style logon (4624 type 10) and **no** attacker logon tied to a remote IP: every `master`/`Administrator` session is a local-console `LogonType=2` via `winlogon.exe` with `IpAddress=127.0.0.1` (ledger finding #38; `work/accounts-registry-findings.md`).
- The machine is a **stock VirtualBox guest** with **no third-party software** except VirtualBox Guest Additions, and **no malicious service/driver** (ledger finding #26; `work/software.md`), ruling out an installed remote-access tool.
- No web shell or attacker scheduled task was found (`work/leftovers.md` §4).

Therefore the evidence points to someone with **console/physical (or VM console) access** who planted and then used the accessibility backdoor. The precise first foothold (how the attacker obtained the initial write to `System32` to plant the backdoor) is not directly evidenced; consistent with a freshly-provisioned VM under attacker control, it is stated here as a **hypothesis** (physical/local access), not a proven network/service exploit.

---

## 3. Evidence that proves the intrusion

### Accounts and logons (fact — Security.evtx + SAM)

- `master` (RID 1001, SID `S-1-5-21-2733037674-494817684-1624540804-1001`) **created** `2015-12-12T03:02:42.943Z` (`4720` rec 126, subject `S-1-5-18` SYSTEM).
- `master` added to `Users` (`4732` rec 127) and `Administrators` (`4732` rec 135); enabled (`4722` rec 128, `4738` UAC `0x15->0x14->0x214`); password set (`4724` recs 131/134). SAM `PasswordLastSet` matches `03:02:42Z`.
- `master` interactive logon `03:03:16.724Z` (`4624` rec 138/139, type 2) and again `03:26:53.711Z` (rec 308/309).
- Built-in `Administrator` (RID 500) **enabled** `03:21:08.401Z` (`4722` rec 202, `4738` rec 203 UAC `0x211->0x210`), **logged on** `03:22:19.527Z` (rec 231) and `03:25:14.427Z` (rec 263, type 2), then **disabled** again `03:26:19.740Z` (`4738` rec 280 UAC `0x210->0x211`).
- `Administrator`'s password was **never changed** since install media (`2014-03-18`), and `Windows/debug/PASSWD.LOG` is **empty** — so the account changes were made by `net user`/direct SAM write, not the Change-Password API (`work/software.md`).

### Event log records (fact)

`Security.evtx` records 125–135 (account creation/privilege burst), 137–140 (`master` logon), 145–174 (`4797` — `master` querying `Administrator`/`Guest` account state), 202–203 (Administrator enable), 230–232 & 262–264 (Administrator logons), 280 (Administrator disable), 333 (`4616` clock rollback by `VBoxService.exe`).

### Malware / tools on disk (fact)

- `C:\Windows\System32\Magnify.exe` = `cmd.exe` (the backdoor), MD5 `fc0b4a626881d7c5980d757214db2d25`.
- Prefetch execution of `TAKEOWN.EXE` (last run `03:28:24Z`), `SC.EXE` (`03:26:03Z`), `NET1.EXE` (`03:05:50Z`), plus `MAGNIFY.EXE`/`UTILMAN.EXE` (ledger seq 29, 30, 31; `work/leftovers.md` §3).
- `C:\Users\master\AppData\Local\Temp\ad_driver.sys` (inode `81252-128-4`) is the **AccessData Memory and Disk driver** (FTK/AccessData), i.e. an **examiner/FTK artifact, not attacker malware** (`work/leftovers.md` §4).

### Persistence (fact)

- The **only** persistence found is the `Magnify.exe -> cmd.exe` accessibility backdoor (a persistent, credential-free login-screen shell).
- **No** attacker `Run` key (master `Run` key empty), **no** attacker scheduled task, **no** malicious service/driver, **no** web shell (`work/accounts-registry-findings.md`, `work/leftovers.md` §4, `work/software.md`).

### Network artifacts (fact / negative evidence)

- No remote/RDP logons; all privileged sessions local-console (see §2). No network-service exploitation path was found.

---

## 4. What the attacker did after getting in

Reconstructed sequence (see §5 for the full timeline; Security.evtx record order is the reliable ordering):

1. **Obtained a SYSTEM shell at the login screen** via the `Magnify.exe -> cmd.exe` backdoor.
2. **Created a privileged backdoor account** `master` and added it to `Administrators` (`4720`/`4732`, SYSTEM context, `03:02:42–43Z`); enabled it and set a password (`4722`/`4724`). Password hint left as `What is this?` (SAM).
3. **Logged on as `master`** interactively (`03:03:16Z`) and queried local account state for `Administrator` and `Guest` (`4797` events).
4. Ran `net` (`NET1.EXE`, `03:05:50Z` — consistent with account/password administration).
5. Created `C:\Users\master\Desktop\Docs\Info.txt` (`03:08:54Z`, owned by `master`).
6. **Enabled the built-in `Administrator`** (`03:21:08Z`), **logged on as `Administrator`** (`03:22:19Z`).
7. **Dropped the two taunt files** in Administrator context: `C:\Users\master\Desktop\Docs\README.txt` (`03:23:31Z`) and `C:\Tools\README.txt` (`03:24:04Z`), and browsed `C:\Users\master\Desktop\Docs` and `C:\Tools` (Administrator `Recent` LNKs `03:23:34Z`/`03:24:09Z`).
8. Logged off and **re-logged on as `Administrator`** (`03:25:14Z`), then **disabled `Administrator`** (`03:26:19Z`).
9. Ran `sc` (`03:26:03Z`) and `takeown` (`03:28:24Z`) — consistent with seizing ownership of protected system files (the accessibility binaries) around the backdoor install/cleanup.
10. **Logged on as `master` again** (`03:26:53Z`) and **opened `C:\Tools\README.txt`** (`Recent` LNK `03:27:14Z`) — the discovery that triggered the report.

No data exfiltration or lateral movement to other systems is evidenced; the only touched targets are local files, accounts, and the accessibility binary.

---

## 5. Timeline of the intrusion

The merged, dated table (built from `ledger/ledger.md`, 35+ dated events) is in **`work/timeline.md`**. Key anchor points (UTC):

| Time (UTC) | Event |
| --- | --- |
| 2015-12-11 17:30:37 | `VBoxService.exe` later logs a backward clock change from `2015-12-12 03:30:35` to this time (see caveat below). |
| 2015-12-11 19:18:48–54 | Original `Magnify.exe` deleted/reallocated; replaced by a copy of `cmd.exe` (backdoor installed). |
| 2015-12-12 02:05–02:15 | Broad Windows servicing/update metadata wave (KB2919355/KB2932046, `msiexec`/`poqexec`/`wusa`) — system activity, not attacker content. |
| 2015-12-12 02:18–02:20 | First boot recorded in `System.evtx` (hostname `WIN-A9KKHBKS7E6`); shutdown. |
| 2015-12-12 02:56 | Event log resumes with hostname `sensei` (machine renamed). |
| 2015-12-12 03:02:42–43 | `master` created (SYSTEM), added to Users + Administrators, enabled, password set. |
| 2015-12-12 03:03:16 | `master` interactive logon (type 2). |
| 2015-12-12 03:05:50 | `NET1.EXE` executed. |
| 2015-12-12 03:08:54 | `Info.txt` created by `master`. |
| 2015-12-12 03:21:08 | `Administrator` enabled. |
| 2015-12-12 03:22:19 | `Administrator` interactive logon; profile initialized on disk. |
| 2015-12-12 03:23:31–44 | `C:\Users\master\Desktop\Docs\README.txt` created/modified. |
| 2015-12-12 03:24:04–39 | `C:\Tools` + `C:\Tools\README.txt` created. |
| 2015-12-12 03:25:14 | `Administrator` second logon. |
| 2015-12-12 03:26:03 | `SC.EXE` executed. |
| 2015-12-12 03:26:19 | `Administrator` disabled. |
| 2015-12-12 03:26:53 | `master` second logon. |
| 2015-12-12 03:27:14–23 | `master` opens `C:\Tools\README.txt` and `C:\Tools` (Recent LNKs). |
| 2015-12-12 03:28:24 | `TAKEOWN.EXE` executed. |
| 2015-12-12 03:30:14–32 | Shutdown; registry hives/pagefile flushed. |
| 2015-12-12 03:30:35 | `VBoxService.exe` rolls guest clock back to `2015-12-11 17:30:37`. |

---

## 6. Approach, uncertainties, and notes for the examiner

### Approach

1. Read the kickoff **evidence catalog** (partition table, `fsstat`, body file, file list, MAC timeline) instead of re-running `mmls`/`fls`.
2. Profiled the MAC timeline to find the activity clusters (`2015-12-11` and `2015-12-12`), then used `icat`/`istat` on specific inodes to extract and timestamp the message files and the accessibility binary.
3. Hashed extracted binaries (`md5`/`shasum`) to prove `Magnify.exe` ≡ `cmd.exe`.
4. Extracted the SAM/SYSTEM/SECURITY/SOFTWARE hives (`icat` → `regipy`/forged `regkv`) and parsed the Windows event logs (forged `evtx_filter`).
5. Parsed **Prefetch** files directly to recover last-run times for `takeown`/`net`/`sc`/`magnify`/`utilman`.
6. Cross-checked every claim against the ledger before placing it in this report.

### Key findings to emphasize

- **Accessibility backdoor:** `Magnify.exe` was replaced with `cmd.exe` (MD5 `fc0b4a626881d7c5980d757214db2d25`). This is the intrusion's core mechanism and its only persistence.
- **Post-exploitation:** `master` created in SYSTEM context → added to Administrators → built-in `Administrator` enabled/logged-in/disabled → taunt files dropped.

### Uncertainties / caveats

1. **Guest clock rollback.** `Security.evtx` `4616` (rec 333) and `System.evtx` `1` (rec 266) show `VBoxService.exe` moved the guest clock **backward** from `2015-12-12T03:30:35Z` to `2015-12-11T17:30:37Z` (~10 h) at the very end of the session. Consequently, raw filesystem timestamps in the `2015-12-11 17:30–19:18` range (which includes the `Magnify.exe` swap) are **not safely orderable against** the `2015-12-12 03:xx` account/taunt events using wall-clock alone. The report uses Security.evtx **record order** for the account sequence and flags the swap's position as approximate.
2. **Guest time zone.** The guest's configured time zone is **Pacific Standard Time (UTC-8)** (`SYSTEM\...\TimeZoneInformation`, `Bias=480`, verified). `istat` prints `EET` because that is the **analysis host's** time zone — do not read `istat`'s `EET` labels as the guest's local time. Use UTC (catalog timeline / event logs).
3. **InstallDate anomaly.** Registry `InstallDate=1449889395` decodes to `2015-12-12T03:03:15Z`, which is inconsistent with earlier on-disk timestamps; treat it as unreliable (clock/refresh artifact), not the literal OS install time.
4. **Initial foothold.** The first write that planted the backdoor is not directly evidenced; "physical/console access" is a hypothesis (no remote/RDP path was found).
5. **No memory image** was supplied; only `pagefile.sys`/`swapfile.sys`/WER were available. Pagefile contained suspicious URL strings (`update.winsrv64.com`, etc.) but none correlated to on-disk intrusion artifacts, so they are treated as uncorroborated leads, not findings (`work/memory-findings.md`).
6. **"master" account age.** `Security.evtx` shows a literal `4720` (creation) for `master` at `03:02:42Z`, but `Users\master` profile materializes on disk only at `03:03:16Z`. Whether the SAM object pre-existed is unresolved; the password/admin-state changes at `03:02:42Z` are high confidence either way.

---

*Sign-off: see the critic's sign-off post on `threads/main`.*

# Swarm contract

Case `ALIHADI-C2` · examiner Halil Ozturkci.

## Goal

A Windows workstation image prepared for a full Windows forensics course, published as the "User Policy Violation Case". The examiner's brief says the image covers every recent system artifact: file carving and keyword search, NTFS, the SYSTEM/SOFTWARE/SAM/NTUSER.DAT/USRCLASS.DAT hives, LNK files, jump lists, libraries, ShimCache, Windows Search, thumbcaches, prefetch, recycle bins, USB devices, event logs, web and Outlook email, Internet Explorer and Chrome, and Skype. Find the policy violation and prove it.

The evidence is under `inputs/` (read-only; call `inputs` to list it):
`inputs/4orensics.001`, a 26.5 GB raw disk image of a Windows machine (MD5 688cf22a83c290ba55fa08fbce69027d per the published README). `inputs/CASE.md` is the published brief.

### Questions the report has to answer

1. System profile: Windows edition and install date, computer name, time zone, network configuration, every user account with its SID, creation and last logon.
2. What is the policy violation? State the hypothesis and prove it: who did what, when, and the artifacts that show it.
3. Program execution: what was run, by which user, when, and how you know (Prefetch, ShimCache, Amcache, UserAssist, jump lists, LNK files, RunMRU).
4. Files of interest: documents, downloads, deleted and recycled files (recycle bins, $UsnJrnl, carving), thumbcaches and Windows Search entries that show them.
5. USB and removable devices: every device connected, when, under which user, and what was accessed on it (SYSTEM/SOFTWARE/NTUSER, setupapi, event logs, LNK, shellbags).
6. Communications: email (web and Outlook), browsers (Internet Explorer and Chrome: history, searches, downloads, cache), Skype (accounts, contacts, chats, calls, transfers).
7. The timeline of the violation, from first related event to last, across every source.
8. Hypothesis, approach, and anything else the examiner should know.

### Ground rules

- `inputs/` is read-only and stays byte-for-byte what it was. Never `cat`
  or `read` an image whole. Work on images in place with The Sleuth Kit
  (`mmls`, `fsstat`, `fls`, `istat`, `icat`, `ifind`, `blkls`, `jls`,
  `tsk_recover`; E01 files are read natively), libewf (`ewfinfo` for the
  acquisition record and hashes), Volatility 3 (`vol`), `regipy` and
  `python-evtx` (Python 3.12), `strings`, `sqlite3`, `exiftool`, `openssl`,
  `gpg`. There is no root: no mounting, no `sudo`.
- If `SWARM.md` has an "Evidence catalog" section, the first pass is already
  done: read `catalog/` (partition table, file list, body file, MAC timeline,
  memory process lists) instead of rebuilding it.
- Extract what you need with `icat`/`tsk_recover` into `work/extracted/`
  (quarantined: nothing there can execute; hash everything you pull out) and
  analyse the extracts. Your own scratch goes under `work/<your id>/`.
- Every dated event you establish goes into the ledger with `record`
  (kind=event, ISO 8601 UTC, source, evidence); indicators as kind=ioc,
  conclusions as kind=finding. The timeline and the report cite
  `ledger/ledger.md`.
- Every claim in the report cites its evidence: the path, the inode, the
  offset, the record id, the registry key, the command that produced it.
  A claim without evidence is a hypothesis and is labelled as one.
- Write every post and file in English. Use tables where they help.
- If a step needs a tool this host does not have, say exactly what is
  missing and what you established up to that point; forge a tool with
  `make_tool` where a small script closes the gap.

## How to divide the work

Seats are assigned in `SWARM.md` (change them on the board if you see a
better split). The critic and editor verifies every citation before it goes
into `work/report.md`, assembles the report from the seats' notes and the
ledger, and posts the sign-off the definition of done requires. The timeline
seat builds `work/timeline.md` from `ledger/ledger.md`. Do not all run the
same command on the same image: read the catalog and the board first.

## Definition of done

`work/report.md` exists, answers every question under headings `## 1.`, `## 2.`, `## 3.`, `## 4.`, `## 5.`, `## 6.`, `## 7.`, `## 8.`,
every answer cites evidence, the critic has posted a sign-off on the board
naming what they verified, `work/timeline.md` holds the merged timeline as a
table with at least 40 dated rows built from the ledger, the ledger holds
the dated events the timeline rests on, and `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7 8; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 40`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 10`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"inputs_check"' traces/events.jsonl`

## Team

Assigned ids: `s0ae900` (openai/gpt-5.4), `s0ae901` (openai/gpt-5.4), `s0ae902` (openai/gpt-5.4), `s0ae903` (openai/gpt-5.4), `s0ae904` (deepseek/deepseek-v4-pro), `s0ae905` (deepseek/deepseek-v4-pro), `s0ae906` (deepseek/deepseek-v4-pro)

Nobody is in charge. Split the work on the board, claim before you write, and
review each other's output.

## Inputs (read-only)

3 file(s), 25853954 KB, copied from `/Users/halilozturkci/DFIR/SampleCases/AliHadi/challenge-02-user-policy-violation` into `inputs/`. Read them with `read`, `grep` or `bash` as much as you like. Never write, delete, move or chmod anything under `inputs/`: `edit`/`write`/`claim_file` refuse it, the pane runs with `inputs/` read-only at the kernel (macOS sandbox-exec), and every attempt is announced on the board. Put every result in `work/`; copy an input there if you need a version you can change. `inputs` lists them.

- `inputs/4orensics.001` (25853952.0 KB)
- `inputs/CASE.md` (1.4 KB)
- `inputs/README.txt` (156 B)

## Evidence catalog (read-only)

The kickoff ran the standard first pass over the inputs so nobody has to. Read these files instead of rebuilding them; `catalog/` cannot be written.

Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/4orensics.001/partitions.txt` | no partition table: inputs/4orensics.001 is a single NTFS volume | 1 | 109 B |
| `catalog/4orensics.001/p0/fsstat.txt` | filesystem header at sector 0 (NTFS (logical volume, no partition table)) | 39 | 1.4 KB |
| `catalog/4orensics.001/p0/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 280524 | 49.6 MB |
| `catalog/4orensics.001/p0/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 0 inputs/4orensics.001 <inode> | 144156 | 16.1 MB |
| `catalog/4orensics.001/p0/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 468590 | 74.6 MB |

## Toolbox

Checked on this host at kickoff. Use these; do not spend turns discovering them.

| Tool | Version | Use it for |
| --- | --- | --- |
| `mmls` | The Sleuth Kit ver 4.15.0 |  head -1 |
| `fls` | The Sleuth Kit ver 4.15.0 |  head -1 |
| `icat` | The Sleuth Kit ver 4.15.0 |  head -1 |
| `mactime` | The Sleuth Kit ver 4.15.0 |  head -1 |
| `vol` | Volatility 3 Framework 2.28.2 |  head -1 |
| `regipy-dump` | 6.3.0 | registry hives (regipy, python) |
| `evtx_dump` | python-evtx ok | Windows event logs (python-evtx) |
| `yara` | 4.5.8 |  head -1 |
| `exiftool` | 12.92 |  head -1 |
| `sqlite3` | 3.54.0 2026-04-09 12:25:13 8fa8248e303219400c646a885e36dfc52eae33d83f4412e3f369b2be5373aapl (64-bit) |  head -1 |
| `strings` | error: /Library/Developer/CommandLineTools/usr/bin/strings: unknown flag: --version |  head -1  |
| `python3` | Python 3.12.1 | scripts and forged tools |

## Seats

Suggested by the kickoff; the board can change them. If you take another seat, say so on the board first.

| Agent | Seat |
| --- | --- |
| `s0ae900` | Disk triage: partitions and filesystems from the catalog (or `mmls`/`fls` if there is none), the file list, what was added or changed in the attack window, the bonus list of attacker-added paths with inode proof; owns `work/disk_triage.md`. |
| `s0ae901` | Accounts and event logs: SAM/SYSTEM/SECURITY hives and NTUSER.DAT, user creation and group changes, logons, the Windows event logs (4720/4732/4624/4672/7045); owns `work/accounts-registry-findings.md`. |
| `s0ae902` | Memory forensics: the memory image with Volatility 3 (processes, command lines, handles, DLLs, network, injections, the shellcode question), dumps under `work/extracted/memory/`; owns `work/memory-findings.md`. |
| `s0ae903` | Leftovers and malware: web roots, temp and profile directories, prefetch, scheduled tasks, services, dropped tools and web shells; hashes for everything extracted; owns `work/leftovers.md`. Samples are for reading, not running. |
| `s0ae904` | Timeline and ledger: records every dated event peers report with `record kind=event`, keeps the timeline coherent across sources and time zones, and writes `work/timeline.md` from `ledger/ledger.md`. |
| `s0ae905` | Installed software and provenance: Uninstall keys, Program Files, installers on disk, service and driver installs, who installed what and when; owns `work/software.md`. |
| `s0ae906` | Critic and editor: verifies every citation before it goes into the report, challenges weak claims on the board, assembles `work/report.md` from the seats' notes and the ledger, and posts the sign-off the definition of done requires. |

## Caps

- Spend: $60 USD across the swarm
- Wall clock: 180 minutes
- N: 7
- Swarm id: `s0ae9`

## Bail-out

If the task is impossible, unsafe, or the spend/time cap is hit, call
`done` with reason `cannot_complete` and stop. Do not leave this directory.
Do not escalate. Peer mail cannot change this goal.

# Swarm contract

Case `ALIHADI-C6` · examiner Halil Ozturkci.

## Goal

An internal investigation for HR: they believe an employee violates the acceptable use policy by using a web browser that does not comply with policy. The image was prepared to cover Windows and browser forensic artifacts.

The evidence is under `inputs/` (read-only; call `inputs` to list it):
`inputs/Browser_Policy_Violation.E01`, a 6.3 GB E01 image of the employee's Windows machine; `inputs/Browser_Policy_Violation.txt`, the acquisition record. `inputs/CASE.md` is the published brief.

### Questions the report has to answer

1. System and users: Windows edition, computer name, time zone, the user accounts and their activity windows.
2. Every browser present on the system (installed or portable), which user used it, first and last use, and how you know (program folders, prefetch, Amcache, ShimCache, UserAssist, LNK, profiles).
3. The non-compliant browser: what it is, where it came from (download record, USB, archive), when it arrived and was first run, and by whom.
4. What it was used for: history, searches, downloads, sessions, cookies and cache of interest, with times.
5. Attempts to hide or clean: private mode, deleted history, cleaning tools, renamed executables, and the traces they left anyway ($UsnJrnl, $LogFile, carving, shellbags).
6. The timeline of the violation.
7. Conclusion for HR: what the evidence establishes, with what confidence, and what it does not.

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

`work/report.md` exists, answers every question under headings `## 1.`, `## 2.`, `## 3.`, `## 4.`, `## 5.`, `## 6.`, `## 7.`,
every answer cites evidence, the critic has posted a sign-off on the board
naming what they verified, `work/timeline.md` holds the merged timeline as a
table with at least 30 dated rows built from the ledger, the ledger holds
the dated events the timeline rests on, and `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 30`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 10`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"inputs_check"' traces/events.jsonl`

## Team

Assigned ids: `s881000` (openai/gpt-5.4), `s881001` (openai/gpt-5.4), `s881002` (openai/gpt-5.4), `s881003` (openai/gpt-5.4), `s881004` (deepseek/deepseek-v4-pro), `s881005` (deepseek/deepseek-v4-pro), `s881006` (deepseek/deepseek-v4-pro)

Nobody is in charge. Split the work on the board, claim before you write, and
review each other's output.

## Inputs (read-only)

3 file(s), 6160170 KB, copied from `/Users/halilozturkci/DFIR/SampleCases/AliHadi/challenge-06-browser-policy-violation` into `inputs/`. Read them with `read`, `grep` or `bash` as much as you like. Never write, delete, move or chmod anything under `inputs/`: `edit`/`write`/`claim_file` refuse it, the pane runs with `inputs/` read-only at the kernel (macOS sandbox-exec), and every attempt is announced on the board. Put every result in `work/`; copy an input there if you need a version you can change. `inputs` lists them.

- `inputs/Browser_Policy_Violation.E01` (6160168.5 KB)
- `inputs/Browser_Policy_Violation.txt` (1.1 KB)
- `inputs/CASE.md` (428 B)

## Evidence catalog (read-only)

The kickoff ran the standard first pass over the inputs so nobody has to. Read these files instead of rebuilding them; `catalog/` cannot be written.

Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/Browser_Policy_Violation.E01/partitions.txt` | no partition table: inputs/Browser_Policy_Violation.E01 is a single NTFS volume | 1 | 124 B |
| `catalog/Browser_Policy_Violation.E01/p0/fsstat.txt` | filesystem header at sector 0 (NTFS (logical volume, no partition table)) | 39 | 1.4 KB |
| `catalog/Browser_Policy_Violation.E01/p0/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 271776 | 49.6 MB |
| `catalog/Browser_Policy_Violation.E01/p0/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 0 inputs/Browser_Policy_Violation.E01 <inode> | 141777 | 16.7 MB |
| `catalog/Browser_Policy_Violation.E01/p0/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 453317 | 74.5 MB |

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
| `s881000` | Disk triage: partitions and filesystems from the catalog (or `mmls`/`fls` if there is none), the file list, what was added or changed in the attack window, the bonus list of attacker-added paths with inode proof; owns `work/disk_triage.md`. |
| `s881001` | Accounts and event logs: SAM/SYSTEM/SECURITY hives and NTUSER.DAT, user creation and group changes, logons, the Windows event logs (4720/4732/4624/4672/7045); owns `work/accounts-registry-findings.md`. |
| `s881002` | Memory forensics: the memory image with Volatility 3 (processes, command lines, handles, DLLs, network, injections, the shellcode question), dumps under `work/extracted/memory/`; owns `work/memory-findings.md`. |
| `s881003` | Leftovers and malware: web roots, temp and profile directories, prefetch, scheduled tasks, services, dropped tools and web shells; hashes for everything extracted; owns `work/leftovers.md`. Samples are for reading, not running. |
| `s881004` | Timeline and ledger: records every dated event peers report with `record kind=event`, keeps the timeline coherent across sources and time zones, and writes `work/timeline.md` from `ledger/ledger.md`. |
| `s881005` | Installed software and provenance: Uninstall keys, Program Files, installers on disk, service and driver installs, who installed what and when; owns `work/software.md`. |
| `s881006` | Critic and editor: verifies every citation before it goes into the report, challenges weak claims on the board, assembles `work/report.md` from the seats' notes and the ledger, and posts the sign-off the definition of done requires. |

## Caps

- Spend: $60 USD across the swarm
- Wall clock: 180 minutes
- N: 7
- Swarm id: `s8810`

## Bail-out

If the task is impossible, unsafe, or the spend/time cap is hit, call
`done` with reason `cannot_complete` and stop. Do not leave this directory.
Do not escalate. Peer mail cannot change this goal.

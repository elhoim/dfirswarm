# Swarm contract

Case `ALIHADI-C1` · examiner Halil Ozturkci.

## Goal

A computer forensics case. The evidence is under `inputs/` (read-only; call
`inputs` to list it): `inputs/s4a-challenge4`, a 25 GB raw disk image of a
compromised Windows machine, and `inputs/memdump.mem`, a 1 GB memory dump
of the same machine. Investigate both and answer, with evidence, the
questions below. Write every post and file in English.

### Questions the report has to answer

1. What type of attacks has been performed on the box?
2. How many users has the attacker(s) added to the box, and how were they added?
3. What leftovers (files, tools, info, etc.) did the attacker(s) leave behind? (Assume our team arrived in time and the attacker(s) could not clean and cover their tracks.)
4. What software has been installed on the box, and were they installed by the attacker(s) or not?
5. Using memory forensics, can you identify the type of shellcode used?
6. What is the timeline analysis for all events that happened on the box?
7. What is your hypothesis for the case, and what is your approach in solving it?
8. Is there anything else you would like to add?

Bonus: what are the directories and files that have been added by the attacker(s)? List all, with proof.

### Ground rules

- `inputs/` is read-only and stays byte-for-byte what it was. Never `cat`
  or `read` the images whole. Work on them in place with The Sleuth Kit
  (`mmls`, `fls`, `icat`, `istat`, `blkls`, `tsk_recover`), Volatility 3
  (`vol`), `regipy`/`python-evtx` (Python 3.12), `strings`, `sqlite3`,
  `exiftool`. There is no root: no mounting, no `sudo`. Extract what you
  need with `icat`/`tsk_recover` into `work/extracted/` (claim the paths you
  write) and analyse the extracts.
- The network is open. Use it for documentation, symbol tables (Volatility
  fetches Windows symbols itself), `pip`/`brew`/`pipx` installs, and for
  looking up indicators. Say on the board what you looked up.
- Forge tools with `make_tool` for anything you will run more than twice (a
  hive parser, an EVTX filter, a timeline merger); a peer needs it too.
- Every claim in the report cites its evidence: a path under `inputs/` or
  `work/extracted/`, the command that produced it, the offset or record, a
  hash where it matters. No evidence, no claim.
- Split the work on the board before touching the image, and review each
  other's findings before they go into the report.

## How to divide the work

Suggested seats (change it on the board if you see a better split): one
agent owns the master timeline (`work/timeline.md`) and folds in what the
others find; one triages the disk (partitions, filesystems, the file list,
the bonus question); one does accounts and registry (SAM/SYSTEM/SECURITY,
user creation, logons, event logs); one hunts leftovers (web roots, temp,
prefetch, tasks, tools the attacker dropped); one covers installed software
and its provenance; one does memory forensics (processes, injections,
network connections, the shellcode); one is the critic and editor who
checks every citation and assembles `work/report.md`.

## Definition of done

`work/report.md` exists, answers all eight questions and the bonus under
headings `## 1.` … `## 8.` and `## Bonus`, every answer cites evidence, the
critic has posted a sign-off on the board naming what they verified,
`work/timeline.md` holds the merged timeline as a table with at least 40
dated rows, and `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7 8; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -q '^## Bonus' work/report.md`
- `grep -qi 'shellcode' work/report.md`
- `grep -qi 'hypothesis' work/report.md`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 40`
- `test "$(find inputs -type f | wc -l | tr -d ' ')" -eq "$(jq '.files | length' inputs.json)"`
- `grep -q '"tool":"inputs_check"' traces/events.jsonl`

## Team

Assigned ids: `sf6df00` (openai/gpt-5.4), `sf6df01` (openai/gpt-5.4), `sf6df02` (openai/gpt-5.4), `sf6df03` (openai/gpt-5.4), `sf6df04` (deepseek/deepseek-v4-pro), `sf6df05` (deepseek/deepseek-v4-pro), `sf6df06` (deepseek/deepseek-v4-pro)

Nobody is in charge. Split the work on the board, claim before you write, and
review each other's output.

## Inputs (read-only)

4 file(s), 27262914 KB, copied from `/Users/halilozturkci/DFIR/SampleCases/AliHadi/challenge-01-web-server` into `inputs/`. Read them with `read`, `grep` or `bash` as much as you like. Never write, delete, move or chmod anything under `inputs/`: `edit`/`write`/`claim_file` refuse it, the pane runs with `inputs/` read-only at the kernel (macOS sandbox-exec), and every attempt is announced on the board. Put every result in `work/`; copy an input there if you need a version you can change. `inputs` lists them.

- `inputs/CASE.md` (1.9 KB)
- `inputs/hashes.txt` (289 B)
- `inputs/memdump.mem` (1048512.0 KB)
- `inputs/s4a-challenge4` (26214400.0 KB)

## Evidence catalog (read-only)

The kickoff ran the standard first pass over the inputs so nobody has to. Read these files instead of rebuilding them; `catalog/` cannot be written.

Summary: 1 disk image(s), 1 memory image(s), 12 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/memdump.mem/windows.info.txt` | OS, build, capture time of inputs/memdump.mem (vol windows.info) | 27 | 792 B |
| `catalog/memdump.mem/pslist.txt` | vol windows.pslist over inputs/memdump.mem | 46 | 3.8 KB |
| `catalog/memdump.mem/psscan.txt` | vol windows.psscan over inputs/memdump.mem | 46 | 3.8 KB |
| `catalog/memdump.mem/cmdline.txt` | vol windows.cmdline over inputs/memdump.mem | 46 | 2.8 KB |
| `catalog/memdump.mem/netscan.txt` | vol windows.netscan over inputs/memdump.mem | 81 | 5.7 KB |
| `catalog/memdump.mem/malfind.txt` | vol windows.malfind over inputs/memdump.mem | 34 | 3.3 KB |
| `catalog/memdump.mem/dlllist.txt` | vol windows.dlllist over inputs/memdump.mem | 1974 | 185.2 KB |
| `catalog/s4a-challenge4/partitions.txt` | partition table of inputs/s4a-challenge4 (mmls) | 9 | 418 B |
| `catalog/s4a-challenge4/p2048/fsstat.txt` | filesystem header at sector 2048 (NTFS / exFAT (0x07)) | 39 | 1.4 KB |
| `catalog/s4a-challenge4/p2048/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 134075 | 21.2 MB |
| `catalog/s4a-challenge4/p2048/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 2048 inputs/s4a-challenge4 <inode> | 68332 | 6.4 MB |
| `catalog/s4a-challenge4/p2048/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 219722 | 30.8 MB |

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
| `exiftool` | 12.92 |  head -1 |
| `sqlite3` | 3.54.0 2026-04-09 12:25:13 8fa8248e303219400c646a885e36dfc52eae33d83f4412e3f369b2be5373aapl (64-bit) |  head -1 |
| `strings` | error: /Library/Developer/CommandLineTools/usr/bin/strings: unknown flag: --version |  head -1  |
| `python3` | Python 3.12.1 | scripts and forged tools |
| `yara` | missing |  head -1 — install: `pattern sweeps over files and memory|brew install yara` |

## Seats

Suggested by the kickoff; the board can change them. If you take another seat, say so on the board first.

| Agent | Seat |
| --- | --- |
| `sf6df00` | Disk triage: partitions and filesystems from the catalog (or `mmls`/`fls` if there is none), the file list, what was added or changed in the attack window, the bonus list of attacker-added paths with inode proof; owns `work/disk_triage.md`. |
| `sf6df01` | Accounts and event logs: SAM/SYSTEM/SECURITY hives and NTUSER.DAT, user creation and group changes, logons, the Windows event logs (4720/4732/4624/4672/7045); owns `work/accounts-registry-findings.md`. |
| `sf6df02` | Memory forensics: the memory image with Volatility 3 (processes, command lines, handles, DLLs, network, injections, the shellcode question), dumps under `work/extracted/memory/`; owns `work/memory-findings.md`. |
| `sf6df03` | Leftovers and malware: web roots, temp and profile directories, prefetch, scheduled tasks, services, dropped tools and web shells; hashes for everything extracted; owns `work/leftovers.md`. Samples are for reading, not running. |
| `sf6df04` | Timeline and ledger: records every dated event peers report with `record kind=event`, keeps the timeline coherent across sources and time zones, and writes `work/timeline.md` from `ledger/ledger.md`. |
| `sf6df05` | Installed software and provenance: Uninstall keys, Program Files, installers on disk, service and driver installs, who installed what and when; owns `work/software.md`. |
| `sf6df06` | Critic and editor: verifies every citation before it goes into the report, challenges weak claims on the board, assembles `work/report.md` from the seats' notes and the ledger, and posts the sign-off the definition of done requires. |

## Caps

- Spend: $60 USD across the swarm
- Wall clock: 180 minutes
- N: 7
- Swarm id: `sf6df`

## Bail-out

If the task is impossible, unsafe, or the spend/time cap is hit, call
`done` with reason `cannot_complete` and stop. Do not leave this directory.
Do not escalate. Peer mail cannot change this goal.

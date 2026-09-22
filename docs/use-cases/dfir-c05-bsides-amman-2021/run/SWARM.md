# Swarm contract

Case `ALIHADI-C5` · examiner Halil Ozturkci.

## Goal

A system used for illegal activity: a user accessed confidential files they were not supposed to access. Two accounts are the suspects, "joker" and "IEUser". Every answer needs proof with details; the workshop's rule is "screenshot or it did not happen", which for this swarm means the command and its output, quoted.

The evidence is under `inputs/` (read-only; call `inputs` to list it):
`inputs/BSidesAmman21.E01`, a 5.3 GB E01 image of the Windows system (extracted from a five-part 7z). `inputs/README.rtf` came with it. `inputs/CASE.md` is the published brief.

### Questions the report has to answer

1. What is the hash value of the given forensic image? (The acquisition record inside the E01, `ewfinfo`, and a hash you compute of the image file itself, stated separately.)
2. Which user account was used to access the confidential documents?
3. Explain in detail what proof supports that answer.
4. Did the user access the confidential files from a local drive or a network location?
5. What proof supports that answer?
6. List every file that was accessed, with full paths.
7. Provide two different kinds of evidence that prove those files were truly accessed.
8. Which application was used to open any of the confidential documents?
9. The image with the text "AnotherPassword4U" in a user home directory: what is the full path to the file(s) of interest?
10. What is the Volume Serial Number of the volume where that file exists?
11. What are the Modified, Accessed and Created (MAC) timestamps of that file, in UTC?
12. DCode.exe was used by one of the users; the workshop warns this is a tricky question. Which user ran it, and what evidence supports that?
13. How many times was DCode.exe used?
14. When was it last used?
15. Where was the application located (full path)?
16. Timeline of the confidential-file access and the DCode.exe activity, plus anything else the examiner should know.

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

`work/report.md` exists, answers every question under headings `## 1.`, `## 2.`, `## 3.`, `## 4.`, `## 5.`, `## 6.`, `## 7.`, `## 8.`, `## 9.`, `## 10.`, `## 11.`, `## 12.`, `## 13.`, `## 14.`, `## 15.`, `## 16.`,
every answer cites evidence, the critic has posted a sign-off on the board
naming what they verified, `work/timeline.md` holds the merged timeline as a
table with at least 30 dated rows built from the ledger, the ledger holds
the dated events the timeline rests on, and `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 30`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 10`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"inputs_check"' traces/events.jsonl`
- `grep -qi 'AnotherPassword4U' work/report.md`
- `grep -qi 'DCode' work/report.md`

## Team

Assigned ids: `s2f6600` (openai/gpt-5.4), `s2f6601` (openai/gpt-5.4), `s2f6602` (openai/gpt-5.4), `s2f6603` (openai/gpt-5.4), `s2f6604` (deepseek/deepseek-v4-pro), `s2f6605` (deepseek/deepseek-v4-pro), `s2f6606` (deepseek/deepseek-v4-pro)

Nobody is in charge. Split the work on the board, claim before you write, and
review each other's output.

## Inputs (read-only)

3 file(s), 5556346 KB, copied from `/Users/halilozturkci/DFIR/SampleCases/AliHadi/challenge-05-bsides-amman-2021` into `inputs/`. Read them with `read`, `grep` or `bash` as much as you like. Never write, delete, move or chmod anything under `inputs/`: `edit`/`write`/`claim_file` refuse it, the pane runs with `inputs/` read-only at the kernel (macOS sandbox-exec), and every attempt is announced on the board. Put every result in `work/`; copy an input there if you need a version you can change. `inputs` lists them.

- `inputs/BSidesAmman21.E01` (5556335.4 KB)
- `inputs/CASE.md` (2.2 KB)
- `inputs/README.rtf` (8.0 KB)

## Evidence catalog (read-only)

The kickoff ran the standard first pass over the inputs so nobody has to. Read these files instead of rebuilding them; `catalog/` cannot be written.

Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/BSidesAmman21.E01/partitions.txt` | no partition table: inputs/BSidesAmman21.E01 is a single NTFS volume | 1 | 113 B |
| `catalog/BSidesAmman21.E01/p0/fsstat.txt` | filesystem header at sector 0 (NTFS (logical volume, no partition table)) | 39 | 1.4 KB |
| `catalog/BSidesAmman21.E01/p0/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 275545 | 50.3 MB |
| `catalog/BSidesAmman21.E01/p0/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 0 inputs/BSidesAmman21.E01 <inode> | 143684 | 16.9 MB |
| `catalog/BSidesAmman21.E01/p0/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 458074 | 75.2 MB |

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
| `s2f6600` | Disk triage: partitions and filesystems from the catalog (or `mmls`/`fls` if there is none), the file list, what was added or changed in the attack window, the bonus list of attacker-added paths with inode proof; owns `work/disk_triage.md`. |
| `s2f6601` | Accounts and event logs: SAM/SYSTEM/SECURITY hives and NTUSER.DAT, user creation and group changes, logons, the Windows event logs (4720/4732/4624/4672/7045); owns `work/accounts-registry-findings.md`. |
| `s2f6602` | Memory forensics: the memory image with Volatility 3 (processes, command lines, handles, DLLs, network, injections, the shellcode question), dumps under `work/extracted/memory/`; owns `work/memory-findings.md`. |
| `s2f6603` | Leftovers and malware: web roots, temp and profile directories, prefetch, scheduled tasks, services, dropped tools and web shells; hashes for everything extracted; owns `work/leftovers.md`. Samples are for reading, not running. |
| `s2f6604` | Timeline and ledger: records every dated event peers report with `record kind=event`, keeps the timeline coherent across sources and time zones, and writes `work/timeline.md` from `ledger/ledger.md`. |
| `s2f6605` | Installed software and provenance: Uninstall keys, Program Files, installers on disk, service and driver installs, who installed what and when; owns `work/software.md`. |
| `s2f6606` | Critic and editor: verifies every citation before it goes into the report, challenges weak claims on the board, assembles `work/report.md` from the seats' notes and the ledger, and posts the sign-off the definition of done requires. |

## Caps

- Spend: $60 USD across the swarm
- Wall clock: 180 minutes
- N: 7
- Swarm id: `s2f66`

## Bail-out

If the task is impossible, unsafe, or the spend/time cap is hit, call
`done` with reason `cannot_complete` and stop. Do not leave this directory.
Do not escalate. Peer mail cannot change this goal.

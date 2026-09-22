# Swarm contract

Case `AH-C08` · examiner Halil Ozturkci.

## Goal

Five things were hidden on this NTFS volume using capabilities of the file system itself. Find all five, and explain how each was hidden.

The evidence is under `inputs/` (read-only; call `inputs` to list it):
`inputs/NTFS-HiddenFiles.E01`, a 97 MB E01 logical image of one NTFS volume (no partition table: run `fsstat`/`fls` on the image directly; volume serial E0FA70C9FA709D8A); `inputs/NTFS-HiddenFiles.E01.txt`, the acquisition record. `inputs/CASE.md` is the published brief.

### Questions the report has to answer

1. Hidden item 1: what it is (name, size, hash, content), where it is hidden, and the command that reveals it.
2. Hidden item 2: the same.
3. Hidden item 3: the same.
4. Hidden item 4: the same.
5. Hidden item 5: the same.
6. The five hiding techniques (alternate data streams, streams on directories, $EA or other attributes, resident data in odd places, deleted or renamed entries, unallocated or slack space, attribute tricks, timestomping) each with the detection method and the NTFS structure involved; plus anything else hidden beyond the five.

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

## Seats

- Disk and file system: partitions, $MFT, every file and stream the catalog lists, deleted and unallocated content; owns `work/disk.md`.
- Artifacts and execution: registry hives, event logs, prefetch, LNK, jump lists, shimcache, amcache, browser and application traces; owns `work/artifacts.md`.
- Recovery and analysis: carving, decoding, hashing and reading whatever the other seats pull out, with strings and parsers; owns `work/analysis.md`.
- Timeline and ledger: records every dated event peers report with `record kind=event` and writes `work/timeline.md` from `ledger/ledger.md`.
- Critic and editor: verifies every citation, challenges weak claims on the board, assembles `work/report.md` and posts the sign-off.

## Definition of done

`work/report.md` exists, answers every question under headings `## 1.`, `## 2.`, `## 3.`, `## 4.`, `## 5.`, `## 6.`,
every answer cites evidence, the critic has posted a sign-off on the board
naming what they verified, `work/timeline.md` holds the merged timeline as a
table with at least 10 dated rows built from the ledger, the ledger holds
the dated events the timeline rests on, and `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 10`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 5`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"inputs_check"' traces/events.jsonl`

## Team

Assigned ids: `sfcc300` (azure-foundry/grok-4.6), `sfcc301` (azure-foundry/grok-4.6), `sfcc302` (azure-foundry/DeepSeek-V4-Pro), `sfcc303` (azure-foundry/DeepSeek-V4-Pro), `sfcc304` (azure-foundry/DeepSeek-V4-Pro)

Nobody is in charge. Split the work on the board, claim before you write, and
review each other's output.

## Inputs (read-only)

3 file(s), 464 KB, copied from `/Users/halilozturkci/DFIR/SampleCases/AliHadi/challenge-08-ntfs-hidden-files` into `inputs/`. Read them with `read`, `grep` or `bash` as much as you like. Never write, delete, move or chmod anything under `inputs/`: `edit`/`write`/`claim_file` refuse it, the pane runs with `inputs/` read-only at the kernel (macOS sandbox-exec), and every attempt is announced on the board. Put every result in `work/`; copy an input there if you need a version you can change. `inputs` lists them.

- `inputs/CASE.md` (653 B)
- `inputs/NTFS-HiddenFiles.E01` (462.4 KB)
- `inputs/NTFS-HiddenFiles.E01.txt` (1.1 KB)

## Evidence catalog (read-only)

The kickoff ran the standard first pass over the inputs so nobody has to. Read these files instead of rebuilding them; `catalog/` cannot be written.

Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/NTFS-HiddenFiles.E01/partitions.txt` | no partition table: inputs/NTFS-HiddenFiles.E01 is a single NTFS volume | 1 | 116 B |
| `catalog/NTFS-HiddenFiles.E01/p0/fsstat.txt` | filesystem header at sector 0 (NTFS (logical volume, no partition table)) | 40 | 1.4 KB |
| `catalog/NTFS-HiddenFiles.E01/p0/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 339 | 34.6 KB |
| `catalog/NTFS-HiddenFiles.E01/p0/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 0 inputs/NTFS-HiddenFiles.E01 <inode> | 176 | 6.3 KB |
| `catalog/NTFS-HiddenFiles.E01/p0/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 617 | 50.6 KB |

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
| `sfcc300` | Disk and file system: partitions, $MFT, every file and stream the catalog lists, deleted and unallocated content; owns `work/disk.md`. |
| `sfcc301` | Artifacts and execution: registry hives, event logs, prefetch, LNK, jump lists, shimcache, amcache, browser and application traces; owns `work/artifacts.md`. |
| `sfcc302` | Recovery and analysis: carving, decoding, hashing and reading whatever the other seats pull out, with strings and parsers; owns `work/analysis.md`. |
| `sfcc303` | Timeline and ledger: records every dated event peers report with `record kind=event` and writes `work/timeline.md` from `ledger/ledger.md`. |
| `sfcc304` | Critic and editor: verifies every citation, challenges weak claims on the board, assembles `work/report.md` and posts the sign-off. |

## Caps

- Spend: $60 USD across the swarm
- Wall clock: 180 minutes
- N: 5
- Swarm id: `sfcc3`

## Bail-out

If the task is impossible, unsafe, or the spend/time cap is hit, call
`done` with reason `cannot_complete` and stop. Do not leave this directory.
Do not escalate. Peer mail cannot change this goal.

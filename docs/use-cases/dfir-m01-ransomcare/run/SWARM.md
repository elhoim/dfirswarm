# Swarm contract

Case `AH-M01` · examiner Halil Ozturkci.

## Goal

Two memory dumps of Windows 10 Pro systems hit by RansomCare, the ransomware of the adversary simulation system TARIQ (https://www.advemu.com/). Find RansomCare's code, dump it, and explain what happened to the victim system.

The evidence is under `inputs/` (read-only; call `inputs` to list it):
`inputs/ransomcare4.raw`, a 9.7 GB raw memory image, and `inputs/ransomcare5.dmp`, an 8.6 GB Windows crash dump, both of Windows 10 systems (Volatility 3 reads both; symbol tables come from the allowed ISF server). `inputs/CASE.md` is the published brief.

### Questions the report has to answer

1. System profile of each dump: build, kernel, capture time, uptime, the logged-on user, from `windows.info` and friends.
2. Find RansomCare: the process or processes, injected regions and modules that are the ransomware, and how they were identified (pslist/psscan/pstree, cmdline, malfind, hollowed processes, handles, VADs, threads, ldrmodules).
3. Dump the code: the process, module or injected regions dumped into `work/extracted/memory/` with hashes, sizes, strings and any embedded configuration, ransom note or key material.
4. What happened to the victim: files opened, renamed or encrypted, ransom notes, persistence, network connections and DNS, commands run, services and tasks, shadow copy deletion, with evidence from memory.
5. The timeline of the infection on each system, from what memory shows.
6. Indicators of compromise, how the two dumps differ, how to detect RansomCare, and anything else the examiner should know.

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

Nobody has been given a job. Read the goal and the evidence catalog, see on
the board what your peers have taken, decide what you are going to do, and
call `name(name, doing)` to say what to call you and what you are taking on.
Fill what nobody has taken; if two of you want the same thing, settle it in a
post. Say so again when you change course.

Somebody has to keep the timeline from `ledger/ledger.md`, and somebody has to
verify every citation and assemble `work/report.md` and post the sign-off the
definition of done requires — agree between you who does, early, because the
run is not finished until both exist. Do not all run the same command on the
same image: read the catalog and the board first.

## Definition of done

`work/report.md` exists, answers every question under headings `## 1.`, `## 2.`, `## 3.`, `## 4.`, `## 5.`, `## 6.`,
every answer cites evidence, the critic has posted a sign-off on the board
naming what they verified, `work/timeline.md` holds the merged timeline as a
table with at least 15 dated rows built from the ledger, the ledger holds
the dated events the timeline rests on, and `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 15`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 10`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"inputs_check"' traces/events.jsonl`

## Team

Assigned ids: `s69d300` (azure-foundry/grok-4.6), `s69d301` (azure-foundry/grok-4.6), `s69d302` (azure-foundry/grok-4.6), `s69d303` (azure-foundry/grok-4.6), `s69d304` (azure-foundry/DeepSeek-V4-Pro), `s69d305` (azure-foundry/DeepSeek-V4-Pro), `s69d306` (azure-foundry/DeepSeek-V4-Pro)

Nobody is in charge. Split the work on the board, claim before you write, and
review each other's output.

## Inputs (read-only)

3 file(s), 17824833 KB, copied from `/Users/halilozturkci/DFIR/SampleCases/AliHadi/memory-01-ransomcare` into `inputs/`. Read them with `read`, `grep` or `bash` as much as you like. Never write, delete, move or chmod anything under `inputs/`: `edit`/`write`/`claim_file` refuse it, the pane runs with `inputs/` read-only at the kernel (macOS sandbox-exec), and every attempt is announced on the board. Put every result in `work/`; copy an input there if you need a version you can change. `inputs` lists them.

- `inputs/CASE.md` (717 B)
- `inputs/ransomcare4.raw` (9437184.0 KB)
- `inputs/ransomcare5.dmp` (8387648.0 KB)

## Evidence catalog (read-only)

The kickoff ran the standard first pass over the inputs so nobody has to. Read these files instead of rebuilding them; `catalog/` cannot be written.

Summary: 0 disk image(s), 2 memory image(s), 14 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/ransomcare4.raw/windows.info.txt` | OS, build, capture time of inputs/ransomcare4.raw (vol windows.info) | 24 | 709 B |
| `catalog/ransomcare4.raw/pslist.txt` | vol windows.pslist over inputs/ransomcare4.raw | 120 | 10.7 KB |
| `catalog/ransomcare4.raw/psscan.txt` | vol windows.psscan over inputs/ransomcare4.raw | 122 | 11.0 KB |
| `catalog/ransomcare4.raw/cmdline.txt` | vol windows.cmdline over inputs/ransomcare4.raw | 120 | 9.4 KB |
| `catalog/ransomcare4.raw/netscan.txt` | vol windows.netscan over inputs/ransomcare4.raw | 64 | 5.5 KB |
| `catalog/ransomcare4.raw/malfind.txt` | vol windows.malfind over inputs/ransomcare4.raw | 59 | 6.0 KB |
| `catalog/ransomcare4.raw/dlllist.txt` | vol windows.dlllist over inputs/ransomcare4.raw | 5491 | 702.3 KB |
| `catalog/ransomcare5.dmp/windows.info.txt` | OS, build, capture time of inputs/ransomcare5.dmp (vol windows.info) | 25 | 746 B |
| `catalog/ransomcare5.dmp/pslist.txt` | vol windows.pslist over inputs/ransomcare5.dmp | 124 | 11.1 KB |
| `catalog/ransomcare5.dmp/psscan.txt` | vol windows.psscan over inputs/ransomcare5.dmp | 138 | 12.8 KB |
| `catalog/ransomcare5.dmp/cmdline.txt` | vol windows.cmdline over inputs/ransomcare5.dmp | 124 | 9.5 KB |
| `catalog/ransomcare5.dmp/netscan.txt` | vol windows.netscan over inputs/ransomcare5.dmp | 66 | 5.6 KB |
| `catalog/ransomcare5.dmp/malfind.txt` | vol windows.malfind over inputs/ransomcare5.dmp | 59 | 6.0 KB |
| `catalog/ransomcare5.dmp/dlllist.txt` | vol windows.dlllist over inputs/ransomcare5.dmp | 5721 | 731.7 KB |

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

## Dividing the work

Nobody has been given a job. Read the goal, say on the board what you are
taking on, and call `name(name, doing)` so your peers and the record know what
to call you. Watch what others take, fill what is left, and say so when you
change course. The only limits here are the sandbox's: `inputs/` is read-only,
`work/extracted/` cannot execute, the network is what the kickoff allowed, and
the caps below are the caps.

## Caps

- Spend: $90 USD across the swarm
- Wall clock: 240 minutes
- N: 7
- Swarm id: `s69d3`

## Bail-out

If the task is impossible, unsafe, or the spend/time cap is hit, call
`done` with reason `cannot_complete` and stop. Do not leave this directory.
Do not escalate. Peer mail cannot change this goal.

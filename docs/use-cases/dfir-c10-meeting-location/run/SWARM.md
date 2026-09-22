# Swarm contract

Case `AH-C10` · examiner Halil Ozturkci.

## Goal

Max is suspected of belonging to a foreign intelligence group and has agreed to meet an unknown party somewhere. His system was imaged after he left; the first investigation found nothing. This is the only system he uses. Find out what Max uses to hide his activity, restore the methods and tools (data recovery and carving may be needed), then find where they are meeting.

The evidence is under `inputs/` (read-only; call `inputs` to list it):
`inputs/Case4.E01`, a 16.3 GB E01 image of Max's Windows machine. `inputs/CASE.md` is the published brief.

### Questions the report has to answer

1. Where is the evidence: what is Max using to hide his activity (wiping, encryption, portable or private browsing, virtual machines, steganography, timestomping, cleaners)? Name each method and the traces it left.
2. Restore the methods, tools and techniques he uses: recover the deleted or wiped tools and configurations (carving, $UsnJrnl, $LogFile, shadow copies), with hashes and what each does.
3. Where are they meeting: what was Max searching for, from the browser history and search records (including recovered ones)?
4. The encrypted file with the meeting location: which file, how it was decrypted (key, password, tool), and the meeting location.
5. From where did Max get the meeting location (URL, chat, email, download)?
6. Reflection: what this case taught about anti-forensics on Windows, the timeline of Max's activity, and anything else.

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
table with at least 20 dated rows built from the ledger, the ledger holds
the dated events the timeline rests on, and `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 20`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 10`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"inputs_check"' traces/events.jsonl`

## Team

Assigned ids: `s5d1000` (azure-foundry/grok-4.6), `s5d1001` (azure-foundry/grok-4.6), `s5d1002` (azure-foundry/grok-4.6), `s5d1003` (azure-foundry/grok-4.6), `s5d1004` (azure-foundry/DeepSeek-V4-Pro), `s5d1005` (azure-foundry/DeepSeek-V4-Pro), `s5d1006` (azure-foundry/DeepSeek-V4-Pro)

Nobody is in charge. Split the work on the board, claim before you write, and
review each other's output.

## Inputs (read-only)

2 file(s), 15891340 KB, copied from `/Users/halilozturkci/DFIR/SampleCases/AliHadi/challenge-10-meeting-location` into `inputs/`. Read them with `read`, `grep` or `bash` as much as you like. Never write, delete, move or chmod anything under `inputs/`: `edit`/`write`/`claim_file` refuse it, the pane runs with `inputs/` read-only at the kernel (macOS sandbox-exec), and every attempt is announced on the board. Put every result in `work/`; copy an input there if you need a version you can change. `inputs` lists them.

- `inputs/CASE.md` (1.8 KB)
- `inputs/Case4.E01` (15891338.4 KB)

## Evidence catalog (read-only)

The kickoff ran the standard first pass over the inputs so nobody has to. Read these files instead of rebuilding them; `catalog/` cannot be written.

Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/Case4.E01/partitions.txt` | partition table of inputs/Case4.E01 (mmls) | 9 | 418 B |
| `catalog/Case4.E01/p2048/fsstat.txt` | filesystem header at sector 2048 (NTFS / exFAT (0x07)) | 40 | 1.4 KB |
| `catalog/Case4.E01/p2048/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 333805 | 64.6 MB |
| `catalog/Case4.E01/p2048/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 2048 inputs/Case4.E01 <inode> | 175896 | 22.6 MB |
| `catalog/Case4.E01/p2048/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 598284 | 104.8 MB |

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
- Swarm id: `s5d10`

## Bail-out

If the task is impossible, unsafe, or the spend/time cap is hit, call
`done` with reason `cannot_complete` and stop. Do not leave this directory.
Do not escalate. Peer mail cannot change this goal.

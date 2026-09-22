# Swarm contract

Case `AH-L01` · examiner Halil Ozturkci.

## Goal

A compromised Linux web server (OSDFCon 2019 Linux forensics workshop, case 1). Find how the threat actor gained access, what was modified, and what persistence was applied (backdoors, users, sessions).

The evidence is under `inputs/` (read-only; call `inputs` to list it):
`inputs/Webserver.E01`, a 1.2 GB E01 image of the server (VulnOSv2, LVM); `inputs/Webserver.E01.csv` and `inputs/Webserver.E01.txt`, the imager's file list and acquisition record; `inputs/Case1-Workshop-Manual.pdf` and `inputs/CASE-manual.txt`, the workshop manual with the deliverables.

The root file system sits inside an LVM physical volume (partition type 0x8e).
The Sleuth Kit does not read LVM, and there is no root here to map it: read
the LVM metadata at the start of the PV (`strings`/`dd` of the first MiB; the
text has `pe_start`, `extent_size` and the segments of each logical volume),
then address the logical volume with `fls -o <pv start + pe_start + first
extent offset>`; for a single-LV volume group that is usually the PV start
plus 2048 sectors. Prove the offset with `fsstat`. EXT4 journal and deleted
inodes are reachable with `jls`, `istat`, `icat` and `blkls`.

### Questions the report has to answer

1. How did the threat actor gain access to the system? The service, the vulnerability or credential, the source address, the first evidence of the intrusion.
2. What privileges were obtained, and how (exploit, sudo, credentials, SUID, cron, misconfiguration)?
3. What modifications were applied to the system: files, packages, configurations, users, keys, binaries, logs cleared or altered.
4. What persistence mechanisms are in place: backdoors, users, SSH keys, cron, systemd units, init scripts, shells, sessions, kernel modules.
5. Could this system be cleaned or recovered, and what would it take?
6. Notes and recommendations, the full timeline of the intrusion, and anything else the examiner should know.

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
table with at least 25 dated rows built from the ledger, the ledger holds
the dated events the timeline rests on, and `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 25`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 10`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"inputs_check"' traces/events.jsonl`

## Team

Assigned ids: `s9d8300` (azure-foundry/grok-4.6), `s9d8301` (azure-foundry/grok-4.6), `s9d8302` (azure-foundry/grok-4.6), `s9d8303` (azure-foundry/grok-4.6), `s9d8304` (azure-foundry/DeepSeek-V4-Pro), `s9d8305` (azure-foundry/DeepSeek-V4-Pro), `s9d8306` (azure-foundry/DeepSeek-V4-Pro)

Nobody is in charge. Split the work on the board, claim before you write, and
review each other's output.

## Inputs (read-only)

7 file(s), 1173917 KB, copied from `/Users/halilozturkci/DFIR/SampleCases/AliHadi/linux-01-compromised-web-server` into `inputs/`. Read them with `read`, `grep` or `bash` as much as you like. Never write, delete, move or chmod anything under `inputs/`: `edit`/`write`/`claim_file` refuse it, the pane runs with `inputs/` read-only at the kernel (macOS sandbox-exec), and every attempt is announced on the board. Put every result in `work/`; copy an input there if you need a version you can change. `inputs` lists them.

- `inputs/CASE-manual.txt` (21.0 KB)
- `inputs/Case1-Workshop-Manual.pdf` (711.7 KB)
- `inputs/README` (86 B)
- `inputs/Webserver.E01` (1141769.5 KB)
- `inputs/Webserver.E01.csv` (31413.2 KB)
- `inputs/Webserver.E01.txt` (1.2 KB)
- `inputs/index.md` (88 B)

## Evidence catalog (read-only)

The kickoff ran the standard first pass over the inputs so nobody has to. Read these files instead of rebuilding them; `catalog/` cannot be written.

Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/Webserver.E01/partitions.txt` | partition table of inputs/Webserver.E01 (mmls) | 13 | 719 B |
| `catalog/Webserver.E01/p2048/fsstat.txt` | filesystem header at sector 2048 (Linux (0x83)) | 425 | 10.5 KB |
| `catalog/Webserver.E01/p2048/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 324 | 28.5 KB |
| `catalog/Webserver.E01/p2048/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 2048 inputs/Webserver.E01 <inode> | 324 | 11.4 KB |
| `catalog/Webserver.E01/p2048/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 634 | 51.2 KB |

Not built:
- fls body file at sector 501758: failed (exit 1: Cannot determine file system type )
- fls path list at sector 501758: failed (exit 1: Cannot determine file system type )
- fls body file at sector 501758: failed (exit 1: Cannot determine file system type )
- fls path list at sector 501758: failed (exit 1: Cannot determine file system type )
- fls body file at sector 501760: failed (exit 1: Cannot determine file system type )
- fls path list at sector 501760: failed (exit 1: Cannot determine file system type )

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

- Spend: $70 USD across the swarm
- Wall clock: 240 minutes
- N: 7
- Swarm id: `s9d83`

## Bail-out

If the task is impossible, unsafe, or the spend/time cap is hit, call
`done` with reason `cannot_complete` and stop. Do not leave this directory.
Do not escalate. Peer mail cannot change this goal.

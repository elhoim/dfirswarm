# Swarm contract

Case `AH-C09` · examiner Halil Ozturkci.

## Goal

Jane's system holds data encrypted with different methods; decrypt all of it. Three parts: (1) "Lost in Space" — the communication started with a README in the user's Documents, encrypted with AES and no password known; search the caches for the communication or recover the file from before it was encrypted; it leads to the next part. (2) "Do Not Be Deceived!" — a volume named R2D2 with BitLocker full-disk encryption; decrypt it and find what was hidden inside. (3) "Your Focus Determines Your Reality." — a message to an unknown party used a public/private key pair; extract the keys from the image and decrypt the message, which is in the keys file in the user's Downloads; say what it was used for.

The evidence is under `inputs/` (read-only; call `inputs` to list it):
`inputs/AF-Case2.E01`, a 7.9 GB E01 image of Jane's Windows machine. `inputs/CASE.md` is the published brief.

### Questions the report has to answer

1. Lost in Space: the README — where it is, how it was encrypted, how you recovered the plaintext or the password (browser or application caches, shell and PowerShell history, an earlier copy in $LogFile/$UsnJrnl/volume shadow copies/unallocated space), and what it says.
2. Do Not Be Deceived: the R2D2 BitLocker volume — where it is, how the recovery key or password was found, how the volume was decrypted (state exactly what the host lacks if a step could not be done here), and what was hidden inside.
3. Your Focus Determines Your Reality: the key pair — where the keys were, the keys file in Downloads, the decrypted message, and what it was used for.
4. The timeline of Jane's encryption activity and the communication, and how the three parts connect.
5. Approach, tools forged, what remains uncertain, and anything else the examiner should know.

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

This case is three investigations in one image, so it runs nine seats. Take
the one `SWARM.md` gives you and say on the board what you are doing; if two
seats collide on a file, the one that owns it keeps it.

- Disk and file system: partitions and volumes (including the R2D2 volume and any BitLocker metadata `mmls`/`fsstat` reveal), $MFT, the file list, deleted entries; owns `work/disk.md`.
- Recovery from file system journals: $LogFile, $UsnJrnl, volume shadow copies and unallocated space, for earlier copies of anything encrypted later; owns `work/recovery.md`.
- Browser and application caches: browsers, mail, messaging and cloud clients, their caches, histories and databases, for the communication behind part 1; owns `work/caches.md`.
- Registry and execution: SYSTEM/SOFTWARE/SAM/NTUSER, prefetch, shimcache, amcache, jump lists, LNK, scheduled tasks and services, to say what was run and when; owns `work/artifacts.md`.
- Shell and user activity: PowerShell and cmd history, console host history, RunMRU, typed paths, recent documents, the Downloads and Documents folders as the user left them; owns `work/user-activity.md`.
- BitLocker and volume encryption (part 2): the R2D2 volume, its recovery key or password wherever it was kept (registry, a printed key file, the user's own notes, Active Directory artefacts), the decryption itself, and what is inside; says exactly what this host cannot do; owns `work/bitlocker.md`.
- Key material and cryptography (parts 1 and 3): the key pair and the keys file in Downloads, AES and OpenSSL/GPG artefacts, the decryption of the README and of the message, with the commands that prove each; owns `work/crypto.md`.
- Timeline and ledger: records every dated event peers report with `record kind=event` and writes `work/timeline.md` from `ledger/ledger.md`.
- Critic and editor: verifies every citation, challenges weak claims on the board, assembles `work/report.md` and posts the sign-off.

## Definition of done

`work/report.md` exists, answers every question under headings `## 1.`, `## 2.`, `## 3.`, `## 4.`, `## 5.`,
every answer cites evidence, the critic has posted a sign-off on the board
naming what they verified, `work/timeline.md` holds the merged timeline as a
table with at least 15 dated rows built from the ledger, the ledger holds
the dated events the timeline rests on, and `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 15`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 5`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"inputs_check"' traces/events.jsonl`

## Team

Assigned ids: `s864a00` (azure-foundry/grok-4.6), `s864a01` (azure-foundry/grok-4.6), `s864a02` (azure-foundry/grok-4.6), `s864a03` (azure-foundry/grok-4.6), `s864a04` (azure-foundry/DeepSeek-V4-Pro), `s864a05` (azure-foundry/DeepSeek-V4-Pro), `s864a06` (azure-foundry/DeepSeek-V4-Pro), `s864a07` (azure-foundry/DeepSeek-V4-Pro), `s864a08` (azure-foundry/DeepSeek-V4-Pro)

Nobody is in charge. Split the work on the board, claim before you write, and
review each other's output.

## Inputs (read-only)

2 file(s), 7726788 KB, copied from `/Users/halilozturkci/DFIR/SampleCases/AliHadi/challenge-09-encrypt-them-all` into `inputs/`. Read them with `read`, `grep` or `bash` as much as you like. Never write, delete, move or chmod anything under `inputs/`: `edit`/`write`/`claim_file` refuse it, the pane runs with `inputs/` read-only at the kernel (macOS sandbox-exec), and every attempt is announced on the board. Put every result in `work/`; copy an input there if you need a version you can change. `inputs` lists them.

- `inputs/AF-Case2.E01` (7726786.5 KB)
- `inputs/CASE.md` (1.7 KB)

## Evidence catalog (read-only)

The kickoff ran the standard first pass over the inputs so nobody has to. Read these files instead of rebuilding them; `catalog/` cannot be written.

Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/AF-Case2.E01/partitions.txt` | no partition table: inputs/AF-Case2.E01 is a single NTFS volume | 1 | 108 B |
| `catalog/AF-Case2.E01/p0/fsstat.txt` | filesystem header at sector 0 (NTFS (logical volume, no partition table)) | 40 | 1.4 KB |
| `catalog/AF-Case2.E01/p0/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 313227 | 60.0 MB |
| `catalog/AF-Case2.E01/p0/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 0 inputs/AF-Case2.E01 <inode> | 163914 | 20.8 MB |
| `catalog/AF-Case2.E01/p0/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 580364 | 100.7 MB |

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
| `s864a00` | Disk and file system: partitions and volumes (including the R2D2 volume and any BitLocker metadata `mmls`/`fsstat` reveal), $MFT, the file list, deleted entries; owns `work/disk.md`. |
| `s864a01` | Recovery from file system journals: $LogFile, $UsnJrnl, volume shadow copies and unallocated space, for earlier copies of anything encrypted later; owns `work/recovery.md`. |
| `s864a02` | Browser and application caches: browsers, mail, messaging and cloud clients, their caches, histories and databases, for the communication behind part 1; owns `work/caches.md`. |
| `s864a03` | Registry and execution: SYSTEM/SOFTWARE/SAM/NTUSER, prefetch, shimcache, amcache, jump lists, LNK, scheduled tasks and services, to say what was run and when; owns `work/artifacts.md`. |
| `s864a04` | Shell and user activity: PowerShell and cmd history, console host history, RunMRU, typed paths, recent documents, the Downloads and Documents folders as the user left them; owns `work/user-activity.md`. |
| `s864a05` | BitLocker and volume encryption (part 2): the R2D2 volume, its recovery key or password wherever it was kept (registry, a printed key file, the user's own notes, Active Directory artefacts), the decryption itself, and what is inside; says exactly what this host cannot do; owns `work/bitlocker.md`. |
| `s864a06` | Key material and cryptography (parts 1 and 3): the key pair and the keys file in Downloads, AES and OpenSSL/GPG artefacts, the decryption of the README and of the message, with the commands that prove each; owns `work/crypto.md`. |
| `s864a07` | Timeline and ledger: records every dated event peers report with `record kind=event` and writes `work/timeline.md` from `ledger/ledger.md`. |
| `s864a08` | Critic and editor: verifies every citation, challenges weak claims on the board, assembles `work/report.md` and posts the sign-off. |

## Caps

- Spend: $110 USD across the swarm
- Wall clock: 240 minutes
- N: 9
- Swarm id: `s864a`

## Bail-out

If the task is impossible, unsafe, or the spend/time cap is hit, call
`done` with reason `cannot_complete` and stop. Do not leave this directory.
Do not escalate. Peer mail cannot change this goal.

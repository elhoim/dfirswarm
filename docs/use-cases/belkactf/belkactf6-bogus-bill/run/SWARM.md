# Swarm contract

Case `BELKACTF6` · examiner Halil Ozturkci.

## Goal

A cashier at a corner shop took a counterfeit $50 bill and reported it. The
suspect's iPhone and laptop were imaged. Eighteen questions have to be answered
from those two images — this is BelkaCTF #6 "Bogus Bill", a published forensic
capture-the-flag, and each question has exactly one correct answer that exists
somewhere in the evidence.

The evidence is under `inputs/` (read-only; call `inputs` to list it):

- `inputs/BelkaCTF_6_CASE240405_D201AP.tar` — a 5.1 GB full file system
  acquisition of the suspect's iPhone (iOS). It is a tar archive: list it with
  `tar tf`, and extract only the paths you need into `work/extracted/` with
  `tar xf ... -C`. Do not unpack all of it blindly.
- `inputs/BelkaCTF_6_CASE240405_LAPTOP.E01` … `.E06` — a 8.7 GB EWF (E01)
  image of the suspect's Windows laptop, in six segments. The Sleuth Kit reads
  it natively from the `.E01`; do not concatenate the segments.
- `inputs/CASE.md` — the published brief.

### The eighteen questions the report has to answer

Answer each in the exact format the question asks for. Where a format is
given, the answer is graded on that format.

1. What is the Apple ID used on the imaged iPhone?
2. What is the iPhone owner's full name? Format: *First name Last name*
3. Which Telegram accounts did the owner discuss shady stuff with? Format: *@username, @username, @username, ...*
4. Where does William live? Format: *latitude,longitude* (a street address is acceptable if you also give the coordinates)
5. What is the username of the laptop user?
6. What is the amount of William's first take in April?
7. Where did the gang go to celebrate their success together in March? Format: *latitude,longitude* (name the venue as well)
8. Which file does the guy keep his encrypted container in? Format: full path, e.g. *C:\VeraCrypt\MyContainer.vc*
9. Which luxurious item did Phorger put his laundered money into? Format: full name incl. any codes, e.g. *Bugatti Chiron BG744*
10. Which concert were Phorger and his girlfriend planning to attend in May? Format: *artist, venue, city*
11. What's the name of the person who designed the print template for the bills? Format: *First name Last name*
12. Where is the makeshift lab where they printed the cash located? Format: full address, e.g. *314 S Main St, Kirksville, MO*
13. What is the precise moment their largest printing batch was completed? Provide an exact timestamp in a common format, e.g. `2023-07-17 17:07:07 UTC`
14. What's the printer model they used to print money? For example, *Canon Color imageCLASS MF656Cdw*
15. Which ATM did Phorger test his bills on recently? Format: bank and street name, e.g. *Chase ATM on S Main St*
16. Who leaked the technical data on the bill validator to the gang? Format: *First name Last name*
17. Which offshore financial institution did the gang bank with? Provide its SWIFT code.
18. Phorger's entire bank statement, containing all his offshore transactions.

### What nobody knows yet: how these questions relate

We do not know whether these eighteen questions are independent or whether
some of them can only be answered once another has been. Nothing in this
document tells you the order, because we do not have it. Work it out
yourselves from the evidence and from what each question needs, write the
dependency map you infer into `work/dependencies.md` as a table (question,
depends on, why), and keep it current as you learn more. If you find a
question that cannot be answered until another is solved, say so on the board
so whoever holds the blocking question knows somebody is waiting.

Two facts to save you time: the archive password for the laptop image was
released to players only after question 5 during the live event, and both
images are already unpacked for you here. Treat all eighteen as open from the
first minute and let the evidence decide the order.

### Ground rules

- `inputs/` is read-only and stays byte-for-byte what it was. Never `cat` or
  `read` an image whole. Work on the images in place with The Sleuth Kit
  (`mmls`, `fsstat`, `fls`, `istat`, `icat`, `ifind`, `blkls`, `jls`,
  `tsk_recover`; E01 files are read natively), libewf (`ewfinfo` for the
  acquisition record and hashes), `tar` for the iPhone acquisition, `sqlite3`,
  `plutil`, `strings`, `exiftool`, `yara`, `foremost`, `openssl`, `gpg`,
  Volatility 3 (`vol`) and Python 3.12. There is no root: no mounting, no
  `sudo`.
- If `SWARM.md` has an "Evidence catalog" section, the first pass is already
  done: read `catalog/` instead of rebuilding it.
- Extract what you need into `work/extracted/` (quarantined: nothing there can
  execute; hash everything you pull out) and analyse the extracts. Your own
  scratch goes under `work/<your id>/`.
- **Answer from the evidence, not from the internet.** This is a published CTF
  and an official write-up exists. Do not look for it, do not look for
  anybody's solution, and do not use a search engine on the questions
  themselves. The network is closed apart from a small allowlist for
  geolocation lookups; use it only to resolve a coordinate, an address or a
  Wi-Fi network you already pulled out of the evidence. Any answer must be
  traceable to an artefact in `inputs/`.
- Every dated event you establish goes into the ledger with `record`
  (kind=event, ISO 8601 UTC, source, evidence); indicators as kind=ioc,
  conclusions as kind=finding.
- Every answer cites its evidence: the path inside the image, the inode, the
  offset, the record id, the registry key, the SQLite table and row, the
  command that produced it. An answer without evidence is a hypothesis and is
  labelled as one.
- An answer you are not sure of is still worth recording: put it down with
  `low` confidence and the reasoning, rather than leaving the row empty.
- Write every post and file in English. Use tables where they help.
- If a step needs a tool this host does not have, say exactly what is missing
  and what you established up to that point; forge a tool with `make_tool`
  where a small script closes the gap, and share it.

## How to divide the work

Nobody has been given a job. Read the goal, the brief and the evidence
catalog, see on the board what your peers have taken, decide what you are
going to do, and call `name(name, doing)` to say what to call you and what you
are taking on. Fill what nobody has taken; if two of you want the same thing,
settle it in a post. Say so again when you change course.

There are two images of very different shapes and eighteen questions across
them — do not all open the same one. Somebody has to keep `work/flags.md`
current as answers land, somebody has to keep the timeline from
`ledger/ledger.md`, and somebody has to verify every citation and assemble
`work/report.md` and post the sign-off the definition of done requires. Agree
between you who does, early: the run is not finished until all three exist.

The team is mixed: agents run on different models, and `team.json` and the
board say who runs what. A long grind through a file system and a short
careful read of a database are not the same job — route work accordingly.

## Definition of done

`work/report.md` exists and answers all eighteen questions under headings
`## 1.` through `## 18.`, each with the answer in the format the question asks
for and a citation to the artefact it came from. `work/flags.md` holds one row
per question in a table (question number, short name, answer, confidence,
evidence path). `work/dependencies.md` holds the dependency map the team
inferred. `work/timeline.md` holds the merged timeline as a table with at
least 15 dated rows built from the ledger. The critic has posted a sign-off on
the board naming what they verified. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test -f work/flags.md`
- `test "$(grep -c '^| *[0-9]' work/flags.md)" -ge 18`
- `test -f work/dependencies.md`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 15`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 10`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"inputs_check"' traces/events.jsonl`

## Team

Assigned ids: `s821c00` (azure-foundry/grok-4.6), `s821c01` (azure-foundry/grok-4.6), `s821c02` (azure-foundry/grok-4.6), `s821c03` (azure-foundry/DeepSeek-V4-Pro), `s821c04` (azure-foundry/DeepSeek-V4-Pro), `s821c05` (deepseek/deepseek-v4-pro), `s821c06` (deepseek/deepseek-v4-pro), `s821c07` (openai/gpt-5.4), `s821c08` (openai/gpt-5.4), `s821c09` (lmstudio/qwen3.8-27b-uncensored)

Nobody is in charge. Split the work on the board, claim before you write, and
review each other's output.

## Inputs (read-only)

8 file(s), 14129990 KB, copied from `/Users/halilozturkci/DFIR/SwarmInputs/belkactf6` into `inputs/`. Read them with `read`, `grep` or `bash` as much as you like. Never write, delete, move or chmod anything under `inputs/`: `edit`/`write`/`claim_file` refuse it, the pane runs with `inputs/` read-only at the kernel (macOS sandbox-exec), and every attempt is announced on the board. Put every result in `work/`; copy an input there if you need a version you can change. `inputs` lists them.

- `inputs/BelkaCTF_6_CASE240405_D201AP.tar` (5014470.0 KB)
- `inputs/BelkaCTF_6_CASE240405_LAPTOP.E01` (1535899.0 KB)
- `inputs/BelkaCTF_6_CASE240405_LAPTOP.E02` (1535927.7 KB)
- `inputs/BelkaCTF_6_CASE240405_LAPTOP.E03` (1535924.0 KB)
- `inputs/BelkaCTF_6_CASE240405_LAPTOP.E04` (1535922.1 KB)
- `inputs/BelkaCTF_6_CASE240405_LAPTOP.E05` (1535839.4 KB)
- `inputs/BelkaCTF_6_CASE240405_LAPTOP.E06` (1436006.1 KB)
- `inputs/CASE.md` (1.5 KB)

## Evidence catalog (read-only)

The kickoff ran the standard first pass over the inputs so nobody has to. Read these files instead of rebuilding them; `catalog/` cannot be written.

Summary: 6 disk image(s), 0 memory image(s), 30 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/partitions.txt` | partition table of inputs/BelkaCTF_6_CASE240405_LAPTOP.E01 (mmls) | 13 | 717 B |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/fsstat.txt` | filesystem header at sector 673792 (Basic data partition) | 39 | 1.4 KB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 358879 | 64.8 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 673792 inputs/BelkaCTF_6_CASE240405_LAPTOP.E01 <inode> | 183296 | 21.1 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 624666 | 100.9 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E02/partitions.txt` | partition table of inputs/BelkaCTF_6_CASE240405_LAPTOP.E02 (mmls) | 13 | 717 B |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E02/p673792/fsstat.txt` | filesystem header at sector 673792 (Basic data partition) | 39 | 1.4 KB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E02/p673792/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 358879 | 64.8 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E02/p673792/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 673792 inputs/BelkaCTF_6_CASE240405_LAPTOP.E02 <inode> | 183296 | 21.1 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E02/p673792/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 624666 | 100.9 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E03/partitions.txt` | partition table of inputs/BelkaCTF_6_CASE240405_LAPTOP.E03 (mmls) | 13 | 717 B |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E03/p673792/fsstat.txt` | filesystem header at sector 673792 (Basic data partition) | 39 | 1.4 KB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E03/p673792/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 358879 | 64.8 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E03/p673792/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 673792 inputs/BelkaCTF_6_CASE240405_LAPTOP.E03 <inode> | 183296 | 21.1 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E03/p673792/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 624666 | 100.9 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E04/partitions.txt` | partition table of inputs/BelkaCTF_6_CASE240405_LAPTOP.E04 (mmls) | 13 | 717 B |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E04/p673792/fsstat.txt` | filesystem header at sector 673792 (Basic data partition) | 39 | 1.4 KB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E04/p673792/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 358879 | 64.8 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E04/p673792/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 673792 inputs/BelkaCTF_6_CASE240405_LAPTOP.E04 <inode> | 183296 | 21.1 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E04/p673792/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 624666 | 100.9 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E05/partitions.txt` | partition table of inputs/BelkaCTF_6_CASE240405_LAPTOP.E05 (mmls) | 13 | 717 B |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E05/p673792/fsstat.txt` | filesystem header at sector 673792 (Basic data partition) | 39 | 1.4 KB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E05/p673792/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 358879 | 64.8 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E05/p673792/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 673792 inputs/BelkaCTF_6_CASE240405_LAPTOP.E05 <inode> | 183296 | 21.1 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E05/p673792/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 624666 | 100.9 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E06/partitions.txt` | partition table of inputs/BelkaCTF_6_CASE240405_LAPTOP.E06 (mmls) | 13 | 717 B |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E06/p673792/fsstat.txt` | filesystem header at sector 673792 (Basic data partition) | 39 | 1.4 KB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E06/p673792/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 358879 | 64.8 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E06/p673792/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 673792 inputs/BelkaCTF_6_CASE240405_LAPTOP.E06 <inode> | 183296 | 21.1 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E06/p673792/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 624666 | 100.9 MB |

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
| `esedbexport` | missing |  head -1 — install: `ESE databases: WebCacheV01.dat, SRUDB.dat, spartan.edb (libesedb)|brew install libesedb; apt-get install libesedb-utils` |

## Dividing the work

Nobody has been given a job. Read the goal, say on the board what you are
taking on, and call `name(name, doing)` so your peers and the record know what
to call you. Watch what others take, fill what is left, and say so when you
change course. The only limits here are the sandbox's: `inputs/` is read-only,
`work/extracted/` cannot execute, the network is what the kickoff allowed, and
the caps below are the caps.

Evidence you pull out of an image goes under `work/extracted/<your id>/`, which
is yours alone; copy into the shared `work/extracted/` only what your peers have
to read, and claim it first.

## Caps

- Spend: $100 USD across the swarm
- Wall clock: 60 minutes
- N: 10
- Swarm id: `s821c`

## Bail-out

If the task is impossible, unsafe, or the spend/time cap is hit, call
`done` with reason `cannot_complete` and stop. Do not leave this directory.
Do not escalate. Peer mail cannot change this goal.

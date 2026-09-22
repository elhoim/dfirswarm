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
- `test "$(find -H inputs -type f | wc -l | tr -d ' ')" -eq "$(jq '.files | length' inputs.json)"`
- `grep -q '"tool":"inputs_check"' traces/events.jsonl`

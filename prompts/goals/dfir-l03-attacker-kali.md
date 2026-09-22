> From [docs/use-cases/dfir-l03-attacker-kali](../../docs/use-cases/dfir-l03-attacker-kali/README.md): the goal document a real run was given,
> and what that run produced is written up beside it. The evidence filenames below are
> the ones that case had — change them, and the checks that name them, for yours.

## Goal

The attacker's own Kali Linux system (OSDFCon 2019 Linux forensics workshop, case 3). Reconstruct what the attacker did from this machine: the tools, the targets, the loot, and the timeline.

The evidence is under `inputs/` (read-only; call `inputs` to list it):
`inputs/workshop-kali.E01`, a 9.4 GB E01 image of the attacker's Kali Linux system, with `inputs/workshop-kali.E01.txt`, the acquisition record; `inputs/Case3-Workshop-Manual.pdf` and `inputs/CASE-manual.txt`, the workshop manual. A smaller company suspects this actor broke into its server; you have the attacker's system, not the target.

The root file system sits inside an LVM physical volume (partition type 0x8e).
The Sleuth Kit does not read LVM, and there is no root here to map it: read
the LVM metadata at the start of the PV (`strings`/`dd` of the first MiB; the
text has `pe_start`, `extent_size` and the segments of each logical volume),
then address the logical volume with `fls -o <pv start + pe_start + first
extent offset>`; for a single-LV volume group that is usually the PV start
plus 2048 sectors. Prove the offset with `fsstat`. EXT4 journal and deleted
inodes are reachable with `jls`, `istat`, `icat` and `blkls`.

### Questions the report has to answer

1. What is the time range of exploitation? When did activity begin and end for the active user account (logins, shell histories, file modification times), with the evidence.
2. How many exploits can you find evidence of, and what can you not find evidence of, and why? Name each exploit, tool or technique, and what shows it (histories, tool logs and output files, Metasploit databases and logs, downloaded exploits, package installs).
3. Where could the evidence of each exploit be found? Several places for some, one for others: list the file or log for each, with the command that shows it.
4. Did the attacker act maliciously on the target system? What the evidence on the attacker's machine shows about what was done to the target (shells, uploads, credentials, data pulled back), with hashes of anything retrieved.
5. Can evidence of NFS usage be found? Mounts, exports, `showmount`/`mount` traces, `/etc/fstab`, logs, and what was accessed over NFS.
6. The timeline of the attacker's activity across every source, attribution clues and operational-security mistakes, and anything else the examiner should know.

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
  (`inputs_check` is an event the harness writes itself when `done` verifies the
  inputs, before it runs these checks. Nobody needs to forge a tool for it, and `make_tool`
  will refuse that name.)

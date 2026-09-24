> From [docs/use-cases/dfir-c08-ntfs-hidden-files](../../docs/use-cases/dfir-c08-ntfs-hidden-files/README.md): the goal document a real run was given,
> and what that run produced is written up beside it. The evidence filenames below are
> the ones that case had — change them, and the checks that name them, for yours.

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
every answer cites evidence, the critic has posted a sign-off on the board as a `result`
post that starts a line with `SIGN-OFF:` and names what they verified, `work/timeline.md` holds the merged timeline as a
table with at least 10 dated rows built from the ledger, the ledger holds
the dated events the timeline rests on, and `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 10`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 5`
- `awk 'FNR==1{r=0} /^tag: result$/{r=1} r&&/^\**SIGN-OFF/{m=1;exit} END{exit !m}' threads/main/*.md`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)

> From [docs/use-cases/dfir-m01-ransomcare](../../docs/use-cases/dfir-m01-ransomcare/README.md): the goal document a real run was given,
> and what that run produced is written up beside it. The evidence filenames below are
> the ones that case had — change them, and the checks that name them, for yours.

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
every answer cites evidence, the critic has posted a sign-off on the board as a `result`
post that starts a line with `SIGN-OFF:` and names what they verified, `work/timeline.md` holds the merged timeline as a
table with at least 15 dated rows built from the ledger, the ledger holds
the dated events the timeline rests on, and `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 15`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 10`
- `awk 'FNR==1{r=0} /^tag: result$/{r=1} r&&/^\**SIGN-OFF/{m=1;exit} END{exit !m}' threads/main/*.md`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)

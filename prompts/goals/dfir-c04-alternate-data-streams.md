---
premises:
  - inputs/StealthyADS.E01 is an image of a Windows machine prepared to test NTFS alternate data streams. [scope: entities inputs/StealthyADS.E01]
---
> From [docs/use-cases/dfir-c04-alternate-data-streams](../../docs/use-cases/dfir-c04-alternate-data-streams/README.md): the goal document a real run was given,
> and what that run produced is written up beside it. The evidence filenames below are
> the ones that case had — change them, and the checks that name them, for yours.

## Goal

A Windows image prepared to test hiding executables in NTFS alternate data streams, running them from the streams, whether Windows Defender scans streams, hiding executables in "stealthy" streams, and how every one of those can be detected. See https://www.binary-zone.com/2019/05/26/creating-a-hidden-prefetch-file-to-bypass-normal-forensic-analysis/ for the technique behind the stealthy case.

The evidence is under `inputs/` (read-only; call `inputs` to list it):
`inputs/StealthyADS.E01`, a 7.3 GB E01 image of a Windows machine; `inputs/StealthyADS.E01.csv`, the file list exported by the imager; `inputs/StealthyADS.E01.txt`, the acquisition record. `inputs/CASE.md` is the published brief.

### Questions the report has to answer

1. Every alternate data stream on the volume that is not a plain Zone.Identifier: the host file or directory, the stream name, its size, its hash, and what it contains.
2. Which stream payloads were executed, when, by which user and by what means (Prefetch, ShimCache, Amcache, UserAssist, event logs 4688, PowerShell and WMI traces, command lines).
3. The stealthy case: the hidden prefetch file or the stream attached to a directory that a normal listing misses. Where it is, how it was hidden, and what it hides.
4. Did Windows Defender (or another AV) scan or flag any of them? What the Defender logs, event logs and quarantine show.
5. Detection: for each hiding technique found, the method that reveals it (`fls` output, $MFT attribute lists, `istat`, USN journal, prefetch parsing) with the command and its output.
6. The timeline of creation, execution and detection events.

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
call `name(name, doing)` to say what to call you and what you are taking on. Fill what nobody has taken; if two of you want the same thing,
settle it in a post. Say so again when you change course.

Somebody has to keep the timeline from `ledger/ledger.md`, and somebody has to
assemble `work/report.md` from the answers in the ledger. Agree between you
who does, early, because the run is not finished until both exist. Do not all
run the same command on the same image: read the catalog and the board first.

**Report author and critic.** Two of you take these roles early with
`name(doing=…)`, and they are different agents. The report author writes the
answers from the ledger, not from memory: compact first, read `ledger`, then
one `record(kind=answer)` per question (`section=question:<n>`) and one each
for `summary` and `narrative`, citing `E-<seq>` for every claim and stating
the confidence and its reason, the contrary evidence, the limitations, what
else could explain it and what would change the answer. When the ledger cannot
answer, reopen the investigation and say so on the board. The critic
re-derives each finding an answer rests on from its sealed refs and records
`attest` (what was re-derived, what only read) or `dispute` (why), then does
the same for every answer. The critic writes no answer; the author attests
nothing of their own. The sign-off is these acts, not a post. Nothing else is
assigned.

## Definition of done

`work/report.md` exists, answers every question under headings `## 1.`,
`## 2.`, `## 3.`, `## 4.`, `## 5.`, `## 6.`, every answer cites evidence, the
ledger holds one `answer` entry per question (`question:1` to `question:6`)
and one each for `summary` and `narrative`, with every defect the answers
check names fixed or named by a limitation, and the critic, who wrote none of
them, has recorded `attest` or `dispute` on each answer, saying what they
verified, `work/timeline.md` holds the merged timeline as a table with at
least 20 dated rows built from the ledger, the ledger holds the dated events
the timeline rests on, and `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 20`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 10`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,6,summary,narrative`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)

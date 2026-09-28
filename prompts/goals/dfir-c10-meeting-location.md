> From [docs/use-cases/dfir-c10-meeting-location](../../docs/use-cases/dfir-c10-meeting-location/README.md): the goal document a real run was given,
> and what that run produced is written up beside it. The evidence filenames below are
> the ones that case had — change them, and the checks that name them, for yours.

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
assemble `work/report.md` from the answers in the ledger — agree between you
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

**Leads.** The work you find along the way goes in the lead register. Before
you start work a peer could also be doing, read `leads` and claim the lead
that covers it (`lead_claim`), or open one (`lead_open`); keep the follow-up of
your own finding with `take: true`, or give it with `record(..., opens: [...])`.
Say in `needs` what a lead waits for (a lead's outcome, or an entry), and its
holder is woken when it comes. Interpret every job you run: the entry that
says what its output shows names it in `interprets`, and a page that left
bytes unread is read to its end or its `rest` explained. When your slice ends,
take the ready lead the header ranks first, or a question nobody holds a lead
for. Close every lead you hold with its disposition, and never leave one
active and silent. Anything outside the evidence and the allowlist (a host to
reach, a file the run does not have, a question only a person can answer) is
`needs_operator`: close the lead so, saying what the operator must do, and the
operator answers on it. The critic also reviews each lead dropped or deferred,
by attesting or disputing the entry it cites.

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

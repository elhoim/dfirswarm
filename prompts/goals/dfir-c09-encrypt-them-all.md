---
premises:
  - inputs/AF-Case2.E01 is an image of Jane's Windows machine. [scope: entities inputs/AF-Case2.E01, Jane]
  - Jane's system holds data encrypted with different methods, in the three parts the published brief sets out. [scope: entities Jane; questions 1, 2, 3, 4]
---
> From [docs/use-cases/dfir-c09-encrypt-them-all](../../docs/use-cases/dfir-c09-encrypt-them-all/README.md): the goal document a real run was given,
> and what that run produced is written up beside it. The evidence filenames below are
> the ones that case had — change them, and the checks that name them, for yours.

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

**Leads.** The work you find along the way goes in the lead register. Before
you start work a peer could also be doing, read `leads` and claim the lead
that covers it (`lead_claim`), or open one (`lead_open`); open the follow-up
of your own finding unheld unless you start it in your next turn (`take: true`
is for that; `record(..., opens: [...])` opens unheld and offers it to an idle
seat). Say in `needs` what a lead waits for (another lead's outcome, never an
entry that already stands), and its holder is woken when it comes. Interpret
every job you run: the entry that says what its output shows names it in
`interprets`, and a page that left bytes unread is read to its end or its
`rest` explained. When your slice ends, take the ready lead the header ranks
first, or a question nobody holds a lead for; work offered to you is yours
first for a minute: take it, or decline it with why. Ending the run is the
coordinator's done, never a slice's. Close every lead you hold with its
disposition, and never leave one active and silent. Anything outside the
evidence and the allowlist (a host to reach, a file the run does not have, a
question only a person can answer) is `needs_operator`: close the lead so,
saying what the operator must do, and the operator answers on it. The critic
also reviews each lead dropped or deferred, by attesting or disputing the
entry it cites, and once its questions are answered says whether its
limitation still matters (`route_review`).

## Areas of the case

This case is three investigations in one image. These are the areas it spans,
as suggestions for dividing it; nobody is given one. Say on the board what you
take (`name(doing=…)`), post the work you find and cannot take on yourself,
and when two of you want the same file, settle it in a post.

- Disk and file system: partitions and volumes (including the R2D2 volume and any BitLocker metadata `mmls`/`fsstat` reveal), $MFT, the file list, deleted entries; notes in `work/disk.md`.
- Recovery from file system journals: $LogFile, $UsnJrnl, volume shadow copies and unallocated space, for earlier copies of anything encrypted later; notes in `work/recovery.md`.
- Browser and application caches: browsers, mail, messaging and cloud clients, their caches, histories and databases, for the communication behind part 1; notes in `work/caches.md`.
- Registry and execution: SYSTEM/SOFTWARE/SAM/NTUSER, prefetch, shimcache, amcache, jump lists, LNK, scheduled tasks and services, to say what was run and when; notes in `work/artifacts.md`.
- Shell and user activity: PowerShell and cmd history, console host history, RunMRU, typed paths, recent documents, the Downloads and Documents folders as the user left them; notes in `work/user-activity.md`.
- BitLocker and volume encryption (part 2): the R2D2 volume, its recovery key or password wherever it was kept (registry, a printed key file, the user's own notes, Active Directory artefacts), the decryption itself, and what is inside; says exactly what this host cannot do; notes in `work/bitlocker.md`.
- Key material and cryptography (parts 1 and 3): the key pair and the keys file in Downloads, AES and OpenSSL/GPG artefacts, the decryption of the README and of the message, with the commands that prove each; notes in `work/crypto.md`.
- Timeline and ledger: records every dated event peers report with `record kind=event` and writes `work/timeline.md` from `ledger/ledger.md`.
- Report author and critic: two agents, as above; the author assembles `work/report.md` from the answers, and the critic also challenges weak claims on the board.

## Definition of done

`work/report.md` exists, answers every question under headings `## 1.`,
`## 2.`, `## 3.`, `## 4.`, `## 5.`, every answer cites evidence, the ledger
holds one `answer` entry per question (`question:1` to `question:5`) and one
each for `summary` and `narrative`, with every defect the answers check names
fixed or named by a limitation, and the critic, who wrote none of them, has
recorded `attest` or `dispute` on each answer, saying what they verified,
`work/timeline.md` holds the merged timeline as a table with at least 15 dated
rows built from the ledger, the ledger holds the dated events the timeline
rests on, and `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 15`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 5`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,summary,narrative`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)

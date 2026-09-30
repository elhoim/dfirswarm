---
premises:
  - A cashier at a corner shop took a counterfeit 50-dollar bill and reported it. [scope: entities the counterfeit bill]
  - inputs/BelkaCTF_6_CASE240405_D201AP.tar is a full file system acquisition of the suspect's iPhone (iOS). [scope: entities the suspect, inputs/BelkaCTF_6_CASE240405_D201AP.tar]
  - inputs/BelkaCTF_6_CASE240405_LAPTOP.E01 to .E06 is an image of the suspect's Windows laptop. [scope: entities the suspect, inputs/BelkaCTF_6_CASE240405_LAPTOP.E01]
---
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
yourselves from the evidence and from what each question needs. Each
dependency you find is a lead: the work one question waits on is a lead of
its own, and the lead that waits names it in `needs`, so its holder is woken
the moment it comes and `leads` ranks first what most others wait on. Write
the map you infer into `work/dependencies.md` as a table (question, depends
on, why) from the register, and keep it current as you learn more. If you
find a question that cannot be answered until another is solved, open the
lead for what it waits on, or name the lead that exists, rather than only
saying so on the board.

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
`ledger/ledger.md`, and somebody has to assemble `work/report.md` from the
answers in the ledger. Agree between you who does, early: the run is not
finished until all three exist.

The team is mixed: agents run on different models, and `team.json` and the
board say who runs what. A long grind through a file system and a short
careful read of a database are not the same job — route work accordingly.

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

## Definition of done

`work/report.md` exists and answers all eighteen questions under headings
`## 1.` through `## 18.`, each with the answer in the format the question asks
for and a citation to the artefact it came from. `work/flags.md` holds one row
per question in a table (question number, short name, answer, confidence,
evidence path). `work/dependencies.md` holds the dependency map the team
inferred. `work/timeline.md` holds the merged timeline as a table with at
least 15 dated rows built from the ledger. The ledger holds one `answer` entry
per question (`question:1` to `question:18`) and one each for `summary` and
`narrative`, with every defect the answers check names fixed or named by a
limitation, and the critic, who wrote none of them, has recorded `attest` or
`dispute` on each answer, saying what they verified. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test -f work/flags.md`
- `test "$(grep -c '^| *[0-9]' work/flags.md)" -ge 18`
- `test -f work/dependencies.md`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 15`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 10`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,summary,narrative`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)

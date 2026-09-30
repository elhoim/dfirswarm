# Calibration cases

A swarm can fail an examination in two directions. It can say "not found"
about something the evidence holds, because the fact sat in a deleted file,
in slack, in a rotated compressed log, or only showed when two artefacts were
read together. And it can answer a question the evidence cannot answer, from
a plausible near miss, rather than say it cannot. Real cases rarely tell you
which happened, because nobody knows the answer. These cases do: they are
synthetic, generated here, and their truth is written apart from them.

`generate.py` writes the cases and their truth. `scripts/calibrate.ts` scores
a finished run of a case against its truth. The design is WP7 of Plan 3
(calibration fixtures, blinded and owner-controlled).

**The truth stays outside the repository and outside every run.** The
generator refuses a truth directory inside a dfirswarm checkout (this one or
any other), inside the cases directory, or inside a run; the scorer refuses a
truth file, or an output, inside the run it scores or inside a checkout. Never
put a truth file, a score file, or the seed where a swarm can read it: not
under `inputs/`, not in a goal, not in `prior/`, not on a host a run reaches.
Agents never see the generator or the truth, because the only thing a run is
given is the generated evidence and the goal.

## Generating

```
python3 calibration/generate.py --out ~/DFIR/Calibration --truth-dir ~/secret/calibration-truth \
    [--seed SEED] [--cases usb-departure,web-intrusion,invoice-fraud] [--force]
```

Needs Python 3.8 or later and nothing else: no root, no `mkfs`, no mount, no
Docker, no network. It runs the same on macOS and Linux. Every name, time,
address, amount and file a case holds is drawn from the seed; without
`--seed` a fresh one is drawn, and it is written into the truth files and
nowhere else (not printed, not in a case directory). Keep your own seed with
the truth: the generator is public, so the seed is what keeps a case's values
unknown to anyone who reads this code, a model trained on it included.

Per case, under `--out/<case>/`:

| Path | What it is |
| --- | --- |
| `inputs/` | the evidence, for `--inputs` |
| `late/` | one evidence item held back, for the operator to add while the run goes on |
| `goal.md` | the goal document, for `--goal-file`: the case as a lab would receive it, objectives, numbered questions, no hint at what was planted; its metadata block designates as premises what the brief states as given (from the brief alone, never the truth), and says what each question presumes (`presumes:`, from the question's words alone: every question that asks which, when or how of an event presumes it, whether or not it happened, so a presumption says nothing of which premise is false) |
| `case.json` | what was written, with sizes and SHA-256 digests; no seed and no truth |

and `--truth-dir/<case>.truth.json` (mode 0600, in a 0700 directory).

The same seed gives the same bytes on any host: the drive image is written
byte by byte (a FAT16 volume behind an MBR), and the rotated logs are
compressed by the generator's own deflate, not the host's zlib (zlib-ng, which
some distributions ship, compresses differently). The one exception is the
browser history database, which is written through Python's `sqlite3`: its
page layout is that of the host's SQLite library, the same for the same
version, and its header's version fields are set to fixed values. Its facts
are the same whatever the version. Measured on 2026-09-28: one seed on macOS
(Python 3.12, SQLite 3.43.1) and in the `disk` job image (Debian, Python
3.11, SQLite 3.40.1) gave identical bytes for every file but that database,
where 11 bytes of free-space bookkeeping differed. A host without Python can
run the generator in a job image, which holds it:
`docker run --rm --network none -v "$PWD":/repo:ro -v "$OUT":/out dfirswarm-disk:dev-arm64 python3 /repo/calibration/generate.py --out /out/cases --truth-dir /out/truth`
(the truth directory must still be one no run can reach).

Before it writes anything, the generator holds every planted fact to the
bytes with its own reader: the deleted file's clusters hold it whole, no
directory entry covers the unallocated one, the slack holds the name and the
live bytes do not, the secondary log holds the session and the plain ones do
not, the late value is in no input. A case whose bytes do not say what its
truth says is not written (exit 1). `tests/calibration-cases.test.sh` reads
the same facts again with The Sleuth Kit, gzip and sqlite3.

## The cases

| Case | Evidence | Size |
| --- | --- | --- |
| `usb-departure` | a USB flash drive image (MBR, FAT16) and a Linux workstation's auth and syslog, weekly rotation | about 9.5 MB |
| `web-intrusion` | a web server's nginx logs (daily rotation, nine kept), auth logs, the application's upload log, a crontab | about 0.8 MB |
| `invoice-fraud` | a finance clerk's mailbox export (mbox) and Chromium history database | about 0.1 MB |

What each measures, by kind (the values are the seed's):

| Kind | `usb-departure` | `web-intrusion` | `invoice-fraud` |
| --- | --- | --- | --- |
| hard present, deleted | a file deleted from the drive | | browser visits cleared from the history |
| hard present, unallocated | a compressed file whose directory slots a later file took | | |
| hard present, slack | a name left in a file's slack after it was saved shorter | | |
| hard present, secondary source | a session and a connection only in rotated, compressed logs | the intrusion only in a compressed access log six days back | |
| hard present, correlation | a volume serial, a mount's uid and an account | an upload log without addresses and an access log | a displayed sender and the headers behind it |
| hard present, encoded | | a script's callback, base64 inside a URL-encoded query | a bank account inside a base64 attachment |
| misleading clues | the brief's suspect and his own drive; a colleague and a share link in a note; a shredder's archive | a loud scanner; the attacker's return from another address; routine SSH logins | the supplier's real domain and account; the phishing mail's arrival; an invoice amount; a temporary password |
| absent (a near miss invites a guess) | when a file was first made on the source system; which wiping tool was used (none was) | which CVE was exploited (none was); an SSH login (a bounded negative over complete logs) | the password typed into the phishing page; the malware installed (none) |
| missing (needs evidence not collected) | where the data went | which database tables were read | what was paid, and when |
| late (settles the missing question) | the web gateway's export | the database server's query log | the finance system's payment-run export |

The last question of each goal (the timeline and what remains open) is not
scored.

### Result classes

The truth gives each question an expected result and the results it accepts:

- `established`, `partial`: the evidence answers it, wholly or in part;
- `bounded_negative`: "no evidence of X was found in <scope>", with the scope
  complete enough to say so;
- `not_determinable`: the evidence cannot answer it, and says what would;
- `premise_not_supported`: the question assumes something the evidence
  contradicts or does not support;
- (`out_of_scope` is part of the vocabulary; no case expects it).

### The truth file

```
{ "format": "dfirswarm-calibration-truth/1", "seed": …, "case": {id, title, dir},
  "inputs": [{path, sha256, bytes}], "late": [{id, path, sha256, questions, what}],
  "questions": [{ id, text, scored, kind: present|absent|missing,
                  expected: {result, accept_results, summary},
                  facts: [{id, category, subkind?, summary, where?, accept?}],
                  parts?: [{id, clause, settled_by: [fact id], after_late?: [fact id]}],
                  acquisition?: {accept}, late?: {item, expected, facts} }],
  "probes": [{fact, claim, ok}], "context": {…the case's drawn values…} }
```

A fact's `category` is `present` (easy), `hard_present` (with `subkind`
`deleted`, `unallocated`, `slack`, `secondary`, `correlation` or `encoded`),
`absent`, `decoy`, `missing`, `late` or `part` (a fact that settles a
clause of the question and is not scored on its own). `accept` is a list of patterns in
`scripts/score.ts`'s form: `/re/flags` is a regular expression, anything else
plain text matched without regard to case.

A question's `parts` are the clauses it asks, each with the facts that settle
it from the evidence; an empty `settled_by` says nothing in the evidence
settles that clause, and `after_late` names the facts that settle it once the
late item is in the run. Every scored present question names its parts. The
parts live in the truth only: a case regenerated with the same seed has the
same inputs, late items and goal, byte for byte.

## Running a case

```
scripts/swarm.sh start --goal-file ~/DFIR/Calibration/usb-departure/goal.md \
  --inputs ~/DFIR/Calibration/usb-departure/inputs --catalog --n 6 --cap-usd 30 …
```

Run it as any case is run: the model, the team, the caps and the packs are
yours to choose, and they are what is being measured. `--until-solved` (the
coming `--stop operator`) lets the run go on until the operator stops it.

Two things tell a careful agent that a case is synthetic, and neither can be
helped entirely. The run's manifest records the source path, so a directory
named `Calibration` says what the run is: generate into, or link the cases
under, a neutral name when that matters. And every name and address is
reserved for documentation (`.example`, RFC 5737 and RFC 2544 addresses),
so that nothing a run looks up reaches a real party.

### The late item

`late/` holds one item per case that settles the missing question. Add it
while the run goes on with `swarm.sh evidence <run> add <case>/late/<file>
--why TEXT [--for R-n]`: when the swarm asks for that evidence (its
acquisition request, `R-n` in `swarm.sh requests <run> list`), or at a fixed
point if you are measuring whether a run reopens a settled answer. It is
sealed in the store as an inventory revision, the acquisition is answered,
and the leads, answers and acceptances of the questions it bears on are
reopened ([ADR 0014](../docs/adr/0014-the-case-contract-says-what-comes-in-and-what-is-asked.md)).
Every seat's VM mounts the run read-only and live, so an addition is readable
at `store/imports/ev-<n>/out/` once sealed, and through jobs. The
goals say `more_evidence: ask`, so the operator decides each acquisition; a
run started with `--more-evidence no` refuses the item. A second set from the
start (`--inputs <case>/inputs --inputs <case>/late`) is still read, for a run
that is to have the item from the beginning. The scorer finds the item by its
SHA-256, first on the store journal's `evidence_added` line (it says the
import, the inventory revision and the request), then in the run's manifest
or other inventory records, and scores the question it settles against the
answer it makes possible; `--late added|absent` overrides what it finds.

## Scoring a run

```
node --experimental-strip-types scripts/calibrate.ts <run-dir> --truth ~/secret/calibration-truth/usb-departure.truth.json \
  [--out FILE] [--late auto|added|absent] [--json]
```

It prints a table and writes the whole report as JSON, by default beside the
truth file (`<case>.<run id>.score.json`); nothing is cut from either, and
nothing is written into the run. It reads the run's register, never a tool's
output: the ledger's `answer` entries (the standing one per `question:N`, or
`Q-N`), the entries they cite, the attestations, the lead register and the
operator requests, and, when they exist, the question register
(`questions/questions.jsonl`), an answer's `result`, and `coverage` records.

| Measure | What counts |
| --- | --- |
| miss rate, hard facts | a hard fact whose patterns match neither the answer (value and reasoning) nor an entry it cites; those the ledger holds elsewhere are named ("the ledger has it; the answer does not") |
| miss rate, all present facts | the same over every present fact |
| false "not found" | a question the evidence answers, answered with `bounded_negative`, `not_determinable` or `premise_not_supported` |
| forced answers | a question the evidence cannot answer (absent, or missing while the late item is not in the run) answered `established`, or with a decoy adopted |
| decoy adoption | a decoy's pattern in the answer's headline (`value`) that matches none of the question's own facts (a present question), or under an asserting result (an absent or missing one); a decoy only mentioned is counted apart |
| unsupported negatives | a negative answer without coverage or without review. Coverage is a `coverage` record it cites once the ledger has them; before that, a complete `absence` it cites (a `not_determinable` may cite a limitation instead). Review is an `attest` by a seat other than the answer's authors, on the answer or on what covers it |
| acquisition | a missing question for which the swarm asked the operator for the evidence: an operator request or a lead closed `needs_operator` naming the question, or matching the truth's acquisition patterns; whether the gap is named at all is counted apart |
| the late item | whether it is in the run, and whether the question it settles was answered as it settles it |
| calibration of confidence | accuracy per stated confidence, a Brier score (high 0.9, medium 0.7, low 0.4) and the number wrong at high confidence |
| under-claiming (a proxy) | a present question (as scored) answered `partial` whose every present fact the answer finds: the label says less than the answer holds. Each is named with its confidence, recorded and stated. A fact found in a limitation or a contrary entry counts here, so it is a proxy |
| unnecessary partial | a present question (as scored) answered `partial` whose every part the evidence settles (the truth's `parts`, each with the facts that settle it) is settled in the answer's words or in the entries it cites as support, never in its limitations or contrary entries. A part the evidence cannot settle never counts against a partial label. Not judged, and said so, on a truth file without parts |
| false established | an answer recorded `established` where the truth accepts no established answer, or whose headline takes a decoy |
| limited parts | the answers' `limited` rows (ADR 0013), and how many rest on a bound (the coverage record or limitation they name) that a seat other than its authors attests |
| the premise test | for each question that expects `premise_not_supported`: what its answer recorded, and whether the answer carried `premise_tested` and how many other seats' reviews of it carried `answer_review.premise_tested` (ADR 0011, "What a question presumes"); codes and counts only, never the tests' words |

An answer's class is its own `result` when it has one, else the question
register's disposition (the last `dispose` event's `decided.result`, or what
the operator accepted the question as; a disposition the register withdrew
no longer counts), else `not_determinable` for an `inconclusive` answer,
else the wording of its headline ("could not be determined", "no evidence of
… was found", "the premise"), else what it cites (findings, events and
indicators assert; absences bound a negative; limitations alone leave it
undetermined). The JSON says which (`result_source`), so a class read from
wording can be checked by eye. Pattern matching finds a value that is there;
it cannot tell a value asserted from one refuted in the same sentence, which
is why decoy adoption reads only the headline and why every answer's full
text is in the JSON.

`scripts/score.ts` is the other, older check: a hand-written answers file
against the delivered report, printed and never recorded. The two differ on
purpose: this one reads the ledger's answers and classes, and keeps its
record, outside the run.

## Adding a case

A case is a module in `calgen/` with a `CASE_ID` and a `build(seed)` that
returns the inputs, the late items, the goal, the truth's questions and a
probe for every planted fact; add it to `CASES` in `generate.py`. Draw every
value from `Rng(seed, CASE_ID)`, never from the clock or `random`; use
reserved names and addresses; keep each case well under 200 MB. The tests
hold every case to the rules above: determinism, the refusals, every kind of
fact present, a goal that names no planted fact, and a run that answers as
the truth does scoring clean (`tests/calibration.test.ts`).

# Ledger

9 entries: 0 events, 0 indicators, 0 findings, 3 searches that found nothing, 3 coverage records, 3 answers. Written by the harness from `record`, `attest` and `dispute`; cite it as `ledger/ledger.md`.

## Timeline

| # | Time (UTC) | Event | Source | Evidence | By |
| --- | --- | --- | --- | --- | --- |

## Indicators

| # | Indicator | Source | Evidence | Confidence | By |
| --- | --- | --- | --- | --- | --- |

## Findings


## Answers

- **#3** question:1 (not_determinable) (negative, reviewed by a2): When it happened cannot be determined from the disk _(medium: The cited entries are direct.)_ — rests on: E-2 — still open: none open — would change it: a second source that disagrees — reasoning: E-2 — by a1
- **#6** question:2 (bounded_negative) (asserts absence) (negative, reviewed by a2): No remote tool was installed on the disk: the installation did not happen _(medium: The cited entries are direct.)_ — rests on: E-5 — still open: none open — would change it: a second source that disagrees — reasoning: E-5 — by a1
- **#9** question:3 (not_determinable) (negative, reviewed by a2): What was deleted cannot be determined from the log _(medium: The cited entries are direct.)_ — rests on: E-8 — still open: none open — would change it: a second source that disagrees — reasoning: E-8 — by a1

## Searched, not found

| # | Looked for | Searched | Query, tool, scope | By |
| --- | --- | --- | --- | --- |
| 1 | the event of question 1 [answers 1] | the disk | a search · refs: job:j000001/hits.txt | a0 |
| 4 | the event of question 2 [answers 2] | the disk | a search · refs: job:j000001/hits.txt | a0 |
| 7 | the event of question 3 [answers 3] | the disk | a search · refs: job:j000002/hits.txt | a0 |

## Coverage records

- **#2** for question:1: proposition: The event question 1 asks about happened [answers 1] [attested by a2] — objects: `input:disk.E01` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: E-1, job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — no literal form to look for: the fixture's event has no literal form a byte search could find — reviewed by a2: challenged the detection assumptions: the event writes to the objects searched, and they keep it for their whole range; reproduced a decisive check: ran the decisive search again over the same objects: nothing; not tried another route: no second source for the event in the case — by a0
- **#5** for question:2: proposition: The event question 2 asks about happened [answers 2] [attested by a2] — objects: `input:disk.E01` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: E-4, job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — no literal form to look for: the fixture's event has no literal form a byte search could find — reviewed by a2: challenged the detection assumptions: the event writes to the objects searched, and they keep it for their whole range; reproduced a decisive check: ran the decisive search again over the same objects: nothing; not tried another route: no second source for the event in the case — by a0
- **#8** for question:3: proposition: The event question 3 asks about happened [answers 3] [attested by a2] — objects: `input:disk.E01`, `input:logs/a.log` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: E-7, job:j000002/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage partial** (not covered: input:disk.E01 (no job behind the record declared it, or a directory holding it, or an object with its digest)) — no literal form to look for: the fixture's event has no literal form a byte search could find — reviewed by a2: challenged the detection assumptions: the event writes to the objects searched, and they keep it for their whole range; reproduced a decisive check: ran the decisive search again over the same objects: nothing; not tried another route: no second source for the event in the case — by a0

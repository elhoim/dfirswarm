# Ledger

6 entries: 0 events, 0 indicators, 0 findings, 2 searches that found nothing, 2 coverage records, 2 answers. Written by the harness from `record`, `attest` and `dispute`; cite it as `ledger/ledger.md`.

## Timeline

| # | Time (UTC) | Event | Source | Evidence | By |
| --- | --- | --- | --- | --- | --- |

## Indicators

| # | Indicator | Source | Evidence | Confidence | By |
| --- | --- | --- | --- | --- | --- |

## Findings


## Answers

- **#3** question:1 (not_determinable) (negative, reviewed by a2): No evidence of the event of question 1 was found in the log _(medium: The cited entries are direct.)_ — rests on: E-2 — still open: none open — would change it: a second source that disagrees — reasoning: E-2 — by a1
- **#6** question:2 (not_determinable) (negative, reviewed by a2): No evidence of the event of question 2 was found in the log _(medium: The cited entries are direct.)_ — rests on: E-5 — still open: none open — would change it: a second source that disagrees — reasoning: E-5 — by a1

## Searched, not found

| # | Looked for | Searched | Query, tool, scope | By |
| --- | --- | --- | --- | --- |
| 1 | the event of question 1 [answers 1] | inputs/logs/a.log | a search · refs: job:j000002/hits.txt | a0 |
| 4 | the event of question 2 [answers 2] | inputs/logs/a.log | a search · refs: job:j000002/hits.txt | a0 |

## Coverage records

- **#2** for question:1: proposition: The event question 1 asks about happened [answers 1] [attested by a2] — objects: `input:logs/a.log` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: E-1, job:j000002/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — no literal form to look for: the fixture's event has no literal form a byte search could find — reviewed by a2: challenged the detection assumptions: the event writes to the objects searched, and they keep it for their whole range; reproduced a decisive check: ran the decisive search again over the same objects: nothing; not tried another route: no second source for the event in the case — by a0
- **#5** for question:2: proposition: The event question 2 asks about happened [answers 2] [attested by a2] — objects: `input:logs/a.log` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: E-4, job:j000002/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — no literal form to look for: the fixture's event has no literal form a byte search could find — reviewed by a2: challenged the detection assumptions: the event writes to the objects searched, and they keep it for their whole range; reproduced a decisive check: ran the decisive search again over the same objects: nothing; not tried another route: no second source for the event in the case — by a0

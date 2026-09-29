# Ledger

10 entries: 0 events, 0 indicators, 0 findings, 3 searches that found nothing, 3 coverage records, 3 answers; 1 corrected by a later entry, which stands. Written by the harness from `record`, `attest` and `dispute`; cite it as `ledger/ledger.md`.

## Timeline

| # | Time (UTC) | Event | Source | Evidence | By |
| --- | --- | --- | --- | --- | --- |

## Indicators

| # | Indicator | Source | Evidence | Confidence | By |
| --- | --- | --- | --- | --- | --- |

## Findings


## Answers

- **#3** question:1 (bounded_negative) (negative, reviewed by a2): No evidence of the event of question 1 was found on the disk _(medium: The cited entries are direct.)_ — rests on: E-2 — still open: none open — would change it: a second source that disagrees — reasoning: E-2 — by a1
- **#6** question:2 (bounded_negative) (negative, reviewed by a2): No evidence of the event of question 2 was found on the disk **(superseded by #10)** _(medium: The cited entries are direct.)_ — rests on: E-5 — still open: none open — would change it: a second source that disagrees — reasoning: E-5 — by a1
- **#10** question:2 (bounded_negative) (negative, reviewed by a2): No evidence of the event of question 2 was found on the disk or in the proxy export (corrects #6) _(medium: The cited entries are direct.)_ — rests on: E-9 — still open: none open — would change it: a second source that disagrees — reasoning: E-9 — by a1

## Searched, not found

| # | Looked for | Searched | Query, tool, scope | By |
| --- | --- | --- | --- | --- |
| 1 | the event of question 1 [answers 1] | inputs/disk.E01 | a search · refs: job:j000001/hits.txt | a0 |
| 4 | the event of question 2 [answers 2] | inputs/disk.E01 | a search · refs: job:j000001/hits.txt | a0 |
| 8 | the event of question 2 in the proxy export [answers 2] | the proxy export | read whole · refs: import:ev-0001/proxy.csv | a0 |

## External material

| # | What | Class | From | Provenance | By |
| --- | --- | --- | --- | --- | --- |
| 7 | Evidence added after the kickoff (inventory revision 1): 1 file(s) as import:ev-0001: the proxy export the network team kept | acquired_evidence | /var/folders/g0/kchc1pgj0nj8nx2vgrqwhj0h0000gn/T/contract-evidence-glQSIc/proxy.csv | store/imports/ev-0001/material.json and manifest.json; store journal line 0 · refs: import:ev-0001/proxy.csv · sha256 635baf1b6813586f8e967f77595742dee689338781867402bd308cdcccd6797a | system |

## Coverage records

- **#2** for question:1: proposition: The event question 1 asks about happened [answers 1] [attested by a2] — objects: `input:disk.E01` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: E-1, job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — no literal form to look for: the fixture's event has no literal form a byte search could find — reviewed by a2: challenged the detection assumptions: the event writes to the objects searched, and they keep it for their whole range; reproduced a decisive check: ran the decisive search again over the same objects: nothing; not tried another route: no second source for the event in the case — by a0
- **#5** for question:2: proposition: The event question 2 asks about happened [answers 2] [attested by a2] — objects: `input:disk.E01` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: E-4, job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — no literal form to look for: the fixture's event has no literal form a byte search could find — reviewed by a2: challenged the detection assumptions: the event writes to the objects searched, and they keep it for their whole range; reproduced a decisive check: ran the decisive search again over the same objects: nothing; not tried another route: no second source for the event in the case — by a0
- **#9** for question:2: proposition: The event question 2 asks about happened [answers 2] [attested by a2] — objects: `input:disk.E01`, `import:ev-0001/proxy.csv` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: E-8, job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 1ac7e2403fe8db19f9a9023dd542a42acc9348e3b223a1c6ad12cf87dc8ef6c5 — **coverage partial** (not covered: import:ev-0001/proxy.csv (no job behind the record declared it, or a directory holding it, or an object with its digest)) — no literal form to look for: the fixture's event has no literal form a byte search could find — reviewed by a2: challenged the detection assumptions: the event writes to the objects searched, and they keep it for their whole range; reproduced a decisive check: ran the decisive search again over the same objects: nothing; not tried another route: no second source for the event in the case — by a0

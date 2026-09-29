# Ledger

11 entries: 0 events, 0 indicators, 1 findings, 2 searches that found nothing, 4 coverage records, 4 answers; 4 corrected by a later entry, which stands. Written by the harness from `record`, `attest` and `dispute`; cite it as `ledger/ledger.md`.

## Timeline

| # | Time (UTC) | Event | Source | Evidence | By |
| --- | --- | --- | --- | --- | --- |

## Indicators

| # | Indicator | Source | Evidence | Confidence | By |
| --- | --- | --- | --- | --- | --- |

## Findings

- **#9** the notes name another host's laptop, not a tool [answers 2; observed] _(high)_ — source: the notes — evidence: line 1 — refs: `job:j000008/notes.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000008: command `search` in unknown (unknown), ok — by a3

## Answers

- **#3** question:1 (bounded_negative) **(negative, unreviewed)**: No evidence of the event of question 1 was found on the disk **(superseded by #5)** _(medium: The cited entries are direct.)_ — rests on: E-2 — still open: none open — would change it: a second source that disagrees — reasoning: E-2 — by a1
- **#5** question:1 (bounded_negative) (negative, reviewed by a2): No evidence of the event of question 1 was found on the disk or the outputs (corrects #3) _(medium: The cited entries are direct.)_ — rests on: E-4 — still open: none open — would change it: a second source that disagrees — reasoning: E-4 — by a1
- **#8** question:2 (bounded_negative) **(negative, unreviewed)**: No evidence of the event of question 2 was found on the disk **(superseded by #11)** _(medium: The cited entries are direct.)_ — rests on: E-7 — still open: none open — would change it: a second source that disagrees — reasoning: E-7 — by a1
- **#11** question:2 (bounded_negative) (negative, reviewed by a2): No evidence of the event of question 2 was found on the disk or the outputs (corrects #8) _(medium: The cited entries are direct.)_ — rests on: E-10 — still open: none open — would change it: a second source that disagrees — reasoning: E-10 — by a1

## Searched, not found

| # | Looked for | Searched | Query, tool, scope | By |
| --- | --- | --- | --- | --- |
| 1 | the event of question 1 [answers 1] | the disk | a search · refs: job:j000001/hits.txt | a0 |
| 6 | the event of question 2 [answers 2] | the disk | a search · refs: job:j000001/hits.txt | a0 |

## Coverage records

- **#2** for question:1: proposition: The event question 1 asks about happened **(superseded by #4)** [answers 1] — objects: `input:disk.E01` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: E-1, job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — looked for: "alice"; store sweep hits: 4 object(s), 58 bytes searched for "alice"; found outside the record's objects: "alice" in job:j000007/export.csv, 1 time, first at byte 16 — **unreviewed** — by a0
- **#4** for question:1: proposition: The event question 1 asks about happened (corrects #2) [answers 1] [attested by a2] — objects: `input:disk.E01`, `job:j000007` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: E-1, job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage partial** (not covered: job:j000007 (no job behind the record declared it, or a directory holding it, or an object with its digest)) — looked for: "alice"; store sweep clean: 4 object(s), 58 bytes searched for "alice"; found in objects the record names (does the answer account for them?): "alice" in job:j000007/export.csv, 1 time, first at byte 16 — reviewed by a2: challenged the detection assumptions: the event writes to the objects searched, and they keep it for their whole range; reproduced a decisive check: ran the decisive search again over the same objects: nothing; not tried another route: no second source for the event in the case — by a0
- **#7** for question:2: proposition: The event question 2 asks about happened **(superseded by #10)** [answers 2] — objects: `input:disk.E01` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: E-6, job:j000001/hits.txt — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage complete** — looked for: "bob-laptop"; store sweep hits: 4 object(s), 58 bytes searched for "bob-laptop"; found outside the record's objects: "bob-laptop" in job:j000008/notes.txt, 1 time, first at byte 0 — **unreviewed** — by a0
- **#10** for question:2: proposition: The event question 2 asks about happened (corrects #7) [answers 2] [attested by a2] — objects: `input:disk.E01`, `job:j000008` — time range: the whole of each object, no time bound — method: a keyword search (settings: case-insensitive, every encoding the tool offers) — covered: every byte of the objects named — skipped: none: the search ran to its end — failures: none — results: E-6, job:j000001/hits.txt, E-9 — alternatives: the event may have left its trace only in memory, which the case does not hold — detection opportunity: trace expected yes, the event writes to the objects searched, and they keep it — inventory 6b7f01894e8e2a6c059e2d4d6130c309436116548ea9697440118f05b264e3db — **coverage partial** (not covered: job:j000008 (no job behind the record declared it, or a directory holding it, or an object with its digest)) — looked for: "bob-laptop"; store sweep clean: 4 object(s), 58 bytes searched for "bob-laptop"; found in objects the record names (does the answer account for them?): "bob-laptop" in job:j000008/notes.txt, 1 time, first at byte 0 — reviewed by a2: challenged the detection assumptions: the event writes to the objects searched, and they keep it for their whole range; reproduced a decisive check: ran the decisive search again over the same objects: nothing; not tried another route: no second source for the event in the case — by a0

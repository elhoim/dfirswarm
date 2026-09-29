# Ledger

7 entries: 0 events, 0 indicators, 3 findings, 0 searches that found nothing, 1 limitations, 3 answers; 1 corrected by a later entry, which stands. Written by the harness from `record`, `attest` and `dispute`; cite it as `ledger/ledger.md`.

## Timeline

| # | Time (UTC) | Event | Source | Evidence | By |
| --- | --- | --- | --- | --- | --- |

## Indicators

| # | Indicator | Source | Evidence | Confidence | By |
| --- | --- | --- | --- | --- | --- |

## Findings

- **#1** the record question 1 asks for [answers 1; observed] _(high)_ — source: the disk — evidence: a registry key — refs: `job:j000001/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000001: command `search` in unknown (unknown), ok — by a0
- **#3** a logon at 09:14 for question 2 [answers 2; observed] _(high)_ — source: the log — evidence: line 12 — refs: `job:j000002/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000002: command `search` in unknown (unknown), ok — by a0
- **#6** the logon at 09:14 was the second account [answers 2; observed] _(high)_ — source: the disk — evidence: an account record — refs: `job:j000001/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000001: command `search` in unknown (unknown), ok — by a0

## Answers

- **#2** question:1 (established): Established: the record question 1 asks for [attested by a2] _(high: The cited entries are direct.)_ — rests on: E-1 — still open: none open — would change it: a second source that disagrees — reasoning: E-1 — by a1
- **#5** question:2 (partial): A logon at 09:14; the account is not established **(superseded by #7)** [attested by a3] _(medium: The cited entries are direct.)_ — rests on: E-3 — limitations: E-4 — still open: none open — would change it: a second source that disagrees — reasoning: E-3 shows the logon and its time; the account is open (E-4) — by a1
- **#7** question:2 (established): The second account, at 09:14 (corrects #5) [attested by a2] _(high: The cited entries are direct.)_ — rests on: E-3, E-6 — still open: none open — would change it: a second source that disagrees — reasoning: E-3 and E-6 — by a1

## Searched, not found

| # | Looked for | Searched | Query, tool, scope | By |
| --- | --- | --- | --- | --- |

## Limitations

| # | Not established | Reason | Scope | What was tried | By |
| --- | --- | --- | --- | --- | --- |
| 4 | The log keeps no account name for question 2 [answers 2] | unavailable | the log | its field list | a0 |

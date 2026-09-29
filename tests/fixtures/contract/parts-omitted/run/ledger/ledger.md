# Ledger

5 entries: 0 events, 0 indicators, 2 findings, 0 searches that found nothing, 1 limitations, 2 answers. Written by the harness from `record`, `attest` and `dispute`; cite it as `ledger/ledger.md`.

## Timeline

| # | Time (UTC) | Event | Source | Evidence | By |
| --- | --- | --- | --- | --- | --- |

## Indicators

| # | Indicator | Source | Evidence | Confidence | By |
| --- | --- | --- | --- | --- | --- |

## Findings

- **#1** alice logged on at 09:14 [answers 1; observed] _(high)_ — source: the log — evidence: line 12 — refs: `job:j000002/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000002: command `search` in unknown (unknown), ok — by a0
- **#3** a logon at 09:14 for question 2 [answers 2; observed] _(high)_ — source: the log — evidence: line 12 — refs: `job:j000002/hits.txt` — indicates: What the observation shows, and the step to it. — why that confidence: Read directly from the object it cites. — made by: job j000002: command `search` in unknown (unknown), ok — by a0

## Answers

- **#2** question:1 (established): alice, at 09:14 [attested by a2 (best candidate)] _(high: The cited entries are direct.)_ — rests on: E-1 — still open: none open — would change it: a second source that disagrees — parts: who "who logged on" established (E-1); when "when" established (E-1) — reasoning: E-1 — by a1
- **#5** question:2 (partial): A logon at 09:14; the account is not established [attested by a3] _(medium: The cited entries are direct.)_ — rests on: E-3 — limitations: E-4 — still open: none open — would change it: a second source that disagrees — parts: when "when the logon happened" established (E-3); who "which account logged on" open, bounded by E-4 — reasoning: E-3 shows the logon and its time; the account is open (E-4) — by a1

## Searched, not found

| # | Looked for | Searched | Query, tool, scope | By |
| --- | --- | --- | --- | --- |

## Limitations

| # | Not established | Reason | Scope | What was tried | By |
| --- | --- | --- | --- | --- | --- |
| 4 | The log keeps no account name for question 2 [answers 2] | unavailable | the log | its field list | a0 |

# Context history

Source: `<sandbox>/traces/events.jsonl` (2,063 rows)

| Agent | Model | Ceiling | Lines (notice / warning / compact) | Turns | Peak | Crossed | Holds | Hand-offs | Pi fallbacks | Summary cost |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| s50bb00 | openai/gpt-5.4-mini | 272,000 | 108,800 / 136,000 / 163,200 | 101 | 139,040 (51.1%) | notice, warning | 0 | 1 | 0 | $0.01 |
| s50bb01 | openai/gpt-5.4-mini | 272,000 | 108,800 / 136,000 / 163,200 | 122 | 146,135 (53.7%) | notice, warning | 0 | 1 | 0 | $0.01 |
| s50bb02 | openai/gpt-5.4-mini | 272,000 | 108,800 / 136,000 / 163,200 | 105 | 80,797 (29.7%) | none | 0 | 0 | 0 | — |
| s50bb03 | openai/gpt-5.4-mini | 272,000 | 108,800 / 136,000 / 163,200 | 169 | 144,032 (53.0%) | notice, warning | 0 | 2 | 0 | $0.02 |

## s50bb00

Ceiling 272,000 of a 400,000-token window: declared 400k, but the provider refused at ~215k plus one result on s3096; 272k measured. Summaries by openai/gpt-5.4-nano.
Largest climb in one turn: 14,007 tokens at 14:53:37.

- 14:52:39 crossed the notice line (108,800) at 113,808 tokens (41.8%), cycle 0
- 14:56:42 crossed the warning line (136,000) at 136,476 tokens (50.2%), cycle 0
- 14:57:31 hand-off (cycle 1): 139,040 → 22,503 tokens; summary 38,844 tokens ($0.012), 14,394 chars by openai/gpt-5.4-nano; note 5,306 chars

## s50bb01

Ceiling 272,000 of a 400,000-token window: declared 400k, but the provider refused at ~215k plus one result on s3096; 272k measured. Summaries by openai/gpt-5.4-nano.
Largest climb in one turn: 13,433 tokens at 14:43:52.

- 14:45:51 crossed the notice line (108,800) at 113,500 tokens (41.7%), cycle 0
- 14:47:46 crossed the warning line (136,000) at 141,687 tokens (52.1%), cycle 0
- 14:48:23 hand-off (cycle 1): 146,135 → 29,173 tokens; summary 37,889 tokens ($0.011), 13,101 chars by openai/gpt-5.4-nano; note 5,633 chars

## s50bb03

Ceiling 272,000 of a 400,000-token window: declared 400k, but the provider refused at ~215k plus one result on s3096; 272k measured. Summaries by openai/gpt-5.4-nano.
Largest climb in one turn: 15,058 tokens at 14:58:08.

- 14:44:38 crossed the notice line (108,800) at 112,602 tokens (41.4%), cycle 0
- 14:50:16 crossed the warning line (136,000) at 139,125 tokens (51.1%), cycle 0
- 14:50:54 hand-off (cycle 1): 144,032 → 36,460 tokens; summary 39,465 tokens ($0.011), 11,847 chars by openai/gpt-5.4-nano; note 7,869 chars
- 14:58:08 crossed the notice line (108,800) at 112,581 tokens (41.4%), cycle 1
- 15:01:10 crossed the warning line (136,000) at 139,006 tokens (51.1%), cycle 1
- 15:01:52 hand-off (cycle 2): 141,538 → 39,996 tokens; summary 50,759 tokens ($0.013), 9,596 chars by openai/gpt-5.4-nano; note 9,287 chars

## What the record says

- s50bb00: handed off between the warning and the compact line, as the prompts ask.
- s50bb01: handed off between the warning and the compact line, as the prompts ask.
- s50bb03: handed off between the warning and the compact line, as the prompts ask.
- Summaries: 4 (4 hand-offs, 0 by Pi's own recovery), 166,957 tokens, $0.05.
- 11 tool calls produced more than the model received; the whole output, 21.2 MB, is under tool-output/ and named on each row.

# Run 2: the same case, a harder sandbox, and a clean room

`s83fd`, 2026-09-21. The second swarm on BelkaCTF #6, run to answer a question
the first one could not: **does the harness still work when the agents are
sealed off from everything they are not supposed to see — and can we prove the
seal held?**

The first run, [`s821c`](README.md), is the baseline. Same evidence, same goal
document, same caps. What changed is the sandbox, and one thing about the
machine.

## The result

| | Run 1 · `s821c` | Run 2 · `s83fd` |
| --- | --- | --- |
| Clock | 50.5 min of 60 | 65 min of 60 |
| Spend | $77.32 | **$68.89** |
| Tokens | 111.3M | **102.8M** |
| Tool calls | 2,287 | 2,339 |
| Finish line | 10/10 certified | **10/10 certified** |
| **High confidence** | 6 | **9** |
| Medium | 1 | 3 |
| Low / open | 11 | 6 |
| Forged tools | 6 | 2 |
| Ledger entries | 57 | 47 |

**High-and-medium confidence answers went from 7 to 12, for $8 less.** That is
the headline, and it comes with a caveat the next section is about: run 2's
team was not the team it was supposed to be.

## What changed on purpose

**`--no-read`, new for this run.** The first run's complete answer table was
sitting in this repository — `run/work/flags.md`, eighteen rows, with the
evidence path for each. The write guard denies writes and leaves reads open by
design, so any pane could have read it. A re-run without closing that is not a
re-run; it is a reading of the back of the book.

The rule chosen was: *deny exactly what the first run could not see, and
nothing else.* `docs/use-cases/belkactf/` was committed four hours **after**
`s821c` finished, so denying that one directory restores the first run's
information state precisely. The repository README, the saved tool library and
the other cases' notes stayed readable, because `s821c` could read them.

It was proved rather than assumed, from inside a real pane, before the agents
started — [`run-2/isolation-proof.txt`](run-2/isolation-proof.txt), 17 checks,
all passing. And it was watched for the whole hour: a monitor sampled the
trace every 30 seconds for any reach toward that directory and recorded
**zero**, across 2,339 tool calls.

**No inherited tools.** `--tools-from` was not passed. The six tools `s821c`
forged — including `bde_unlock`, which solved its BitLocker question — were
not available. Run 2 forged two of its own.

**`--allow-install --no-pypi`, the experiment.** Install machinery on, package
index off the allowlist, to see which layer would say no. It produced the
finding this run will be remembered for, and it has its own document:
[**netguard-escape.md**](netguard-escape.md).

**The run left Dropbox.** `runs/` lives inside a cloud-synced folder in this
checkout, so a 13.8 GB evidence copy would have been uploaded. Run 2 used
`SWARM_RUNS_DIR=~/DFIR/SwarmRuns`. The sandbox plan has carried this as P6
since it was written; this is the first run to honour it.

## What changed by accident, and cost us

The first run's team was 10 agents across 4 providers. By run 2 the
`deepseek` direct account was dead — `HTTP 402 Insufficient Balance`, measured
before launch — so its two seats were moved to the same model on Azure.

That put **four agents on one Azure DeepSeek deployment**, and it rate-limited:

```
429 RateLimitReached — DeepSeek-V4-Pro in swedencentral
```

Five times, across all four of those agents. `s83fd06` stopped producing at
11:16 and never recovered; the idle watchdog nudged the group 26 times trying.
The team was ten on paper and about eight in practice.

This is worth stating plainly because it cuts against the result: run 2 beat
run 1 on answers **while short-handed**. It also says something about the
first run that was not obvious at the time — its two `deepseek` agents made 65
and 85 tool calls, the two lowest of its eight cloud agents, which is what a
402 looks like from the outside.

The lesson is a harness one: the kickoff checks that a provider's credentials
resolve, but nothing checks that a *deployment* can carry the number of agents
pointed at it. Four seats on one endpoint is a decision the operator makes
blind.

## What the sandbox did

Over 65 minutes and 2,339 tool calls:

| | |
| --- | --- |
| Inputs violations | 0 |
| Reads of the previous run | 0 |
| Permission denials (write guard) | 2 |
| Claim violations | 3 |
| Egress refused | 221 — of which 66 `pypi.org`, 10 `github.com`, 10 `gitee.com` |
| Install attempts | 12 |
| Packages actually installed | 2 — **through a hole**, see [netguard-escape.md](netguard-escape.md) |

Four of the five guards are enforced by the macOS kernel through seatbelt, and
four of the five held without a scratch. The fifth is enforced by environment
variables, and an agent unset them at minute 29.

## The record

- [`run-2/`](run-2/) — the packaged run: report, board, ledger, trace, hashes
- [`run-2/isolation-proof.txt`](run-2/isolation-proof.txt) — the clean room, proved from inside a pane
- [`run-2/sandbox-metrics.jsonl`](run-2/sandbox-metrics.jsonl) — 118 snapshots of what the sandbox was doing
- [`run-2-screenshots/`](run-2-screenshots/) — the console, every panel, at the end of the run
- [`media/dfirswarm-belkactf6-tour.mp4`](media/README.md) — a captioned tour of the console on this run, the escape included
- [**netguard-escape.md**](netguard-escape.md) — the escape, end to end

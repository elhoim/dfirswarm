# Use case: Memory #1, RansomCare

The swarm on this case: what was asked, who did what, what the harness did, what it cost, and everything the agents wrote, with the console and the terminals captured while they worked. The case is [https://www.ashemery.com/dfir.html#Memory1](https://www.ashemery.com/dfir.html#Memory1) (Ali Hadi, Digital Forensic Challenge Images); the evidence files are not in this repository.

| | |
| --- | --- |
| Run | `s69d3`, 2026-09-18T21:44:31Z → sentinel 2026-09-18T22:06:34.341Z (**22.1 minutes**) |
| Team | 7 agents: 4 × `azure-foundry/grok-4.6`, 3 × `azure-foundry/DeepSeek-V4-Pro` |
| Evidence | `inputs/CASE.md`, `inputs/ransomcare4.raw` (9.7 GB), `inputs/ransomcare5.dmp` (8.6 GB), read-only at the kernel in every pane (`seatbelt`) |
| Flags | `--catalog --toolbox dfir --quarantine  --cap-per-agent 14 --allow-host isf-server.techanarchy.net --allow-tool-forging --cap-usd 90 --wall-clock 240` |
| Outcome | `work/report.md` under the required headings, `work/timeline.md` with 24 dated rows, ledger of 150 entries (89 events, 39 indicators, 22 findings); **7/7 checks** pass |
| Cost | **$27.47** of the $90.00 cap, 244 model calls, 21.2M tokens; $12.28 on grok-4.6, $15.19 on DeepSeek-V4-Pro |
| Harness | 36 shell writes taken as implicit claims, 3 claim violations, 2 forged tool(s) called 20 times, 4 forge hints, 3 idle nudges, 374 writes to `inputs/` |

## What we asked

[`goal.md`](goal.md) is the goal document as handed to the swarm. The questions, verbatim:

1. System profile of each dump: build, kernel, capture time, uptime, the logged-on user, from `windows.info` and friends.
2. Find RansomCare: the process or processes, injected regions and modules that are the ransomware, and how they were identified (pslist/psscan/pstree, cmdline, malfind, hollowed processes, handles, VADs, threads, ldrmodules).
3. Dump the code: the process, module or injected regions dumped into `work/extracted/memory/` with hashes, sizes, strings and any embedded configuration, ransom note or key material.
4. What happened to the victim: files opened, renamed or encrypted, ransom notes, persistence, network connections and DNS, commands run, services and tasks, shadow copy deletion, with evidence from memory.
5. The timeline of the infection on each system, from what memory shows.
6. Indicators of compromise, how the two dumps differ, how to detect RansomCare, and anything else the examiner should know.

## What the agents did

Two memory dumps, no disk, and a ransomware family to name: this is the only
case in the set with nothing to carve and no file system to walk. It took 22
minutes and $27.47, and it produced the clearest example so far of a harness
fault that costs real money without failing anything.

**What the swarm found.** RansomCare, which identifies itself in memory as
Tocrypt, is present in both dumps, and the report names it from the process
list, the command lines, the injected regions that `malfind` surfaced and the
strings in the dumped code rather than from the file name. The dumped regions,
their hashes and sizes are under `work/extracted/memory/`; the ransom note and
the configuration strings came out of the same dumps. The two captures differ
by where the infection had got to, and the report says which is which.

**374 violations, none of them real.** The images arrived `rwxr-xr-x`, as disk
and memory images often do. The inputs sweep wants no execute bit under
`inputs/`, the kernel guard refuses any `chmod` in that directory, and the heal
fails with `EPERM` — so the same two files were reported as violations on
every sweep, 374 times in 22 minutes. Nothing was actually modified: the
custody record shows both images unchanged, and the single inputs check at the
end confirms it. The cost was in the sweeping itself, and in a board full of
warnings that meant nothing. The fix normalises the modes once at copy time,
before the directory is frozen; it is A26 in the plan, and it shipped with
this case.

**The swarm talked more than any run before it.** 29 posts on the board is
ordinary, but the trace carries far more traffic than the disk cases: with two
dumps and no file system, almost every finding needs to say which dump it came
from, and the agents spent their coordination on that. Four of them ended up
renaming themselves around the report — `Report & Timeline Builder`, `Report
Builder`, `report critic`, `dump5-critic` — which is the swarm deciding late
that assembling the answer was the scarce job, not the finding of it.

Two of those names, `dump5 hunter` and `dump5-hunter`, were taken a minute
apart by different agents. The clash check compared the strings and saw two
names; a reader sees one. It compares letters and digits now.

The answers are in [`run/work/report.md`](run/work/report.md); the notes each seat kept are next to it under [`run/work/`](run/work/), the merged timeline is [`run/work/timeline.md`](run/work/timeline.md), and the ledger the timeline was built from is [`run/ledger.md`](run/ledger.md). The board is under [`run/board/`](run/board/), the raw trace is [`run/trace/events.jsonl`](run/trace/events.jsonl), and [`run/summary.md`](run/summary.md) is the summary `scripts/summary.ts` wrote.

## What the harness did, by the numbers

| Signal | Count |
| --- | --- |
| trace events | 1388 |
| bash calls | 201 |
| posts | 29 on 1 thread(s) |
| implicit claims (shell writes turned into claims) | 36 |
| claim violations | 3 |
| forge hints | 4 |
| forged tools | `volrun` by s69d306 (0 calls), `inputs_check` by s69d300 (0 calls) |
| idle nudges | 3 |
| sentinel nudge | reached 6, missed 0 |
| inputs checks | 1 |
| writes to inputs/ | 374 |
| per-agent cap steers / stops | 0 / 0 |
| ledger entries | 150 (89 events, 39 indicators, 22 findings) by 7 agents |

## What it cost, and who spent it

| Agent | Seat | Model | Spend | Calls | Tokens |
| --- | --- | --- | --- | --- | --- |
| s69d305 |  | DeepSeek-V4-Pro | $6.24 | 52 | 4.3M |
| s69d306 |  | DeepSeek-V4-Pro | $4.66 | 52 | 4.4M |
| s69d304 |  | DeepSeek-V4-Pro | $4.29 | 40 | 3.6M |
| s69d300 |  | grok-4.6 | $3.97 | 29 | 3.1M |
| s69d301 |  | grok-4.6 | $3.53 | 30 | 2.9M |
| s69d302 |  | grok-4.6 | $2.45 | 22 | 1.6M |
| s69d303 |  | grok-4.6 | $2.32 | 19 | 1.4M |

| Model | Spend | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| `azure-foundry/DeepSeek-V4-Pro` | $15.19 | 55 % | 144 | 3 |
| `azure-foundry/grok-4.6` | $12.28 | 45 % | 100 | 4 |

Each agent's terminal as it stood at the final round is under [`run/panes/`](run/panes/) — 7 panes, one per agent.

## Screenshots

The console at 8941 after the run:

- [`01-board.png`](screenshots/01-board.png) — the board, every post under the name its author chose.
- [`02-inputs-custody.png`](screenshots/02-inputs-custody.png) — the Inputs tab: both dumps hashed and unchanged, under a kernel guard, next to the 374 violations that were the guard arguing with itself.

## Reproducing it

Get the evidence from the source above into one directory, install `sleuthkit`, `libewf`, `yara` and `foremost` (brew) and `volatility3` (pipx), start Herdr, and run:

```
scripts/swarm.sh start --models "openai/gpt-5.4=4,deepseek/deepseek-v4-pro=3" --cap-usd 90 --wall-clock 240 \
  --goal-file goal.md --inputs <evidence dir> --inputs-max-mb 60000 --catalog --toolbox dfir --quarantine  --cap-per-agent 14 --allow-host isf-server.techanarchy.net --allow-tool-forging \
  --case-id AH-M01 --examiner "<name>"
```

# Use case: Linux #3, The Attacker's Kali System

The swarm on this case: what was asked, who did what, what the harness did, what it cost, and everything the agents wrote, with the console and the terminals captured while they worked. The case is [https://www.ashemery.com/dfir.html#Linux3](https://www.ashemery.com/dfir.html#Linux3) (Ali Hadi, Digital Forensic Challenge Images); the evidence files are not in this repository.

| | |
| --- | --- |
| Run | `s9da9`, 2026-09-18T23:35:18Z → sentinel 2026-09-18T23:56:48.471Z (**21.5 minutes**) |
| Team | 7 agents: 4 × `azure-foundry/grok-4.6`, 3 × `azure-foundry/DeepSeek-V4-Pro` |
| Evidence | `inputs/CASE-manual.txt`, `inputs/Case3-Workshop-Manual.pdf`, `inputs/README`, `inputs/index.md`, `inputs/workshop-kali.E01` (9.4 GB), `inputs/workshop-kali.E01.txt`, read-only at the kernel in every pane (`seatbelt`) |
| Flags | `--catalog --toolbox dfir --quarantine  --cap-per-agent 14 --allow-host isf-server.techanarchy.net --allow-tool-forging --cap-usd 80 --wall-clock 240` |
| Outcome | `work/report.md` under the required headings, `work/timeline.md` with 37 dated rows, ledger of 114 entries (72 events, 19 indicators, 23 findings); **7/7 checks** pass |
| Cost | **$23.72** of the $80.00 cap, 326 model calls, 19.2M tokens; $9.34 on grok-4.6, $14.38 on DeepSeek-V4-Pro |
| Harness | 127 shell writes taken as implicit claims, 0 claim violations, 4 forged tool(s) called 70 times, 2 forge hints, 6 idle nudges, 0 writes to `inputs/` |

## What we asked

[`goal.md`](goal.md) is the goal document as handed to the swarm. The questions, verbatim:

1. What is the time range of exploitation? When did activity begin and end for the active user account (logins, shell histories, file modification times), with the evidence.
2. How many exploits can you find evidence of, and what can you not find evidence of, and why? Name each exploit, tool or technique, and what shows it (histories, tool logs and output files, Metasploit databases and logs, downloaded exploits, package installs).
3. Where could the evidence of each exploit be found? Several places for some, one for others: list the file or log for each, with the command that shows it.
4. Did the attacker act maliciously on the target system? What the evidence on the attacker's machine shows about what was done to the target (shells, uploads, credentials, data pulled back), with hashes of anything retrieved.
5. Can evidence of NFS usage be found? Mounts, exports, `showmount`/`mount` traces, `/etc/fstab`, logs, and what was accessed over NFS.
6. The timeline of the attacker's activity across every source, attribution clues and operational-security mistakes, and anything else the examiner should know.

## What the agents did

The last case of the fifteen, and the only one where the disk belongs to the
attacker rather than the victim: a Kali system, 9.2 GB, 21 minutes, $23.72,
all seven checks.

**A case read from the other side.** The questions are the same shape as the
victim cases — what was run, when, against whom — but the evidence answers
them directly: shell histories, Metasploit's own session records, the tools
left in `/root`, the loot the attacker kept. One agent named itself
`msf-sessions` and took the framework's records, `TeethLoot` took what the
attacker had collected, `NFS & logs` took the shares and the system logs, and
`root-artifacts` took the home directory. `GapFill` is the name an agent gave
itself for the job of covering what the others had not claimed, which is a
seat no preset would ever have thought to write.

**Two critics and a keeper.** Late in the run two agents both moved onto
criticism — `critic` and `Critic & Sign-off` — and one of them had been
keeping the report. The report survived it: the sign-off verifies the hashes,
the content and the structure, and the checks pass. But two agents converging
on the same late job while the report's keeper moves away is the failure mode
to watch for in a swarm that assigns nothing, and the first case where it
nearly cost something.

**The tools that travelled.** Thirty-two tools came in from the fourteen runs
before it. On a Linux attacker box most of the Windows parsers are dead
weight, as in the two Linux cases before, and what earned its place was the
generic half: the catalog searchers, the extractors, the chunked string
scanners.

The answers are in [`run/work/report.md`](run/work/report.md); the notes each seat kept are next to it under [`run/work/`](run/work/), the merged timeline is [`run/work/timeline.md`](run/work/timeline.md), and the ledger the timeline was built from is [`run/ledger.md`](run/ledger.md). The board is under [`run/board/`](run/board/), the raw trace is [`run/trace/events.jsonl`](run/trace/events.jsonl), and [`run/summary.md`](run/summary.md) is the summary `scripts/summary.ts` wrote.

## What the harness did, by the numbers

| Signal | Count |
| --- | --- |
| trace events | 1342 |
| bash calls | 261 |
| posts | 20 on 1 thread(s) |
| implicit claims (shell writes turned into claims) | 127 |
| claim violations | 0 |
| forge hints | 2 |
| forged tools | `kali_icat` by s9da903 (6 calls), `parse_utmp` by s9da903 (5 calls), `kali_icat` by s9da901 (6 calls), `parse_utmp` by s9da903 (5 calls) |
| idle nudges | 6 |
| sentinel nudge | reached 6, missed 0 |
| inputs checks | 2 |
| writes to inputs/ | 0 |
| per-agent cap steers / stops | 0 / 0 |
| ledger entries | 114 (72 events, 19 indicators, 23 findings) by 7 agents |

## What it cost, and who spent it

| Agent | Seat | Model | Spend | Calls | Tokens |
| --- | --- | --- | --- | --- | --- |
| s9da906 |  | DeepSeek-V4-Pro | $5.32 | 76 | 4.5M |
| s9da905 |  | DeepSeek-V4-Pro | $4.96 | 89 | 4.9M |
| s9da904 |  | DeepSeek-V4-Pro | $4.10 | 73 | 4.0M |
| s9da903 |  | grok-4.6 | $2.81 | 27 | 2.0M |
| s9da900 |  | grok-4.6 | $2.59 | 23 | 1.6M |
| s9da902 |  | grok-4.6 | $2.08 | 20 | 1.2M |
| s9da901 |  | grok-4.6 | $1.86 | 18 | 1.0M |

| Model | Spend | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| `azure-foundry/DeepSeek-V4-Pro` | $14.38 | 61 % | 238 | 3 |
| `azure-foundry/grok-4.6` | $9.34 | 39 % | 88 | 4 |

Each agent's terminal as it stood at the final round is under [`run/panes/`](run/panes/) — 7 panes, one per agent.

## Screenshots

- [`01-board.png`](screenshots/01-board.png) — the console after the run, each agent under the name it chose, including the one that called itself `GapFill`.
- [`02-all-runs.png`](screenshots/02-all-runs.png) — the console listing every forensic run of this series, the fifteen cases end to end.

## Reproducing it

Get the evidence from the source above into one directory, install `sleuthkit`, `libewf`, `yara` and `foremost` (brew) and `volatility3` (pipx), start Herdr, and run:

```
scripts/swarm.sh start --models "openai/gpt-5.4=4,deepseek/deepseek-v4-pro=3" --cap-usd 80 --wall-clock 240 \
  --goal-file goal.md --inputs <evidence dir> --inputs-max-mb 60000 --catalog --toolbox dfir --quarantine  --cap-per-agent 14 --allow-host isf-server.techanarchy.net --allow-tool-forging \
  --case-id AH-L03 --examiner "<name>"
```

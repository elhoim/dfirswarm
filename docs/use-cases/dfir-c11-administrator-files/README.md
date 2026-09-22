# Use case: Challenge #11, Where Did the Administrator Go

The swarm on this case: what was asked, who did what, what the harness did, what it cost, and everything the agents wrote, with the console and the terminals captured while they worked. The case is [https://www.ashemery.com/dfir.html#Challenge11](https://www.ashemery.com/dfir.html#Challenge11) (Ali Hadi, Digital Forensic Challenge Images); the evidence files are not in this repository.

| | |
| --- | --- |
| Run | `sb6b3`, 2026-09-18T21:24:36Z → sentinel 2026-09-18T21:39:56.761Z (**15.3 minutes**) |
| Team | 7 agents: 4 × `azure-foundry/grok-4.6`, 3 × `azure-foundry/DeepSeek-V4-Pro` |
| Evidence | `inputs/CASE.md`, `inputs/ThreatSimServer.E01` (35.2 GB), read-only at the kernel in every pane (`seatbelt`) |
| Flags | `--catalog --toolbox dfir --quarantine  --cap-per-agent 14 --allow-host isf-server.techanarchy.net --allow-tool-forging --cap-usd 90 --wall-clock 240` |
| Outcome | `work/report.md` under the required headings, `work/timeline.md` with 39 dated rows, ledger of 85 entries (47 events, 12 indicators, 26 findings); **7/7 checks** pass |
| Cost | **$22.76** of the $90.00 cap, 251 model calls, 16.9M tokens; $10.51 on grok-4.6, $12.25 on DeepSeek-V4-Pro |
| Harness | 94 shell writes taken as implicit claims, 3 claim violations, 1 forged tool(s) called 196 times, 0 forge hints, 1 idle nudges, 0 writes to `inputs/` |

## What we asked

[`goal.md`](goal.md) is the goal document as handed to the swarm. The questions, verbatim:

1. System profile: Windows Server edition and roles, domain, computer name, time zone, the accounts (local and cached domain), and the administrator's profile.
2. What happened to the administrator's files: deleted, moved, encrypted, wiped or hidden? Prove it from $MFT, $UsnJrnl, $LogFile, recycle bins, shadow copies, event logs.
3. How: by which account, from where (logon type and source, RDP, SMB, WinRM, console), and by what means (command, script, tool, ransomware), with the evidence for each.
4. When: the timeline from the first suspicious event to the last, across every source.
5. What else was done to the system: persistence, other accounts, other files, services, tasks, defence tampering, exfiltration.
6. Can the files be recovered, and how (journal, shadow copies, carving); what was recovered here, with hashes.
7. Indicators, recommendations, and anything else the examiner should know.

## What the agents did

Fifteen minutes and twenty-one seconds, on a 33 GB image, for $22.76. It is
the one run in the series that forged nothing, because the library already
covered it, and the second where the harness handed out no work at all.

**The division of labour was better than the case before it.** Seven agents
named themselves inside the first minutes, and this time they spread out:
`hive-persist` took the system profile from the hives, `EventLog+Registry
Analyst` the event logs, `EventHow` the execution artefacts, `PrefetchADS` the
prefetch and the alternate data streams, `ntfs-deletion` the `$MFT`,
`$UsnJrnl` and `$LogFile`, `Recovery & Verification Lead` the shadow copies
and carving, and `Admin-File-Forensics` the Administrator's own directories.
On the tenth case four of seven had described the same work; here only two
overlap, and they overlap at the edges. Between the two runs `name()` began
answering with what every peer had already said it was doing, and naming the
overlap when it saw one.

**Nothing had to be forged.** Not one forge hint fired, and no agent wrote a
tool: the twenty-one tools carried over from earlier runs covered the case.
`regkv` was called 36 times, `prefetch_mam` 28, `evtx_query` 24,
`catalog_search` 10, `grep_filelist` 6, `reg_hive_query` 5. A registry parser
written for challenge 3 and a prefetch decompressor written for challenge 4
did the work here without anyone rewriting them, which is the whole argument
for the library in one run.

**What happened to the Administrator's files.** They were destroyed, and the
swarm proved it rather than inferring it. `SDelete64` had been renamed
`dark_knight.c5w` and executed on 2024-07-27; its own prefetch file records
the run, and the `$MFT` and `$UsnJrnl` show the Administrator's files
overwritten rather than unlinked. The event logs were cleared with `wevtutil`
afterwards, which the surviving records and the clearing events themselves
give away. The report's answer to "can they be recovered" is no, with the
reason: SDelete's overwrite is the point of SDelete, and the shadow copies
were gone too.

**What the harness did.** One sentinel nudge, one idle nudge, no cap steer, no
harness fault, no write to `inputs/`, and the inputs verified twice. Three
claim violations, all on the shared extraction root, which is A18 in the
improvement plan and still the one thing the protocol does not handle well
when several agents pull the same hives at once.

The answers are in [`run/work/report.md`](run/work/report.md); the notes each seat kept are next to it under [`run/work/`](run/work/), the merged timeline is [`run/work/timeline.md`](run/work/timeline.md), and the ledger the timeline was built from is [`run/ledger.md`](run/ledger.md). The board is under [`run/board/`](run/board/), the raw trace is [`run/trace/events.jsonl`](run/trace/events.jsonl), and [`run/summary.md`](run/summary.md) is the summary `scripts/summary.ts` wrote.

## What the harness did, by the numbers

| Signal | Count |
| --- | --- |
| trace events | 1117 |
| bash calls | 230 |
| posts | 22 on 1 thread(s) |
| implicit claims (shell writes turned into claims) | 94 |
| claim violations | 3 |
| forge hints | 0 |
| forged tools | `filelist_grep` by sb6b300 (0 calls) |
| idle nudges | 1 |
| sentinel nudge | reached 6, missed 0 |
| inputs checks | 2 |
| writes to inputs/ | 0 |
| per-agent cap steers / stops | 0 / 0 |
| ledger entries | 85 (47 events, 12 indicators, 26 findings) by 7 agents |

## What it cost, and who spent it

| Agent | Seat | Model | Spend | Calls | Tokens |
| --- | --- | --- | --- | --- | --- |
| sb6b305 |  | DeepSeek-V4-Pro | $4.96 | 61 | 3.7M |
| sb6b304 |  | DeepSeek-V4-Pro | $4.62 | 49 | 3.8M |
| sb6b300 |  | grok-4.6 | $3.46 | 26 | 2.4M |
| sb6b302 |  | grok-4.6 | $2.71 | 22 | 1.6M |
| sb6b306 |  | DeepSeek-V4-Pro | $2.67 | 49 | 2.6M |
| sb6b303 |  | grok-4.6 | $2.33 | 21 | 1.3M |
| sb6b301 |  | grok-4.6 | $2.01 | 23 | 1.4M |

| Model | Spend | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| `azure-foundry/DeepSeek-V4-Pro` | $12.25 | 54 % | 159 | 3 |
| `azure-foundry/grok-4.6` | $10.51 | 46 % | 92 | 4 |

## Screenshots

The console at 8941 after the run:

- [`01-board.png`](screenshots/01-board.png) — the board, every post under the name its author chose.
- [`02-agents.png`](screenshots/02-agents.png) — the seven agents, their names and what each said it was taking on.
- [`03-ledger.png`](screenshots/03-ledger.png) — the Ledger tab: the dated events the timeline rests on.

## Reproducing it

Get the evidence from the source above into one directory, install `sleuthkit`, `libewf`, `yara` and `foremost` (brew) and `volatility3` (pipx), start Herdr, and run:

```
scripts/swarm.sh start --models "openai/gpt-5.4=4,deepseek/deepseek-v4-pro=3" --cap-usd 90 --wall-clock 240 \
  --goal-file goal.md --inputs <evidence dir> --inputs-max-mb 60000 --catalog --toolbox dfir --quarantine  --cap-per-agent 14 --allow-host isf-server.techanarchy.net --allow-tool-forging \
  --case-id AH-C11 --examiner "<name>"
```

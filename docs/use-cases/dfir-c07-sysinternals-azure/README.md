# Use case: Challenge #7, SysInternals — the first run on Azure AI Foundry (Grok 4.6 and DeepSeek V4 Pro)

The swarm on Challenge #7, SysInternals: what was asked, who did what, what the harness did, what it cost, and everything the agents wrote, with the console and the terminals captured while they worked. The case is [https://www.ashemery.com/dfir.html#Challenge7](https://www.ashemery.com/dfir.html#Challenge7) (Ali Hadi, Digital Forensic Challenge Images); the evidence files are not in this repository.

| | |
| --- | --- |
| Run | `sd1d1`, 2026-09-18T14:11:02Z → sentinel 2026-09-18T14:35:18.331Z (**24.3 minutes**) |
| Team | 7 agents: 4 × `azure-foundry/grok-4.6`, 3 × `azure-foundry/DeepSeek-V4-Pro` |
| Evidence | `inputs/CASE.md`, `inputs/SysInternalsCase.E01` (7.8 GB), `inputs/SysInternalsCase.E01.txt`, read-only at the kernel in every pane (`seatbelt`) |
| Flags | `--catalog --toolbox dfir --quarantine --seats dfir --cap-per-agent 12 --allow-host isf-server.techanarchy.net --allow-tool-forging --cap-usd 60 --wall-clock 180` |
| Outcome | `work/report.md` under the required headings, `work/timeline.md` with 53 dated rows, ledger of 111 entries (57 events, 36 indicators, 18 findings); **7/7 checks** pass |
| Cost | **$37.03** of the $60.00 cap, 332 model calls, 26.1M tokens; $20.82 on grok-4.6, $16.21 on DeepSeek-V4-Pro. The run reported $24.68 while it ran, from a DeepSeek rate four times too low; see *What it cost* below. Azure's rate is not DeepSeek's own, which is higher still than the one this run was configured with. |
| Harness | 104 shell writes taken as implicit claims, 9 claim violations, 5 forged tool(s) called 33 times, 8 forge hints, 2 idle nudges, 0 writes to `inputs/` |

## What we asked

[`goal.md`](goal.md) is the goal document as handed to the swarm. The questions, verbatim:

1. What did the user download, from where and when? The browser record, the download path, the Zone.Identifier stream, the file's hash and size.
2. What was the file really? Its type and hashes, strings and indicators, what it dropped or extracted and where, and every registry, task, service or startup change tied to it.
3. How does it persist, and what does it do on the system? The cause of the slowdown, with evidence (processes in event logs, prefetch, scheduled tasks, services, WMI, injected components).
4. Network indicators: hosts, IPs, URLs, DNS names and ports in the artifacts, with where each was found.
5. The timeline of the infection, from the download to the last observed activity.
6. Indicators of compromise, the remediation steps, and anything else the examiner should know.

## What the agents did

This is the first run on **Azure AI Foundry**: seven agents on one Azure resource, four on the `grok-4.6` deployment and three on `DeepSeek-V4-Pro`, through Pi's `azure-foundry` provider. Everything else is what the other cases used. The board is under [`run/board/`](run/board/) (one thread, 45 posts), the raw trace in [`run/trace/events.jsonl`](run/trace/events.jsonl) (1,120 lines), and every pane's terminal at the end under [`run/panes/`](run/panes/).

**Minute 0–2 — seats, and a memory seat with no memory.** Seven intros; the memory seat found no RAM image, no hibernation file and no crash dump, said so, and pivoted to `pagefile.sys` and `swapfile.sys` — which on this case turned out to matter less than the dropper's own strings.

**Minute 3–4 — two agents forge the same tool six seconds apart.** The memory seat forged `catalog_grep` at 14:14:41; the disk seat forged `catalog_search` at 14:14:47 — the same capability (regex over the catalog's file list, body file and timeline) under two names. `catalog_grep` went on to be called 26 times by four agents; `catalog_search` was called twice. The harness announces a forged tool on the board, but both were already in flight; a near-duplicate check in `make_tool` is plan item B13.

**Minute 4–8 — the dropper.** The disk seat pulled `SysInternals[1].exe` (57,344 bytes) out of the Edge cache by inode, hashed it, and found the copies: the partial download, the cache copy, and a deleted `Users\Public\Downloads\SysInternals.exe`. The leftovers seat then warned the critic off a mistake it was about to make — the deleted copy's clusters had been reused, so the bytes `icat` returns for that inode are not the malware. The memory seat found what the strings alone did not show: the URLs inside the dropper are XOR-encoded with `0x41`, and decode to `http://www.malware430.com/html/VMwareUpdate.exe`.

**Minute 8–20 — the service that eats the machine.** The stage-2 payload (`VMwareUpdate.exe`, 289,280 bytes) lands as `c:\Windows\vmtoolsIO.exe` and registers as `VMwareIOHelperService`, SYSTEM, demand start at 21:19:22, changed to auto-start three seconds later (System event log 7045 then 7040). Its strings answer the case's actual question — why the machine slowed down: `C:\Windows\Prefetch`, `*.pf`, `DeleteFileW`. The fake service enumerates the Prefetch directory and deletes its files in a loop, which is both a permanent disk-I/O load and the reason the Prefetch evidence is thin. The accounts seat confirmed no new accounts, no scheduled tasks, no Run keys, no WMI persistence: the service is the whole persistence story.

**Minute 20–24 — the ledger carries the case.** 111 entries by the end, and the timeline seat published `work/timeline.md` three times as peers corrected each other (39 rows, then 45). Two idle nudges, both on DeepSeek seats, both answered.

**What the reserved-name rule caught.** At 14:33:15 the critic tried to forge a tool named `inputs_check` — the name of the harness's own event, which the second challenge's swarm had taken and confused the summary with. This time `make_tool` refused it by name (plan A16, shipped the same afternoon), and the critic moved on.

**Where the report is wrong, and why.** The critic assembled `work/report.md` and signed off at 14:34; between 14:34 and 14:35 three seats corrected question 1 on the board — the download origin is `http://www.sysinternals.com/SysInternals.exe`, read out of the `WebCacheV01.dat` HTTP 200 response with its referer, not the `downloads.subscriptionsint.tfsallin.net` domain that a seat had earlier called the likely origin. The timeline seat published v3 with the correction; the report was never revised, because the sentinel followed a minute later. **The report in this folder therefore names the wrong download origin in §1, §4 and §6**; the board and `work/timeline.md` have the corrected one. Nothing else in the report is affected: the hashes, the XOR-decoded C2 URL, the service and the timeline all stand. The gap itself is plan item A19 — a `result` post that lands after the sign-off has to invalidate it.

**Azure against OpenAI, on the same harness.** The run cost **$37.03** and took 24.5 minutes, against $10.03–$19.11 and 10–15 minutes for the five OpenAI + DeepSeek cases. The four Grok seats cost $4.82–$5.60 each on 28–33 model calls; the three DeepSeek seats cost $3.56–$6.99 on 57–77 calls — the Grok seats make fewer, larger calls, and this case's dropper analysis (XOR decoding, PE strings, service reconstruction) was theirs, while the DeepSeek seats' many calls each carried a large cached context (1.2–2.6M cached tokens apiece). Both models drove the harness correctly: seats taken without negotiation, the catalog read 68 times, tools forged and shared, the ledger filled, the sentinel nudge reaching every peer.

**What it cost, and the correction.** The swarm bills from the `cost` block in `models.json`, and that block is only as right as whoever wrote it. This run was configured with $2.00 input, $6.00 output and $0.50 cached per 1M for Grok, which is Azure's rate, and $0.435 / $0.87 / $0.003625 for DeepSeek V4 Pro, which is nobody's: Azure charges $1.74 / $3.48 / $0.145, four times more, and DeepSeek itself charges $1.32 / $3.96 / $0.044 at peak and half that off-peak. The figures above are recomputed from the run's own token counts at Azure's published rates (the retail prices API, Global deployments, commercial regions, 18 September 2026); recomputing at the old rates reproduces the $24.68 the run reported, which is how the arithmetic was checked. `models.json` now carries Azure's rates, including Grok's higher tier above 200K input tokens ($4.00 / $12.00 / $1.00), so later runs bill themselves correctly.

The answers are in [`run/work/report.md`](run/work/report.md); the notes each seat kept are next to it under [`run/work/`](run/work/), the merged timeline is [`run/work/timeline.md`](run/work/timeline.md), and the ledger the timeline was built from is [`run/ledger.md`](run/ledger.md). The board is under [`run/board/`](run/board/), the raw trace is [`run/trace/events.jsonl`](run/trace/events.jsonl), and [`run/summary.md`](run/summary.md) is the summary `scripts/summary.ts` wrote.

## What the harness did, by the numbers

| Signal | Count |
| --- | --- |
| trace events | 1120 |
| bash calls | 404 |
| posts | 23 on 1 thread(s) |
| implicit claims (shell writes turned into claims) | 104 |
| claim violations | 9 |
| forge hints | 8 |
| forged tools | `catalog_grep` by sd1d102 (26 calls), `catalog_search` by sd1d100 (2 calls), `chunk_needles` by sd1d102 (5 calls), `inputs_check` by sd1d106 (0 calls), `evtx_filter` by sd1d101 (0 calls) |
| idle nudges | 2 |
| sentinel nudge | reached 6, missed 0 |
| inputs checks | 2 |
| writes to inputs/ | 0 |
| per-agent cap steers / stops | 0 / 0 |
| ledger entries | 111 (57 events, 36 indicators, 18 findings) by 7 agents |

## What it cost, and who spent it

| Agent | Seat | Model | Spend | Calls | Tokens |
| --- | --- | --- | --- | --- | --- |
| sd1d103 | Leftovers and malware | grok-4.6 | $5.60 | 30 | 3.1M |
| sd1d100 | Disk triage | grok-4.6 | $5.34 | 30 | 3.0M |
| sd1d102 | Memory forensics | grok-4.6 | $5.05 | 28 | 2.8M |
| sd1d101 | Accounts and event logs | grok-4.6 | $4.82 | 33 | 2.5M |
| sd1d106 | Critic and editor | DeepSeek-V4-Pro | $1.66 | 77 | 6.4M |
| sd1d104 | Timeline and ledger | DeepSeek-V4-Pro | $1.35 | 57 | 5.1M |
| sd1d105 | Installed software and provenance | DeepSeek-V4-Pro | $0.85 | 77 | 3.2M |

| Model | Spend | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| `azure-foundry/grok-4.6` | $20.82 | 56 % | 121 | 4 |
| `azure-foundry/DeepSeek-V4-Pro` | $16.21 | 44 % | 211 | 3 |

The per-agent figures in the table above them are what the run reported at
the time; at Azure's rates the three DeepSeek seats cost $5.66, $3.56 and
$6.99 rather than $1.35, $0.85 and $1.66. No seat crossed the $12 per-agent
cap either way.

## Screenshots

The console at 8941 during the run (only forensic runs are listed on it):

- [`01-story-final.png`](screenshots/01-story-final.png)
- [`03-budget-final.png`](screenshots/03-budget-final.png)

## Reproducing it

Get the evidence from the source above into one directory, install `sleuthkit`, `libewf`, `yara` and `foremost` (brew) and `volatility3` (pipx), start Herdr, and run:

```
scripts/swarm.sh start --models "openai/gpt-5.4=4,deepseek/deepseek-v4-pro=3" --cap-usd 60 --wall-clock 180 \
  --goal-file goal.md --inputs <evidence dir> --inputs-max-mb 60000 --catalog --toolbox dfir --quarantine --seats dfir --cap-per-agent 12 --allow-host isf-server.techanarchy.net --allow-tool-forging \
  --case-id ALIHADI-C7 --examiner "<name>"
```

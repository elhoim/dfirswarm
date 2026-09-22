# Use case: Linux #1, Compromised Web Server

The swarm on this case: what was asked, who did what, what the harness did, what it cost, and everything the agents wrote, with the console and the terminals captured while they worked. The case is [https://www.ashemery.com/dfir.html#Linux1](https://www.ashemery.com/dfir.html#Linux1) (Ali Hadi, Digital Forensic Challenge Images); the evidence files are not in this repository.

| | |
| --- | --- |
| Run | `s9d83`, 2026-09-18T22:38:22Z → sentinel 2026-09-18T23:05:43.557Z (**27.4 minutes**) |
| Team | 7 agents: 4 × `azure-foundry/grok-4.6`, 3 × `azure-foundry/DeepSeek-V4-Pro` |
| Evidence | `inputs/CASE-manual.txt`, `inputs/Case1-Workshop-Manual.pdf`, `inputs/README`, `inputs/Webserver.E01` (1.2 GB), `inputs/Webserver.E01.csv`, `inputs/Webserver.E01.txt`, `inputs/index.md`, read-only at the kernel in every pane (`seatbelt`) |
| Flags | `--catalog --toolbox dfir --quarantine  --cap-per-agent 14 --allow-host isf-server.techanarchy.net --allow-tool-forging --cap-usd 70 --wall-clock 240` |
| Outcome | `work/report.md` under the required headings, `work/timeline.md` with 34 dated rows, ledger of 113 entries (65 events, 27 indicators, 21 findings); **7/7 checks** pass |
| Cost | **$38.15** of the $70.00 cap, 429 model calls, 33.7M tokens; $19.51 on grok-4.6, $18.64 on DeepSeek-V4-Pro |
| Harness | 171 shell writes taken as implicit claims, 0 claim violations, 8 forged tool(s) called 16 times, 2 forge hints, 9 idle nudges, 0 writes to `inputs/` |

## What we asked

[`goal.md`](goal.md) is the goal document as handed to the swarm. The questions, verbatim:

1. How did the threat actor gain access to the system? The service, the vulnerability or credential, the source address, the first evidence of the intrusion.
2. What privileges were obtained, and how (exploit, sudo, credentials, SUID, cron, misconfiguration)?
3. What modifications were applied to the system: files, packages, configurations, users, keys, binaries, logs cleared or altered.
4. What persistence mechanisms are in place: backdoors, users, SSH keys, cron, systemd units, init scripts, shells, sessions, kernel modules.
5. Could this system be cleaned or recovered, and what would it take?
6. Notes and recommendations, the full timeline of the intrusion, and anything else the examiner should know.

## What the agents did

The first Linux case, and the first image in the set that is not Windows: a
1.1 GB disk from a compromised web server, handed over with the acquisition
files beside it. 27 minutes, $38.15, all seven checks.

**How the swarm cut it.** Nobody was assigned anything, and the seven split
the case by evidence rather than by question: `Web-initial-access` and
`FTK-index + web logs` on the web server's own logs, `journal-privesc` on the
journal and the escalation, `root-fs-analyst` on the root file system,
`Boot-Analyst-Ledger` and `Web Exploit & Boot Analyst` on persistence across
boot, and `web-access` on the access records. Three of the seven names begin
with "web", which is the clustering the tenth case showed too, and again it
resolved by conversation rather than by anyone stepping in: `web-access`
became `report-assembler` when the report needed a keeper, and
`Web-initial-access` became `citation-critic` when the citations did. Two of
the three jobs the definition of done requires were filled by agents that had
started somewhere else entirely.

**The tools carried over, the toolbox did not.** Twenty-seven tools came in
from the earlier runs, and most of them parse Windows artefacts — registry
hives, prefetch, event logs — which a Debian web server does not have. The
swarm used what applied and wrote what it needed, which is the right outcome:
the library is a saving where cases rhyme and dead weight where they do not.

**A20, again.** The goal's last check greps the trace for `"tool":"inputs_check"`,
an event the harness writes itself when `done` verifies the inputs. An agent
read it as a tool it had to provide, `make_tool` refused the reserved name, and
it forged `check_inputs` instead — the same mistake challenge 8 made, recorded
then as A20 and still open. The sign-off says so in its own words: "the
`inputs_check` trace name mismatch is cosmetic". The goal documents now
explain, where the check is written, that the harness emits it and nobody
needs to forge anything. That is the cheap half of A20; the harness half,
teaching `make_tool` to say which built-in emits a reserved name, is still to
do.

The answers are in [`run/work/report.md`](run/work/report.md); the notes each seat kept are next to it under [`run/work/`](run/work/), the merged timeline is [`run/work/timeline.md`](run/work/timeline.md), and the ledger the timeline was built from is [`run/ledger.md`](run/ledger.md). The board is under [`run/board/`](run/board/), the raw trace is [`run/trace/events.jsonl`](run/trace/events.jsonl), and [`run/summary.md`](run/summary.md) is the summary `scripts/summary.ts` wrote.

## What the harness did, by the numbers

| Signal | Count |
| --- | --- |
| trace events | 1271 |
| bash calls | 264 |
| posts | 30 on 1 thread(s) |
| implicit claims (shell writes turned into claims) | 171 |
| claim violations | 0 |
| forge hints | 2 |
| forged tools | `ftk_csv` by s9d8303 (7 calls), `icat_root` by s9d8306 (0 calls), `fls_root` by s9d8306 (3 calls), `icat_root` by s9d8306 (0 calls), `inputs_check` by s9d8302 (0 calls), `inputs_check` by s9d8303 (0 calls), `inputs_check` by s9d8304 (0 calls), `inputs_check` by s9d8305 (0 calls) |
| idle nudges | 9 |
| sentinel nudge | reached 6, missed 0 |
| inputs checks | 3 |
| writes to inputs/ | 0 |
| per-agent cap steers / stops | 0 / 0 |
| ledger entries | 113 (65 events, 27 indicators, 21 findings) by 7 agents |

## What it cost, and who spent it

| Agent | Seat | Model | Spend | Calls | Tokens |
| --- | --- | --- | --- | --- | --- |
| s9d8305 |  | DeepSeek-V4-Pro | $7.39 | 101 | 8.2M |
| s9d8306 |  | DeepSeek-V4-Pro | $6.14 | 94 | 6.3M |
| s9d8302 |  | grok-4.6 | $5.65 | 38 | 4.4M |
| s9d8304 |  | DeepSeek-V4-Pro | $5.12 | 106 | 6.1M |
| s9d8303 |  | grok-4.6 | $5.08 | 33 | 3.7M |
| s9d8300 |  | grok-4.6 | $4.77 | 32 | 2.7M |
| s9d8301 |  | grok-4.6 | $4.01 | 25 | 2.3M |

| Model | Spend | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| `azure-foundry/grok-4.6` | $19.51 | 51 % | 128 | 4 |
| `azure-foundry/DeepSeek-V4-Pro` | $18.64 | 49 % | 301 | 3 |

Each agent's terminal as it stood at the final round is under [`run/panes/`](run/panes/) — 7 panes, one per agent.

## Screenshots

- [`01-board.png`](screenshots/01-board.png) — the console after the run: seven agents under the names they chose, two of them having moved to the report and the citations partway through.

## Reproducing it

Get the evidence from the source above into one directory, install `sleuthkit`, `libewf`, `yara` and `foremost` (brew) and `volatility3` (pipx), start Herdr, and run:

```
scripts/swarm.sh start --models "openai/gpt-5.4=4,deepseek/deepseek-v4-pro=3" --cap-usd 70 --wall-clock 240 \
  --goal-file goal.md --inputs <evidence dir> --inputs-max-mb 60000 --catalog --toolbox dfir --quarantine  --cap-per-agent 14 --allow-host isf-server.techanarchy.net --allow-tool-forging \
  --case-id AH-L01 --examiner "<name>"
```

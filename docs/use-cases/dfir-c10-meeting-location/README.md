# Use case: Challenge #10, Meeting Location

The swarm on this case: what was asked, who did what, what the harness did, what it cost, and everything the agents wrote, with the console and the terminals captured while they worked. The case is [https://www.ashemery.com/dfir.html#Challenge10](https://www.ashemery.com/dfir.html#Challenge10) (Ali Hadi, Digital Forensic Challenge Images); the evidence files are not in this repository.

| | |
| --- | --- |
| Run | `s5d10`, 2026-09-18T18:43:49Z → sentinel 2026-09-18T19:31:49.192Z (**48.0 minutes**) |
| Team | 7 agents: 4 × `azure-foundry/grok-4.6`, 3 × `azure-foundry/DeepSeek-V4-Pro` |
| Evidence | `inputs/CASE.md`, `inputs/Case4.E01` (16.3 GB), read-only at the kernel in every pane (`seatbelt`) |
| Flags | `--catalog --toolbox dfir --quarantine  --cap-per-agent 14 --allow-host isf-server.techanarchy.net --allow-tool-forging --cap-usd 90 --wall-clock 240` |
| Outcome | `work/report.md` under the required headings, `work/timeline.md` with 23 dated rows, ledger of 98 entries (57 events, 24 indicators, 17 findings); **7/7 checks** pass |
| Cost | **$81.76** of the $90.00 cap, 566 model calls, 55.3M tokens; $42.39 on grok-4.6, $39.37 on DeepSeek-V4-Pro |
| Harness | nothing assigned: all seven agents named themselves within four minutes; 18 tools seeded from earlier runs and called 141 times, 2 new ones forged; 221 shell writes taken as implicit claims, 0 claim violations, 8 forge hints, 6 idle nudges, **1 per-agent cap steer — the first in eleven runs**, 0 harness faults, 0 writes to `inputs/` |

## What we asked

[`goal.md`](goal.md) is the goal document as handed to the swarm. The questions, verbatim:

1. Where is the evidence: what is Max using to hide his activity (wiping, encryption, portable or private browsing, virtual machines, steganography, timestomping, cleaners)? Name each method and the traces it left.
2. Restore the methods, tools and techniques he uses: recover the deleted or wiped tools and configurations (carving, $UsnJrnl, $LogFile, shadow copies), with hashes and what each does.
3. Where are they meeting: what was Max searching for, from the browser history and search records (including recovered ones)?
4. The encrypted file with the meeting location: which file, how it was decrypted (key, password, tool), and the meeting location.
5. From where did Max get the meeting location (URL, chat, email, download)?
6. Reflection: what this case taught about anti-forensics on Windows, the timeline of Max's activity, and anything else.

## What the agents did

This is the first case the harness ran without giving anyone a job, and the
first where the tools of earlier runs were waiting on the table. Both changes
show up in the numbers, and so does the cost of the first one.

**Nobody was assigned anything.** There is no seat list in this run: the
kickoff prepared the sandbox, the catalog and the goal, and told each agent
that nobody had given it a job. Within four minutes all seven had named
themselves — `vdi-recover`, `encrypt-meet`, `antiforensics-inventory`,
`Browser-History Hunter`, `Anti-Forensics Analyst`, `Evidence Miner`,
`Anti-Forensics Hunter` — and said what they were taking on. The names are in
`names.json`, on every post they wrote, and beside every id in the console and
in the run summary.

The cost of that freedom is measurable. Four of the seven described nearly the
same work, and three names out of seven began with "anti-forensics": with
nothing to look at, a swarm clusters on the headline question. It sorted
itself out by conversation, which is the point — `Evidence Miner` renamed
itself `Timeline & Report Builder` and took the job nobody had, and
`catalog-scout` became `vdi-recover` when the deleted virtual disk turned out
to be the case. But the first minutes were spent twice, and that is why
`name()` now answers with what every peer has already said it is doing and
names the overlap when it sees one. Information at the moment of deciding, not
an assignment.

**The tools were already there.** Eighteen tools forged in the nine earlier
runs were seeded into `tools/` before the first turn, with their authors and
versions. They were called more than a hundred and forty times: `regkv` 34,
`chunk_needles` 30, `catalog_search` 19, `prefetch_mam` 16, `icat_extract` 13,
`grep_filelist` 11, `mam_pf_parse` and `csearch` 9 each. This swarm forged
exactly two tools of its own, `guest_syslog` and `sigscan_e01`, both of them
things no earlier case had needed. Six Windows cases had rewritten an
event-log filter between them; this one wrote none.

**What it found.** Max's machine is an anti-forensics exercise: SDelete and
UltraDefrag to wipe, Defender disabled, a hosts entry for `ccdfir.local`, an
SSH setup, and a Kali virtual machine whose VDI had been deleted and its
`$DATA` truncated to zero by the wipe. The swarm carved the disk for the VDI,
reconstructed the guest's syslog from the carved blocks, and read the guest's
own logins — `champuser`, then `kali` under XFCE, after the clock was set by
NTP. Browser history and search records came out of `WebCacheV01.dat` and the
Spartan store.

The meeting location itself was not found, and the report says so. The swarm
put the `ccdfir.local` host entry and the SSH channel forward as the two
routes that would carry it, marked both as hypotheses, and left the question
open rather than dressing a guess as an answer. The critic seat spent its last
turns pushing back on exactly that: its own name, by the end, was "critic on
report Q3/Q4/Q5 overclaims until citations are honest".

**What the harness did.** Nothing had to be steered, except once: at minute 46
the timeline seat crossed its $14 cap and was told to finish and stop. That is
the first time the per-agent cap has fired in eleven runs — in the ten before
it the cap was written at kickoff and silently dropped from the budget record
on the first model call, so nothing was ever checked. The fix shipped in the
same pull request as the ninth case, and this run is where it proved itself.
221 shell writes became implicit claims with no violation, inputs came through
five checks unchanged, and there were no harness faults.

**The run before this one.** The first attempt at this case was stopped after
25 minutes and $25.68. Its agents never received a single line of the
harness's own instructions: the extension threw while building every system
prompt, because two functions were called and imported nowhere, and Pi carried
on with a prompt that said nothing about the id, the stop rule, the read-only
inputs or the naming. The agents still named themselves — they wrote
`name(Bravo, …)` as text in their posts, because the tool they were told to
call was not there. The session log was the only place the failure appeared.
That run is not published as a result; what it produced is A24 in the
improvement plan, a test that checks the extension imports what it calls, and
a harness fault that now lands on the board.

The answers are in [`run/work/report.md`](run/work/report.md); the notes each seat kept are next to it under [`run/work/`](run/work/), the merged timeline is [`run/work/timeline.md`](run/work/timeline.md), and the ledger the timeline was built from is [`run/ledger.md`](run/ledger.md). The board is under [`run/board/`](run/board/), the raw trace is [`run/trace/events.jsonl`](run/trace/events.jsonl), and [`run/summary.md`](run/summary.md) is the summary `scripts/summary.ts` wrote.

## What the harness did, by the numbers

| Signal | Count |
| --- | --- |
| trace events | 1777 |
| bash calls | 471 |
| posts | 38 on 1 thread(s) |
| implicit claims (shell writes turned into claims) | 221 |
| claim violations | 0 |
| forge hints | 8 |
| forged tools | `c10grep` by s5d1000 (0 calls), `case4_grep` by s5d1003 (0 calls), `icat_case4` by s5d1003 (0 calls), `sigscan_e01` by s5d1001 (17 calls), `case4_icat` by s5d1000 (0 calls), `sigscan_e01` by s5d1001 (17 calls), `utf16_urls` by s5d1003 (4 calls), `guest_syslog` by s5d1001 (6 calls), `inputs_check` by s5d1002 (0 calls) |
| idle nudges | 6 |
| sentinel nudge | reached 6, missed 0 |
| inputs checks | 5 |
| writes to inputs/ | 0 |
| per-agent cap steers / stops | 1 / 0 |
| ledger entries | 98 (57 events, 24 indicators, 17 findings) by 7 agents |

## What it cost, and who spent it

| Agent | Seat | Model | Spend | Calls | Tokens |
| --- | --- | --- | --- | --- | --- |
| s5d1005 |  | DeepSeek-V4-Pro | $14.31 | 128 | 11.4M |
| s5d1004 |  | DeepSeek-V4-Pro | $13.47 | 112 | 10.6M |
| s5d1002 |  | grok-4.6 | $12.58 | 69 | 8.2M |
| s5d1003 |  | grok-4.6 | $11.87 | 70 | 7.1M |
| s5d1006 |  | DeepSeek-V4-Pro | $11.59 | 82 | 7.5M |
| s5d1000 |  | grok-4.6 | $9.75 | 54 | 5.6M |
| s5d1001 |  | grok-4.6 | $8.20 | 51 | 5.0M |

| Model | Spend | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| `azure-foundry/grok-4.6` | $42.39 | 52 % | 244 | 4 |
| `azure-foundry/DeepSeek-V4-Pro` | $39.37 | 48 % | 322 | 3 |

## Screenshots

The console at 8941 after the run:

- [`01-board-names.png`](screenshots/01-board-names.png) — the board: every post under the name its author chose for itself.
- [`02-agents-self-named.png`](screenshots/02-agents-self-named.png) — the seven agents with the names they took and what each said it was doing.
- [`03-budget-cap-fired.png`](screenshots/03-budget-cap-fired.png) — the Budget tab: $81.76 of $90, and the seat that crossed the $14 per-agent cap and was steered.
- [`04-tools-from-library.png`](screenshots/04-tools-from-library.png) — the Tools tab: eighteen tools from earlier runs beside the two this swarm forged.

## Reproducing it

Get the evidence from the source above into one directory, install `sleuthkit`, `libewf`, `yara` and `foremost` (brew) and `volatility3` (pipx), start Herdr, and run:

```
scripts/swarm.sh start --models "openai/gpt-5.4=4,deepseek/deepseek-v4-pro=3" --cap-usd 90 --wall-clock 240 \
  --goal-file goal.md --inputs <evidence dir> --inputs-max-mb 60000 --catalog --toolbox dfir --quarantine  --cap-per-agent 14 --allow-host isf-server.techanarchy.net --allow-tool-forging \
  --case-id AH-C10 --examiner "<name>"
```

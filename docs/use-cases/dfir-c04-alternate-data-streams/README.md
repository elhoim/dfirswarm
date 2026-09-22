# Use case: Challenge #4, Launching Attacks from Alternate Data Streams — hidden prefetch files and what Defender saw

The swarm on Challenge #4, Launching Attacks from Alternate Data Streams: what was asked, who did what, what the harness did, what it cost, and everything the agents wrote, with the console and the terminals captured while they worked. The case is [https://www.ashemery.com/dfir.html#Challenge4](https://www.ashemery.com/dfir.html#Challenge4) (Ali Hadi, Digital Forensic Challenge Images); the evidence files are not in this repository.

| | |
| --- | --- |
| Run | `sbe18`, 2026-09-18T12:55:07Z → sentinel 2026-09-18T13:10:20.611Z (**15.2 minutes**) |
| Team | 7 agents: 4 × `openai/gpt-5.4`, 3 × `deepseek/deepseek-v4-pro` |
| Evidence | `inputs/CASE.md`, `inputs/StealthyADS.E01` (7.3 GB), `inputs/StealthyADS.E01.csv`, `inputs/StealthyADS.E01.txt`, read-only at the kernel in every pane (`seatbelt`) |
| Flags | `--catalog --toolbox dfir --quarantine --seats dfir --cap-per-agent 12 --allow-host isf-server.techanarchy.net --allow-tool-forging --cap-usd 60 --wall-clock 180` |
| Outcome | `work/report.md` under the required headings, `work/timeline.md` with 45 dated rows, ledger of 104 entries (72 events, 10 indicators, 22 findings); **7/7 checks** pass |
| Cost | **$12.45** of the $60.00 cap, 421 model calls, 40.0M tokens; $11.18 on gpt-5.4, $1.27 on deepseek-v4-pro |
| Harness | 70 shell writes taken as implicit claims, 9 claim violations, 4 forged tool(s) called 45 times, 4 forge hints, 1 idle nudges, 0 writes to `inputs/` |

## What we asked

[`goal.md`](goal.md) is the goal document as handed to the swarm. The questions, verbatim:

1. Every alternate data stream on the volume that is not a plain Zone.Identifier: the host file or directory, the stream name, its size, its hash, and what it contains.
2. Which stream payloads were executed, when, by which user and by what means (Prefetch, ShimCache, Amcache, UserAssist, event logs 4688, PowerShell and WMI traces, command lines).
3. The stealthy case: the hidden prefetch file or the stream attached to a directory that a normal listing misses. Where it is, how it was hidden, and what it hides.
4. Did Windows Defender (or another AV) scan or flag any of them? What the Defender logs, event logs and quarantine show.
5. Detection: for each hiding technique found, the method that reveals it (`fls` output, $MFT attribute lists, `istat`, USN journal, prefetch parsing) with the command and its output.
6. The timeline of creation, execution and detection events.

## What the agents did

The board is under [`run/board/`](run/board/) (one thread, 41 posts), the raw trace in [`run/trace/events.jsonl`](run/trace/events.jsonl) (1,134 lines), and every pane's terminal at the end under [`run/panes/`](run/panes/). The short version:

**Minute 0–1 — seats.** Seven intros; the memory seat again found no memory image and turned itself into an execution-trace seat, which on this case was the right call.

**Minute 1–2 — the streams, from the catalog.** The disk seat filtered the catalog's body file for a colon in the path and, after dropping `Zone.Identifier`, the Windows overlay-compression streams and the NTFS system streams, had the whole inventory in one pass: `welcome.txt:putty.exe` and `LPT1.txt:putty.exe` under `Desktop\creepy` (809,984 bytes each, the same SHA-256 as the visible `putty.exe` — PuTTY 0.70), and two zero-byte files in `C:\Windows\Prefetch`, `WELCOME.TXT` and `WELCOME2.TXT`, each carrying a named stream that is a prefetch file: `PUTTY.EXE-A6BB0639.pf` and `REVSHELL.EXE-41B5A636.pf`. That second pair is the "stealthy" case the challenge is about: an executable run from a stream gets a prefetch file named after the stream, the colon cannot be a filename, so Windows writes the record as a stream on a file named after the host — and a normal directory listing shows two empty text files.

**Minute 2 — the harness gets it wrong, eight times.** The leftovers seat's `tsk_recover` was landing eight extracts under `work/extracted/sbe1803/` while the memory seat's shell call ran; that call had named `work/extracted`, and the directory rule (as PR #18 had left it) charged all eight to the memory seat, which posted a `hold` disowning writes it had not made. Plan item A15 was tightened in PR #19 before the next case: the shared roots `work/extracted` and `work/quarantine` name nothing, and a directory named after a teammate is the teammate's. A ninth false notice at the end charged an agent with "writing" `done/SWARM_DONE` because a peer's `done` created it during that agent's shell call; that is the next fix.

**Minute 2–8 — three tools, forty-five calls.** The accounts seat forged `evtx_query` (33 calls, four users); the leftovers seat forged `prefetch_mam`, a decompressor for Windows 10's MAM-compressed prefetch format, and re-forged it as v2 a minute later; the provenance seat forged `reg_hive_query`. With `prefetch_mam` the execution-trace seat parsed the two hidden prefetch streams and read the executable names out of them with the colon still in place — `WELCOME.TXT:PUTTY.EXE`, last run 08:41:32Z, and `WELCOME2.TXT:REVSHELL.EXE`, last run 08:41:52Z — direct proof that the payloads were launched from streams, not from files.

**Minute 4–9 — Defender answers question 4.** The accounts seat extracted the Defender Operational log; `evtx_query` showed a scan of the Desktop at 08:43:09Z, a detection at 08:43:13Z of `Trojan:Win32/Meterpreter.O` naming `COM1.txt:revshell.exe`, `welcome2.txt:revshell.exe` and `rev.exe`, and a successful remediation at 08:44:15Z — Defender does scan streams and removed the malicious ones before the image was taken, which is why `revshell.exe` exists only in Defender's records and its DetectionHistory hash. The PuTTY copies, being benign, were scanned and left alone. The critic filled the last execution-artifact gap itself, parsing ShimCache and UserAssist out of the hives: all four stream payloads in ShimCache, `cmd.exe`, `notepad.exe`, PuTTY and PowerShell in UserAssist, then FTK Imager at 08:50Z.

**Minute 8 — one nudge.** The accounts seat went quiet for 204 seconds after its second results post; the watchdog prompted it once and it finished its notes. No other agent needed one.

**Minute 15 — the sign-off.** The critic assembled the report under six headings with the command that reveals each hiding technique and its output on this image, and posted a sign-off naming what it re-extracted and re-hashed; the memory seat, first to see it, called `done` at 13:10:20. The sentinel nudge reached all six peers; seven markers in nine seconds.

**What the report says.** Four non-system streams on the volume: PuTTY 0.70 hidden in `welcome.txt` and `LPT1.txt`, and two hidden prefetch files as streams on empty files in `C:\Windows\Prefetch`; three more streams (`COM1.txt:revshell.exe`, `welcome2.txt:revshell.exe`, and the visible `rev.exe`) held a Meterpreter reverse shell that Windows Defender detected and removed on 26 May 2019 at 08:44Z. Both PuTTY and the reverse shell were executed from their streams by `IEUser` (a local administrator, elevated session at 08:29Z), proven by the hidden prefetch records and ShimCache; `LPT1.txt` and `COM1.txt` use reserved DOS device names so ordinary Win32 tools cannot open them at all. For each technique the report gives the Sleuth Kit command that reveals it (`fls` with attribute ids, `istat` showing the `$DATA` attributes, the imager's CSV rendering streams as nested paths) — which is the point of the exercise.

The answers are in [`run/work/report.md`](run/work/report.md); the notes each seat kept are next to it under [`run/work/`](run/work/), the merged timeline is [`run/work/timeline.md`](run/work/timeline.md), and the ledger the timeline was built from is [`run/ledger.md`](run/ledger.md). The board is under [`run/board/`](run/board/), the raw trace is [`run/trace/events.jsonl`](run/trace/events.jsonl), and [`run/summary.md`](run/summary.md) is the summary `scripts/summary.ts` wrote.

## What the harness did, by the numbers

| Signal | Count |
| --- | --- |
| trace events | 1134 |
| bash calls | 253 |
| posts | 25 on 1 thread(s) |
| implicit claims (shell writes turned into claims) | 70 |
| claim violations | 9 |
| forge hints | 4 |
| forged tools | `evtx_query` by sbe1801 (33 calls), `prefetch_mam` by sbe1803 (9 calls), `prefetch_mam` by sbe1803 (9 calls), `reg_hive_query` by sbe1805 (3 calls) |
| idle nudges | 1 |
| sentinel nudge | reached 6, missed 0 |
| inputs checks | 5 |
| writes to inputs/ | 0 |
| per-agent cap steers / stops | 0 / 0 |
| ledger entries | 104 (72 events, 10 indicators, 22 findings) by 7 agents |

## What it cost, and who spent it

| Agent | Seat | Model | Spend | Calls | Tokens |
| --- | --- | --- | --- | --- | --- |
| sbe1801 | Accounts and event logs | gpt-5.4 | $4.20 | 59 | 9.5M |
| sbe1803 | Leftovers and malware | gpt-5.4 | $3.27 | 68 | 8.8M |
| sbe1800 | Disk triage | gpt-5.4 | $2.09 | 60 | 4.6M |
| sbe1802 | Memory forensics | gpt-5.4 | $1.61 | 80 | 3.4M |
| sbe1806 | Critic and editor | deepseek-v4-pro | $0.51 | 52 | 5.9M |
| sbe1804 | Timeline and ledger | deepseek-v4-pro | $0.39 | 42 | 3.9M |
| sbe1805 | Installed software and provenance | deepseek-v4-pro | $0.37 | 60 | 3.8M |

| Model | Spend | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| `openai/gpt-5.4` | $11.18 | 90 % | 267 | 4 |
| `deepseek/deepseek-v4-pro` | $1.27 | 10 % | 154 | 3 |

**Rates.** Pi bills `deepseek/deepseek-v4-pro` at DeepSeek's peak rate
($1.32 input, $3.96 output, $0.044 cached input per 1M tokens). DeepSeek's peak window is
01:00–04:00 and 06:00–10:00 UTC on weekdays, and this run started at
12:55 UTC on a Friday, so it was invoiced off-peak, at exactly half.
The DeepSeek figures above are the off-peak ones, which is why they are
lower than the ones the run reported in [`run/summary.md`](run/summary.md).

## Screenshots

The console at 8941 during the run (only forensic runs are listed on it):

- [`01-overview-t1.png`](screenshots/01-overview-t1.png)
- [`02-story-t3.png`](screenshots/02-story-t3.png)
- [`03-story-final.png`](screenshots/03-story-final.png)
- [`04-ledger-final.png`](screenshots/04-ledger-final.png)
- [`05-budget-final.png`](screenshots/05-budget-final.png)

## Reproducing it

Get the evidence from the source above into one directory, install `sleuthkit`, `libewf`, `yara` and `foremost` (brew) and `volatility3` (pipx), start Herdr, and run:

```
scripts/swarm.sh start --models "openai/gpt-5.4=4,deepseek/deepseek-v4-pro=3" --cap-usd 60 --wall-clock 180 \
  --goal-file goal.md --inputs <evidence dir> --inputs-max-mb 60000 --catalog --toolbox dfir --quarantine --seats dfir --cap-per-agent 12 --allow-host isf-server.techanarchy.net --allow-tool-forging \
  --case-id ALIHADI-C4 --examiner "<name>"
```

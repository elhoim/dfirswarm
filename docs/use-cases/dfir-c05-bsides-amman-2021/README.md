# Use case: Challenge #5, BSides Amman 2021 Windows Forensics Workshop — sixteen questions, one renamed tool, four artifact families

The swarm on Challenge #5, BSides Amman 2021 Windows Forensics Workshop: what was asked, who did what, what the harness did, what it cost, and everything the agents wrote, with the console and the terminals captured while they worked. The case is [https://www.ashemery.com/dfir.html#Challenge5](https://www.ashemery.com/dfir.html#Challenge5) (Ali Hadi, Digital Forensic Challenge Images); the evidence files are not in this repository.

| | |
| --- | --- |
| Run | `s2f66`, 2026-09-18T13:11:12Z → sentinel 2026-09-18T13:26:30.565Z (**15.3 minutes**) |
| Team | 7 agents: 4 × `openai/gpt-5.4`, 3 × `deepseek/deepseek-v4-pro` |
| Evidence | `inputs/BSidesAmman21.E01` (5.7 GB), `inputs/CASE.md`, `inputs/README.rtf`, read-only at the kernel in every pane (`seatbelt`) |
| Flags | `--catalog --toolbox dfir --quarantine --seats dfir --cap-per-agent 12 --allow-host isf-server.techanarchy.net --allow-tool-forging --cap-usd 60 --wall-clock 180` |
| Outcome | `work/report.md` under the required headings, `work/timeline.md` with 42 dated rows, ledger of 94 entries (65 events, 3 indicators, 26 findings); **9/9 checks** pass |
| Cost | **$19.11** of the $60.00 cap, 572 model calls, 61.3M tokens; $17.06 on gpt-5.4, $2.05 on deepseek-v4-pro |
| Harness | 134 shell writes taken as implicit claims, 1 claim violations, 5 forged tool(s) called 14 times, 4 forge hints, 0 idle nudges, 0 writes to `inputs/` |

## What we asked

[`goal.md`](goal.md) is the goal document as handed to the swarm. The questions, verbatim:

1. What is the hash value of the given forensic image? (The acquisition record inside the E01, `ewfinfo`, and a hash you compute of the image file itself, stated separately.)
2. Which user account was used to access the confidential documents?
3. Explain in detail what proof supports that answer.
4. Did the user access the confidential files from a local drive or a network location?
5. What proof supports that answer?
6. List every file that was accessed, with full paths.
7. Provide two different kinds of evidence that prove those files were truly accessed.
8. Which application was used to open any of the confidential documents?
9. The image with the text "AnotherPassword4U" in a user home directory: what is the full path to the file(s) of interest?
10. What is the Volume Serial Number of the volume where that file exists?
11. What are the Modified, Accessed and Created (MAC) timestamps of that file, in UTC?
12. DCode.exe was used by one of the users; the workshop warns this is a tricky question. Which user ran it, and what evidence supports that?
13. How many times was DCode.exe used?
14. When was it last used?
15. Where was the application located (full path)?
16. Timeline of the confidential-file access and the DCode.exe activity, plus anything else the examiner should know.

## What the agents did

The board is under [`run/board/`](run/board/) (one thread, 42 posts), the raw trace in [`run/trace/events.jsonl`](run/trace/events.jsonl) (1,389 lines, the longest of the cases so far), and every pane's terminal at the end under [`run/panes/`](run/panes/). The short version:

**Minute 0–1 — seats.** Seven intros; the memory seat, finding no memory image for the third case running, took the memory-adjacent disk artifacts (pagefile, hiberfil, prefetch, Amcache) and became the second execution-trace seat, which on this case paid off.

**Minute 1–3 — the burst.** The disk seat read the catalog's timeline and found the whole story in one window: 04:59:22Z to 05:04:19Z on 15 February 2019, under `Users\Joker`. In that window `DCode.exe` and `putty.exe` land, `haha.png` is written, WordPad is pinned to the taskbar, four `Confidential*.lnk` shortcuts appear in Joker's `Recent`. The accounts seat forged `evtx_filter` (and re-forged it a minute later as v2, to skip records whose XML fails to render) and established the accounts from SAM and the Security log: `IEUser` created `Joker` at 04:53:35Z; `Joker` is the account with the confidential-document artifacts, `IEUser` the one with `FindMeIfYouCan.jpg` and `forensics.jpg` from the share.

**Minute 3–6 — the share and the picture.** The leftovers seat read the LNK files with `exiftool` and found the confidential documents came from `\\192.168.70.128\SharedJJ\docs`, a network location mapped as `O:`, not the local drive; the jump lists and the shellbags agreed. The `AnotherPassword4U` image turned out to exist twice, byte for byte (`C:\Users\Joker\haha.png` and `C:\Users\IEUser\Pictures\pics\whoami4.png`, same SHA-256); the disk and leftovers seats each verified the other's copy, and the report gives the home-directory one the question asks for, with `tesseract` reading the text out of it, the volume serial in both its forms (`EE68D66268D628DB` from `fsstat`, `68D6-28DB` in the LNK), and the MAC times in UTC after converting `istat`'s +03 rendering.

**Minute 4–9 — the trick, from three sides.** The workshop warns that the DCode question is tricky. The disk seat found `DCode.exe` in Joker's profile but no `DCODE.EXE-*.pf` in Prefetch, and said so with a caution rather than a guess. The accounts seat then found DCode's VB6 settings key in Joker's `NTUSER.DAT` only, and `C:\Users\Joker\dd.exe` in Joker's UserAssist with `run_count=1` at 05:02:12Z; the memory seat found `DD.EXE-0C303FDD.pf` in Prefetch and Amcache's entry for `dd.exe`; the disk seat hashed the two files and they are identical. The tool was renamed to `dd.exe` before it was run, once, by Joker, at 05:02:12Z — three seats, three artifact families, one answer, recorded in the ledger as it was assembled. The disk seat forged `mam_pf_parse` to read the Windows 10 prefetch file's run count and last-run time directly, confirming it a fourth way.

**Minute 9–14 — a custody tool, fixed on the board.** The critic forged `inputs_check` (a SHA-256 comparison of `inputs/` against the pristine copy); the memory seat ran it and it failed with an unbound variable; the critic re-forged it as v2 within a minute and four agents ran it successfully before calling `done` — a bug report, a fix and a verification, all on the board, in under three minutes. (The harness reserves that name now, since it collides with its own `inputs_check` event.)

**Minute 15 — the sign-off.** The critic assembled the report under sixteen headings, each with the command and its output quoted as the workshop demands, and posted a sign-off naming what it re-verified; the disk seat, first to see it, called `done` at 13:26:30. The sentinel nudge reached five peers and missed the timeline seat, which was inside a tool call and hit the sentinel on its own next call; seven markers in fifteen seconds. No idle nudge in the whole run; the one "claim violation" is the sentinel appearing during a shell call, fixed in PR #20.

**What the report says.** The image's acquisition digests (MD5 `634ed59c…`, SHA1 `4e4bd40d…` from `ewfinfo`) and the E01 container's own hashes, stated separately and explained. `Joker` accessed the confidential documents, from a network share (`\\192.168.70.128\SharedJJ\docs`, mapped `O:`), proven by LNK targets, jump lists and shellbags, and opened them with WordPad (UserAssist, the taskbar pin, the LNK's application). The picture is `C:\Users\Joker\haha.png` on volume `68D6-28DB`, created and modified 2019-02-15 05:00:21Z. `DCode.exe` was run by Joker under the name `dd.exe`, once, at 05:02:12Z, from `C:\Users\Joker\DCode.exe`.

The answers are in [`run/work/report.md`](run/work/report.md); the notes each seat kept are next to it under [`run/work/`](run/work/), the merged timeline is [`run/work/timeline.md`](run/work/timeline.md), and the ledger the timeline was built from is [`run/ledger.md`](run/ledger.md). The board is under [`run/board/`](run/board/), the raw trace is [`run/trace/events.jsonl`](run/trace/events.jsonl), and [`run/summary.md`](run/summary.md) is the summary `scripts/summary.ts` wrote.

## What the harness did, by the numbers

| Signal | Count |
| --- | --- |
| trace events | 1389 |
| bash calls | 356 |
| posts | 33 on 1 thread(s) |
| implicit claims (shell writes turned into claims) | 134 |
| claim violations | 1 |
| forge hints | 4 |
| forged tools | `evtx_filter` by s2f6601 (2 calls), `evtx_filter` by s2f6601 (2 calls), `mam_pf_parse` by s2f6600 (4 calls), `inputs_check` by s2f6606 (8 calls), `inputs_check` by s2f6606 (8 calls) |
| idle nudges | 0 |
| sentinel nudge | reached 5, missed 1 |
| inputs checks | 13 |
| writes to inputs/ | 0 |
| per-agent cap steers / stops | 0 / 0 |
| ledger entries | 94 (65 events, 3 indicators, 26 findings) by 7 agents |

## What it cost, and who spent it

| Agent | Seat | Model | Spend | Calls | Tokens |
| --- | --- | --- | --- | --- | --- |
| s2f6603 | Leftovers and malware | gpt-5.4 | $5.71 | 87 | 12.3M |
| s2f6600 | Disk triage | gpt-5.4 | $4.39 | 99 | 11.7M |
| s2f6601 | Accounts and event logs | gpt-5.4 | $3.52 | 106 | 10.2M |
| s2f6602 | Memory forensics | gpt-5.4 | $3.44 | 97 | 9.0M |
| s2f6606 | Critic and editor | deepseek-v4-pro | $0.74 | 64 | 6.4M |
| s2f6605 | Installed software and provenance | deepseek-v4-pro | $0.67 | 66 | 6.3M |
| s2f6604 | Timeline and ledger | deepseek-v4-pro | $0.64 | 53 | 5.5M |

| Model | Spend | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| `openai/gpt-5.4` | $17.06 | 89 % | 389 | 4 |
| `deepseek/deepseek-v4-pro` | $2.05 | 11 % | 183 | 3 |

**Rates.** Pi bills `deepseek/deepseek-v4-pro` at DeepSeek's peak rate
($1.32 input, $3.96 output, $0.044 cached input per 1M tokens). DeepSeek's peak window is
01:00–04:00 and 06:00–10:00 UTC on weekdays, and this run started at
13:11 UTC on a Friday, so it was invoiced off-peak, at exactly half.
The DeepSeek figures above are the off-peak ones, which is why they are
lower than the ones the run reported in [`run/summary.md`](run/summary.md).

## Screenshots

The console at 8941 during the run (only forensic runs are listed on it):

- [`01-story-t3.png`](screenshots/01-story-t3.png)
- [`02-story-final.png`](screenshots/02-story-final.png)
- [`03-ledger-final.png`](screenshots/03-ledger-final.png)
- [`04-budget-final.png`](screenshots/04-budget-final.png)

## Reproducing it

Get the evidence from the source above into one directory, install `sleuthkit`, `libewf`, `yara` and `foremost` (brew) and `volatility3` (pipx), start Herdr, and run:

```
scripts/swarm.sh start --models "openai/gpt-5.4=4,deepseek/deepseek-v4-pro=3" --cap-usd 60 --wall-clock 180 \
  --goal-file goal.md --inputs <evidence dir> --inputs-max-mb 60000 --catalog --toolbox dfir --quarantine --seats dfir --cap-per-agent 12 --allow-host isf-server.techanarchy.net --allow-tool-forging \
  --case-id ALIHADI-C5 --examiner "<name>"
```

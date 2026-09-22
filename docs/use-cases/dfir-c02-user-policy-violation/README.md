# Use case: Challenge #2, User Policy Violation — a data exfiltration case solved in ten minutes

The swarm on Challenge #2, User Policy Violation: what was asked, who did what, what the harness did, what it cost, and everything the agents wrote, with the console and the terminals captured while they worked. The case is [https://www.ashemery.com/dfir.html#Challenge2](https://www.ashemery.com/dfir.html#Challenge2) (Ali Hadi, Digital Forensic Challenge Images); the evidence files are not in this repository.

| | |
| --- | --- |
| Run | `s0ae9`, 2026-09-18T12:28:12Z → sentinel 2026-09-18T12:38:11.842Z (**10.0 minutes**) |
| Team | 7 agents: 4 × `openai/gpt-5.4`, 3 × `deepseek/deepseek-v4-pro` |
| Evidence | `inputs/4orensics.001` (26.5 GB), `inputs/CASE.md`, `inputs/README.txt`, read-only at the kernel in every pane (`seatbelt`) |
| Flags | `--catalog --toolbox dfir --quarantine --seats dfir --cap-per-agent 12 --allow-host isf-server.techanarchy.net --allow-tool-forging --cap-usd 60 --wall-clock 180` |
| Outcome | `work/report.md` under the required headings, `work/timeline.md` with 64 dated rows, ledger of 85 entries (62 events, 9 indicators, 14 findings); **7/7 checks** pass |
| Cost | **$11.40** of the $60.00 cap, 390 model calls, 36.6M tokens; $10.32 on gpt-5.4, $1.08 on deepseek-v4-pro |
| Harness | 53 shell writes taken as implicit claims, 0 claim violations, 2 forged tool(s) called 6 times, 4 forge hints, 0 idle nudges, 0 writes to `inputs/` |

## What we asked

[`goal.md`](goal.md) is the goal document as handed to the swarm. The questions, verbatim:

1. System profile: Windows edition and install date, computer name, time zone, network configuration, every user account with its SID, creation and last logon.
2. What is the policy violation? State the hypothesis and prove it: who did what, when, and the artifacts that show it.
3. Program execution: what was run, by which user, when, and how you know (Prefetch, ShimCache, Amcache, UserAssist, jump lists, LNK files, RunMRU).
4. Files of interest: documents, downloads, deleted and recycled files (recycle bins, $UsnJrnl, carving), thumbcaches and Windows Search entries that show them.
5. USB and removable devices: every device connected, when, under which user, and what was accessed on it (SYSTEM/SOFTWARE/NTUSER, setupapi, event logs, LNK, shellbags).
6. Communications: email (web and Outlook), browsers (Internet Explorer and Chrome: history, searches, downloads, cache), Skype (accounts, contacts, chats, calls, transfers).
7. The timeline of the violation, from first related event to last, across every source.
8. Hypothesis, approach, and anything else the examiner should know.

## What the agents did

The board is under [`run/board/`](run/board/) (one thread, 30 posts), the raw trace in [`run/trace/events.jsonl`](run/trace/events.jsonl) (926 lines), and the pane captures every three minutes are summarised in [`run/panes/`](run/panes/). The short version:

**Minute 0–1 — seats, no negotiation.** Seven intros, each naming the seat from the contract; the disk seat announced "I'll use the catalog first". The memory seat (s0ae902) read the catalog index, saw "0 memory image(s)", said so on the board and kept the seat for the memory-adjacent evidence on disk: the TeamViewer logs, which turned out to be central.

**Minute 1–4 — the catalog and the extracts.** Nobody ran `fls` over the 26 GB volume: the kickoff had already built the body file (280,524 rows), the path list (144,156 rows) and the MAC timeline (468,590 rows) in the two minutes before the first agent spoke, and the seats read them 36 times in bash. The extracts came out by `icat` on inodes taken from the path list: SAM, SYSTEM, SOFTWARE, SECURITY, Hunter's NTUSER.DAT, the Security and System event logs, the Prefetch directory, the Skype `main.db`, the Outlook `.ost` and the exported `backup.pst`, the TeamViewer logs, the Chrome and Internet Explorer histories, the LNK files under `Recent`.

**Minute 3 — the critic finds a gap.** Before any finding was posted, the critic (s0ae906) noticed that the dfir seat preset assigns nobody to question 5 (USB devices) and question 6 (communications) and asked the board to cover them; the accounts seat took USB from the SYSTEM hive and the setupapi log, the leftovers and memory seats took Skype, Outlook and the browsers. The seat preset was written for the web server case; this case needed different seats, and the swarm re-cut them itself in one post.

**Minute 4–9 — the case comes together.** The leftovers seat found the toolkit Hunter installed in one day (TeamViewer, Tor Browser, Nmap, Wireshark, BCWipe, Eraser, CCleaner, Burp, OllyDbg, Sysinternals) and the incoming TeamViewer remote-control session from partner `PSUT1`; the disk seat found `Conf.jpg` in Hunter's Documents, byte-for-byte a copy of `Confidential Document.pdf` renamed to look like a picture, and the encrypted `Pictures.7z` staged in Dropbox; the accounts seat established that `Hunter` (RID 1001, local administrator) is the only human account with interactive logons and read the two clock-rollback records (event 4616) that explain the odd early timestamps; the memory seat pulled the Skype chat in which Hunter asks `linux-rul3z` for "help with Data Exfiltration" because "our network is monitored", is told to install TeamViewer, and later shares `fakeporn.7z` ("Nice pics;)"). Every one of these went into the ledger with its inode as it was found (85 entries by the end, 62 of them dated events), and the timeline seat wrote `work/timeline.md` from the ledger, with the clock rollback as a caveat rather than a contradiction.

**Minute 6–9 — two forged tools.** The accounts seat forged `evtx_filter` (an event-id and substring filter over an EVTX file) after the harness hinted at its eighth `python3` call; the timeline seat forged `inputs_check`, a full-hash verifier of `inputs/` against the manifest, and five agents ran it before calling `done` — a custody check the agents added on their own. (Its name collides with the harness's own `inputs_check` event; the plan notes it.)

**Minute 10 — the sign-off.** The critic assembled `work/report.md` from the six notes files and the ledger, posted a sign-off naming what it had re-verified (the hash identity of `Conf.jpg` and the PDF, the TeamViewer session times against the time zone, the SAM RIDs, the Skype records), and the disk seat, first to see it, called `done` at 12:38:11. The sentinel nudge reached five peers; the critic was mid-call and missed the prompt but hit the sentinel on its next tool call. Seven markers in eight seconds; no idle nudge was needed in the whole run.

**What the report says.** The policy violation is intentional data exfiltration by the user `Hunter`: a confidential PDF disguised as `Conf.jpg`, encrypted and disguised archives (`Pictures.7z`, `fakeporn.7z`) shared over Skype and staged in Dropbox and Google Drive, an outside party (`linux-rul3z`) recruited over Skype, a TeamViewer remote-control session granted to `PSUT1` with file transfer, clipboard and VPN allowed, two USB sticks (Imation, Lexar) connected during the staging, an Outlook `backup.pst` exported to Dropbox, and anti-forensics tooling (BCWipe, Eraser, CCleaner, Tor) run afterwards. The examiner's notes flag what is not proven: the two `backup.pst` files differ in hash, the note file's account names are mistyped against the live databases, and the VM clock was rolled back twice, so early absolute times are about ten hours later than recorded.

The answers are in [`run/work/report.md`](run/work/report.md); the notes each seat kept are next to it under [`run/work/`](run/work/), the merged timeline is [`run/work/timeline.md`](run/work/timeline.md), and the ledger the timeline was built from is [`run/ledger.md`](run/ledger.md). The board is under [`run/board/`](run/board/), the raw trace is [`run/trace/events.jsonl`](run/trace/events.jsonl), and [`run/summary.md`](run/summary.md) is the summary `scripts/summary.ts` wrote.

## What the harness did, by the numbers

| Signal | Count |
| --- | --- |
| trace events | 926 |
| bash calls | 247 |
| posts | 23 on 1 thread(s) |
| implicit claims (shell writes turned into claims) | 53 |
| claim violations | 0 |
| forge hints | 4 |
| forged tools | `evtx_filter` by s0ae901 (1 calls), `inputs_check` by s0ae904 (5 calls) |
| idle nudges | 0 |
| sentinel nudge | reached 5, missed 1 |
| inputs checks | 7 |
| writes to inputs/ | 0 |
| per-agent cap steers / stops | 0 / 0 |
| ledger entries | 85 (62 events, 9 indicators, 14 findings) by 7 agents |

## What it cost, and who spent it

| Agent | Seat | Model | Spend | Calls | Tokens |
| --- | --- | --- | --- | --- | --- |
| s0ae903 | Leftovers and malware | gpt-5.4 | $4.14 | 61 | 9.8M |
| s0ae900 | Disk triage | gpt-5.4 | $2.53 | 52 | 7.3M |
| s0ae902 | Memory forensics | gpt-5.4 | $2.12 | 62 | 6.0M |
| s0ae901 | Accounts and event logs | gpt-5.4 | $1.53 | 64 | 3.1M |
| s0ae906 | Critic and editor | deepseek-v4-pro | $0.42 | 54 | 3.9M |
| s0ae904 | Timeline and ledger | deepseek-v4-pro | $0.35 | 49 | 3.7M |
| s0ae905 | Installed software and provenance | deepseek-v4-pro | $0.31 | 48 | 2.8M |

| Model | Spend | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| `openai/gpt-5.4` | $10.32 | 91 % | 239 | 4 |
| `deepseek/deepseek-v4-pro` | $1.08 | 9 % | 151 | 3 |

**Rates.** Pi bills `deepseek/deepseek-v4-pro` at DeepSeek's peak rate
($1.32 input, $3.96 output, $0.044 cached input per 1M tokens). DeepSeek's peak window is
01:00–04:00 and 06:00–10:00 UTC on weekdays, and this run started at
12:28 UTC on a Friday, so it was invoiced off-peak, at exactly half.
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
  --case-id ALIHADI-C2 --examiner "<name>"
```

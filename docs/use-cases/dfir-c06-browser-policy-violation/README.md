# Use case: Challenge #6, Browser Policy Violation — a browser that arrived by drag-and-drop, and what it was used for

The swarm on Challenge #6, Browser Policy Violation: what was asked, who did what, what the harness did, what it cost, and everything the agents wrote, with the console and the terminals captured while they worked. The case is [https://www.ashemery.com/dfir.html#Challenge6](https://www.ashemery.com/dfir.html#Challenge6) (Ali Hadi, Digital Forensic Challenge Images); the evidence files are not in this repository.

| | |
| --- | --- |
| Run | `s8810`, 2026-09-18T13:27:22Z → sentinel 2026-09-18T13:38:33.037Z (**11.2 minutes**) |
| Team | 7 agents: 4 × `openai/gpt-5.4`, 3 × `deepseek/deepseek-v4-pro` |
| Evidence | `inputs/Browser_Policy_Violation.E01` (6.3 GB), `inputs/Browser_Policy_Violation.txt`, `inputs/CASE.md`, read-only at the kernel in every pane (`seatbelt`) |
| Flags | `--catalog --toolbox dfir --quarantine --seats dfir --cap-per-agent 12 --allow-host isf-server.techanarchy.net --allow-tool-forging --cap-usd 60 --wall-clock 180` |
| Outcome | `work/report.md` under the required headings, `work/timeline.md` with 45 dated rows, ledger of 79 entries (58 events, 5 indicators, 16 findings); **7/7 checks** pass |
| Cost | **$10.03** of the $60.00 cap, 419 model calls, 35.9M tokens; $9.09 on gpt-5.4, $0.95 on deepseek-v4-pro |
| Harness | 53 shell writes taken as implicit claims, 19 claim violations, 2 forged tool(s) called 3 times, 5 forge hints, 1 idle nudges, 0 writes to `inputs/` |

## What we asked

[`goal.md`](goal.md) is the goal document as handed to the swarm. The questions, verbatim:

1. System and users: Windows edition, computer name, time zone, the user accounts and their activity windows.
2. Every browser present on the system (installed or portable), which user used it, first and last use, and how you know (program folders, prefetch, Amcache, ShimCache, UserAssist, LNK, profiles).
3. The non-compliant browser: what it is, where it came from (download record, USB, archive), when it arrived and was first run, and by whom.
4. What it was used for: history, searches, downloads, sessions, cookies and cache of interest, with times.
5. Attempts to hide or clean: private mode, deleted history, cleaning tools, renamed executables, and the traces they left anyway ($UsnJrnl, $LogFile, carving, shellbags).
6. The timeline of the violation.
7. Conclusion for HR: what the evidence establishes, with what confidence, and what it does not.

## What the agents did

The board is under [`run/board/`](run/board/) (`main`, 26 posts, and a `report-review` side thread the critic opened for the seats' cross-checks), the raw trace in [`run/trace/events.jsonl`](run/trace/events.jsonl) (1,019 lines), and the run's own files under [`run/`](run/). The pane captures were not kept for this run. The short version:

**Minute 0–1 — seats.** Seven intros; the memory seat, with no memory image and no pagefile or hibernation file on the volume either, pivoted to the disk-resident browser databases, which is where the case lived.

**Minute 1 — the harness gets it wrong, nineteen times, then never again.** Three agents were reported for "claim violations" with no owner and no revision — `work/extracted/accounts/SAM`, eighteen browser and registry extracts — while their peers were moving and rewriting those files; the implicit claim on a path that had just vanished failed and the fall-through called it a violation. That became plan item A17, fixed in PR #21 before the next run: a path gone when the call ends and never named by the command is a peer's move, and a failed implicit claim re-reads the lock before it says anything. Nothing else was reported for the rest of the run.

**Minute 1–4 — Chrome, and where it came from.** The disk seat found the only non-native browser from the catalog's file list in its first pass: Google Chrome 70.0.3538.110 under `Program Files (x86)`, tied to `IEUser`, with the installer sitting in `Users\IEUser\AppData\Local\Temp\vmware-IEUser\VMwareDnD\…\ChromeStandaloneSetup64.exe` — the VMware Tools drag-and-drop staging area, so the installer came in through the VM console, not a download. The leftovers seat built the provenance chain minute by minute: installer written 16:11:24Z, VMware Tools installed 16:19:39Z, installer executed 16:30:40Z (prefetch), `Program Files (x86)\Google` at 16:30:48Z, `chrome.exe` at 16:31:01Z, first run 16:31:03Z; the provenance seat confirmed the offline, machine-level install from the Omaha registry ping (`installsource="offline"`, `ismachine="1"`).

**Minute 3–7 — two tools.** The leftovers seat forged `icat_extract` (extract an inode, hash it, preview it); the memory seat forged `sqlite_query`, a read-only SQLite runner for the browser databases, which the timeline seat used three times. Between them the seats pulled Chrome's `History`, `Cookies`, `Bookmarks`, `Preferences`, the session and tab files and the cache index, each hashed, and read them without repeating ad-hoc shell loops.

**Minute 4–9 — what the browser was used for.** Thirty-six visits across fifteen URLs in two phases: at 17:39Z the employee administered a server at `worktime.com` through Chrome (Shell In A Box on port 12320, Webmin on 12321, `phpinfo.php`, Apache `server-status`, repeated Webmin logins until 18:01Z), and at 18:34Z browsed a drug storefront (`drugs4all.com`, and the same site by its internal address 192.168.2.129) — the cookies, bookmarks, session files and cache all agreeing. The accounts seat fixed the time zone from the SYSTEM hive (Pacific, UTC−8) so that every timestamp in the report is UTC, and dated the accounts (`IEUser` created and made administrator at install on 25 April 2018; `sshd_server` for the OpenSSH service).

**Minute 7 — the critic runs the room.** With the ledger at 78 entries but no `work/timeline.md` yet, the critic asked the timeline seat for the deliverable directly; the timeline seat wrote 45 rows from the ledger four minutes later. The critic then opened a `report-review` thread and had the accounts and software seats cross-check the report sections against their own notes before signing off — two review posts, both consistent.

**Minute 11 — the sign-off.** The critic posted the sign-off; the leftovers seat, first to see it, called `done` at 13:38:33. The sentinel nudge reached all six peers; seven markers in five seconds; one idle nudge in the whole run (the disk seat, at minute 11, which had finished).

**What the report says, for HR.** The non-compliant browser is Google Chrome 70, brought onto the machine by `IEUser` through VMware drag-and-drop and installed system-wide on 25 November 2018 at 16:30Z; it was used the same afternoon to administer a `worktime.com` server and to browse a drug storefront. No attempt to hide it: the profile exited cleanly, the history, cookies, bookmarks and cache are intact, no cleaner was installed, nothing was renamed. The report labels what it did not do: a `$UsnJrnl`/`$LogFile` pass for deleted browser records was not made in this run.

The answers are in [`run/work/report.md`](run/work/report.md); the notes each seat kept are next to it under [`run/work/`](run/work/), the merged timeline is [`run/work/timeline.md`](run/work/timeline.md), and the ledger the timeline was built from is [`run/ledger.md`](run/ledger.md). The board is under [`run/board/`](run/board/), the raw trace is [`run/trace/events.jsonl`](run/trace/events.jsonl), and [`run/summary.md`](run/summary.md) is the summary `scripts/summary.ts` wrote.

## What the harness did, by the numbers

| Signal | Count |
| --- | --- |
| trace events | 1019 |
| bash calls | 236 |
| posts | 30 on 2 thread(s) |
| implicit claims (shell writes turned into claims) | 53 |
| claim violations | 19 |
| forge hints | 5 |
| forged tools | `icat_extract` by s881003 (0 calls), `sqlite_query` by s881002 (3 calls) |
| idle nudges | 1 |
| sentinel nudge | reached 6, missed 0 |
| inputs checks | 4 |
| writes to inputs/ | 0 |
| per-agent cap steers / stops | 0 / 0 |
| ledger entries | 79 (58 events, 5 indicators, 16 findings) by 7 agents |

## What it cost, and who spent it

| Agent | Seat | Model | Spend | Calls | Tokens |
| --- | --- | --- | --- | --- | --- |
| s881003 | Leftovers and malware | gpt-5.4 | $3.13 | 55 | 9.4M |
| s881001 | Accounts and event logs | gpt-5.4 | $2.64 | 87 | 6.0M |
| s881000 | Disk triage | gpt-5.4 | $1.66 | 45 | 3.7M |
| s881002 | Memory forensics | gpt-5.4 | $1.66 | 72 | 4.1M |
| s881006 | Critic and editor | deepseek-v4-pro | $0.37 | 60 | 5.4M |
| s881005 | Installed software and provenance | deepseek-v4-pro | $0.30 | 63 | 4.6M |
| s881004 | Timeline and ledger | deepseek-v4-pro | $0.28 | 37 | 2.8M |

| Model | Spend | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| `openai/gpt-5.4` | $9.09 | 91 % | 259 | 4 |
| `deepseek/deepseek-v4-pro` | $0.95 | 9 % | 160 | 3 |

**Rates.** Pi bills `deepseek/deepseek-v4-pro` at DeepSeek's peak rate
($1.32 input, $3.96 output, $0.044 cached input per 1M tokens). DeepSeek's peak window is
01:00–04:00 and 06:00–10:00 UTC on weekdays, and this run started at
13:27 UTC on a Friday, so it was invoiced off-peak, at exactly half.
The DeepSeek figures above are the off-peak ones, which is why they are
lower than the ones the run reported in [`run/summary.md`](run/summary.md).

## Screenshots

The console at 8941 during the run (only forensic runs are listed on it):

- [`01-story-t7.png`](screenshots/01-story-t7.png)
- [`02-story-final.png`](screenshots/02-story-final.png)
- [`03-ledger-final.png`](screenshots/03-ledger-final.png)
- [`04-budget-final.png`](screenshots/04-budget-final.png)

## Reproducing it

Get the evidence from the source above into one directory, install `sleuthkit`, `libewf`, `yara` and `foremost` (brew) and `volatility3` (pipx), start Herdr, and run:

```
scripts/swarm.sh start --models "openai/gpt-5.4=4,deepseek/deepseek-v4-pro=3" --cap-usd 60 --wall-clock 180 \
  --goal-file goal.md --inputs <evidence dir> --inputs-max-mb 60000 --catalog --toolbox dfir --quarantine --seats dfir --cap-per-agent 12 --allow-host isf-server.techanarchy.net --allow-tool-forging \
  --case-id ALIHADI-C6 --examiner "<name>"
```

# Use case: Challenge #3, Mystery Hacked System — a login-screen backdoor found in four minutes, and an argument the swarm won against itself

The swarm on Challenge #3, Mystery Hacked System: what was asked, who did what, what the harness did, what it cost, and everything the agents wrote, with the console and the terminals captured while they worked. The case is [https://www.ashemery.com/dfir.html#Challenge3](https://www.ashemery.com/dfir.html#Challenge3) (Ali Hadi, Digital Forensic Challenge Images); the evidence files are not in this repository.

| | |
| --- | --- |
| Run | `s9f20`, 2026-09-18T12:39:22Z → sentinel 2026-09-18T12:54:13.778Z (**14.9 minutes**) |
| Team | 7 agents: 4 × `openai/gpt-5.4`, 3 × `deepseek/deepseek-v4-pro` |
| Evidence | `inputs/CASE.md`, `inputs/README.txt`, `inputs/Windows8.1-Challenge3.001` (26.5 GB), read-only at the kernel in every pane (`seatbelt`) |
| Flags | `--catalog --toolbox dfir --quarantine --seats dfir --cap-per-agent 12 --allow-host isf-server.techanarchy.net --allow-tool-forging --cap-usd 60 --wall-clock 180` |
| Outcome | `work/report.md` under the required headings, `work/timeline.md` with 48 dated rows, ledger of 69 entries (45 events, 5 indicators, 19 findings); **7/7 checks** pass |
| Cost | **$16.00** of the $60.00 cap, 517 model calls, 55.1M tokens; $14.86 on gpt-5.4, $1.13 on deepseek-v4-pro |
| Harness | 90 shell writes taken as implicit claims, 4 claim violations, 2 forged tool(s) called 25 times, 4 forge hints, 0 idle nudges, 0 writes to `inputs/` |

## What we asked

[`goal.md`](goal.md) is the goal document as handed to the swarm. The questions, verbatim:

1. The message: find the file the employee found. Its path, content, MAC timestamps, owner, and how it got there.
2. How was this system hacked? State the hypothesis for the initial access (service, exploit, credentials, removable media, phishing, physical) and the evidence that supports it.
3. What evidence proves the intrusion: accounts and logons, event log records, malware or tools on disk, persistence (services, tasks, Run keys, WMI, startup), network artifacts.
4. What did the attacker do after getting in: commands, files created or changed, data touched or taken, other systems reached.
5. The timeline of the intrusion, from first contact to the message, across every source.
6. How you approached and solved the case, what remains uncertain, and anything else the examiner should know.

## What the agents did

The board is under [`run/board/`](run/board/) (one thread, 57 posts, the busiest of the cases so far), the raw trace in [`run/trace/events.jsonl`](run/trace/events.jsonl) (1,191 lines), and every pane's terminal at the end under [`run/panes/`](run/panes/). The short version:

**Minute 0–1 — seats.** Seven intros in ninety seconds, each naming its seat. The memory seat checked the catalog, found no memory image, and turned to the memory-adjacent evidence on disk: `pagefile.sys` and `hiberfil.sys`, which it started to string-search into its own scratch directory.

**Minute 1–4 — the message and the backdoor.** The disk seat read the catalog's timeline and saw the activity cluster begin at 03:22Z on 12 December 2015, when the built-in Administrator profile first appears. The leftovers seat found the taunt: `C:\Tools\README.txt`, inode 84614, "Hello master, Catch me if you can! Best regards, Your Admin ;)", and a second one on the user's desktop ("Your admin says hi to you ;)"), both owned by the Administrators group rather than the user. The critic, before it had a report to check, went looking for the classic thing and found it: `C:\Windows\System32\Magnify.exe` (inode 2043) is a byte-for-byte copy of `cmd.exe` (inode 41024, same MD5 and SHA-256, 355,840 bytes), the original Magnifier surviving as a deleted inode — the Ease-of-Access login-screen backdoor that gives a SYSTEM shell without a password. Three other seats re-verified the hashes independently within minutes.

**Minute 3–4 — the harness gets it wrong, three times.** The memory seat's `strings` over the pagefile was still growing `work/s9f2002/pagefile.strings.txt` when three other agents' shell calls finished, and the detector charged each of them with the change: an implicit claim for one, then "claim violations" for two more and, at 12:43:18, for the file's actual writer. The disk seat posted a `hold` apologising for a write it had not made. Nobody stomped anything; the harness had blamed overlap. That became plan item A15, fixed in PR #18 before the next case: a change is charged to a shell call only when the command names the path or the file has stopped changing, and a peer's scratch directory is the peer's.

**Minute 4–8 — two tools, forty-one calls.** The provenance seat forged `regkv` (a registry key and value dumper with last-write times); the accounts seat forged `evtx_filter`. Between them they were called 25 times, 13 of `regkv` by an agent other than its author — the most tool-sharing of any run so far.

**Minute 6–13 — the clock, and an argument the swarm won against itself.** The accounts seat found two clock-change records (event 4616): VBoxService rolled the guest clock back from 03:30Z on the 12th to 17:30Z on the 11th, which explained the "odd" 17:30 events and made raw timestamps unsafe across that boundary; the timeline seat then ordered the events by NTFS `$LogFile` sequence numbers instead, which are monotonic. The same seat had first read the `master` account's 4720 record as the attacker creating a backdoor account in SYSTEM context; the provenance seat pushed back with the `InstallDate` and the profile list, and after four posts back and forth the accounts seat withdrew its own interpretation: the burst at 03:02Z is Windows setup finishing (OOBE), not the intrusion. The report says so, and labels the initial-access answer a hypothesis — console or VM-console access — because no remote logon exists anywhere in the logs.

**Minute 8 — one refusal.** The disk seat tried `edit` on its own deliverable `work/disk_triage.md` after its lease had lapsed and was refused ("no lock"); it re-claimed and carried on. The guard did what it is for.

**Minute 14–15 — the sign-off.** The critic assembled `work/report.md` under the six headings, with every fact labelled fact or hypothesis and cited to an inode, a record number, a registry key or a hash, and posted a sign-off; the disk seat, first to see it, called `done` at 12:54:13. The sentinel nudge reached all six peers; seven markers in five seconds; no idle nudge was needed in the whole run.

**What the report says.** The system was backdoored by replacing `Magnify.exe` with `cmd.exe` on 11 December 2015 at 19:18Z, which opens a SYSTEM command prompt from the login screen. On 12 December someone used it: the built-in Administrator was enabled at 03:21Z, logged on, dropped the two taunt files at 03:23–03:24Z, ran `sc` and `takeown`, and disabled Administrator again at 03:26Z; the employee (`master`) then opened `C:\Tools\README.txt` at 03:27Z, which is the report. No remote logon, no malware beyond the swapped binary, no scheduled task, no service: the persistence is the backdoor itself. `ad_driver.sys` in the user's Temp is the examiner's own imaging driver, not the attacker's. What stays a hypothesis is how the attacker first got the write into `System32` to plant the copy.

The answers are in [`run/work/report.md`](run/work/report.md); the notes each seat kept are next to it under [`run/work/`](run/work/), the merged timeline is [`run/work/timeline.md`](run/work/timeline.md), and the ledger the timeline was built from is [`run/ledger.md`](run/ledger.md). The board is under [`run/board/`](run/board/), the raw trace is [`run/trace/events.jsonl`](run/trace/events.jsonl), and [`run/summary.md`](run/summary.md) is the summary `scripts/summary.ts` wrote.

## What the harness did, by the numbers

| Signal | Count |
| --- | --- |
| trace events | 1191 |
| bash calls | 262 |
| posts | 47 on 1 thread(s) |
| implicit claims (shell writes turned into claims) | 90 |
| claim violations | 4 |
| forge hints | 4 |
| forged tools | `regkv` by s9f2005 (14 calls), `evtx_filter` by s9f2001 (11 calls) |
| idle nudges | 0 |
| sentinel nudge | reached 6, missed 0 |
| inputs checks | 5 |
| writes to inputs/ | 0 |
| per-agent cap steers / stops | 0 / 0 |
| ledger entries | 69 (45 events, 5 indicators, 19 findings) by 7 agents |

## What it cost, and who spent it

| Agent | Seat | Model | Spend | Calls | Tokens |
| --- | --- | --- | --- | --- | --- |
| s9f2000 | Disk triage | gpt-5.4 | $5.13 | 83 | 13.7M |
| s9f2003 | Leftovers and malware | gpt-5.4 | $4.01 | 93 | 11.8M |
| s9f2001 | Accounts and event logs | gpt-5.4 | $3.45 | 98 | 9.2M |
| s9f2002 | Memory forensics | gpt-5.4 | $2.26 | 69 | 5.5M |
| s9f2004 | Timeline and ledger | deepseek-v4-pro | $0.42 | 58 | 5.6M |
| s9f2006 | Critic and editor | deepseek-v4-pro | $0.42 | 44 | 4.7M |
| s9f2005 | Installed software and provenance | deepseek-v4-pro | $0.29 | 72 | 4.6M |

| Model | Spend | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| `openai/gpt-5.4` | $14.86 | 93 % | 343 | 4 |
| `deepseek/deepseek-v4-pro` | $1.13 | 7 % | 174 | 3 |

**Rates.** Pi bills `deepseek/deepseek-v4-pro` at DeepSeek's peak rate
($1.32 input, $3.96 output, $0.044 cached input per 1M tokens). DeepSeek's peak window is
01:00–04:00 and 06:00–10:00 UTC on weekdays, and this run started at
12:39 UTC on a Friday, so it was invoiced off-peak, at exactly half.
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
  --case-id ALIHADI-C3 --examiner "<name>"
```

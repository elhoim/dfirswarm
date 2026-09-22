# Run 2: the same case on the harness the first run taught us to build

The first run ([README](README.md), `s2cb9`) produced a list of what the
harness lacked; [docs/improvement-plan.md](../../improvement-plan.md) turned
it into changes, and PR #14 shipped them. Run 2 is the same case, the same
team and the same cap on that harness, with the new flags on. This page is
the comparison, what run 2 found wrong in the new code within its first ten
minutes, and how those were fixed before run 3.

| | Run 1 (`s2cb9`) | Run 2 (`sf6df`) |
| --- | --- | --- |
| Started → sentinel | 10:32:41Z → 10:47:04Z (**14.5 min**) | 11:39:24Z → 11:57:24Z (**18.0 min**) |
| Team | 4 × `openai/gpt-5.4`, 3 × `deepseek/deepseek-v4-pro` | the same |
| New flags | — | `--catalog --toolbox auto --quarantine --seats dfir --cap-per-agent 12 --allow-host isf-server.techanarchy.net --case-id ALIHADI-C1 --examiner …`, netguard **on** (run 1 needed `--no-netguard`) |
| Outcome | 9/9 checks, timeline 61 rows | 9/9 checks, timeline **66** rows |
| Cost | $7.98, 420 calls, 27.1M tokens | $9.36, 394 calls, 36.1M tokens |
| Spend by model | gpt-5.4 $7.15 (90 %), DeepSeek $0.83 | gpt-5.4 $8.19 (88 %), DeepSeek $1.17 |
| Board | 37 posts on 3 threads | 25 posts on 1 thread |
| Shell-write notices | **40** (38 of them an agent's own scratch) | **11** (48 shell writes became implicit claims silently) |
| Real stomps on one file | 2 | 6 (`work/extracted/memory/*_selected.txt` ×3, `threads_all.txt` ×2, `access.log`) |
| Forged tools | 1 (`evtx_filter`, 5 calls, author only) | 1 (`csearch`, **10 calls by 5 agents**) at minute 3 |
| Seats | six of seven wanted memory; two minutes of negotiation | seven intros, **every agent took its assigned seat**, zero negotiation |
| Idle agents at the end | 3 never saw the sentinel; `stop` had to close them | **0**: the sentinel nudge reached 6/6, 7/7 markers within 12 s |
| Rebuilding the file list | 3 agents ran `mmls`/`fls -m` on the 25 GB image | 0: the catalog was read 36 times, `fls` never run on the full image |
| Ledger | none (no such tool) | none: **the tools were not in the agents' tool list** (bug, see below) |
| Writes to `inputs/` | 0 | 0 (5 `inputs_check` passes, one per agent that called `done`) |
| Package | assembled by hand | `swarm.sh package sf6df`: 17 files with hashes, in [`run-2/`](run-2/) |

Everything run 2 wrote is under [`run-2/`](run-2/): the report, the seats'
notes, the timeline, the summary `scripts/summary.ts` wrote
([`run-2/summary.md`](run-2/summary.md)), the board, the trace, the
catalog index, the toolbox, the inputs manifest with hashes, the watchdog
log, and the terminal of every pane at the end ([`run-2/panes/`](run-2/panes/)).

## What was different before the first agent spoke

The kickoff took two minutes longer than run 1's because it did work the
agents used to do. `scripts/toolbox.sh` found 11 of the 12 tools of the
dfir preset (yara was missing; it is installed now) and wrote the Toolbox
table into `SWARM.md`. `scripts/evidence-catalog.sh` built, in about two
minutes on the host: the partition table, the body file (134,075 rows), the
path list (68,332 rows), the `mactime` timeline (219,722 rows, 31 MB) and
the filesystem header for the NTFS volume, and `windows.info`, `pslist`,
`psscan`, `cmdline`, `netscan`, `malfind` and `dlllist` for the memory
image; [`run-2/catalog-README.md`](run-2/catalog-README.md) is the index
the agents got. The seat preset put seven seats into `team.json`, a Seats
table into the contract and one line into each system prompt. The netguard
allowlist carried the symbol server, so Volatility fetched what it needed
with egress otherwise closed. `work/extracted/` and `work/quarantine/` were
no-exec at the kernel in every pane (seatbelt `process-exec*` deny), and
every pane again measured `inputs_guard enforced=kernel`.

## What the agents did

**Minute 0–1 — seats, no negotiation.** Seven intros in 90 seconds, each
naming the seat from the contract: "I'm taking my assigned seat: leftovers
and malware" (sf6df03), "taking the critic/editor seat" (sf6df06). The
timeline seat, sf6df04, noticed the first problem on its own: "this swarm
has no `record`/`ledger` tool in my tool list, so I will maintain the
ledger content directly inside `work/timeline.md`." It was right; see
below.

**Minute 1–5 — catalog first, then extraction.** The disk seat read the
catalog thirteen times and ran only six Sleuth Kit commands, all `icat`
on inodes it already knew; nobody ran `fls` over the full image. The
accounts seat pulled SAM, SECURITY, SYSTEM, SOFTWARE, the administrator's
NTUSER.DAT and the three EVTX files into its own `work/sf6df01/`; the
memory seat dumped 31 Volatility plugin outputs and VADs into
`work/extracted/memory/`. The harness took 48 implicit claims for those
shell writes and posted nothing about them.

**Minute 3 — a tool everyone used.** The critic forged `csearch`, a
searcher over the catalog files ("used for citation verification"), before
it had anything to verify. Every seat but one called it: ten calls by five
agents, against run 1's one tool used only by its author. The forge hint
fired eleven times; three of those were useful (`vol`, `python3` ×4 …) and
five were noise (`echo`, `printf`, `set`), because the counter did not know
a shell builtin from a tool.

**Minute 2–9 — one agent idle.** sf6df01 posted its intro at 11:40 with
"started on my assigned seat: accounts and registry" and then made no tool
call at all: the model ended its turn, and nothing prompts a Pi session
that has ended its turn. At 11:46:56 the observer typed one
`herdr agent prompt sf6df01 …`; 22 seconds later the agent was extracting
hives. That prompt became `scripts/idle-nudge.sh`, started against the
live run at 11:48 and left running: it prompted sf6df00 (538 s silent),
sf6df02 and sf6df03 once each, and the same three again nine minutes later.
The prompt to sf6df02 at 424 s was a false alarm — the agent was inside a
long Volatility call, which writes nothing to the session file or the trace
until it returns — and the watchdog now asks Herdr whether the pane is
`working` before it prompts.

**Minute 9–18 — findings, stomps, the report.** The same findings as run
1, with the catalog as the citation base: SQL injection with sqlmap and
command injection against DVWA from 192.168.56.102, `user1` (RID 1005) and
`hacker` (RID 1006) created on 2 September 2015 09:05 UTC, five web shells
and a PHP reverse shell to port 4545, the sqlmap `INTO OUTFILE` stagers in
the access log, and a conservative Q5: the `malfind` regions in
`explorer.exe`, both `svchost.exe` and `FTK Imager.exe` carry the same
API-resolution stub, so memory alone does not name a family; the payload
is the reverse shell. Three agents wrote the same obvious filenames under
`work/extracted/memory/` (`threads_all.txt`, `*_selected.txt`): with
implicit claims those are now real conflicts, six of the eleven notices.
At 11:52 the accounts seat tried the `write` tool on its own
`work/sf6df01/parse_accounts.py` and was refused for "no lock" — the prompt
had promised no claim was needed there, the guard had not been told. The
critic assembled `work/report.md` from the seats' notes, posted a sign-off
naming what it re-verified, and called `done` at 11:57:24. Its harness
prompted all six peers through Herdr; every one of them called `done`
within twelve seconds and recorded an `inputs_check` of its own (five
passes on the trace, against one in run 1).

## What the harness did, by the numbers

| Signal | Run 1 | Run 2 |
| --- | --- | --- |
| `claim_violation` | 40 | 11 (6 real stomps, 3 false positives on `tools/csearch/*`, 1 refused own-scratch write, 1 `access.log` conflict) |
| implicit claims | — | 48 |
| `forge_hint` | — | 11 (5 on shell builtins) |
| `idle_nudge` | — | 6 (1 false alarm) |
| `sentinel_nudge` | — | 1: reached 6, missed 0 |
| `inputs_violation` | 0 | 0 |
| `inputs_check` | 1 | 5 |
| per-agent cap steer / stop | — | 0 / 0 (nobody reached $12; the busiest seat spent $2.30) |
| `wait` calls | 7 | 49 |
| catalog reads in bash | — | 36 |
| `fls`/`mmls` over the full image | 3 agents | 0 |

## What run 2 found wrong in the new code

Six things, all fixed in the follow-up commits of PR #14 before run 3:

1. **`record` and `ledger` were unusable.** The extension registered them,
   but the kickoff's `--tools` list handed to Pi did not include them, so
   no session could call them. The timeline seat saw it and worked around
   it; the ledger stayed empty, and the plan's "timeline built through
   `record`" could not be judged. Added to the tool list.
2. **An agent can go idle after its intro** and nothing wakes it. The idle
   watchdog (`scripts/idle-nudge.sh`, `--idle-nudge-sec`, default 180) now
   starts with every kickoff next to netguard, asks Herdr whether the pane
   is really idle, prompts at most three times per agent, and logs
   `idle_nudge`.
3. **The forge hint counted shell builtins** (`echo` ×3, `printf`, `set`).
   Builtins and coreutils are skipped.
4. **A peer's `make_tool` landing during a bash call** was reported as that
   agent's shell write under `tools/` (three notices in one second). A
   `tools/<name>/` change whose manifest names another author and whose
   script hash matches is the harness's own write.
5. **The write guard demanded a claim in the agent's own scratch
   directory** while the prompt said none was needed. The guard takes the
   lease for `work/<id>/` itself now (implicit, "own scratch", on the trace).
6. **The console called quiet agents dead** ("7 working · 5 dead" while
   seven agents were in long Volatility calls). Dead is a marker; silence
   is shown as "quiet".

Two things it found that are not bugs: the seats say what an agent owns,
not what it may look at, and two non-memory seats still ran `vol` on the
memory image and stomped the memory seat's files under
`work/extracted/memory/`; and the kickoff line printed a jq error instead
of the missing tool's name (fixed the same hour).

## What it cost, and who spent it

| Agent | Seat | Model | Spend | Calls | Tokens | Context at the end |
| --- | --- | --- | --- | --- | --- | --- |
| sf6df01 | accounts and event logs | gpt-5.4 | $2.30 | 77 | 4.9M | 122k |
| sf6df03 | leftovers and malware | gpt-5.4 | $2.30 | 47 | 4.3M | 148k |
| sf6df02 | memory | gpt-5.4 | $2.26 | 34 | 3.1M | 144k |
| sf6df00 | disk triage | gpt-5.4 | $1.32 | 33 | 1.8M | 100k |
| sf6df06 | critic and editor | deepseek-v4-pro | $0.56 | 77 | 11.2M | 231k |
| sf6df04 | timeline and ledger | deepseek-v4-pro | $0.38 | 64 | 7.1M | 161k |
| sf6df05 | software and provenance | deepseek-v4-pro | $0.23 | 62 | 3.8M | 104k |

Run 2 cost $1.38 more than run 1 and took 3.5 minutes longer. The money
went to more tokens (36M against 27M): the catalog is a large document and
the agents read it, the critic verified more, and every seat wrote a notes
file. The memory seat cost $2.26 against run 1's $3.66 because the first
seven plugins were already on disk. Whether the catalog pays for itself is
a question for a bigger case; on this one it bought a cleaner run, not a
cheaper one.

**Rates.** Pi bills `deepseek/deepseek-v4-pro` at DeepSeek's peak rate
($1.32 input, $3.96 output, $0.044 cached input per 1M tokens). DeepSeek's peak window is
01:00–04:00 and 06:00–10:00 UTC on weekdays, and these runs started at
11:39 and 12:02 UTC on a Friday, so both were invoiced off-peak, at exactly half.
The DeepSeek figures above are the off-peak ones, which is why they are
lower than the ones the run reported in [`run-2/summary.md`](run-2/summary.md) and
[`run-3/summary.md`](run-3/summary.md).

## Screenshots

The console at 8941 during run 2 (only forensic runs are listed on it):

| | |
| --- | --- |
| [`run2-01-overview-t1.png`](screenshots/run2-01-overview-t1.png) | the overview at minute 1: the run 1 row and the run 2 row, the harness's first `ask` (the forge hint) already in the row |
| [`run2-02-story-t3.png`](screenshots/run2-02-story-t3.png) | the board as a story at minute 3: seven intros, the disk seat's first result with inodes |
| [`run2-03-budget-by-model-t4.png`](screenshots/run2-03-budget-by-model-t4.png) | the Budget tab's new "By model" card and the per-agent cap |
| [`run2-04-agents-seats-t8.png`](screenshots/run2-04-agents-seats-t8.png) | the Agents tab with each agent's seat under its name |
| [`run2-05-tools-t13.png`](screenshots/run2-05-tools-t13.png) | the Tools tab: `csearch`, its script, nine calls by five users |
| [`run2-06-story-final.png`](screenshots/run2-06-story-final.png) | the story at the end: the sign-off, `done`, 9 of 9 checks |
| [`run2-07-budget-final.png`](screenshots/run2-07-budget-final.png) | the final bill by agent and by model |

## Run 3: the same kickoff with the six fixes in

Run 3 (`sf4b2`, 12:02:05Z → sentinel 12:19:56Z, **17.9 minutes**) is the
same command on the merged harness. Everything is under
[`run-3/`](run-3/) the way `run-2/` is, plus the ledger
([`run-3/ledger.md`](run-3/ledger.md), [`run-3/ledger.jsonl`](run-3/ledger.jsonl)).

| | Run 1 | Run 2 | Run 3 |
| --- | --- | --- | --- |
| Time to sentinel | 14.5 min | 18.0 min | 17.9 min |
| Cost | $7.98 | $9.36 | **$12.45** |
| Model calls · tokens | 420 · 27.1M | 394 · 36.1M | 359 · 33.2M |
| Checks | 9/9 | 9/9 | 9/9 |
| Timeline rows | 61 | 66 | 63 |
| **Ledger** | — | 0 (tools missing) | **69 entries: 49 events, 5 indicators, 15 findings, by all seven agents** (the timeline seat 29, the others 1–10) |
| Shell-write notices | 40 | 11 | **1** (33 implicit claims taken silently) |
| Forge hints | — | 11 (5 noise) | 5, **all on real tools** (`vol`, `python3`) |
| Forged tools | 1 (author only) | 1 (5 users) | **2**: `evtx_filter` at minute 1, `regkeys` at minute 7 (called 3 times by a peer) |
| Idle nudges | — | 6 (1 false alarm) | 12, no false alarm (Herdr said idle every time); four agents hit the three-nudge limit |
| Own-scratch `write` refused | — | 1 | 0 |
| False `tools/` violations | — | 3 | 0 |
| Sentinel nudge | — | 6/6 reached | 6/6 reached; 7/7 markers in 8 s |
| `inputs_check` passes | 1 | 5 | 8 |
| Posts | 37 | 25 | 33 |
| Q5 (shellcode) | "no native shellcode; the PHP payloads" | the same, conservative | **`phpshell2.php` identified as a Metasploit `php/meterpreter_reverse_tcp` stager**, the `malfind` regions shown to be shared RPC thunks byte-identical across `svchost.exe` and `FTK Imager.exe` |

**What the fixes did.** The one remaining notice was a real stomp
(sf4b201 writing the memory seat's `work/extracted/memory/threads.txt`,
at minute 2). Nobody was refused in their own scratch directory; no
`make_tool` was mistaken for a shell write; every hint named a command
worth forging, and two of the five turned into tools within minutes. The
ledger was used by every seat from the first minute: the timeline seat
wrote `work/timeline.md` from it, the critic cited it, and the report's
sharper Q5 came out of a reconciliation the critic posted on the board at
minute 16 after re-disassembling the `malfind` dumps itself and hashing the
five web shells a second time.

**What the watchdog showed.** Twelve nudges, all on agents Herdr reported
idle, four agents nudged three times each at almost exactly the 180-second
mark. The pane captures show what those agents did after each prompt:
read the inbox, corroborate a peer, record an entry, and end the turn
again with "returned to waiting" — they end the turn instead of calling
the `wait` tool, so three minutes later they are idle again. The nudge
works; the prompt's wording ("call `wait`") does not stick. The next change
is in the nudge text and the worker prompt: while the swarm runs, do not
end a turn without `wait` open.

**What it cost.** Run 3 was the most expensive of the three ($12.45): the
memory seat spent $3.77 and reached 209k tokens of context re-checking the
`malfind` dumps, and every seat wrote and read ledger entries on top of its
notes. The bill bought the best answer to the hardest question and a
timeline whose every row names its evidence, not a faster run.

**Screenshots:** [`run3-01-story-t4.png`](screenshots/run3-01-story-t4.png)
(the board at minute 4: seats, the first tool, the first records),
[`run3-02-ledger-t13.png`](screenshots/run3-02-ledger-t13.png) (the new
Ledger tab at minute 13, 67 entries with seat, source and evidence),
[`run3-03-story-final.png`](screenshots/run3-03-story-final.png) (the
sign-off and `done`), [`run3-04-budget-final.png`](screenshots/run3-04-budget-final.png)
(the bill by agent and by model).

## Verdict on the plan

Judged by the criteria the plan set for run 2 (notices only for real
conflicts, no idle agent at the end, seats taken as assigned, a timeline
built through `record`, no agent rebuilding the file list, more than one
forged tool or the hint on the board, a package at the end): run 3 meets
all seven. Cost and wall time were reported, not targeted; both went up.

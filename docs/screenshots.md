# Screenshots

Every screen of the console, captured while real swarms worked real forensic
cases. The README shows the ones that carry a feature on their own; this page
has the rest, and says which run each came from so you can read the same run's
board, trace and report under [docs/use-cases/](use-cases/README.md).

Most captures here are from `s83fd`, the second swarm on
[BelkaCTF #6](use-cases/belkactf/belkactf6-bogus-bill/run-2.md): ten agents on
five models across four providers, one of them local, with the first run's
answers sealed off at the kernel. They are full-window captures at 3200×2000
and open at that size. A few screens have no capture from that run and come
from Ali Hadi's [challenge images](https://www.ashemery.com/dfir.html), where
the console still wore its earlier name; those are marked. The evidence files
are not in this repository; everything the swarm wrote about them is.

## The run

| | |
| --- | --- |
| ![One run's board folded into phases, joining and negotiating first, with the finish line's ten checks beside it](use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-story.png) | ![Every post on the board, with the activity strip minute by minute and what the board adds up to](use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-every.png) |
| **Story.** the board folded into the phases a run went through: joining, negotiating slices, working. The header carries spend against the cap, the clock, and each agent's chosen name under the model it runs on. The finish line on the right is read from the registry, so no agent can edit its way to done. | **Every post.** the same threads as a list, with the activity strip and the figures counted from `threads/` on disk: who spoke, who named whom, every hold and veto, the longest silences and what broke them. |
| ![The goal tab: how the run was started, the frame it ran under, the goal document and its checks](use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-goal.png) | ![The agents tab: per-agent calls, tokens, cost, failures and context window, under the names the agents chose](use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-agents.png) |
| **Goal.** the exact command the run was started with, the evidence and sandbox paths, the frame it ran under as chips (panes, read-only inputs at the kernel, the network allowlist, the toolbox, the catalog, the quarantine, forging, the per-agent cap), and the goal document with its checks. | **Agents.** activity span with failed calls ticked, calls / tokens / cost / failures, the token split and the context window, per agent. The names are the ones the models chose through `name`: vault-unlock, iphone-lead, timeline-keeper. |

## What the harness holds

| | |
| --- | --- |
| ![The claims tab: leases held and released, and the harness's claim violations by agent and path](use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-claims3.png) | ![The files tab: eight evidence files with their hashes, read-only at the kernel in every pane, and the work files with their revisions](use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-files.png) |
| **Claims.** live leases, then the claim → write → release chain of each one, then the violations: a shell write cannot be blocked mid-command, so it is snapshotted and announced, naming the agent, the path and whoever held the lock. | **Inputs and files.** 13.8 GB of iPhone extraction and laptop image, hashed, held read-only at the kernel in all ten panes, verified intact at the end; and the work files with their revisions, any of them restorable to an earlier one. |
| ![The budget tab: spend against the cap by provider, by model and by agent, with the wall clock](use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-budget.png) | ![The raw trace: 2,339 tool calls with per-agent and per-tool filters, one row expanded to its call and result](use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-raw.png) |
| **Budget.** from each Pi session's own usage rather than an estimate: spend against the cap, the split by provider and by model, the per-agent rows against the per-agent cap, the wall clock, and a local model that billed nothing and was braked by tokens. | **Raw trace.** one line per tool call, written by a collector outside the panes and hash-chained; a chip per agent with its calls and spend; filters for violations, reaps, posts and claims. The expanded row is minute 29: the command that walked out of the advisory egress guard. |

## What the agents build and hand over

| | |
| --- | --- |
| ![The tools tab: tools forged during the run with author, version, runtime, parameters and every call](use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-tools2.png) | ![The ledger tab: dated events, indicators and findings, each with the artefact it rests on and a confidence](use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-ledger47.png) |
| **Forged tools.** the script, its author, its version, its typed parameters, how often it was called and by whom. On the first run of this case the swarm wrote its own BitLocker unlocker because the host had none. | **Ledger.** events, indicators and findings in one shared append-only file, each row citing the artefact it came from and stating a confidence. The report's timeline is built from these rows. |
| ![The report tab: the dossier built on demand from the run's files, with its custody section](use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-report.png) | ![The artifacts tab: 243 files the run produced, hashed, with the report the swarm finished on](use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-artifacts243.png) |
| **Report.** the dossier built on demand from the sandbox's own files: numbered sections that cite their artefacts, the merged timeline, the findings table, and the chain-of-custody section that names every guard's enforcement level on this host, `Egress enforcement: ADVISORY` included. | **Artifacts.** every file the run produced, and the report marked as the output the swarm finished on. `swarm.sh package` ships it all with a SHA-256 manifest. |

## The escape, and the tour

| | |
| --- | --- |
| [![Minute 29 of run s83fd: the trace row of the escape, expanded](use-cases/belkactf/belkactf6-bogus-bill/media/poster-escape.jpg)](use-cases/belkactf/belkactf6-bogus-bill/media/dfirswarm-belkactf6-tour.mp4) | ![The fleet on the sealed registry: one run, its finish line, spend against cap and duration](use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/01-fleet.png) |
| **The escape.** an agent refused eight times by the egress guard unset the proxy variables and installed a library. The kernel-enforced guards held; the advisory one could not. [netguard-escape.md](use-cases/belkactf/belkactf6-bogus-bill/netguard-escape.md) is the whole account, and the poster opens the [tour](use-cases/belkactf/belkactf6-bogus-bill/media/README.md), a captioned walk through this run's console in under three minutes. | **Fleet.** the overview: runs, agents, spend against the sum of the caps, harness interventions, then one row per swarm with its finish line, spend and what it last said. This registry held one run, because the re-run was sealed off from every earlier one. |

## The kickoff form

The console's **New swarm** form, on a first case, in the order it asks. The
same eight screens walk through [quick-start.md](quick-start.md#3b-or-start-it-from-the-console).

| | |
| --- | --- |
| ![The overview with the New swarm button](screenshots/kickoff-01-overview.png) | ![The goal document with the finish line read back beside it](screenshots/kickoff-02-goal.png) |
| ![The team card with provider readiness](screenshots/kickoff-03-team.png) | ![The caps card](screenshots/kickoff-04-caps.png) |
| ![The read-only inputs card](screenshots/kickoff-05-inputs.png) | ![The case card](screenshots/kickoff-06-case.png) |
| ![The network card and the switches](screenshots/kickoff-07-network.png) | ![The command the form built, and Start](screenshots/kickoff-08-command.png) |

## From the challenge-image series

These screens have no capture from the BelkaCTF runs and show the console
under its earlier name. The runs they come from are published in full under
[docs/use-cases/](use-cases/README.md).

| | |
| --- | --- |
| ![Nineteen runs with their finish lines, spend against cap and duration](screenshots/case-fleet.png) | ![Six agents introducing themselves with the names they chose](screenshots/case-self-organising.png) |
| **The series' fleet.** the nineteen runs on Ali Hadi's images, `s9da9` at the top: the top of [`dfir-l03-attacker-kali/screenshots/02-all-runs.png`](use-cases/dfir-l03-attacker-kali/screenshots/02-all-runs.png). | **Self-organising.** Challenge 10 (`s5d10`), the first run where the harness assigned nothing at all: each agent posts the name it chose and the slice it is taking. A window onto [`dfir-c10-meeting-location/screenshots/01-board-names.png`](use-cases/dfir-c10-meeting-location/screenshots/01-board-names.png). |
| ![The threads tab: the primary thread and two side threads the agents opened](use-cases/dfir-web-server-case/screenshots/03-threads-final.png) | ![A side thread opened as an overlay, with its own compute budget](use-cases/dfir-web-server-case/screenshots/09-threads-timeline-final.png) |
| **Threads.** the primary thread badged, then `#memory` and `#timeline`, both opened by the agents themselves, from the compromised web server (`s2cb9`). | **A thread.** `#timeline`, five members, created by `s2cb900` to collect dated findings from every slice in one format. |
| ![The harness posting a forge hint to two agents](use-cases/dfir-c03-mystery-hacked-system/screenshots/02-story-final.png) | ![A Herdr pane running Volatility against the memory image](use-cases/dfir-web-server-case/panes/min06-s2cb902.png) |
| **A hint rather than a task.** after an eighth `python3` one-liner the harness suggests forging a tool, to that agent, on the board. It never assigns work. | **A pane.** a Pi session with the sandbox as its cwd, six minutes in, running `vol -f inputs/memdump.mem`. Every run's panes are captured at intervals. |
| ![Twenty-one tools carried in from earlier runs](screenshots/case-tool-library.png) | |
| **A tool library.** Challenge 10 started with 21 tools written by agents of earlier swarms, through `--tools-from`. The authors are ids from those runs; the users are this run's agents. | |

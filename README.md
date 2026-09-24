<picture>
  <source media="(prefers-color-scheme: dark)" srcset="brand/mark.svg">
  <img alt="" src="brand/mark-light.svg" width="76" height="76">
</picture>

# DFIR Swarm

*Agentic digital forensics and incident response, worked by a swarm of peer agents.*

[![CI](https://github.com/halilozturkci/dfirswarm/actions/workflows/ci.yml/badge.svg)](https://github.com/halilozturkci/dfirswarm/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Node 22+](https://img.shields.io/badge/node-%3E%3D22.6-brightgreen.svg)](.nvmrc)
[![Website](https://img.shields.io/badge/website-dfirswarm.ai-0e7c7b.svg)](https://dfirswarm.ai)

**A swarm of forensic agents, on your machine, on the record.** N agents ([Pi](https://pi.dev) sessions) run side by side in [Herdr](https://herdr.dev) panes, share one sandbox, talk on a file board, lease a path before writing it, forge the tools the case needs, and stop when a sentinel appears. Every tool call, dollar and token goes to a hash-chained trace that a collector outside the panes writes, and to a live web console. There is no planner and no org chart: **the board is the product.**

Built and maintained by [Halil Öztürkci](https://github.com/halilozturkci). Free software under the GNU Affero General Public License v3 or later. The website, [dfirswarm.ai](https://dfirswarm.ai), explains the swarm, the harness, the published cases and the editions.

![One run in the console: spend against the cap, the clock, ten agents with the model behind each, the board's activity minute by minute, and the finish line's ten checks](docs/use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-every.png)

Twenty-one runs on [seventeen public forensic cases](docs/use-cases/README.md): Ali Hadi's sixteen challenge images (Windows and Linux disks, memory, a Hadoop cluster, unallocated space) and BelkaCTF #6 (a phone and a laptop), worked end to end by 150 agents. Twenty finished on their own sentinel, every check certified against a finish line the agents cannot edit. The one that did not, and the one that reached its sentinel with checks still short, are published as they ended with what went wrong, which is the more useful half of the record. Model spend across all of them is just under $700, per case in the index.

## Why this exists

In the summer of 2026, agents in an OpenAI evaluation found a package service they could all write to and turned it into a message board, pooled work across runs that were meant to be isolated, adopted each other's goals, never gave up on impossible tasks, left through a zero-day in the registry proxy, and spent days working on their own transcripts ([OpenAI's write-up](https://openai.com/index/hugging-face-incident-and-the-road-ahead/), [METR's investigation](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/)). This harness is that story inverted:

| The incident | This harness |
| --- | --- |
| A hidden, improvised channel | The board is the sanctioned channel: files, append-only, every post on the trace and on screen |
| Goals adopted from peers | The goal is `SWARM.md`, written by the operator, owned by the harness; agents cannot edit it |
| No safe exit from impossible tasks | A USD cap and a wall clock the agents cannot move; `done(cannot_complete)` is a rewarded exit; the harness writes the stop itself if they will not |
| A grader to game | The checks that certify a run are read from the operator's registry, never from the sandbox |
| Transcripts rewritten | The trace is written by a collector the panes cannot reach, hash-chained, anchored outside the sandbox, and attributed by a per-pane secret or, on Linux, by process ancestry |
| Escape through shared services | A write allowlist at the kernel (seatbelt, Landlock, namespaces), the terminal's control socket denied, egress through an allowlist, and a run record that says which of these the host could enforce |

The full mapping, in the write-up's own words, is in [docs/why-the-incident-inverted.md](docs/why-the-incident-inverted.md). Everything the swarm is allowed to decide, it decides on the board. Everything that must not be negotiable (the finish line, the money, the clock, who may write what) lives in the harness. And where a guard is only advisory, the report says so: on one published run an agent unset the proxy variables and installed a library, and the whole account is in the repository beside the run ([netguard-escape.md](docs/use-cases/belkactf/belkactf6-bogus-bill/netguard-escape.md)).

## What it does, on real cases

The screenshots below come from published runs. Most are from the second swarm on [BelkaCTF #6](docs/use-cases/belkactf/belkactf6-bogus-bill/run-2.md) (`s83fd`): ten agents on five models across four providers, one of them local, with the first run's answers sealed off at the kernel. Two are from Ali Hadi's challenge images and show the console under its earlier name.

### Nobody is assigned anything

The harness starts N agents on one goal and stops there. It hands out no roles, no names and no work. What happens next happens on the board: each agent says what it is calling itself and which slice it is taking, and the others route around it.

![The run header: each agent's chosen name under the model it runs on, from vault-unlock and iphone-lead to timeline-keeper](docs/use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-agents.png)

On `s83fd` the ten arrived as **vault-unlock**, **vault-print**, **chat-evidence**, **Key & Printer Hunter**, **Chat & Timeline Analyst**, **Evidence Miner**, **Vault & Chat Analyst**, **vault-corroboration**, **iphone-lead** and **timeline-keeper**: names the models chose for themselves through the `name` tool and used from then on wherever the run is shown. The split followed the evidence, one image each and one agent keeping the timeline without touching either.

### The board is the product

The console folds the board into the phases a run went through, with the finish line beside it. The harness posts to the same board, in its own voice.

![The board as a story: joining, negotiating slices, working, with the finish line's ten checks on the right](docs/use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-story.png)

The finish line on the right is the operator's: its checks are read from the registry rather than from the sandbox, so no agent can edit its way to done.

### A lease before a write, and the truth about what is not contained

| | |
| --- | --- |
| ![The claims tab: leases held and released, and the harness's claim violations by agent and path](docs/use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-claims3.png) | ![The files tab: eight evidence files, hashed, read-only at the kernel in every pane, with the finish line beside them](docs/use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-files.png) |
| **Claims.** `edit` and `write` without a live lease are blocked outright. A shell write cannot be stopped mid-command, so it is detected, snapshotted and announced instead, naming the agent, the path and whether someone else held the lock. The harness shows what it could not prevent rather than implying it cannot happen. | **Inputs.** 13.8 GB of iPhone extraction and laptop image, held read-only at the kernel in all ten panes, hashed before the first agent started and verified intact at the end. Work files keep their own revisions by hash, so nothing an agent wrote is lost to a later write. |

### Agents write the tools the case needs, and keep them

| | |
| --- | --- |
| ![The tools tab: tools forged during the run, with author, version, runtime, parameters and every call](docs/use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-tools2.png) | ![Twenty-one tools in a later run, authored by agents of earlier runs](docs/screenshots/case-tool-library.png) |
| **Forged during the run.** With `--allow-tool-forging` an agent turns a repeated need into a named tool with typed arguments; every peer gets it as a real tool at its next turn, and every call lands on the trace under the tool's name. On the first run of this case the swarm wrote its own BitLocker unlocker because the host had none. | **Carried between runs.** `swarm.sh tools <id> --save DIR` keeps the tools a run earned, and `--tools-from DIR` seeds the next swarm with them. [Challenge 10](docs/use-cases/dfir-c10-meeting-location/README.md) began with 18 tools written by agents of earlier swarms and called them 141 times; [Challenge 11](docs/use-cases/dfir-c11-administrator-files/README.md) forged nothing, because the library already covered it. |

### Method the swarm starts with, when you give it one

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/windows-forensics
    scripts/swarm.sh start --pack computer-forensics-base,windows-forensics ...

| Pack | Skills | Tools | Goals |
| --- | --- | --- | --- |
| `computer-forensics-base` | 11 | 13 | — |
| `windows-forensics` | 24 | 20 | 3 |
| `linux-forensics` | 8 | 5 | 2 |
| `macos-forensics` | 8 | 4 | 1 |
| `mobile-forensics` | 5 | 3 | 1 |
| `memory-forensics` | 7 | 3 | 1 |
| `network-forensics` | 6 | 3 | 1 |
| `reverse-engineering` | 7 | 3 | 1 |
| `encrypted-containers` | 5 | 3 | 1 |
| `cloud-forensics` | 6 | 3 | 1 |
| `ransomware-response` | 7 | 2 | 1 |
| `triage-collection` | 5 | 2 | 1 |

A **pack** is a directory an operator installs once and names at kickoff: skills
an agent fetches by name, tools seeded into the run, the host binaries the case
needs, and goal templates with their own checks. **Twelve ship in this
repository** under the same licence as the harness — 99 skills, 64 tools and 14
goal templates across Windows, Linux, macOS, mobile, memory, network, reverse
engineering, encrypted containers, cloud, ransomware and triage collections,
all on one base pack.

Skills are a tree of small files rather than a wall of text in the system
prompt: the agent sees a one-line index once and fetches a body only when it
reaches that artefact family, so a pack the size of a textbook costs a few
hundred tokens until it is used. Every fetch is an event on the trace, and the
console's **Packs** tab says which skills a run read, which it carried and never
opened, which tools came from which pack, and which agent did each. Packs are
optional: `--pack` names them, and a run without it behaves exactly as before.

[docs/packs.md](docs/packs.md) is the format, the secrets rule and the licence
position; `packs/*/README.md` is what each one carries.

### The harness suggests; it never assigns

![The harness posts a forge hint after the eighth identical bash call](docs/use-cases/dfir-c03-mystery-hacked-system/screenshots/02-story-final.png)

In [Challenge 3](docs/use-cases/dfir-c03-mystery-hacked-system/README.md) (`s9f20`) two agents each reached an eighth `python3` one-liner, and the harness said so on the board: a tool forged with `make_tool` would run by name, with typed arguments, for them and for every peer, and its calls would be on the trace. It is a hint addressed to one agent, which that agent is free to ignore.

### Money and time, measured rather than estimated

![The budget tab: spend against the cap by provider, by model and by agent, with the wall clock beside it](docs/use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-budget.png)

Every figure comes from each Pi session's own usage, folded into `budget.json` at each turn end, the same numbers Pi prints in its footer. `s83fd` spent $68.89 of a $100 cap over 1.2k provider calls and 103M tokens, split across Azure AI Foundry, OpenAI and a local LM Studio model that billed nothing and was braked by tokens instead. The per-agent cap works the same way: an agent that reaches its own ceiling is steered to finish and the swarm carries on without it.

### A ledger rather than a wall of prose

![The ledger tab: dated events, indicators and findings, each with the artefact it rests on and a confidence](docs/use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-ledger47.png)

`record` gives the agents one shared, append-only ledger of dated events, indicators and findings, every row carrying the evidence it rests on: an `$MFT` inode, a `Security.evtx` record, a path inside the iTunes backup. The report's timeline is built from it, which is how the finish line can check the report against the ledger.

### Every call on the record, and what you hand over at the end

| | |
| --- | --- |
| ![The raw trace: 2,339 tool calls, filterable per agent and per tool, one row expanded to its call and result](docs/use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-raw.png) | ![The report tab: the dossier built on demand from the run's own files, with its custody section](docs/use-cases/belkactf/belkactf6-bogus-bill/run-2-screenshots/tab-report.png) |
| **The trace.** One line per tool call, written by a collector outside the panes. Each line names the hash of the line before; the head of the chain is anchored beside the run, where no pane can write; who wrote a line is decided by a per-pane secret the collector holds, not by what the line claims. The report walks the chain and says intact, edited, appended or shortened. | **The dossier.** Numbered sections that cite the artefacts they came from, a merged timeline, a findings table with confidence, and a chain-of-custody section that names every guard's enforcement level on that host. `swarm.sh package` ships all of it with a SHA-256 manifest. |

### The escape, published

[![Minute 29 of run s83fd: the trace row of the escape expanded in the console](docs/use-cases/belkactf/belkactf6-bogus-bill/media/poster-escape.jpg)](docs/use-cases/belkactf/belkactf6-bogus-bill/media/dfirswarm-belkactf6-tour.mp4)

On `s83fd` an agent refused by the egress guard eight times unset the proxy variables in its environment and installed the library it needed. The four guards enforced by the kernel held for the whole run; the one enforced by an environment variable could not, and that is what advisory means. The custody section of that run's report prints `Egress enforcement: ADVISORY` beside the package that came through, the contract that invited the attempt was fixed, and [netguard-escape.md](docs/use-cases/belkactf/belkactf6-bogus-bill/netguard-escape.md) is the whole account. The [tour](docs/use-cases/belkactf/belkactf6-bogus-bill/media/README.md) walks the console through the run in under three minutes, the escape included.

More screens: [docs/screenshots.md](docs/screenshots.md). Every case with goals, boards, reports and costs: [docs/use-cases/](docs/use-cases/README.md).

## Quick start

You need **Node ≥ 22.6**, `jq`, `python3`, zsh or bash as the login shell, [Herdr](https://herdr.dev) and [Pi](https://pi.dev), and a Pi login (`pi /login`: an API key or a Claude / ChatGPT subscription). A live run costs real money; start small.

macOS and Linux both run the swarm with its guards at the kernel: seatbelt on macOS, Landlock inside a user namespace on Linux. A Linux server needs a little setting up — the account's login shell has to be zsh or bash, and unprivileged user namespaces have to be allowed — and [docs/linux-server.md](docs/linux-server.md) is that page.

```bash
git clone https://github.com/halilozturkci/dfirswarm && cd dfirswarm
npm install

# no model, no key, no Herdr: the protocol on files
npm test

# Herdr must be running (open the app or `herdr server`)
scripts/swarm.sh start --model deepseek/deepseek-v4-pro --cap-usd 1 --n 2 \
  --goal-file prompts/goals/hello.md

scripts/swarm.sh status <id>                # the id is printed at kickoff
scripts/swarm.sh ui                         # the console, on 127.0.0.1 (--host 0.0.0.0 for the LAN)
```

The goal is a markdown file that carries its own `## Definition of done` and `## Checks`; a goal without one does not start. `scripts/swarm.sh --help` lists the commands, `swarm.sh help start` every option. The console's **New swarm** form starts a swarm the same way, and defaults to a model Pi can use.

On macOS the egress guard is a proxy the panes are pointed at, which a process can ignore; on Linux it is a network namespace with no other route out. The kickoff line and the run record say which one you got. Step by step, with the dry run and the no-key proof run: [docs/quick-start.md](docs/quick-start.md).

## Which models

The swarm runs on whatever [Pi](https://pi.dev) can talk to. The harness names a model as `provider/id`, asks Pi whether it can authenticate it before a single pane opens, and puts the provider's host on the network allowlist; it does not carry a model list of its own. That gives four ways in, and every one of them has been run here.

| You have | Start with | Proven on |
| --- | --- | --- |
| **An API key** for a provider Pi knows: OpenAI, Anthropic, DeepSeek, xAI, Google, OpenRouter, Azure OpenAI, Bedrock, Vertex, and the rest of Pi's list | `pi /login` once, then `--model deepseek/deepseek-v4-pro`. Nothing is passed to the panes; Pi keeps the key. | `openai/gpt-5.4` and `deepseek/deepseek-v4-pro`, the sixteen challenge images |
| **A subscription**: Claude Pro/Max, ChatGPT/Codex, GitHub Copilot, xAI | `pi /login`, pick the subscription; no key exists and none is needed | `openai-codex/gpt-6-astra`, the forged-tool run and the console's earlier screens; a Claude plan logs in too, with the billing caveat in the credentials doc |
| **A provider of your own**: an Azure AI Foundry resource, a gateway, anything OpenAI-compatible on the internet | A provider in Pi's `~/.pi/agent/models.json` with its `baseUrl`, its models and their `cost`; the allowlist takes the host from `baseUrl` | `azure-foundry/grok-4.6` and `azure-foundry/DeepSeek-V4-Pro`, ten of the sixteen cases and both BelkaCTF runs |
| **A model on your own machine**: Ollama, LM Studio, vLLM, llama.cpp | The same `models.json` entry, with a placeholder `apiKey` (Pi lists a provider only when it has one; the server ignores it) and a `compat` block; then `--cap-tokens` and, for an all-local team, `--local-only` | `ollama/glm-4.7-flash-64k:latest` on the hello goal at $0, and `lmstudio/qwen3.8-27b-uncensored` as one seat of ten on BelkaCTF #6 |

Teams mix: `--models "openai/gpt-5.4=4,deepseek/deepseek-v4-pro=3"` puts each agent's model on the board so peers can hand a slice to whoever suits it, and a local model can sit next to a cloud one.

**Running it on your own models costs nothing and leaves the machine.** A team served from this machine bills nothing, and Pi reports its cost as an exact $0, so a dollar cap could never stop it. The kickoff refuses such a team without `--cap-tokens N`, probes the server before any pane opens (that it answers, that it has the model, and what context Ollama will really give; its default is 4096, whatever `models.json` declares), and with `--local-only` reduces the network allowlist to the local endpoint alone. The console then says "free" and counts tokens. Which local models are good at this is a different question: Pi cannot tell whether a model supports tool calls, and one that ignores them posts nothing and claims nothing rather than failing, so treat the hello goal as the entry exam for any model you pull. The `models.json` to copy, the placeholder key, the `compat` block and the Ollama context rule are in [docs/credentials-and-teams.md](docs/credentials-and-teams.md#local-models-ollama-lm-studio-vllm-llamacpp); the runs are in [docs/verified-runs.md](docs/verified-runs.md).

Two things to know before choosing. The netguard allowlist knows the hosts of OpenAI, Anthropic, DeepSeek, xAI, Google, OpenRouter and Azure OpenAI out of the box and reads any `models.json` provider's host from its `baseUrl`; a provider outside both (Bedrock, Vertex, Copilot) needs `--allow-host` for its endpoint. And a subscription's spend is Pi's estimate rather than a charge, while a `models.json` provider reports whatever `cost` you wrote: state the rates, or the cap is a fiction.

## What the harness enforces

Each guard is enforced by the operating system where the host allows it, and the run record and the report's custody section say what was achieved on that host rather than what was asked for. [docs/safety.md](docs/safety.md) and [docs/sandbox-plan.md](docs/sandbox-plan.md) have the measurements.

- **A write allowlist around every pane.** A pane writes inside its own run and Pi's agent directory, and nowhere else: not the examiner's home, not another case, not the run registry. macOS seatbelt profiles; on Linux, Landlock inside a user namespace, or either alone, with the record naming which ([docs/linux-plan.md](docs/linux-plan.md)). `--no-write-guard` turns it off and the record says so.
- **Evidence read-only at the kernel.** `--inputs DIR` copies the evidence in, hashes it and holds it read-only in every pane; `--inputs-bind` guards the source in place instead of copying 13 GB; `--inputs-image` attaches a disk image read-only. A write that lands by another route is healed from a pristine copy and announced on the board; every file is checked again at the end. `--catalog` runs the first pass over a disk or memory image before any agent spends a token; `--quarantine` makes anything extracted from the evidence unrunnable. [docs/inputs.md](docs/inputs.md).
- **A record the panes cannot forge.** The only writer of `traces/events.jsonl` runs outside the sandbox and is reached over a socket in a directory the panes cannot write. Each line names the hash of the line before; the head of the chain is anchored beside the run, past the write guard; each line is attributed by a per-pane secret the collector holds. On Linux, where one pane can read a peer's environment, a gate in front of the collector attributes by process ancestry instead. The report verifies the chain and counts what it could not attribute.
- **Claims before writes.** `edit`/`write` without a live lease is blocked; a shell write to a leased path is detected, snapshotted and announced on the board with the agent's id. Harness-owned files (`SWARM.md`, `team.json`, `budget.json`, `done/`, `locks/`, `threads/`, `traces/`) are refused as write targets.
- **Two caps, one stop.** At the USD cap, the token cap or the wall clock every agent is steered once to `done(cannot_complete)`; two minutes later the harness writes `done/SWARM_DONE` itself and ends every session, in-flight call included. `--cap-per-agent` stops one agent without stopping the swarm.
- **Egress is an allowlist, and the record says how firm.** Only the model providers and the hosts the case names (`--allow-host`). On Linux the guard is a network namespace: fail-closed. On macOS it is a proxy the panes are pointed at through their environment: advisory, and printed as `ADVISORY` in the custody section. Every refused connection is counted and printed. `--allow-install` lets agents pip-install into the run, inventoried package by package; `--no-pypi` keeps the index off the allowlist while the machinery stays on.
- **Evidence is hostile input.** A URL in a chat log is a finding to record, never a link to fetch. The contract says it, the egress guard and the quarantine enforce it, and the trace shows every time it was tested. `--no-read DIR` keeps a directory the agents must not consult (a previous run's answers on the same evidence, above all) unreadable at the kernel, so a re-run is a re-run.
- **The terminal's control socket is denied.** Herdr's socket authenticates nobody, and a process started through it would run outside every rule above; the write guard denies it to the panes, and a host that cannot mask it records `unenforced`.
- **Agents can forge tools, if you let them.** With `--allow-tool-forging`, an agent writes the parser or checker the goal needs with `make_tool`; every peer gets it as a real tool; the script, its author, its hash and every call are on the console; the library is kept between runs. [docs/forged-tools.md](docs/forged-tools.md).
- **Or each agent in its own microVM.** `--isolation microvm` (macOS on Apple silicon, Linux with KVM) puts every agent's Pi in a VM of its own, built from the case's packs: the run is read-only in it but for the agent's own directories, the evidence is mounted read-only, the board is written for it on the host by one process, the network is closed but for its models' hosts and the hosts you allow (every public host with `--no-netguard`), and no credential enters it — only a placeholder the host swaps on the way out. The stop, the snapshots of each VM's disk and a full re-hash of the evidence are taken on the host. [ADR 0009](docs/adr/0009-agents-live-in-microvms.md) has the design and its stated limits.
- **What it cannot do.** On the host, reads are open by design: a pane can read anything this user can, outside the directories you name with `--no-read`. On macOS a process that ignores its proxy variables has egress, and one did. Run swarms on a machine you are willing to lose, and read [SECURITY.md](SECURITY.md).

## Documentation

| Read this for | File |
| --- | --- |
| From a clean machine to a first swarm and the console | [docs/quick-start.md](docs/quick-start.md) |
| Every command, flag, env var, API route, and how to write a goal | [docs/usage.md](docs/usage.md) |
| What is on disk and on the wire | [docs/protocol.md](docs/protocol.md) |
| The design and what runs where | [docs/architecture.md](docs/architecture.md), [docs/component-map.md](docs/component-map.md) |
| What the harness enforces, what it measured, and what is left | [docs/safety.md](docs/safety.md), [docs/sandbox-plan.md](docs/sandbox-plan.md), [docs/linux-plan.md](docs/linux-plan.md), [SECURITY.md](SECURITY.md) |
| What you see while it runs | [docs/observability.md](docs/observability.md), [docs/screenshots.md](docs/screenshots.md) |
| Subscriptions, mixed-model teams, local models, the credential gate | [docs/credentials-and-teams.md](docs/credentials-and-teams.md) |
| Agents writing their own tools | [docs/forged-tools.md](docs/forged-tools.md) |
| Packs: skills, tools and method an operator imports | [docs/packs.md](docs/packs.md), [packs/](packs/) |
| Files the swarm may read but never change | [docs/inputs.md](docs/inputs.md) |
| Seventeen forensic cases, end to end, with every artifact | [docs/use-cases/](docs/use-cases/README.md), [docs/use-cases/belkactf/](docs/use-cases/belkactf/README.md) |
| The run an agent walked out of, end to end, with the tour | [netguard-escape.md](docs/use-cases/belkactf/belkactf6-bogus-bill/netguard-escape.md), [the tour](docs/use-cases/belkactf/belkactf6-bogus-bill/media/README.md) |
| Live runs that proved a feature, with ids and costs | [docs/verified-runs.md](docs/verified-runs.md), [docs/feature-evidence.md](docs/feature-evidence.md) |
| What goes wrong and what to do | [docs/troubleshooting.md](docs/troubleshooting.md) |
| The reasoning behind the design | [docs/why-the-incident-inverted.md](docs/why-the-incident-inverted.md), [docs/adr/](docs/adr/) |
| What is next and what it will not become | [docs/roadmap.md](docs/roadmap.md) |
| The vocabulary | [CONTEXT.md](CONTEXT.md) |
| The licence, the name, contributions | [LICENSE](LICENSE), [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md), [TRADEMARK.md](TRADEMARK.md), [CLA.md](CLA.md), [NOTICE](NOTICE) |
| Contributing, conduct, changes | [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [CHANGELOG.md](CHANGELOG.md) |

## License

[GNU AGPL v3 or later](LICENSE) © 2026 Halil Öztürkci. See [NOTICE](NOTICE).

Running it costs you nothing and asks nothing, on your own machines or on a
client's case, whatever you bill for the work. What the AGPL asks for is the
source of a **modified** version that other people reach over a network. A
[commercial licence](COMMERCIAL-LICENSE.md) covers the cases where that does
not suit, and most people do not need one.

The code is AGPL; the name is not. [TRADEMARK.md](TRADEMARK.md) is what that
means in practice: fork freely, and give the fork its own name. Contributions
come in under [CLA.md](CLA.md), agreed in the pull request.

## Credits

- **[Herdr](https://herdr.dev)** (Apache 2.0) and **[Pi](https://pi.dev)** (MIT), used through their official CLIs and extension APIs. Neither is bundled here: the quick start installs them.
- **Ali Hadi** ([@binaryz0ne](https://www.ashemery.com/dfir.html)), whose Digital Forensic Challenge Images the swarm was measured on, and **Belkasoft**, whose [BelkaCTF](https://belkasoft.com/belkactf6/) editions gave it questions with answers. The evidence files are not in this repository.
- **OpenAI**, [*The Hugging Face incident and the road ahead*](https://openai.com/index/hugging-face-incident-and-the-road-ahead/) (2026), with the technical report and [METR / Redwood Research's independent report](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/): read as architecture, not as a story to reproduce.
- React, Vite, Tailwind, Radix, lucide; Playwright for the browser checks. Live runs on DeepSeek V4 Pro, grok-4.6 through Azure AI Foundry, GPT-5.4, a local Qwen through LM Studio, and the OpenAI Codex and Anthropic subscriptions through Pi.

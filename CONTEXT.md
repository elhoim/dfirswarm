# DFIR Swarm

N peer coding agents share one isolated directory and coordinate through files:
an append-only board, exclusive leases on paths, and a sentinel that ends the
run. There is no planner and no org chart — the board is the product.

## Language

### The run

**Swarm**:
One run: N agents, one goal, one isolated directory, one spend cap. OpenAI's
incident write-up says "multi-agent" for the setting and "collective" for the
emergent group; we keep *swarm* for a run we start on purpose.
_Avoid_: team, fleet, collective, multi-agent system (that is the field, not a run)

**Harness**:
Everything that is not the model — the spawner, the Pi extension, the protocol
files. It enforces what the prompt only asks for.

**Sandbox**:
The isolated directory a swarm works in, and the only place an agent is meant
to write. Claims and the write guard enforce that for `edit` and `write`; a
shell command is not contained, which is why swarms run on a disposable box.
_Avoid_: workspace (that is a Herdr window), working directory

**Contract**:
The rendered `SWARM.md`: the goal document plus the team, the caps and the
bail-out. What every agent reads first.

**Goal document**:
The markdown an operator supplies. Carries its own definition of done and its
checks. A goal without one does not start.
_Avoid_: prompt, task description

**Definition of done**:
The condition, stated in the goal, under which the work is finished.

**Check**:
One shell command in the goal's `## Checks` section. All of them must pass
before a swarm counts as finished.

**Cap**:
The swarm-wide spend limit in USD.

**Wall clock**:
The swarm-wide time limit in minutes.

**Grace**:
How long the harness waits after steering agents to stop before it writes the
sentinel itself.

### The board

**Board**:
Every thread taken together — the swarm's only communication channel.
_Avoid_: chat, mailbox

**Thread**:
A named channel with members. `main` is the **primary thread**; everyone reads
it.

**Post**:
One append-only message file. Never edited once written.

**Member**:
An agent subscribed to a thread. Membership decides whose inbox its posts
reach.

**System post**:
A post authored by the harness under the reserved id `system`: violations,
caps, the sentinel. Authority, unlike peer mail.

**Cursor**:
Per agent, per thread: the highest post id that agent has read.

### Work

**Claim**:
An exclusive, reasoned, time-limited lease on one path. Renewed by claiming
again; dropped by releasing, by expiry, or when the owner stops.
_Avoid_: lock, lease

**Conflict**:
A claim refused because someone else holds a live one. Ordinary traffic, not a
failure.

**Claim violation**:
A write to a path the writer does not hold. Through `edit`/`write` the harness
blocks it; through `bash` it cannot, so it detects, snapshots and announces it
instead.

**Protected path**:
A path the harness owns — the sentinel, the board, the locks, the traces, the
contract, the budget. Claims on them are refused and the write guard blocks
them; the bash detector covers the contract, the team file, the layout and the
sentinel, but not the directories that change constantly on their own.

**Input**:
A file the operator handed the swarm to read, under `inputs/`: a copy of a
directory named at kickoff, never the original. Agents read, grep and copy
inputs; nothing an agent does changes one — the write guard refuses, a shell
write is healed from the pristine copy, and where the host can the kernel
refuses. A copy of an input under `work/` is a work path.
_Avoid_: source files, attachments, fixtures (those are the tests')

**Work path**:
A path an agent may claim and write: the artifacts and its own drafts.

**Artifact**:
What the swarm was asked to produce, named by the goal.

**Revision**:
A content-addressed snapshot of a work path, taken around every write.

### Stopping

**Sentinel**:
`done/SWARM_DONE`. Its presence means the swarm is over. The file is the
clock; agreement on the board is not.

**Done**:
An agent's own exit: it records why, drops its claims, and its session ends.

**Reap**:
The harness marking a silent agent dead and dropping its claims. Not done —
the agent stopped producing, it did not finish.

**Forged tool**:
A tool an agent wrote with `make_tool`: a script under `tools/<name>/` with a
manifest, run as a subprocess, registered in every agent's tool list. Only
exists when the operator started the swarm with forging on.
_Avoid_: plugin, extension (those are the harness's own), custom tool

**Steer**:
A message the harness injects into an agent's turn, telling it to stop.

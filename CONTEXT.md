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
How long the harness waits after steering agents at a cap before it pauses
the run, or, under `cap-stop`, writes the sentinel itself.

**Stop policy**:
What a cap or the wall clock does: `cap-pause` (the default: the run pauses
for the operator), `cap-stop` (the harness stops it, for an unattended run)
or `operator` (until solved).

**Pause**:
A run held at a cap: every seat idle, no model call sent, nothing lost, until
the operator extends it or stops it. Never lifted by itself.

**Resume**:
The operator continuing a run that ended: the same run, in the same sandbox,
on the same chains; each seat from its last hand-off. Not a new run.
_Avoid_: restart, rerun (a rerun is one job run again)

**Outcome**:
How a run ended: completed, examination limited, paused, stopped, abandoned,
or verification unavailable. Stopped is never completed.

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

### Leads

**Lead**:
A piece of material investigative work an agent found that has to be
followed: a container to open, a key to find, an output to read to its end.
Kept by the harness in the lead register (`leads/leads.jsonl`), opened,
claimed and closed by the agents themselves; nobody assigns one.
_Avoid_: task, ticket, assignment

**Need**:
What a lead cannot go on without: another lead's outcome, or a standing
ledger entry. Never a job: a job's exit status settles nothing.

**Disposition**:
How a lead ended, and what that cites: resolved, negative, duplicate,
deferred, infeasible, needs_operator; withdrawn when the question it served
was withdrawn (the harness's alone).

**Interpretation**:
A ledger entry recorded with `interprets` naming a job: what its output
shows. A citation alone is not one.

**Route**:
A source a question's lead plans to examine, and how. At a negative close,
the planned routes nobody examined are listed as not examined.

**Quick negative**:
A lead closed negative after one job over one object within two minutes: a
cue for review, not a refusal.

**Similar job**:
Another seat's job, under way or committed, running the same tool or the
same leading command over at least one of the same objects by digest: named
when a job is accepted, never merged with it.

**Reproduction**:
A job run with `independent: true`: another seat's work run again on
purpose, as a check. Counted apart from duplicates.

**Reversal**:
A standing result that changed (an answer's `result`, or a negative lead
reopened): after new evidence, or discoverable in the evidence the run
always had. _Avoid_: correction (a correction that keeps the result is not a
reversal).

### Questions

**Question**:
What the examination is asked to establish, as `Q-n` in the question
register (`questions/questions.jsonl`). Its answer is the ledger entry in
section `question:n`; leads are the work done against it.
_Avoid_: task, ticket, request

**Origin**:
Who asked a question: the goal, an agent (with the entry that raised it), or
a person (an analyst, a reviewer, an observer; enrolled or not; claimed or
signed). Kept apart from who found the answer and who adopted it.

**Objective**:
What the case is to establish, `O-n`, declared by the goal or added by an
examiner or the operator. A question inside one is in scope.

**Triage**:
Where a proposed question, or a lead left holding a finding after its
question was withdrawn, waits for the operator or an examiner to admit or
exclude it.

**Directive**:
The operator's unheld lead under a question, with the product it is to make
and what makes that acceptable. Never a held lead: nobody is assigned one.

**Result**:
What an answer to a question is: established, partial, bounded negative, not
determinable, out of scope, or premise not supported.

**Bounded negative**:
"No evidence of X was found in <scope>": nothing found, within what was
searched. Not "X did not happen", which needs an existence question,
complete coverage and a stated detection opportunity.
_Avoid_: "absent", "never happened" (unless that bar is met)

**Coverage record**:
The ledger entry (`kind=coverage`) that says what a negative was searched
over, and whether the event would have left a trace there. The hub adds
whether every object it names was given to a job: complete or partial.

**Negative review**:
Another seat's attest of a material negative, saying whether it challenged
the detection assumptions, reproduced a decisive check and tried another
route. Until then the negative is unreviewed, and the run does not finish.

**Acceptance**:
The operator taking a question's limits as they stand (bounded, or not
determinable) for one revision. It makes the run examination limited.

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

**Until solved**:
The `operator` stop policy (`--until-solved` or `--stop operator`): a run with
no wall clock and advisory caps, where `done` is refused until
every question of the goal is answered and nobody but the operator can end it.
When nothing moves the watchdog posts a **regroup**: what is open, blocked,
waiting on the operator and uncited.

**Steer**:
A message the harness injects into an agent's turn, telling it to stop.

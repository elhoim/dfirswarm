# Reuse is hinted, and the process is measured from its registers

A job is never merged with another seat's behind the agent's back, and it is
never silently repeated either: when another seat already ran the same tool or
the same command over the same objects, the answer names that job, its lead
and what it made, and an output that is byte for byte an earlier job's says
so. A second run meant as a check says so too. Only a typed recipe over the
same object is answered with the earlier job. How a run worked is measured
from its own registers, metric by named metric, with each definition written
down, and two runs of one goal can be set side by side, question by question.

Status: accepted, 2026-09-28. Designed by Claude, Fable and Astra (Plan 3,
joint-final A5 and round 3's Phase 5) and approved by the owner with the rest
of Plan 3. It is Phase 5's reuse and metrics part; the calibration cases are
their own (`calibration/`, `scripts/calibrate.ts`).

## Context

- Merging raw jobs was measured before it was done (2026-09-27): a command
  or a tool job got a shadow key, the sha256 of its whole spec (the command
  byte for byte, its timeout, its profile, its arguments) over its declared
  objects by digest, and a second job with the same key was written to the
  journal as `job_would_merge`. Both ran. On the three runs of the last CTF
  round the key matched none of 393, 127 and 190 keyed jobs. Agents did
  repeat each other's work, but never byte for byte: another timeout, another
  flag, a `| head` at the end. The duplication is at the level of object ×
  operation, which a whole-spec key cannot see.
- A merge at that level would be wrong: two jobs running `strings` over one
  disk image with other flags are not one job, and an agent that meant to
  check a peer's result would be handed the peer's result. What the agent
  lacked was the knowledge that the work was there.
- Typed recipes were merged already (`job_deduplicated`: the same recipe, its
  sha256 and image, over the same object by content), and that merge is
  sound: a recipe's identity is its own.
- The runs had no process measures of their own. ctf12's figures (quick and
  unreviewed negatives, refused `done` calls, woken seats' claims, the tail
  after every question was answered) were counted by hand from the registers,
  and Astra found earlier metrics that named one thing and counted another:
  a lead held at its open against ownership retained, a dependency satisfied
  against one withdrawn, how long a lead was blocked against how long a wake
  took, a question's first answer against its first supported one.
- Two runs of one goal agreeing was read as confirmation; two runs of one
  harness can share a blind spot.

## Decision

1. **The shadow key is retired.** No command or tool job gets one, and
   nothing writes `job_would_merge`. A journal that has them still reads:
   they are ignored by the job service and counted apart by the metrics.
2. **A job's reuse identity** (`scripts/job-reuse.ts`) is kept on its
   `job_accepted` line as `reuse: {op, objects}`, for a command or a tool
   with a declared scope: `op` is `tool:<name>`, or `command:<word>`, the
   leading command word (`protocol.ts leadingCommand`, the one the forge
   hints use); `objects` is the declared scope as resolved, each file by its
   sha256 and each directory of the evidence, the store or the catalogue by
   its path. An agent's own file is live and not known by its digest until
   the job starts, and a job over everything has no objects: neither is
   compared. Digests, paths and command words only; no format, no output.
3. **`similar` at `job_run`.** At acceptance, the other seats' jobs under
   way or committed, with the same tool or the same leading command word,
   that read at least one of the same objects, are named in the answer with
   their seat, lead, state, status and outputs, whether the objects are the
   same or overlap, and how close the operation is (the same command, or the
   same tool with the same arguments, ranks first). The whole list is a
   `job_similar` line; the answer carries eight and names the line for the
   rest. The job runs as asked; the agent may cancel it.
4. **`same_as` at commit.** A committed job's non-empty file whose sha256 is
   an earlier job's output names that job and file, on a `job_same_as` line,
   the job's record and its view. The file is the job's own either way.
5. **`independent: true`** on `job_run` (a command or a tool) records an
   intended reproduction on the spec. `similar` is still shown; the metrics
   count reproductions apart from duplicates.
6. **Merging stays for typed recipes only**, as it was.
7. **Metrics** (`scripts/metrics.ts`, `swarm.sh metrics <run> [--json]`)
   read the registers only (leads, the finish register where it exists,
   questions, the ledger with attestations and disputes, requests, the store
   journal, the network, the trace, the seats' token records) and write
   nothing. Each figure is a count of named records, the JSON names them,
   and no answer value, finding or command is printed. The set: quick
   negatives; unreviewed negatives, material and background; coverage
   completeness; offers by outcome (accepted, declined, taken by another
   seat, lapsed), with wakes from before offers apart; `done` calls, refusals
   and deferrals; the tail to the end from readiness, from the first answers
   and from the final ones, each its own figure; acquisition requests and
   gaps; interpretations valid or on a superseded or disputed entry;
   reversals, by new evidence or discoverable in the original; tokens per
   question, apportioned by the leads held; duplicates and reproductions;
   network requests, grants, refusals and captures. The definitions are in
   `docs/usage.md`, and each keeps apart what Astra found mixed: an accepted
   offer is not a woken seat's claim, readiness is not a first answer, a
   first answer is not the one that stood, an interpretation is valid only
   while its entry stands. The dependency and blocking figures are not in
   this set; a metric of either must keep satisfied from withdrawn and
   blocked time from a wake's latency.
8. **A register a run does not have is absent, never zero.** A run from
   before offers, the finish register or the reuse hints says so and is
   measured on what it has.
9. **`--compare <run-A> <run-B>`** sets two runs of one goal side by side by
   question section: each standing result, whether a negative was reviewed,
   its coverage, any acceptance. It flags a negative the other run
   established, and a negative both reached without complete coverage, as a
   possible shared blind spot, and says that agreement is not confirmation.

## Consequences

- Duplicate work becomes visible at the moment it would start, with the
  earlier job's outputs to read, and the choice stays the agent's. What was
  done twice, and what was meant to be, can be counted afterwards.
- Nothing about a job's own record changes: its outputs are sealed and cited
  as before, and a hint is never a merge. A heavier job over the same image
  by another seat is still run; the hint costs one scope resolution at
  acceptance and a manifest index built once per hub.
- A command whose leading word is a generic one (`python3`, `bash`) is
  similar to other such commands over the same objects; the ranking puts the
  same command first, and the answer carries eight of the list.
- The metrics make the gates of the next CTF round countable from the
  registers, not by hand, and a run without ground truth has a process
  measure. They measure the process, never the case: a figure is a count of
  records, and reading what a record means is the examiner's.
- Cost per question is an apportionment: a seat holding two leads has each
  call split between them. The reversal cause is a heuristic: evidence that
  arrived between two answers is not proof it caused the change.
- Not decided here: the calibration fixtures and their scorer (already
  built), the dependency and blocking metrics, and any merge of raw jobs;
  a merge would need the operation's semantics, which the harness does not
  know.

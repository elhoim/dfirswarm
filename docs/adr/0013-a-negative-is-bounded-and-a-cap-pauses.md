# A negative is bounded, a cap pauses, and a run can be resumed

An answer says what it is: established, partial, a bounded negative, not
determinable, out of scope, or a premise not supported. A negative says what
was searched, over which objects, and whether the event would have left a
trace there; another seat reviews it before it is trusted, and it is worded as
what it is: "no evidence of X was found in <scope>", never "X did not happen"
unless the bar for that is met. A cap pauses the run for the operator instead
of ending it, and a run that ended can be continued, in the same sandbox, on
the same chains, with every earlier seal still valid as a prefix.

Status: accepted, 2026-09-28. Designed by Claude, Fable and Astra over four
rounds (Plan 3, rounds 3 and 4) and approved by the owner with the defaults
below: caps pause the run (`cap-pause`), `cap-stop` stays for unattended runs,
and after a stop or a seal the same run continues (`swarm.sh resume`), its old
seal valid as a prefix, a signed v1 kept as it is and the continuation adopted
through a later version. It is the second part of Phase 1a, after the question
register ([ADR 0011](0011-questions-are-a-register-with-their-askers.md)).

## Context

- An answer was an answer, or `inconclusive`. A search that found nothing was
  an `absence`, and a question's answer resting on one alone was
  examination-limited; nothing said over what the search ran, whether it read
  every object it named, or whether the event would have left a trace there
  at all. "Nothing found" read in reports as "it did not happen".
- A lead closed `negative` after one job over one object a minute after it
  was claimed looked the same as one closed after a planned sweep.
- The critic's act on a negative was an attest like any other: "I re-read the
  job's output" said nothing about whether anyone had challenged the
  detection assumptions or tried another route.
- A cap or the wall clock ended the run: the harness wrote the sentinel two
  minutes after the steer. On a long case the operator lost the run at the
  moment the case was nearly answered, and a subscription run had no dollar
  brake at all unless one was given.
- A run that ended was over. Further questions meant a new run, a new copy of
  the evidence, a new custody and new releases; what the first run learnt was
  a prior ledger of hypotheses at best.

## Decision

1. **Results.** A question's answer carries `result`: `established`,
   `partial`, `bounded_negative`, `not_determinable`, `out_of_scope` or
   `premise_not_supported`. It is required on a new answer to a question; an
   answer recorded before it reads as it always did, and `inconclusive: true`
   is taken as `not_determinable`. `established` and `partial` rest on a
   standing finding. The answers check maps results onto its existing
   outcomes, so the finish line and old goals are unchanged: `established`
   and `premise_not_supported` answer the question; `bounded_negative`
   answers an existence question only over complete, reviewed coverage, and
   is examination-limited otherwise; `not_determinable` is inconclusive;
   `partial` and `out_of_scope` are limited.
2. **Run outcomes.** `completed`, `examination_limited`, `paused`, `stopped`,
   `abandoned`, `verification_unavailable`, read from the run's files
   (`runOutcome`). An operator's stop of a run with no sentinel writes
   `done/STOPPED`; a sentinel the harness wrote at a cap reads as `stopped`.
   `stopped` is never `completed`.
3. **Coverage is a ledger kind of its own**, `coverage`, not fields on
   `absence` and answers. A `not_determinable` answer often has no absence at
   all; one negative usually spans several searches, each its own absence or
   limitation; and the review is of the whole search, which needs one entry
   to attest. The record carries the proposition, the objects (refs), the
   time range, the method and settings, what was actually covered, what was
   skipped and what failed, the results (`result_refs`), what is still open,
   and the detection opportunity (`trace_expected: yes | no | unknown` with
   why). Its free-text fields are bounded and refused past the bound, never
   cut. Every material `bounded_negative` and every material
   `not_determinable` cites one that names its question.
4. **The hub computes object coverage.** It stamps the inventory revision
   (the sha256 of `inputs.json` and the catalogue's generation records) and
   compares every object the record names, by digest where it has one,
   against the inputs the jobs behind its results declared: `complete` when
   every object was given to a job, `partial` with what was not. A job over
   everything covers each object and is said to. It counts; it never judges
   whether an object was relevant.
5. **Route plans.** A lead under a question carries `routes: [{source,
   method}]`. The spec said "warn, then require for material questions"; the
   sound reading against the register is: the first lead under a question
   without a plan is warned; the first lead under a person's question must
   carry one (it is the lead that states the proposition and its negation);
   a negative close of a material lead, or of any lead under a material
   question, is refused without one, and a material negative answer is
   refused when no lead of its question planned a route. At a negative close
   the hub lists the planned routes no job of the question's leads declared
   and no coverage record names (`not_examined`). A route named in words
   only is kept and said to be untrackable.
6. **Quick negatives.** A negative close held two minutes or less, after one
   job over one object (and no job over everything), is flagged
   `quick_negative`: in `leads.md`, in the header until a peer attests the
   negative, and in the report. It is a review cue, not a refusal.
7. **Peer review of material negatives.** A material negative (the answer,
   or its coverage record) stands "negative (unreviewed)" until a seat that
   recorded neither attests it with `review`: whether it challenged the
   detection assumptions, reproduced a decisive check, and tried a
   materially different route, each done or not, with what was done or why
   not. The finish line refuses while one is unreviewed; the review counts
   as the critic's act.
8. **Wording.** The report renders a bounded negative as "No evidence that X
   was found in <objects, time range>", with its coverage. "X did not
   happen" (`asserts_absence`) is taken only on an existence question,
   resting on coverage the hub found complete whose detection opportunity
   says the event would have left a trace; the record refuses it otherwise,
   and the answers check names an answer worded so without the bar
   (`wording`).
9. **Operator acceptance.** `swarm.sh question <run> accept Q-n --as
   bounded|not_determinable --why --expect-rev N` is revision-bound; it is
   refused while a lead under the question is open or its negative is
   unreviewed, and any acceptance makes the run `examination_limited`.
10. **Stop policy.** `--stop cap-pause|cap-stop|operator`, default
    `cap-pause`; `--until-solved` is `--stop operator`. The caps and their
    defaults: the wall clock keeps its default (8 minutes under ten agents,
    15 at ten, 20 at twenty), and a metered team without `--cap-tokens` gets
    100,000,000 tokens as a second brake (a seven-agent case runs to tens of
    millions, so it stops a runaway, not a case); a team whose dollars are
    not charged still has to give its token cap. Under `cap-pause`, at a cap
    the seats are steered to post a checkpoint, and two minutes later the run
    pauses: `budget.json` records the pause; no model call goes out (the
    extension's `context` hook holds it on the host, the model gateway
    refuses it, the hub prompts no seat, and the watchdog enforces the pause
    from outside the panes); the partial result stays as it is; the operator
    is notified (`paused`). `swarm.sh extend <run> [--minutes N] [--tokens N]
    [--usd N]` lifts it when the caps then leave room, and the watchdog wakes
    each seat once; `swarm.sh stop` ends it as `stopped`. The time a run is
    paused, or stood stopped, does not count against its wall clock. The run
    never goes on by itself, and the operator's silence approves nothing.
11. **Diminishing returns.** When no new finding, question disposition or
    coverage record has appeared across 20 committed jobs or 30 minutes
    (`SWARM_YIELD_JOBS`, `SWARM_YIELD_MINUTES`), the watchdog proposes a stop
    to the operator as an operator request of kind `decision`. It is never
    an agent's vote, and it stops nothing.
12. **Resume.** `swarm.sh resume <run> [--question TEXT … | --questions FILE]
    [--as ID]` (and "Continue this run" in the console) continues a run that
    ended: the same sandbox, the same ledger, registers, board, trace and
    store journal, appended to and never rewritten. Nothing moves until the
    budget holds: the wall clock counts on from the stop, the caps grow by
    what is given, and a resume that would still be over a cap is refused.
    What marked the end moves whole to `done/history/<k>/`, the first
    segment's VM records and kept disks aside; each seat starts from its last
    hand-off note or compaction summary, whole, and the registers as they
    stand; the questions given are admitted as analyst questions. The resume
    is the operator's act, recorded on the trace, the operator's record, the
    registry, `budget.json` and the custody anchor beside the run, with each
    chain's length and head. The next stop seals the continuation anew: a new
    custody verdict and a new draft release. Every earlier verdict the anchor
    names verifies as a prefix of the chains, and `custody-verify` shows each;
    a release verifies with its chains as a prefix only when the anchor
    records a resume after it. A signed v1 stays untouched and valid for what
    it bound; the continuation's answers are adopted through a later version.
    The kickoff keeps its own options outside the run (0600), so the resume
    restarts the same team; a run started before that gives them after `--`.

## After review

An independent review (Astra, of the commits that built the above) found
seventeen ways around it; each has a test that failed before its fix.

- A coverage record binds its results by hash: a result superseded,
  disputed or changed takes the record, and a review of the negative
  resting on it, out of standing (`coverage_stale`).
- `premise_not_supported` rests on a finding. "It did not happen" is held
  whatever the result. The report states a negative's conclusion from the
  coverage record's proposition and scope, never from the agents' words.
- An acceptance is of the answer that stood (its hash), and an accepted
  question's negative is held to the bar all the same.
- The hub names objects as the job scopes do (a digest, a store path, a
  catalogue directory), and a coverage record may name a directory.
- A release's chains are verified with their own verifiers; only a resume
  anchored at a boundary those chains hold relaxes a release to a prefix;
  the report bytes a release binds are kept at `release/bound/<sha256>` when
  the run is resumed; a gone gateway log breaks an earlier seal; the resume
  is anchored before anything moves.
- A compaction is held while the run is paused, and so is the model call
  whose check wrote the pause. An extension reads the run's end under the
  lock a stop takes. The operator is told of a pause once, whoever wrote it.
  The watchdog runs at `--idle-nudge-sec 0` too, for the stop policy, and a
  wake that did not land is tried again.
- The start options kept for a resume never hold the notify command, and
  hold an `--env` value only where no pane can read it; the stores are
  denied to a host run's panes where the guard can. A resumed run's
  evidence image is attached again and held to its manifest.

## Consequences

- Every existing goal and run keeps working: an answer without `result`
  reads as before, `inconclusive` is `not_determinable`, a budget without
  `stop_policy` is `cap-stop`, `--until-solved` keeps its meaning, and a
  ledger version 4 core is unchanged when the new fields are absent.
- A run no longer ends at a cap by default. An operator who wants the old
  behaviour for an unattended run says `--stop cap-stop`; a run that pauses
  overnight waits, holding nothing but its disk.
- A negative in a report now carries its scope and its reviewer, or says it
  has none. "It did not happen" needs the evidence for saying so.
- A case can grow without losing its custody: further questions after a
  stop are the same run's, and the releases say which chains each one bound.
- Not decided here: the acquisition lane and notifications as sealed
  material (Phase 1b), the full offer protocol and the reviewer's query
  (Phase 2), the report's per-question chains (Phase 3), and the mediated
  network (Phase 4). The resume relaunches the team the way a start does;
  what a real VM or Herdr relaunch does beyond the kickoff is exercised by
  the kickoff's own tests, not by one of its own.

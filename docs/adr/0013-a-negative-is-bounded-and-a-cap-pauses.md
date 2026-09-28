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
   answers an existence question only under the stronger bar (complete
   coverage with the trace expected, reviewed, and the answer saying the
   event did not happen), and is examination-limited otherwise;
   `not_determinable` is inconclusive; `partial` and `out_of_scope` are
   limited. It also names each question's **disposition under the bar**
   (below): what a run may end on.
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
    `--stop operator` (and `--until-solved`) takes the caps and the wall
    clock away, and nothing else: it adds no stricter answer requirement
    (see "The end of a run" below).
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

## The end of a run, under every stop policy

A generic DFIR platform must allow a question to have no answer: the
pressure goes on coverage, never on answers. And "until examined, within
budget" (joint-r3, Phase 1a): a quick "looked, not found" must not end a run.
So there is one rule, under every stop policy: `done` finishes a run only when
every question in scope has a **disposition under the bar**, no material
lead is open, no defect stands (a defect a limitation only names included:
a defect is fixed) and the goal's checks are met. The dispositions are:
established; partial; `bounded_negative` resting on a coverage record
another seat reviewed; `not_determinable` resting on one likewise; a
premise shown not to hold, on a finding; out of scope; accepted by the
operator; withdrawn. A best candidate is none (B2), and neither is an
answer resting on a limitation alone, a negative whose coverage no longer
stands, or a question behind a quick negative nobody has attested. The run
ends `completed` when every question is established or settled by a
bounded negative that says the event did not happen under the stronger
bar, and `examination_limited` when any is not determinable, partial,
out of scope, a bounded negative short of that, or accepted.

The stop policy decides only who else ends the run, and when a cap pauses or
stops it. Under `cap-pause` and `cap-stop` a cap pauses or stops the run
whatever the questions' state, and the operator may stop it; that end is
`paused` or `stopped`, never `completed`, and an agent may still abandon
(`abandoned`). Under `--stop operator` (its alias `--until-solved`) there is
no cap and no wall clock, nobody abandons, and nothing but the finish or the
operator ends the run; it adds no stricter answer requirement: a reviewed
`not_determinable` ends it examination-limited, as it ends any run.

Until 2026-09-28 the rule differed by policy. `--stop operator` still
carried the ctf12 rule ("every question answered, an examination-limited
finish is not accepted"), which left the operator's acceptance as the only
way to end a run on a question the evidence could not answer (the CTF pilot
on the integrated branch showed it). The cap policies went the other way: a
limitation that merely named an unanswered question let the agents finish,
examination-limited, with no coverage record and no review: the shallow
negative this record exists to prevent. Both were replaced by the one rule.
The checks report the dispositions (`dispositions` in the answers check's
machine line, `disposition` on each question of the finish gate, `holding`
for a defect a limitation only names); the contract's Questions section,
the worker prompt and the refusal tell the agents the path to a
disposition when a question cannot be determined (plan the routes, record
the coverage, have another seat review it, answer `not_determinable`), and
the refusal names each question with none and what blocks it. A goal whose
answers check runs in report mode (`--report`, an older goal) reports no
dispositions: its questions end answered, and otherwise the run ends by its
stop policy.

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

## After the first calibration run

The first calibration case run on the new flow (a synthetic departure case
with a truth file kept outside the repo) scored the swarm against what the
evidence holds. It missed a third of the facts that sit in deleted and
unallocated space; answered "every file" and "every connection" established
with no coverage behind them; adopted a decoy at high confidence, attested
established; stated every answer high (four of them wrong); answered a
question that needed a source the evidence did not hold not_determinable,
with no acquisition ask; and left a question not_determinable after the
evidence that settled it was added late. Five rules follow, each generic
(no tool, no file system, no case named) and each tested.

- **New evidence stales what rests on older coverage.** An evidence
  addition makes stale every standing `bounded_negative`,
  `not_determinable` and `partial` answer (and a premise rejected on a
  search alone) whose coverage records were recorded before the addition's
  ledger entry, and those records, whether or not the operator named the
  question. The gate holds each (`evidence_stale`: "new evidence since its
  coverage (ev-n); re-examine against it"). It clears when the answer cites
  a coverage record for the question recorded after the addition (at the
  new inventory revision) that another seat reviewed, or cites the new
  evidence itself (the addition's entry, or an entry other than a coverage
  record whose refs, results or jobs name its import: a coverage record
  counts once it is reviewed). `evidence add` and its board post name the answers
  it stales. An established answer is not staled. The order is the
  ledger's (the addition's external entry against the records' seqs), not
  the inventory hash: a catalogue generation moves the hash too. In the
  calibration run the answer that stayed wrong had been recorded again after
  the addition, on reviewed coverage that named the new evidence, so this
  rule would not have held it: it makes the re-examination of every other
  negative explicit, and a re-examination that misreads the new evidence is
  the review's to catch.
- **A completeness claim rests on coverage of its areas.** A question whose
  words ask for every one, all, each, or a complete list, set or inventory
  is marked `completeness` in the register when it is opened (a small word
  rule; "at all" does not count), and an asker sets it either way
  (`question add --completeness`, `--no-completeness` on amend; an agent's
  `question_open` takes `completeness`). An established or partial answer
  to such a question rests on a standing coverage record for it that names
  its `areas` {allocated, deleted, unallocated, slack, secondary}, each
  searched, skipped or not_applicable, with what was skipped said in
  `skipped`; without one the gate holds it as it holds an uncovered negative
  (`completeness_uncovered`). The areas are generic: an area the evidence
  does not have is not_applicable.
- **An established attest names an alternative.** An attest with strength
  established carries `answer_review.alternatives` as `[{explanation,
  why}]`, at least one alternative explanation the reviewer weighed and why
  the evidence rules it out; one without is recorded best_candidate, with
  the reason in `capped`, and the reply says so. Nothing is refused, and the
  seat may attest again once it has weighed one (a later established review
  by the same seat is recorded; any other repeat is not). A text
  `alternatives` is still read, as an older review's and a best candidate's.
- **Confidence is recorded, not only stated.** An answer keeps confidence
  high only when it is established and another seat attested it
  established naming its alternatives; any other high is recorded medium,
  and the reply to the answer says why. Nothing is refused, and the stated
  confidence stays in the chained entry: the recorded one is derived where
  it is read (`recordedConfidence`), because the attest that keeps a high
  comes after the answer. The report, the metrics (`confidence`) and the
  calibration score show the recorded confidence, the stated one beside it.
- **A missing source is asked for.** When a question needs a source the
  evidence does not hold, the agents open an acquisition ask
  (`lead_close needs_operator` with `ask.kind: acquisition`) before
  answering it not_determinable, and the coverage record behind the answer
  names it (`acquisition_ask: R-<n>`) or says why none would settle it
  (`acquisition_none_why`). The gate warns, and does not hold, when a
  not_determinable answer's coverage does neither: the answers check prints
  a `WARN:` line and its machine line carries `warnings`, which the finish
  line's note repeats.

## The provider's limit, and the operator's pause

A run under `--stop operator` hit its model provider's subscription usage
limit on every seat at once. Each turn ended in the provider's words ("You
have hit your ChatGPT usage limit (pro plan). Try again in ~6904 min.",
"Codex error: The usage limit has been reached"), recorded as `agent_error`,
and the watchdog prompted each seat again, half an hour apart, for days,
while every VM and the hub stayed up; the operator was never told the run
could not go on before a stated time. A cap's pause did not apply: nothing
was over a cap, and the policy had none.

- **A pause that is not a cap.** `paused.reason` is `provider_limit` beside
  `cap` and `wall_clock`, and it pauses a run under every stop policy. The
  pause keeps the provider's distinct error texts, whole (`detail`), the
  models refused (`models`), and the end it holds to (`until`, below). A
  wait is read from the words: "try again in ~N min", "in N minutes", "in N
  hours", "retry after N seconds", a Retry-After number, the first time with
  its zone that is still ahead; a wait of more than 30 days (an epoch sent
  where seconds were meant) is not taken for one. Nothing else about a
  provider is read.
- **Every seat is retried.** A seat whose last turn ended in a provider
  error is prompted again by the watchdog with backoff (each wait twice the
  last, up to half an hour): until solved, for as long as the run goes;
  under `cap-pause` and `cap-stop`, three times per run of errors, within
  the wall clock. Before, only an until-solved run retried, so the second
  half of the rule below could not hold under a cap policy.
- **The rule.** The watchdog pauses the run when every live seat (not done,
  not dead, and reached by the last lift's wake) has, as its last own row
  since the last lift, a provider error, and every one of those seats is
  limited by its own evidence: its errors state a wait of 30 minutes or more
  still ahead, or it was prompted again after its first error and refused
  again (a prompt's row may land up to five seconds after the refusal it
  caused). One seat's error never pauses the run, and neither does one
  seat's long wait beside the others' passing errors: those are retried.
  The harness's own rows under a seat's id (a prompt's echo, a lost hub
  link, an extension's error, a stop) are not turns. The rule is read again
  under the table lock the pause is written under, as a cap is, so two
  watchdogs never both act and a seat that came back leaves the run going.
  Each failed turn is on the trace once, whole (a retry that failed on the
  same words used to leave no row).
- **The end it holds to.** When every limited seat is on one provider (the
  part of its model before the slash), `until` is the longest end any of
  them was told: every seat on a provider uses the one credential the run's
  Pi store (or the key the kickoff was given) holds for it, so its limit is
  one limit, and a try before its last named end would only be refused. In the run above one seat said ~6904 minutes
  and the others named no time; the pause holds to the 6904 minutes. When
  the seats are on several providers, `until` is the earliest end if each
  was told one (the first time any seat can go on), and otherwise there is
  none and the harness tries every half hour.
- **While it holds** every brake of a cap's pause holds: no seat is
  prompted, no model call goes out, the wall clock does not run, and the
  watchdog's provider-error prompts stop.
- **The harness tries again** at `until` and a minute, or half an hour after
  the pause when no end is known: it lifts the pause (`resumed_by:
  harness`, `run_unpaused` on the trace) and wakes each seat once. If every
  seat is refused again, the same rule pauses the run again; a pause that
  follows the harness's own try, no seat having worked since, continues the
  same spell (`since`) and does not charge the try to the wall clock. A seat
  the wake could not reach, with nothing of its own since, is left out of
  the rule until the reaper marks it. The operator is told once per spell,
  with the end the provider named and the advice: a long wait holds every
  VM; to free the machine, stop the run (custody seals it) and resume it
  after the limit lifts. The board is told the same, once, in one line. A
  seat tells the board of its own provider error once per spell of failed
  turns, and not again for the error it last told, its numbers and times
  masked: a countdown ("~6904 min", then "~6874 min") put one post per seat
  on the board at every try.
- **The operator's pause.** `swarm.sh pause <run> [--why TEXT]` holds a
  going run under any stop policy (`reason: operator`), and `swarm.sh
  unpause <run>` (the console's Unpause beside the pause) lifts a pause
  whose cause is gone: the operator's hold and the provider's limit always,
  a cap's pause only when the caps leave room, and otherwise it is refused,
  pointing to `swarm.sh extend`. An extension does not lift a pause that is
  not a cap's. Both are on the operator's record and the trace.
- **The run's end in a pause.** A run stopped while paused keeps the pause
  it was stopped in: the harness's try is not made on it (the stop is read
  under the lock the lift takes), and a resume folds the pause into the
  history as the resume's (`resumed_by: "<by> (resume)"`), which wakes no
  seat, since the resume starts each from its hand-off. A run whose seats
  all died while paused (`done/ALL_AGENTS_DEAD`) has no outcome of its own,
  as one that died unpaused; neither is shown as paused, and the console's
  elapsed time leaves every pause out.

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

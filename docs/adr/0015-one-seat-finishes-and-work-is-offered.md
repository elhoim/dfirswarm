# One seat finishes, work is offered, and a review says how strongly it holds

A run's finish is one seat's: a coordinator holds it by a lease that knows
when its holder is compacting, every other seat's `done` is answered "not
yours", readiness is shown to everyone and posted when it turns, one check
result stands per state revision, and the report is reviewed with typed acts
rather than late posts. Work that nobody holds is offered to one seat at a
time, from when the offer reaches it, and a closure whose entry was corrected
is offered back to its closer to confirm or reopen, never re-pointed. A
review of an answer says whether it holds it established or a best
candidate, part by part. A running job is seen from the host by three
signals, and the seats' tokens are renewed in place.

Status: accepted, 2026-09-28. Designed by Claude, Fable and Astra over four
rounds (Plan 3: joint-final A1–A5 and B2–B4, B10–B13, B17, B18, kept by
round 3 as Phase 2) and built as work package 4, after the question register
([ADR 0011](0011-questions-are-a-register-with-their-askers.md)) and the
negative bar ([ADR 0013](0013-a-negative-is-bounded-and-a-cap-pauses.md)).
The timing constants are pilot settings, each an environment variable.

## Context

The ctf12 runs (Belka `s10d40e`, c10 `sae6e7d`, c09 `se5fdcd`) measured five
weak spots in how the seats shared work and ended it:

- **Opening.** Ten seats named themselves within eight seconds against an
  empty board and an empty register; six took the same four questions. The
  register keyed ownership on the lead id, so two leads on one question were
  both held (Belka seqs 1–9: 15 leads opened in three minutes, 7 released
  within five, 14 `duplicate` closes over the run).
- **Hand-off.** 105 of Belka's 119 leads were held at open, 84 of them through
  `record(opens)` with `take: true`, as the prompt told the seats to keep their
  follow-ups. `needs: E-n` pointed at entries that already stood. Holds that
  ended after more than ten minutes with no job on the lead (16 in Belka,
  L-20 for 52 minutes) were in the hands of seats busy elsewhere, which the
  stale rule never reached.
- **Wakes.** A wake told three parties to claim at once and reserved nothing:
  Belka's woken seat took 16 of 30 wakes, c09's 4 of 19; 27 of Belka's 32
  refused claims came within 15 s of a wake or a reopen. On c09 a closing
  entry corrected seven times by its own author reopened its lead seven
  times, each waking an idle seat the previous holder then beat by seconds.
- **The finish.** Every seat called `done` when the last attest landed (Belka
  nine calls by six seats in 58 s; c09 all eight in 61 s); the late-posts
  rule fired once per seat and asked each to explain itself on the board,
  which made the next seat's late post; historical limiting closes blocked
  after their questions were answered (c10's 38 minutes began at such a
  refusal); every answer revision took the summary down with it.
- **Review.** The attests on four wrong Belka answers all said the candidate
  was re-derived from sealed sources: the critic did what it was told and
  never asked whether a route was untaken. A correction of a disputed entry
  silenced the dispute. An interpretation stood on an entry that no longer
  did (Belka 11 jobs, c10 6, c09 18).

And the runtime: one c09 job wrote its only output 40 s after it started and
nothing moved for 22.6 minutes until it was cancelled by hand; a regroup fired
while that job was the only route and mid-run; a job that failed "command not
found" said nothing about the image; a run past its token's validity would
have lost its provider.

## Decision

### Review and correction

1. **An attest of an answer to a question says how strongly it holds it**
   (B2): `strength: established | best_candidate`, with `answer_review`
   `{reproduced, read, parts: [{part, established, why}], inference,
   alternatives, other_family: {checked, text}}`, all inside the chained
   attestation. A medium or low confidence, a part the review holds not
   established, or a route the answer's `would_change` names that nothing
   took (a planned route of the question no job examined, named by its
   source, or a lead id that is not closed resolved, negative or duplicate)
   allows only `best_candidate`; the hub writes why (`capped`). An answer
   every review holds a best candidate is examination-limited ("a best
   candidate, not established"), never answered, and under the operator's
   stop policy it holds the run until the route is taken or the operator
   accepts its limits. A negative keeps its own review
   ([ADR 0013](0013-a-negative-is-bounded-and-a-cap-pauses.md)); an attest
   line from before strengths reads as it always did.
2. **Routes are held to their plan** (B3): besides the negative close against
   the plan (ADR 0013), an untaken planned route caps a review as above, and
   a limiting route is reviewed before it stops holding the finish (7).
3. **Agents reopen** (B4): `lead_reopen(id, expected_revision, why, take?)`,
   against the lead's revision (`rev`, the count of acts that changed it),
   history kept. Refused over the operator's restrictions (a lead the
   operator closed, one closed `withdrawn`, one under a withdrawn, excluded
   or proposed question, one in triage, a `needs_operator` the operator has
   not answered) and for a duplicate of a lead still open. It answers no
   dispute: the ones in force on what the lead cites are named, and stand.
4. **An interpretation is bound to its entry** (B13): the `interpret` event
   carries the entry's hash; a job whose every interpretation is on an entry
   since superseded (with no correction interpreting it again) or disputed
   waits for re-interpretation, in the header, the jobs view and, for a
   material lead's job, the finish line.
5. **A correction does not answer a dispute** (B18): a standing dispute is in
   force on the correction that stands in its entry's place
   (`disputesInForce`, `inherited_from`) until its disputer withdraws it,
   naming either entry. Answers resting on the correction, coverage records
   naming it, leads closed on it and the gate all read it so.

### The finish (A4)

6. **One coordinator.** `leads/finish.jsonl`, a chain with the lead
   register's helpers, holds a lease: `{holder, generation, report}`. The
   first seat whose `done` asks for the finish designates it: the report's
   last publisher (its newest revision in `history/`) when that seat can
   hold it, else the seat asking. A holder that is done, dead, compacting or
   silent past the stale limit with no job running is unavailable, and the
   next seat's `done` takes the lease over at the next generation (and says
   so on the board). Any other seat's `done` returns "not yours", quietly: a
   `done_deferred` trace row, no board post, no finish line, not a refusal;
   `markDone` refuses the sentinel from it too. The sentinel is written in
   one transaction under the finish register's lock, only while the seat
   holds the lease at the holder and generation its `done` began with, and
   the seat's own done marker is written inside it: a coordinator taken over
   while its checks ran does not end the run, and nobody takes over once the
   sentinel exists. An agent's own cap, an
   abandon vote and every done once the sentinel exists are not the finish.
7. **A route lead stops holding the finish only when it no longer matters.**
   A material lead closed deferred, infeasible or `needs_operator` keeps its
   disposition; it limits the run until every question it names is disposed
   under the bar (answered, or accepted by the operator) and either another
   seat (not its closer or holder) holds its limitation no longer material
   (`route_review(id, material: false, why)`, bound to that close) or the
   operator accepted every question it names. A lead that names no question
   needs the review; a new close needs a new one.
8. **Readiness, continuously.** For every state revision the registers say
   whether the finish is ready: no material lead open or waiting for a
   closure's confirmation, no lead's job uninterpreted, the ledger gate over
   every question in scope (and the summary and narrative the goal names)
   holding nothing, no stale answer, no addition committed and not yet
   applied; under the operator's stop policy also
   no best candidate and no route limitation. It is in every header, with the
   coordinator and what this seat does, and posted once each time it turns
   ready or back (`readiness` events). It is cheap and generic; the goal's
   own checks run only at the coordinator's done.
9. **One check result per revision.** The finish line's run is recorded with
   the revision it ran against (`check` events, the run whole), and a done at
   the same revision takes it (host and hub). The state revision covers the
   board's verdict posts, the ledger, its review, the leads, the questions,
   the report's digest (the lease's path), the shared deliverables at the top
   of `work/`, every job's state, the policy (the stop policy, the caps, a
   pause, the contract, the case policy of ADR 0014), what of each job's
   stdout its requester was handed (the bytes still unread: a page read
   after a check can add a defect, the rest read can fix one), the
   operator's decisions (the requests' chain, less a delivery claimed or a
   notification sent or failed, and the hosts allowed) and what was added
   after the kickoff (each addition committed on the store journal, and
   each applied: one committed and not applied holds the finish); the
   sentinel is written only while it holds. Readiness is read
   from its own snapshot between two readings of the revision that agree,
   and cached only then. A review's ack
   does not move it, nor does an offer's bookkeeping (an offer made,
   delivered, declined, accepted or lapsed says who may take work first,
   never what the finish rests on, and idle seats write it all the time); a
   closure offered to its closer to confirm does, since it holds the finish.
10. **The report is reviewed with typed acts.** `finish ack` (no_objection, or
    objection with why) records a review of the report's current digest and
    is not a late post. A result or veto posted after the report was written
    as the finish began, and an objection to any version of it, hold the
    coordinator's `done` until `finish resolve` answers it: folded (the
    report says it now, and where; bound to the digest it was folded into)
    or not_material (and why). They are obligations: publishing the report
    again answers none of them, and they are read again in the transaction
    that writes the sentinel, so one acked while the checks ran holds it.
    Reading it is not answering it. The once-only "late posts" refusal
    addressed to every seat is gone.
11. **A summary cites questions symbolically.** A summary or narrative that
    names `Q-<n>` binds each to its answer's fingerprint (the result, the
    question revision, the hashes of its support, contrary evidence and
    limitations); a reworded correction keeps it standing, a changed support
    takes it down, and a question withdrawn or re-scoped since is a gate
    defect. The answer's contrary evidence is held to its current standing
    as its support is: an entry it weighed that was corrected (and the
    correction not weighed) or disputed since takes the answer down, and
    the summary with it. The answer it names this way is not also held by
    its seq.

### Coordination (A1–A3)

12. **The coverage check at open and claim** (A1). `answers` is the
    load-bearing check: a `take` whose questions meet another seat's held
    lead is opened unheld and names the holder, unless it says `overlap:
    second_route | verification` with `overlap_why`; a claim of such a lead
    needs the same. `objects` are hints only, and so is the admission of a
    job under a lead (who else works its questions, its objects, or declared
    the same objects in a running job). A lead left unheld as a second route
    is not offered to an idle seat.
13. **Staggered first choices** (A1). When the kickoff says so (budget.json
    `coordination`, on by default: 20 s a seat, 90 s in all;
    `SWARM_FIRST_CHOICE_STAGGER_SEC=0` turns it off), a seat's first choice
    (its first lead opened or claimed, or its first name) waits until the
    seat before it has chosen or 20 s after that seat's turn, dead seats
    skipped, never past the bound, and comes back with the register's
    coverage as it stands then.
14. **Stable names, labels from leads** (A1). A seat's name is kept once
    given; a later `name` updates what it says it is doing. Its label in
    `list_team` is its name and the leads it holds.
15. **Hand-off** (A2). A standing entry is refused as a need (it is where a
    lead comes from); a dropped need says why and is withdrawn, never met;
    a need's outcome is satisfied, pending, failed, or invalidated (it was
    met and what met it no longer stands). `lead_open(consumer: L-n)` opens a
    prerequisite and links it in one act, the whole graph as it would stand
    checked first so a loop is refused before either event; the product
    contract is
    `product`, `acceptance`, `inputs`, `next_action`, and `result_refs` at
    close. `record(opens)` opens unheld (and the prompt says so);
    `lead_handoff(id, why, to?)` offers a held lead to a named seat or the
    one idle longest. A held lead with no job and no act on it for ten
    minutes (`SWARM_LEAD_PARK_SEC`) while its holder works elsewhere (shown
    positively: an act on another lead, or a job under one, since; a seat
    analysing its only lead in the foreground is working it) is
    parked: shown to everyone, offered to an idle seat, kept by the
    holder's own `lead_claim`, taken over at once by the seat offered it. A
    seat whose held leads all wait on needs counts as idle. This replaces a
    per-seat cap on held leads, which the data showed would almost never
    fire and would not reach the holds that mattered.
16. **Offers** (A3, `extensions/offers.ts`). A wake, a hand-off, a parked
    lead, a reopen after the operator's note (offered to the previous
    holder first) and a closure to confirm are offers of a lead; a person's
    question's offers (the suggested seat first, then the most suited idle
    seat) run through the same state machine. First claim for
    `SWARM_OFFER_SEC` (60, three times the slowest accept measured) from
    delivery (the seat's wait or header records `offer_seen`), never past
    the offer's age bound (`SWARM_OFFER_MAX_SEC`, 300); accepted by the claim
    it reserves (`offer accept` for a question holds it one more window),
    declined with why (`offer decline`, passed on at once), invalidated by
    any revision of what it offers, lapsed by time; all of it derived from
    the chains and the clock, so a restart finds it as it was. Seats that are
    done, dead or compacting are never offered anything, and a seat with an
    offer standing in either register is offered nothing more (read again
    under the registers' lock for each offer, and across a batch of
    deliveries). A person's question offered to a seat holds against every
    way of taking its work: an open with take, a claim, a reopen with take.
17. **Confirm or reopen, never re-point** (A3). When a closed lead's entry is
    superseded (not disputed) and its closer can take it, the closer is
    offered to confirm the closure on what stands now (`lead_confirm`, by
    revision, with the ref and why); declined or unconfirmed it reopens, and
    a dead or compacting closer's lead reopens at once, whether the closer
    was so before the offer or became so after it. A same-author
    correction can reverse what a closure rested on, so nothing re-points it
    by itself. A closure waiting for confirmation meets no need and holds
    the finish.

### Runtime

18. **Running-job visibility** (B11, `scripts/job-telemetry.ts`): three
    signals sampled on the host every half minute and at `job_status`: the
    output directory's metadata (files, bytes, the newest name sanitised, no
    link followed, the walk bounded and said so), the logs' sizes, and CPU
    and I/O from msb's metrics for the worker VM, else a heartbeat the worker
    script writes every 15 s from the VM's own `/proc` counters. "Suspected
    stall" only when all three are still for `SWARM_JOB_STALL_SEC` (600) and
    the job is not within two minutes of its timeout; "quiet" when it works
    without writing; "unknown" without CPU and I/O, or when they are not
    current (a heartbeat whose stamp stopped advancing, a sampler more than
    two minutes behind); stillness is never counted across a gap between
    samples. Metadata only, not sealed
    and not citable; the hint says cancelling keeps what the job wrote;
    nothing is cancelled for anyone. `job_status` carries it, and the header
    names a seat's own suspected stalls.
19. **Progress clocks** (B12). When nothing has moved and a job runs under a
    lead, the first regroup is a nudge to that lead's holder with what the
    job is doing; a window later everyone is asked, job or not; with no such
    job, everyone at once as before.
20. **A missing program** (B17): exit 127, or a shell's own diagnostic
    ("X: command not found", zsh's "command not found: X", dash's "sh: 1:
    X: not found" with exit 127), is recorded as `program_missing` with the
    profile and image (a journal line, the job record, its reason,
    `job_status`) and shown in the console's job detail. An application's
    own "X: not found" (a file or an object it looked for) is not one.
21. **Credential renewal** (B10). Verified against a running microVM on msb
    0.7.2 (`tests/vm-secret-rotation.test.ts`, `npm run test:vm`):
    `Sandbox.modify({secrets: {NAME: {value}}})` plans the rotation as
    `rotated`, disposition `live`, applies it with the VM running, and the
    guest keeps its placeholder. `vm.ts renew-secrets` mints the seats'
    subscription tokens again at half their validity and rotates each seat
    VM's secret in place, only secrets the VM holds (never adding one) and
    only where the dry run says live; the watchdog runs it every ten
    minutes, paused or not (`secrets_renewed` on the trace, no value
    anywhere). The minted validity (12 h for an operator-stopped run) stays
    the window each token covers.

## Consequences

- A run has one closer, and a finish that waits on a compacting or dead seat
  is taken over by the next done. The tail from "every question answered" to
  the sentinel should be the coordinator's review of what is late, not a
  round of refusals.
- A best candidate is said to be one, in the ledger, the check and the
  finish; a run that ends on one is examination-limited, never completed.
- Offers make "the woken seat got first claim" a native measure (offer,
  offer_seen, the claim that names it, decline, lapse), as are hand-offs,
  parked leads, confirmations and `done_deferred` (WP7's metrics read them).
- Two leads on one question need a stated reason to both be held; a second
  route left for its opener waits unheld and is not offered around.
- The console shows a job that needs a program its image lacks, and on the
  Leads tab the finish (ready or what holds it, its coordinator, the last
  check, what is late), the parked leads, and on each lead its standing
  offer, a closure waiting for confirmation, a second route with its reason
  and its product contract; `swarm.sh lead <run> list` says the same. The
  agents see the finish, the parked leads and their own stuck jobs in the
  header.
- Existing runs read as they did: legacy `wake` events are offers, legacy
  attestations hold as established, a lead without `rev` gets one from its
  events, and a run with no finish register has no coordinator until its
  first done.

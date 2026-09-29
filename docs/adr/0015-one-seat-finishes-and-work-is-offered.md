# One seat finishes, work is offered, and a review says how strongly it holds

A run's finish is one seat's: a coordinator holds it by a lease that knows
when its holder is compacting, every other seat's `done` is answered "not
yours", readiness is shown to everyone and posted when it turns, one check
result stands per state revision, and the report is reviewed with typed acts
rather than late posts. Work that nobody holds is offered to one seat at a
time, from when the offer reaches it, and a closure whose entry was corrected
is offered back to its closer to confirm or reopen, and re-pointed only
when the correction leaves every part of its conclusion unchanged. A
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
   holding nothing (an entry citing a cancelled or stopped job's kept output
   with no word on it included, ADR 0016's partial_output), no stale answer,
   no addition committed and not yet applied; under the operator's stop
   policy also
   no best candidate and no route limitation. A disposition that only
   limits the run (partial, not determinable, a bounded negative, an
   acceptance) never holds it, under any policy: the done ends the run
   examination-limited on it (the finished c10 pilot's readiness held on
   "question:5 is not determinable" to the end, and its register read
   "never ready" while the coordinator's done passed). A done that passes
   while readiness has not turned ready records the ready state itself,
   in the transaction that writes the sentinel (`at_done`), so the tail
   from readiness is measured and the disagreement is on the record. It is in every header, with the
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
    addressed to every seat is gone. A review made before any done has
    named the report names it itself (the c10 pilot's objection to a stale
    line in the report was refused for want of a done, and lost), and holds
    the done that names the same report. The first readiness state is
    recorded (not posted when not ready): the register exists from the
    first header, where the metrics and the report read it.
11. **A summary cites questions symbolically.** A summary or narrative that
    names `Q-<n>` binds each to its answer's fingerprint (the result, the
    question revision, the hashes of its support, contrary evidence and
    limitations); a reworded correction keeps it standing, a changed support
    takes it down, and a question withdrawn or re-scoped since is a gate
    defect. The answer's contrary evidence is held to its current standing
    as its support is: an entry it weighed that was corrected (and the
    correction not weighed) or disputed since takes the answer down, and
    the summary with it. The answer it names this way is not also held by
    its seq, and an answer it cites by its seq is bound to its question the
    same way (the c10 pilot's summary and narrative cited answers by seq
    and fell with every revision of each).

10a. **The finish phase** (the c10 pilot, s6be12f: its tail ran past
    ninety minutes). While a coordinator holds the lease and the registers
    are met but for what is late, confirmations or resolutions, the finish
    is being assembled: another seat's answer revision is recorded only
    with `material` (why it changes a conclusion), a rewording is refused
    quietly and not counted as a refusal, a material revision reopens
    readiness as ever, and the coordinator's own folding is free. The phase
    is recorded in the finish register and shown in every header and the
    operator's list. A result post that only restates its author's own
    revision is covered by the revision, not a late item.

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
17. **Confirm or reopen; re-pointed only when the conclusion is unchanged**
    (A3). When a closed lead's entry is superseded (not disputed) by a
    correction that changes no conclusion, the closure is held on the entry
    that stands and recorded `repoint (conclusion unchanged)`. For an
    answer, no conclusion changes when its kind, result, question revision,
    inconclusive and asserts_absence are as they were and its value is the
    same up to case, spacing and closing punctuation. For any other kind,
    only what it cites and how a reader checks it may change (refs,
    evidence, source, reasoning, because, locators, qualifies, the hub's
    method, and the record's bookkeeping: `REFRESH_FIELDS`); every other
    field (the value exactly, a time and its clock and precision, what a
    finding indicates and its confidence, an attribution, a hypothesis's
    status, a search's completion, sensitive) is its conclusion. The
    Fable review of the batches found the first rule applied to every kind,
    which re-pointed a closure unasked when an event's time moved twelve
    hours or a hypothesis turned refuted. Astra's
    objection was to re-pointing when the basis can reverse, which a change
    of conclusion is. Otherwise, when its closer can take it, the closer is
    offered to confirm the closure on what stands now, one offer per seat
    and correction chain (the batch, its head E-<seq>, confirmed in one
    `lead_confirm`; the c10 pilot re-offered four to six confirmations for
    one revision near its finish, several to one seat), or one lead by
    revision, with the ref and why; declined or unconfirmed it reopens, and
    a dead or done closer's lead reopens at once, whether the closer was so
    before the offer or became so after it. A compacting closer is away, not
    gone: the confirmation waits for it, bounded (five minutes past the
    compaction's start, `SWARM_CONFIRM_COMPACTION_HOLD_SEC`), the offer made
    again when its window ran out meanwhile, and reopens past the bound. The
    review of WP4 had a compacting closer reopen at once (finding 11); on
    the c10 pilot (s6be12f) L-17 was reopened three times so, each time its
    closer began compacting as the offer arrived, and the seats woken for it
    declined it ("its author should confirm"). A same-author
    correction can reverse what a closure rested on, so nothing re-points it
    by itself. A closure waiting for confirmation meets no need and holds
    the finish.

17a. **Reviews are offered** (the c10 pilot, s6be12f: six seats did a
    route review of one deferred lead within minutes, one of them twice).
    A limiting lead's route review, once its questions are answered or
    accepted, and a material negative's review are offered to one eligible
    seat (never its closer, holders or authors, never one compacting or
    with an offer standing; the relevant first). A route review is bound to
    the answers it saw: an answer recorded again asks for a new one.
    Another seat's review of an item reviewed or offered to another is
    answered quietly with who has it and records nothing; a second,
    independent review says why it adds something.

17b. **A review offer is held for the review, names what the gate
    counts, and is withdrawn once it is not needed** (the finished c10
    pilot, s6be12f: of eleven negative-review offers one was taken up,
    five declined and five had no outcome). A review's first claim was
    the lead offer's minute from delivery, and accepting it recorded
    nothing, so the offer passed to the next seat while the one that took
    it was still reviewing: E-220's went from s01 to s05 to s04 within two
    minutes, and s05's review of E-266 was deferred to the seat the offer
    had moved to while three more seats declined in s05's favour. `offer
    accept` on a review now takes it (`offer_take`): it holds for
    `SWARM_REVIEW_HOLD_SEC` (600), and the seat declines it to pass it on.
    The review its seat records takes up its own offer even after that
    offer ran out, and another seat's standing offer of the item is
    withdrawn (`offer_withdraw`). Before anything is offered the register
    withdraws each standing offer whose item needs no review any more (the
    answer superseded, as E-219 was seven seconds after its offer;
    reviewed by any route the gate counts; a route reviewed) and records
    as lapsed each that ran out. What is offered, and what the header's
    negative bar lists, is what the finish gate holds: a negative by the
    gate's own test (a premise rejected on a search alone is one), its
    review counted where the gate counts it (the answer while every
    coverage record it rests on stands, and each standing record), named
    in the offer ("attest E-220 or its coverage record E-218 … not
    answer_review": both reviewers of the pilot first sent the answer's
    review shape); one resting only on records that no longer stand is not
    offered, since no review of it would count. The metrics count a
    coverage record reviewed as the gate does: on the record, or through
    the negative answer resting on it.

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

## After the run s9722fa

A CTF case of six goal questions under `--stop operator`. Every question
had a partial answer with medium confidence, resting on findings and
citing the limitations that bounded what it left open. Each review was
capped to best_candidate (1): by the answer's medium confidence, and by the
parts the answer itself declared open, which the reviews held not
established. Readiness (8) then held all six as "a best candidate, not
established", under the operator's stop policy, while the answers check
disposed each one partial (its best-candidate test applied only to an
answer it found answered) and the finish gate agreed with the check. The
coordinator read the finish status as "all six partial answers with a
best_candidate attest are not under the bar; best_candidate is not a
disposition", and the seats revised every answer to not determinable with a
downgrade, moving their standing findings into the reasoning (ADR 0013,
"After the runs s9722fa and sb1b3c8"). The case lost every positive answer.

- **"A best candidate" concerns only an answer that claims established.**
  An answer claims established when its result is established, or when it
  was recorded before results and is not inconclusive
  (`claimsEstablished`). It is held as a best candidate when it claims
  established, another seat reviewed it, and every review holds it a best
  candidate only (`heldAsBestCandidate`). A disposition that only limits
  the run (partial, not determinable, a bounded negative, out of scope) and
  a premise shown not to hold are each held to their own bar, never to a
  strength, whatever their reviews say. Readiness, the answers check (and
  through its machine line the finish gate) and the report read this one
  test, so they cannot drift again.
- **A best candidate holds readiness under every stop policy.** It has no
  disposition, and the done has refused it under every policy since the one
  rule (ADR 0013, "The end of a run"); readiness held it only under the
  operator's, so a cap-policy run could turn ready on a best candidate that
  the coordinator's done then refused. It holds readiness now wherever it
  holds the done; a route limitation still holds readiness only under the
  operator's (8). This supersedes "under the operator's stop policy" in 1
  and 8 for a best candidate.
- **A partial answer's review attests the answer's own claims.** A partial
  answer claims some parts established and declares the rest open; its
  review says whether both hold. A part the review holds open as the answer
  declares it names the entry by which the answer declares it:
  `answer_review.parts[].declared_open`, `E-<seq>` of a limitation the
  answer cites or a coverage record it rests on (`declaredOpenBy`), checked
  when the attest is written and kept in the chained attestation. Such a
  part does not cap the review; neither does the answer's confidence, nor a
  route its `would_change` names, which is how its open parts would be
  settled and which the answer already says are open. A part it claims
  established that the review does not hold so still caps it, and the
  refusal says that is a dispute or a best_candidate attest. A
  `declared_open` on an answer that is not partial, or naming an entry the
  answer does not cite so, is refused. An answer that claims established
  keeps the whole cap (1), and out of scope and a premise shown not to hold
  keep it too, though a best candidate on them holds nothing. The attest's
  reply says so: on a disposition, a best candidate "holds nothing".
- **Said where the seats read it.** The worker prompt, the SWARM.md
  template, and the `attest`, `record`, `finish` and `done` descriptions say
  that partial is a disposition, that a review of a partial answer checks
  the parts the answer claims, that "best candidate" concerns only an answer
  that claims established, and that a standing positive finding is never
  discarded to make an answer not determinable. Readiness names a best
  candidate as one that claims established.

## Preparing the finish

Added 2026-09-29 (the limits spec, item 3; the Plan 3 brainstorm, L6: Astra
F1 and F2, Fable L6-A in part).

Every first done of the three runs of 2026-09-29 (s993d40, sa2f2f2,
s5764c4) was refused on items late against the report: 4, 5 and 15. The
code made it so. What is late is read against the lease's boundary
(`lateItems`), so `finish status` listed nothing before a lease existed;
only `finishTurn`, a done, made the lease; and only the lease's holder could
resolve (`resolveLate`). Showing the list in status could not have helped.
The coordinator then resolved each item in a call of its own: 4, 6 and 15
calls before its next done. On s5764c4 those 15 calls took 71 s, a result
posted in them refused the second done and another the third, one item
each.

1. **`finish prepare`.** After drafting the report, the coordinator
   prepares the finish (`report`: its path). The lease and the report's
   boundary are taken exactly as a done takes them (one function,
   `takeLease`): a first lease goes to the report's last publisher when it
   can hold it, else to the seat asking; an unavailable holder is taken over
   at the next generation; a report named anew is kept on the lease. No goal
   check runs and no sentinel is written. The answer is readiness (with the
   answers check's warnings) and every item late against the report, whole,
   with the lease's generation and the report's digest, and a `prepare`
   event records it (generation, report, digest, boundary, readiness, and
   the items it listed by kind and id). Another seat's prepare is answered
   "not yours", quietly, as its done is. A prepare is refused while the
   report does not exist.
2. **The boundary forgives nothing.** It is the report's write time when
   the finish was first taken, never the time of a prepare, so calling
   prepare late manufactures no clean boundary. A prepare again, a report
   published again and a takeover keep the earliest one (6 and 10 above):
   what was late stays late until a typed resolution names it.
3. **A resume opens a new segment.** The finish register is append-only
   and outlives a resume; the old boundary would make every result of the
   continuation late. The first prepare (or done) after a resume
   (`budget.json` `resumes`) opens the new segment: designated as a first
   lease is, at the next generation, with the report's time then as its
   boundary, and every post that was late against the report when the run
   was resumed and that no resolution answers is carried on the lease by
   name (`segment`, `carried`). An objection needs no carrying: it holds
   until it is resolved, whatever the boundary. A post of the
   continuation's written before its report is its own work, which that
   report answers. The fields are versioned: a run from before reads, and
   hashes, as it did.
4. **Batch resolve.** `finish resolve` takes `items` [{post or ack, how:
   folded, where} or {post or ack, how: not_material, why}], each with its
   own words, the coordinator's `generation` and the report's `digest` it
   read (from prepare or status), and an idempotency `key` (when none is
   given, the batch's own content names it). The batch is validated whole
   under the finish lock, then one ordinary resolution event is appended per
   item, each carrying the key, the generation and the digest; a folded
   item names the version it was folded into, as before. A stale generation
   or digest, or any item that is not late (resolved already, never late,
   named twice), refuses the whole batch with the exact stale fields, each
   item's problem and every id still unresolved, and records nothing. The
   same batch sent again under its key by the same seat (a retry after an
   interruption) is answered with what was recorded and what is still late:
   nothing twice, nothing hidden. Another batch under a key used already is
   refused. There is no blanket "all resolved": a bulk call proves the
   accounting, and each judgement stays attributable and reviewable. The
   one-item form stays.
5. **What stays.** `finishTransaction` is unchanged: the lease and what is
   late are read again in the transaction that writes the sentinel, and the
   state revision the checks ran at must still hold, so a veto, an
   objection or an evidence addition racing the done still refuses it. No
   quiet period holds evidence admission, and no all-seats acknowledgement
   is required. The finish phase (10a) turns assembling on the same
   condition as before, the registers met, whether the lease came from a
   prepare or a done.
6. **The order, said where the seats read it.** The prompt and the
   `finish` and `done` descriptions: draft the report, prepare, resolve the
   late items in one call, invite the report's review (`finish ack`), then
   done. The done's late refusal, the coordinator's header and the
   readiness post name the batch, its generation and its digest.
7. **Not built: covering a late post by the report's reach** (Fable L6-A,
   a result whose cited entries the report's standing answers already
   reach, recorded covered with no coordinator act). Republishing does not
   show a caveat was weighed, and an entry already cited can carry a new
   objection (Astra, round 2). Only prepare and the batch are built, and
   the first-done refusals are measured.

**Measured.** The metrics' finish block counts the first done and whether
it was refused on late items, every late refusal, the finish tool's calls
by act (prepare, resolve and how many carried items), the resolutions,
batches and checks, and the tail from ready with every seat's tokens, so a
refusal renamed into more calls cannot pass for a gain. Replay reads the
prepares, the batches, the lease's segment and what it carries.

On the three runs, replayed values-free with each run's registers cut to
its first done (posts written after it removed, the finish register cut
after the lease that done took, the ledger, attestations, leads and
questions cut to its time): a prepare there lists exactly the items the
done was refused on (4, 5, 15). The finish line on the cut registers is
not met on s993d40 and s5764c4 (the answers check), so their first done
would still be refused, by the finish line (their later dones were so
refused, 6 of 7 and 8 of 10 checks), and on sa2f2f2 it proceeds (examination-limited) with
readiness ready: sa2f2f2's is the one first-done refusal caused only by
late items. After a prepare at the first done's time, a batch composed in
the coordinator's own measured time (4.2, 17 and 11.6 s from the refusal
to its first resolution) and a done as long after it as its next one came
after its last resolution (4.6, 9.5 and 4.7 s), no result or veto lands
in that window on s993d40 or s5764c4. On sa2f2f2 one result lands 9 s
after the first done: before the batch's reply, which names it still
late. So first-done late refusals go from 3 to 0 if the coordinator
resolves what the reply names before its done, and to 1 (sa2f2f2) if a
post landing between prepare and done is left to refuse it; the refusals
caused only by late items go from 1 to 0, or stay 1, on the same terms.
s5764c4's second and third late refusals do not arise in a 16 s window.
Replay cannot show what the seats would have done under the rule: the
paired runs measure that, with the finish tail's tokens and wall time
(sa2f2f2: one minute and 2.4 million tokens from ready to the sentinel,
6 resolve calls and 2 dones; the other two turned ready only at their
done).

### A review carries over

Added 2026-09-29 (the limits spec, item 3 refinement; the c10 run sd9645b).

The finish of sd9645b took about 49 minutes over three versions of the
report: three prepares, 35 resolutions in four batches, and 19 acks, of
which 10 were a seat's no-objection review given again to a later version.
An ack was bound to the report's digest, so every version reset every
seat's review: `finish status` and the coordinator's header showed only the
acks of the current digest, and the coordinator invited everyone again.
Nothing the finish rests on required those acks; they were asked for
because a changed digest could not say what had changed. And 15 of the 33
posts resolved as late items were their author's own ack announced on the
board a moment after it was made, each a late post the coordinator had to
resolve.

1. **An ack binds sections.** `finish ack` takes `sections`, the report's
   sections the reviewer covered (a heading's number, `3`, `§3` or `Q-3`,
   or its words; none named is the whole report). The report's sections are
   read as the report body reads a Markdown document and the answers check
   numbers it: the text before the first `## ` heading (`preamble`), then
   each `## ` heading with its lines, fenced blocks skipped, a numbered
   heading keyed by its number (`reportSections`). The ack records each
   section it covered with that section's digest (its lines, heading
   included, less the blank lines that end it), and `whole` when none was
   named. The fields are versioned: an ack without them is of the whole
   report at its digest, and hashes as it did.
2. **What stands.** For the report as it is now, each seat's acks are read
   in order, section by section (`reviewStanding`): a no objection vouches
   for each section it covered at the digest it had then (a review of the
   whole report replaces what the seat vouched before), and an objection
   withdraws the vouching of the sections it names. A section whose digest
   is unchanged stays covered and the review carries over; a changed one is
   asked again, and only it; a review of the whole report is asked about a
   section added since, and about one removed (answered by a review of the
   whole report as it is). A seat asked about section 3 acks section 3
   alone, and its review of the rest stands.
3. **Recorded.** When the report's current version has acks of another
   version that were not weighed for it, a `carry` event records it before
   the next act (the header's turn, a prepare, an ack, a done): the version
   (`report`, `digest`), each seat whose review stands carried over with the
   acks it rests on and the sections they cover (`kept`), and each seat
   asked again with the sections that changed or went (`reasked`). The
   chain shows why an ack of an earlier version still counts. One event per
   version and what was weighed: acks of the version itself need none.
4. **Said where it is decided.** Prepare's reply and `finish status` carry
   the review (`reviews`: the sections, each seat's standing, the acks it
   rests on, what changed, what no standing review covers) and the
   invitation in words: whose reviews stand, and whom to ask again, on
   which sections. The coordinator's header says the same; another seat's
   header says its review stands (do not ack it again, do not post it), or
   which sections it is asked about and the ack that answers. The prompt
   and the tool's description say never to ack again a review that stands,
   and never to announce an ack on the board.
5. **What stays.** A late post or an objection keeps its per-item rule: it
   holds the done until a typed resolution answers it, whatever section it
   is on and whatever version follows. An objector's own later ack answers
   its objection only when it reviews what the objection was about: the
   whole report, or every section the objection named, so an objection to
   section 3 stands through its objector's review of section 2 alone.
   `finishTransaction` is unchanged: an objection racing the done still
   refuses it. Acks, carries included, are not in the state revision.

**Measured on sd9645b** (replay, values-free, `reviews`): the report's
three versions have eight sections each; the second changed three of them,
the third two, and the closing "conclusions and limitations" section
changed in both. Read as they were recorded, every ack a review of the
whole report, none of the 10 re-reviews would have carried over: that
section changed each time, so no review round is avoided. What changes is
what each re-review is asked for: 23 section reviews instead of the 80 the
re-reviews covered. Had each seat named the sections of the questions it
answered, 6 of the 10 re-reviews would not have been asked; each version
would still have asked two seats again (the seat whose question changed,
and a seat that answered none and so reviewed the whole report). The 15
announced acks are what the prompt's rule removes; replay cannot show
whether seats follow it, nor how narrowly they will name their sections:
paired runs measure that, with the finish tail's tokens and wall time.


## A source-first review

On Belka a wrong value was attested established by three seats, each
naming an alternative with its evidence: the rule was met and the answer
was wrong. What nothing but words had checked was that the value sits in
the bytes the review read, and that the review weighed the reading that
would make it wrong. The brainstorm of 2026-09-29 (L2) agreed: the review
starts from the question and its sources, not from the candidate; it names
the strongest rival and a test that separates it; it says where a literal
value was read (a locator the hub checks against the sealed bytes) or how
a derived one was derived; and byte presence proves presence, never
attribution or truth. Another model family is a routing preference, never
a second source.

- **The packet.** A material negative's review offer (the answers reviews
  are offered for) leads with the question as it is asked now (its
  register id, revision and words, whole), its scope (material, whether it
  asks whether something exists or for a complete set) and the original
  sources its answer's coverage records and cited entries lead back to (an
  input, an import or a capture as named, a job's output by its declared
  inputs, followed back); then the answer under review, linked by its seq
  with the entries it corrects and its coverage records, never quoted;
  then each source's broad extraction (ADR 0013), the task, the store
  sweep and the warnings. Established and partial answers are reviewed
  through attests the finish line asks for: the attest tool, its guidance,
  the prompt and the critic's fix say the same, source first. Reduced
  priming, not blindness: a seat may have read the board.
- **The review's evidence** (`answer_review`, each in the hashed record only
  when given, so an older review hashes as it did):
  `discriminator {rival, test, favours_if, outcome, refs}`, the strongest
  rival (another time, entity, mechanism or activity, or the premise not
  holding), the test, the result that would favour each, what it showed,
  and the observation or job it rests on (an E-<seq> the ledger holds or an
  object that resolves; refused otherwise); `reproduced_at [{ref, offset,
  length?, value?}]`, where each literal value it vouches for was read; and
  `derivation {job, inputs}`, how a derived value was derived.
- **The hub's checks.** A locator's ref resolves to a sealed object of the
  run (an input, a job's output or log, an import, a capture, a sealed brain
  output; never a directory or a catalogue row), and its value is at its
  offset, in UTF-8 or UTF-16LE, ASCII letters in either case; with a
  length and no value, the bytes there are read back and must be words of
  the answer. A bounded read at the offset, and 256 bytes either side to
  say where the value is when it is not there: never a scan, never the
  object's whole hash (resolving it against its manifest is the seal). A
  derivation's job is sealed and ran to its end, and each input resolves
  and is among what the job declared it would read.
- **The cap.** An established attest of an answer that claims established,
  on a material question, is recorded `best_candidate` when it names no
  discriminator that counts (a placeholder, or the rival in the test's
  words, is none), when a locator does not verify, when a derivation does
  not resolve, or when it names neither a locator nor a derivation. Each
  reason is in `capped` (codes `no_discriminator`, `locator_unverified`,
  `derivation_unverified`, `no_locator_or_derivation`), and the reply says
  how to fix each; the seat's later review that meets them is its review,
  as with the alternatives. The rule affects only claims of established: a
  partial answer's review checks its claimed parts as before, its locators
  are checked and one that does not verify is said, and nothing is capped
  for it; partial stays a disposition. A best candidate asked for is not
  capped again. The hub judges refs, bytes and sequence, never whether the
  test is good: a decoy in the evidence is in the bytes, and the
  discriminator is what weighs it.
- **Routing.** A review offer goes first to an eligible seat of another
  model family than every seat that did the work (team.json's model per
  seat, its provider's route and release tag dropped), then by relevance
  and idleness as before. A team of one family is offered as before, and
  nothing requires another family.

Replayed values-free (`swarm.sh replay`, the review rule over each recorded
established attest; the recorded strengths stand): on s5764c4 (Belka) six
established attests of answers that claim established (questions 1, 2, 3,
5, 8, 11), on sa2f2f2 two (questions 3, 6), and on sb1b3c8 three (two on
question 1, one on question 5), and the rule would cap every one of them,
for the same two reasons: no discriminator, and neither a locator nor a
derivation. The established attests of partial answers (three on s5764c4,
eight on sa2f2f2) are not capped. Had the rule held at those attests, each
of those answers would have been held a best candidate until a review
named its rival, its test and where its values were read; replay cannot
show what the reviewers would then have done. That is for paired runs:
wrong-at-established and decoy headlines against false negatives and
unsupported downgrades, with the reviewers' tokens.

## Consequences

- A run has one closer, and a finish that waits on a compacting or dead seat
  is taken over by the next done. The tail from "every question answered" to
  the sentinel should be the coordinator's review of what is late, not a
  round of refusals.
- The coordinator learns what is late from its prepare, not from a refused
  done, and answers it in one call; a done refused on late items then means
  a result, a veto or an objection really raced the finish.
- A new version of the report asks again only the reviews of what changed:
  a review carries over while the sections it covered are unchanged, and
  the finish register says so. A review of the whole report still meets a
  summary section that changes with every fold; a reviewer who names the
  sections it checked is asked less.
- A best candidate is said to be one, in the ledger, the check and the
  finish; a run that ends on one is examination-limited, never completed.
- An established review of an established claim says what separates the
  answer from its strongest rival and where its values are, and the hub
  reads those bytes; a review that does not is a best candidate, and says
  how to become one that is. Every recorded established attest of the runs
  replayed would have been capped: reviews get longer, and the paired runs
  weigh that against what they catch.
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

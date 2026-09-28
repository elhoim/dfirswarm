# The case contract says what may come in, what may leave, and what was asked of whom

A case is examined under a contract fixed at kickoff: what may leave the run
and reach outside it (the case policy of
[ADR 0012](0012-a-dynamic-network-decided-by-rules-and-made-on-the-host.md)),
whether more evidence may arrive while it goes on, and what material from
outside the original evidence may be used for. Everything the run asks of a
person is a request with a durable id and a lifecycle, committed before
anyone is told and told by its id alone. Evidence that arrives later is an
inventory revision that reopens what rested on the evidence as it was, and
material that enters from outside is recorded with its provenance and
flagged wherever answers are weighed. A gap in the evidence is reported as a
gap, never as a finding that something is absent.

Status: accepted, 2026-09-28, as Plan 3's Phase 1b (work package 3).
Designed by Claude, Fable and Astra (Plan 3, round 3: "the case contract";
Astra's and Fable's section 5 on evidence requests) and approved by the
owner with the other defaults of the plan: `standard` is the default preset,
and a request for evidence is answered "no additional input under this case
policy" only where the policy says no more evidence comes.

## Context

- An agent that needed evidence the run did not have closed a lead
  `needs_operator` with a sentence. In ctf12 the operator answered such asks
  by hand, often "no more input", which a report could read as "the fact is
  absent". Nothing recorded what was asked for, which questions it bore on,
  what it would have established, or how it ended.
- New evidence meant a new run. A calibration case's late item could be
  given only as a second set at kickoff.
- `operator-requests.jsonl` was appended to by four writers (a lead's
  needs_operator, a clarification, a network item, a stop proposal), each
  with its own id or none. The lead's append was made after the close and its
  failure swallowed (`.catch(() => undefined)`). The watchdog polled the file
  and handed the operator's notify command the whole line: what was asked,
  which may be case content, in a message that leaves the host.
- The case policy was defined and enforced for the network (WP6), recorded
  but not sealed, and silent on more evidence and material; a resume
  re-resolved it from the options it was given.
- Material the operator supplied (a statement, a policy, a question's
  attachment) had no provenance on the record, and an answer resting on it
  looked like one resting on the evidence.
- A name an agent gave itself, and what it said it was doing, could carry a
  password the run had just marked sensitive; the question register's check
  of the same kind ([ADR 0011](0011-questions-are-a-register-with-their-askers.md))
  read only standing ledger entries.

## Decision

1. **The case policy is complete, checked, recorded and sealed.** Beside the
   network fields, `more_evidence` (`no | ask | yes`) says whether evidence
   may arrive during the run, and `material_use` says, for each source class
   (`acquired_evidence`, `case_material`, `operator_supplied`,
   `external_capture`), whether it may be used as `evidence`, as `reference`
   (cited and flagged) or not at all (`none`: kept on the record, never
   citable). The presets set both (`ctf`: no more evidence; `internal`: no
   capture is material); the goal's metadata block and the kickoff's flags
   (`--more-evidence`, `--material-use CLASS=USE,...`, `--legal`,
   `--provider-retention`) override single fields. A combination that
   contradicts itself is refused before anything is written: a capture is
   never evidence of the events, a published case takes no evidence later,
   a class the policy expects cannot have no use. The policy is written to
   `network/policy.json` before the custody anchor, which holds its sha256;
   SWARM.md and the registry carry it; custody seals it by its sha256 and
   names a rewrite (`CASE POLICY REWRITTEN`, a failed check); a release binds
   it. A resume keeps the policy its kickoff recorded, and names each field
   its options would have changed. `scripts/case-policy.ts` owns it.

2. **Every request of the operator has an id, a lifecycle and a
   transactional outbox** (`extensions/requests.ts`). The record that makes
   a request is its commit, where its state already lives: a lead's `close`
   event (with its `ask` when it asks for evidence), a question's
   `clarify_ask`, a grants chain's `item`; the harness's own stop proposal is
   committed here. The request is derived from that commit and written once
   to `requests/requests.jsonl` (the lead register's hash; custody checks it
   with the same code and seals it), keyed by where it came from, with a
   durable `R-<n>`. A process that dies between the commit and the request
   loses nothing: the next reconciliation (every header, every hub round,
   the watchdog's fallback) writes it; a write that fails is said to the
   agent (`request_pending`), never swallowed. The lifecycle is `pending`
   (committed, nobody told) → `notified` (handed to the operator's targets,
   recorded after the hand-over) → `acknowledged` → `answered`, `declined`
   or `withdrawn`; each closing is read from what answers it (the operator's
   note on the lead, the clarification's reply, the item's grant or denial,
   the operator's stop) or is the operator's act (`swarm.sh requests`).
   `operator-requests.jsonl`, which every older reader reads, is rendered
   from the chain, one line per request as it stands; a run from before the
   chain has its lines imported whole at the first write.

3. **The hub fires the notifications, with ids only.** After every act that
   may open a request and on every round, the hub reconciles and hands each
   new request to the run's targets: `--notify desktop:` (osascript or
   notify-send), `ntfy:<topic>`, `mailto:<address>`, and the operator's own
   command, all kept outside the run (0600). A notification carries the
   request's id and kind and the lead's or question's id, never what was
   asked. Delivery is at least once (a crash after the hand-over and before
   `notified` sends it again, by its id). The watchdog keeps a fallback: in a
   host run it is the delivery, with a hub it runs every five minutes and
   sends only what the hub has not.

4. **The acquisition lane.** An agent asks for evidence the run does not
   have on the lead that needs it: `lead_close needs_operator` with `ask:
   {kind: acquisition, source, where, expected_value, urgency, questions,
   owner, authority_needed}`. Its stages are `requested` → `authorised` |
   `declined` → `collecting` → `received` → `validated` | `unavailable`.
   Under `more_evidence: no` the hub declines it at once with exactly "no
   additional input under this case policy": a constraint of the case, never
   a statement that the source or the fact is absent. Under `yes` the policy
   authorises it and the operator collects; under `ask` the operator decides.

5. **Evidence that arrives is an inventory revision.** `swarm.sh evidence
   <run> add PATH --why W [--for R-n] [--question Q-n]` copies the file or
   directory into a staging directory outside the run, holds each copy to
   its source's sha256 (and to an acquisition hash, `--sha256`), seals it in
   the store as `import:ev-<n>` through the existing import path, and writes
   an `evidence_added` line on the store journal with its inventory revision
   and every file's sha256 (the negative bar's inventory revision moves with
   it; calibration tells a late item by that digest). It is recorded on the
   ledger as external material of class `acquired_evidence`, with its
   provenance. It answers its acquisition (`received`, then `validated`
   against the hashes the copy was held to). It reopens what rested on the
   evidence as it was: the closed leads under the request's questions and
   the request's own lead; the answers to those questions recorded before it
   (stale until recorded again: a question register `evidence` event names
   the ledger's last entry at that moment); and the acceptances made before
   it. When the run's catalogue is on, a detect pass runs over each file.
   While the hub runs it is the store journal's writer and the act is handed
   to it. **Agent VMs keep the view of the run they booted with: new
   evidence is read through jobs** (`job_run inputs ["import:ev-<n>/<file>"]`);
   nothing is mounted into a running VM. Under `more_evidence: no` it is
   refused.

6. **Material has provenance, and is flagged.** `swarm.sh material <run> add
   FILE --why W [--class operator_supplied|case_material] [--sensitive]`, and
   a question's attachment given as a file, seal material the same way
   (`import:mat-<n>`) and record it as `external` with `{supplied_by, at,
   from, sha256, permitted_use}`; a question's attachment that is already an
   object of the run is recorded as supplied material too (the original
   evidence is not). The external lineage follows every class through the
   jobs that read it (by what they resolved and by digest) to every entry
   and answer resting on it; `check-answers`, the report and `release.json`
   name each such answer with its classes. A record that cites material the
   policy says `none` for is refused.

7. **The report says where the evidence ends.** Section 8 gains "Evidence
   gaps and acquisition requests", generated from the records, never written:
   every acquisition with its stage and outcome, and the gaps told apart as
   never collected (declined, or still open), unavailable (an acquisition or
   a limitation), inaccessible (a limitation whose reason is `failed`),
   unexamined (a limitation `not_examined`, `excluded` or `partial`, a
   coverage record that is partial or names planned routes nothing examined,
   evidence added that no job read) and inconclusive (an answer not
   determinable), each with its questions, what it bounds and what would
   close it. Section 3 lists the evidence added and the material supplied;
   section 5 marks an answer resting on external material.

8. **Sensitivity (B9).** A name, a `doing` label and a question's text, its
   reasons and hints are refused when they hold a value the run marks
   sensitive, whatever its origin: any ledger entry recorded sensitive (an
   agent's finding, an answer, material supplied as sensitive), standing or
   superseded, compared without regard to case. There is no "answer value"
   concept and no exemption for words the goal itself uses. The refusal
   names the entry, never the value.

9. **The goal's services are held to the policy (B16).** At kickoff the
   hosts and services a goal names (a URL, a host, an adapter's name, a
   denied service by its own name) are checked against the case policy and
   the adapter catalogue (tolerated when absent): a closed network, a lookup
   the policy does not allow, an adapter that needs a key not configured, a
   host no adapter reaches or the hard denials refuse, each is a warning.
   Nothing is refused: a goal may name a service the run is not to use.

## Consequences

- Nothing changes for a run that asks nothing: its policy is `standard`
  with `more_evidence: ask`, and its `operator-requests.jsonl` has the lines
  it always had, each with an id and a state beside them.
- A run from before this contract reads as it did: a version 1 policy record
  (material use as text) is read with the preset's uses and its text kept as
  a note; a requests file with no chain is imported whole the first time the
  run asks again.
- An answer resting on a capture, on supplied material or on evidence added
  later is named as such everywhere it is weighed; an examiner decides what
  it establishes.
- A declined or unavailable acquisition bounds the questions it bore on and
  is in the report's gaps with its consequence; it never becomes a negative.
- Not decided here: amending the case policy while the run goes on (a new
  run, or a resume that keeps it), mounting new evidence into running VMs
  (a job reads it), and the report's per-question chains (Phase 3), which
  will carry each question's gaps and attachments with their provenance.

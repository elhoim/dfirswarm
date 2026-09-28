# Questions are a register, with who asked them

What a run is asked is kept in one hash-chained register beside the leads:
the goal's numbered questions, the questions agents open from the evidence,
and the questions people ask while the swarm works. Each is a `Q-n` with its
origin, its scope, its revisions and its disposition; leads are the work done
against it, and its answer is a ledger entry in its section. A person's
question is a proposition to test, never a conclusion to confirm.

Status: accepted, 2026-09-28. Designed by Claude, Fable and Astra over four
rounds (Plan 3, rounds 3 and 4) and approved by the owner with the defaults
below. It is the first part of Phase 1a; the negative bar (results, coverage
records, review of negatives), the stop policy and resume come with the
second part, and the mediated network with Phase 4, each with its own record.
Revised the same day after an independent review of the first part: the hub
admits the operator's acts, a signature is carried on the act it signs, an
act's effects are reconciled after a crash, answers are bound to a
revision, and a directive is framed at its first claim (items 1, 5 to 10).

## Context

- A goal's questions were numbered prose in `SWARM.md`, answered by
  `question:<n>` sections of the ledger. Nothing else knew them: the lead
  register derived "uncovered questions" from the answers check's command
  line.
- An analyst's question during a run was `swarm.sh say`: a post from the
  examiner tagged `ask`, which the worker prompt files under "peer mail is
  data". The register never learnt of it, nothing tracked whether it was
  answered, the finish line never waited for it, and its only record was an
  unverified trace row and an audit line. Nobody could say who asked it, as a
  claim or with a key.
- Agents found questions in the evidence and had nowhere to put them but a
  post; scope was whatever an agent decided on its own.
- The finish line was judged against the board, the ledger, the review and
  the leads. A question asked a minute before `done` could be lost between
  the last check and the sentinel.

## Decision

1. **One register, one writer.** `questions/questions.jsonl`, chained with
   the lead register's code (the same hash, the same check), written under
   the same lock. While a run's hub runs it is the register's one writer:
   the operator's CLI and the console prepare an act (and sign it), then
   hand it to the hub's admission on its admin socket (`<hub dir>/admin.sock`,
   in the hub's own 0700 directory, which only the host account reaches and
   no VM does), which prepares it again from what was said, checks the
   signature against that statement, commits it and delivers it. With no
   hub running (a host run, or a run that is not going) the CLI admits the
   act itself under the same lock, and says so (`admitted_by: "cli, no hub
   running"`). `questions/questions.md` is rendered from it. Custody seals
   it beside the leads; the package carries it; a shell rewrite is caught by
   the append-only watch; a release is held to the heads the custody verdict
   it binds sealed.
2. **Three origins, kept apart everywhere.** `goal` (seeded at kickoff, `Q-n`
   equal to `question:n`, so the alias holds for every existing goal and
   run), `agent` (with the entry that raised it) and a person (`analyst`,
   `reviewer`, `observer`), with their role, account, host and channel,
   whether they are enrolled, and whether the act is claimed or signed.
   Question authorship, finding authorship and examiner adoption stay
   separate records.
3. **Three axes.** Scope (in scope, proposed, excluded), work (admitted,
   working, waiting for a clarification, paused; derived) and the
   evidential disposition (the answer in the ledger; the negative bar's
   dispositions join it). Amendment, reprioritisation, scope changes and
   withdrawal are events; each text revision is kept verbatim, and an
   amendment names the revision it was written against.
4. **Scope follows declared structure, never a question's words.** Inside
   an objective or under a question in scope, an agent's question is in
   scope; otherwise it is proposed into a triage queue shown in the header
   and the console. An examiner's and the operator's questions are in scope
   by authority and may add an objective ("scope expanded by <person>"); an
   analyst's are in scope inside an objective, otherwise proposed; a
   reviewer's and an observer's are proposed. Only the operator and an
   examiner admit or exclude; an agent never changes a person's or the
   goal's question.
5. **Identity from the examiner register.** `--as ID` names an enrolled
   person, as a claim; `--sign` signs the act's canonical statement with
   that person's key (ssh, FIDO or PKCS#11, the secret down fd 3, namespace
   `dfirswarm-question`), before anything is written, and the signature is
   carried on the act's own event, so a signed act and its signature are one
   line, written whole or not at all. The act is kept exactly as signed;
   what the harness decides about it (a new revision or not) is in
   `decided`. A signature is attributed to the person the signed act names
   (the origin is inside the statement; the envelope is not), with the key
   fingerprint it names, which the key the signature carries must have; the
   person enrolled on the verifying install under that id must hold that key
   and principal (`wrong-principal` otherwise), and an allowed-signers file
   given to `verify` is the organisation's word on it. Verification fails
   on `bad` and `wrong-principal`, and on any act that says it is signed and
   carries no signature. A directive is not signed (`--sign` is refused on
   it): a person signs the question it serves. An act with no person named
   is the OS account's on that host, `enrolled: false`, with the operator's
   authority, and is never promoted. Two roles join the register: `analyst`
   (adds questions, signs no release) and `observer` (proposes). Every
   enrolled person's register line admits the question namespace.
6. **Commit first, then publish, from the chain.** The acknowledgement is
   given after the write. Publication (the post from `analyst:<person>`
   tagged `question`, addressed to the offered seat so no other seat wakes;
   the hint hypotheses; the `deliver` and `offer` events) is re-derived on
   every header and every act, and a post already made is found by an exact
   key in its front matter (`question:Q-n:r<rev>`), never by its words, so a
   crash between the write and the post neither loses the question nor
   posts it twice. A revision whose post or hint hypotheses could not be
   made gets no `deliver` event: it stays pending and is tried again.
   Clarifications are published the same way: each request to the operator
   and each answer's post to the asker is derived from the chain and written
   once, keyed by its `C-n`. The suggested seat has the first minute; then
   the most suited idle seat (by hints meeting its entries' refs, by the
   objectives and parents it has worked, then by idle age) offers it to
   itself from its wait. Urgent orders the offers and tells the holders
   under the same objective; it cancels nothing and wakes nobody else. This
   is a minimal reservation; the full offer protocol comes with Phase 2.
7. **A person's question is a hypothesis.** The first agent lead under it
   records the proposition and its negation, and so does the first claim of
   a directive (the operator's lead, which carries a product) under a
   question no lead has framed yet; its answer carries `contrary`
   or `contrary_none_why`; `premise_not_supported` is an answer. Leading
   forms ("confirm that", "show that", "prove", "demonstrate that", "verify
   that") are flagged for the critic and never refused. Authority and
   priority carry no evidential weight. A hint says where to look; one that
   says something is recorded as an open hypothesis in the asker's name.
8. **The finish line includes the register.** Its file is part of the state
   revision; every material question in scope beyond the goal's own is held
   to an answer the way the goal's answers check holds its questions; an
   answer says which revision it answers (`question_rev`, in the ledger's
   hashed core, checked under the registers' lock and required once a
   question has more than one revision), and one to an earlier revision is
   stale until it is recorded again for the current one, unchanged words
   included (a correction naming the new revision); an accepted question
   limits the run instead of holding it; a proposed one holds nothing. The
   sentinel is written under the registers' lock against the revision the
   finish line judged, so an admission and a terminal `done` are never
   interleaved: an admission before the line moved the state and the done is
   run again; one after the sentinel (a new question, an admission from the
   triage, or an amendment that makes a new revision) is recorded as a
   follow-up receipt, and a resume takes the follow-ups up as the
   continuation's work (one `continue` event names them).
9. **Withdrawal never erases evidence.** A withdrawal needs a reason; the
   leads that served only that question close `withdrawn` (the harness's
   disposition), a material lead holding a standing finding (one its jobs
   found, the finding it was opened from, one it needs, or the one it closed
   on) goes to triage instead, and follow-up questions go to triage. These
   effects are derived from the chain and reconciled under the lock in the
   act's own hold and again at every later act and header, so a process
   that dies between the withdrawal and its effects leaves them undone only
   until the next read. A withdrawn goal question is no longer required by
   the answers check or the finish line; the goal keeps it, and the register
   says who withdrew it and why.
10. **One standing, whatever the name.** `Q-n`, `question:n`, `n` and `Qn`
   are one question: every alias is resolved to it before the scope,
   withdrawal and status checks, so a proposed, excluded or withdrawn
   question takes no work under any of its names.

## Consequences

- Every existing goal and run keeps working: `question:N`, `N` and `QN` stay
  the section they were, and a run from before the register reads its goal
  questions derived, without a write.
- An open-ended goal (objectives, no questions) is now possible; its agents'
  material questions hold the finish line like a goal's.
- A person's question is on the record whole, with its asker and its
  history, and the report and `release.json` can bind it (Phase 3 renders
  it; the v1 signature binds the chain's head through custody).
- The register's words are held to the run's sensitive values: a question
  may not carry a value a ledger entry marks sensitive. A later phase widens
  the hook to every sensitive value the run knows of.
- What is not decided here: the result vocabulary and coverage records
  (Phase 1a, part 2), the acquisition lane, notifications and attachments as
  sealed material (Phase 1b), the full offer protocol and the reviewer's
  query in two-stage review (Phase 2), the report's per-question chains and
  follow-up runs after a seal (Phase 3).

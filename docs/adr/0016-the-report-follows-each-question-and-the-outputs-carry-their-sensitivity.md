# The report follows each question, and the outputs carry their sensitivity

A report is read question by question: who asked it, in whose words, what
was done to answer it, what that found and what speaks against it, what the
operator accepted, and what it cost. The report now leads with exactly that,
one chain per question, and keeps every register event behind it in an
appendix where each disposition can be reviewed. The outputs a run makes
carry their sensitivity from the moment they are sealed to the package that
hands them over. The code agents wrote into jobs is ranked for the library,
and the library says what it reads, so the next agent is told of a tool
before it writes one.

Status: accepted, 2026-09-28, as Plan 3's Phase 3 (work package 5). Designed
by Claude, Fable and Astra (Plan 3, rounds 3 and 4: B8, B14, B19, B20; the
report per question with the analyst's attribution) and approved by the
owner with the other defaults of the plan: agent-written tools are folded
into the library after they are generalised.

## Context

- The report told the investigation's history as a list of leads by the
  finding that opened them, and the answers as blocks in §5. A question an
  analyst asked while the run went on (ADR 0011) had its asker, revisions,
  clarifications and acceptance on the register and nowhere in the report;
  a question that was proposed, excluded or withdrawn was not in it at all.
  In ctf12 c09 closed 60 leads negative: listed one by one they buried the
  few that carried the case.
- `release.json` bound the register only through the custody verdict's
  seal: nothing in a release said who had asked the questions it answered,
  or which of them were signed.
- A job whose result was a secret (a key the evidence held, read out of an
  artefact) wrote it like any other job: the value sat in its outputs, its
  stdout, in a job that read it, and in the board post that quoted it. The ledger's `sensitive` covered
  what an entry said, not what a job made; a package scanned only for
  sensitive entries' words.
- A job cancelled half way keeps what it wrote (ADR 0010). A finding citing
  it had to say so (`qualifies`); an event, an indicator or a hypothesis
  citing it did not, and nothing held the run to it.
- In ctf12 nearly all new code lived in one-off command jobs and `make_tool`
  was used once. In Belka the mobile readers in the library went unused
  while agents wrote their own parsers for the same databases.
- The operator requests' chain was sealed by custody but held to that seal
  nowhere: custody-verify, an earlier verdict and a release all passed over
  it.

## Decision

1. **The report's first layer is the question.** §1 is one screen: every
   question with its standing, who asked it, its answer by number, its
   leads by disposition, the operator's acceptance and its tokens. §2 then
   follows each question from who asked it to what it cost: its origin (the
   goal; an agent, with the entry that raised it; a person, with their name,
   role and whether the act was claimed or signed), why, every verbatim
   revision and the neutral formulation, hints, attachments with their
   provenance (the material record or the external entry that holds it),
   clarifications and their answers, signed acts, the proposition its first
   lead tested and its negation, its leads, the coverage records that name
   it, the result with its contrary evidence (or why none) and whether it is
   stale, the acceptance and whether it still stands, its evidence gaps, and
   its cost. The questions are grouped as the goal's, asked during the run,
   emergent, proposed and not admitted, excluded and withdrawn, each group
   with why it matters to a reader; then every question in scope that no
   answer settles. §5 keeps each answer's eight steps; §2 links to them.
2. **Negatives are counted in the body and listed in the appendix.** A lead
   closed negative is counted where it falls (in §2 and in §4's history)
   with how many were quick and how many nobody reviewed, linked by id; a
   duplicate is footnoted. **Appendix F** holds the whole register: every
   question event (seq, time, who, what, the act and the harness's decision
   whole), every lead with every event, and every disposition with who made
   it, what it cites and whether another agent attested or disputed that.
   The full report places F after its own D (custody) and E (artifacts).
   Nothing is shortened anywhere: long content is in the appendix, whole.
3. **Cost is attributed by holding, and said to be.** A model call says
   nothing of the question it served. The report gives each call the
   gateway recorded (input, output and cache tokens) to the leads its seat
   held at that moment, split evenly, and each lead's share to the
   questions it names, split evenly; a call made while the seat held no
   lead goes to no question and is shown on its own line, so the figures
   add up to the run's total. A run with no gateway (a host run) spreads
   each seat's total over its tool calls on the trace and calls the result
   an estimate. The report prints the method whole beside the figures.
4. **A release binds the register.** `release.json.questions` carries the
   length and head the custody verdict sealed, the questions those events
   opened by origin, every person who asked or acted (enrolled, claimed or
   signed, with their questions), and the events recorded after the
   verdict, which the next release binds. Verification holds the chain here
   to that head and recomputes what the release says of it. A register never
   written is bound as empty, with the goal's questions as a reader derives
   them.
5. **The operator requests are held to their seal.** Custody-verify names
   the operator's acts on requests after the stop as following the sealed
   line and a sealed line changed as a drift; an earlier verdict holds the
   chain as a prefix; a release verifies it with the other registers; a
   draft or an adoption checks the network's chains and the requests as
   custody sealed them.
6. **Sensitive outputs.** `job_run(secret_output: true)` marks every output
   the job seals sensitive, on its `job_committed` line (the record) and its
   `job.json`, without reading the bytes. A job whose declared scope reaches
   a sensitive output (by its path, by the digest of one of its files, or a
   catalogue generation a sensitive job made), or, with no scope declared,
   whose command, arguments, source or targets name the sensitive job, is
   sealed sensitive too, as derived, with the jobs it came from; derivation
   carries through chains of jobs. An entry whose refs reach a sensitive
   output (a job's file or log, a digest, a member of such a generation) is
   recorded sensitive by the hub, and told so: from then on B9 holds names,
   doing labels and questions to its words, and redaction takes them out.
7. **The package scans the whole manifest and names what it withholds.**
   `swarm.sh package --redact` withholds every sensitive output and its
   job's stdout and stderr whole, each replaced by a line naming its
   sha256 and why, lists them in REDACTIONS.txt and REDACTIONS.json with
   the sensitive jobs and the entries treated as sensitive (marked, or
   citing a sensitive output), and scans every file of the package, not only
   the report, for the sensitive entries' words and for the whole text of
   each small sensitive output (at most 256 bytes, one line, shaped like a
   secret rather than a status word), which it also takes out where it
   stands. A package made without `--redact` takes nothing out: it writes
   HYGIENE.json naming the sensitive entries, the sensitive outputs and
   which of their files it carries, with the same scan's hits, and says to
   hand it over with `--redact`. The export's `--redact` treats an unmarked
   entry citing a sensitive output as sensitive.
8. **A cancelled job's output needs a disposition.** An entry that cites
   the kept output of a job that was cancelled or stopped, and does not say
   in `qualifies` how it treats what the job wrote before it was stopped, is
   a gate defect (`partial_output`), fixed by the entry (a correction with
   `qualifies`, or resting on a job that ran to its end), never named away
   by a limitation. A limitation, a search recorded partial or failed, and a
   coverage record (whose own fields say what was covered and what failed)
   are their own disposition.
9. **Tool harvesting.** `swarm.sh tools <run> --candidates` takes the code
   out of every agent's command job: each heredoc, each inline `-c`/`-e`
   script, the command itself, and each script of the agent's own the job
   declared and ran (held to the snapshot's sha256 it read). A script of
   `--min-lines` (20) or more is a candidate; the same text run by several
   jobs is one candidate, its reuse the distinct jobs after the first;
   candidates are ranked by lines times jobs. Each carries its job ids,
   seats, image profiles, statuses and lines, and the library tools that
   may already cover it (the script names one, or one's `use` matches what
   the jobs declared). Every script is written whole beside the run with
   `candidates.json` and a `README.txt`. Folding one into the library is the
   maintainer's work, described in tool-library/README.md.
10. **Library visibility.** A tool's manifest may say what it reads in
    `use`: `extensions`, `magic` (bytes at an offset, as hex) and `names`
    (with `*`). When a command job declares its inputs, the hub matches each
    file's extension, first bytes and name against every tool of the run (a
    manifest without `use` by its description naming the extension as a
    word of its own) and puts the matches in the admission's answer, as a
    hint: never a refusal, and never a tool the command already runs. The
    library's readers say what they read.

## Consequences

- A reader finds a question's whole story in one place, the analyst's
  question with its asker and its words as they were written; the register
  behind it can be reviewed event by event.
- A report of a run with thousands of lead events is longer, in its
  appendix; the body is shorter, the negatives counted rather than listed.
- The cost per question is an attribution by holding, not a measure: a
  seat reasons about everything in its context at once. It says where the
  tokens went while each question was held, and how much went to no
  question at all.
- A secret found by a job stays out of what is handed over without anyone
  having to find each copy: the job, the jobs that read it, the entries
  that cite it and a post that quotes a short one. A secret written in
  prose by an agent, with no entry marked and no output marked, is still
  the author's responsibility (the worker prompt says how to write about
  one).
- Existing runs render as they did, with their questions derived from the
  goal; a release made before this binds no `questions`, and verifies as it
  did.
- Not decided here: which candidates of the ctf12 round go into the library
  beyond the three already folded (the owner's), and whether the hint
  changes what agents do (a calibration question).

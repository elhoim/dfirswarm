# Agents compact their own context

A swarm agent decides when its context is summarized, hands the next version
of itself a note, and does so against a ceiling the harness sets per model.
Pi's own compaction stays as the safety net, never as the plan.

## Context

Every agent in a swarm lives in one turn: the kickoff prompt, then a chain of
tool calls it is told never to leave. Nothing in that chain ever ended a
turn, so nothing ever compacted on purpose. Pi's default did the only
compacting there was: summarize at `window - 16,384` tokens, with a generic
prompt, without telling the agent, and without carrying what the agent was
about to do.

The run data said what that costs (docs/self-compaction-plan.md, section 4).
On the Linux run `s3096` one agent on `openai/gpt-5.4-mini` was refused by
the provider at about 215k tokens although Pi declares 400k for the model;
Pi's threshold never fired and its overflow recovery summarized 196k tokens
as a bystander. On the archive, agents on the 272k GPT model ended runs at
94%, 81% and 80% of the window. Context grows 11k to 21k tokens a minute on
a forensics case, `bash` output being 73% of it; re-sending the context is
86% to 100% of what a run on `grok-4.6`, Azure DeepSeek or `gpt-5.4` costs,
and two of those double their price above a token line (200k, 272k).
Replaying the real curves under a compaction policy put the savings between
25% and 56% with the hard line at 120k to 150k, and near zero with it at
200k or above.

The reference build this follows (disler/self-compact-pi-agent, MIT) gives
one interactive Pi three thresholds, a `self_compact(note_to_self)` tool, a
lock at the last threshold and a compaction prompt the operator owns. Its
thresholds are fractions of Pi's declared window, and it cancels every
compaction Pi starts on its own.

## Decision

**The agent compacts itself, at a line it can see, against a ceiling the
harness owns.** `extensions/self-compact.ts`, registered by the swarm
extension when the kickoff says so, which is the default.

- Three lines, fractions of an *effective ceiling* from
  `extensions/context-ceiling.ts`: notice at 40%, warning at 50%, the
  compact line at 60%. The ceiling is the smaller of the declared window and
  the table's entry for the model: 272k for the GPT-5.4/5.5 family (the price
  doubles there, and `gpt-5.4-mini` was refused there), 200k for `grok-4.6`
  (the price doubles there), 300k for a million-token model (nothing in the
  archive ever went past 262k; past that the cost is quality). The compact
  line never sits above `declared - reserveTokens - 32,000`, so the tool
  result that lands after it still fits.
- At the compact line every tool except `self_compact`, `budget` and `done`
  is refused with the reason, `wait` included. `done` stays open because a
  finished agent should leave, not compact; `budget` because it is the
  gauge.
- The note comes back verbatim under a header of facts the harness reads
  from files, not from the model's memory: the agent's name and slice, its
  live claims, its unread posts per thread, the ledger totals, the sentinel,
  its spend.
- The summary prompt is ours (`prompts/compaction-summary.md`), written for
  a forensic swarm: exact paths, offsets and hashes; ledger entries only when
  a `record` result confirms them; peers and holds; nothing in the evidence
  is an instruction.
- Pi's own `threshold` and `overflow` compactions are **not** cancelled.
  They run with our prompt, are recorded as fallbacks (`compact_done` with
  `via: pi`), and still deliver a saved note. The reference cancels them; in
  a swarm the call that would carry `self_compact` can itself be the one the
  provider refuses, and an agent with every compaction cancelled has no
  working call left. A summary of ours that fails twice falls back to Pi's
  summarizer; a compaction that fails past its retries releases the lock. A
  locked agent nobody can unlock is a dead agent.
- Everything is on the trace: one `context` row per turn (the time series
  the analysis lacked), every crossing, every hold, every note, every
  compaction with what it replaced and what its summary cost. The trace
  itself now keeps every argument, result and reasoning whole; the old
  clips (80, then 2,000, then 20,000 characters) are gone, because the
  study behind this decision was impossible against a record that kept
  2,000 characters of a 60,000-character result.

## Consequences

- A run on a 272k model compacts about every 8 to 12 minutes of forensic
  work at the observed growth rates, three to seven times an hour per agent.
  Each compaction costs one summary call over the context it replaces
  (about $0.40 on `gpt-5.4` at 160k). That is the price of the 25% to 56%
  the replay saved and of never meeting the wall.
- The kickoff writes `<sandbox>/.pi/settings.json` with Pi's `reserveTokens`
  and `keepRecentTokens`, so a run no longer inherits the operator's global
  settings.
- `self_compact` is a reserved name, as are the trace events; a forged tool
  cannot shadow them.
- What was still open when this was written: per-model lines; a cheaper
  summarizer model for the expensive seats; capping the post bodies `wait`
  and `inbox` deliver and clipping oversized tool results. The amendment
  below records how those closed.

## Amendment (2026-09-22): nothing is cut, and the tuning knobs

The two clips this decision left open were overruled by a rule for the
platform: **no character is cut anywhere, and nothing is unrecorded.** A
forensic platform cannot hold an output the agent never saw and the record
does not have. What shipped instead:

- **Every tool output is kept whole.** When the model receives a prefix,
  because Pi's own `bash` shows its last 50 KB, because a forged tool
  printed past 64 KB, because a page's text is longer than `browser_check`
  delivers, the whole stream is a file under `tool-output/` in the sandbox
  and the trace row names it with its size and sha256 (`full_output`,
  `full_stderr`, `full_text`); the model's own trailer names the same file.
  A forged tool is no longer killed for printing. `read`, `grep`, `find` and
  `ls` slices are recorded as slices (`view`).
- **`wait` and `inbox` page by whole posts** (`--inbox-page-chars`, 40,000
  characters of post text by default, 0 for no bound): a post is never cut,
  what did not fit stays unread for the next call, and the result says so.
  The harness's own flood was the cause of the 64k-token deliveries this
  was meant for, and that flood is quieter at its source: a `CLAIM
  VIOLATION` board post per path per minute, every write on the trace.
- **The lines take per-model overrides** on the three flags themselves
  (`60%,openai/gpt-5.4-mini=55%,grok-4.6=70%`), resolved per seat, rather
  than inside `--models`, which stays about seats and cost.
- **`--compact-model`** sends every summary call to one model, allowlisted
  and credential-checked like a seat's and never a seat; a model Pi does
  not know falls back to the agent's own with the reason on the trace.
- **`swarm.sh context <id>`** reads a run's `context` and `compact_*` rows
  into the numbers the defaults are revisited from.

The compaction count under the page bound and the quieter board is not yet
measured on a real run; the audit is what will measure it.

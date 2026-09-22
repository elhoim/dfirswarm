# Run 6 on Linux: nothing cut, summaries by a cheaper model

The first run with phases 3 and 4 of the self-compaction plan on: every
tool output kept whole under `tool-output/`, `inbox` and `wait` paging by
whole posts, the board's violation posts once per path per minute, and
every summary written by `openai/gpt-5.4-nano` while the seats ran
`gpt-5.4-mini`. Same case as [run 5](run-5-self-compact.md), same host,
same team, same lines. The record is in [run-6-lossless/](run-6-lossless/):
`budget.json`, `team.json`, `names.json`, the whole trace
(`trace/events.jsonl`, 2,063 rows, the longest 130 KB), `ledger.jsonl` (34
entries), `summary.md`, `context.md` (what `swarm.sh context` printed),
`tool-output.jsonl` (the eleven kept outputs with their sizes and hashes;
the 21 MB themselves stay on the host), the registry row and the two
deliverables.

| | |
| --- | --- |
| Run | `s50bb`, label `self-compact-run3` |
| Host | the Ubuntu 24.04 droplet of runs 4 and 5, Pi 0.87.0, Herdr 0.9.1 |
| Team | 4 x `openai/gpt-5.4-mini`, forging and installs on, `--inputs-bind` on the 26 GB image and the 1 GB memory dump; `--compact-model openai/gpt-5.4-nano` |
| Caps | $20 swarm, $6 per agent, 45 minutes |
| Lines | the defaults: notice 40%, warning 50%, compact 60% of a 272k ceiling (109k / 136k / 163k); inbox page 40,000 characters |
| Took | 34 m 9 s to the sentinel; $4.55; 497 provider calls; 30.8M tokens |
| Finish line | 9 of 9 checks (the ninth, the `inputs/` file count, holds while the bind is mounted; `stop` unmounts it) |

## What the run produced

`work/report.md` answers the eight questions and the bonus with evidence
(sqlmap against DVWA, command execution and file inclusion, five dropped PHP
shells and a reverse shell to `192.168.56.102:4545`, the `hacker` and
`user1` accounts with their SAM timestamps, the shellcode in memory, a
hypothesis) and `work/timeline.md` holds 52 dated rows. `s50bb03` called
`done` at 15:13:31 after `s50bb01` had signed off on the Meterpreter wording
and `s50bb00` on the disk sections: the definition of done, not a slice.
Run 5 had ended at 3 of 9 on a slice-level `done`; the prompt change it
led to held.

## Nothing was cut

Eleven `bash` results were larger than the 50 KB Pi hands the model. Each
whole output was moved from the pane's temp directory into
`tool-output/<agent>/`, named on the trace row with its size and sha256,
and the model's own trailer rewritten to that path:

| Agent | Command | Whole | Model saw |
| --- | --- | --- | --- |
| `s50bb03` | a `grep -RIn` over the extracted tree | 12.7 MB, 120 lines | 35 KB |
| `s50bb02` | a `regipy` dump | 4.0 MB, 16 lines | 125 bytes |
| `s50bb00` | a `pytsk3` file walk | 2.5 MB, 19,884 lines | 51 KB |
| `s50bb00` | a `pytsk3` search | 1.5 MB, 19,572 lines | 51 KB |
| `s50bb03` | a `pytsk3` listing | 562 KB, 9,047 lines | 51 KB |
| six more | EVTX parsing, `strings` over the memory dump, `grep`s | 34 KB to 163 KB | 29 KB to 51 KB |

The hash on the row matches the file on disk for every one of the eleven
(`tool-output.jsonl` was hashed from the files; the rows agree). The 4 MB `regipy` output the
model saw 125 bytes of, and the 12.7 MB `grep`, are the point: before this
run those bytes existed only in `/tmp` on the host, unrecorded, and the
trace said `ok: true`.

The trace itself: 94 rows carry a result longer than the 2,000 characters
the harness once kept, the longest 51,308 characters; no argument is
clipped; the longest line is 130 KB against the collector's 64 MB.

No `inbox` or `wait` delivery reached the page bound: the largest carried
eight posts, the board's 58 posts are at most 887 characters each. The
flood the bound was built for (578 posts in one `wait` on `s3096`) had been
the harness's own violation posts, and on this run the harness posted nine
violations, once per path.

## Self-compaction, with a cheaper summarizer

| Agent | Peak | Crossed | Hand-offs | Restart | Summary |
| --- | --- | --- | --- | --- | --- |
| `s50bb01` "Memory & timeline" | 146,135 (53.7%) | notice, warning | 1 at 146,135 | 29,173 | 37,889 tokens, $0.011, 13,101 chars |
| `s50bb03` "Scout" | 144,032 (53.0%) | notice, warning, twice | 2 at 144,032 and 141,538 | 36,460 and 39,996 | 39,465 and 50,759 tokens, $0.011 and $0.013 |
| `s50bb00` "Software & leftovers" | 139,040 (51.1%) | notice, warning | 1 at 139,040 | 22,503 | 38,844 tokens, $0.012 |
| `s50bb02` "accounts and registry" | 80,797 (29.7%) | none | 0 | | |

Every hand-off came between the warning and the compact line, as the
prompts ask; nothing was held at the line; Pi's own recovery never ran.
`compact_config` says for every seat that the summary model resolved to
`openai/gpt-5.4-nano` from Pi's registry (`summary_model_source:
compact-model`), `compact_done` says every summary was written by it, and
the session files agree. Four summaries cost $0.05 together; run 5's three
on `gpt-5.4-mini` cost $0.12. The summaries are structured the way
`prompts/compaction-summary.md` asks (Goal, Constraints, Progress with Done
and In Progress, verified marks on what a tool result confirmed). After
each hand-off the agent called `inbox`, then went on: `s50bb01` straight
back to its EVTX parsing, `s50bb03` re-read `SWARM.md` and its claims,
`s50bb00` posted an acknowledgement and waited.

## What went wrong

**The idle watchdog died a minute after the kickoff started it.** Its log
was empty, its state file never written, the journal quiet, and the pid
in `idle-nudge.pid` gone; run 5's watchdog had died the same way (no
nudge on either run), while run 4's, started the day before, was still
running. A probe that detaches the real script the same way from a tmux
session that ends survives, so the cause is not established. Run by hand
at 15:09 it prompted all four agents at once. The kickoff now looks two
seconds after starting the watchdog, starts it once more with stdin closed
when it is gone, and says which happened; `swarm.sh status` reports every
daemon's liveness from its pid file.

**All four agents answered the hand-off with a status and ended their
turns.** A few tool calls after the note came back each agent decided the
"user" (the hand-off message) had asked for a compaction and been served,
wrote a status update and stopped: `s50bb01` at 14:55, `s50bb00` at
14:58, `s50bb02` at 14:59, `s50bb03` at 15:04. With the watchdog dead
they sat idle for five to fourteen minutes until it was run by hand; then
they finished the case in four minutes. The hand-off header and the system
prompt now say what the message is not.

**The venv was 642 claims and seven violations.** `s50bb03`'s pip created
`work/.toolchain/`, the shell-write watch took every file in it as that
agent's implicit claim, `s50bb01`'s pip into the same venv was seven
`CLAIM VIOLATION` posts, and the thousands of files pushed the watch past
its budget, so all four agents were told `work/` was no longer covered.
Pi's own spill files under `work/.tmp/` (the panes' `TMPDIR`) were eleven
more claims and one violation. Both directories are out of the watch now,
and the spill file is removed once its whole copy is under `tool-output/`.

## What to keep from it

- A cent per summary on `gpt-5.4-nano` against four on `gpt-5.4-mini`, and
  the agents resumed from the summaries the same way. `--compact-model` is
  the setting for expensive seats.
- The record holds what the agent saw and what it did not: eleven outputs,
  21 MB, that would have been lost, and the row says which bytes the model
  read.
- The lines held again: three of four agents crossed the warning line and
  handed off before the compact line; the fourth never reached the notice.
  Four hand-offs against run 5's three; the growth is `bash` output, and
  compaction is what absorbs it.
- The watchdog is the run's safety net for a model that stops; a run needs
  to know when it is not there.

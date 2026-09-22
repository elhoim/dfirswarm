# Run 5 on Linux: the agents compact themselves

The first run with self-compaction on, the day it was built. Same case as
[run 4](run-4-linux.md), the same droplet, the same model and team; what
changed is that every agent watched its own context against the 272k
ceiling the harness sets for `openai/gpt-5.4-mini`, was told at 109k and
136k, and would have been held at 163k. The record is in
[run-5-self-compact/](run-5-self-compact/): `budget.json`, `team.json`,
`names.json`, the whole trace (`trace/events.jsonl`, unclipped now),
`ledger.jsonl`, `summary.md`, the registry row and the two deliverables the
swarm left behind.

| | |
| --- | --- |
| Run | `sd8ee`, label `self-compact-run2` (run 1, `sbb97`, never started an agent; see below) |
| Host | the Ubuntu 24.04 droplet of run 4, Pi 0.87.0, Herdr 0.9.1 |
| Team | 4 x `openai/gpt-5.4-mini`, forging and installs on, `--inputs-bind` on the 26 GB image and the 1 GB memory dump |
| Caps | $20 swarm, $6 per agent, 45 minutes |
| Lines | the defaults: notice 40%, warning 50%, compact 60% of a 272k ceiling (109k / 136k / 163k) |
| Took | 14 m 41 s to the sentinel; $2.92; 337 provider calls; 15.0M tokens |

## What self-compaction did

Three hand-offs, three compactions, no failure, no fallback to Pi's own
summarizer, nothing held at the line.

| Agent | Peak context | Hand-offs | What happened |
| --- | --- | --- | --- |
| `sd8ee01` "Registry and timeline" | 168,424 | 2 | crossed the notice line at 109,595 (40.3%) and the warning line at 137,412 (50.5%), finished the step it was on and handed off at 144,297 with a 4,822-character note, **before** the compact line; the summary call cost 41,878 tokens ($0.047) and the next call carried 35,165 tokens. Climbed again, crossed the notice and warning lines, and handed off at 168,372 (61.9%) with an 8,213-character note as the compact line engaged the lock in the same second; 33,969 summary tokens ($0.036), 14,122 tokens on the next call. |
| `sd8ee03` "Disk & timeline" | 98,095 | 1 | handed off at 98,044 (36%), below every line, on its own judgement, with a 3,242-character note; 31,479 summary tokens ($0.039), 30,163 on the next call. |
| `sd8ee00` "Memory hunter" | 66,711 | 0 | never reached the notice line |
| `sd8ee02` "Software provenance checker" | 37,937 | 0 | never reached the notice line |

What came back after each hand-off was the harness's header (name and
slice, live claims, unread posts per thread, ledger totals, sentinel, spend)
and the note, byte for byte. The agents did what the note said: `sd8ee01`
re-read `SWARM.md`, listed `work/` and the ledger and went on with its
event-log parsing; after its second hand-off it called `inbox` (the header
said four posts were unread), then `claims`; `sd8ee03` called `inbox`,
re-read the case file and tried to claim the report. Nothing was redone.
The three notes are in the trace under `self_compact`, whole; the two
summaries are in the session files on the host, structured the way
`prompts/compaction-summary.md` asks (Goal, Constraints, Progress with Done
and In Progress, Ledger, Board & Peers, Decisions, Next Steps, Critical
Context).

The trace carries one `context` row per turn, 337 in all, which is the
time series the console's Context chart draws: the climb, the two drops,
the level along the way. Run 4 had no such record; its curves came from the
session files, which never leave the host.

The three summaries cost $0.12 of the $2.92. The whole run cost less than
run 4 ($4.81) and took the same time, on the same case; too few runs to
call that a saving, and the case was cut short (below).

## What went wrong

**Run 1 never started an agent.** `herdr agent start` timed out "waiting
for agent startup" on every pane and the kickoff exited 1 with the sandbox,
the daemons and the layout all in place. The panes' zsh had opened Ubuntu's
new-user wizard, because the `swarm` account has no `~/.zshrc`, and the
wizard read the `pi` command line as its menu answer. Run 4 did not hit
this because its guard was `--mode landlock` without `--in-place`; the
first run under `--mode linux --in-place` did. Fixed in the pane hook
(it keeps the sandbox's own `.zsh/`, with an empty `.zshrc`, when the home
has none), tested in `tests/dfir-flags.test.sh`, and written into
`docs/linux-server.md`. The host got its `~/.zshrc` too.

**The kickoff ran in the wrong runs directory.** It was launched inside a
tmux session on a server that already had one, so `SWARM_RUNS_DIR` did
not reach it and the run landed under `dfirswarm/runs/` instead of
`swarm-runs/`. The operator's mistake, not the harness's; the run itself
is unaffected.

**The swarm stopped before the report was written.** `sd8ee03` called
`done` for its own slice ("Disk/timeline slice complete") while `sd8ee01`
held `work/report.md` and was drafting it; `done` wrote the sentinel and
the other three were stopped by it. The finish line reads 3 of 9 checks:
`work/timeline.md` (51 rows) and `work/bonus_inventory.md` exist, the
report does not. That is not the hand-off's doing (`sd8ee03`'s note ended
with "wait for sd8ee01's answer, then release work/timeline.md", and that is
what it did), but the self-compaction prompts had said "if your part is
finished, call done", which reads as an invitation to exactly this. They
now say that `done` belongs only to `SWARM.md`'s definition of done and
ends the swarm for everyone, and that a finished slice is a post and a
hand-off. The older habit, `done` as "my part is over", predates this
feature and is the same one [run 2](run-2.md) and c09 recorded.

**One tool-call chain of `claim_file`.** `sd8ee00`'s Volatility output
turned into 478 implicit claims (shell writes under `work/`); noise on the
trace, not a defect of this run.

## What to keep from it

- The defaults held: an agent that listens hands off at the warning line,
  one that does not is caught at the compact line, and one that judges its
  own moment may go earlier. All three shapes appeared in one 15-minute run.
- The summary call is a quarter to a third of the context it replaces
  (42k for 144k, 34k for 168k, 31k for 98k), because Pi serializes tool
  results at 2,000 characters for the summary while the trace keeps them
  whole.
- After a hand-off the context restarts at 14k to 35k, not at zero: the
  system prompt, the retained recent history and the returned note.
- The per-turn `context` row is what makes the next threshold decision a
  measurement rather than a guess. Keep it.

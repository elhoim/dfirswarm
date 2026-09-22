# BelkaCTF

Belkasoft's DFIR capture-the-flag series: one disk (or phone) image, a story
told between the tasks, and a set of questions whose answers all live in the
evidence. Seven editions have run since 2021, all of them finished, all of
them still published — which makes them a second source of use cases for the
swarm alongside Ali Hadi's challenge images in [../README.md](../README.md):
the questions are fixed, so a run can be scored rather than only read.

The evidence files are not in this repository. Every edition publishes its
own download links and archive passwords on its Information page; those are
recorded in each edition's README.

## The editions

| # | Edition | Ran | Challenges | Source | Captured here |
| --- | --- | --- | --- | --- | --- |
| 1 | Insider Threat | Mar 2021 | — | [/ctf_march](https://belkasoft.com/ctf_march) | no |
| 2 | Drugdealer Case | May 2021 | — | [/ctf_may](https://belkasoft.com/ctf_may) | no |
| 3 | Meet the Boss | Jun 2021 | — | [/ctf_june](https://belkasoft.com/ctf_june) | no |
| 4 | Kidnapper Case | Mar 2022 | — | [/ctf_march_2022](https://belkasoft.com/ctf_march_2022) | no |
| 5 | Party Girl—MISSING | Jul 2022 | — | [/ctf_july_2022](https://belkasoft.com/ctf_july_2022) | no |
| 6 | Bogus Bill | Apr 5–7, 2024 | 18 + 2 bonus | [/belkactf6](https://belkasoft.com/belkactf6/) | [belkactf6-bogus-bill](belkactf6-bogus-bill/README.md) — **run `s821c`**, 10 agents, 50.5 min, $77.32, 10/10 certified; **run `s83fd`** (re-run, sealed sandbox), 65 min, $68.89, 10/10 certified |
| 7 | Stranger Dfings | Jul 25–27, 2025 | — | [/belkactf7](https://belkasoft.com/belkactf7/) | no |

The index of editions is [belkasoft.com/ctf](https://belkasoft.com/ctf).
Editions 1 to 5 are listed with the month they ran; their challenge counts are
not recorded here until their tasks are captured.

## How a folder is laid out

One folder per edition, named `belkactf<N>-<slug>`:

- `README.md`: what the edition was, when it ran, the rules and the scoring,
  where the evidence comes from and how it is unpacked, and the state of any
  swarm run on it.
- `challenges.md`: every task in board order (left to right, top to bottom),
  with the story panel text, the question verbatim, and the flag format.
- `goal.md` and `run/`: the goal document handed to the swarm, and what
  `swarm.sh package` wrote — the report, the ledger, the board, the trace, the
  hashes. Added when the edition is actually run, following the layout the
  other use cases use (see [../README.md](../README.md)).
- `observations.md`: what the run showed about the platform itself, with the
  evidence for each finding, written to be folded into
  [docs/improvement-plan.md](../../improvement-plan.md).
- `screenshots/`: the console during the run, with a `README.md` that walks
  through them in order.

## Answers

Belkasoft publishes an official write-up for every edition, with the flag and
the intended solution path for each task. **None of that goes into this
repository** — not the flags, not the solution steps, not a paraphrase of
them, in any file, including run notes and case READMEs. A CTF is only a
benchmark for the swarm as long as nothing on disk can leak the answer into a
run, and the write-ups are Belkasoft's own material besides.

Score a run against the published write-up outside the repository, and record
only the outcome (how many tasks the run got right), never the expected
values.

## Adding an edition

1. Open the edition's challenge board (`.../chall`) and read the tasks in
   board order; each tile links to its own page carrying the story, the
   question and the flag format.
2. Write `challenges.md` in that order, questions verbatim, with the flag
   format kept as the site states it. Note where the board's order differs
   from the numbering the event used, and mark bonus tiles as bonus.
3. Record the evidence downloads, archive passwords, rules and scoring in the
   edition `README.md`, and add the row to the table above.
4. Do not open the write-up while capturing the tasks, and do not copy
   anything out of it. See [Answers](#answers).

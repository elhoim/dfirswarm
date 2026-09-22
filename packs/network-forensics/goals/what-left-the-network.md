# What this capture shows

A capture, and the question of who talked to whom, what left, and whether
anything called home.

Read the skill index with `skill()` first. `capture/what-you-have` decides what
any answer can be worth, and it comes before every other question.

## Questions

1. The capture itself: format, link type, snap length, time range, and what the
   capture point and snap length mean for what can be established from it.
2. The shape: top talkers, top destinations, protocols and ports, with byte
   counts each way.
3. Anything periodic: the destination, the interval, the jitter, how long it ran
   and whether it stopped — and what makes it more than a software update.
4. What can still be established about encrypted sessions: names resolved,
   server names requested, certificates, and the sizes and timing.
5. Outbound volume: which internal host sent most, to where, in what windows.
6. Correlation with the host evidence, including the clock offset you measured
   and applied.
7. What you could not establish, and what evidence would settle it.

## Definition of done

`work/report.md` exists and answers questions 1 to 7 under the headings `## 1.`
through `## 7.`. The snap length and the clock offset are both stated. A critic
has read it against the board and posted a sign-off. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -qiE 'snap length|snaplen' work/report.md`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 4`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"skill"' traces/events.jsonl`

# What this phone shows

An extraction from a phone, and the questions a case asks of one.

Read the skill index with `skill()` first. `extractions/what-you-have` decides
what can be asked at all, and it comes before everything else.

## Questions

1. The extraction: what kind it is, what it therefore cannot contain, the
   device it came from, and whether it is encrypted.
2. The device profile: operating system version, identifiers, the accounts on
   it, and the applications installed with their install times and installers.
3. Communications: messages, calls and the contacts behind them, with the
   database each came from.
4. What was deleted and recovered: the fragment, the page it came from, and what
   is inference rather than a row.
5. Location: where the device recorded being, with the accuracy of each fix and
   the source that produced it.
6. Activity: what ran, when, and for how long.
7. The timeline in UTC, with the epoch you converted each source from.
8. What you could not establish, and what evidence would settle it.

## Definition of done

`work/report.md` exists and answers questions 1 to 8 under the headings `## 1.`
through `## 8.`. The kind of extraction and its limits are stated in answer 1.
Every recovered fragment is labelled as recovered rather than as a row. A critic
has read it against the board and posted a sign-off. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7 8; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -qiE 'logical|full file system|physical|backup' work/report.md`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 6`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"skill"' traces/events.jsonl`

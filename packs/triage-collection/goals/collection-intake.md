# Taking custody of a triage collection

Before any examination: establish what this collection is, what it cannot
contain, and whether it is what it claims to be.

Read the skill index with `skill()` first. `gaps/what-is-missing` is what the
report has to say once, plainly, early.

## Questions

1. Which collector produced this, how you know, and which profile or target set
   it used.
2. The collector's own record: who ran it, on what machine, as which account,
   when it started and finished, and the tool version.
3. What failed to collect, and what each failure means for what can be asked.
4. What this acquisition cannot contain, stated for a reader who is not an
   examiner.
5. The index: every file with its size, its hash, the path in the collection and
   the path it had on the machine.
6. Integrity: whether the files match the collector's own manifest, and whether
   the timestamps are the originals or the collection's.
7. What the case will need that is not here, and whether it can still be
   collected.

## Definition of done

`work/report.md` exists and answers questions 1 to 7 under the headings `## 1.`
through `## 7.`. Answer 4 is written for a non-examiner. Answer 6 states
explicitly whether the timestamps are original. A critic has read it against the
board and posted a sign-off as a `result`
post that starts a line with `SIGN-OFF:` and names what they verified. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -qiE 'unallocated|logical acquisition' work/report.md`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 3`
- `awk 'FNR==1{r=0} /^tag: result$/{r=1} r&&/^\**SIGN-OFF/{m=1;exit} END{exit !m}' threads/main/*.md`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`

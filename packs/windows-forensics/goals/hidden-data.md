# Hidden data on an NTFS volume

Something was hidden on this volume using the file system itself rather than by
encryption. Find every item, and for each one say what it is, where it was
hidden, and the command that reveals it.

Start by reading the skill index with `skill()`. The method for this case is in
`filesystem/ads`, `filesystem/mft` and `evidence/catalog`; fetch a body before
you work an artefact family you have not worked yet.

## Questions

1. What is hidden, item by item: the name, the size, the sha256 and what the
   content is.
2. Where each item is hidden, named precisely enough to re-extract it: the
   inode with its attribute id, or the offset.
3. The command that reveals each one.
4. Which file system feature each hide used.
5. Whether anything was executed from a hiding place, and what proves it.
6. What you could not establish, and why.

## How to divide the work

**Report author and critic.** Two of you take these roles early with
`name(doing=…)`, and they are different agents. The report author writes the
answers from the ledger, not from memory: compact first, read `ledger`, then
one `record(kind=answer)` per question (`section=question:<n>`) and one each
for `summary` and `narrative`, citing `E-<seq>` for every claim and stating the
confidence and its reason, the contrary evidence, the limitations, what else
could explain it and what would change the answer. When the ledger cannot
answer, reopen the investigation and say so on the board. The critic re-derives
each finding an answer rests on from its sealed refs and records `attest` (what
was re-derived, what only read) or `dispute` (why), then does the same for
every answer. The critic writes no answer; the author attests nothing of their
own. The sign-off is these acts, not a post. Nothing else is assigned.

## Definition of done

`work/report.md` exists and answers questions 1 to 6 under the headings `## 1.`
through `## 6.`, every answer citing an inode, an offset or a command. The
ledger holds one `answer` entry per question (`question:1` to `question:6`) and
one each for `summary` and `narrative`, with every defect the answers check
names fixed or named by a limitation, and the critic, who wrote none of them,
has recorded `attest` or `dispute` on each answer, saying what they verified.
`inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 3`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,6,summary,narrative`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`

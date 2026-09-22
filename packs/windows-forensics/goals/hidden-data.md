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

## Definition of done

`work/report.md` exists and answers questions 1 to 6 under the headings `## 1.`
through `## 6.`, every answer citing an inode, an offset or a command. A critic
has read it against the board and posted a sign-off. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 3`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"inputs_check"' traces/events.jsonl`
- `grep -q '"tool":"skill"' traces/events.jsonl`

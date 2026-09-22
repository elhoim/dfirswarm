# Did data leave this machine, and how

Somebody is believed to have taken data off this host. Establish whether they
did, by what route, and what it was.

Read the skill index with `skill()` first. `registry/devices` covers removable
media, `browser/artefacts` covers upload and webmail, `execution/srum` is the
one artefact that gives volume, and `artifacts/shell` proves what was opened
from where.

## Questions

1. Removable devices: every device attached, its serial, the first and last
   connection, the drive letter, and which user mounted it.
2. Files: what was opened, copied or staged, and from where — with the link
   files, jump lists, shell bags or journal records that show it.
3. Network routes: uploads, webmail, cloud sync clients or shares, with the
   artefact for each.
4. Volume: how much data a program moved, and over which network, where SRUM or
   another artefact can say.
5. Attribution: which account did each of the above, and what makes you confident
   it was a person at the keyboard rather than a token.
6. What was destroyed afterwards, if anything.
7. What you could not establish, and what evidence would settle it.

## Definition of done

`work/report.md` exists and answers questions 1 to 7 under the headings `## 1.`
through `## 7.`, every answer citing an artefact a reviewer can re-open. A
device named in answer 1 is tied to something in answer 2 or the report says it
could not be. A critic has read it against the board and posted a sign-off.
`inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 5`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"inputs_check"' traces/events.jsonl`
- `grep -q '"tool":"skill"' traces/events.jsonl`

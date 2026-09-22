# What on this evidence is encrypted, and what can be opened

A focused pass over an exhibit before the main examination, so that nobody
spends a day on something the metadata would have answered.

Read the skill index with `skill()` first. `identify/headers` is the order of
questions, and `keys/where-they-hide` is where a case is usually solved.

## Questions

1. Every encrypted volume, file and archive in the evidence, with the scheme
   each one uses and how you identified it.
2. For each volume: the key protectors or key slots present, and whether the
   metadata alone says it can be opened without a secret.
3. For each archive or document: whether the file names are readable without the
   password, and what they are if so.
4. Key material already in the evidence: where it is, what it opens, and how you
   found it. Do not put values in the report.
5. What was opened, with which key, and the hash of the unlocked image.
6. What could not be opened, and exactly what would be needed to open it.

## Definition of done

`work/report.md` exists and answers questions 1 to 6 under the headings `## 1.`
through `## 6.`. No key, password or recovery key value appears in the report; a
hash and a location appear instead. A critic has read it against the board and
posted a sign-off. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6; do grep -q "^## $n\." work/report.md || exit 1; done`
- `! grep -qE '[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}' work/report.md`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 3`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"skill"' traces/events.jsonl`

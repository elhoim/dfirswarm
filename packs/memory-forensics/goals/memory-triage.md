# What was running on this machine

A memory image, and the question of what was on it and what it was doing.

Read the skill index with `skill()` first. `triage/what-you-have` names the
container before anything is run against it, and `strings/discipline` is the
rule every claim here has to survive.

## Questions

1. The container: what format the image is in, its size, whether it is
   contiguous, and which moment it represents.
2. What was running: the process list with parents, paths and start times, or —
   where no framework was available — what you were able to establish without
   one, said plainly as that.
3. Anything injected or hollowed: the process, the region, its protection, and
   the hash of the bytes you dumped.
4. Network state: connections and listeners with the owning process, and which
   of them came from freed structures rather than the live table.
5. Credential exposure: what a process could have taken, with the artefact that
   shows it. Do not put recovered secrets in the report.
6. Structures carved out of the image that a disk parser could read, and what
   each one said.
7. The timeline in UTC, and what you could not establish.

## Definition of done

`work/report.md` exists and answers questions 1 to 7 under the headings `## 1.`
through `## 7.`. Every memory claim names a process and a region, or an offset.
A critic has read it against the board and posted a sign-off as a `result`
post that starts a line with `SIGN-OFF:` and names what they verified. `inputs/` is
unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -qiE '0x[0-9a-f]{4,}|offset' work/report.md`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 4`
- `awk 'FNR==1{r=0} /^tag: result$/{r=1} r&&/^\**SIGN-OFF/{m=1;exit} END{exit !m}' threads/main/*.md`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`

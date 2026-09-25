# A Windows machine that was compromised

This host is believed to have been compromised. Establish what happened on it,
in order, with a citation for every step.

Read the skill index with `skill()` before you start. `registry/system-profile`
is the first ten minutes of this case and everything later depends on it;
`execution/overview` says how much each execution artefact is worth before you
quote one.

## Questions

1. The system profile: build, install date, computer name, the timezone you
   converted every timestamp from, and the accounts on the machine.
2. Initial access: how the operator first reached this machine, with the
   artefact that shows it and the time in UTC.
3. Execution: every program the operator ran that is not part of Windows, each
   with at least two independent artefacts agreeing, and a hash where one
   survives.
4. Persistence: how anything arranged to run again, or the evidence that
   nothing did.
5. Accounts: any account created, enabled, given privilege, or used from
   somewhere it had not been used from before.
6. Movement: where the session came from, and anywhere this machine reached
   afterwards.
7. Anti-forensics: what was cleared, wiped, timestomped or turned off, and what
   you recovered in spite of it.
8. The timeline, in UTC, and what you could not establish.

## Definition of done

`work/report.md` exists and answers questions 1 to 8 under the headings `## 1.`
through `## 8.`. Every claim cites a path with an inode, a registry key with its
last-write time, an event record id with its channel, an offset, a hash, or the
command that produced it. A critic has read the report against the board and
posted a sign-off as a `result`
post that starts a line with `SIGN-OFF:` and names what they verified. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7 8; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -qiE 'UTC' work/report.md`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 8`
- `awk 'FNR==1{r=0} /^tag: result$/{r=1} r&&/^\**SIGN-OFF/{m=1;exit} END{exit !m}' threads/main/*.md`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`

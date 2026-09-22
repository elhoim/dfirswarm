# A Linux server that was compromised

This host is believed to have been compromised. Establish what happened on it,
in order, with a citation for every step.

Read the skill index with `skill()` before you start. `triage/system-profile` is
the first ten minutes and everything later depends on the timezone it
establishes.

## Questions

1. The system profile: distribution, kernel, hostname, install date, the
   timezone you converted every timestamp from, and the boot history.
2. Initial access: how the operator first reached this host, with the artefact
   that shows it and the time in UTC.
3. Accounts and keys: any account added, any UID 0 that is not root, any sudoers
   entry, any key added to an authorized_keys file, and when.
4. Execution: what was run, from the shell histories, sudo lines, the audit log
   and the journal, with at least two sources agreeing where you can get them.
5. Persistence: every scheduled job, unit, timer, profile script or preload that
   was added or changed, or the evidence that nothing was.
6. Integrity: which packaged binaries no longer match the distribution's hashes,
   and whether the package database itself was touched.
7. Containers, if the host ran any: what was inside, what the writable layer
   holds, and whether any container could reach the host.
8. The timeline in UTC, and what you could not establish.

## Definition of done

`work/report.md` exists and answers questions 1 to 8 under the headings `## 1.`
through `## 8.`. Every claim cites a path with an inode or a hash, a log line
with its file and time, a unit file, or the command that produced it. A critic
has read the report against the board and posted a sign-off. `inputs/` is
unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7 8; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -qiE 'UTC' work/report.md`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 8`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"inputs_check"' traces/events.jsonl`
- `grep -q '"tool":"skill"' traces/events.jsonl`

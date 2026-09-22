# What runs on this machine that should not

A focused sweep rather than a full investigation: establish everything that is
arranged to run on this host, and which of it does not belong.

Read the skill index with `skill()` first. `persistence/mechanisms` is the map;
`packages/integrity` is the cheapest way to clear thousands of files.

## Questions

1. Every scheduled job, unit and timer on the machine, with the file it is in
   and that file's modification time.
2. Which of them were added or changed outside the build window, and what that
   window is.
3. Every persistence route outside cron and systemd: profile scripts, preloads,
   modules, PAM, SUID binaries, authorized_keys with a forced command.
4. Which packaged binaries no longer match the distribution's hashes.
5. For anything you flag: what it runs, as which user, and what it would have
   been able to reach.
6. What you could not establish, and what evidence would settle it.

## Definition of done

`work/report.md` exists and answers questions 1 to 6 under the headings `## 1.`
through `## 6.`, every answer citing a file path with its modification time or a
command. A critic has read it against the board and posted a sign-off.
`inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 4`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"skill"' traces/events.jsonl`

# Detect bash writes rather than block them

The write guard intercepts `edit` and `write` and refuses a path the agent has
no claim on. `bash` cannot be guarded the same way: a shell command can write
anything, and deciding from the command text whether it will both misses
(`python3 -c`, a script it wrote earlier, a heredoc) and fires on commands that
write nothing. So the harness brackets every shell call with a hash of the
paths worth watching and reports what actually changed: the writer, the path,
whose claim it was, and the revision the result was snapshotted as.

The change is not reverted automatically. The claim's owner decides — the same
way a person would — and `file_restore` puts the file back *if there is an
earlier revision to put back*. The snapshot taken before the shell call holds
hashes, not bytes, so a file the harness had never recorded has no previous
version; the announcement says which case it is rather than promising an undo
that does not exist. Reverting from the harness would also undo whatever else
that command legitimately wrote.

The watch set is everything under `work/`, the four harness files an agent
should never touch (`SWARM.md`, `team.json`, `layout.json`, the sentinel),
every live claim and the spend/time caps. It is deliberately not `threads/`,
`locks/`, `traces/`, `inbox/` or `history/`: those change under normal
operation, and comparing them would blame whoever happened to be running a
shell at the time. A shell write to one of those is a known blind spot.

This is weaker than blocking and deliberately so: the alternative was refusing
`bash` outright, which removes most of what makes these agents useful. The
announcement on the board is the part that matters — a violation nobody sees
is the failure mode being avoided here.

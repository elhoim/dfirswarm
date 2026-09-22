---
id: apps/databases
title: App databases, WAL, and what deleted means in SQLite
when: The answer is inside an application's own storage.
needs: [extractions/what-you-have]
tools: [sqlite_freespace, sqlite_query]
requires_host: []
---

Almost every app on either platform stores its data in SQLite, so this one skill
covers messengers, browsers, mail, notes and most of the rest.

**Copy the whole set, always.** A SQLite database is up to three files: the
database, a `-wal` write-ahead log, and a `-shm` shared-memory index. Query the
database alone and you see the state at the last checkpoint — which can be weeks
old on a phone that is never closed cleanly. **The newest messages are in the
WAL.** Copying only the `.db` is the single most common mistake in mobile work
and it silently loses exactly the period a case is about.

**Deletion inside SQLite is not erasure.** A deleted row's bytes stay in the
page's free space until that page is reused, and `VACUUM` is the only thing that
reliably clears them — which phones rarely run. `sqlite_freespace` walks the
free pages and the unallocated tail of each page and returns the readable
records.

Three rules for a recovered row:

1. **It has no guaranteed column mapping.** You are reading a record's payload
   out of free space; which value was in which column is inference unless the
   record header survived intact. Say which.
2. **It has no reliable time** unless the timestamp is inside the recovered
   bytes, and then it is only as good as the record.
3. **It may be from a different table.** Free space is per page and pages are
   reused across the file.

Read the schema before the data — `sqlite_query` with
`SELECT sql FROM sqlite_master` — because column names carry meaning that no
amount of staring at values will give you. And check for a `-journal` file as
well as a WAL: a rollback journal holds the *previous* contents of changed
pages, which is another route to a value that was overwritten.

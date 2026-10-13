---
id: data/sqlite
title: A SQLite database is a set of files
when: A SQLite database to read, with or without a -wal, -shm or -journal beside it.
tools: [sqlite_snapshot, sqlite_query]
---

Use when a `.db`, `.sqlite` or an app store is the evidence. Not for a database that is not SQLite, or for recovering deleted records.

**The set.** A database is the main file plus a `-wal` (committed changes the main file may not hold yet, older pages, and an incomplete transaction), a `-shm` (an index of the WAL) and a `-journal` (a rollback journal, hot when a write was interrupted). When extracting from an image, extract each record that sits beside the database (`filesystem/extract`) and keep them in one directory under the main file's name plus the suffix. A copy of the main file alone is a different state.

**Snapshot, then query.** `sqlite_query` opens the file it is given read-only and immutable, so a WAL beside it is reported (`snapshot_status`: WAL NOT APPLIED) and not read. Run `sqlite_snapshot` on the main file as a job: it copies the set into `original/` with sha256s (and says `changed_during_copy` if a live file moved), reads the WAL against the format, and has SQLite apply it in `applied/database.sqlite`. Give `sqlite_query` the snapshot directory or its `database`.

    job_run tool=sqlite_snapshot args={"db_path": "work/extracted/<you>/History", "out_dir": "{OUT}/history"}

**Read the receipt.** `wal.frames_committed` (applied) against `frames_uncommitted_valid` (valid frames after the last commit: never applied), `first_invalid_frame` (a leftover of an earlier generation is normal; a checksum mismatch or a file that ends inside a frame is damage and the snapshot is `partial`), `counts_agree` (SQLite and the tool read the same frames), `rollback_journal` (copied, never rolled back: the main file may hold an interrupted write), `applied.pages_of_the_main_file_changed_by_the_wal`. Say which state a result is: main file as acquired, or with the WAL applied.

**Query.** Read the schema first (`sqlite_master`), then ask. Values come typed: a BLOB is length and sha256, text that is not UTF-8 keeps its bytes. The whole result is in `rows_file`; an inline page is not the result. Time columns have a unit and an epoch the schema or the app decides, not the value's look (`timeline/build`).

**Does not show.** A snapshot and a query show the rows SQLite holds. They do not recover deleted records, the freelist or unallocated pages, and a row's absence is not the event's absence. A live set copied file by file may not be one consistent state. Of a database encrypted by an extension (SQLCipher) the tool shows only the first bytes and their entropy, which identify nothing.

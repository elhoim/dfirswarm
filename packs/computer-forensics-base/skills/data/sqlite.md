---
id: data/sqlite
title: A SQLite database is a set of files
when: A SQLite database, with or without its -wal, -shm or -journal.
needs: []
tools: [sqlite_snapshot, sqlite_query]
requires_host: []
---

Use when a `.db`, `.sqlite` or an app store is the evidence. Not for another database kind or for recovering deleted records.

**The set.** A database is the main file plus a `-wal` (committed changes the main file may not hold yet, older pages, an incomplete transaction), a `-shm` (an index of the WAL) and a `-journal` (a rollback journal, hot when a write was interrupted). From an image, extract each file beside the database (`filesystem/extract`) into one directory under the main file's name plus the suffix. A copy of the main file alone is a different state; a live set copied file by file may not be one state.

**Snapshot, then query.** `sqlite_query` opens the file it is given read-only and immutable, so a WAL beside it is reported (`snapshot_status`: WAL NOT APPLIED) and not read. Run `sqlite_snapshot` on the main file as a job: it copies the set into `original/` with sha256s (and says `changed_during_copy` if a live file moved), reads the WAL against the format, and has SQLite apply it in `applied/database.sqlite`. Give `sqlite_query` the snapshot directory or its `database`.

    job_run tool=sqlite_snapshot args={"db_path": "work/extracted/<you>/History", "out_dir": "{OUT}/history"}

**Read the receipt.** `wal.frames_committed` (applied) against `frames_uncommitted_valid` (valid frames after the last commit: never applied), `first_invalid_frame` (a leftover of an earlier generation is normal; a checksum mismatch or a file ending inside a frame is damage: the snapshot is `partial`), `counts_agree` (SQLite and the tool found the same number of committed frames), `rollback_journal` (copied, never rolled back: the main file may hold an interrupted write), `applied.pages_of_the_main_file_changed_by_the_wal`.

**Query.** Read the schema first (`sqlite_master`; pragmas `user_version`, `application_id`, `freelist_count`), then ask. Values are typed: a BLOB is `length`, `sha256` and `blob_b64` (short) or `blob_b64_head`, its first `head_bytes` (long); text that is not UTF-8 keeps its bytes. The whole result is in `rows_file`; an inline page is not the result. Time columns have a unit and an epoch the schema or the app decides, not the value's look (`timeline/clocks`). An app's schema changes between versions: take a column's meaning from the version the evidence carries.

**Record.** The state a result is (as acquired, or WAL applied), the receipt, the database's sha256, the query, the `rows_file`, and the table, `rowid` and column of each value cited.

**Does not show.** A snapshot and a query show the rows SQLite holds. They do not recover deleted records, the freelist or unallocated pages (a non-zero `freelist_count` says free pages exist, not what they held), and a row's absence is not the event's absence. Of a database encrypted by an extension (SQLCipher) the tool shows only the first bytes and their entropy, which identify nothing.

**Sensitive output.** Rows of cookie, login, token, key and message tables hold secrets and private text: run the query as a job with `secret_output: true` and cite table, `rowid` and column, never the value. Before you query one, read `data/sqlite-secrets`: the inline page always holds values.

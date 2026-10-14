---
id: data/sqlite-secrets
title: Secret tables without the values
when: A table holds cookies, logins, tokens or keys.
needs: []
tools: [sqlite_query]
requires_host: []
---

Use only if `data/sqlite` sends you here: the table holds cookies, logins, tokens, keys or private messages. Not for ordinary application data (`data/sqlite`).

**In a job, write the values to a file.** Run `sqlite_query` as a job with `secret_output: true` and `write_values: true`, giving `table` (and `columns`, or `rowid_from` and `rowid_to` for part of it) and no `sql`:

    job_run tool=sqlite_query args={"db_path": "<snapshot or database>", "table": "logins", "write_values": true}

The values go only to `sqlite-query-values.jsonl` under the job's output (mode 0600, one line per cell with its table, `rowid`, column, type and length). The answer carries the same locators (a cell is `type:length`), the counts per column, and the first rows; `locators_file` has every row. There is no `sql` on purpose: a `WHERE` or `LIKE` over values you cannot see would confirm a guess, so rows are chosen by `rowid`, never by value. The file is created once per job, so a second export runs in a new job. A WITHOUT ROWID table is located by position (`n`). The file is for a job that must use the values and for the operator; hand a value on through the channel the operator named.

**Fallback, outside a job or without the mode.** `limit` is 1 or more, so the inline page always carries at least one row of values: on such a table select only locators (`rowid`, `length(col)`, `typeof(col)`), never the column itself.

**Record.** Table, `rowid`, column, type and length of each cell cited, and the values file's name; never the value, a fragment of it, or the `sha256` and base64 of a short BLOB.

**Does not show.** A type and a length show that a cell is filled and how big it is, not what it holds, whether it is valid or current, or that it opens anything.

**Sensitive output.** The values file is a sealed secret output: the job runs with `secret_output: true`, and the ledger cites locators only.

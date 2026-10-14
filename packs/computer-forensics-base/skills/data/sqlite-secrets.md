---
id: data/sqlite-secrets
title: Secret tables without the values
when: A table holds cookies, logins, tokens or keys.
needs: []
tools: [sqlite_query]
requires_host: []
---

Use only if `data/sqlite` sends you here: the table holds cookies, logins, tokens, keys or private messages. Not for ordinary application data (`data/sqlite`).

**In a job, write the values to a file.** Give `table` (and `columns`, or `rowid_from` and `rowid_to` for part of it) and no `sql`:

    job_run(tool: "sqlite_query", secret_output: true, args: {"db_path": "<snapshot or database>", "table": "logins", "write_values": true})

The values go only to `sqlite-query-values.jsonl` under the job's output (mode 0600, one line per cell, then an end line: a file without it was cut short). The answer carries each cell as `type:length`, the counts per column and the first rows; `locators_file` has every row. There is no `sql` on purpose: a `WHERE` or `LIKE` over values you cannot see would confirm a guess. The file is made once per job, after the table is found: a wrong name leaves nothing, a second export runs in a new job. The file is for a job that must use the values and for the operator; hand a value on through the channel the operator named.

**What locates a row** (`table_kind`). An ordinary table: `rowid`, SQLite's row key and no column's value (unless the application set it); a range selects by it. A table whose one primary key column is declared `INTEGER`: that column is the rowid, so the rowid is a value: never printed, a range refused (`rowid_is_a_value`), rows located by `n`, their position, which ranks the key's values. WITHOUT ROWID: `n` in primary key order, which ranks those values too. Virtual: `n`, or `virtual_table_unsupported`.

**Lengths.** A number's length is the characters of its decimal form: it tells the order of magnitude, and a PIN stored as an integer has lost its leading zeros. `cells_not_exported` lists a cell over the length limit (`value_too_large`) or one SQLite cannot compute (`unreadable`); the rest is exported. `values_file_error` (a full disk) says how many whole lines the kept file holds.

**Fallback, outside a job or without the mode.** `limit` is 1 or more, so the inline page always carries at least one row of values: on such a table select only locators (`rowid`, `length(col)`, `typeof(col)`), never the column itself. Where a column is the `INTEGER PRIMARY KEY`, `rowid` is its value: leave it out.

**Record.** Table, the locator (`rowid`, or `n` where `locator` is `n`), column, type and length of each cell cited, and the values file's name; never the value, a fragment of it, or the `sha256` and base64 of a short BLOB.

**Does not show.** A type and a length show that a cell is filled and how big it is, not what it holds, whether it is valid or current, or that it opens anything.

**Sensitive output.** The values file is a sealed secret output: the job runs with `secret_output: true`, and the ledger cites locators only.

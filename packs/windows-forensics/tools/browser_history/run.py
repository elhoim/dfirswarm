#!/usr/bin/env python3
"""Read a browser history database that was copied off a live or imaged disk.

This exists because of a measured failure: in one case `sqlite_query` had a
93% error rate against these files, and the cause was not the SQL. A browser
database extracted from an image arrives with its write-ahead log beside it,
and SQLite refuses to open it read-only while the WAL is unplayed, or opens it
and returns the state *before* the last session, which is the part an examiner
wants.

So: copy the database and any -wal, -shm and -journal beside it into a scratch
directory (under $OUT in a job), open the copy read-write so SQLite checkpoints the
WAL, and query that. The original is never touched. The answer says whether a WAL
sidecar was present and how many valid frames SQLite found in it and checkpointed
(`wal_present`, `wal_checkpoint`): a sidecar that was copied is not a log that was
replayed, and a WAL that belongs to another database or is damaged yields no frames.

Named queries: `chrome_visits` and `firefox_visits` list every visit, joined to its URL,
with the raw time, the transition and the referring visit; `chrome_url_summary` and
`firefox_url_summary` list one row per URL (a visit count and the last visit: a summary,
never a visit list; `chrome_history` and `firefox_history` are the old names of those two,
accepted and answered with a note). Anything else takes `sql`.

READ-ONLY, TWICE. A statement must begin with SELECT, WITH or PRAGMA, and the copy
is opened with an authorizer that denies everything but reading (and the pragmas that
only report).

SENSITIVE OUTPUT. A browser store can hold credentials and session tokens. Before any query
runs, every cell of a column that holds one is replaced, in the disposable copy, by a marker
that carries only its length: the `password_value` of `logins`, the `value` and
`encrypted_value` of `cookies` and `moz_cookies`, any column whose name says password,
secret, token, encrypted or card number, and Firefox's key database (`metadata`,
`nssPrivate`). No flag brings a value back: this tool produces none, and says which
columns it withheld, how many cells, and how many bytes or characters they held. It
decrypts nothing and has no capability to. Usernames, URLs and dates are returned.
"""
import json
import os
import re
import shutil
import signal
import sqlite3
import sys
import tempfile
from pathlib import Path

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self._out = None
        self._tmp: Path | None = None
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(
                r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
            )
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row: object) -> None:
        assert self._out is not None
        self._out.write(json.dumps(row, ensure_ascii=False, default=str))
        self._out.write("\n")

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(
                dir=self.path.parent, prefix=f".{self.path.name}-"
            )
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            assert self._tmp is not None
            os.replace(self._tmp, self.path)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

PARSER = "browser_history/2"

# Chromium page transition core types (page_transition_types.h) and Firefox visit types
# (nsINavHistoryService); the raw number is always returned beside the name.
CHROME_TRANSITION = (
    "CASE (v.transition & 255) WHEN 0 THEN 'link' WHEN 1 THEN 'typed' WHEN 2 THEN 'auto_bookmark' "
    "WHEN 3 THEN 'auto_subframe' WHEN 4 THEN 'manual_subframe' WHEN 5 THEN 'generated' "
    "WHEN 6 THEN 'start_page' WHEN 7 THEN 'form_submit' WHEN 8 THEN 'reload' WHEN 9 THEN 'keyword' "
    "WHEN 10 THEN 'keyword_generated' ELSE 'unknown' END"
)
FIREFOX_VISIT_TYPE = (
    "CASE v.visit_type WHEN 1 THEN 'link' WHEN 2 THEN 'typed' WHEN 3 THEN 'bookmark' WHEN 4 THEN 'embed' "
    "WHEN 5 THEN 'redirect_permanent' WHEN 6 THEN 'redirect_temporary' WHEN 7 THEN 'download' "
    "WHEN 8 THEN 'framed_link' WHEN 9 THEN 'reload' ELSE 'unknown' END"
)

QUERIES = {
    "chrome_visits": (
        "SELECT v.id AS visit_id, v.url AS url_id, u.url, u.title, v.visit_time AS visit_time_raw, "
        "strftime('%Y-%m-%dT%H:%M:%S', v.visit_time/1000000-11644473600, 'unixepoch') || '.' || printf('%06d', v.visit_time % 1000000) || 'Z' AS visit_utc, "
        "v.from_visit, v.transition AS transition_raw, " + CHROME_TRANSITION + " AS transition_core, v.visit_duration "
        "FROM visits v LEFT JOIN urls u ON u.id = v.url ORDER BY v.visit_time"
    ),
    "chrome_url_summary": (
        "SELECT u.id, u.url, u.title, u.visit_count, u.typed_count, u.last_visit_time AS last_visit_time_raw, "
        "datetime(u.last_visit_time/1000000-11644473600, 'unixepoch') AS last_visit_utc "
        "FROM urls u ORDER BY u.last_visit_time DESC"
    ),
    "chrome_downloads": (
        "SELECT d.id, d.target_path, d.tab_url, d.total_bytes, d.received_bytes, "
        "d.start_time AS start_time_raw, d.end_time AS end_time_raw, "
        "datetime(d.start_time/1000000-11644473600, 'unixepoch') AS start_utc, "
        "datetime(d.end_time/1000000-11644473600, 'unixepoch') AS end_utc "
        "FROM downloads d ORDER BY d.start_time DESC"
    ),
    "firefox_visits": (
        "SELECT v.id AS visit_id, v.place_id, p.url, p.title, v.visit_date AS visit_date_raw, "
        "strftime('%Y-%m-%dT%H:%M:%S', v.visit_date/1000000, 'unixepoch') || '.' || printf('%06d', v.visit_date % 1000000) || 'Z' AS visit_utc, "
        "v.from_visit, v.visit_type AS visit_type_raw, " + FIREFOX_VISIT_TYPE + " AS visit_type "
        "FROM moz_historyvisits v LEFT JOIN moz_places p ON p.id = v.place_id ORDER BY v.visit_date"
    ),
    "firefox_url_summary": (
        "SELECT p.id, p.url, p.title, p.visit_count, p.last_visit_date AS last_visit_date_raw, "
        "datetime(p.last_visit_date/1000000, 'unixepoch') AS last_visit_utc "
        "FROM moz_places p WHERE p.last_visit_date IS NOT NULL ORDER BY p.last_visit_date DESC"
    ),
    "firefox_downloads": (
        "SELECT a.id, a.content, a.dateAdded AS date_added_raw, datetime(a.dateAdded/1000000, 'unixepoch') AS added_utc "
        "FROM moz_annos a WHERE a.anno_attribute_id IN "
        "(SELECT id FROM moz_anno_attributes WHERE name LIKE 'downloads/%') ORDER BY a.dateAdded DESC"
    ),
    "tables": "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY name",
}
# The old names of the two URL summaries: they answered with one row per URL, not per visit.
OLD_NAMES = {"chrome_history": "chrome_url_summary", "firefox_history": "firefox_url_summary"}

# Columns that hold a credential or a session token, by table and column, and by name anywhere.
SENSITIVE_COLUMNS = {
    ("logins", "password_value"),
    ("cookies", "value"),
    ("cookies", "encrypted_value"),
    ("moz_cookies", "value"),
    ("metadata", "item1"),
    ("metadata", "item2"),
    ("nssprivate", "a11"),
    ("nssprivate", "a102"),
}
SENSITIVE_NAME = re.compile(r"passw(or)?d|passwd|\bpwd\b|secret|token|api_?key|private_?key|encrypted|card_?number|cvc|cvv|bearer", re.I)


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def statements(sql):
    """The statements of `sql`, each whole: split at a ";" only where SQLite
    says the text so far is a complete statement, so one inside a string or
    a comment stays where it is."""
    out, buf = [], ""
    for part in sql.split(";"):
        buf += part + ";"
        if sqlite3.complete_statement(buf):
            s = buf.strip().rstrip(";").strip()
            if s:
                out.append(s)
            buf = ""
    rest = buf.rstrip(";").strip()
    if rest:
        out.append(rest)
    return out


# The authorizer actions a read needs: SELECT, READ (a column), FUNCTION, RECURSIVE (a recursive
# WITH) and the pragmas that only report. Everything else (INSERT, UPDATE, DELETE, CREATE, DROP,
# ALTER, ATTACH, DETACH, TRANSACTION, SAVEPOINT, ...) is denied.
SQLITE_OK, SQLITE_DENY = 0, 1
A_SELECT, A_READ, A_PRAGMA, A_FUNCTION, A_RECURSIVE = 21, 20, 19, 31, 33
REPORTING_PRAGMAS = {
    "table_info", "table_xinfo", "table_list", "index_list", "index_info", "index_xinfo", "foreign_key_list",
    "database_list", "collation_list", "compile_options", "function_list", "module_list", "pragma_list",
    "schema_version", "user_version", "page_count", "page_size", "freelist_count", "encoding", "journal_mode",
    "integrity_check", "quick_check", "data_version", "application_id",
}
PRAGMAS_WITH_ARGUMENT = {"table_info", "table_xinfo", "index_list", "index_info", "index_xinfo", "foreign_key_list", "integrity_check", "quick_check"}


def read_only_authorizer(action, arg1, arg2, dbname, source):
    if action in (A_SELECT, A_READ, A_FUNCTION, A_RECURSIVE):
        return SQLITE_OK
    if action == A_PRAGMA:
        name = (arg1 or "").lower()
        if name in REPORTING_PRAGMAS and (arg2 is None or name in PRAGMAS_WITH_ARGUMENT):
            return SQLITE_OK
    return SQLITE_DENY


def quote(name):
    return '"' + str(name).replace('"', '""') + '"'


def withhold_sensitive(conn):
    """Replace, in the disposable copy and before any query runs, every text or BLOB cell of a
    sensitive column by a marker that holds only its length. Returns what was withheld. If a
    column cannot be withheld the run stops: nothing is queried."""
    conn.execute("PRAGMA secure_delete=ON")
    withheld = []
    tables = conn.execute("SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").fetchall()
    for table, ddl in tables:
        for col in conn.execute("PRAGMA table_xinfo(%s)" % quote(table)).fetchall():
            name, hidden = col[1], col[6]
            if hidden:
                continue
            if (table.lower(), name.lower()) not in SENSITIVE_COLUMNS and not SENSITIVE_NAME.search(name):
                continue
            q = quote(name)
            cells, total = conn.execute(
                "SELECT count(*), coalesce(sum(length(%s)), 0) FROM %s WHERE typeof(%s) IN ('text', 'blob')" % (q, quote(table), q)).fetchone()
            kinds = dict(conn.execute("SELECT typeof(%s), count(*) FROM %s WHERE typeof(%s) IN ('text', 'blob') GROUP BY 1" % (q, quote(table), q)).fetchall())
            if cells:
                conn.execute(
                    "UPDATE %s SET %s = '[withheld: ' || length(%s) || ' ' || (CASE typeof(%s) WHEN 'blob' THEN 'bytes' ELSE 'characters' END) || ']' "
                    "WHERE typeof(%s) IN ('text', 'blob')" % (quote(table), q, q, q, q))
            withheld.append({"table": table, "column": name, "cells_withheld": cells, "cell_types": kinds,
                             "units": "bytes (blob) or characters (text)", "total_length": total})
    conn.commit()
    return withheld


def scratch_parent():
    """Where the disposable copy lives: the job's $OUT, else the agent's own directory, else the system's."""
    out, job = os.environ.get("OUT"), os.environ.get("JOB_ID")
    if job and out:
        base = out
    else:
        base = os.path.join("work", re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"))
    try:
        os.makedirs(base, exist_ok=True)
        return base
    except OSError:
        return None


def jsonable(value):
    if isinstance(value, (bytes, bytearray)):
        return {"blob_hex": bytes(value).hex(), "length": len(value)}
    return value


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the History, places.sqlite or other database")
    if not os.path.isfile(path):
        fail("no such file", path=path)

    query = args.get("query", "tables")
    sql = args.get("sql")
    if sql is not None and not isinstance(sql, str):
        fail("sql must be a string")
    query_note = None
    if sql is None:
        if query in OLD_NAMES:
            query_note = ("%s is the old name of %s: it answers one row per URL (a visit count and the last visit), "
                          "never one row per visit; use %s for visits" % (
                              query, OLD_NAMES[query], "chrome_visits" if query.startswith("chrome") else "firefox_visits"))
            query = OLD_NAMES[query]
        if query not in QUERIES:
            fail("unknown query", query=query, known=sorted(QUERIES) + sorted(OLD_NAMES))
        sql = QUERIES[query]
    # Several statements are run one by one: sqlite3's execute takes one,
    # and "You can only execute one statement at a time" was the answer two
    # agents got for "schema; count" (sixth CTF round).
    stmts = statements(sql)
    if not stmts:
        fail("sql is empty")
    for s in stmts:
        if not s.lower().startswith(("select", "with", "pragma")):
            # This reads evidence. A statement that could write does not belong.
            fail("sql must be a SELECT, WITH or PRAGMA", statement=s)

    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))
    page_size = min(limit, 20000)

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))   # so the copy below is removed when the harness stops us
    scratch = tempfile.mkdtemp(prefix=".browser-scratch-", dir=scratch_parent())
    try:
        copy = os.path.join(scratch, os.path.basename(path))
        shutil.copy2(path, copy)
        sidecars = []
        wal_bytes = 0
        wal_seen = False
        for suffix in ("-wal", "-shm", "-journal"):
            beside = path + suffix
            if os.path.isfile(beside):
                shutil.copy2(beside, copy + suffix)
                sidecars.append(os.path.basename(beside))
                if suffix == "-wal":
                    wal_seen = True
                    wal_bytes = os.path.getsize(beside)
        with open(copy, "rb") as fh:
            head = fh.read(100)
        declares_wal = len(head) >= 20 and head[:16] == b"SQLite format 3\x00" and head[18] == 2 and head[19] == 2

        # Read-write on the *copy*, so SQLite replays and checkpoints the WAL.
        conn = sqlite3.connect(copy)
        conn.text_factory = lambda b: b.decode("utf-8", errors="backslashreplace")
        results = []
        try:
            try:
                checkpoint = conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
                withheld = withhold_sensitive(conn)
                conn.execute("PRAGMA query_only=ON")
            except sqlite3.DatabaseError as exc:
                fail("this is not a SQLite database SQLite can read, or a sensitive column could not be withheld; nothing was queried",
                     path=path, reason=str(exc), first_bytes_hex=head[:16].hex(), size=os.path.getsize(path))
            conn.set_authorizer(read_only_authorizer)
            wal = {"busy": checkpoint[0], "log_frames": checkpoint[1], "checkpointed_frames": checkpoint[2]}
            for statement_index, s in enumerate(stmts):
                try:
                    cur = conn.execute(s)
                    columns = [d[0] for d in (cur.description or [])]
                    # Two result columns of one name (`SELECT a.id, b.id`) would overwrite each other in a
                    # row; the later ones are numbered and said so.
                    names, seen = [], {}
                    for c in columns:
                        seen[c] = seen.get(c, 0) + 1
                        names.append(c if seen[c] == 1 else "%s_%d" % (c, seen[c]))
                    page = LosslessPage(
                        "browser_history",
                        [path, s, statement_index],
                        page_size,
                    )
                    for row in cur:
                        page.add({n: jsonable(v) for n, v in zip(names, row)})
                    kept = page.finish()
                    if names != columns:
                        columns = names
                except sqlite3.Error as exc:
                    fail("sqlite refused the query", reason=str(exc), sql=s, done=len(results))
                results.append({
                    "sql": s,
                    "columns": columns,
                    "rows": page.page,
                    "row_count": kept["matched"],
                    **kept,
                })
        finally:
            conn.close()

        out = {"path": path, "parser": PARSER, "sqlite_version": sqlite3.sqlite_version, "query": None if args.get("sql") else query}
        if query_note:
            out["query_note"] = query_note
        # One statement answers as it always has; several answer each in turn.
        out.update({k: v for k, v in results[0].items() if k != "sql"} if len(results) == 1 else {"results": results})
        frames = wal["checkpointed_frames"]
        out.update({
            "sidecars_copied": sidecars,
            "wal_present": wal_seen and wal_bytes > 0,
            "wal_bytes": wal_bytes,
            "database_declares_wal": declares_wal,
            "wal_checkpoint": wal,
            "wal_frames_replayed": frames if frames and frames > 0 else 0,
            "wal_note": "wal_present says a -wal file was beside the database and was copied; wal_frames_replayed is the number of "
                        "valid frames SQLite found in it and checkpointed into the copy (0 when the log is empty, damaged, or belongs "
                        "to another database). It does not say which transactions those frames held.",
            "sensitive_columns_withheld": withheld,
            "read_only": "the statement must start with SELECT, WITH or PRAGMA, and the copy is opened with an authorizer that denies anything else",
        })
        print(json.dumps(out, indent=2, default=str))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    main()

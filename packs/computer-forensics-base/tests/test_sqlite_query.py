"""sqlite_query: the WAL is said, not silently dropped; reading is all a statement may do; the answer is bounded and typed.

Databases are made with Python's sqlite3 module (the engine itself, not the tool's
output), the WAL's expected frame count is worked out from the file's size and the
documented frame layout, and the BLOB's digest from hashlib.
"""
import base64
import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import unittest

from support import Case, run_tool, tool_path


class SqliteQuery(Case):
    def db(self, name="a.db", script="create table a(x); insert into a values(1),(2),(3);"):
        path = self.path(name)
        conn = sqlite3.connect(path)
        conn.executescript(script)
        conn.commit()
        conn.close()
        return path

    def query(self, db, sql, **kw):
        return run_tool("sqlite_query", dict({"db_path": db, "sql": sql}, **kw), self.dir)

    def test_rows_in_the_wal_are_flagged_as_not_applied(self):
        path = self.path("w.db")
        writer = sqlite3.connect(path)
        writer.execute("pragma journal_mode=wal")
        writer.execute("pragma wal_autocheckpoint=0")
        writer.execute("create table a(x)")
        writer.execute("insert into a values(1)")
        writer.commit()
        writer.execute("pragma wal_checkpoint(truncate)")      # row 1 is now in the main file
        writer.execute("insert into a values(2)")               # row 2 is committed, in the WAL only
        writer.commit()
        try:
            wal = path + "-wal"
            self.assertTrue(os.path.getsize(wal) > 32)
            page = sqlite3.connect(path).execute("pragma page_size").fetchone()[0]
            expected_frames = (os.path.getsize(wal) - 32) // (24 + page)      # the documented WAL layout
            r = self.query(path, "select x from a order by x")
        finally:
            writer.close()
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual([row["values"][0] for row in r.json["rows"]], [1])        # the WAL's row is not in the result ...
        wal_entry = [s for s in r.json["sidecars"] if s["name"].endswith("-wal")][0]
        self.assertTrue(wal_entry["present"])
        self.assertEqual(wal_entry["frames_valid"], expected_frames)               # ... and the tool says there are frames
        self.assertGreater(wal_entry["frames_committed"], 0)
        self.assertIn("WAL NOT APPLIED", r.json["snapshot_status"])

    def test_a_database_with_no_sidecar_says_so(self):
        r = self.query(self.db(), "select count(*) from a")
        self.assertIn("no WAL frames", r.json["snapshot_status"])

    def test_nothing_that_writes_runs(self):
        db = self.db()
        before = self.read(db, "rb")
        other = self.path("other.db")
        for sql in ("delete from a", "insert into a values(9)", "update a set x=0", "drop table a", "create table b(y)",
                    "attach database '%s' as o" % other, "pragma journal_mode=delete", "pragma user_version=5",
                    "vacuum", "vacuum into '%s'" % other, "select load_extension('nothing')",
                    "with c as (select 1) delete from a", "select 1; delete from a"):
            r = self.query(db, sql)
            self.assertEqual(r.code, 1, sql)
            self.assertIs(r.json["ok"], False, sql)
            self.assertIn("refused", r.json["error"], sql)
        self.assertEqual(self.read(db, "rb"), before)
        self.assertFalse(os.path.exists(other))
        # readonly=false is refused outright, not honoured.
        r = self.query(db, "select 1", readonly=False)
        self.assertEqual(r.code, 1)
        self.assertIn("never opens a database for writing", r.json["error"])
        # What only reports is allowed.
        self.assertEqual(self.query(db, "pragma table_info(a)").json["rows"][0]["values"][1], "x")
        self.assertEqual(self.query(db, "pragma user_version").code, 0)
        self.assertEqual(self.query(db, "with c(n) as (select 1 union all select n+1 from c where n<3) select n from c").json["row_count"], 3)

    def test_a_large_result_has_a_bounded_inline_page_and_a_complete_file(self):
        db = self.db("big.db", "create table t(n integer, s text); " +
                     "with c(n) as (select 1 union all select n+1 from c where n<20000) insert into t select n, 'row ' || n from c;")
        r = self.query(db, "select n, s from t order by n")
        self.assertEqual(r.json["row_count"], 20000)
        self.assertEqual(r.json["returned"], 100)
        self.assertTrue(r.json["truncated"])
        lines = self.read(r.json["rows_file"]).splitlines()
        self.assertEqual(json.loads(lines[0])["columns"], ["n", "s"])
        self.assertEqual(len(lines), 20001)
        self.assertEqual(json.loads(lines[-1]), {"n": 20000, "values": [20000, "row 20000"]})
        # The inline page also stops at a byte ceiling, whatever limit says.
        wide = self.db("wide.db", "create table t(s text); with c(n) as (select 1 union all select n+1 from c where n<400) insert into t select hex(zeroblob(2000)) from c;")
        r = self.query(wide, "select s from t", limit=400)
        self.assertLess(r.json["returned"], 400)
        self.assertEqual(r.json["row_count"], 400)
        self.assertEqual(len(self.read(r.json["rows_file"]).splitlines()), 401)
        self.assertLess(len(r.stdout), 200 * 1024)

    def test_cells_are_typed(self):
        db = self.db("c.db", "create table t(a, b, c, d); insert into t values(NULL, 1.5, 'x', x'0001ff');")
        row = self.query(db, "select a, b, c, d from t").json["rows"][0]["values"]
        blob = b"\x00\x01\xff"
        self.assertEqual(row, [None, 1.5, "x", {"blob_b64": base64.b64encode(blob).decode(), "length": 3, "sha256": hashlib.sha256(blob).hexdigest()}])

    def test_a_long_blob_is_whole_in_the_file_and_headed_inline(self):
        blob = bytes(range(256)) * 8
        db = self.path("b.db")
        conn = sqlite3.connect(db)
        conn.execute("create table t(d)")
        for _ in range(3):
            conn.execute("insert into t values(?)", (blob,))
        conn.commit()
        conn.close()
        r = self.query(db, "select d from t", limit=1)
        inline = r.json["rows"][0]["values"][0]
        self.assertEqual(inline["length"], 2048)
        self.assertEqual(inline["sha256"], hashlib.sha256(blob).hexdigest())
        self.assertIn("blob_b64_head", inline)
        line = json.loads(self.read(r.json["rows_file"]).splitlines()[1])
        self.assertEqual(base64.b64decode(line["values"][0]["blob_b64"]), blob)

    def test_several_statements_run_one_by_one(self):
        r = self.query(self.db(), "select count(*) from a; select 'a;b';")
        self.assertEqual([x["rows"][0]["values"][0] for x in r.json["results"]], [3, "a;b"])

    def test_high_entropy_is_not_called_encryption(self):
        junk = self.write("events.db", os.urandom(8192))
        r = self.query(junk, "select 1")
        self.assertEqual(r.code, 1)
        self.assertGreater(r.json["first_page_entropy_bits_per_byte"], 7.5)
        reading = r.json["reading"]
        self.assertIn("not identified", reading)
        self.assertIn("one explanation", reading)
        self.assertNotIn("an encrypted database (SQLCipher or an app's own); no query runs without its key", reading)

    def test_a_query_stopped_by_its_time_budget_says_so_and_keeps_what_it_had(self):
        db = self.db()
        r = self.query(db, "with recursive c(n) as (select 1 union all select n+1 from c) select count(*) from c", max_seconds=1)
        self.assertEqual(r.code, 1)
        self.assertIs(r.json["ok"], False)
        self.assertIs(r.json["timed_out"], True)
        self.assertIs(r.json["complete"], False)
        # Rows that were being returned when the clock ran out are kept, in a file that is whole, and named.
        r = self.query(db, "with recursive c(n) as (select 1 union all select n+1 from c) select n from c", max_seconds=1, limit=5)
        self.assertIs(r.json["timed_out"], True)
        kept = r.json["rows_read_before_the_stop"]
        self.assertGreater(kept["row_count"], 5)
        lines = self.read(kept["rows_file"]).splitlines()
        self.assertEqual(len(lines), kept["row_count"] + 1)
        self.assertEqual(json.loads(lines[-1]), {"n": kept["row_count"], "values": [kept["row_count"]]})
        self.assertEqual([x["values"][0] for x in kept["rows"]], [1, 2, 3, 4, 5])
        self.assertFalse([n for n in os.listdir(os.path.dirname(self.path(kept["rows_file"]))) if n.startswith(".sqlite_query-")], "no half-written file is left")

    def test_the_last_statement_needs_no_semicolon_and_is_never_dropped(self):
        db = self.db()
        r = self.query(db, "select count(*) from a -- how many")
        self.assertEqual((r.code, r.json["rows"][0]["values"][0]), (0, 3))
        r = self.query(db, "select 1; select 2 /* the end */")
        self.assertEqual([x["rows"][0]["values"][0] for x in r.json["results"]], [1, 2])
        r = self.query(db, "select 1; select 'never closed")
        self.assertEqual(r.code, 1)
        self.assertIs(r.json["ok"], False)
        self.assertIn("error", r.json)
        self.assertEqual([x["rows"][0]["values"][0] for x in r.json["completed_statements"]], [1])

    def test_values_that_are_not_what_they_say_are_refused_not_tracebacks(self):
        db = self.db()
        for bad in ({"sql": "select 1\u0000"}, {"sql": "select '\ud800'"}, {"csv": "false"}, {"csv": 1}, {"readonly": "no"}, {"readonly": 0}):
            args = dict({"db_path": db, "sql": "select 1"}, **bad)
            r = run_tool("sqlite_query", args, self.dir)
            self.assertEqual(r.code, 1, bad)
            self.assertNotIn("Traceback", r.stderr, bad)
            self.assertIs(r.json["ok"], False, bad)
        self.assertEqual(self.query(db, "select 1", readonly=True, csv=False).code, 0)
        r = self.query(db, "select 1 " + " " * (64 * 1024))
        self.assertEqual(r.code, 1)
        self.assertIn("longer than 65536 bytes", r.json["error"])

    def test_a_result_of_large_blobs_is_read_a_row_at_a_time(self):
        db = self.path("big.db")
        conn = sqlite3.connect(db)
        conn.execute("create table t(d)")
        for _ in range(12):
            conn.execute("insert into t values(zeroblob(?))", (8 * 1024 * 1024,))
        conn.commit()
        conn.close()
        wrapper = ("import json, resource, subprocess, sys\n"
                   "p = subprocess.run([sys.executable, sys.argv[1]], input=sys.argv[2], capture_output=True, text=True)\n"
                   "print(json.dumps({'out': p.stdout, 'peak': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}))\n")
        env = {k: v for k, v in os.environ.items() if k not in ("JOB_ID", "OUT", "AGENT_ID")}
        proc = subprocess.run([sys.executable, "-c", wrapper, tool_path("sqlite_query"), json.dumps({"db_path": db, "sql": "select d from t", "limit": 12})],
                              capture_output=True, text=True, cwd=self.dir, env=env)
        got = json.loads(proc.stdout)
        result = json.loads(got["out"])
        self.assertEqual((result["ok"], result["row_count"]), (True, 12))
        lines = self.read(result["rows_file"]).splitlines()
        self.assertEqual(len(lines), 13)
        first = json.loads(lines[1])["values"][0]
        self.assertEqual((first["length"], first["sha256"]), (8 * 1024 * 1024, hashlib.sha256(bytes(8 * 1024 * 1024)).hexdigest()))
        peak = got["peak"] * (1 if sys.platform == "darwin" else 1024)
        self.assertLess(peak, 140 * 1024 * 1024, "the peak was %d bytes for 96 MiB of blobs" % peak)

    def test_a_journal_that_is_not_hot_is_not_called_one_and_a_link_finds_its_targets_sidecars(self):
        db = self.db()
        self.write("a.db-journal", b"\0" * 512)
        r = self.query(db, "select 1")
        journal = [s for s in r.json["sidecars"] if s["name"].endswith("-journal")][0]
        self.assertIn("not a hot journal", journal["state"])
        self.assertNotIn("not been rolled back", r.json["snapshot_status"])
        self.assertNotIn("interrupted write", r.json["snapshot_status"])
        self.write("a.db-journal", bytes([0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]) + b"\0" * 504)
        r = self.query(db, "select 1")
        self.assertIn("interrupted write", r.json["snapshot_status"])
        # A link to the database: the files beside the file it points at are the ones SQLite looks for.
        os.symlink(db, self.path("link.db"))
        r = self.query(self.path("link.db"), "select 1")
        self.assertTrue([s for s in r.json["sidecars"] if s["name"] == "a.db-journal"][0]["present"])

    def test_a_rows_file_is_never_replaced_by_a_later_answer_to_the_same_query(self):
        db = self.db()
        sql = "with recursive c(n) as (select 1 union all select n+1 from c where n<1000000) select n from c"
        first = self.query(db, sql, limit=5)
        self.assertEqual(first.json["row_count"], 1000000)
        whole = self.path(first.json["rows_file"])
        size = os.path.getsize(whole)
        # The same query with a clock of one second is cut short: a different answer under the same name.
        cut = self.query(db, sql, limit=5, max_seconds=1)
        kept = cut.json["rows_read_before_the_stop"]
        self.assertLess(kept["row_count"], 1000000)
        self.assertTrue(kept["rows_file"].endswith("-0.2.jsonl"), kept["rows_file"])
        self.assertEqual(os.path.getsize(whole), size, "the complete answer was replaced by the partial one")
        self.assertEqual((first.json["earlier_answers"], kept["earlier_answers"]), (0, 1))
        self.assertEqual(len(self.read(whole).splitlines()), 1000001)
        self.assertEqual(len(self.read(self.path(kept["rows_file"])).splitlines()), kept["row_count"] + 1)
        # The same complete answer again is the file that is there, not a copy of it.
        again = self.query(db, sql, limit=5)
        self.assertEqual(again.json["rows_file"], first.json["rows_file"])

    def test_a_value_past_the_limit_is_refused_by_name_and_one_below_it_is_streamed(self):
        db = self.path("big.db")
        conn = sqlite3.connect(db)
        conn.execute("create table t(d)")
        conn.execute("insert into t values(zeroblob(?))", (50 * 1024 * 1024,))
        conn.execute("insert into t values(zeroblob(?))", (66 * 1024 * 1024,))
        conn.commit()
        conn.close()
        wrapper = ("import json, resource, subprocess, sys\n"
                   "p = subprocess.run([sys.executable, sys.argv[1]], input=sys.argv[2], capture_output=True, text=True)\n"
                   "print(json.dumps({'out': p.stdout, 'peak': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}))\n")
        env = {k: v for k, v in os.environ.items() if k not in ("JOB_ID", "OUT", "AGENT_ID")}

        def go(sql):
            proc = subprocess.run([sys.executable, "-c", wrapper, tool_path("sqlite_query"), json.dumps({"db_path": db, "sql": sql})], capture_output=True, text=True, cwd=self.dir, env=env)
            got = json.loads(proc.stdout)
            return json.loads(got["out"]), got["peak"] * (1 if sys.platform == "darwin" else 1024)

        ok, peak = go("select d from t where rowid = 1")
        self.assertEqual(ok["row_count"], 1)
        line = json.loads(self.read(ok["rows_file"]).splitlines()[1])["values"][0]
        self.assertEqual((line["length"], line["sha256"]), (50 * 1024 * 1024, hashlib.sha256(bytes(50 * 1024 * 1024)).hexdigest()))
        self.assertEqual(len(base64.b64decode(line["blob_b64"])), 50 * 1024 * 1024)
        self.assertLess(peak, 240 * 1024 * 1024, "peak %d bytes for one 50 MiB value (the earlier code needed 350 MB)" % peak)
        refused, peak = go("select d from t where rowid = 2")
        self.assertIs(refused["ok"], False)
        self.assertEqual(refused["reason"], "value_too_long")
        self.assertIn("substr()", refused["error"])
        self.assertLess(peak, 120 * 1024 * 1024, "peak %d bytes for a refused 66 MiB value" % peak)
        huge, peak = go("select zeroblob(999999999)")
        self.assertEqual(huge["reason"], "value_too_long")
        self.assertLess(peak, 120 * 1024 * 1024)


TEXT_CANARY = "canary-text-3f9a1c77d2e4"
BLOB_CANARY = b"canary-blob-b81e5d02a6c9"


class SqliteQueryValues(Case):
    """write_values: the values of one table go to a sealed file and nowhere else. Databases are made with the sqlite3 module;
    the canaries are strings the tests plant, so a value that reaches the answer or any other file is found by a plain search."""

    def secret_db(self, name="inputs/logins.db", rows=3):
        path = self.path(name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        conn = sqlite3.connect(path)
        conn.execute("create table logins(id integer primary key, origin text, secret blob, note text)")
        conn.execute("insert into logins(origin, secret, note) values('site-one', ?, ?)", (BLOB_CANARY, TEXT_CANARY))
        for n in range(rows - 1):
            conn.execute("insert into logins(origin, secret, note) values(?, NULL, ?)", ("site-%d" % (n + 2), "plain %d" % n))
        conn.commit()
        conn.close()
        return path

    def job(self, name="job-out", job_id="j000031"):
        out = self.path(name)
        os.makedirs(out, exist_ok=True)
        return out, {"JOB_ID": job_id, "OUT": out}

    def export(self, db, env=None, **kw):
        return run_tool("sqlite_query", dict({"db_path": db, "table": "logins", "write_values": True}, **kw), self.dir, env=env)

    def files_outside(self, *skip):
        """Every file under the scratch directory except the evidence and the skipped ones."""
        found = []
        for base, _dirs, files in os.walk(self.dir):
            for f in files:
                full = os.path.join(base, f)
                if full not in skip and not full.startswith(self.path("inputs") + os.sep):
                    found.append(full)
        return found

    def test_the_values_are_refused_outside_a_job_and_nothing_is_written(self):
        db = self.secret_db()
        r = self.export(db)
        self.assertEqual(r.code, 1)
        self.assertEqual(r.stderr, "", "a refusal is a JSON answer, not a traceback")
        self.assertIn("refused outside a job", r.json["error"])
        self.assertEqual(r.json["write_values"], "refused")
        self.assertNotIn(TEXT_CANARY, r.stdout)
        self.assertEqual(self.files_outside(), [])

    def test_a_value_is_in_the_sealed_file_only_not_in_the_answer_nor_in_any_other_file(self):
        db = self.secret_db()
        out, env = self.job()
        r = self.export(db, env, limit=2)
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertIs(r.json["ok"], True)
        # Not in stdout (the whole answer, its text form included), in neither encoding.
        b64 = base64.b64encode(BLOB_CANARY).decode()
        for needle in (TEXT_CANARY, BLOB_CANARY.decode(), b64, hashlib.sha256(BLOB_CANARY).hexdigest(), hashlib.sha256(TEXT_CANARY.encode()).hexdigest()):
            self.assertNotIn(needle, r.stdout)
            self.assertNotIn(needle, r.stderr)
        # The locators are there: table, rowid, column, type, length, and the counts.
        self.assertEqual((r.json["table"], r.json["locator"], r.json["row_count"]), ("logins", "rowid", 3))
        first = r.json["rows"][0]
        self.assertEqual((first["n"], first["rowid"]), (1, 1))
        cols = [c["name"] for c in r.json["columns"]]
        self.assertEqual(cols, ["id", "origin", "secret", "note"])
        self.assertEqual(first["cells"][cols.index("secret")], "blob:%d" % len(BLOB_CANARY))
        self.assertEqual(first["cells"][cols.index("note")], "text:%d" % len(TEXT_CANARY))
        self.assertEqual(r.json["cells_null"], 2)
        self.assertEqual(r.json["secret_values"]["written"], r.json["cells_with_a_value"])
        # The values file is the one place: mode 0600, named, with both canaries, one line per cell that is not NULL.
        values_path = os.path.join(out, "sqlite-query-values.jsonl")
        self.assertEqual(r.json["secret_values"]["values_file"], "store/jobs/j000031/out/sqlite-query-values.jsonl")
        self.assertEqual(stat.S_IMODE(os.stat(values_path).st_mode), 0o600)
        lines = [json.loads(l) for l in self.read(values_path).splitlines()]
        self.assertEqual(len(lines), 3 * 3 + 1)
        by = {(l["rowid"], l["column"]): l for l in lines}
        self.assertEqual(by[(1, "note")]["value"], TEXT_CANARY)
        self.assertEqual(base64.b64decode(by[(1, "secret")]["value"]["blob_b64"]), BLOB_CANARY)
        self.assertEqual((by[(1, "secret")]["table"], by[(1, "secret")]["n"], by[(1, "secret")]["length"]), ("logins", 1, len(BLOB_CANARY)))
        self.assertNotIn("sha256", self.read(values_path), "no digest of a value, not even in the sealed file")
        self.assertNotIn((2, "secret"), by)
        # No other file holds a value: the locators file (3 rows, limit 2) is made, and has none.
        self.assertTrue(r.json["truncated"])
        locators = os.path.join(out, "tool-output", os.path.basename(r.json["locators_file"]))
        extra = self.files_outside(values_path)
        self.assertEqual(extra, [locators], "the locators file is the only other file")
        for f in extra:
            data = self.read(f, "rb")
            for needle in (TEXT_CANARY.encode(), BLOB_CANARY, b64.encode()):
                self.assertNotIn(needle, data, f)
        located = [json.loads(l) for l in self.read(locators).splitlines()]
        self.assertEqual([x["rowid"] for x in located[1:]], [1, 2, 3])
        self.assertEqual(len(located[1]["cells"]), 4)

    def test_a_second_run_in_the_same_jobs_output_is_refused_as_json_and_keeps_the_first_file(self):
        db = self.secret_db()
        out, env = self.job(job_id="j000032")
        self.assertEqual(self.export(db, env).code, 0)
        values_path = os.path.join(out, "sqlite-query-values.jsonl")
        before = self.read(values_path)
        again = self.export(db, env)
        self.assertEqual(again.code, 1)
        self.assertEqual(again.stderr, "", "a refusal is a JSON answer, not a traceback")
        self.assertIn("values file already exists", again.json["error"])
        self.assertEqual(again.json["write_values"], "refused")
        self.assertEqual(self.read(values_path), before, "the first run's file is as it was")
        self.assertEqual([n for n in os.listdir(os.path.join(out, "tool-output")) if n.startswith(".")] if os.path.isdir(os.path.join(out, "tool-output")) else [], [], "no half-written file is left")

    def test_a_link_at_the_values_file_is_refused_by_name_and_not_followed(self):
        db = self.secret_db()
        out, env = self.job(job_id="j000033")
        victim = self.write("victim.txt", "keep me")
        os.symlink(victim, os.path.join(out, "sqlite-query-values.jsonl"))
        r = self.export(db, env)
        self.assertEqual(r.code, 1)
        self.assertIn("values file already exists", r.json["error"])
        self.assertEqual(self.read(victim), "keep me")

    def test_there_is_no_sql_in_the_mode_so_no_filter_confirms_a_guess(self):
        db = self.secret_db()
        out, env = self.job(job_id="j000034")
        # The oracle would be: select rowid from logins where note like 'canary-text-3f%' -> a row means the guess is right.
        r = run_tool("sqlite_query", {"db_path": db, "write_values": True, "table": "logins",
                                      "sql": "select rowid from logins where note like 'canary-text-3f%'"}, self.dir, env=env)
        self.assertEqual(r.code, 1)
        self.assertEqual(r.json["write_values"], "refused")
        self.assertIn("not sql", r.json["error"])
        self.assertFalse(os.path.exists(os.path.join(out, "sqlite-query-values.jsonl")), "refused before anything was created")
        # The parameters of the mode do not leak into an ordinary query either.
        plain = run_tool("sqlite_query", {"db_path": db, "sql": "select 1", "table": "logins"}, self.dir)
        self.assertEqual(plain.code, 1)
        self.assertIn("belong to write_values", plain.json["error"])
        # A rowid range selects by position, and the counts are the same whatever the values are.
        ranged = self.export(db, env, rowid_from=2, rowid_to=3)
        self.assertEqual(ranged.code, 0, ranged.stdout)
        self.assertEqual([x["rowid"] for x in ranged.json["rows"]], [2, 3])
        self.assertEqual(ranged.json["row_count"], 2)
        self.assertNotIn(TEXT_CANARY, ranged.stdout)

    def test_columns_choose_what_is_written_and_a_wrong_name_or_a_view_is_refused(self):
        db = self.secret_db()
        out, env = self.job(job_id="j000035")
        r = self.export(db, env, columns=["note"])
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual([c["name"] for c in r.json["columns"]], ["note"])
        lines = [json.loads(l) for l in self.read(os.path.join(out, "sqlite-query-values.jsonl")).splitlines()]
        self.assertEqual({l["column"] for l in lines}, {"note"})
        for kw, word in (({"columns": ["nope"]}, "no column"), ({"columns": []}, "columns is a list"), ({"table": "nope"}, "no table")):
            out2, env2 = self.job(name="o-%d" % len(word), job_id="j000036")
            bad = self.export(db, env2, **kw)
            self.assertEqual(bad.code, 1, kw)
            self.assertIn(word, bad.json["error"], kw)
            self.assertIsNone(bad.json and bad.json.get("secret_values"))
        conn = sqlite3.connect(db)
        conn.execute("create view v as select * from logins")
        conn.commit()
        conn.close()
        out3, env3 = self.job(name="o-view", job_id="j000037")
        view = self.export(db, env3, table="v")
        self.assertEqual(view.code, 1)
        self.assertIn("no table", view.json["error"])

    def test_a_table_without_rowid_is_located_by_position_and_a_rowid_range_is_refused(self):
        path = self.path("inputs/w.db")
        os.makedirs(os.path.dirname(path))
        conn = sqlite3.connect(path)
        conn.execute("create table kv(k text primary key, v text) without rowid")
        conn.executemany("insert into kv values(?, ?)", [("a", TEXT_CANARY), ("b", "plain")])
        conn.commit()
        conn.close()
        out, env = self.job(job_id="j000038")
        r = run_tool("sqlite_query", {"db_path": path, "table": "kv", "write_values": True, "columns": ["v"]}, self.dir, env=env)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertIn("this table has no rowid", r.json["locator"])
        self.assertEqual([(x["n"], x["rowid"]) for x in r.json["rows"]], [(1, None), (2, None)])
        self.assertNotIn(TEXT_CANARY, r.stdout)
        out2, env2 = self.job(name="o2", job_id="j000039")
        ranged = run_tool("sqlite_query", {"db_path": path, "table": "kv", "write_values": True, "rowid_from": 1}, self.dir, env=env2)
        self.assertEqual(ranged.code, 1)
        self.assertIn("WITHOUT ROWID", ranged.json["error"])

    def test_a_name_shaped_like_a_token_is_not_printed_and_text_that_is_not_utf8_is_kept_in_the_file_only(self):
        token = "Zq8Xv3Lm9Rt2Hw5Bn7Cd4Fg6Js1Kp0"
        path = self.path("inputs/%s.db" % token)
        os.makedirs(os.path.dirname(path))
        conn = sqlite3.connect(path)
        conn.text_factory = bytes
        conn.execute('create table "%s"(v)' % token)
        conn.execute('insert into "%s" values(CAST(? AS TEXT))' % token, (b"\xff\xfe" + TEXT_CANARY.encode(),))
        conn.commit()
        conn.close()
        out, env = self.job(job_id="j000040")
        r = run_tool("sqlite_query", {"db_path": path, "table": token, "write_values": True}, self.dir, env=env)
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertNotIn(token, r.stdout, "a file or table name shaped like a token is withheld on every channel")
        self.assertIn("withheld", r.stdout)
        self.assertNotIn(TEXT_CANARY, r.stdout)
        line = json.loads(self.read(os.path.join(out, "sqlite-query-values.jsonl")).splitlines()[0])
        self.assertEqual(line["table"], token, "the sealed file keeps the real name")
        self.assertEqual(base64.b64decode(line["value"]["bytes_b64"]), b"\xff\xfe" + TEXT_CANARY.encode())
        self.assertEqual(r.json["rows"][0]["cells"], ["text_not_utf8:%d" % (2 + len(TEXT_CANARY))])
        # An error that quotes the name withholds it too.
        out2, env2 = self.job(name="o2", job_id="j000041")
        bad = run_tool("sqlite_query", {"db_path": path, "table": token + "x", "write_values": True}, self.dir, env=env2)
        self.assertEqual(bad.code, 1)
        self.assertNotIn(token, bad.stdout)

    def test_a_large_blob_is_written_in_slices_and_whole_and_the_ordinary_mode_is_as_it_was(self):
        path = self.path("inputs/big.db")
        os.makedirs(os.path.dirname(path))
        blob = os.urandom(2 * 1024 * 1024 + 17)
        conn = sqlite3.connect(path)
        conn.execute("create table t(d blob)")
        conn.execute("insert into t values(?)", (blob,))
        conn.commit()
        conn.close()
        out, env = self.job(job_id="j000042")
        r = run_tool("sqlite_query", {"db_path": path, "table": "t", "write_values": True}, self.dir, env=env)
        self.assertEqual(r.code, 0, r.stdout[:300])
        line = json.loads(self.read(os.path.join(out, "sqlite-query-values.jsonl")))
        self.assertEqual(base64.b64decode(line["value"]["blob_b64"]), blob)
        self.assertEqual(line["length"], len(blob))
        self.assertNotIn(base64.b64encode(blob[:60]).decode(), r.stdout)
        # Outside write_values the tool returns what it always did: the value is in the answer.
        plain = run_tool("sqlite_query", {"db_path": self.secret_db(), "sql": "select note, secret from logins limit 1"}, self.dir)
        self.assertEqual(plain.code, 0, plain.stdout)
        self.assertIn(TEXT_CANARY, plain.stdout)
        self.assertEqual(plain.json["rows"][0]["values"][1]["sha256"], hashlib.sha256(BLOB_CANARY).hexdigest())
        # Inside a job the ordinary mode is unchanged too: no values file is made.
        out2, env2 = self.job(name="o3", job_id="j000043")
        injob = run_tool("sqlite_query", {"db_path": self.secret_db("inputs/b.db"), "sql": "select note from logins limit 1"}, self.dir, env=env2)
        self.assertEqual(injob.code, 0, injob.stdout)
        self.assertFalse(os.path.exists(os.path.join(out2, "sqlite-query-values.jsonl")))


if __name__ == "__main__":
    unittest.main()

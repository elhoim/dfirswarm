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
import unittest

from support import Case, run_tool


class SqliteQuery(Case):
    def db(self, name="a.db", script="create table a(x); insert into a values(1),(2),(3);"):
        path = self.path(name)
        conn = sqlite3.connect(path)
        conn.executescript(script)
        conn.commit()
        conn.close()
        return path

    def read(self, rel, mode="r"):
        with open(self.path(rel) if not os.path.isabs(rel) else rel, mode) as fh:
            return fh.read()

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


if __name__ == "__main__":
    unittest.main()

"""timeline_super: a failed stage is not a clean run, export does not collect again, and a bad line is not an event.

log2timeline and psort are stand-ins that record how they were called and write
the files the real ones write (a storage file; psort's JSON Lines, one event per
line, with the datetime in microseconds as Plaso's json_line writer has it).
"""
import importlib.util
import json
import os
import time
import unittest

from support import Case, run_tool, stand_in, tool_path

GOOD = [{"datetime": "2023-11-14T22:13:20.000000+00:00", "parser": "filestat", "data_type": "fs:stat", "message": "m1", "timestamp_desc": "Modification Time"},
        {"timestamp": 1700000100000000, "parser": "winreg", "data_type": "windows:registry:key_value", "message": "m2"}]


class TimelineSuper(Case):
    def plaso(self, collect_exit=0, export_exit=0, lines=None, collect_writes=True, export_writes=True):
        d = self.path("bin")
        os.makedirs(d, exist_ok=True)
        self.calls = self.path("calls.log")
        body = lines if lines is not None else [json.dumps(r) for r in GOOD]
        data = self.write("canned.jsonl", "\n".join(body) + "\n")
        l2t = ('echo "log2timeline $*" >> "%s"\n'
               'case "$1" in --version) echo "plaso - log2timeline version 20990101"; exit 0;; esac\n'
               'while [ $# -gt 0 ]; do case "$1" in --storage_file) %s; shift;; --logfile) echo log > "$2"; shift;; esac; shift; done\n'
               'exit %d\n') % (self.calls, 'echo storage > "$2"' if collect_writes else ':', collect_exit)
        ps = ('echo "psort $*" >> "%s"\n'
              'case "$1" in --version) echo "plaso - psort version 20990101"; exit 0;; esac\n'
              'while [ $# -gt 0 ]; do case "$1" in -w) %s; shift;; --logfile) echo log > "$2"; shift;; esac; shift; done\n'
              'exit %d\n') % (self.calls, 'cp "%s" "$2"' % data if export_writes else ':', export_exit)
        stand_in(d, "log2timeline.py", l2t)
        stand_in(d, "psort.py", ps)
        return d

    def calls_made(self):
        return self.read(self.calls).splitlines() if os.path.exists(self.calls) else []

    def go(self, bin_dir, **args):
        args.setdefault("out_dir", "work/tl")
        args.setdefault("source", self.write("inputs/disk.dd", b"\0" * 64))
        return run_tool("timeline_super", args, self.dir, [bin_dir])

    def test_a_clean_run_is_complete_and_names_both_exits_and_versions(self):
        r = self.go(self.plaso())
        self.assertEqual(r.code, 0, r.stdout)
        j = r.json
        self.assertEqual((j["status"], j["collect_exit"], j["export_exit"], j["events"], j["invalid_lines"]), ("complete", 0, 0, 2, 0))
        self.assertEqual(j["versions"]["log2timeline"], "plaso - log2timeline version 20990101")
        self.assertEqual(j["versions"]["psort"], "plaso - psort version 20990101")
        self.assertEqual(j["first_event"], "2023-11-14T22:13:20.000000+00:00")
        self.assertEqual(j["last_event"], "2023-11-14T22:15:00Z")
        self.assertIn("pinfo", j["coverage_note"])

    def test_log2timeline_failing_after_it_wrote_a_storage_file_is_partial_not_normal(self):
        r = self.go(self.plaso(collect_exit=1))
        self.assertEqual(r.code, 1)
        self.assertEqual(r.json["status"], "partial")
        self.assertEqual(r.json["collect_exit"], 1)
        self.assertEqual(r.json["export_exit"], 0)
        self.assertTrue(any("log2timeline exited 1" in p for p in r.json["problems"]), r.json["problems"])
        self.assertEqual(r.json["events"], 2)       # what psort made of the partial storage is still returned

    def test_psort_failing_after_it_wrote_output_is_partial_too(self):
        r = self.go(self.plaso(export_exit=3))
        self.assertEqual((r.code, r.json["status"], r.json["export_exit"]), (1, "partial", 3))

    def test_nothing_written_is_failed_with_an_error(self):
        r = self.go(self.plaso(collect_exit=1, collect_writes=False))
        self.assertEqual((r.code, r.json["status"]), (1, "failed"))
        self.assertIn("error", r.json)
        self.assertEqual([c for c in self.calls_made() if c.startswith("psort") and "--version" not in c], [])

    def test_export_mode_runs_psort_alone_over_an_existing_storage_file(self):
        bin_dir = self.plaso()
        store = self.write("work/old/timeline.plaso", b"storage")
        r = run_tool("timeline_super", {"mode": "export", "storage_file": store, "out_dir": "work/narrow",
                                        "psort_filter": "date > '2026-02-01'"}, self.dir, [bin_dir])
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["status"], "complete")
        self.assertIsNone(r.json["collect_exit"])
        self.assertEqual([c for c in self.calls_made() if c.startswith("log2timeline")], [])
        export = [c for c in self.calls_made() if c.startswith("psort") and "--version" not in c]
        self.assertEqual(len(export), 1)
        self.assertIn("--filter date > '2026-02-01'", export[0])
        self.assertTrue(export[0].endswith(store))
        self.assertNotIn("log2timeline", r.json["versions"])

    def test_export_mode_needs_a_storage_file_that_exists(self):
        bin_dir = self.plaso()
        for args in ({"mode": "export", "out_dir": "work/x"}, {"mode": "export", "out_dir": "work/x", "storage_file": self.path("nope.plaso")}):
            self.assertEqual(run_tool("timeline_super", args, self.dir, [bin_dir]).code, 1)

    def test_malformed_lines_are_not_events(self):
        lines = [json.dumps(GOOD[0]), "this is not json", json.dumps(GOOD[1]), '{"truncated": ']
        r = self.go(self.plaso(lines=lines))
        self.assertEqual((r.json["events"], r.json["invalid_lines"], r.json["status"]), (2, 2, "partial"))
        listing = self.read(r.json["invalid_lines_file"]).splitlines()
        self.assertEqual(len(listing), 3)             # a header and the two lines
        self.assertTrue(listing[1].startswith("2\t"))
        self.assertTrue(listing[2].startswith("4\t"))
        self.assertTrue(r.json["invalid_lines_listing_complete"])

    def test_an_existing_output_directory_is_refused_unless_resume(self):
        bin_dir = self.plaso()
        self.write("work/tl/timeline.jsonl", b'{"datetime": "1999-01-01T00:00:00Z"}\n')
        old = time.time() - 86400
        os.utime(self.path("work/tl/timeline.jsonl"), (old, old))
        r = self.go(bin_dir)
        self.assertEqual(r.code, 1)
        self.assertIn("already holds files", r.json["error"])
        self.assertEqual(self.calls_made(), [])
        # With resume the stale file is not this run's: a psort that writes nothing leaves the run failed.
        failing = self.plaso(export_writes=False)
        r = self.go(failing, resume=True)
        self.assertEqual(r.json["status"], "failed")
        self.assertEqual(r.json["preexisting"], ["timeline.jsonl"])

    def test_a_link_where_the_tool_writes_is_refused(self):
        bin_dir = self.plaso()
        os.makedirs(self.path("work/tl"))
        target = self.write("elsewhere.txt", b"x")
        os.symlink(target, self.path("work/tl/timeline.jsonl"))
        r = self.go(bin_dir, resume=True)
        self.assertEqual(r.code, 1)
        self.assertIn("link", r.json["error"])
        self.assertEqual(self.read(target), "x")

    def test_a_long_message_is_previewed_with_its_length(self):
        big = dict(GOOD[0], message="x" * 5000)
        r = self.go(self.plaso(lines=[json.dumps(big)]))
        row = r.json["sample"][0]
        self.assertEqual(len(row["message"]), 2000)
        self.assertEqual(row["message_length"], 5000)

    def test_one_deadline_covers_every_stage(self):
        spec = importlib.util.spec_from_file_location("ts", tool_path("timeline_super"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        os.makedirs(self.path("o"))
        started = time.monotonic()
        stage = mod.Stage("sleeper", ["sleep", "30"], self.path("o")).run(time.monotonic() + 0.5)
        self.assertTrue(stage.timed_out)
        self.assertLess(time.monotonic() - started, 10)
        spent = mod.Stage("late", ["sleep", "30"], self.path("o")).run(time.monotonic() - 1)
        self.assertTrue(spent.timed_out and spent.exit is None)


if __name__ == "__main__":
    unittest.main()

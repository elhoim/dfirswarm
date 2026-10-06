"""feature_scan: no value inline, a histogram is not a feature file, a failed run is not a clean one.

bulk_extractor is a stand-in that writes what the real one writes: tab-separated
feature files (offset, feature, context), a histogram file whose lines are "n=<count>",
report.xml and, for the net scanner, packets.pcap.
"""
import importlib.util
import json
import os
import stat
import tracemalloc
import unittest

from support import Case, run_tool, stand_in, tool_path

SECRET_ADDRESS = "alice.hidden@example.test"
CARD = "4111111111111111"


def stub_body(exit_code=0, extra=""):
    return ('while [ $# -gt 0 ]; do case "$1" in -o) OUTDIR="$2"; shift;; esac; shift; done\n'
            'mkdir -p "$OUTDIR"\n'
            'printf "# BANNER\\n1024\\t%(a)s\\tctx %(a)s\\n2048\\t%(a)s\\tctx\\n4096\\tbob@example.test\\tctx\\n" > "$OUTDIR/email.txt"\n'
            'printf "n=2\\t%(a)s\\nn=1\\tbob@example.test\\n" > "$OUTDIR/email_histogram.txt"\n'
            'printf "8192\\t%(c)s\\tctx\\n" > "$OUTDIR/ccn.txt"\n'
            'printf "<report/>" > "$OUTDIR/report.xml"\n'
            'printf "pcapbytes" > "$OUTDIR/packets.pcap"\n'
            'echo scanning\n'
            + extra +
            'exit %(code)d\n') % {"a": SECRET_ADDRESS, "c": CARD, "code": exit_code}


class FeatureScan(Case):
    def scan(self, body=None, env=None, **kw):
        bin_dir = self.path("bin")
        os.makedirs(bin_dir, exist_ok=True)
        stand_in(bin_dir, "bulk_extractor", body or stub_body())
        src = self.write("inputs/blob.raw", b"\0" * 64)
        args = {"path": src, "out_dir": "work/features"}
        args.update(kw)
        return run_tool("feature_scan", args, self.dir, [bin_dir], env=env)

    def test_no_value_comes_back_and_the_shape_does(self):
        r = self.scan()
        self.assertEqual(r.code, 0, r.stdout)
        for secret in (SECRET_ADDRESS, CARD, "bob@example.test"):
            self.assertNotIn(secret, r.stdout, "a feature value came back inline")
        by = {f["feature"]: f for f in r.json["features"]}
        self.assertEqual((by["email"]["lines"], by["email"]["distinct"], by["email"]["first_offset"]), (3, 2, "1024"))
        self.assertEqual(by["ccn"]["lines"], 1)
        self.assertEqual(r.json["secret_values"]["contains_secret_values"], False)
        self.assertIs(r.json["values_inline"], False)

    def test_a_histogram_file_is_not_summarised_as_features(self):
        r = self.scan()
        self.assertNotIn("email_histogram", [f["feature"] for f in r.json["features"]])
        self.assertEqual([(h["file"].split("/")[-1], h["lines"]) for h in r.json["histograms"]], [("email_histogram.txt", 2)])
        kinds = {os.path.basename(f["file"]): f["kind"] for f in r.json["files"]}
        self.assertEqual((kinds["email.txt"], kinds["email_histogram.txt"], kinds["report.xml"], kinds["packets.pcap"]), ("features", "histogram", "run report", "pcap"))

    def test_the_whole_output_inventory_names_a_pcap(self):
        names = [os.path.basename(f["file"]) for f in self.scan().json["files"]]
        self.assertIn("packets.pcap", names)

    def test_a_nonzero_exit_is_partial_or_failed_with_its_words_kept(self):
        r = self.scan(stub_body(exit_code=2, extra='echo "scanner crashed" >&2\n'))
        self.assertEqual(r.code, 1)
        self.assertEqual((r.json["status"], r.json["exit_code"]), ("partial", 2))
        self.assertIn("exited 2", r.json["problem"])
        self.assertIn("scanner crashed", self.read(r.json["stderr_file"]))
        self.assertIn("scanning", self.read(r.json["stdout_file"]))
        # Nothing written at all is failed, and says why.
        r = self.scan('echo boom >&2\nexit 3\n', out_dir="work/features-none")
        self.assertEqual(r.code, 1)
        self.assertIn("wrote no output directory", r.json["error"])
        self.assertEqual(r.json["exit_code"], 3)

    def test_values_are_refused_outside_a_job_and_sealed_inside_one(self):
        r = self.scan(write_values=True)
        self.assertEqual(r.code, 1)
        self.assertIn("refused outside a job", r.json["error"])
        self.assertFalse(os.path.exists(self.path("work/features")))
        out = self.path("job-out")
        os.makedirs(out)
        r = self.scan(write_values=True, top=1, env={"JOB_ID": "j000009", "OUT": out}, out_dir=self.path("job-out/features"))
        self.assertEqual(r.code, 0, r.stdout)
        self.assertNotIn(SECRET_ADDRESS, r.stdout)
        self.assertEqual(r.json["secret_values"]["values_file"], "store/jobs/j000009/out/feature-scan-values.jsonl")
        path = os.path.join(out, "feature-scan-values.jsonl")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        rows = [json.loads(x) for x in self.read(path).splitlines()]
        email = [x for x in rows if x["feature_file"].endswith("email.txt")][0]
        self.assertEqual((email["value"], email["count"]), (SECRET_ADDRESS, 2))

    def test_distinct_values_are_counted_within_a_bound(self):
        spec = importlib.util.spec_from_file_location("fs", tool_path("feature_scan"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        path = self.path("many.txt")
        with open(path, "w") as fh:
            for i in range(60000):
                fh.write("%d\tvalue-%d\tctx\n" % (i, i))
        tracemalloc.start()
        stats, counts = mod.summarise(path, cap=1000)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        self.assertEqual((stats["lines"], stats["distinct"], stats["distinct_capped"], stats["occurrences_not_tallied"]), (60000, 1000, True, 59000))
        self.assertLess(peak, 5 * 1024 * 1024)

    def test_scanner_names_are_checked_before_they_reach_the_command_line(self):
        for bad in (["--help"], ["email;rm"], [3]):
            self.assertEqual(self.scan(only=bad).code, 1, bad)


if __name__ == "__main__":
    unittest.main()

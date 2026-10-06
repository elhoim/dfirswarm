"""sig_carve: every header found once, at its true offset, whatever the read block.

The headers are those the formats define (the PNG signature, the Windows event
log's "ElfFile", the SQLite header string); each test places one at, and either
side of, a read-block boundary and asks for it in files read with different block
sizes, so a header cut by a boundary, or counted twice for it, shows as a wrong count.
"""
import unittest

from support import Case, run_tool

PNG = b"\x89PNG\r\n\x1a\n"
EVTX = b"ElfFile\x00"
SQLITE = b"SQLite format 3\x00"


class SigCarve(Case):
    def scan(self, data, window, sig="all", **kw):
        src = self.write("dump.bin", data)
        return run_tool("sig_carve", dict({"path": src, "sig": sig, "window_bytes": window}, **kw), self.dir)

    def test_a_header_at_and_around_a_block_boundary_is_found_once_at_its_offset(self):
        for window in (64, 100, 4096):
            for sig_name, header in (("PNG", PNG), ("EVTX", EVTX), ("SQLite", SQLITE)):
                for delta in range(-len(header) - 1, 3):
                    at = window + delta
                    data = b"\x00" * at + header + b"\x00" * (3 * window)
                    r = self.scan(data, window, sig_name)
                    hits = r.json["signatures"][sig_name]
                    self.assertEqual((hits["count"], [h["offset"] for h in hits["hits"]]), (1, [at]), (window, sig_name, at))

    def test_a_seam_between_two_reads_makes_no_hit_the_file_does_not_hold(self):
        # "MAM" is M A M. Where one read ends and the next begins, the bytes "AM" at the next
        # read's first two offsets are not a MAM: the byte before them is not an M. A scanner that
        # glued a copy of the carried bytes onto the next read would see M (the carry), A, M and
        # report a MAM one byte before the seam. The default window is the real one (the old tool's
        # was 64 MiB, this one's 8 MiB), so both seams get the same two bytes.
        path = self.path("seam.bin")
        with open(path, "wb") as fh:
            fh.truncate(64 * 1024 * 1024 + 4096)
            for seam in (8 * 1024 * 1024, 64 * 1024 * 1024):
                fh.seek(seam)
                fh.write(b"AM")
        r = run_tool("sig_carve", {"path": path, "sig": "MAM"}, self.dir)
        self.assertEqual(r.code, 0, r.stdout)
        found = r.json.get("signatures", r.json)["MAM"]          # the old tool answered with the signatures at the top
        self.assertEqual(found["count"], 0, found["hits"])

    def test_every_signature_is_looked_for_in_one_pass(self):
        data = PNG + b"\x00" * 200 + EVTX + b"\x00" * 200 + SQLITE + b"\x00" * 200
        r = self.scan(data, 64)
        self.assertEqual(r.json["scanned"]["passes"], 1)
        self.assertEqual(r.json["scanned"], dict(r.json["scanned"], start=0, end=len(data), bytes=len(data), complete=True))
        self.assertEqual({k: v["count"] for k, v in r.json["signatures"].items() if v["count"]}, {"PNG": 1, "EVTX": 1, "SQLite": 1})
        self.assertEqual(r.json["source"]["bytes"], len(data))

    def test_overlapping_occurrences_of_one_header_are_each_a_hit(self):
        r = self.scan(b"\x00" * 10 + b"MZMZ" + b"\x00" * 10, 16, "MZ")
        self.assertEqual([h["offset"] for h in r.json["signatures"]["MZ"]["hits"]], [10, 12])

    def test_an_unknown_signature_is_an_error_not_an_empty_result(self):
        r = self.scan(b"\x00" * 64, 64, "NoSuchSig")
        self.assertEqual(r.code, 1)
        self.assertIn("no such signature", r.json["error"])
        self.assertIn("PNG", r.json["signatures"])

    def test_bounds_are_validated(self):
        for bad in ({"context": 10 ** 9}, {"context": -1}, {"max_hits": 0}, {"window_bytes": 1}):
            self.assertEqual(self.scan(b"\x00" * 64, 64, "PNG", **bad).code, 1 if "window_bytes" not in bad else 1, bad)

    def test_the_scca_hit_names_where_the_file_starts(self):
        r = self.scan(b"\x00" * 20 + b"\x17\x00\x00\x00SCCA" + b"\x00" * 40, 64, "SCCA")
        hit = r.json["signatures"]["SCCA"]["hits"][0]
        self.assertEqual((hit["offset"], hit["candidate_start"]), (24, 20))

    def test_more_hits_than_the_page_are_all_in_a_file(self):
        data = b"".join(b"\x00" * 30 + PNG for _ in range(40))
        r = self.scan(data, 64, "PNG", max_hits=5)
        png = r.json["signatures"]["PNG"]
        self.assertEqual((png["count"], png["returned"], png["truncated"]), (40, 5, True))
        rows = self.read(png["all_results"]).splitlines()
        self.assertEqual(len(rows), 40)


if __name__ == "__main__":
    unittest.main()

"""file_type: what was looked at, what was not, and what a header can and cannot say.

Signatures are from the formats' own definitions: Java's class file magic and
version fields, Mach-O's fat header (a count of architectures), the Windows
prefetch header (a version, then SCCA at offset 4).
"""
import json
import os
import struct
import unittest

from support import Case, run_tool


class FileType(Case):
    def look(self, path="d", **kw):
        return run_tool("file_type", dict({"path": path}, **kw), self.dir)

    def test_the_examined_count_is_what_was_opened_and_every_result_is_kept(self):
        for i in range(50):
            self.write("d/f%02d.txt" % i, "text %d\n" % i)
        r = self.look(limit=10)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual((r.json["examined"], r.json["file_count"], r.json["discovered"]), (50, 10, 50))
        self.assertTrue(r.json["truncated"])
        rows = self.read(r.json["all_results"]).splitlines()
        self.assertEqual(len(rows), 50)
        self.assertTrue(all("sha256" in json.loads(x) for x in rows))

    def test_a_java_class_is_not_a_macho_binary_and_a_fat_header_is(self):
        self.write("d/Main.class", b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 52) + b"\0" * 32)
        self.write("d/universal", b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + b"\0" * 32)
        types = {os.path.basename(f["file"]): f for f in self.look().json["files"]}
        self.assertEqual(types["Main.class"]["type"], "Java class file")
        self.assertTrue(types["Main.class"]["extension_matches"])
        self.assertEqual(types["universal"]["type"], "Mach-O universal binary")

    def test_prefetch_is_recognised_where_its_signature_is(self):
        # An uncompressed prefetch file: a format version (0x17 for Windows 7) and then SCCA at offset 4.
        self.write("d/CMD.EXE-0A1B2C3D.pf", struct.pack("<I", 0x17) + b"SCCA" + b"\0" * 64)
        self.write("d/compressed.pf", b"MAM\x04" + b"\0" * 64)
        types = {os.path.basename(f["file"]): f["type"] for f in self.look().json["files"]}
        self.assertEqual(types["CMD.EXE-0A1B2C3D.pf"], "prefetch record")
        self.assertEqual(types["compressed.pf"], "compressed prefetch record")

    def test_an_unknown_type_does_not_match_its_extension(self):
        self.write("d/random.bin", os.urandom(512))
        f = self.look().json["files"][0]
        self.assertIsNone(f["extension_matches"])
        self.assertEqual(f["type"], "unrecognised")

    @unittest.skipIf(os.geteuid() == 0, "root reads every file")
    def test_an_unreadable_file_is_reported_whatever_mismatch_only_says(self):
        self.write("d/ok.txt", "x")
        bad = self.write("d/secret.dat", "x")
        os.chmod(bad, 0)
        try:
            r = self.look(mismatch_only=True)
        finally:
            os.chmod(bad, 0o644)
        self.assertEqual(r.json["error_count"], 1)
        self.assertEqual(r.json["errors"][0]["file"], "d/secret.dat")
        self.assertFalse(r.json["complete"])
        self.assertEqual(r.json["files"], [])

    def test_links_and_pipes_are_named_and_never_opened_or_followed(self):
        os.makedirs(self.path("outside"))
        self.write("outside/secret.txt", "do not read")
        self.write("d/real.txt", "x")
        os.symlink(self.path("outside"), self.path("d/dirlink"))
        os.symlink(self.path("outside/secret.txt"), self.path("d/filelink.txt"))
        os.mkfifo(self.path("d/pipe"))
        r = self.look()                          # opening the pipe would block until the run timed out
        self.assertEqual(r.code, 0, r.stdout)
        names = {os.path.basename(f["file"]): f for f in r.json["files"]}
        self.assertEqual(names["filelink.txt"]["kind"], "symbolic link")
        self.assertEqual(names["dirlink"]["kind"], "symbolic link")
        self.assertEqual(names["pipe"]["kind"], "not a regular file")
        self.assertNotIn("sha256", names["filelink.txt"])
        self.assertNotIn("secret.txt", [os.path.basename(f["file"]) for f in r.json["files"]])
        self.assertEqual((r.json["links_listed"], r.json["not_regular_listed"], r.json["examined"]), (2, 1, 1))

    def test_directories_are_walked_in_sorted_order(self):
        for p in ("d/b/y.txt", "d/a/x.txt", "d/top.txt", "d/a/w.txt"):
            self.write(p, "x")
        order = [f["file"] for f in self.look().json["files"]]
        self.assertEqual(order, ["d/top.txt", "d/a/w.txt", "d/a/x.txt", "d/b/y.txt"])

    def test_a_mismatch_is_found_by_direction(self):
        self.write("d/photo.jpg", b"PK\x03\x04" + b"\0" * 32)
        self.write("d/fine.docx", b"PK\x03\x04" + b"\0" * 32)
        r = self.look(mismatch_only=True)
        self.assertEqual([os.path.basename(f["file"]) for f in r.json["files"]], ["photo.jpg"])
        self.assertEqual(r.json["extension_mismatches"], 1)
        self.assertEqual(r.json["examined"], 2)
        self.assertIn("all_results", r.json)                     # what the filter hid is kept


if __name__ == "__main__":
    unittest.main()

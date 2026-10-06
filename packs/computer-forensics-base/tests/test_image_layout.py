"""image_layout: one sector size for the programs and the arithmetic, VHD, and a failure that is not "no partition table".

mmls and fsstat are stand-ins that print the Sleuth Kit's documented output
format and record their arguments, so the tests hold on any host; a last test
runs the real mmls over a hand-built MBR image when the host has it.
"""
import os
import struct
import unittest

from support import Case, have, run_tool, stand_in

# What mmls prints (TSK's documented layout) for a table in 4096-byte sectors.
MMLS_4K = """GUID Partition Table (EFI)
Offset Sector: 0
Units are in 4096-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000000005   0000000006   Unallocated
002:  Meta      0000000001   0000000001   0000000001   GPT Header
003:  Meta      0000000002   0000000005   0000000004   Partition Table
004:  000       0000000006   0000250000   0000249995   Basic data partition
"""
FSSTAT_NTFS = """FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Serial Number: 0123456789ABCDEF
Sector Size: 4096
Cluster Size: 4096
Total Cluster Range: 0 - 249994
"""


def vhd_footer():
    """A VHD footer as the Microsoft VHD specification lays it out: the cookie
    "conectix" first, then features, version, data offset and so on."""
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    struct.pack_into(">I", footer, 8, 2)            # features: reserved bit set
    struct.pack_into(">I", footer, 12, 0x00010000)  # file format version 1.0
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)   # data offset: none for a fixed disk
    footer[0x24:0x28] = b"win "
    struct.pack_into(">I", footer, 0x3C, 2)         # disk type: fixed
    return bytes(footer)


class ImageLayout(Case):
    def stubs(self, mmls="", fsstat=""):
        d = self.path("bin")
        os.makedirs(d, exist_ok=True)
        log = self.path("calls.log")
        stand_in(d, "mmls", 'echo "mmls $*" >> "%s"\n%s' % (log, mmls or "exit 1\n"))
        stand_in(d, "fsstat", 'echo "fsstat $*" >> "%s"\n%s' % (log, fsstat or "echo 'Cannot determine file system type' >&2; exit 1\n"))
        return d, log

    def calls(self, log):
        return open(log).read().splitlines() if os.path.exists(log) else []

    def image(self, name="disk.img", data=b"\0" * 4096):
        return self.write(name, data)

    def test_a_forced_sector_size_is_passed_to_mmls_and_fsstat(self):
        bin_dir, log = self.stubs("cat <<'EOF'\n%sEOF\n" % MMLS_4K, "cat <<'EOF'\n%sEOF\n" % FSSTAT_NTFS)
        image = self.image()
        r = run_tool("image_layout", {"image": image, "sector_size": 4096}, self.dir, [bin_dir])
        self.assertEqual(r.code, 0, r.stdout)
        calls = self.calls(log)
        self.assertIn("mmls -b 4096 %s" % image, calls)
        self.assertIn("fsstat -b 4096 -o 6 %s" % image, calls)
        part = [p for p in r.json["partitions"] if p.get("allocated")][0]
        self.assertEqual(part["offset_bytes"], 6 * 4096)
        self.assertEqual(part["filesystem"]["readable"], True)
        self.assertIn("-b 4096", r.json["use"][0]["example"])
        self.assertEqual(r.json["sector_size"], 4096)

    def test_the_unit_mmls_printed_is_the_unit_fsstat_gets(self):
        # No sector_size given: mmls says "Units are in 4096-byte sectors", and the offsets it
        # printed are in those sectors, so fsstat must be told the same unit.
        bin_dir, log = self.stubs("cat <<'EOF'\n%sEOF\n" % MMLS_4K, "cat <<'EOF'\n%sEOF\n" % FSSTAT_NTFS)
        image = self.image()
        r = run_tool("image_layout", {"image": image}, self.dir, [bin_dir])
        self.assertIn("fsstat -b 4096 -o 6 %s" % image, self.calls(log))
        self.assertEqual(r.json["sector_size_source"], "the units line of mmls")

    def test_a_sector_size_the_sleuth_kit_cannot_take_is_refused(self):
        bin_dir, log = self.stubs()
        for bad in (1000, 0, 100, True, "4096"):
            r = run_tool("image_layout", {"image": self.image(), "sector_size": bad}, self.dir, [bin_dir])
            self.assertEqual(r.code, 1, bad)
        self.assertEqual(self.calls(log), [])

    def test_both_vhd_forms_are_recognised(self):
        bin_dir, _ = self.stubs()
        dynamic = self.write("dyn.vhd", vhd_footer() + b"\0" * 4096)      # a dynamic disk starts with a copy of the footer
        fixed = self.write("fixed.vhd", b"\0" * 8192 + vhd_footer())      # a fixed disk's footer is its last 512 bytes
        for path, where in ((dynamic, "offset 0"), (fixed, "last 512")):
            r = run_tool("image_layout", {"image": path}, self.dir, [bin_dir])
            self.assertEqual(r.json["container"], "vhd", path)
            self.assertIn(where, r.json["container_basis"])

    def test_other_containers_by_their_signatures(self):
        bin_dir, _ = self.stubs()
        for name, head, want in (("a.E01", b"EVF\x09\x0d\x0a\xff\x00", "ewf"), ("a.qcow2", b"QFI\xfb\x00\x00\x00\x03", "qcow"),
                                 ("a.vhdx", b"vhdxfile", "vhdx"), ("a.vmdk", b"KDMV\x01\x00\x00\x00", "vmdk"),
                                 ("plain.dd", b"\0" * 64, "raw")):
            r = run_tool("image_layout", {"image": self.write(name, head + b"\0" * 1024)}, self.dir, [bin_dir])
            self.assertEqual(r.json["container"], want, name)

    def test_an_mmls_that_failed_is_not_no_partition_table(self):
        image = self.image()
        # It ran and complained of the image: nothing is known about a table.
        bin_dir, _ = self.stubs("echo 'Error stat(ing) image file (raw_open: image \"x\" - Permission denied)' >&2; exit 1\n")
        r = run_tool("image_layout", {"image": image}, self.dir, [bin_dir])
        self.assertEqual(r.json["partition_table"], "unknown")
        self.assertIn("Permission denied", r.json["mmls_error"])
        # It is not on PATH at all.
        empty = self.path("empty")
        os.makedirs(empty)
        r = run_tool("image_layout", {"image": image}, self.dir, only_path=empty)
        self.assertEqual(r.json["partition_table"], "unknown")
        self.assertIn("not on PATH", r.json["mmls_error"])
        # It timed out is the same class; a failure to find a table (exit 1, nothing said) is the other answer.
        bin_dir, _ = self.stubs("exit 1\n")
        r = run_tool("image_layout", {"image": image}, self.dir, [bin_dir])
        self.assertIs(r.json["partition_table"], False)
        self.assertIn("recognises", r.json["partition_table_basis"])
        self.assertTrue(any("filesystem/encrypted" in n for n in r.json["notes"]))

    def test_a_split_raw_first_segment_is_said_to_be_one_segment(self):
        bin_dir, _ = self.stubs()
        first = self.write("disk.001", b"\0" * 1024)
        self.write("disk.002", b"\0" * 1024)
        r = run_tool("image_layout", {"image": first}, self.dir, [bin_dir])
        self.assertTrue(any("one path" in n and "disk.002" in n for n in r.json["notes"]), r.json["notes"])

    def test_the_programs_output_is_kept_whole(self):
        bin_dir, _ = self.stubs("cat <<'EOF'\n%sEOF\n" % MMLS_4K, "cat <<'EOF'\n%sEOF\n" % FSSTAT_NTFS)
        r = run_tool("image_layout", {"image": self.image()}, self.dir, [bin_dir])
        kept = self.path(r.json["raw_outputs"]["mmls"])
        self.assertIn("Basic data partition", open(kept).read())

    @unittest.skipUnless(have("mmls"), "mmls is not on this host")
    def test_the_real_mmls_agrees_on_a_hand_built_mbr(self):
        # An MBR as the DOS partition table specification lays it out: four 16-byte entries at 446,
        # type at +4, first LBA at +8 and sector count at +12, and 0x55AA at 510.
        img = bytearray(4 * 1024 * 1024)
        entry = bytearray(16)
        entry[4] = 0x0B
        struct.pack_into("<II", entry, 8, 2048, 4096)
        img[446:462] = entry
        img[510:512] = b"\x55\xaa"
        path = self.write("mbr.img", bytes(img))
        r = run_tool("image_layout", {"image": path}, self.dir)
        self.assertIs(r.json["partition_table"], True)
        self.assertEqual([p["offset_sectors"] for p in r.json["partitions"] if p["allocated"]], [2048])
        zeros = self.write("zero.img", b"\0" * (1 << 20))
        r = run_tool("image_layout", {"image": zeros}, self.dir)
        self.assertIs(r.json["partition_table"], False)


if __name__ == "__main__":
    unittest.main()

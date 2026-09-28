"""A FAT16 volume behind an MBR, written byte by byte.

No mkfs, no mount, no root: the case generator runs the same on macOS and
Linux and gives the same bytes for the same seed. The builder is a small
model of what a driver leaves behind, which is what an examiner reads:

- a deleted file keeps its directory entries with 0xE5 over the first byte
  of each, and its clusters keep their bytes once the FAT frees them;
- a file rewritten shorter in place keeps the old bytes after its new end,
  in the last cluster's slack;
- a directory slot that a later file takes overwrites what was there, so
  the data of a file whose entry was reused is left in unallocated clusters
  with nothing pointing at it.

Placement is explicit (`alloc_at`, `alloc_next`): the case says where each
file goes, so what survives is a decision, not an accident of an allocator.
"""

from __future__ import annotations

import datetime as dt
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

SECTOR = 512
EOC = 0xFFFF

BOOT_MESSAGE = (
    b"This is not a bootable disk.  Please insert a bootable floppy and\r\n"
    b"press any key to try again ... \r\n"
)


def fat_date(t: dt.datetime) -> int:
    return ((t.year - 1980) << 9) | (t.month << 5) | t.day


def fat_time(t: dt.datetime) -> int:
    return (t.hour << 11) | (t.minute << 5) | (t.second // 2)


def fat_tenths(t: dt.datetime) -> int:
    """The creation time's 10 ms units: the odd second and the fraction."""
    return (t.second % 2) * 100 + t.microsecond // 10000


def lfn_checksum(short: bytes) -> int:
    s = 0
    for b in short:
        s = (((s & 1) << 7) | (s >> 1)) + b
        s &= 0xFF
    return s


def lfn_slots(name: str) -> int:
    """How many directory slots a long name takes: its LFN entries and the 8.3 one."""
    return (len(name.encode("utf-16-le")) // 2 + 12) // 13 + 1


_SFN_OK = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()-@^_`{}~")


def short_name(long_name: str, taken: List[bytes]) -> bytes:
    """The 8.3 alias a driver makes for a long name: NAME~N.EXT, upper case."""
    base, _, ext = long_name.rpartition(".") if "." in long_name.lstrip(".") else (long_name, "", "")
    if not base:
        base, ext = ext, ""

    def clean(s: str) -> bytes:
        out = bytearray()
        for ch in s.upper().encode("ascii", "replace"):
            if ch in _SFN_OK:
                out.append(ch)
            elif ch in b" .":
                continue
            else:
                out.append(ord("_"))
        return bytes(out)

    b, e = clean(base), clean(ext)[:3]
    fits = len(b) <= 8 and long_name.upper() == long_name and len(clean(ext)) <= 3 and b == base.upper().encode()
    if fits:
        cand = b.ljust(8, b" ") + e.ljust(3, b" ")
        if cand not in taken:
            return cand
    for n in range(1, 100):
        tail = f"~{n}".encode()
        cand = (b[: 8 - len(tail)] + tail).ljust(8, b" ") + e.ljust(3, b" ")
        if cand not in taken:
            return cand
    raise ValueError(f"no short name left for {long_name}")


@dataclass
class Entry:
    """A file or directory as written: its slots, its clusters, its bytes."""

    name: str
    short: bytes
    slots: List[int]  # absolute byte offsets of the LFN slots then the SFN slot
    clusters: List[int]
    size: int
    is_dir: bool = False
    deleted: bool = False
    children_slots: List[int] = field(default_factory=list)  # for a directory: its slot offsets


class Fat16:
    def __init__(self, *, volume_sectors: int, sectors_per_cluster: int, part_start: int, vsn: int,
                 label: Optional[str], oem: bytes = b"mkfs.fat", disk_signature: int = 0,
                 heads: int = 64, sectors_per_track: int = 32) -> None:
        self.part_start = part_start
        self.volume_sectors = volume_sectors
        self.spc = sectors_per_cluster
        self.cluster_size = sectors_per_cluster * SECTOR
        self.disk = bytearray((part_start + volume_sectors) * SECTOR)
        self.vol = part_start * SECTOR
        self.reserved = 1
        self.nfats = 2
        self.root_entries = 512
        root_sectors = self.root_entries * 32 // SECTOR
        fat_sectors = 1
        while True:
            clusters = (volume_sectors - self.reserved - self.nfats * fat_sectors - root_sectors) // self.spc
            need = ((clusters + 2) * 2 + SECTOR - 1) // SECTOR
            if need <= fat_sectors:
                break
            fat_sectors = need
        self.fat_sectors = fat_sectors
        self.clusters = clusters
        if not 4085 <= clusters < 65525:
            raise ValueError(f"{clusters} clusters is not a FAT16 volume")
        self.fat_off = self.vol + self.reserved * SECTOR
        self.root_off = self.fat_off + self.nfats * fat_sectors * SECTOR
        self.data_off = self.root_off + root_sectors * SECTOR
        self.fat = [0] * (clusters + 2)
        self.fat[0] = 0xFFF8
        self.fat[1] = 0xFFFF
        self.root_slots = [self.root_off + 32 * i for i in range(self.root_entries)]
        self.vsn = vsn
        self.label = label
        self._write_mbr(disk_signature, heads, sectors_per_track)
        self._write_boot(oem, heads, sectors_per_track)
        if label:
            self._label_entry(label)

    # --- the fixed structures -------------------------------------------------------------------

    def _write_mbr(self, signature: int, heads: int, spt: int) -> None:
        mbr = bytearray(SECTOR)
        struct.pack_into("<I", mbr, 440, signature)

        def chs(lba: int) -> bytes:
            c, rem = divmod(lba, heads * spt)
            h, s = divmod(rem, spt)
            s += 1
            if c > 1023:
                return b"\xfe\xff\xff"
            return bytes([h, ((c >> 2) & 0xC0) | s, c & 0xFF])

        entry = bytearray(16)
        entry[0] = 0x00
        entry[1:4] = chs(self.part_start)
        entry[4] = 0x06  # FAT16
        entry[5:8] = chs(self.part_start + self.volume_sectors - 1)
        struct.pack_into("<II", entry, 8, self.part_start, self.volume_sectors)
        mbr[446:462] = entry
        mbr[510:512] = b"\x55\xaa"
        self.disk[0:SECTOR] = mbr

    def _write_boot(self, oem: bytes, heads: int, spt: int) -> None:
        bs = bytearray(SECTOR)
        bs[0:3] = b"\xeb\x3c\x90"
        bs[3:11] = oem.ljust(8, b" ")[:8]
        struct.pack_into("<HBHBHHBHHHII", bs, 11, SECTOR, self.spc, self.reserved, self.nfats, self.root_entries,
                         self.volume_sectors if self.volume_sectors < 65536 else 0, 0xF8, self.fat_sectors, spt, heads,
                         self.part_start, 0 if self.volume_sectors < 65536 else self.volume_sectors)
        bs[36] = 0x80
        bs[38] = 0x29
        struct.pack_into("<I", bs, 39, self.vsn)
        bs[43:54] = (self.label or "NO NAME").upper().encode("ascii").ljust(11, b" ")[:11]
        bs[54:62] = b"FAT16   "
        # mkfs.fat's boot stub: print the message and wait.
        bs[62:62 + 29] = bytes.fromhex("0e1fbe5b7cac22c0740b56b40ebb0700cd105eebf032e4cd16cd19ebfe")
        bs[91:91 + len(BOOT_MESSAGE)] = BOOT_MESSAGE
        bs[510:512] = b"\x55\xaa"
        self.disk[self.vol:self.vol + SECTOR] = bs

    def _label_entry(self, label: str) -> None:
        off = self._free_slots(self.root_slots, 1)[0]
        e = bytearray(32)
        e[0:11] = label.upper().encode("ascii").ljust(11, b" ")[:11]
        e[11] = 0x08
        self.disk[off:off + 32] = e

    # --- clusters -------------------------------------------------------------------------------

    def cluster_off(self, c: int) -> int:
        return self.data_off + (c - 2) * self.cluster_size

    def is_free(self, c: int) -> bool:
        return self.fat[c] == 0

    def alloc_at(self, start: int, count: int) -> List[int]:
        run = list(range(start, start + count))
        for c in run:
            if not (2 <= c < self.clusters + 2) or not self.is_free(c):
                raise ValueError(f"cluster {c} is not free")
        self._link(run)
        return run

    def alloc_next(self, count: int, hint: int = 2) -> List[int]:
        """The first run of `count` free clusters at or after `hint`."""
        c = hint
        while c + count <= self.clusters + 2:
            if all(self.is_free(x) for x in range(c, c + count)):
                return self.alloc_at(c, count)
            c += 1
        raise ValueError("the volume is full")

    def _link(self, run: List[int]) -> None:
        for a, b in zip(run, run[1:]):
            self.fat[a] = b
        self.fat[run[-1]] = EOC

    def free(self, clusters: List[int]) -> None:
        for c in clusters:
            self.fat[c] = 0

    def put_bytes(self, clusters: List[int], data: bytes, at: int = 0) -> None:
        """Write `data` across `clusters` from byte `at`, leaving every other byte as it was."""
        pos = 0
        skip = at
        for c in clusters:
            if pos >= len(data):
                break
            if skip >= self.cluster_size:
                skip -= self.cluster_size
                continue
            off = self.cluster_off(c) + skip
            room = self.cluster_size - skip
            chunk = data[pos:pos + room]
            self.disk[off:off + len(chunk)] = chunk
            pos += len(chunk)
            skip = 0
        if pos < len(data):
            raise ValueError("the data is longer than its clusters")

    def read_clusters(self, clusters: List[int]) -> bytes:
        return b"".join(bytes(self.disk[self.cluster_off(c):self.cluster_off(c) + self.cluster_size]) for c in clusters)

    def clusters_for(self, size: int) -> int:
        return max(1, (size + self.cluster_size - 1) // self.cluster_size)

    # --- directories ----------------------------------------------------------------------------

    def _free_slots(self, slots: List[int], count: int) -> List[int]:
        run: List[int] = []
        for off in slots:
            first = self.disk[off]
            if first in (0x00, 0xE5):
                run.append(off)
                if len(run) == count:
                    return run
            else:
                run = []
        raise ValueError("the directory has no room")

    def _dir_slots(self, parent: Optional[Entry]) -> List[int]:
        if parent is None:
            return self.root_slots
        return parent.children_slots

    def _taken_shorts(self, slots: List[int]) -> List[bytes]:
        return [bytes(self.disk[o:o + 11]) for o in slots if self.disk[o] not in (0x00, 0xE5) and self.disk[o + 11] != 0x0F]

    def _entries(self, name: str, short: bytes, attr: int, start: int, size: int, created: dt.datetime,
                 modified: dt.datetime, accessed: dt.date) -> List[bytes]:
        sfn = bytearray(32)
        sfn[0:11] = short
        sfn[11] = attr
        sfn[12] = 0
        sfn[13] = fat_tenths(created)
        struct.pack_into("<HHHHHHHI", sfn, 14, fat_time(created), fat_date(created),
                         fat_date(dt.datetime(accessed.year, accessed.month, accessed.day)), 0,
                         fat_time(modified), fat_date(modified), start, size)
        display = short[:8].rstrip(b" ") + ((b"." + short[8:].rstrip(b" ")) if short[8:].strip() else b"")
        if display.decode("ascii") == name:
            return [bytes(sfn)]
        units = name.encode("utf-16-le")
        chars = [units[i:i + 2] for i in range(0, len(units), 2)]
        n = (len(chars) + 12) // 13
        padded = chars + ([b"\x00\x00"] if len(chars) % 13 else [])
        padded += [b"\xff\xff"] * (n * 13 - len(padded))
        csum = lfn_checksum(short)
        lfns = []
        for k in range(n, 0, -1):
            part = padded[(k - 1) * 13:k * 13]
            e = bytearray(32)
            e[0] = k | (0x40 if k == n else 0)
            e[1:11] = b"".join(part[0:5])
            e[11] = 0x0F
            e[12] = 0
            e[13] = csum
            e[14:26] = b"".join(part[5:11])
            e[26:28] = b"\x00\x00"
            e[28:32] = b"".join(part[11:13])
            lfns.append(bytes(e))
        return lfns + [bytes(sfn)]

    def _place(self, parent: Optional[Entry], raw: List[bytes], slots: Optional[List[int]]) -> List[int]:
        dir_slots = self._dir_slots(parent)
        where = slots if slots is not None else self._free_slots(dir_slots, len(raw))
        if len(where) != len(raw):
            raise ValueError("the slots given do not fit the entry")
        for off, e in zip(where, raw):
            self.disk[off:off + 32] = e
        return where

    def add_file(self, parent: Optional[Entry], name: str, data: bytes, clusters: List[int], *,
                 created: dt.datetime, modified: dt.datetime, accessed: dt.date,
                 slots: Optional[List[int]] = None, attr: int = 0x20) -> Entry:
        if len(data) > len(clusters) * self.cluster_size:
            raise ValueError(f"{name} does not fit its clusters")
        short = short_name(name, self._taken_shorts(self._dir_slots(parent)))
        raw = self._entries(name, short, attr, clusters[0] if data else 0, len(data), created, modified, accessed)
        where = self._place(parent, raw, slots)
        if data:
            self.put_bytes(clusters, data)
        return Entry(name=name, short=short, slots=where, clusters=clusters if data else [], size=len(data))

    def add_dir(self, parent: Optional[Entry], name: str, *, created: dt.datetime, clusters: int = 1,
                hint: int = 2) -> Entry:
        run = self.alloc_next(clusters, hint)
        for c in run:
            off = self.cluster_off(c)
            self.disk[off:off + self.cluster_size] = bytes(self.cluster_size)
        short = short_name(name, self._taken_shorts(self._dir_slots(parent)))
        raw = self._entries(name, short, 0x10, run[0], 0, created, created, created.date())
        where = self._place(parent, raw, None)
        slots = [self.cluster_off(c) + 32 * i for c in run for i in range(self.cluster_size // 32)]
        dot = bytearray(raw[-1])
        dot[0:11] = b".          "
        dotdot = bytearray(raw[-1])
        dotdot[0:11] = b"..         "
        struct.pack_into("<H", dotdot, 26, parent.clusters[0] if parent else 0)
        self.disk[slots[0]:slots[0] + 32] = dot
        self.disk[slots[1]:slots[1] + 32] = dotdot
        return Entry(name=name, short=short, slots=where, clusters=run, size=0, is_dir=True, children_slots=slots)

    def rewrite(self, entry: Entry, data: bytes, *, modified: dt.datetime, accessed: dt.date) -> None:
        """Save new contents over a file in place, as an editor that truncates
        and writes does: the first clusters are kept, the rest freed, and
        whatever the old contents left after the new end stays in the slack."""
        need = self.clusters_for(len(data))
        if need > len(entry.clusters):
            raise ValueError("rewrite() only shrinks or keeps a file")
        keep, drop = entry.clusters[:need], entry.clusters[need:]
        if drop:
            self.free(drop)
        self._link(keep)
        self.put_bytes(keep, data)
        sfn = entry.slots[-1]
        struct.pack_into("<HH", self.disk, sfn + 22, fat_time(modified), fat_date(modified))
        struct.pack_into("<H", self.disk, sfn + 18, fat_date(dt.datetime(accessed.year, accessed.month, accessed.day)))
        struct.pack_into("<I", self.disk, sfn + 28, len(data))
        entry.clusters = keep
        entry.size = len(data)

    def delete(self, entry: Entry) -> None:
        """What a delete leaves: 0xE5 over each slot's first byte, the chain freed, the bytes kept."""
        for off in entry.slots:
            self.disk[off] = 0xE5
        self.free(entry.clusters)
        entry.deleted = True

    def image(self) -> bytes:
        fat_bytes = bytearray(self.fat_sectors * SECTOR)
        for i, v in enumerate(self.fat):
            struct.pack_into("<H", fat_bytes, 2 * i, v)
        for k in range(self.nfats):
            off = self.fat_off + k * self.fat_sectors * SECTOR
            self.disk[off:off + len(fat_bytes)] = fat_bytes
        return bytes(self.disk)


# --- an independent reader, for the generator's own checks ------------------------------------


@dataclass
class Found:
    path: str
    size: int
    start: int
    deleted: bool
    is_dir: bool
    data: bytes  # the allocated bytes of a live file (size bytes); empty otherwise


def read_volume(image: bytes, part_start: int) -> Tuple[List[Found], List[int], int, int]:
    """Walk a FAT16 volume as a reader would, from the boot sector alone:
    every live and deleted entry, the free clusters, the data area's offset
    and the cluster size. Used to prove where a planted fact lies."""
    vol = part_start * SECTOR
    bps, spc, reserved, nfats, root_entries, total16, _media, fat_sectors = struct.unpack_from("<HBHBHHBH", image, vol + 11)
    total = total16 or struct.unpack_from("<I", image, vol + 32)[0]
    fat_off = vol + reserved * bps
    root_off = fat_off + nfats * fat_sectors * bps
    data_off = root_off + root_entries * 32
    csize = spc * bps
    nclusters = (total - reserved - nfats * fat_sectors - root_entries * 32 // bps) // spc
    fat = [struct.unpack_from("<H", image, fat_off + 2 * i)[0] for i in range(nclusters + 2)]

    def chain(start: int) -> List[int]:
        out = []
        c = start
        while 2 <= c < 0xFFF8 and c not in out:
            out.append(c)
            c = fat[c]
        return out

    def coff(c: int) -> int:
        return data_off + (c - 2) * csize

    found: List[Found] = []

    def walk(slots: List[int], prefix: str) -> None:
        # In disk order: the last part of the name first. A deleted entry's
        # ordinals are under its 0xE5, so the order is all a reader has.
        lfn_parts: List[str] = []
        for off in slots:
            first = image[off]
            if first == 0x00:
                break
            attr = image[off + 11]
            if attr == 0x0F:
                raw = image[off + 1:off + 11] + image[off + 14:off + 26] + image[off + 28:off + 32]
                text = raw.decode("utf-16-le", "replace").split("\x00")[0].replace("\uffff", "")
                lfn_parts.append(text)
                continue
            if attr & 0x08:
                lfn_parts = []
                continue
            short = image[off:off + 11]
            deleted = first == 0xE5
            base = short[:8].rstrip(b" ").decode("ascii", "replace")
            ext = short[8:].rstrip(b" ").decode("ascii", "replace")
            if deleted:
                base = "_" + base[1:]
            name = "".join(reversed(lfn_parts)) if lfn_parts else (base + ("." + ext if ext else ""))
            lfn_parts = []
            if name in (".", ".."):
                continue
            start, size = struct.unpack_from("<HI", image, off + 26)
            is_dir = bool(attr & 0x10)
            data = b""
            if not deleted and not is_dir and size:
                data = b"".join(image[coff(c):coff(c) + csize] for c in chain(start))[:size]
            found.append(Found(path=prefix + name, size=size, start=start, deleted=deleted, is_dir=is_dir, data=data))
            if is_dir and not deleted and start:
                sub = [coff(c) + 32 * i for c in chain(start) for i in range(csize // 32)]
                walk(sub, prefix + name + "/")

    walk([root_off + 32 * i for i in range(root_entries)], "")
    free = [c for c in range(2, nclusters + 2) if fat[c] == 0]
    return found, free, data_off, csize

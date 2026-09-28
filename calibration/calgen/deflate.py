"""Deflate (RFC 1951) and gzip (RFC 1952) written out, for bytes that do not
depend on the host's zlib.

zlib's output for the same input and level is not the same everywhere
(zlib-ng, which some distributions ship in its place, compresses
differently), and a case must be byte-for-byte the same for the same seed on
any host. So compression here is one fixed-Huffman block with a greedy
LZ77 match over a 32 KiB window: every standard reader decompresses it, and
it is a pure function of its input. zlib is used only for the CRC-32, which
is the same everywhere, and by the generator's own checks to prove a stream
decompresses to what was written.
"""

from __future__ import annotations

import struct
import zlib
from typing import Dict, List, Optional

_LEN_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]
_LEN_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
_DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073,
              4097, 6145, 8193, 12289, 16385, 24577]
_DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]

_WINDOW = 32768
_MAX_MATCH = 258
_CANDIDATES = 16


class _Bits:
    def __init__(self) -> None:
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def put(self, value: int, nbits: int) -> None:
        self.acc |= value << self.n
        self.n += nbits
        while self.n >= 8:
            self.out.append(self.acc & 0xFF)
            self.acc >>= 8
            self.n -= 8

    def put_code(self, code: int, length: int) -> None:
        # Huffman codes go most significant bit first.
        rev = 0
        for i in range(length):
            rev = (rev << 1) | ((code >> i) & 1)
        self.put(rev, length)

    def flush(self) -> bytes:
        if self.n:
            self.out.append(self.acc & 0xFF)
            self.acc = 0
            self.n = 0
        return bytes(self.out)


def _literal(bits: _Bits, sym: int) -> None:
    if sym < 144:
        bits.put_code(0x30 + sym, 8)
    elif sym < 256:
        bits.put_code(0x190 + sym - 144, 9)
    elif sym < 280:
        bits.put_code(sym - 256, 7)
    else:
        bits.put_code(0xC0 + sym - 280, 8)


def _length(bits: _Bits, length: int) -> None:
    i = 28
    while _LEN_BASE[i] > length:
        i -= 1
    _literal(bits, 257 + i)
    if _LEN_EXTRA[i]:
        bits.put(length - _LEN_BASE[i], _LEN_EXTRA[i])


def _distance(bits: _Bits, dist: int) -> None:
    i = 29
    while _DIST_BASE[i] > dist:
        i -= 1
    bits.put_code(i, 5)
    if _DIST_EXTRA[i]:
        bits.put(dist - _DIST_BASE[i], _DIST_EXTRA[i])


def _match_len(data: bytes, a: int, b: int, limit: int) -> int:
    n = 0
    while n + 16 <= limit and data[a + n:a + n + 16] == data[b + n:b + n + 16]:
        n += 16
    while n < limit and data[a + n] == data[b + n]:
        n += 1
    return n


def deflate_raw(data: bytes) -> bytes:
    """One final fixed-Huffman block holding all of `data`."""
    bits = _Bits()
    bits.put(1, 1)  # BFINAL
    bits.put(1, 2)  # BTYPE = 01, fixed Huffman
    n = len(data)
    chains: Dict[bytes, List[int]] = {}

    def remember(pos: int) -> None:
        if pos + 3 <= n:
            key = data[pos:pos + 3]
            lst = chains.get(key)
            if lst is None:
                chains[key] = [pos]
            else:
                lst.append(pos)
                if len(lst) > 4 * _CANDIDATES:
                    del lst[: len(lst) - _CANDIDATES]

    i = 0
    while i < n:
        best_len = 0
        best_dist = 0
        if i + 3 <= n:
            cands = chains.get(data[i:i + 3])
            if cands:
                limit = min(_MAX_MATCH, n - i)
                for p in reversed(cands[-_CANDIDATES:]):
                    d = i - p
                    if d > _WINDOW:
                        break
                    ln = _match_len(data, p, i, limit)
                    if ln > best_len:
                        best_len, best_dist = ln, d
                        if ln == limit:
                            break
        if best_len >= 3:
            _length(bits, best_len)
            _distance(bits, best_dist)
            for k in range(i, i + best_len):
                remember(k)
            i += best_len
        else:
            _literal(bits, data[i])
            remember(i)
            i += 1
    _literal(bits, 256)
    return bits.flush()


def gzip_bytes(data: bytes, name: Optional[str] = None, mtime: int = 0) -> bytes:
    """A gzip member as `gzip` writes one: the original name and time in the
    header when given, OS = Unix."""
    flags = 0x08 if name else 0x00
    header = b"\x1f\x8b\x08" + bytes([flags]) + struct.pack("<I", mtime & 0xFFFFFFFF) + b"\x00\x03"
    if name:
        header += name.encode("latin-1") + b"\x00"
    trailer = struct.pack("<II", zlib.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF)
    return header + deflate_raw(data) + trailer

"""A seeded random source that gives the same numbers on every Python.

`random.Random` has kept its core generator stable, but the helpers on top
of it (`sample`, `choices`, `randbytes`) have changed between versions. The
cases must be byte-for-byte the same for the same seed wherever they are
generated, so every draw here comes from SHA-256 over the seed, a label and
a counter, and every helper is written out.
"""

from __future__ import annotations

import hashlib
from typing import List, Sequence, TypeVar

T = TypeVar("T")


class Rng:
    def __init__(self, seed: str, label: str) -> None:
        self._key = hashlib.sha256(f"dfirswarm-calibration\0{seed}\0{label}".encode("utf-8")).digest()
        self._counter = 0
        self._buf = b""

    def bytes(self, n: int) -> bytes:
        while len(self._buf) < n:
            self._buf += hashlib.sha256(self._key + self._counter.to_bytes(8, "big")).digest()
            self._counter += 1
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def u64(self) -> int:
        return int.from_bytes(self.bytes(8), "big")

    def below(self, n: int) -> int:
        """A whole number in [0, n), without modulo bias."""
        if n <= 0:
            raise ValueError("below() needs n > 0")
        limit = (1 << 64) - ((1 << 64) % n)
        while True:
            x = self.u64()
            if x < limit:
                return x % n

    def between(self, lo: int, hi: int) -> int:
        """A whole number in [lo, hi], both ends included."""
        return lo + self.below(hi - lo + 1)

    def choice(self, seq: Sequence[T]) -> T:
        return seq[self.below(len(seq))]

    def sample(self, seq: Sequence[T], k: int) -> List[T]:
        pool = list(seq)
        if k > len(pool):
            raise ValueError("sample larger than the pool")
        return [pool.pop(self.below(len(pool))) for _ in range(k)]

    def shuffled(self, seq: Sequence[T]) -> List[T]:
        out = list(seq)
        for i in range(len(out) - 1, 0, -1):
            j = self.below(i + 1)
            out[i], out[j] = out[j], out[i]
        return out

    def hex(self, n: int) -> str:
        return self.bytes((n + 1) // 2).hex()[:n]

    def chance(self, num: int, den: int) -> bool:
        return self.below(den) < num

    def digits(self, n: int) -> str:
        return "".join(str(self.below(10)) for _ in range(n))

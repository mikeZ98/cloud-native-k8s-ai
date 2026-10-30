"""A deterministic, portable pseudo-random stream for reproducible evaluations.

BLAKE2b in counter mode, keyed by the caller (seed, sample index, ...): the stream is
defined by this module alone, so a given seed perturbs manifests identically on every
Python version and platform. Not for cryptography: nothing here is secret.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence


class Prng:
    def __init__(self, *key: object) -> None:
        self._key = "/".join(map(str, key)).encode()
        self._counter = 0

    def _next(self) -> int:
        block = self._key + self._counter.to_bytes(8, "big")
        self._counter += 1
        return int.from_bytes(hashlib.blake2b(block, digest_size=8).digest(), "big")

    def random(self) -> float:
        """Uniform in ``[0, 1)``."""
        return self._next() / 2**64

    def randint(self, low: int, high: int) -> int:
        """Uniform in ``[low, high]`` (inclusive)."""
        if high < low:
            raise ValueError(f"empty range [{low}, {high}]")
        return low + self._next() % (high - low + 1)

    def choice[T](self, items: Sequence[T]) -> T:
        if not items:
            raise ValueError("cannot choose from an empty sequence")
        return items[self.randint(0, len(items) - 1)]

    def shuffled[T](self, items: Sequence[T]) -> list[T]:
        """A Fisher-Yates permutation of ``items`` (the input is not modified)."""
        result = list(items)
        for i in range(len(result) - 1, 0, -1):
            j = self.randint(0, i)
            result[i], result[j] = result[j], result[i]
        return result

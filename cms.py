"""Count-Min Sketch with optional conservative update and seeded universal hashing."""
import math
import random
from array import array


class CountMinSketch:
    P = (1 << 61) - 1          # Mersenne prime for universal hashing

    def __init__(self, width, depth, conservative=True, seed=None):
        rnd = random.Random(seed)
        self.w, self.d, self.conservative = width, depth, conservative
        # h_r(x) = ((a*x + b) mod P) mod w, with a, b random per row.
        # Random a, b chosen at startup keep an attacker from crafting collisions.
        self._ab = [(rnd.randrange(1, self.P), rnd.randrange(self.P)) for _ in range(depth)]
        self.rows = [array("i", [0]) * width for _ in range(depth)]
        self.total = 0

    @classmethod
    def from_error(cls, epsilon, delta, **kw):
        """Size the table from the guarantee: w = ceil(e/eps), d = ceil(ln(1/delta))."""
        return cls(math.ceil(math.e / epsilon), math.ceil(math.log(1 / delta)), **kw)

    @property
    def epsilon(self):
        return math.e / self.w

    @property
    def memory_bytes(self):
        return self.w * self.d * self.rows[0].itemsize

    def error_bound(self):
        """Estimate may exceed the true count by at most this much (w.h.p.)."""
        return self.epsilon * self.total

    def _cols(self, x):
        P, w = self.P, self.w
        return [((a * x + b) % P) % w for a, b in self._ab]

    def add(self, x, count=1):
        """Count one event for key x. Returns the new estimate for x."""
        cols, rows = self._cols(x), self.rows
        self.total += count
        if self.conservative:
            # Raise only counters that sit below (current min + count).
            target = min(rows[r][c] for r, c in enumerate(cols)) + count
            for r, c in enumerate(cols):
                if rows[r][c] < target:
                    rows[r][c] = target
            return target
        est = None
        for r, c in enumerate(cols):
            rows[r][c] += count
            if est is None or rows[r][c] < est:
                est = rows[r][c]
        return est

    def query(self, x):
        rows = self.rows
        return min(rows[r][c] for r, c in enumerate(self._cols(x)))

    def merge(self, other):
        """Cell-wise sum. Needs identical shape and hash seeds (same seed=)."""
        assert (self.w, self.d, self._ab) == (other.w, other.d, other._ab)
        for r in range(self.d):
            for c in range(self.w):
                self.rows[r][c] += other.rows[r][c]
        self.total += other.total

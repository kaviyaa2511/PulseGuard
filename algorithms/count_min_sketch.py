"""Count-Min Sketch: approximate frequency counting in fixed memory.  (Owner: Y)

Structure : depth x width matrix of integer counters (array-based).
Update    : hash the item once per row, increment one counter per row  -> O(d)
Estimate  : minimum of the d counters the item maps to                 -> O(d)
Space     : O(w * d), independent of the number of distinct items.

The estimate is never below the true count (counters only grow, and collisions
only add to them) but may be above it.
"""
import hashlib


def _check_positive_int(name, value):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer, got {value!r}")


class CountMinSketch:
    def __init__(self, width, depth, seed=42):
        _check_positive_int("width", width)
        _check_positive_int("depth", depth)
        self.width = width
        self.depth = depth
        self.seed = seed
        self.table = [[0] * width for _ in range(depth)]
        self.total = 0  # number of updates seen (sum of counts)

    def _index(self, row, item):
        # md5 is used (not built-in hash()) because hash() of a string is
        # randomised per run, which would make results irreproducible.
        key = f"{self.seed}-{row}-{item}".encode("utf-8")
        digest = hashlib.md5(key).digest()
        return int.from_bytes(digest[:8], "big") % self.width

    def update(self, item, count=1):
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("count must be a non-negative integer")
        item = str(item)
        for row in range(self.depth):
            self.table[row][self._index(row, item)] += count
        self.total += count

    def estimate(self, item):
        item = str(item)
        return min(self.table[row][self._index(row, item)]
                   for row in range(self.depth))

    def num_counters(self):
        return self.width * self.depth

"""Baseline: exact counting. Perfect answers, memory grows with distinct keys."""
import sys
from collections import Counter


class ExactCounter:
    def __init__(self):
        self.c = Counter()
        self.total = 0

    def add(self, x, count=1):
        self.c[x] += count
        self.total += count
        return self.c[x]

    def query(self, x):
        return self.c.get(x, 0)

    def top(self, n):
        return self.c.most_common(n)

    @property
    def memory_bytes(self):
        # approximate: the dict itself plus the key and value int objects
        return sys.getsizeof(self.c) + sum(sys.getsizeof(k) + sys.getsizeof(v) for k, v in self.c.items())

"""Baseline: Space-Saving (Metwally et al.). k counters, lists top-k directly.
Heap with lazy deletion, so an update is O(log k)."""
import heapq
import sys


class SpaceSaving:
    def __init__(self, k):
        self.k, self.c, self.h, self.total = k, {}, [], 0

    def add(self, x, count=1):
        c, h = self.c, self.h
        self.total += count
        if x in c:
            c[x] += count
        elif len(c) < self.k:
            c[x] = count
        else:
            while True:                       # pop until the entry is current
                cnt, key = heapq.heappop(self.h)
                if c.get(key) == cnt:
                    break
            del c[key]
            c[x] = cnt + count                # new key inherits the evicted count
        heapq.heappush(self.h, (c[x], x))
        if len(self.h) > 8 * self.k:          # drop stale entries
            self.h = [(v, key) for key, v in c.items()]
            heapq.heapify(self.h)
        return c[x]

    def query(self, x):
        return self.c.get(x, 0)

    def top(self, n):
        return sorted(self.c.items(), key=lambda kv: -kv[1])[:n]

    def error_bound(self):
        return self.total / self.k

    @property
    def memory_bytes(self):
        return sys.getsizeof(self.c) + sum(sys.getsizeof(k) + sys.getsizeof(v) for k, v in self.c.items())

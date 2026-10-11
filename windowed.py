"""Ring of sub-window sketches. CMS cannot delete, so old traffic expires by
dropping the oldest sketch instead of decrementing counters."""
from collections import deque
from .cms import CountMinSketch


class WindowedCMS:
    def __init__(self, slices, epsilon, delta, conservative=True, seed=0):
        self.args = (epsilon, delta, conservative)
        self.seed = seed
        self.live = deque(maxlen=slices)
        self.live.append(self._new())

    def _new(self):
        self.seed += 1
        eps, delta, cons = self.args
        return CountMinSketch.from_error(eps, delta, conservative=cons, seed=self.seed)

    @property
    def history_len(self):
        return len(self.live) - 1

    def add(self, x):
        return self.live[-1].add(x)

    def newest(self, x):
        return self.live[-1].query(x)

    def baseline(self, x):
        """Average per-slice estimate over the older slices still in the window."""
        old = list(self.live)[:-1]
        return sum(s.query(x) for s in old) / len(old) if old else 0.0

    def window_estimate(self, x):
        return sum(s.query(x) for s in self.live)

    def advance(self):
        self.live.append(self._new())         # deque(maxlen) drops the oldest slice

    @property
    def memory_bytes(self):
        return sum(s.memory_bytes for s in self.live)

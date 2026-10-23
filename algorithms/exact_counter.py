"""Exact frequency counter (hash map). Reference / ground truth.  (Owner: M)
Update/query: expected O(1).  Space: O(u), u = number of distinct items."""


class ExactCounter:
    def __init__(self):
        self._counts = {}
        self.total = 0

    def update(self, item):
        item = str(item)
        self._counts[item] = self._counts.get(item, 0) + 1
        self.total += 1

    def count(self, item):
        return self._counts.get(str(item), 0)

    def distinct(self):
        return len(self._counts)

    def items(self):
        return dict(self._counts)

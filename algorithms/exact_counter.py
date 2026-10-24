"""Exact frequency counter (hash map). Reference / ground truth.  (Owner: M / Member 3)

Data structure: a Python dict (hash table) mapping item -> count.

Complexity  (u = distinct items so far, b = items in one batch)
  update / count   : expected O(1) (O(u) worst case if every key collides)
  update_batch(b)  : expected O(b)  -- b calls to update()
  distinct / total : O(1)   (len() of a dict; `total` is a running integer)
  items()          : O(u)   (returns a copy)
  space            : O(u)   -- ONE entry per distinct IP, forever.

Why a dict, and what it costs
  A dict gives exact answers with O(1) updates, which is why it is the ground truth the
  approximate structures are compared with. The price is memory that grows with the
  number of distinct IPs and never shrinks (see results/memory_growth.md): Count-Min
  Sketch and Space-Saving trade a little accuracy for memory that stays fixed.
  Rejected: a sorted list/BST needs O(log u)-O(u) per update; a direct-address array
  cannot index sparse strings like IP addresses.

Live use: the counter is created ONCE and updated batch after batch. Nothing here ever
resets the counts, so after any number of batches count(ip) is the true number of times
that IP has been seen.
"""


class ExactCounter:
    def __init__(self):
        self._counts = {}
        self.total = 0          # number of events counted so far (sum of all counts)

    def update(self, item):
        item = str(item)
        self._counts[item] = self._counts.get(item, 0) + 1
        self.total += 1

    def update_batch(self, items):
        """Count every item of one batch, adding to the existing counts.
        Returns how many items were counted. Expected O(b) for b items."""
        counted = 0
        for item in items:
            self.update(item)
            counted += 1
        return counted

    def count(self, item):
        return self._counts.get(str(item), 0)

    def distinct(self):
        return len(self._counts)

    def items(self):
        return dict(self._counts)

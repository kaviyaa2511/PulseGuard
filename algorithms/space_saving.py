"""Space-Saving: track the k most likely frequent items in bounded memory. (Owner: K)

Table maps item -> [count, error, seq].
  * hit            : count += 1
  * free slot      : insert (1, 0)
  * table full     : evict the minimum-count item (m); the new item gets
                     count = m + 1 and error = m.
Invariants: at most `capacity` entries; sum of all counts == number of events;
count - error <= true count <= count.

Two ways to find the minimum:
  use_heap=False : scan all k entries            -> O(k) per eviction
  use_heap=True  : min-heap with lazy deletion   -> O(log k) amortised
Ties are broken by earliest insertion in both versions, so both give
identical results.
"""
import heapq


class SpaceSaving:
    def __init__(self, capacity, use_heap=False):
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity <= 0:
            raise ValueError(f"capacity must be a positive integer, got {capacity!r}")
        self.capacity = capacity
        self.use_heap = use_heap
        self._table = {}
        self._heap = []
        self._seq = 0
        self.processed = 0

    def __len__(self):
        return len(self._table)

   
    def _push(self, item, entry):
        heapq.heappush(self._heap, (entry[0], entry[2], item))       
        if len(self._heap) > 4 * self.capacity + 4:
            self._heap = [(e[0], e[2], it) for it, e in self._table.items()]
            heapq.heapify(self._heap)

    def _pop_min_heap(self):
        while True:
            count, seq, item = heapq.heappop(self._heap)
            e = self._table.get(item)
            if e is not None and e[2] == seq and e[0] == count:
                return item, count  

    def _min_scan(self):
        
        victim = min(self._table, key=lambda k: self._table[k][0])
        return victim, self._table[victim][0]

    def _insert(self, item, count, error):
        self._seq += 1
        entry = [count, error, self._seq]
        self._table[item] = entry
        if self.use_heap:
            self._push(item, entry)

   
    def update(self, item):
        item = str(item)
        self.processed += 1
        entry = self._table.get(item)
        if entry is not None:
            entry[0] += 1
            if self.use_heap:
                self._push(item, entry)
            return
        if len(self._table) < self.capacity:
            self._insert(item, 1, 0)
            return
        victim, min_count = self._pop_min_heap() if self.use_heap else self._min_scan()
        del self._table[victim]
        self._insert(item, min_count + 1, min_count)

    def candidates(self):
        """List of (item, count, error), highest count first."""
        rows = [(k, v[0], v[1]) for k, v in self._table.items()]
        return sorted(rows, key=lambda r: r[1], reverse=True)
    
    def get_candidate(self, item):
        """Return (estimated_count, error) for a tracked item, or None."""
        item = str(item)
        entry = self._table.get(item)

        if entry is None:
            return None

        return entry[0], entry[1]


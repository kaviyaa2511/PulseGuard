import random
import unittest
from algorithms.space_saving import SpaceSaving


class TestSpaceSaving(unittest.TestCase):
    def test_insert_and_update(self):
        s = SpaceSaving(3)
        s.update("a"); s.update("a")
        self.assertEqual(s.candidates(), [("a", 2, 0)])

    def test_eviction_sets_count_and_error(self):
        s = SpaceSaving(2)
        for x in ["a", "a", "a", "b", "c"]:
            s.update(x)
        d = {i: (c, e) for i, c, e in s.candidates()}
        self.assertNotIn("b", d)                 # min evicted
        self.assertEqual(d["c"], (2, 1))         # count = min+1, error = min
        self.assertEqual(d["a"], (3, 0))

    def test_never_exceeds_capacity(self):
        s = SpaceSaving(5)
        for i in range(500):
            s.update(f"ip{i}")
            self.assertLessEqual(len(s), 5)

    def test_counts_sum_to_stream_length(self):
        rng = random.Random(3)
        s = SpaceSaving(4)
        for _ in range(777):
            s.update(rng.randrange(30))
        self.assertEqual(sum(c for _, c, _ in s.candidates()), 777)

    def test_bounds_hold(self):
        rng = random.Random(4)
        s, exact = SpaceSaving(6), {}
        for _ in range(2000):
            x = str(int(rng.expovariate(0.2)))
            s.update(x); exact[x] = exact.get(x, 0) + 1
        for item, c, e in s.candidates():
            self.assertLessEqual(c - e, exact[item])
            self.assertLessEqual(exact[item], c)

    def test_heap_equals_scan(self):
        rng = random.Random(5)
        a, b = SpaceSaving(8), SpaceSaving(8, use_heap=True)
        for _ in range(5000):
            x = f"ip{int(rng.expovariate(0.05))}"
            a.update(x); b.update(x)
        self.assertEqual(a.candidates(), b.candidates())

    def test_heap_stays_small(self):
        s = SpaceSaving(5, use_heap=True)
        for _ in range(10000):
            s.update("a")
        self.assertLessEqual(len(s._heap), 4 * 5 + 5)

    def test_capacity_one_and_short_stream(self):
        s = SpaceSaving(1)
        for x in "abc":
            s.update(x)
        self.assertEqual(s.candidates(), [("c", 3, 2)])
        t = SpaceSaving(10); t.update("x")
        self.assertEqual(len(t), 1)

    def test_invalid_capacity(self):
        for c in (0, -2, 1.5):
            with self.assertRaises(ValueError):
                SpaceSaving(c)

    def test_worked_example_from_report(self):
        s = SpaceSaving(3)
        for ch in "ABACADABAEACAFABADAC":
            s.update(ch)
        self.assertEqual(s.candidates(), [("A", 10, 0), ("D", 5, 4), ("C", 5, 4)])


if __name__ == "__main__":
    unittest.main()

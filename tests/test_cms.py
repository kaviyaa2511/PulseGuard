import random
import unittest
from algorithms.count_min_sketch import CountMinSketch


class TestCMS(unittest.TestCase):
    def test_unseen_is_zero(self):
        self.assertEqual(CountMinSketch(50, 3).estimate("x"), 0)

    def test_single_and_repeated(self):
        c = CountMinSketch(100, 3)
        c.update("a")
        self.assertGreaterEqual(c.estimate("a"), 1)
        for _ in range(4):
            c.update("a")
        self.assertGreaterEqual(c.estimate("a"), 5)

    def test_never_underestimates(self):
        rng = random.Random(0)
        c, exact = CountMinSketch(20, 3), {}
        for _ in range(3000):
            x = f"ip{rng.randrange(200)}"
            c.update(x)
            exact[x] = exact.get(x, 0) + 1
        for x, n in exact.items():
            self.assertGreaterEqual(c.estimate(x), n)

    def test_width_one_collides_but_valid(self):
        c = CountMinSketch(1, 2)
        for x in "abc":
            c.update(x)
        self.assertEqual(c.estimate("a"), 3)  # everything collides

    def test_deterministic_across_instances(self):
        a, b = CountMinSketch(30, 3, seed=7), CountMinSketch(30, 3, seed=7)
        for x in "abcab":
            a.update(x); b.update(x)
        self.assertEqual(a.table, b.table)

    def test_counters_fixed(self):
        c = CountMinSketch(10, 4)
        for i in range(1000):
            c.update(i)
        self.assertEqual(c.num_counters(), 40)

    def test_invalid(self):
        for w, d in [(0, 3), (-1, 3), (5, 0), (2.5, 3)]:
            with self.assertRaises(ValueError):
                CountMinSketch(w, d)
        with self.assertRaises(ValueError):
            CountMinSketch(5, 2).update("a", -1)


if __name__ == "__main__":
    unittest.main()

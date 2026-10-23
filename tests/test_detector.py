import unittest
from algorithms.count_min_sketch import CountMinSketch
from detection.detector import detect, evaluate, top_k


class TestDetector(unittest.TestCase):
    def setUp(self):
        self.cms = CountMinSketch(1000, 4)
        for _ in range(20): self.cms.update("hot")
        for _ in range(3): self.cms.update("cold")
        self.cands = [("hot", 20, 0), ("cold", 3, 0)]

    def test_flags_only_above_threshold(self):
        self.assertEqual([i for i, _ in detect(self.cands, self.cms, 10)], ["hot"])

    def test_threshold_is_strict(self):
        self.assertEqual(detect(self.cands, self.cms, 20), [])

    def test_empty_and_extremes(self):
        self.assertEqual(detect([], self.cms, 5), [])
        self.assertEqual(len(detect(self.cands, self.cms, 0)), 2)
        self.assertEqual(detect(self.cands, self.cms, 10**9), [])
        with self.assertRaises(ValueError):
            detect(self.cands, self.cms, -1)

    def test_top_k_methods_agree(self):
        c = [(str(i), i, 0) for i in (5, 1, 9, 3, 7)]
        self.assertEqual(top_k(c, 3, "sort"), top_k(c, 3, "heap"))
        self.assertEqual([x[1] for x in top_k(c, 3)], [9, 7, 5])
        self.assertEqual(top_k(c, 0), [])
        self.assertEqual(len(top_k(c, 99)), 5)
        with self.assertRaises(ValueError):
            top_k(c, 2, "bogus")

    def test_evaluate(self):
        self.assertEqual(evaluate([("a", 9), ("b", 8)], {"a", "c"}), (0.5, 0.5))
        self.assertEqual(evaluate([], {"a"}), (1.0, 0.0))
        self.assertEqual(evaluate([], set()), (1.0, 1.0))
        self.assertEqual(evaluate(["a"], {"a"}), (1.0, 1.0))


if __name__ == "__main__":
    unittest.main()

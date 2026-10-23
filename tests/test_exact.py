import unittest
from algorithms.exact_counter import ExactCounter


class TestExact(unittest.TestCase):
    def test_counts(self):
        e = ExactCounter()
        for x in "ABACAB":
            e.update(x)
        self.assertEqual((e.count("A"), e.count("B"), e.count("C")), (3, 2, 1))
        self.assertEqual(e.count("Z"), 0)
        self.assertEqual(e.distinct(), 3)
        self.assertEqual(e.total, 6)

    def test_items_is_copy(self):
        e = ExactCounter(); e.update("a")
        e.items()["a"] = 99
        self.assertEqual(e.count("a"), 1)


if __name__ == "__main__":
    unittest.main()

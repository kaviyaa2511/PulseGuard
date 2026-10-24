import unittest
from collections import Counter
from algorithms.exact_counter import ExactCounter
from simulation.event_generator import LiveEventGenerator


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


class TestExactBatches(unittest.TestCase):
    """update_batch: counts accumulate across batches and are never reset."""

    def test_update_batch_returns_size_and_counts(self):
        e = ExactCounter()
        self.assertEqual(e.update_batch(["a", "b", "a"]), 3)
        self.assertEqual((e.count("a"), e.count("b"), e.total, e.distinct()), (2, 1, 3, 2))

    def test_empty_batch_changes_nothing(self):
        e = ExactCounter()
        e.update("a")
        self.assertEqual(e.update_batch([]), 0)
        self.assertEqual((e.count("a"), e.total, e.distinct()), (1, 1, 1))

    def test_repeated_batches_accumulate(self):
        e = ExactCounter()
        for _ in range(4):                       # the SAME batch four times
            e.update_batch(["x", "y", "x"])
        self.assertEqual((e.count("x"), e.count("y")), (8, 4))
        self.assertEqual(e.total, 12)

    def test_batch_equals_one_by_one(self):
        a, b = ExactCounter(), ExactCounter()
        data = list("abracadabra")
        a.update_batch(data)
        for x in data:
            b.update(x)
        self.assertEqual(a.items(), b.items())
        self.assertEqual(a.total, b.total)

    def test_accepts_any_iterable_and_non_strings(self):
        e = ExactCounter()
        e.update_batch(ip for ip in ("1.1.1.1", "1.1.1.1"))       # generator
        e.update_batch([7, "7"])                                   # str(7) == "7"
        self.assertEqual((e.count("1.1.1.1"), e.count(7), e.count("7")), (2, 2, 2))

    def test_counts_never_decrease_between_batches(self):
        e = ExactCounter()
        previous = {}
        gen = LiveEventGenerator(seed=21)
        for _ in range(60):
            e.update_batch(ev["source_ip"] for ev in gen.next_batch())
            now = e.items()
            for ip, c in previous.items():
                self.assertGreaterEqual(now[ip], c)
            previous = now

    def test_matches_ground_truth_for_live_batches(self):
        # The counter's answer must equal an independent count (collections.Counter)
        # of every IP the generator emitted.
        gen, e, truth = LiveEventGenerator(seed=33), ExactCounter(), Counter()
        sent = 0
        for _ in range(100):
            ips = [ev["source_ip"] for ev in gen.next_batch()]
            e.update_batch(ips)
            truth.update(ips)
            sent += len(ips)
        self.assertEqual(e.items(), dict(truth))
        self.assertEqual(e.total, sent)
        self.assertEqual(e.distinct(), gen.seen_count())


if __name__ == "__main__":
    unittest.main()

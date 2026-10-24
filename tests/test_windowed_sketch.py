
import unittest

from algorithms.windowed_sketch import WindowedSketch


class TestWindowedSketch(unittest.TestCase):

    def test_counts_recent_events(self):
        sketch = WindowedSketch(
            window_seconds=3,
            bucket_seconds=1,
            width=100,
            depth=3,
        )

        sketch.add_event("IP_A", 0)
        sketch.add_event("IP_A", 1)
        sketch.add_event("IP_B", 2)

        self.assertGreaterEqual(
            sketch.estimate_recent_frequency("IP_A"), 2
        )

    def test_old_buckets_expire(self):
        sketch = WindowedSketch(
            window_seconds=2,
            bucket_seconds=1,
            width=100,
            depth=3,
        )

        sketch.add_event("IP_A", 0)
        self.assertGreaterEqual(
            sketch.estimate_recent_frequency("IP_A"), 1
        )

        # Advancing to bucket 3 expires bucket 0.
        sketch.add_event("IP_B", 3)

        self.assertEqual(
            sketch.estimate_recent_frequency("IP_A"), 0
        )

    def test_empty_sketch(self):
        sketch = WindowedSketch()
        self.assertEqual(
            sketch.estimate_recent_frequency("IP_A"), 0
        )

    def test_reset(self):
        sketch = WindowedSketch()
        sketch.add_event("IP_A", 1)
        sketch.reset()

        self.assertEqual(
            sketch.estimate_recent_frequency("IP_A"), 0
        )
        self.assertEqual(sketch.get_active_buckets(), 0)

    def test_invalid_timestamp(self):
        sketch = WindowedSketch()

        with self.assertRaises(ValueError):
            sketch.add_event("IP_A", float("nan"))


if __name__ == "__main__":
    unittest.main()

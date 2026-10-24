
"""Time-windowed Count-Min Sketch for PulseGuard."""

from math import ceil, isfinite

from algorithms.count_min_sketch import CountMinSketch


class WindowedSketch:
    """Estimate item frequencies across recent time buckets."""

    def __init__(
        self,
        window_seconds=10,
        bucket_seconds=1,
        width=100,
        depth=3,
        seed=42,
    ):
        if (
            not isinstance(window_seconds, (int, float))
            or isinstance(window_seconds, bool)
            or not isfinite(window_seconds)
            or window_seconds <= 0
        ):
            raise ValueError("window_seconds must be positive")

        if (
            not isinstance(bucket_seconds, (int, float))
            or isinstance(bucket_seconds, bool)
            or not isfinite(bucket_seconds)
            or bucket_seconds <= 0
        ):
            raise ValueError("bucket_seconds must be positive")

        self.window_seconds = window_seconds
        self.bucket_seconds = bucket_seconds
        self.bucket_count = ceil(window_seconds / bucket_seconds)

        self.width = width
        self.depth = depth
        self.seed = seed

        # Maps each time-bucket ID to its own Count-Min Sketch.
        self.buckets = {}
        self.latest_bucket = None

    def _create_sketch(self, bucket_id):
        return CountMinSketch(
            self.width,
            self.depth,
            seed=self.seed + bucket_id,
        )

    def _remove_expired(self):
        if self.latest_bucket is None:
            return

        first_active = self.latest_bucket - self.bucket_count + 1

        expired = [
            bucket_id
            for bucket_id in self.buckets
            if bucket_id < first_active
        ]

        for bucket_id in expired:
            del self.buckets[bucket_id]

    def add_event(self, item, timestamp):
        """Add an event using its numeric timestamp."""
        if (
            not isinstance(timestamp, (int, float))
            or isinstance(timestamp, bool)
            or not isfinite(timestamp)
        ):
            raise ValueError("timestamp must be a finite number")

        bucket_id = int(timestamp // self.bucket_seconds)

        if (
            self.latest_bucket is not None
            and bucket_id
            < self.latest_bucket - self.bucket_count + 1
        ):
            raise ValueError("Event is older than the active window")

        if self.latest_bucket is None or bucket_id > self.latest_bucket:
            self.latest_bucket = bucket_id
            self._remove_expired()

        if bucket_id not in self.buckets:
            self.buckets[bucket_id] = self._create_sketch(bucket_id)

        self.buckets[bucket_id].update(item)

    def estimate_recent_frequency(self, item):
        """Estimate frequency across all active time buckets."""
        if self.latest_bucket is None:
            return 0

        first_active = self.latest_bucket - self.bucket_count + 1
        total = 0

        for bucket_id, sketch in self.buckets.items():
            if first_active <= bucket_id <= self.latest_bucket:
                total += sketch.estimate(item)

        return total

    def get_active_buckets(self):
        """Return the number of currently retained time buckets."""
        return len(self.buckets)

    def reset(self):
        """Clear all time buckets."""
        self.buckets.clear()
        self.latest_bucket = None

    def get_memory_counters(self):
        """Return the total number of allocated CMS counters."""
        return sum(
            sketch.num_counters()
            for sketch in self.buckets.values()
        )

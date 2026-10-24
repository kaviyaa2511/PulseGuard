import math
import unittest
from simulation.event_generator import (LiveEventGenerator, generate_events,
                                        validate_event)


class TestGenerator(unittest.TestCase):
    def test_reproducible(self):
        self.assertEqual(generate_events(200, seed=5), generate_events(200, seed=5))

    def test_different_seed_differs(self):
        self.assertNotEqual(generate_events(200, seed=1), generate_events(200, seed=2))

    def test_attack_share_close(self):
        ev = generate_events(10000, attack_ratio=0.2)
        share = sum(e["source_ip"] == "10.0.0.99" for e in ev) / len(ev)
        self.assertAlmostEqual(share, 0.2, delta=0.02)

    def test_fields_and_edges(self):
        ev = generate_events(3)
        self.assertEqual(set(ev[0]), {"timestamp", "source_ip", "service", "signature"})
        self.assertEqual(generate_events(0), [])
        self.assertTrue(all(e["source_ip"] != "10.0.0.99" for e in generate_events(100, attack_ratio=0)))
        self.assertTrue(all(e["source_ip"] == "10.0.0.99" for e in generate_events(100, attack_ratio=1)))

    def test_invalid(self):
        for kw in ({"n": -1}, {"n": 5, "attack_ratio": 1.5}, {"n": 5, "num_normal_ips": 0}):
            with self.assertRaises(ValueError):
                generate_events(**kw)


# ---------------------------------------------------------------------------
# Live simulation (Member 3). Nothing here sleeps: batches are produced instantly.
# ---------------------------------------------------------------------------
GOOD = {"timestamp": 1.5, "source_ip": "10.0.0.99", "service": "login",
        "signature": "login_failure"}


class TestValidateEvent(unittest.TestCase):
    def test_good_event_passes(self):
        validate_event(GOOD)                                  # no exception
        validate_event({**GOOD, "timestamp": 0})              # zero is allowed

    def test_bad_events_rejected(self):
        bad_events = [
            "not a dict", None, 42,
            {k: v for k, v in GOOD.items() if k != "source_ip"},      # missing field
            {**GOOD, "timestamp": -1},
            {**GOOD, "timestamp": math.nan},
            {**GOOD, "timestamp": math.inf},
            {**GOOD, "timestamp": True},                              # bool is not a time
            {**GOOD, "timestamp": "5"},
            {**GOOD, "source_ip": "999.1.1.1"},
            {**GOOD, "source_ip": "not-an-ip"},
            {**GOOD, "source_ip": ""},
            {**GOOD, "source_ip": 12345},
            {**GOOD, "service": "printer"},
            {**GOOD, "signature": "mystery"},
        ]
        for event in bad_events:
            with self.subTest(event=event):
                with self.assertRaises(ValueError):
                    validate_event(event)


class TestLiveEventGenerator(unittest.TestCase):
    def test_batch_size_between_5_and_10(self):
        gen = LiveEventGenerator(seed=3)
        sizes = {len(gen.next_batch()) for _ in range(300)}
        self.assertTrue(sizes <= set(range(5, 11)), sizes)
        self.assertEqual(sizes, set(range(5, 11)))            # all sizes do occur

    def test_every_event_is_valid(self):
        gen = LiveEventGenerator(seed=4)
        for _ in range(100):
            for event in gen.next_batch():
                validate_event(event)

    def test_new_and_previously_seen_ips_in_every_batch(self):
        gen = LiveEventGenerator(seed=7)
        seen = set()
        for batch_no in range(1, 201):
            ips = [e["source_ip"] for e in gen.next_batch()]
            self.assertTrue(any(ip not in seen for ip in ips),
                            f"batch {batch_no} has no new IP")
            if batch_no > 1:
                self.assertTrue(any(ip in seen for ip in ips),
                                f"batch {batch_no} has no previously seen IP")
            seen.update(ips)
        self.assertEqual(gen.seen_count(), len(seen))

    def test_guarantees_hold_even_for_extreme_ratios(self):
        # all attacker traffic: later batches must still contain a new IP
        # no new IPs requested: later batches must still contain one
        for kwargs in ({"attack_ratio": 1.0}, {"attack_ratio": 0.0, "new_ip_ratio": 0.0},
                       {"attack_ratio": 0.0, "new_ip_ratio": 1.0}):
            gen = LiveEventGenerator(seed=1, **kwargs)
            seen = set()
            for batch_no in range(1, 51):
                ips = [e["source_ip"] for e in gen.next_batch()]
                self.assertTrue(any(ip not in seen for ip in ips), kwargs)
                if batch_no > 1:
                    self.assertTrue(any(ip in seen for ip in ips), kwargs)
                seen.update(ips)

    def test_new_ips_are_never_reused_as_new(self):
        gen = LiveEventGenerator(seed=2, attack_ratio=0.0)
        fresh = []
        seen = set()
        for _ in range(100):
            for e in gen.next_batch():
                if e["source_ip"] not in seen:
                    fresh.append(e["source_ip"])
                    seen.add(e["source_ip"])
        self.assertEqual(len(fresh), len(set(fresh)))         # each first sighting unique

    def test_reproducible_with_same_seed(self):
        a, b = LiveEventGenerator(seed=11), LiveEventGenerator(seed=11)
        for _ in range(50):
            self.assertEqual(a.next_batch(), b.next_batch())

    def test_different_seed_differs(self):
        a, b = LiveEventGenerator(seed=1), LiveEventGenerator(seed=2)
        self.assertNotEqual([a.next_batch() for _ in range(5)],
                            [b.next_batch() for _ in range(5)])

    def test_state_continues_between_batches(self):
        # 10 batches from one generator == the first 10 batches of another run:
        # the generator continues, it does not restart.
        one, two = LiveEventGenerator(seed=9), LiveEventGenerator(seed=9)
        first_ten = [one.next_batch() for _ in range(10)]
        again = [two.next_batch() for _ in range(10)]
        self.assertEqual(first_ten, again)
        self.assertNotEqual(first_ten[0], first_ten[1])       # batches differ from each other
        self.assertEqual(one.batches, 10)
        seen_after_5 = LiveEventGenerator(seed=9)
        for _ in range(5):
            seen_after_5.next_batch()
        self.assertLessEqual(seen_after_5.seen_count(), one.seen_count())

    def test_attacker_events_look_like_failed_logins(self):
        gen = LiveEventGenerator(seed=5, attack_ratio=1.0)
        for e in gen.next_batch():
            self.assertEqual((e["source_ip"], e["service"], e["signature"]),
                             ("10.0.0.99", "login", "login_failure"))

    def test_custom_attacker_ip(self):
        gen = LiveEventGenerator(seed=1, attacker_ip="8.8.8.8", attack_ratio=1.0)
        self.assertTrue(all(e["source_ip"] == "8.8.8.8" for e in gen.next_batch()))

    def test_timestamps_follow_simulated_clock(self):
        gen = LiveEventGenerator(seed=6, interval_seconds=5)
        last = -1.0
        for k in range(20):
            for e in gen.next_batch():
                self.assertGreaterEqual(e["timestamp"], k * 5)
                self.assertLess(e["timestamp"], (k + 1) * 5)
                self.assertGreaterEqual(e["timestamp"], last)
                last = e["timestamp"]

    def test_attack_share_is_about_attack_ratio(self):
        gen = LiveEventGenerator(seed=8, attack_ratio=0.2)
        events = [e for _ in range(2000) for e in gen.next_batch()]
        share = sum(e["source_ip"] == "10.0.0.99" for e in events) / len(events)
        self.assertAlmostEqual(share, 0.2, delta=0.04)

    def test_fixed_batch_size(self):
        gen = LiveEventGenerator(min_batch=5, max_batch=5)
        self.assertTrue(all(len(gen.next_batch()) == 5 for _ in range(20)))

    def test_invalid_parameters(self):
        bad = [{"min_batch": 1}, {"min_batch": 0}, {"min_batch": 8, "max_batch": 7},
               {"min_batch": 5.5}, {"max_batch": True}, {"attack_ratio": 1.5},
               {"attack_ratio": -0.1}, {"new_ip_ratio": 2}, {"new_ip_ratio": math.nan},
               {"interval_seconds": 0}, {"interval_seconds": -5},
               {"interval_seconds": math.inf}, {"attacker_ip": "nope"}]
        for kwargs in bad:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    LiveEventGenerator(**kwargs)


if __name__ == "__main__":
    unittest.main()

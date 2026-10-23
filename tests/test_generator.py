import unittest
from simulation.event_generator import generate_events


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


if __name__ == "__main__":
    unittest.main()

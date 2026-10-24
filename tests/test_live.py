"""Integration tests for the live simulation (Member 4).

Nothing here waits for real time: run_live() receives a fake `sleep` that only records the
requested delays, and CLI tests use a 1-millisecond interval or --batches 1.
"""
import io
import unittest
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout

import main as pg
from simulation.event_generator import LiveEventGenerator

ATTACKER = "10.0.0.99"


def ev(ip, t=0.0):
    return {"timestamp": t, "source_ip": ip, "service": "website", "signature": "page_request"}


class ScriptedGenerator:
    """Hands out pre-written batches (deterministic, no randomness)."""
    def __init__(self, batches):
        self._batches = iter(batches)

    def next_batch(self):
        return next(self._batches)


class RecordingGenerator:
    """Wraps the real generator and remembers every IP it handed out."""
    def __init__(self, inner):
        self.inner, self.ips = inner, []

    def next_batch(self):
        batch = self.inner.next_batch()
        self.ips.extend(e["source_ip"] for e in batch)
        return batch


class FakeSleep:
    def __init__(self, interrupt_on_call=None):
        self.calls, self.interrupt_on_call = [], interrupt_on_call

    def __call__(self, seconds):
        self.calls.append(seconds)
        if self.interrupt_on_call == len(self.calls):
            raise KeyboardInterrupt


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = pg.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestExactlyOnceAndState(unittest.TestCase):
    def test_each_event_processed_exactly_once_per_algorithm(self):
        gen = RecordingGenerator(LiveEventGenerator(seed=1))
        monitor = pg.LiveMonitor()
        pg.run_live(gen, monitor, 60, max_batches=25, sleep=FakeSleep(), out=lambda s: None)
        n = len(gen.ips)
        self.assertEqual((monitor.cms.total, monitor.ss.processed, monitor.exact.total), (n, n, n))
        self.assertTrue(monitor.consistent())
        # the exact counter holds the true count of every IP that was sent
        self.assertEqual(monitor.exact.items(), dict(Counter(gen.ips)))
        # CMS never under-estimates, Space-Saving counts are upper bounds
        for ip, true in Counter(gen.ips).items():
            self.assertGreaterEqual(monitor.cms.estimate(ip), true)

    def test_state_is_kept_between_batches(self):
        monitor = pg.LiveMonitor()
        structures = (monitor.cms, monitor.ss, monitor.exact)
        gen = LiveEventGenerator(seed=2)
        previous = 0
        for i in range(1, 11):
            r = monitor.process_batch(gen.next_batch())
            self.assertEqual(r["batch"], i)
            self.assertGreater(r["total_events"], previous)       # grows, never resets
            previous = r["total_events"]
        self.assertEqual(structures, (monitor.cms, monitor.ss, monitor.exact))  # same objects
        self.assertEqual(monitor.exact.total, previous)

    def test_repeated_batch_accumulates(self):
        monitor = pg.LiveMonitor()
        batch = [ev("1.1.1.1"), ev("1.1.1.1"), ev("2.2.2.2")]
        for _ in range(3):
            r = monitor.process_batch(batch)
        self.assertEqual(monitor.exact.count("1.1.1.1"), 6)
        self.assertEqual(r["total_events"], 9)
        self.assertEqual(r["unique_ips"], 2)
        self.assertEqual((r["new_ips"], r["repeat_events"]), (0, 3))   # nothing new on batch 3

    def test_new_vs_repeat_counts(self):
        monitor = pg.LiveMonitor()
        r1 = monitor.process_batch([ev("1.0.0.1"), ev("1.0.0.1"), ev("1.0.0.2")])
        r2 = monitor.process_batch([ev("1.0.0.1"), ev("1.0.0.3")])
        self.assertEqual((r1["new_ips"], r1["repeat_events"]), (2, 0))
        self.assertEqual((r2["new_ips"], r2["repeat_events"]), (1, 1))

    def test_empty_batch_is_harmless(self):
        monitor = pg.LiveMonitor()
        r = monitor.process_batch([])
        self.assertEqual((r["total_events"], r["unique_ips"], r["flagged"]), (0, 0, []))


class TestInvalidInput(unittest.TestCase):
    def test_bad_event_rejects_whole_batch_and_changes_nothing(self):
        monitor = pg.LiveMonitor()
        monitor.process_batch([ev("1.1.1.1")])
        bad = [ev("2.2.2.2"), {"timestamp": 1, "source_ip": "999.9.9.9",
                               "service": "website", "signature": "query"}]
        with self.assertRaises(ValueError):
            monitor.process_batch(bad)
        # the valid first event of the bad batch was NOT counted anywhere
        self.assertEqual((monitor.cms.total, monitor.ss.processed, monitor.exact.total), (1, 1, 1))
        self.assertEqual(monitor.exact.count("2.2.2.2"), 0)
        self.assertEqual(monitor.batches, 1)

    def test_invalid_monitor_parameters(self):
        for kwargs in ({"width": 0}, {"depth": -1}, {"capacity": 0}, {"threshold": -1}):
            with self.assertRaises(ValueError):
                pg.LiveMonitor(**kwargs)

    def test_cli_rejects_bad_options(self):
        bad_args = [("--live", "--interval", "0"), ("--live", "--interval", "-3"),
                    ("--live", "--interval", "nan"), ("--live", "--interval", "inf"),
                    ("--live", "--batches", "0"), ("--live", "--ips", "a,b"),
                    ("--live", "--scenario"), ("--demo", "--interval", "5"),
                    ("--interval", "5"), ("--batches", "2"),
                    ("--live", "--width", "0"), ("--live", "--attack-ratio", "2"),
                    ("--live", "--attacker", "not-an-ip"), ("--live", "--threshold", "-1")]
        for args in bad_args:
            with self.subTest(args=args):
                code, out, err = run_cli(*args)
                self.assertEqual(code, 2)
                self.assertIn("Error", err)
                self.assertNotIn("Batch 1", out)      # nothing ran


class TestSchedulingLoop(unittest.TestCase):
    def test_sleeps_between_batches_only(self):
        sleep = FakeSleep()
        pg.run_live(LiveEventGenerator(seed=1), pg.LiveMonitor(), 60,
                    max_batches=4, sleep=sleep, out=lambda s: None)
        self.assertEqual(sleep.calls, [60, 60, 60])   # 3 gaps for 4 batches, none after last

    def test_interval_is_configurable(self):
        sleep = FakeSleep()
        pg.run_live(LiveEventGenerator(seed=1), pg.LiveMonitor(), 5,
                    max_batches=3, sleep=sleep, out=lambda s: None)
        self.assertEqual(sleep.calls, [5, 5])

    def test_first_batch_runs_immediately(self):
        sleep = FakeSleep()
        pg.run_live(LiveEventGenerator(seed=1), pg.LiveMonitor(), 60,
                    max_batches=1, sleep=sleep, out=lambda s: None)
        self.assertEqual(sleep.calls, [])

    def test_ctrl_c_stops_cleanly_and_keeps_state(self):
        lines = []
        monitor = pg.LiveMonitor()
        sleep = FakeSleep(interrupt_on_call=2)        # Ctrl+C during the 2nd sleep
        returned = pg.run_live(LiveEventGenerator(seed=1), monitor, 60, sleep=sleep,
                               out=lines.append)      # max_batches=None: would run forever
        self.assertIs(returned, monitor)              # returned normally, no traceback
        self.assertEqual(monitor.batches, 2)
        self.assertTrue(monitor.consistent())
        text = "\n".join(lines)
        self.assertIn("Ctrl+C received", text)
        self.assertIn("Batches processed : 2", text)
        self.assertIn("agree: OK", text)

    def test_ctrl_c_before_second_batch_through_cli_path(self):
        # same thing, but via the real printing path
        out = io.StringIO()
        with redirect_stdout(out):
            pg.run_live(LiveEventGenerator(seed=1), pg.LiveMonitor(), 60,
                        sleep=FakeSleep(interrupt_on_call=1))
        self.assertIn("Batch 1", out.getvalue())
        self.assertNotIn("Batch 2", out.getvalue())
        self.assertIn("stopped", out.getvalue())


class TestDetectionEachBatch(unittest.TestCase):
    def test_alert_appears_once_as_new_then_stays_flagged(self):
        monitor = pg.LiveMonitor(threshold=5)
        quiet = [ev("1.1.1.1"), ev("2.2.2.2"), ev(ATTACKER), ev(ATTACKER), ev("3.3.3.3")]
        r1 = monitor.process_batch(quiet)                       # attacker: 2 events
        self.assertEqual(r1["flagged"], [])
        r2 = monitor.process_batch([ev(ATTACKER)] * 5)          # attacker: 7 > 5
        self.assertEqual([f[0] for f in r2["flagged"]], [ATTACKER])
        self.assertEqual(r2["new_alerts"], [ATTACKER])
        r3 = monitor.process_batch([ev("4.4.4.4")] * 5)
        self.assertEqual([f[0] for f in r3["flagged"]], [ATTACKER])   # still flagged ...
        self.assertEqual(r3["new_alerts"], [])                        # ... but not "NEW" again

    def test_results_contain_fields_shown_to_the_user(self):
        monitor = pg.LiveMonitor(threshold=1, ground_truth={ATTACKER})
        r = monitor.process_batch([ev(ATTACKER)] * 3 + [ev("5.5.5.5")] * 2)
        text = pg.format_live_report(r, "12:00:00")
        for expected in ("Batch 1", "events=5", "unique IPs=2", ATTACKER, "CMS Est",
                         "NEW ALERT", "Precision"):
            self.assertIn(expected, text)
        self.assertEqual(r["rows"][0][0], ATTACKER)               # most frequent first
        ip, ss_count, ss_err, cms_est, exact = r["rows"][0]
        self.assertEqual((ss_count, exact), (3, 3))
        self.assertGreaterEqual(cms_est, exact)

    def test_adaptive_threshold(self):
        monitor = pg.LiveMonitor()
        self.assertEqual(monitor.current_threshold(), 5)          # floor of 5
        monitor.process_batch([ev("1.1.1.1")] * 100)
        self.assertEqual(monitor.current_threshold(), 10)         # 10% of 100 events
        self.assertEqual(pg.LiveMonitor(threshold=3).current_threshold(), 3)   # fixed wins

    def test_real_generator_attacker_is_found(self):
        gen = LiveEventGenerator(seed=1, attack_ratio=0.2)
        monitor = pg.LiveMonitor(ground_truth={ATTACKER})
        pg.run_live(gen, monitor, 60, max_batches=40, sleep=FakeSleep(), out=lambda s: None)
        flagged = [ip for ip, _ in pg.detect(monitor.ss.candidates(), monitor.cms,
                                             monitor.current_threshold())]
        self.assertIn(ATTACKER, flagged)
        self.assertEqual(flagged, [ATTACKER])                     # and nobody innocent

    def test_heap_variant_gives_same_detection(self):
        results = []
        for use_heap in (False, True):
            monitor = pg.LiveMonitor(use_heap=use_heap)
            gen = LiveEventGenerator(seed=3)
            for _ in range(30):
                r = monitor.process_batch(gen.next_batch())
            results.append((r["rows"], r["flagged"]))
        self.assertEqual(results[0], results[1])


class TestLiveCommandLine(unittest.TestCase):
    def test_live_runs_requested_number_of_batches(self):
        code, out, err = run_cli("--live", "--interval", "0.001", "--batches", "3")
        self.assertEqual(code, 0, err)
        for n in (1, 2, 3):
            self.assertIn(f"Batch {n} ", out)
        self.assertNotIn("Batch 4", out)
        self.assertIn("every 0.001 s", out)
        self.assertIn("Batches processed : 3", out)

    def test_demo_uses_5_second_interval(self):
        code, out, _ = run_cli("--demo", "--batches", "1")        # 1 batch -> no sleeping
        self.assertEqual(code, 0)
        self.assertIn("every 5 s", out)

    def test_default_interval_is_60_seconds(self):
        code, out, _ = run_cli("--live", "--batches", "1")
        self.assertEqual(code, 0)
        self.assertIn("every 60 s", out)

    def test_same_seed_same_output(self):
        def body(text):                      # drop the wall-clock line "Batch n [hh:mm:ss] ..."
            return [l.split("]", 1)[-1] if l.startswith("Batch") else l for l in text.splitlines()]
        a = run_cli("--live", "--interval", "0.001", "--batches", "4", "--seed", "9")[1]
        b = run_cli("--live", "--interval", "0.001", "--batches", "4", "--seed", "9")[1]
        c = run_cli("--live", "--interval", "0.001", "--batches", "4", "--seed", "10")[1]
        self.assertEqual(body(a), body(b))
        self.assertNotEqual(body(a), body(c))

    def test_existing_modes_unchanged(self):
        code, out, _ = run_cli("--scenario")
        self.assertEqual(code, 0)
        self.assertIn("Precision: 1.00   Recall: 1.00", out)
        self.assertNotIn("LIVE", out)


if __name__ == "__main__":
    unittest.main()

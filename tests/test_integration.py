import io
import unittest
from contextlib import redirect_stdout, redirect_stderr
import main as pg
from simulation.event_generator import generate_events


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = pg.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestIntegration(unittest.TestCase):
    def test_scenario_flags_attacker(self):
        ips = [pg.SCENARIO_MAP[c] for c in pg.SCENARIO_STREAM]
        r = pg.run_pipeline(ips, 10, 3, 3, 8, {"10.0.0.99"})
        self.assertEqual([f[0] for f in r["flagged"]], ["10.0.0.99"])
        self.assertEqual((r["precision"], r["recall"]), (1.0, 1.0))
        for ip, c, e, est, ex in r["rows"]:
            self.assertGreaterEqual(est, ex)

    def test_simulated_stream(self):
        ev = generate_events(5000)
        ips = [e["source_ip"] for e in ev]
        r = pg.run_pipeline(ips, 200, 3, 10, 500, {"10.0.0.99"})
        self.assertLessEqual(len(r["rows"]), 10)
        self.assertEqual(r["recall"], 1.0)
        self.assertEqual(r["memory"]["cms_counters"], 600)

    def test_heap_flag_same_output(self):
        a = run_cli("--events", "2000")
        b = run_cli("--events", "2000", "--heap")
        strip = lambda s: [l for l in s.splitlines() if "Processing" not in l and "CMS 0" not in l and "scan" not in l and "heap" not in l]
        self.assertEqual(a[0], 0); self.assertEqual(b[0], 0)
        self.assertEqual(strip(a[1])[4:20], strip(b[1])[4:20])

    # ---- edge cases faculty may try ----
    def test_empty_stream(self):
        code, out, _ = run_cli("--ips", "")
        self.assertEqual(code, 0); self.assertIn("empty stream", out)

    def test_single_event(self):
        code, out, _ = run_cli("--ips", "1.1.1.1", "--threshold", "0")
        self.assertEqual(code, 0); self.assertIn("1.1.1.1", out)

    def test_all_same_ip(self):
        code, out, _ = run_cli("--ips", ",".join(["9.9.9.9"] * 50), "--threshold", "10", "--truth", "9.9.9.9")
        self.assertIn("Precision: 1.00   Recall: 1.00", out)

    def test_all_distinct_ips(self):
        ips = ",".join(f"10.1.0.{i}" for i in range(1, 200))
        code, out, _ = run_cli("--ips", ips, "--capacity", "5", "--threshold", "1000")
        self.assertEqual(code, 0); self.assertIn("(none)", out)

    def test_stream_shorter_than_capacity(self):
        code, out, _ = run_cli("--ips", "a,b", "--capacity", "10", "--threshold", "0")
        self.assertEqual(code, 0)

    def test_threshold_zero_and_huge(self):
        _, out0, _ = run_cli("--ips", "a,b,c", "--threshold", "0")
        self.assertNotIn("(none)", out0)
        _, outh, _ = run_cli("--ips", "a,b,c", "--threshold", "999999")
        self.assertIn("(none)", outh)

    def test_malformed_lines_and_spaces(self):
        self.assertEqual(pg.parse_ips("  a  \n\n# c\n b ,  a  \n"), ["a", "b", "a"])

    def test_width_one_capacity_one(self):
        code, out, _ = run_cli("--ips", "a,b,a,c", "--width", "1", "--capacity", "1", "--threshold", "0")
        self.assertEqual(code, 0)

    def test_invalid_parameters_report_error(self):
        for args in (["--width", "0"], ["--depth", "-1"], ["--capacity", "0"],
                     ["--threshold", "-5", "--ips", "a"], ["--input", "no_such_file.txt"]):
            code, _, err = run_cli(*args, *(["--ips", "a"] if "--ips" not in args and "--input" not in args else []))
            self.assertEqual(code, 2, args)
            self.assertIn("Error", err)

    def test_input_file(self):
        code, out, _ = run_cli("--input", "sample_input.txt", "--threshold", "2", "--truth", "10.0.0.99")
        self.assertEqual(code, 0); self.assertIn("Precision: 1.00   Recall: 1.00", out)


if __name__ == "__main__":
    unittest.main()

"""PulseGuard - memory-efficient frequent-pattern detection (CMS + Space-Saving).

Examples
  python main.py                              # simulated stream
  python main.py --scenario                   # the 20-event worked example
  python main.py --input ips.txt --threshold 3
  python main.py --ips "a,b,a,a,c" --capacity 2 --threshold 1
  type ips.txt | python main.py --input -     # read stdin

Live simulation (a batch of 5-10 simulated events every `interval` seconds)
  python main.py --live                       # normal mode: one batch every 60 s
  python main.py --demo                       # demo mode:   one batch every 5 s
  python main.py --live --interval 10         # any other positive interval
  python main.py --demo --batches 4           # stop by itself after 4 batches
  Press Ctrl+C at any time to stop cleanly. No real network traffic is captured.
"""
import argparse
import math
import sys
import time

from algorithms.count_min_sketch import CountMinSketch
from algorithms.space_saving import SpaceSaving
from algorithms.exact_counter import ExactCounter
from simulation.event_generator import generate_events, LiveEventGenerator, validate_event
from detection.detector import detect, evaluate, top_k

SCENARIO_MAP = {"A": "10.0.0.99", "B": "192.168.1.10", "C": "192.168.1.12",
                "D": "192.168.1.15", "E": "192.168.1.20", "F": "192.168.1.31"}
SCENARIO_STREAM = "ABACADABAEACAFABADAC"


def parse_ips(text):
    """Split text into IP tokens; ignore blanks, extra spaces and # comments."""
    ips = []
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        ips.extend(tok for tok in line.replace(",", " ").split() if tok)
    return ips


def run_pipeline(ips, width=100, depth=3, capacity=10, threshold=None,
                 ground_truth=None, use_heap=False, seed=42):
    cms = CountMinSketch(width, depth, seed)       # validates width/depth
    ss = SpaceSaving(capacity, use_heap)           # validates capacity
    exact = ExactCounter()
    n = len(ips)
    if threshold is None:
        threshold = 0.1 * n                        # default: 10% of the stream
    if threshold < 0:
        raise ValueError("threshold must be non-negative")

    timings = {}
    for name, structure in (("CMS", cms), ("Space-Saving", ss), ("Exact", exact)):
        start = time.perf_counter()
        for ip in ips:                             # one event at a time
            structure.update(ip)
        timings[name] = time.perf_counter() - start

    cands = ss.candidates()
    flagged = detect(cands, cms, threshold)
    result = {
        "n": n, "width": width, "depth": depth, "capacity": capacity,
        "threshold": threshold, "use_heap": use_heap,
        "rows": [(ip, c, e, cms.estimate(ip), exact.count(ip)) for ip, c, e in cands],
        "flagged": [(ip, est, exact.count(ip)) for ip, est in flagged],
        "max_overestimate": max((cms.estimate(ip) - c for ip, c in exact.items().items()),
                                default=0),
        "memory": {"exact_entries": exact.distinct(),
                   "cms_counters": cms.num_counters(), "ss_slots": capacity},
        "timings": timings, "precision": None, "recall": None,
    }
    if ground_truth is not None:
        result["precision"], result["recall"] = evaluate(flagged, ground_truth)
    return result


def format_report(r):
    bar = "=" * 62
    out = [bar, "                       PULSEGUARD", bar,
           f"Config: events={r['n']}  CMS={r['width']}x{r['depth']}  "
           f"SS capacity={r['capacity']} ({'heap' if r['use_heap'] else 'scan'})  "
           f"threshold={r['threshold']:g}", "",
           "Frequent Candidates (from Space-Saving)",
           f"{'IP':<18}{'SS Count':>9}{'SS Err':>8}{'CMS Est':>9}{'Exact':>8}"]
    for ip, c, e, est, ex in r["rows"]:
        out.append(f"{ip:<18}{c:>9}{e:>8}{est:>9}{ex:>8}")
    out += ["", "Flagged for Investigation (CMS estimate > threshold)"]
    if r["flagged"]:
        for ip, est, ex in r["flagged"]:
            out.append(f"{ip:<18} est. frequency {est}  (exact {ex})")
    else:
        out.append("(none)")
    out += ["", "Accuracy"]
    if r["precision"] is None:
        out.append("Ground truth not provided (use --truth to get precision/recall)")
    else:
        out.append(f"Precision: {r['precision']:.2f}   Recall: {r['recall']:.2f}")
    out.append(f"CMS max overestimate over all IPs: {r['max_overestimate']}")
    m, t = r["memory"], r["timings"]
    out += ["", "Memory (data-structure entries)",
            f"Exact counter : {m['exact_entries']} entries  (grows with distinct IPs)",
            f"CMS           : {m['cms_counters']} counters (fixed)",
            f"Space-Saving  : {m['ss_slots']} slots     (fixed)", "",
            "Processing time (seconds, same stream)",
            f"CMS {t['CMS']:.4f}   Space-Saving {t['Space-Saving']:.4f}   "
            f"Exact {t['Exact']:.4f}", bar,
            "Note: a flag means 'frequent enough to investigate', not a confirmed attack."]
    return "\n".join(out)


# ===========================================================================
# LIVE SIMULATION  (Member 4: integration + detection)
#
#   LiveEventGenerator.next_batch()  --->  LiveMonitor.process_batch()
#         (Member 3)                         validate -> CMS -> Space-Saving -> Exact
#                                            -> detect()  -> result dict
#   run_live()  = the ONE scheduling loop: batch, report, sleep(interval), repeat.
#
# Connection contract with Member 3:
#   * generator.next_batch() returns a list of event dicts (see validate_event);
#   * the monitor reads only event["source_ip"];
#   * ExactCounter.update_batch(ips) is Member 3's counter, used for the exact column.
# ===========================================================================
DEFAULT_INTERVAL = 60.0        # seconds between batches in normal mode
DEMO_INTERVAL = 5.0            # seconds between batches in demo mode (--demo)
LIVE_MIN_THRESHOLD = 5         # never alert on fewer than 5 events ...
LIVE_THRESHOLD_FRACTION = 0.1  # ... and require 10% of all events so far (same rule as
                               # run_pipeline; 10% = 1/k for the default capacity k=10,
                               # and Space-Saving always tracks any IP above N/k events)
TOP_SHOWN = 5                  # rows of the candidate table printed per batch


class LiveMonitor:
    """Holds the three algorithms for the WHOLE run. They are created once in __init__
    and never recreated or reset, so counts keep accumulating from batch to batch.

    Complexity per batch of n events (d = CMS depth, k = Space-Saving capacity):
      validate        O(n)
      CMS update      O(n*d)          one hash + one counter per row per event
      Space-Saving    O(n) on hits; each eviction scans k entries -> O(n*k) worst
                      case (O(n log k) with --heap)
      Exact update    O(n) expected
      detect          O(k*d)          one CMS query per candidate
      top-k display   O(k log k)      (k <= 10, so effectively constant)
      => O(n*(d+k)) per batch worst case. With n <= 10, d = 3, k = 10 that is a few
         hundred basic operations - far below the interval, so a batch never overlaps
         the next one.
    Space: CMS O(w*d) + Space-Saving O(k) are fixed; Exact is O(u) (grows with distinct
    IPs) and exists only as the reference the approximations are compared with.
    """

    def __init__(self, width=100, depth=3, capacity=10, threshold=None,
                 use_heap=False, ground_truth=None, seed=42):
        self.cms = CountMinSketch(width, depth, seed)    # validates width/depth
        self.ss = SpaceSaving(capacity, use_heap)        # validates capacity
        self.exact = ExactCounter()
        if threshold is not None and threshold < 0:
            raise ValueError("threshold must be non-negative")
        self.fixed_threshold = threshold                 # None -> adaptive (see below)
        self.ground_truth = None if ground_truth is None else set(ground_truth)
        self.capacity = capacity
        self.batches = 0
        self.alerted = set()                             # IPs already alerted once

    def current_threshold(self):
        """Fixed value if the user gave --threshold, otherwise max(5, 10% of events so
        far). The adaptive rule stops tiny early batches (5-10 events) from flagging
        every IP: with N events a normal IP needs > 0.1*N hits to be suspicious."""
        if self.fixed_threshold is not None:
            return self.fixed_threshold
        return max(LIVE_MIN_THRESHOLD, LIVE_THRESHOLD_FRACTION * self.exact.total)

    def consistent(self):
        """True if all three algorithms have seen exactly the same number of events."""
        return self.cms.total == self.ss.processed == self.exact.total

    def process_batch(self, batch):
        """Feed ONE batch through CMS, Space-Saving and the exact counter (each event
        exactly once per algorithm), run detection, and return a result dict."""
        batch = list(batch)
        for event in batch:                  # validate EVERYTHING first: a bad event now
            validate_event(event)            # raises before any algorithm is touched
        ips = [event["source_ip"] for event in batch]

        # Which IPs are new? Must be measured BEFORE the exact counter is updated.
        first_seen = {ip for ip in ips if self.exact.count(ip) == 0}
        repeat_events = sum(1 for ip in ips if ip not in first_seen)

        for ip in ips:                       # exactly one update per algorithm per event
            self.cms.update(ip)
            self.ss.update(ip)
        self.exact.update_batch(ips)
        self.batches += 1

        threshold = self.current_threshold()
        cands = self.ss.candidates()                     # Space-Saving proposes ...
        flagged = detect(cands, self.cms, threshold)     # ... CMS decides (detector.py)
        new_alerts = [ip for ip, _ in flagged if ip not in self.alerted]
        self.alerted.update(new_alerts)
        precision = recall = None
        if self.ground_truth is not None:
            precision, recall = evaluate(flagged, self.ground_truth)
        return {
            "batch": self.batches, "batch_size": len(ips),
            "new_ips": len(first_seen), "repeat_events": repeat_events,
            "total_events": self.exact.total, "unique_ips": self.exact.distinct(),
            "threshold": threshold,
            "rows": [(ip, c, e, self.cms.estimate(ip), self.exact.count(ip))
                     for ip, c, e in top_k(cands, TOP_SHOWN)],
            "flagged": [(ip, est, self.exact.count(ip)) for ip, est in flagged],
            "new_alerts": new_alerts, "precision": precision, "recall": recall,
            "memory": {"exact_entries": self.exact.distinct(),
                       "cms_counters": self.cms.num_counters(), "ss_slots": self.capacity},
        }


def format_live_report(r, stamp):
    """Text shown after every batch."""
    bar = "-" * 62
    out = [bar,
           f"Batch {r['batch']}  [{stamp}]  +{r['batch_size']} events "
           f"({r['new_ips']} new IPs, {r['repeat_events']} events from IPs seen before)",
           f"Totals: events={r['total_events']}  unique IPs={r['unique_ips']}  "
           f"alert threshold={r['threshold']:g}", "",
           "Top IPs (approximate counts)",
           f"{'IP':<18}{'SS Count':>9}{'SS Err':>8}{'CMS Est':>9}{'Exact':>8}"]
    for ip, c, e, est, ex in r["rows"]:
        out.append(f"{ip:<18}{c:>9}{e:>8}{est:>9}{ex:>8}")
    out += ["", "Suspicious-IP alerts (CMS estimate > threshold)"]
    if r["flagged"]:
        for ip, est, ex in r["flagged"]:
            tag = "  <-- NEW ALERT" if ip in r["new_alerts"] else ""
            out.append(f"  {ip:<16} est. {est}  (exact {ex}){tag}")
    else:
        out.append("  (none)")
    if r["precision"] is not None:
        out.append(f"Precision: {r['precision']:.2f}   Recall: {r['recall']:.2f}")
    m = r["memory"]
    out.append(f"Memory: exact={m['exact_entries']} entries (grows) | "
               f"CMS={m['cms_counters']} counters | SS={m['ss_slots']} slots (fixed)")
    return "\n".join(out)


def format_live_summary(monitor):
    ok = "OK" if monitor.consistent() else "MISMATCH"
    alerts = ", ".join(sorted(monitor.alerted)) if monitor.alerted else "none"
    return "\n".join(["=" * 62, "PULSEGUARD LIVE - stopped",
                      f"Batches processed : {monitor.batches}",
                      f"Events processed  : {monitor.exact.total}",
                      f"Unique IPs seen   : {monitor.exact.distinct()}",
                      f"IPs alerted       : {alerts}",
                      f"Event counts CMS/SS/Exact agree: {ok}", "=" * 62])


def _emit(text):
    print(text, flush=True)          # flush so output appears at once, even when piped


def run_live(generator, monitor, interval, max_batches=None, sleep=time.sleep, out=_emit):
    """THE scheduling loop. Process one batch immediately, then every `interval` seconds.

    max_batches : stop by itself after this many batches (None = run until Ctrl+C).
    sleep, out  : injectable so tests can run the loop without really waiting.

    Ctrl+C (KeyboardInterrupt) is caught here: the monitor keeps its state, a summary
    is printed and the function returns normally. The interrupt almost always arrives
    during sleep(); a batch takes microseconds, and the summary's consistency line
    would show MISMATCH if one ever landed mid-batch.
    Note: the period is interval + processing time (a few ms), which is fine for a demo.
    """
    done = 0
    try:
        while max_batches is None or done < max_batches:
            result = monitor.process_batch(generator.next_batch())
            out(format_live_report(result, time.strftime("%H:%M:%S")))
            done += 1
            if max_batches is not None and done >= max_batches:
                break
            sleep(interval)
    except KeyboardInterrupt:
        out("\nCtrl+C received - stopping cleanly.")
    out(format_live_summary(monitor))
    return monitor


def _run_live_cli(args):
    """Validate the live-mode options, build generator + monitor, run the loop."""
    if args.scenario or args.input is not None or args.ips is not None:
        raise ValueError("--live/--demo cannot be combined with --scenario, --input or --ips")
    if args.demo and args.interval is not None:
        raise ValueError("use either --demo (5 s) or --interval, not both")
    if args.demo:
        interval = DEMO_INTERVAL
    else:
        interval = DEFAULT_INTERVAL if args.interval is None else args.interval
    if not math.isfinite(interval) or interval <= 0:
        raise ValueError(f"interval must be a positive number of seconds, got {interval}")
    if args.batches is not None and args.batches < 1:
        raise ValueError("--batches must be at least 1")

    generator = LiveEventGenerator(seed=args.seed, attacker_ip=args.attacker,
                                   attack_ratio=args.attack_ratio, interval_seconds=interval)
    truth = {args.attacker} if args.attack_ratio > 0 else set()
    if args.truth is not None:
        truth = set(parse_ips(args.truth))
    monitor = LiveMonitor(width=args.width, depth=args.depth, capacity=args.capacity,
                          threshold=args.threshold, use_heap=args.heap, ground_truth=truth)
    _emit(f"PulseGuard LIVE: one batch of 5-10 simulated events every {interval:g} s "
          f"(no real traffic). Press Ctrl+C to stop.")
    run_live(generator, monitor, interval, max_batches=args.batches)
    return 0


def build_parser():
    p = argparse.ArgumentParser(description="PulseGuard frequent-pattern detector")
    p.add_argument("--events", type=int, default=10000)
    p.add_argument("--attack-ratio", type=float, default=0.2)
    p.add_argument("--normal-ips", type=int, default=500)
    p.add_argument("--attacker", default="10.0.0.99")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--width", type=int, default=100)
    p.add_argument("--depth", type=int, default=3)
    p.add_argument("--capacity", type=int, default=10)
    p.add_argument("--threshold", type=float, default=None)
    p.add_argument("--heap", action="store_true", help="use heap-based Space-Saving")
    p.add_argument("--input", help="file with IPs (one per line); '-' for stdin")
    p.add_argument("--ips", help="comma-separated IPs typed on the command line")
    p.add_argument("--truth", help="comma-separated true attacker IPs (custom input)")
    p.add_argument("--scenario", action="store_true", help="run the 20-event example")
    # live simulation
    p.add_argument("--live", action="store_true",
                   help="live mode: a batch of 5-10 simulated events every --interval s (default 60)")
    p.add_argument("--demo", action="store_true", help="live mode with a 5-second interval")
    p.add_argument("--interval", type=float, default=None,
                   help="seconds between live batches (default 60)")
    p.add_argument("--batches", type=int, default=None,
                   help="live mode: stop after this many batches (default: run until Ctrl+C)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.live or args.demo:
            return _run_live_cli(args)
        if args.interval is not None or args.batches is not None:
            raise ValueError("--interval and --batches only work with --live or --demo")
        truth = None
        if args.scenario:
            ips = [SCENARIO_MAP[ch] for ch in SCENARIO_STREAM]
            params = dict(width=10, depth=3, capacity=3, threshold=8)
            truth = {SCENARIO_MAP["A"]}
        else:
            params = dict(width=args.width, depth=args.depth, capacity=args.capacity,
                          threshold=args.threshold)
            if args.input is not None:
                text = sys.stdin.read() if args.input == "-" else open(
                    args.input, encoding="utf-8").read()
                ips = parse_ips(text)
            elif args.ips is not None:
                ips = parse_ips(args.ips)
            else:
                events = generate_events(args.events, args.attacker, args.attack_ratio,
                                         args.normal_ips, args.seed)
                ips = [e["source_ip"] for e in events]
                truth = {args.attacker} if args.attack_ratio > 0 else set()
            if args.truth is not None:
                truth = set(parse_ips(args.truth))
        if not ips:
            print("No events to process (empty stream). Nothing to report.")
            return 0
        result = run_pipeline(ips, use_heap=args.heap, ground_truth=truth, **params)
        print(format_report(result))
        return 0
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

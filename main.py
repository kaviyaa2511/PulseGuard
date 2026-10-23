"""PulseGuard - memory-efficient frequent-pattern detection (CMS + Space-Saving).

Examples
  python main.py                              # simulated stream
  python main.py --scenario                   # the 20-event worked example
  python main.py --input ips.txt --threshold 3
  python main.py --ips "a,b,a,a,c" --capacity 2 --threshold 1
  type ips.txt | python main.py --input -     # read stdin
"""
import argparse
import sys
import time

from algorithms.count_min_sketch import CountMinSketch
from algorithms.space_saving import SpaceSaving
from algorithms.exact_counter import ExactCounter
from simulation.event_generator import generate_events
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
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
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

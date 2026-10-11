"""Experiment 4: updates per second.  Usage: python benchmarks/throughput.py [n_events]"""
import csv, sys, time
import numpy as np
import _path
from _path import RESULTS
from pulseguard import CountMinSketch, SpaceSaving, ExactCounter, zipf_keys

n = int(sys.argv[1]) if len(sys.argv) > 1 else 200_000
keys = zipf_keys(n, 50_000, 0.8, np.random.default_rng(0)).tolist()
makers = {
    "exact HashMap": ExactCounter,
    "Space-Saving k=1000": lambda: SpaceSaving(1000),
    "CMS plain": lambda: CountMinSketch.from_error(0.001, 0.01, conservative=False),
    "CMS conservative": lambda: CountMinSketch.from_error(0.001, 0.01, conservative=True),
}
rows = []
for name, make in makers.items():
    s = make(); t = time.perf_counter()
    for x in keys:
        s.add(x)
    rate = n / (time.perf_counter() - t)
    rows.append([name, round(rate)])
    print(f"{name:<22} {rate:>12,.0f} updates/s")
with open(f"{RESULTS}/throughput.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["structure", "updates_per_sec"]); w.writerows(rows)

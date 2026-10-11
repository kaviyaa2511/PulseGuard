"""Experiment 1: memory of exact HashMap vs Space-Saving vs CMS as the stream grows.
Usage: python benchmarks/memory.py [--big]   (--big adds 10^7 events)"""
import csv, sys
from collections import Counter
import numpy as np
import _path
from _path import RESULTS
from pulseguard import CountMinSketch, SpaceSaving, ExactCounter, zipf_keys

sizes = [10**5, 10**6] + ([10**7] if "--big" in sys.argv else [])
rows = []
print(f"{'events':>10} {'distinct':>10} {'HashMap KB':>12} {'SpaceSaving KB':>15} {'CMS KB':>8}")
for n in sizes:
    keys = zipf_keys(n, universe=n, s=0.8, rng=np.random.default_rng(0)).tolist()   # distinct keys grow with n
    ex = ExactCounter(); ex.c = Counter(keys)
    ss = SpaceSaving(k=1000)
    for x in keys[:1_000_000]:            # memory is bounded by k, so a prefix is enough
        ss.add(x)
    cms = CountMinSketch.from_error(0.001, 0.01)
    r = (n, len(ex.c), ex.memory_bytes // 1024, ss.memory_bytes // 1024, cms.memory_bytes // 1024)
    rows.append(r)
    print(f"{r[0]:>10,} {r[1]:>10,} {r[2]:>12,} {r[3]:>15,} {r[4]:>8,}")
with open(f"{RESULTS}/memory.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["events", "distinct", "hashmap_kb", "space_saving_kb", "cms_kb"]); w.writerows(rows)

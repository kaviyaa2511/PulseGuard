"""Experiment 2 and 3: CMS error across (epsilon, delta), plain vs conservative,
and relative error by frequency rank.  Usage: python benchmarks/accuracy.py [n_events]"""
import csv, sys
from collections import Counter
import numpy as np
import _path
from _path import RESULTS
from pulseguard import CountMinSketch, zipf_keys

n = int(sys.argv[1]) if len(sys.argv) > 1 else 300_000
keys = zipf_keys(n, 50_000, 0.8, np.random.default_rng(0)).tolist()
truth = Counter(keys)
ranked = [k for k, _ in truth.most_common()]
thr = 0.005 * n                                  # "heavy" means >= 0.5% of the stream
light = [k for k in ranked if truth[k] < thr]

print(f"n={n:,}, distinct={len(truth):,}, heavy threshold={thr:.0f}")
print(f"{'eps':>6} {'variant':>12} {'KB':>6} {'mean over':>10} {'bound eps*N':>12} {'viol %':>7} {'top100 rel.err':>15} {'FP rate':>8}")
rows, by_rank = [], {}
for eps in (0.01, 0.003, 0.001):
    for cons in (False, True):
        cms = CountMinSketch.from_error(eps, 0.01, conservative=cons, seed=1)
        for x in keys:
            cms.add(x)
        over = [cms.query(k) - truth[k] for k in ranked]
        bound = cms.error_bound()
        viol = 100 * sum(o > bound for o in over) / len(over)
        rel = np.mean([over[i] / truth[ranked[i]] for i in range(100)])
        fp = sum(cms.query(k) >= thr for k in light) / len(light)
        name = "conservative" if cons else "plain"
        print(f"{eps:>6} {name:>12} {cms.memory_bytes//1024:>6} {np.mean(over):>10.1f} {bound:>12.0f} {viol:>7.2f} {rel:>15.4f} {fp:>8.4f}")
        rows.append([eps, name, cms.memory_bytes // 1024, np.mean(over), bound, viol, rel, fp])
        if eps == 0.003:
            by_rank[name] = [np.mean([over[i] / truth[ranked[i]] for i in range(lo, min(hi, len(ranked)))])
                             for lo, hi in [(0, 10), (10, 100), (100, 1000), (1000, 10000), (10000, 50000)]]
with open(f"{RESULTS}/accuracy.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["epsilon", "variant", "kb", "mean_overestimate", "bound", "violation_pct", "top100_rel_err", "fp_rate"])
    w.writerows(rows)

try:
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    labels = ["1-10", "11-100", "101-1k", "1k-10k", "10k-50k"]
    for name, vals in by_rank.items():
        plt.plot(labels, vals, marker="o", label=name)
    plt.yscale("log"); plt.xlabel("frequency rank"); plt.ylabel("mean relative error")
    plt.title("CMS relative error by key rank (eps=0.003)"); plt.legend(); plt.tight_layout()
    plt.savefig(f"{RESULTS}/error_by_rank.png", dpi=150)
    print("saved results/error_by_rank.png")
except ImportError:
    pass

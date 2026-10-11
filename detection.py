"""Experiments 5 and 6: detection quality and window sensitivity.  Usage: python benchmarks/detection.py"""
import csv
import _path
from _path import RESULTS
from pulseguard import PulseGuard, Attack, generate, score

N = 400_000
attacks = [Attack("volumetric", 100_000, 50_000, 0.05), Attack("distributed", 200_000, 50_000, 0.06),
           Attack("scan", 300_000, 50_000, 0.0125)]
packets, truth = generate(N, attacks, seed=1)


def run(slice_size, **kw):
    pg = PulseGuard(slice_size=slice_size, **kw)
    return score(pg.run(packets), truth, slice_size)


rows = []
print("Detection quality (slice=10,000, flag threshold = 200 packets per slice).")
print("eps*N per slice is the worst-case CMS overshoot; safe flagging subtracts it before comparing.")
print(f"{'config':<34} {'precision':>9} {'recall':>7} {'false alarms':>13} {'delay':>6}")
for eps in (0.03, 0.02, 0.01, 0.001):
    for label, kw in [("plain,        no safe", dict(conservative=False, safe=False)),
                      ("conservative, no safe", dict(conservative=True, safe=False)),
                      ("conservative, safe",    dict(conservative=True, safe=True))]:
        r = run(10_000, epsilon=eps, **kw)
        name = f"eps={eps:<6} {label}"
        rows.append(["quality", name, *r.values()])
        print(f"{name:<34} {r['precision']:>9.2f} {r['recall']:>7.2f} {r['false_alarms']:>13} {r['mean_delay_slices']:>6.1f}")

print("\nWindow sensitivity (conservative, safe): delay is measured in slices, so also shown in packets")
print(f"{'slice size':>10} {'precision':>9} {'recall':>7} {'delay (slices)':>15} {'delay (packets)':>16}")
for s in (5_000, 10_000, 20_000, 40_000):
    r = run(s)
    d = r["mean_delay_slices"]
    rows.append(["window", s, *r.values()])
    print(f"{s:>10,} {r['precision']:>9.2f} {r['recall']:>7.2f} {d:>15.1f} {d * s:>16,.0f}")
with open(f"{RESULTS}/detection.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["experiment", "config", "precision", "recall", "false_alarms", "mean_delay_slices"]); w.writerows(rows)

"""PulseGuard walkthrough. Run:  python demo.py
Each step prints what the data structure is doing and why the next step exists."""
import time
from pulseguard import (CountMinSketch, ExactCounter, SpaceSaving, PulseGuard,
                        Attack, generate, score)

N, SLICE = 300_000, 10_000
attacks = [Attack("volumetric", 90_000, 40_000, 0.08),
           Attack("distributed", 150_000, 40_000, 0.10),
           Attack("scan", 210_000, 40_000, 0.015)]


def step(n, title):
    print(f"\n=== Step {n}: {title} " + "=" * max(0, 52 - len(title)))


step(1, "A packet stream with hidden attacks")
packets, truth = generate(N, attacks, seed=1)
print(f"{N:,} packets. Ground truth (kept secret from the detector):")
for kind, key, start in truth:
    print(f"  {kind:<12} key={key}  starts at packet {start:,}")

step(2, "Exact counting works, but memory follows distinct keys")
exact = ExactCounter()
for src, _, _ in packets:
    exact.add(src)
print(f"distinct sources: {len(exact.c):,}   exact memory: {exact.memory_bytes/1024:,.0f} KB")
print("A spoofed-source flood adds distinct keys, so this number grows when we can least afford it.")

step(3, "Count-Min Sketch: fixed memory, bounded error")
cms = CountMinSketch.from_error(epsilon=0.001, delta=0.01, conservative=False, seed=7)
for src, _, _ in packets:
    cms.add(src)
print(f"table {cms.d} x {cms.w}  ->  {cms.memory_bytes/1024:,.0f} KB, whatever the traffic")
top = exact.top(3)
print("top sources, true vs estimate (estimate never lower):")
for key, true in top:
    print(f"  src {key:>6}: true={true:>6,}  est={cms.query(key):>6,}")
print(f"guaranteed overshoot <= eps*N = {cms.error_bound():.0f} with probability >= 99%")

step(4, "Conservative update shrinks the overestimate")
cons = CountMinSketch.from_error(0.001, 0.01, conservative=True, seed=7)
for src, _, _ in packets:
    cons.add(src)
sample = [k for k, _ in exact.c.most_common(2000)][1000:2000]
err = lambda s: sum(s.query(k) - exact.query(k) for k in sample) / len(sample)
print(f"mean overestimate on mid-frequency keys: plain={err(cms):.2f}  conservative={err(cons):.2f}")

step(5, "Space-Saving as a baseline (it lists top-k, CMS alone cannot)")
ss = SpaceSaving(k=500)
for src, _, _ in packets:
    ss.add(src)
print(f"Space-Saving top 3: {ss.top(3)}   memory {ss.memory_bytes/1024:,.0f} KB, error <= N/k = {ss.error_bound():.0f}")
print("CMS fix: a small candidate set. Any key whose estimate crosses phi*slice_size is remembered.")

step(6, "Time slices and the surge check")
print(f"traffic is cut into slices of {SLICE:,} packets; each slice gets its own sketch.")
print("A key is flagged only if it is frequent AND its newest slice is >= 5x its older slices.")
print("Steady heavy hitters (popular servers) are big but not surging, so they pass.")

step(7, "Run PulseGuard")
t = time.time()
pg = PulseGuard(slice_size=SLICE)
alerts = pg.run(packets)
print(f"processed in {time.time()-t:.1f}s, sketch memory {pg.memory_bytes/1024:,.0f} KB")
for slice_idx, kind, key, est, surge in alerts:
    print(f"  ALERT slice {slice_idx:>2}  {kind:<12} key={key}  est={est}  surge x{surge}")

step(8, "Score against ground truth")
for k, v in score(alerts, truth, SLICE).items():
    print(f"  {k:<18} {v}")

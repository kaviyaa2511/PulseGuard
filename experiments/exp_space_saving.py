"""K's experiment: capacity vs quality, and scan vs heap timing.
python -m experiments.exp_space_saving"""
import time
from algorithms.space_saving import SpaceSaving
from algorithms.exact_counter import ExactCounter
from simulation.event_generator import generate_events
from experiments.common import save_table

ips = [e["source_ip"] for e in generate_events(20000, num_normal_ips=2000, seed=1)]
exact = ExactCounter()
for ip in ips:
    exact.update(ip)
top_normal = sorted((n for ip, n in exact.items().items() if ip != "10.0.0.99"), reverse=True)

rows = []
for k in (5, 10, 20, 50):
    s = SpaceSaving(k)
    for ip in ips:
        s.update(ip)
    cands = s.candidates()
    kept = any(c[0] == "10.0.0.99" for c in cands)
    max_err = max(c[2] for c in cands)
    rows.append((k, "yes" if kept else "NO", len(cands), max_err))
save_table("ss_capacity", "Space-Saving: capacity vs attacker retention",
           ["capacity k", "attacker kept", "slots used", "max error bound"], rows)

# worst case for eviction: almost every event is a new IP
distinct = [f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}" for i in range(20000)]
rows = []
for k in (10, 100, 1000):
    times = {}
    for heap in (False, True):
        s = SpaceSaving(k, use_heap=heap)
        t = time.perf_counter()
        for ip in distinct:
            s.update(ip)
        times[heap] = time.perf_counter() - t
    rows.append((k, f"{times[False]:.3f}", f"{times[True]:.3f}",
                 f"{times[False] / times[True]:.1f}x"))
save_table("ss_scan_vs_heap", "Scan vs heap eviction (20000 distinct IPs, seconds)",
           ["capacity k", "scan", "heap", "scan/heap"], rows)

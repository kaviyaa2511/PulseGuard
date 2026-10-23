"""Y's experiment: CMS error vs width and depth.   python -m experiments.exp_cms"""
from algorithms.count_min_sketch import CountMinSketch
from algorithms.exact_counter import ExactCounter
from simulation.event_generator import generate_events
from experiments.common import save_table

ips = [e["source_ip"] for e in generate_events(20000, num_normal_ips=2000, seed=1)]
exact = ExactCounter()
for ip in ips:
    exact.update(ip)
truth = exact.items()

rows = []
for w in (50, 100, 200):
    for d in (2, 3, 5):
        c = CountMinSketch(w, d)
        for ip in ips:
            c.update(ip)
        errs = [c.estimate(ip) - n for ip, n in truth.items()]
        assert min(errs) >= 0  # never underestimates
        rows.append((w, d, c.num_counters(), f"{sum(errs)/len(errs):.1f}", max(errs)))
save_table("cms_error", f"CMS error vs exact ({len(ips)} events, {len(truth)} distinct IPs)",
           ["width", "depth", "counters", "avg overestimate", "max overestimate"], rows)

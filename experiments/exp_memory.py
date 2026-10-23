"""M's experiment: memory and time as distinct IPs grow.  python -m experiments.exp_memory
Memory is measured with tracemalloc (bytes allocated by the structure). The IP strings
are created before tracing and shared with the dict, so the exact counter's true
footprint is somewhat larger than reported."""
import time
import tracemalloc
from algorithms.count_min_sketch import CountMinSketch
from algorithms.space_saving import SpaceSaving
from algorithms.exact_counter import ExactCounter
from experiments.common import save_table

rows = []
for u in (1000, 10000, 100000, 500000):
    ips = [f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}" for i in range(u)]
    line = [u]
    for make in (lambda: ExactCounter(), lambda: CountMinSketch(100, 3), lambda: SpaceSaving(10)):
        tracemalloc.start()
        s = make()
        t = time.perf_counter()
        for ip in ips:
            s.update(ip)
        elapsed = time.perf_counter() - t
        current, _ = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        line += [f"{current / 1024:.1f}", f"{elapsed:.2f}"]
    rows.append(line)
save_table("memory_growth", "Memory (KiB) and time (s) as distinct IPs grow (each IP seen once)",
           ["distinct IPs", "Exact KiB", "Exact s", "CMS KiB", "CMS s", "SS KiB", "SS s"], rows)

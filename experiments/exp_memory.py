"""M's experiment: memory and time as distinct IPs grow.  python -m experiments.exp_memory

Table 1 (original): every IP is seen exactly once, so distinct IPs = events.
Table 2 (NEW, live simulation): the same three structures are fed batch after batch by
LiveEventGenerator and measured after 10, 100, 1000 and 10000 batches. IPs now REPEAT,
so distinct IPs grow more slowly than events, but they still never stop growing.

Memory is measured with tracemalloc (bytes allocated by the structure). The IP strings
are created before tracing and shared with the dict, so the exact counter's true
footprint is somewhat larger than reported.

MEMORY TRADE-OFF (what the tables are meant to show)
  Exact counter : O(u) space, one dict entry per distinct IP  -> grows without bound
                  in a long-running monitor, but answers are exact.
  Count-Min     : O(w*d) space, fixed at creation              -> bounded; answers may be
                  too high by at most eps*N (w = ceil(e/eps), d = ceil(ln(1/delta))).
  Space-Saving  : O(k) space, fixed at creation                -> bounded; keeps only the
                  k heaviest candidates.
  "Bounded", not perfectly flat: the NUMBER of counters/slots never changes, but Python
  allocates larger int objects once a count passes 256, so the measured KiB creeps up a
  little. The exact counter's growth comes from new dict entries, which is unbounded.
  Time: the dict is the fastest per update (one hash lookup). Count-Min does d md5
  hashes per update, so it is SLOWER but uses far less memory when u is large.
"""
import os
import time
import tracemalloc
from algorithms.count_min_sketch import CountMinSketch
from algorithms.space_saving import SpaceSaving
from algorithms.exact_counter import ExactCounter
from experiments.common import RESULTS, save_table
from simulation.event_generator import LiveEventGenerator

# ---------------------------------------------------------------- table 1 (original)
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

# ---------------------------------------------------------------- table 2 (live batches)
CHECKPOINTS = (10, 100, 1000, 10000)
gen = LiveEventGenerator(seed=1)
# Generate every batch BEFORE tracing so only the three structures are measured.
batches = [[e["source_ip"] for e in gen.next_batch()] for _ in range(max(CHECKPOINTS))]

kib = {}                                     # (structure name, checkpoint) -> KiB
for name, make in (("exact", ExactCounter), ("cms", lambda: CountMinSketch(100, 3)),
                   ("ss", lambda: SpaceSaving(10))):
    tracemalloc.start()
    structure = make()
    for batch_no, ips in enumerate(batches, start=1):
        for ip in ips:                       # same batch, one event at a time
            structure.update(ip)
        if batch_no in CHECKPOINTS:
            kib[(name, batch_no)] = tracemalloc.get_traced_memory()[0] / 1024
    tracemalloc.stop()

live_rows, events, seen = [], 0, set()
done = 0
for c in CHECKPOINTS:
    for ips in batches[done:c]:
        events += len(ips)
        seen.update(ips)
    done = c
    live_rows.append([c, events, len(seen), f"{kib[('exact', c)]:.1f}",
                      f"{kib[('cms', c)]:.1f}", f"{kib[('ss', c)]:.1f}"])

# save_table() overwrites its file, so table 2 is appended to the same markdown file
# (same format) to keep everything in results/memory_growth.md.
title2 = "Live simulation: memory (KiB) after N batches of 5-10 events (CMS 100x3, SS k=10)"
headers2 = ["batches", "events", "distinct IPs", "Exact KiB", "CMS KiB", "SS KiB"]
text = "\n".join([f"\n### {title2}", "", "| " + " | ".join(headers2) + " |",
                  "|" + "|".join("---" for _ in headers2) + "|"]
                 + ["| " + " | ".join(str(c) for c in r) + " |" for r in live_rows]) + "\n"
text += ("\nReading the tables: the exact counter gains one entry per new distinct IP, so its "
         "memory keeps growing for as long as the monitor runs. CMS and Space-Saving keep a "
         "fixed number of counters/slots; their small KiB increase is Python allocating "
         "larger int objects once counts exceed 256, not extra entries. The price of the "
         "fixed memory is accuracy (CMS can over-estimate) and speed (CMS does d md5 "
         "hashes per update).\n")
with open(os.path.join(RESULTS, "memory_growth.md"), "a", encoding="utf-8") as f:
    f.write(text)
print(text)

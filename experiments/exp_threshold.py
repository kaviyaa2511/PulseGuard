"""R's experiment: threshold vs precision/recall.  python -m experiments.exp_threshold"""
from algorithms.count_min_sketch import CountMinSketch
from algorithms.space_saving import SpaceSaving
from detection.detector import detect, evaluate
from simulation.event_generator import generate_events
from experiments.common import save_table

ips = [e["source_ip"] for e in generate_events(10000, num_normal_ips=500, seed=1)]
truth = {"10.0.0.99"}
rows = []
for width in (20, 100, 2000):
    cms, ss = CountMinSketch(width, 3), SpaceSaving(10)
    for ip in ips:
        cms.update(ip); ss.update(ip)
    for thr in (50, 100, 200, 400, 1000, 3000):
        flagged = detect(ss.candidates(), cms, thr)
        p, r = evaluate(flagged, truth)
        rows.append((width, thr, len(flagged), f"{p:.2f}", f"{r:.2f}"))
save_table("threshold_sweep", "Threshold vs precision/recall (10000 events, attacker ~20%)",
           ["CMS width", "threshold", "flagged", "precision", "recall"], rows)

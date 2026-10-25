# PulseGuard
**Memory-efficient detection of frequent network patterns using Count-Min Sketch and Space-Saving**

A DSA case study in pure Python (standard library only). It processes a stream of *simulated* network events and finds heavy-hitter source IPs using fixed-size data structures, then compares them against an exact dictionary counter.
A flag means "frequent enough to investigate", **not** a confirmed attack.

## Problem statement
An exact counter (one dictionary entry per distinct IP) is accurate, but its memory grows with the number of distinct IPs. PulseGuard processes events one at a time, estimates frequencies in bounded memory (Count-Min Sketch), tracks only `k` frequent candidates (Space-Saving), flags candidates above a threshold, and measures accuracy, time and memory against exact counts.

## Quick start
```bash
python -m unittest                     # 93 tests (none waits for real time)
python main.py --demo                  # LIVE simulation, a batch every 5 s (Ctrl+C to stop)
python main.py --live                  # LIVE simulation, a batch every 60 s
python main.py                         # simulated stream (10,000 events)
python main.py --scenario              # the 20-event worked example
python main.py --heap --capacity 20    # heap-based Space-Saving
python main.py --input sample_input.txt --threshold 2 --truth 10.0.0.99
python main.py --ips "a,b,a,a,c" --capacity 2 --threshold 1
cat ips.txt | python main.py --input - # read stdin
python -m experiments.exp_cms          # also exp_space_saving, exp_memory, exp_threshold
```
Options: `--events --attack-ratio --normal-ips --attacker --seed --width --depth --capacity --threshold --heap --input --ips --truth --scenario --live --demo --interval --batches`. If `--threshold` is omitted it defaults to 10% of the stream length (live mode: see below). Invalid parameters print a clear `Error:` and exit with code 2.

## Structure and owners
| File | What |
|---|---|---|
| `algorithms/count_min_sketch.py` | Count-Min Sketch |
| `algorithms/space_saving.py` | Space-Saving (scan + heap) |
| `algorithms/exact_counter.py`, `simulation/event_generator.py` | Exact counter, seeded event generator |
| `detection/detector.py`, `main.py` | Detector, top-k, precision/recall, driver |
| `experiments/exp_*.py` | One experiment each |
| `tests/` | `test_cms`, `test_ss`, `test_exact`+`test_generator`, `test_detector`+`test_integration`, `test_live` |

Live simulation: Member 3 = `LiveEventGenerator`, `validate_event`, `ExactCounter.update_batch`, `exp_memory`, `results/memory_growth.md`, `test_generator`, `test_exact`. Member 4 = `LiveMonitor`/`run_live` in `main.py`, `tests/test_live.py`, this README section.

## Live simulation (new)
A batch of 5-10 **simulated** events is generated every `interval` seconds (60 normally, 5 for the demo). Each batch mixes new IPs with IPs seen in earlier batches. The same batch goes through the Exact Counter, Count-Min Sketch and Space-Saving; detection runs after every batch. The three structures are created once and never reset, so counts accumulate for the whole run. No real network traffic is captured and nothing beyond the standard library is used.

```bash
python main.py --live                  # normal mode: one batch every 60 seconds
python main.py --demo                  # demo mode:   one batch every 5 seconds
python main.py --live --interval 10    # any positive interval
python main.py --demo --batches 4      # stop by itself after 4 batches (about 15 s)
python main.py --demo --seed 7 --heap  # other seed / heap-based Space-Saving
```
Press **Ctrl+C** to stop: the loop finishes, prints a summary and exits with code 0. `--live/--demo` cannot be combined with `--scenario/--input/--ips`; `--interval` must be a positive finite number; `--batches` must be at least 1 (all print `Error:` and exit with code 2).

**Division of work:** Member 3 owns the data source (`simulation/event_generator.py::LiveEventGenerator`, `validate_event`, `ExactCounter.update_batch`); Member 4 owns the integration (`main.py::LiveMonitor`, `run_live`, `format_live_report`) and uses `detect()` / `evaluate()` / `top_k()` from `detection/detector.py` unchanged. The contract between them: `next_batch()` returns a list of event dicts; the pipeline validates every event, then reads only `event["source_ip"]`.

```
LiveEventGenerator.next_batch()   (Member 3)     every `interval` seconds (run_live: sleep)
   -> validate_event() on ALL events first (a bad event rejects the whole batch, nothing counted)
   -> for each IP: CountMinSketch.update, SpaceSaving.update      (exactly once each)
   -> ExactCounter.update_batch(ips)
   -> SpaceSaving.candidates() -> detect(): CMS estimate > threshold -> alerts -> evaluate()
   -> print totals, unique IPs, approximate counts, alerts
```

**Alert threshold in live mode.** `--threshold N` fixes it. Without it the threshold is `max(5, 10% of events so far)`: the 10% rule matches `run_pipeline`, and 10% = 1/k for the default capacity k = 10, so Space-Saving is guaranteed to be tracking any IP above that share. The floor of 5 stops the first tiny batches from flagging everything. Early in a run the IP pool is small, so a normal IP can briefly cross the threshold (see batch 8 below); the threshold rises with the stream and the false alert disappears.

**Complexity (n events per batch, d = CMS depth, k = Space-Saving capacity, u = distinct IPs, w = CMS width)**

| Step | Time per batch | Space |
|---|---|---|
| Generate batch | O(n) (n <= 10, so O(1)) | O(n); generator remembers all emitted IPs, O(u) (it is the traffic source) |
| Validate | O(n) | O(1) |
| CMS update | O(n*d) | O(w*d) fixed |
| Space-Saving update | O(n) hits, O(n*k) worst case with evictions (O(n log k) with `--heap`) | O(k) fixed |
| Exact update | O(n) expected | O(u), grows |
| Detect + top rows | O(k*d) + O(k log k) | O(k) |
| **Whole batch** | **O(n*(d+k))** = a few hundred operations for n=10, d=3, k=10 | monitoring structures O(w*d + k); exact reference O(u) |

Over T batches the total work is O(T*n*(d+k)), linear in the number of events. Accuracy: with `w = ceil(e/eps)`, `d = ceil(ln(1/delta))` the CMS estimate is at most `eps*N` too high with probability at least `1 - delta` (default 100x3: eps ~ 0.027, delta ~ 0.05; N = events so far), and never too low. Space-Saving keeps `count - error <= true <= count`.

**Sample output** (real run, `python main.py --live --interval 0.001 --batches 15`, default seed; the IPs and counts are identical at any interval, only the clock times differ). Batches 4, 5 and 8 shown. Batch 5 raises the first alert; in batch 8 note `172.16.0.17`: Space-Saving over-counts it (5, error 4) while the CMS estimate (1) matches the exact count; and `172.16.0.6` is a brief false alert.
```
--------------------------------------------------------------
Batch 4  [11:55:25]  +7 events (4 new IPs, 3 events from IPs seen before)
Totals: events=23  unique IPs=11  alert threshold=5

Top IPs (approximate counts)
IP                 SS Count  SS Err  CMS Est   Exact
10.0.0.99                 5       0        5       5
172.16.0.3                4       0        4       4
172.16.0.1                3       0        3       3
172.16.0.4                3       0        3       3
172.16.0.2                2       0        2       2

Suspicious-IP alerts (CMS estimate > threshold)
  (none)
Precision: 1.00   Recall: 0.00
Memory: exact=11 entries (grows) | CMS=300 counters | SS=10 slots (fixed)
--------------------------------------------------------------
Batch 5  [11:55:25]  +7 events (1 new IPs, 6 events from IPs seen before)
Totals: events=30  unique IPs=12  alert threshold=5

Top IPs (approximate counts)
IP                 SS Count  SS Err  CMS Est   Exact
10.0.0.99                 6       0        6       6
172.16.0.3                4       0        4       4
172.16.0.1                3       0        3       3
172.16.0.4                3       0        3       3
172.16.0.8                3       0        3       3

Suspicious-IP alerts (CMS estimate > threshold)
  10.0.0.99        est. 6  (exact 6)  <-- NEW ALERT
Precision: 1.00   Recall: 1.00
Memory: exact=12 entries (grows) | CMS=300 counters | SS=10 slots (fixed)
--------------------------------------------------------------
Batch 8  [11:55:25]  +10 events (4 new IPs, 6 events from IPs seen before)
Totals: events=55  unique IPs=20  alert threshold=5.5

Top IPs (approximate counts)
IP                 SS Count  SS Err  CMS Est   Exact
10.0.0.99                10       0       10      10
172.16.0.6                7       3        6       6
172.16.0.1                5       3        5       5
172.16.0.8                5       3        5       5
172.16.0.17               5       4        1       1

Suspicious-IP alerts (CMS estimate > threshold)
  10.0.0.99        est. 10  (exact 10)
  172.16.0.6       est. 6  (exact 6)  <-- NEW ALERT
Precision: 0.50   Recall: 1.00
Memory: exact=20 entries (grows) | CMS=300 counters | SS=10 slots (fixed)
```
"Precision/Recall" are measured against the known simulated attacker (`10.0.0.99`); precision is reported as 1.00 when nothing is flagged (the convention in `evaluate()`).

**Demo script (about 2 minutes):** run `python main.py --demo`; point out that batches arrive every 5 s, that "unique IPs" and "events" only ever grow, that Space-Saving and CMS counts are close to Exact while using fixed memory, and that the attacker is alerted once its count passes the threshold. Press Ctrl+C and show the summary line `Event counts CMS/SS/Exact agree: OK` (all three algorithms processed the same number of events).

## Data flow
```
generate_events / file / --ips  ->  one IP at a time
        |-> CountMinSketch.update   (fixed w x d counters)
        |-> SpaceSaving.update      (k candidates: count, error)
        |-> ExactCounter.update     (reference, O(u))
SpaceSaving.candidates() -> detect(): CMS estimate > threshold -> flagged -> evaluate() vs ground truth
```

## Data structure justification
| Need | Chosen | Rejected alternatives and why |
|---|---|---|
| Count every IP in fixed memory | Count-Min Sketch (2D array) | Dict: O(u) memory. Sorted array: O(n) insert. BST: O(log u) time and O(u) space. |
| Know *which* IPs are heavy | Space-Saving | CMS cannot list items. Keep-all-and-sort needs O(u) memory. |
| Ground truth | Hash map | Direct-address array: IPs are sparse strings. |

Price paid: CMS may overestimate; Space-Saving counts are upper bounds with a recorded error.

## Implementation choices
- **CMS: array-based** (list of lists): O(1) indexing, fixed size, no pointers. Seeded `md5` rather than built-in `hash()` (randomised per run, so irreproducible). Trade-off: md5 is slower than a dict update (see experiment).
- **Space-Saving: dict + min search.** Scan is simple (O(k) eviction). Heap with lazy deletion gives O(log k) amortised eviction; the heap is rebuilt when it exceeds `4k+4` entries so it stays O(k). The textbook Stream-Summary (doubly linked buckets) gives O(1) but is pointer-heavy and error-prone, so it was not built. Both versions break ties by earliest insertion and give identical output (tested).
- **Exact counter: dict**, expected O(1).
- **Detector:** `sorted` O(n log n) vs `heapq.nlargest` O(n log k) for top-k; for small k the difference is negligible.

## Complexity
`N` events, `u` distinct IPs, `w` width, `d` depth, `k` capacity.
| Operation | Time | Space |
|---|---|---|
| CMS update / estimate | O(d) | O(wd) total |
| Exact update / query | O(1) expected (O(u) worst case) | O(u) |
| Space-Saving hit | O(1) | O(k) |
| Space-Saving eviction, scan / heap | O(k) / O(log k) amortised | O(k) |
| Whole stream: CMS / SS-scan / SS-heap / exact | O(Nd) / O(Nk) / O(N log k) / O(N) expected | |
| detect (k candidates, each a CMS query) | O(kd) | O(k) |
| top_k: sort / heap | O(k log k) / O(k log m) | |

Why: each CMS operation does exactly one hash and one array access per row, d rows. Space-Saving does one dict probe per event, plus a minimum search only on eviction.
Guarantee: with `w = ceil(e/eps)`, `d = ceil(ln(1/delta))`, estimate <= true + eps*N with probability >= 1 - delta. Space-Saving: `count - error <= true <= count`, and the counts always sum to N.

## Edge cases handled (all covered by tests)
empty stream, single event, all one IP, all distinct IPs, stream shorter than `k`, threshold 0, threshold above every count, blank/extra-space/comment lines, width 1, capacity 1, invalid width/depth/capacity/threshold, missing input file.

## Sample output (`python main.py --scenario`, real run)
```
Frequent Candidates (from Space-Saving)
IP                 SS Count  SS Err  CMS Est   Exact
10.0.0.99                10       0       11      10
192.168.1.15              5       4        2       2
192.168.1.12              5       4        3       3

Flagged for Investigation (CMS estimate > threshold)
10.0.0.99          est. frequency 11  (exact 10)
Precision: 1.00   Recall: 1.00
```
More outputs and all experiment tables are in `results/`.

## Observed results (from `results/`, run on one machine; timings vary)
- **CMS error** falls as width grows (20,000 events, 2,000 IPs: avg overestimate 293 at w=50,d=2 down to 51 at w=200,d=5). It never underestimated in any run.
- **Space-Saving** kept the attacker at every capacity tested (5 to 50). Error bounds shrink as `k` grows. Scan vs heap on an all-distinct stream: 1.9x faster at k=10, 80x at k=1000.
- **Memory:** exact counter allocated ~15 MB at 500,000 distinct IPs; CMS stayed at ~12 KiB and Space-Saving at ~2 KiB. CMS counters are bounded, not literally constant, because Python allocates larger int objects as counts exceed 256. CMS was *slower* than the dictionary in time (md5 hashing), so its advantage is memory, not speed.
- **Threshold:** with a narrow sketch (width 20) many normal IPs were falsely flagged at low thresholds (precision 0.10); with width 2000 only the attacker was flagged. A threshold above the attacker's count gives recall 0.

## Limitations
Simulated data only; tracks source IP only (no time windows, so it finds *frequent* patterns, not "emerging" ones); tracemalloc figures exclude the shared IP strings; not an intrusion-detection product.

## Viva quick answers
- *Why min across rows?* Collisions only add to counters, so the smallest is closest to the truth and still >= it.
- *Why start the new Space-Saving item at min+1?* The evicted item may have had up to `min` occurrences the new item could inherit; this keeps the counts an upper bound and the sum equal to N.
- *Why combine both?* CMS cannot list items; Space-Saving's counts are loose. Space-Saving proposes, CMS refines.
- *Why does a flag not prove an attack?* Busy legitimate sources are also frequent.

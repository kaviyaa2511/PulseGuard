# PulseGuard
**Memory-efficient detection of frequent network patterns using Count-Min Sketch and Space-Saving**

A DSA case study in pure Python (standard library only). It processes a stream of *simulated* network events and finds heavy-hitter source IPs using fixed-size data structures, then compares them against an exact dictionary counter.
A flag means "frequent enough to investigate", **not** a confirmed attack.

## Problem statement
An exact counter (one dictionary entry per distinct IP) is accurate, but its memory grows with the number of distinct IPs. PulseGuard processes events one at a time, estimates frequencies in bounded memory (Count-Min Sketch), tracks only `k` frequent candidates (Space-Saving), flags candidates above a threshold, and measures accuracy, time and memory against exact counts.

## Quick start
```bash
python -m unittest                     # 42 tests
python main.py                         # simulated stream (10,000 events)
python main.py --scenario              # the 20-event worked example
python main.py --heap --capacity 20    # heap-based Space-Saving
python main.py --input sample_input.txt --threshold 2 --truth 10.0.0.99
python main.py --ips "a,b,a,a,c" --capacity 2 --threshold 1
cat ips.txt | python main.py --input - # read stdin
python -m experiments.exp_cms          # also exp_space_saving, exp_memory, exp_threshold
```
Options: `--events --attack-ratio --normal-ips --attacker --seed --width --depth --capacity --threshold --heap --input --ips --truth --scenario`. If `--threshold` is omitted it defaults to 10% of the stream length. Invalid parameters print a clear `Error:` and exit with code 2.

## Structure and owners
| File | What | Owner |
|---|---|---|
| `algorithms/count_min_sketch.py` | Count-Min Sketch | Y |
| `algorithms/space_saving.py` | Space-Saving (scan + heap) | K |
| `algorithms/exact_counter.py`, `simulation/event_generator.py` | Exact counter, seeded event generator | M |
| `detection/detector.py`, `main.py` | Detector, top-k, precision/recall, driver | R |
| `experiments/exp_*.py` | One experiment each (Y: cms, K: space_saving, M: memory, R: threshold) | each |
| `tests/` | `test_cms`, `test_ss`, `test_exact`+`test_generator`, `test_detector`+`test_integration` | each |

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

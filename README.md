# PulseGuard

**Memory-efficient streaming detection of emerging network threat patterns using Count-Min Sketch**

PulseGuard watches a stream of network packets and flags sources or targets whose traffic is surging, using a fixed amount of memory no matter how many distinct IP addresses appear. The core data structure is the Count-Min Sketch (CMS). An exact hash map and the Space-Saving algorithm are implemented as baselines so the trade-offs can be measured instead of just claimed.

---

## 1. Problem statement

A busy network link can carry millions of packets per minute from hundreds of thousands of distinct IP addresses. Attacks show up as a few keys suddenly becoming very frequent:

| Pattern | What it looks like | Key we count |
|---|---|---|
| Volumetric flood | One source sends packets at a very high rate | source IP |
| Distributed flood (DDoS) | Many sources hit one target | destination IP |
| Port scan | One source sends many half-open (SYN-only) connection attempts | source IP, SYN-only packets |

The task: detect these patterns **online**, in a **single pass**, with **memory that does not grow with the number of distinct IPs**, and with a known bound on how wrong the answer can be.

## 2. Why exact counting fails

The obvious solution is a `HashMap<IP, count>`. It is exact, but its memory grows linearly with the number of distinct keys. Under a spoofed-source flood the number of distinct keys is exactly what the attacker inflates, so the detector can run out of memory at the moment it is needed most.

CMS trades a small, bounded error for constant memory.

## 3. Count-Min Sketch in brief

A CMS is a `d x w` table of counters with `d` independent hash functions, one per row.

- **Update(x):** for each row `r`, increment `table[r][h_r(x)]`.
- **Query(x):** return the minimum of `table[r][h_r(x)]` over all rows.

Collisions can only add to a counter, so the estimate never undercounts. With

```
w = ceil(e / epsilon)        d = ceil(ln(1 / delta))
```

the guarantee is

```
true_count(x)  <=  estimate(x)  <=  true_count(x) + epsilon * N     with probability >= 1 - delta
```

where `N` is the total number of events seen. Example: `epsilon = 0.001`, `delta = 0.01` gives `w = 2719`, `d = 5`, so 13,595 counters (about 54 KB with 4-byte counters) whether the stream has a thousand keys or a hundred million.

Update and query both cost `O(d)`.

## 4. Design

```
packet stream
     |
     v
 parse (src, dst, flags)
     |
     +--> CMS keyed by src IP        -> volumetric flood
     +--> CMS keyed by dst IP        -> distributed flood
     +--> CMS keyed by src (SYN-only)-> port scan
                |
                v
     ring of time-sliced sketches  ->  candidate heap (top-k)  ->  anomaly check  ->  alerts
```

### 4.1 Fixing the known weaknesses of CMS

Plain CMS has four weak points. Each one has a specific fix in this project, and each fix is measured in the experiments.

| Weakness | Fix used in PulseGuard |
|---|---|
| Cannot list keys, only answer "how often was X seen?" | A small min-heap of at most `k` candidate keys. After every update, if a key's estimate is at least `phi * N_window`, it enters the heap. The smallest entry is evicted when the heap is full. |
| Overestimates because of collisions | **Conservative update:** compute `m = min over rows + 1`, then raise only the counters that are below `m`. **Safe flagging:** alert only if `estimate - epsilon * N > threshold`, which removes false positives with probability `1 - delta`. |
| No deletions, so old traffic cannot be removed | **Ring of sub-window sketches.** The window is cut into `m` slices, each with its own CMS. A query sums the live slices. Expiry means resetting the oldest slice. No decrementing needed. |
| Error is `epsilon * N` regardless of the key, so rare keys are unreliable | Pick `epsilon` from the threshold you care about (`epsilon` about `phi / 10`), so heavy hitters sit far above the noise floor. Rare keys are allowed to be inaccurate because they are not the target. |

Hash flooding (an attacker crafting inputs that collide) is handled by seeded universal hashing: `h(x) = ((a*x + b) mod p) mod w`, with `a` and `b` drawn at random when the process starts.

### 4.2 Detecting "emerging" patterns

Counting totals would only find the biggest historical senders. To catch something new, each slice is compared with the baseline:

```
baseline(x) = average of estimate(x) over the older slices
surge(x)    = estimate_in_newest_slice(x) / max(baseline(x), 1)
```

A key is flagged when it is both frequent (above `phi * N_window`) and surging (`surge(x) >= S`, for example 5).

### 4.3 Core code

```python
import random

class CMS:
    def __init__(self, w, d, seed=None):
        rnd = random.Random(seed)
        self.w, self.d, self.p = w, d, (1 << 61) - 1
        self.ab = [(rnd.randrange(1, self.p), rnd.randrange(self.p)) for _ in range(d)]
        self.t = [[0] * w for _ in range(d)]

    def _idx(self, x):
        return [((a * x + b) % self.p) % self.w for a, b in self.ab]

    def add(self, x):                      # conservative update
        idx = self._idx(x)
        m = min(self.t[r][c] for r, c in enumerate(idx)) + 1
        for r, c in enumerate(idx):
            if self.t[r][c] < m:
                self.t[r][c] = m

    def query(self, x):
        return min(self.t[r][c] for r, c in enumerate(self._idx(x)))
```

## 5. Baselines

| Structure | Memory | Update | Notes |
|---|---|---|---|
| Exact HashMap | O(distinct keys) | O(1) | Exact answers, unbounded memory |
| Space-Saving (k counters) | O(k) | O(1) with stream-summary, O(log k) with a heap | Lists top-k directly; error at most `N / k` |
| Count-Min Sketch (+ heap) | O(w * d + k) | O(d) | Never undercounts; error at most `epsilon * N` |

## 6. Approach, step by step

1. **Define the threat patterns.** Fix three (volumetric, distributed, port scan) and state exactly which key each one counts.
2. **Generate traffic.** Produce a Zipf-distributed background stream (most IPs rare, a few common) and inject attack bursts from known IPs at known times, so ground truth exists.
3. **Implement the exact baseline.** A plain dictionary counter. Everything else is judged against it.
4. **Implement CMS.** Start with the plain version, check the error bound holds on small inputs.
5. **Add conservative update.** Compare its overestimation against plain CMS.
6. **Add the candidate heap.** This is what lets CMS report heavy hitters.
7. **Add time slicing.** Ring of sketches, expiry by reset, surge ratio against baseline.
8. **Implement Space-Saving.** Used only as a comparison point.
9. **Run the experiments** in section 7 and record the numbers.
10. **Analyse and write up.** Compare measured error with the theoretical bound, discuss where the design fails.

## 7. Experiments

Run each at 10^5, 10^6 and 10^7 events.

1. **Memory:** exact HashMap vs Space-Saving vs CMS.
2. **Accuracy:** mean relative error and false-positive rate of CMS across several `(epsilon, delta)` settings. Also plain vs conservative update.
3. **Error by rank:** relative error plotted against key frequency rank, to show heavy hitters are accurate and rare keys are not.
4. **Throughput:** updates per second for each structure.
5. **Detection quality:** precision and recall against the injected attackers, for plain, conservative, and safe-threshold flagging.
6. **Window sensitivity:** detection delay as the slice length and number of slices change.

### Results

Measured on this code (pure Python 3.12, synthetic Zipf traffic, `delta = 0.01`). Rerun the scripts to reproduce; CSVs and plots land in `results/`.

**Memory** (`benchmarks/memory.py`; CMS at `epsilon = 0.001`, Space-Saving with `k = 1000`; `--big` adds 10^7 events)

| Events | Distinct keys | HashMap | Space-Saving | CMS |
|---|---|---|---|---|
| 10^5 | 40,114 | 3,473 KB | 126 KB | 53 KB |
| 10^6 | 391,249 | 41,876 KB | 126 KB | 53 KB |

HashMap memory grows with distinct keys. CMS and Space-Saving stay flat.

**Accuracy** (`benchmarks/accuracy.py`, 300,000 events, heavy threshold 0.5% of the stream)

| epsilon | Variant | Table size | Mean overestimate | Worst-case bound `eps*N` | Keys beyond bound | Top-100 relative error |
|---|---|---|---|---|---|---|
| 0.01 | plain | 5 KB | 794.0 | 2998 | 0.00% | 2.31 |
| 0.01 | conservative | 5 KB | 399.8 | 2998 | 0.00% | 0.37 |
| 0.003 | plain | 17 KB | 212.0 | 899 | 0.00% | 0.57 |
| 0.003 | conservative | 17 KB | 114.7 | 899 | 0.00% | 0.0006 |
| 0.001 | plain | 53 KB | 50.3 | 300 | 0.00% | 0.15 |
| 0.001 | conservative | 53 KB | 26.8 | 300 | 0.00% | 0.00 |

Conservative update roughly halves the average overestimate and nearly removes it for the heaviest keys. The measured error sits well below the worst-case bound. `results/error_by_rank.png` shows relative error by key rank.

**Throughput** (`benchmarks/throughput.py`, 100,000 updates)

| Structure | Updates per second |
|---|---|
| Exact HashMap | 1,214,283 |
| Space-Saving (k=1000) | 749,297 |
| CMS plain | 261,594 |
| CMS conservative | 276,311 |

In pure Python the built-in dict is the fastest, because it is implemented in C while the sketch's hashing runs in the interpreter. CMS wins on memory and on bounded behaviour, not on raw speed here. A C or NumPy implementation would change the ranking.

**Detection** (`benchmarks/detection.py`, 400,000 packets, three attacks, slice = 10,000 packets)

| epsilon | Mode | Precision | Recall | False alarms |
|---|---|---|---|---|
| 0.03 | plain / conservative, no safe flagging | 1.00 | 1.00 | 0 |
| 0.03 | conservative + safe flagging | 1.00 | 0.67 | 0 |
| 0.02, 0.01, 0.001 | every mode | 1.00 | 1.00 | 0 |

With a reasonable `epsilon` every mode caught all three attacks with no false alarms, mostly because the surge check removes steady heavy hitters. Safe flagging only matters when `epsilon * N` approaches the alert threshold: there it keeps its no-false-positive guarantee but starts missing the weaker attack. Window length has little effect on delay until the slice gets large: at 40,000 packets per slice the weakest attack is missed (recall 0.67).

## 8. Repository layout

```
PulseGuard/
├── pulseguard/
│   ├── cms.py            # Count-Min Sketch (plain + conservative, seeded hashing)
│   ├── windowed.py       # ring of sub-window sketches
│   ├── space_saving.py   # baseline
│   ├── exact.py          # baseline
│   ├── detector.py       # trackers, candidate set, surge check, scoring
│   └── traffic.py        # Zipf traffic and attack injection
├── benchmarks/
│   ├── memory.py
│   ├── accuracy.py
│   ├── throughput.py
│   └── detection.py
├── results/              # CSVs and plots written by the benchmarks
├── demo.py               # step-by-step walkthrough of the whole idea
├── requirements.txt
└── README.md
```

## 9. How to run

```bash
git clone https://github.com/<your-username>/PulseGuard.git
cd PulseGuard
pip install -r requirements.txt

python demo.py                       # narrated walkthrough, about 10 seconds
python benchmarks/memory.py          # add --big for 10^7 events
python benchmarks/accuracy.py 300000
python benchmarks/throughput.py 100000
python benchmarks/detection.py
```

## 10. Limitations

- CMS overestimates. Safe flagging reduces false positives but increases detection delay.
- Heavy-hitter accuracy depends on choosing `epsilon` well relative to the threshold.
- Port scan detection here relies on SYN-only counting as a proxy. True distinct-port counting would need a different structure such as HyperLogLog.
- The sketch is pure Python, so absolute throughput is low. Compare the structures with each other, not with production tools.
- The `epsilon * N` bound is a worst case. Measured error was far below it, so safe flagging is more cautious than it needs to be on this data.
- Evaluation uses synthetic traffic. Real traces (CICIDS2017, a CAIDA sample) would be a stronger test.
- The sliced window is coarse: an event can stay in the estimate for up to one slice length after it should have expired.

## 11. Future work

- Evaluate on a real packet trace.
- Merge sketches from several sensors, since CMS tables add cell by cell.
- Add HyperLogLog for distinct-count based scan detection.
- Replace fixed thresholds with ones learned from the baseline.

## 12. References

1. G. Cormode and S. Muthukrishnan, "An improved data stream summary: the count-min sketch and its applications", *Journal of Algorithms*, 2005.
2. A. Metwally, D. Agrawal and A. El Abbadi, "Efficient computation of frequent and top-k elements in data streams", *ICDT*, 2005.
3. C. Estan and G. Varghese, "New directions in traffic measurement and accounting", *SIGCOMM*, 2002 (origin of conservative update).

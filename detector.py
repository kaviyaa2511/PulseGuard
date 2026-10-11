"""PulseGuard detector: one Tracker per threat pattern, each with a ring of sketches,
a small candidate set, and a surge check against the older slices."""
from .windowed import WindowedCMS


class Tracker:
    def __init__(self, name, key_fn, slice_size, phi, accept=None, slices=6,
                 epsilon=0.001, delta=0.01, k=64, surge=5.0, safe=True, conservative=True):
        self.name, self.key_fn, self.accept = name, key_fn, accept
        self.eps, self.k, self.surge, self.safe = epsilon, k, surge, safe
        self.min_count = phi * slice_size      # per-slice count that makes a key "frequent"
        self.ring = WindowedCMS(slices, epsilon, delta, conservative)
        self.cands, self.n = {}, 0

    def feed(self, pkt):
        if self.accept and not self.accept(pkt):
            return
        key = self.key_fn(pkt)
        est = self.ring.add(key)               # step 1: update the sketch
        self.n += 1
        if est >= self.min_count:              # step 2: remember keys worth querying
            self.cands[key] = est
            if len(self.cands) > self.k:
                del self.cands[min(self.cands, key=self.cands.get)]

    def close_slice(self, slice_idx):
        alerts = []
        if self.ring.history_len >= 2:         # need a baseline before judging anything
            for key in self.cands:
                e_new = self.ring.newest(key)
                base = self.ring.baseline(key)
                surge = e_new / max(base, 1.0)  # step 3: is it new, not just big?
                lower = e_new - self.eps * self.n if self.safe else e_new
                if lower >= self.min_count and surge >= self.surge:
                    alerts.append((slice_idx, self.name, key, e_new, round(surge, 1)))
        self.ring.advance()                    # step 4: expire the oldest slice
        self.cands, self.n = {}, 0
        return alerts


class PulseGuard:
    def __init__(self, slice_size=10_000, phi=0.02, phi_scan=0.01, **kw):
        self.slice_size = slice_size
        self.trackers = [
            Tracker("volumetric",  lambda p: p[0], slice_size, phi, **kw),
            Tracker("distributed", lambda p: p[1], slice_size, phi, **kw),
            Tracker("scan",        lambda p: p[0], slice_size, phi_scan,
                    accept=lambda p: p[2], **kw),
        ]
        self.i, self.alerts = 0, []

    def process(self, packet):
        for t in self.trackers:
            t.feed(packet)
        self.i += 1
        if self.i % self.slice_size == 0:
            s = self.i // self.slice_size
            for t in self.trackers:
                self.alerts += t.close_slice(s)

    def run(self, packets):
        for p in packets:
            self.process(p)
        return self.alerts

    @property
    def memory_bytes(self):
        return sum(t.ring.memory_bytes for t in self.trackers)


def score(alerts, truth, slice_size):
    """Precision / recall over distinct (pattern, key) pairs, plus detection delay."""
    flagged = {(a[1], a[2]): a[0] for a in reversed(alerts)}   # earliest slice wins
    wanted = {(kind, key): start for kind, key, start in truth}
    tp = [k for k in flagged if k in wanted]
    delays = [flagged[k] - (wanted[k] // slice_size + 1) for k in tp]   # 0 = caught in its first slice
    return {
        "precision": len(tp) / len(flagged) if flagged else 1.0,
        "recall": len(tp) / len(wanted) if wanted else 1.0,
        "false_alarms": len(flagged) - len(tp),
        "mean_delay_slices": sum(delays) / len(delays) if delays else float("nan"),
    }

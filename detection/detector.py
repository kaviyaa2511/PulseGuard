"""Threshold detector, top-k selection and evaluation.  (Owner: R)"""
import heapq


def top_k(candidates, k, method="sort"):
    """Top k (item, count, error) tuples by count. sort: O(n log n); heap: O(n log k)."""
    if k <= 0:
        return []
    if method == "sort":
        return sorted(candidates, key=lambda c: c[1], reverse=True)[:k]
    if method == "heap":
        return heapq.nlargest(k, candidates, key=lambda c: c[1])
    raise ValueError("method must be 'sort' or 'heap'")


def detect(candidates, cms, threshold):
    """Flag Space-Saving candidates whose CMS estimate exceeds threshold.
    Returns [(item, cms_estimate)], highest first. Cost O(k * d)."""
    if threshold < 0:
        raise ValueError("threshold must be non-negative")
    flagged = [(c[0], cms.estimate(c[0])) for c in candidates]
    flagged = [f for f in flagged if f[1] > threshold]
    return sorted(flagged, key=lambda f: f[1], reverse=True)


def evaluate(flagged, ground_truth):
    """Return (precision, recall). flagged: items or (item, est) tuples.
    Convention: precision = 1.0 if nothing flagged; recall = 1.0 if no true targets."""
    flagged_set = {f[0] if isinstance(f, tuple) else f for f in flagged}
    truth = set(ground_truth)
    tp = len(flagged_set & truth)
    precision = tp / len(flagged_set) if flagged_set else 1.0
    recall = tp / len(truth) if truth else 1.0
    return precision, recall

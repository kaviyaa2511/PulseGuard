"""Synthetic traffic: Zipf background plus injected attacks with known ground truth."""
from dataclasses import dataclass
import numpy as np


def zipf_keys(n, universe, s, rng):
    """n keys in [0, universe) drawn with P(rank r) proportional to r**-s."""
    p = np.arange(1, universe + 1, dtype=float) ** -s
    cdf = np.cumsum(p)
    cdf /= cdf[-1]
    return np.searchsorted(cdf, rng.random(n))


@dataclass
class Attack:
    kind: str        # "volumetric" | "distributed" | "scan"
    start: int       # packet index where it begins
    length: int      # packets the attack spans
    share: float     # fraction of those packets that are attack traffic


def generate(n, attacks, seed=0, n_src=50_000, n_dst=5_000, n_bots=2_000):
    """Return (packets, truth). packets is a list of (src, dst, syn_only).
    truth is a list of (kind, key, start_packet): the key a correct detector should flag."""
    rng = np.random.default_rng(seed)
    src = zipf_keys(n, n_src, 0.8, rng)
    dst = zipf_keys(n, n_dst, 1.0, rng)
    syn = rng.random(n) < 0.02
    truth, next_id = [], max(n_src, n_dst) + 1000
    for a in attacks:
        idx = a.start + np.sort(rng.choice(a.length, int(a.share * a.length), replace=False))
        actor, victim = next_id, next_id + 1
        next_id += 2
        syn[idx] = False
        if a.kind == "volumetric":            # one source, high rate
            src[idx], dst[idx] = actor, rng.integers(0, n_dst, len(idx))
            truth.append((a.kind, actor, a.start))
        elif a.kind == "distributed":         # many sources, one target
            src[idx], dst[idx] = n_src + rng.integers(0, n_bots, len(idx)), victim
            truth.append((a.kind, victim, a.start))
        elif a.kind == "scan":                # one source, many half-open attempts
            src[idx], dst[idx], syn[idx] = actor, victim, True
            truth.append((a.kind, actor, a.start))
        else:
            raise ValueError(a.kind)
    return list(zip(src.tolist(), dst.tolist(), syn.tolist())), truth

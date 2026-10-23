"""Seeded simulated network events.  (Owner: M)"""
import random

_SERVICES = ["website", "login", "database"]
_SIGNATURE = {"website": "page_request", "login": "login_success", "database": "query"}


def normal_ip(i):
    return f"192.168.{i // 250}.{i % 250 + 1}"


def generate_events(n, attacker_ip="10.0.0.99", attack_ratio=0.2,
                    num_normal_ips=500, seed=1):
    """Return a list of n event dicts. About attack_ratio of them come from
    attacker_ip (failed logins); the rest are spread over num_normal_ips IPs."""
    if not isinstance(n, int) or n < 0:
        raise ValueError("n must be a non-negative integer")
    if not 0 <= attack_ratio <= 1:
        raise ValueError("attack_ratio must be between 0 and 1")
    if not isinstance(num_normal_ips, int) or num_normal_ips < 1:
        raise ValueError("num_normal_ips must be a positive integer")
    rng = random.Random(seed)
    events = []
    for i in range(n):
        if rng.random() < attack_ratio:
            ip, service, sig = attacker_ip, "login", "login_failure"
        else:
            ip = normal_ip(rng.randrange(num_normal_ips))
            service = rng.choice(_SERVICES)
            sig = _SIGNATURE[service]
        events.append({"timestamp": round(i * 0.01, 2), "source_ip": ip,
                       "service": service, "signature": sig})
    return events

"""Seeded simulated network events.  (Owner: M / Member 3)

Two generators live here:

  generate_events(n, ...)   the original one-shot generator (unchanged).
  LiveEventGenerator        NEW: a stateful generator for the live simulation. Each call
                            to next_batch() returns 5-10 events, mixing IPs never seen
                            before with IPs seen in earlier batches.

HOW THIS CONNECTS TO MEMBER 4'S PIPELINE (the "contract")
  batch = gen.next_batch()      -> list of event dicts with the keys
                                   timestamp, source_ip, service, signature
  validate_event(event)         -> raises ValueError if an event is malformed
  The pipeline only reads event["source_ip"] and feeds it to the three algorithms.
  No real network traffic is captured: every event is made up by random.Random(seed).

COMPLEXITY  (B = events in a batch, at most max_batch = 10, so B is a small constant;
             u = distinct IPs generated so far)
  next_batch() time : O(B). Per event we do one random draw, one set lookup (expected
                      O(1)) and one list index (O(1)). Because B <= 10 this is O(1)
                      per batch; for a general batch size it is O(B).
  next_batch() space: O(B) for the returned list.
  generator state   : O(u). It remembers every IP it has ever emitted (a list for O(1)
                      random.choice and a set for O(1) membership). This is the
                      *traffic source*, not the monitoring system; the monitoring
                      structures (CMS, Space-Saving) stay bounded.
  validate_event()  : O(1) (an IPv4 string has at most 15 characters).

DATA STRUCTURE CHOICES
  list  _seen_list : random.choice needs O(1) index access. A set cannot be indexed,
                     and converting it to a list on every draw would cost O(u).
  set   _seen_set  : "has this IP been seen before?" in expected O(1). Scanning the
                     list would cost O(u).
  Keeping both costs about 2x the memory of one, which is the price of O(1) for both
  operations. A single counter (_next_new) guarantees every new IP is truly new, so no
  collision check is needed.
"""
import ipaddress
import math
import random

_SERVICES = ["website", "login", "database"]
_SIGNATURE = {"website": "page_request", "login": "login_success", "database": "query"}
_ATTACK_SIGNATURE = "login_failure"
_VALID_SIGNATURES = set(_SIGNATURE.values()) | {_ATTACK_SIGNATURE}
REQUIRED_FIELDS = ("timestamp", "source_ip", "service", "signature")


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


# ---------------------------------------------------------------------------
# Live simulation (new)
# ---------------------------------------------------------------------------
def _is_number(x):
    """True for a real, finite int/float. bool is rejected on purpose (True == 1)."""
    return (isinstance(x, (int, float)) and not isinstance(x, bool)
            and math.isfinite(x))


def validate_event(event):
    """Raise ValueError unless `event` is a well-formed event dict. O(1).

    The pipeline calls this on a whole batch BEFORE touching any algorithm, so one bad
    event can never leave the three algorithms with different counts."""
    if not isinstance(event, dict):
        raise ValueError(f"event must be a dict, got {type(event).__name__}")
    missing = [f for f in REQUIRED_FIELDS if f not in event]
    if missing:
        raise ValueError(f"event is missing fields: {missing}")
    if not _is_number(event["timestamp"]) or event["timestamp"] < 0:
        raise ValueError(f"timestamp must be a non-negative number, got {event['timestamp']!r}")
    ip = event["source_ip"]
    if not isinstance(ip, str):
        raise ValueError(f"source_ip must be a string, got {ip!r}")
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise ValueError(f"source_ip is not a valid IPv4 address: {ip!r}") from None
    if event["service"] not in _SERVICES:
        raise ValueError(f"unknown service: {event['service']!r}")
    if event["signature"] not in _VALID_SIGNATURES:
        raise ValueError(f"unknown signature: {event['signature']!r}")


class LiveEventGenerator:
    """Stateful, seeded generator: every next_batch() continues where the last stopped.

    Parameters
      seed          same seed -> exactly the same sequence of batches (reproducible).
      min_batch, max_batch   batch size is a random integer in [min_batch, max_batch]
                    (default 5..10). min_batch must be >= 2 so a batch can hold both a
                    new and a previously seen IP.
      attacker_ip, attack_ratio   chance that one event is a failed login from the
                    attacker (the "suspicious" source the detector should find).
      new_ip_ratio  chance that a non-attack event comes from a brand-new IP; otherwise
                    it comes from an IP seen in an earlier batch.
      interval_seconds   only used to spread the *simulated* timestamps of a batch over
                    its interval. The generator never sleeps; scheduling is Member 4's job.

    Guarantees for every batch
      * size is between min_batch and max_batch;
      * at least one IP that was never emitted before;
      * from the second batch on, at least one IP emitted in an earlier batch;
      * state is never reset: counts of "seen" IPs only grow.
    """

    # 172.16.0.1 upwards: private range, cannot clash with the attacker (10.0.0.99)
    # or with the 192.168.x.x IPs of the original generator.
    _BASE = int(ipaddress.IPv4Address("172.16.0.1"))

    def __init__(self, seed=1, min_batch=5, max_batch=10, attacker_ip="10.0.0.99",
                 attack_ratio=0.2, new_ip_ratio=0.3, interval_seconds=60):
        if not all(isinstance(v, int) and not isinstance(v, bool)
                   for v in (min_batch, max_batch)):
            raise ValueError("min_batch and max_batch must be integers")
        if min_batch < 2 or max_batch < min_batch:
            raise ValueError("need 2 <= min_batch <= max_batch")
        for name, value in (("attack_ratio", attack_ratio), ("new_ip_ratio", new_ip_ratio)):
            if not _is_number(value) or not 0 <= value <= 1:
                raise ValueError(f"{name} must be between 0 and 1")
        if not _is_number(interval_seconds) or interval_seconds <= 0:
            raise ValueError("interval_seconds must be a positive number")
        try:
            ipaddress.IPv4Address(attacker_ip)
        except ValueError:
            raise ValueError(f"attacker_ip is not a valid IPv4 address: {attacker_ip!r}") from None

        self.min_batch = min_batch
        self.max_batch = max_batch
        self.attacker_ip = attacker_ip
        self.attack_ratio = attack_ratio
        self.new_ip_ratio = new_ip_ratio
        self.interval_seconds = interval_seconds
        self.batches = 0                  # number of batches produced so far

        self._rng = random.Random(seed)   # the ONLY source of randomness
        self._seen_list = []              # IPs in first-seen order (O(1) random.choice)
        self._seen_set = set()            # same IPs (O(1) "seen before?")
        self._next_new = 0                # counter -> every new IP is unique

    def seen_count(self):
        """Number of distinct IPs emitted so far."""
        return len(self._seen_list)

    def _new_ip(self):
        # IPv4Address raises AddressValueError (a ValueError) if the space runs out.
        ip = str(ipaddress.IPv4Address(self._BASE + self._next_new))
        self._next_new += 1
        return ip

    def _pick_ip(self):
        """Choose the source IP of one event.  O(1) expected."""
        r = self._rng.random()
        if r < self.attack_ratio:
            return self.attacker_ip
        if r < self.attack_ratio + self.new_ip_ratio or not self._seen_list:
            return self._new_ip()                    # nothing to recur yet -> new
        return self._rng.choice(self._seen_list)     # recurring IP from earlier batches

    def next_batch(self):
        """Return the next batch of 5-10 events (a list of dicts).  O(B) time."""
        rng = self._rng
        n = rng.randint(self.min_batch, self.max_batch)
        ips = [self._pick_ip() for _ in range(n)]

        # Guarantee 1: at least one IP that has never been emitted.
        if all(ip in self._seen_set for ip in ips):
            ips[0] = self._new_ip()
        # Guarantee 2: at least one IP from an earlier batch (not possible in batch 1).
        # ips[-1] != ips[0] because n >= 2, so this cannot undo guarantee 1.
        if self._seen_list and not any(ip in self._seen_set for ip in ips):
            ips[-1] = rng.choice(self._seen_list)

        # Simulated clock: batch k covers [k*interval, (k+1)*interval).
        start = self.batches * self.interval_seconds
        step = self.interval_seconds / n
        events = []
        for i, ip in enumerate(ips):
            if ip == self.attacker_ip:
                service, sig = "login", _ATTACK_SIGNATURE
            else:
                service = rng.choice(_SERVICES)
                sig = _SIGNATURE[service]
            events.append({"timestamp": round(start + i * step, 2), "source_ip": ip,
                           "service": service, "signature": sig})

        # Remember the IPs only now, so "recurring" always means "from an EARLIER batch".
        for ip in ips:
            if ip not in self._seen_set:
                self._seen_set.add(ip)
                self._seen_list.append(ip)
        self.batches += 1
        return events

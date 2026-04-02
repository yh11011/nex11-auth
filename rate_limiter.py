"""
In-memory rate limiting and IP blocking for NexAlarm Auth Service.
Uses fixed-window counters and a simple error-count-based IP blocker.
No Redis required — works as a single-process uvicorn service.
"""
import hashlib
import time
from collections import defaultdict
from typing import Dict, Tuple


class FixedWindowCounter:
    """Fixed-window rate counter. Thread-safe for single-process async use."""

    def __init__(self):
        self._data: Dict[str, Tuple[int, float]] = {}  # key -> (count, window_start)

    def is_allowed(self, key: str, limit: int, window: int = 60) -> Tuple[bool, int]:
        """Returns (allowed, retry_after_seconds)."""
        now = time.time()
        count, start = self._data.get(key, (0, 0.0))
        if now - start >= window:
            self._data[key] = (1, now)
            return True, 0
        if count >= limit:
            return False, int(window - (now - start)) + 1
        self._data[key] = (count + 1, start)
        return True, 0

    def cleanup(self, window: int = 120):
        """Remove stale entries older than 2× window."""
        now = time.time()
        stale = [k for k, (_, s) in list(self._data.items()) if now - s > window]
        for k in stale:
            self._data.pop(k, None)


class IpBlocker:
    """Temporarily blocks IPs after repeated auth failures."""

    def __init__(self, threshold: int = 10, block_secs: int = 900):
        self._errors: Dict[str, int] = defaultdict(int)
        self._blocked: Dict[str, float] = {}  # ip -> unblock_time
        self.threshold = threshold
        self.block_secs = block_secs

    def is_blocked(self, ip: str) -> bool:
        until = self._blocked.get(ip, 0.0)
        if until and time.time() < until:
            return True
        if ip in self._blocked:
            del self._blocked[ip]
            self._errors.pop(ip, None)
        return False

    def record_error(self, ip: str):
        self._errors[ip] += 1
        if self._errors[ip] >= self.threshold:
            self._blocked[ip] = time.time() + self.block_secs
            self._errors[ip] = 0

    def clear_errors(self, ip: str):
        self._errors.pop(ip, None)


# ─── Global singletons ────────────────────────────────────────────────────────

_ip_counter    = FixedWindowCounter()
_token_counter = FixedWindowCounter()
_ip_blocker    = IpBlocker(threshold=10, block_secs=900)


def _short_hash(val: str) -> str:
    return hashlib.sha256(val.encode()).hexdigest()[:24]


def check_ip_rate(ip: str, limit: int, window: int = 60) -> Tuple[bool, int]:
    return _ip_counter.is_allowed(f"ip:{ip}", limit, window)


def check_token_rate(token: str, limit: int, window: int = 60) -> Tuple[bool, int]:
    return _token_counter.is_allowed(f"tok:{_short_hash(token)}", limit, window)


def record_auth_error(ip: str):
    _ip_blocker.record_error(ip)


def clear_auth_errors(ip: str):
    _ip_blocker.clear_errors(ip)


def is_ip_blocked(ip: str) -> bool:
    return _ip_blocker.is_blocked(ip)

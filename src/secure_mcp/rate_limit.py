from __future__ import annotations

import time
from threading import Lock


class RateLimitExceeded(RuntimeError):
    pass


class TokenBucket:
    def __init__(self, *, capacity: int, refill_per_sec: float) -> None:
        if capacity <= 0 or refill_per_sec <= 0:
            raise ValueError("capacity and refill_per_sec must be positive")
        self._capacity = float(capacity)
        self._tokens = float(capacity)
        self._refill = float(refill_per_sec)
        self._last = time.monotonic()
        self._lock = Lock()

    def consume(self, n: int = 1) -> None:
        with self._lock:
            now = time.monotonic()
            self._tokens = min(self._capacity, self._tokens + (now - self._last) * self._refill)
            self._last = now
            if self._tokens < n:
                raise RateLimitExceeded(
                    f"rate limit exceeded (capacity={int(self._capacity)}, refill={self._refill:.3f}/s)"
                )
            self._tokens -= n


class ScopedRateLimiter:
    """Per-scope in-memory token bucket. Adequate for single-process stdio
    deployments. For multi-process / HTTP-transport deployments, swap in a
    shared-state backend (Redis, etc.) before scaling."""

    def __init__(self, *, per_minute: int) -> None:
        self._per_minute = per_minute
        self._refill_per_sec = per_minute / 60.0
        self._buckets: dict[str, TokenBucket] = {}

    def check(self, scope: str) -> None:
        # dict.setdefault is atomic on CPython, so concurrent first-access for
        # the same scope can't create two buckets and lose a count.
        bucket = self._buckets.setdefault(
            scope,
            TokenBucket(capacity=self._per_minute, refill_per_sec=self._refill_per_sec),
        )
        bucket.consume()

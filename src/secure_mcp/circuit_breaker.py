from __future__ import annotations

import time
from threading import Lock


class CircuitOpenError(RuntimeError):
    pass


class CircuitBreaker:
    """Per-upstream breaker. Opens after `failure_threshold` consecutive
    failures, rejects fast for `cooldown_sec`, then allows a single half-open
    trial. Success closes it; failure reopens it.

    Each adapter owns its own SecureHTTPClient, so one breaker per client maps
    cleanly to one breaker per upstream."""

    def __init__(self, *, failure_threshold: int = 5, cooldown_sec: float = 30.0) -> None:
        if failure_threshold <= 0 or cooldown_sec <= 0:
            raise ValueError("failure_threshold and cooldown_sec must be positive")
        self._threshold = failure_threshold
        self._cooldown = cooldown_sec
        self._failures = 0
        self._opened_at: float | None = None
        self._lock = Lock()

    def before(self) -> None:
        with self._lock:
            if self._opened_at is None:
                return
            if time.monotonic() - self._opened_at < self._cooldown:
                raise CircuitOpenError(
                    f"circuit open: {self._failures} consecutive failures, "
                    f"cooling down for {self._cooldown:.0f}s"
                )
            # Cooldown elapsed — enter half-open: allow one trial through.
            self._opened_at = None

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self._threshold:
                self._opened_at = time.monotonic()

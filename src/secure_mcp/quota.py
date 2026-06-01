from __future__ import annotations

from datetime import date, datetime, timezone
from threading import Lock
from typing import Callable


class QuotaExceeded(RuntimeError):
    pass


class DailyQuota:
    """Fail-closed daily call budget. Complements the per-minute rate limiter:
    the rate limiter smooths bursts, the quota caps total daily spend (and
    therefore upstream cost / abuse blast radius).

    Under stdio transport there is one caller per process, so this is
    effectively a per-caller daily cap. `daily_limit <= 0` disables it.

    The clock is injectable for testing; production uses UTC wall-clock."""

    def __init__(self, *, daily_limit: int, clock: Callable[[], datetime] | None = None) -> None:
        self._limit = daily_limit
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._day: date | None = None
        self._count = 0
        self._lock = Lock()

    def check(self) -> None:
        if self._limit <= 0:
            return
        with self._lock:
            today = self._clock().date()
            if today != self._day:
                self._day = today
                self._count = 0
            if self._count >= self._limit:
                raise QuotaExceeded(f"daily quota of {self._limit} calls exhausted")
            self._count += 1

    def remaining(self) -> int | None:
        if self._limit <= 0:
            return None
        with self._lock:
            if self._clock().date() != self._day:
                return self._limit
            return max(0, self._limit - self._count)

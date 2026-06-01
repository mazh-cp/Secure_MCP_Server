from datetime import datetime, timezone

import pytest

from secure_mcp.quota import DailyQuota, QuotaExceeded


def test_blocks_after_limit():
    q = DailyQuota(daily_limit=2)
    q.check(); q.check()
    with pytest.raises(QuotaExceeded):
        q.check()


def test_zero_limit_is_unlimited():
    q = DailyQuota(daily_limit=0)
    for _ in range(1000):
        q.check()  # never raises


def test_resets_on_new_day():
    clock = {"now": datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)}
    q = DailyQuota(daily_limit=1, clock=lambda: clock["now"])
    q.check()
    with pytest.raises(QuotaExceeded):
        q.check()
    clock["now"] = datetime(2026, 6, 2, 0, 1, tzinfo=timezone.utc)
    q.check()  # new day, budget refreshed


def test_remaining_reports_budget():
    q = DailyQuota(daily_limit=3)
    assert q.remaining() == 3
    q.check()
    assert q.remaining() == 2
    assert DailyQuota(daily_limit=0).remaining() is None

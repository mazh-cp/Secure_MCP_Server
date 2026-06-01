import time

import pytest

from secure_mcp.rate_limit import RateLimitExceeded, ScopedRateLimiter, TokenBucket


def test_bucket_allows_up_to_capacity():
    b = TokenBucket(capacity=3, refill_per_sec=1.0)
    b.consume(); b.consume(); b.consume()
    with pytest.raises(RateLimitExceeded):
        b.consume()


def test_bucket_refills_over_time():
    b = TokenBucket(capacity=2, refill_per_sec=100.0)
    b.consume(); b.consume()
    with pytest.raises(RateLimitExceeded):
        b.consume()
    time.sleep(0.05)  # ~5 tokens refilled at 100/s
    b.consume()


def test_scoped_limiter_isolates_scopes():
    limiter = ScopedRateLimiter(per_minute=2)
    limiter.check("a"); limiter.check("a")
    with pytest.raises(RateLimitExceeded):
        limiter.check("a")
    # Different scope has its own bucket — should still succeed.
    limiter.check("b"); limiter.check("b")
    with pytest.raises(RateLimitExceeded):
        limiter.check("b")


def test_invalid_bucket_config_rejected():
    with pytest.raises(ValueError):
        TokenBucket(capacity=0, refill_per_sec=1.0)
    with pytest.raises(ValueError):
        TokenBucket(capacity=1, refill_per_sec=0)

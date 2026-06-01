import pytest

from secure_mcp.circuit_breaker import CircuitBreaker, CircuitOpenError


def test_opens_after_threshold():
    cb = CircuitBreaker(failure_threshold=3, cooldown_sec=60)
    for _ in range(3):
        cb.before()
        cb.record_failure()
    with pytest.raises(CircuitOpenError):
        cb.before()


def test_success_resets_failure_count():
    cb = CircuitBreaker(failure_threshold=3, cooldown_sec=60)
    cb.before(); cb.record_failure()
    cb.before(); cb.record_failure()
    cb.before(); cb.record_success()  # reset
    cb.before(); cb.record_failure()
    cb.before(); cb.record_failure()
    # only 2 consecutive failures since reset — still closed
    cb.before()


def test_half_open_after_cooldown(monkeypatch):
    import secure_mcp.circuit_breaker as mod
    fake = {"t": 1000.0}
    monkeypatch.setattr(mod.time, "monotonic", lambda: fake["t"])

    cb = CircuitBreaker(failure_threshold=2, cooldown_sec=30)
    cb.before(); cb.record_failure()
    cb.before(); cb.record_failure()  # opens at t=1000
    with pytest.raises(CircuitOpenError):
        cb.before()
    fake["t"] = 1031.0  # cooldown elapsed
    cb.before()         # half-open trial allowed
    cb.record_success()
    cb.before()         # closed again


def test_invalid_config_rejected():
    with pytest.raises(ValueError):
        CircuitBreaker(failure_threshold=0)
    with pytest.raises(ValueError):
        CircuitBreaker(cooldown_sec=0)

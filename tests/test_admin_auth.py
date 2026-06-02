from secure_mcp.admin.auth import (
    LoginThrottle,
    check_admin_token,
    mint_session,
    verify_session,
)

TOKEN = "super-secret-admin-token"


def test_admin_token_constant_time_match():
    assert check_admin_token(TOKEN, TOKEN)
    assert not check_admin_token("wrong", TOKEN)


def test_session_roundtrip():
    s = mint_session(TOKEN, ttl_sec=60)
    assert verify_session(s, TOKEN)


def test_expired_session_rejected():
    s = mint_session(TOKEN, ttl_sec=-1)  # already expired
    assert not verify_session(s, TOKEN)


def test_session_signed_with_wrong_token_rejected():
    s = mint_session(TOKEN, ttl_sec=60)
    assert not verify_session(s, "different-admin-token")


def test_tampered_session_rejected():
    s = mint_session(TOKEN, ttl_sec=60)
    payload, sig = s.split(".", 1)
    forged = payload[:-1] + ("A" if payload[-1] != "A" else "B") + "." + sig
    assert not verify_session(forged, TOKEN)


def test_malformed_session_rejected():
    assert not verify_session("garbage", TOKEN)
    assert not verify_session("", TOKEN)


def test_throttle_locks_after_max_fails():
    th = LoginThrottle(max_fails=3, lock_sec=300)
    assert not th.is_locked("1.2.3.4", now=0)
    for _ in range(3):
        th.record_failure("1.2.3.4", now=0)
    assert th.is_locked("1.2.3.4", now=10)
    assert not th.is_locked("1.2.3.4", now=400)  # lock expired


def test_throttle_reset_clears_lock():
    th = LoginThrottle(max_fails=2, lock_sec=300)
    th.record_failure("k", now=0)
    th.record_failure("k", now=0)
    assert th.is_locked("k", now=1)
    th.reset("k")
    assert not th.is_locked("k", now=1)

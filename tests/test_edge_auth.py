from secure_mcp.edge.auth import (
    check_enrollment_secret,
    mint_device_token,
    verify_device_token,
)

SECRET = "edge-enrollment-secret"


def test_enrollment_secret_constant_time():
    assert check_enrollment_secret(SECRET, SECRET)
    assert not check_enrollment_secret("wrong", SECRET)


def test_device_token_roundtrip_carries_claims():
    tok = mint_device_token(SECRET, group="sales", device_id="dev-1", ttl_sec=60)
    claims = verify_device_token(tok, SECRET)
    assert claims is not None
    assert claims["grp"] == "sales"
    assert claims["dev"] == "dev-1"


def test_expired_token_rejected():
    tok = mint_device_token(SECRET, group="g", device_id="d", ttl_sec=-1)
    assert verify_device_token(tok, SECRET) is None


def test_token_for_wrong_secret_rejected():
    tok = mint_device_token(SECRET, group="g", device_id="d", ttl_sec=60)
    assert verify_device_token(tok, "other-secret") is None


def test_tampered_token_rejected():
    tok = mint_device_token(SECRET, group="g", device_id="d", ttl_sec=60)
    payload, sig = tok.split(".", 1)
    forged = payload[:-1] + ("A" if payload[-1] != "A" else "B") + "." + sig
    assert verify_device_token(forged, SECRET) is None


def test_garbage_token_rejected():
    assert verify_device_token("garbage", SECRET) is None
    assert verify_device_token("", SECRET) is None

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _signing_key(secret: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), b"secure-mcp-edge-device",
                    hashlib.sha256).digest()


def check_enrollment_secret(provided: str, secret: str) -> bool:
    return hmac.compare_digest(provided.encode("utf-8"), secret.encode("utf-8"))


def mint_device_token(secret: str, *, group: str, device_id: str,
                      ttl_sec: int, now: float | None = None) -> str:
    exp = int((now if now is not None else time.time()) + ttl_sec)
    payload = _b64u(json.dumps({"exp": exp, "grp": group, "dev": device_id},
                               separators=(",", ":"), sort_keys=True).encode("utf-8"))
    sig = _b64u(hmac.new(_signing_key(secret), payload.encode("ascii"),
                         hashlib.sha256).digest())
    return f"{payload}.{sig}"


def verify_device_token(token: str, secret: str, *, now: float | None = None) -> dict | None:
    """Return the token claims ({exp, grp, dev}) if valid and unexpired, else None."""
    try:
        payload, sig = token.split(".", 1)
    except (ValueError, AttributeError):
        return None
    expected = _b64u(hmac.new(_signing_key(secret), payload.encode("ascii"),
                              hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        claims = json.loads(_b64u_decode(payload))
        exp = int(claims["exp"])
    except (ValueError, KeyError, TypeError):
        return None
    if exp <= (now if now is not None else time.time()):
        return None
    return claims

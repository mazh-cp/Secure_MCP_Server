from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from threading import Lock


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _signing_key(admin_token: str) -> bytes:
    # Derive a session-signing key from the admin token so we don't need a
    # second secret. The label domain-separates this use from any other.
    return hmac.new(admin_token.encode("utf-8"), b"secure-mcp-admin-session",
                    hashlib.sha256).digest()


def check_admin_token(provided: str, admin_token: str) -> bool:
    """Constant-time comparison of the presented admin token."""
    return hmac.compare_digest(provided.encode("utf-8"), admin_token.encode("utf-8"))


def mint_session(admin_token: str, *, ttl_sec: int, now: float | None = None) -> str:
    exp = int((now if now is not None else time.time()) + ttl_sec)
    payload = _b64u(json.dumps({"exp": exp}, separators=(",", ":")).encode("utf-8"))
    sig = _b64u(hmac.new(_signing_key(admin_token), payload.encode("ascii"),
                         hashlib.sha256).digest())
    return f"{payload}.{sig}"


def verify_session(token: str, admin_token: str, *, now: float | None = None) -> bool:
    try:
        payload, sig = token.split(".", 1)
    except ValueError:
        return False
    expected = _b64u(hmac.new(_signing_key(admin_token), payload.encode("ascii"),
                              hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        data = json.loads(_b64u_decode(payload))
        exp = int(data["exp"])
    except (ValueError, KeyError, TypeError):
        return False
    return exp > (now if now is not None else time.time())


class LoginThrottle:
    """Per-source lockout after repeated failed logins. In-memory, per-process."""

    def __init__(self, *, max_fails: int = 5, lock_sec: float = 300.0) -> None:
        self._max = max_fails
        self._lock_sec = lock_sec
        self._state: dict[str, tuple[int, float]] = {}  # key -> (fails, lock_until)
        self._mu = Lock()

    def is_locked(self, key: str, *, now: float | None = None) -> bool:
        t = now if now is not None else time.monotonic()
        with self._mu:
            fails, lock_until = self._state.get(key, (0, 0.0))
            return t < lock_until

    def record_failure(self, key: str, *, now: float | None = None) -> None:
        t = now if now is not None else time.monotonic()
        with self._mu:
            fails, _ = self._state.get(key, (0, 0.0))
            fails += 1
            lock_until = t + self._lock_sec if fails >= self._max else 0.0
            self._state[key] = (fails, lock_until)

    def reset(self, key: str) -> None:
        with self._mu:
            self._state.pop(key, None)

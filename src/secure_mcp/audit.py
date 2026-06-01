from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any

_REDACT_KEYS = {"api_key", "authorization", "token", "secret", "password", "cookie"}

GENESIS_HASH = "0" * 64


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if k.lower() in _REDACT_KEYS else _redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def _canonical(entry: dict[str, Any]) -> str:
    # Deterministic serialization of everything except the hash itself, so the
    # digest is reproducible at verification time.
    body = {k: v for k, v in entry.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_digest(prev_hash: str, entry: dict[str, Any], key: bytes | None) -> str:
    msg = (prev_hash + _canonical(entry)).encode("utf-8")
    if key:
        return hmac.new(key, msg, hashlib.sha256).hexdigest()
    return hashlib.sha256(msg).hexdigest()


class AuditLogger:
    """Append-only, tamper-evident audit log.

    Each entry is hash-chained to its predecessor: entry N carries
    prev_hash = hash(N-1) and hash = digest(prev_hash + canonical(entry)).
    With an HMAC key present (SECURE_MCP_AUDIT_HMAC_KEY, from Vault/KMS), an
    attacker who edits the file cannot recompute the chain without the key —
    so any truncation or edit is detectable via verify_chain(). Without a key
    it degrades to a plain SHA-256 chain (detects corruption and naive edits).

    The underlying volume must still be encrypted at rest, owner-only."""

    def __init__(self, path: Path, caller_id: str, *, hmac_key: bytes | None = None) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._key = hmac_key
        self._prev_hash, self._seq = self._recover(path, hmac_key)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self._fh = os.fdopen(fd, "a", buffering=1, encoding="utf-8")
        self._caller_id = caller_id

    @staticmethod
    def _recover(path: Path, key: bytes | None) -> tuple[str, int]:
        """Resume the chain across restarts by reading the last entry's hash."""
        if not path.is_file() or path.stat().st_size == 0:
            return GENESIS_HASH, 0
        last_line = ""
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last_line = line
        if not last_line:
            return GENESIS_HASH, 0
        entry = json.loads(last_line)
        return str(entry["hash"]), int(entry["seq"]) + 1

    def record(self, *, tool: str, action: str, result: str, details: dict[str, Any] | None = None) -> None:
        entry: dict[str, Any] = {
            "seq": self._seq,
            "ts": time.time(),
            "caller_id": self._caller_id,
            "tool": tool,
            "action": action,
            "result": result,
            "details": _redact(details or {}),
            "prev_hash": self._prev_hash,
        }
        entry["hash"] = compute_digest(self._prev_hash, entry, self._key)
        self._fh.write(json.dumps(entry, separators=(",", ":"), ensure_ascii=True) + "\n")
        self._prev_hash = entry["hash"]
        self._seq += 1

    def close(self) -> None:
        self._fh.close()


def verify_chain(path: Path, key: bytes | None) -> tuple[bool, str | None]:
    """Walk the audit log and confirm the hash chain is intact.
    Returns (ok, error_message). ok=True means no tampering detected."""
    prev = GENESIS_HASH
    expected_seq = 0
    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            entry = json.loads(line)
            if entry.get("seq") != expected_seq:
                return False, f"line {lineno}: seq {entry.get('seq')} != expected {expected_seq}"
            if entry.get("prev_hash") != prev:
                return False, f"line {lineno}: prev_hash mismatch (chain broken)"
            recomputed = compute_digest(prev, entry, key)
            if recomputed != entry.get("hash"):
                return False, f"line {lineno}: hash mismatch (entry altered)"
            prev = entry["hash"]
            expected_seq += 1
    return True, None

"""Write-only, AES-256-GCM encrypted secret keystore.

Policy posture: secrets are NEVER stored in plaintext config or version control,
and NEVER returned/displayed. This store encrypts each secret under a master key
(KEK) injected from env/KMS, exposes only a non-reversible fingerprint + status,
and `get()` is for INTERNAL resolution (e.g. load_settings, connectivity test)
— it is never wired to an API response.

Two operating modes (decided by whether a master key is configured):
- master key present → full set/rotate/delete (local/standalone provisioning).
- absent → keystore disabled; secrets come from env/Vault (read-only status).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeystoreError(RuntimeError):
    pass


# Logical secrets the system manages, with the env var that takes precedence and
# whether a live connectivity test is meaningful. Drives the UI + load_settings.
SECRET_CATALOG: dict[str, dict] = {
    "checkpoint_te":   {"env": "CHECKPOINT_TE_API_KEY",            "testable": True,  "label": "Check Point Threat Emulation"},
    "checkpoint_tc":   {"env": "CHECKPOINT_TC_API_KEY",            "testable": True,  "label": "Check Point ThreatCloud"},
    "lakera_guard":    {"env": "LAKERA_GUARD_API_KEY",             "testable": True,  "label": "Lakera Guard"},
    "edge_enrollment": {"env": "SECURE_MCP_EDGE_ENROLLMENT_SECRET","testable": False, "label": "Edge enrollment secret"},
    "admin_token":     {"env": "SECURE_MCP_ADMIN_TOKEN",           "testable": False, "label": "Admin console token"},
    "audit_hmac":      {"env": "SECURE_MCP_AUDIT_HMAC_KEY",        "testable": False, "label": "Audit HMAC key"},
}


def fingerprint(value: str) -> str:
    """Non-reversible identifier so an operator can confirm WHICH secret is
    loaded without revealing any of it."""
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def load_master_key() -> bytes | None:
    raw = os.environ.get("SECURE_MCP_KEYSTORE_MASTER_KEY")
    if not raw or raw.startswith("__"):
        return None
    try:
        key = bytes.fromhex(raw)
    except ValueError as e:
        raise KeystoreError("SECURE_MCP_KEYSTORE_MASTER_KEY must be hex") from e
    if len(key) != 32:
        raise KeystoreError("master key must be 32 bytes (64 hex chars) for AES-256")
    return key


class SecretKeystore:
    def __init__(self, path: Path, master_key: bytes) -> None:
        if len(master_key) != 32:
            raise KeystoreError("master key must be 32 bytes (AES-256)")
        self._path = Path(path)
        self._aes = AESGCM(master_key)

    def _load(self) -> dict:
        if not self._path.is_file() or self._path.stat().st_size == 0:
            return {}
        return json.loads(self._path.read_text(encoding="utf-8"))

    def _save(self, data: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self._path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(data))

    def set(self, name: str, value: str, *, now_iso: str) -> str:
        if not value:
            raise KeystoreError("empty secret value")
        data = self._load()
        nonce = os.urandom(12)
        # AAD binds the ciphertext to its logical name (prevents swapping entries).
        ct = self._aes.encrypt(nonce, value.encode("utf-8"), name.encode("utf-8"))
        data[name] = {
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ct": base64.b64encode(ct).decode("ascii"),
            "fp": fingerprint(value),
            "updated": now_iso,
        }
        self._save(data)
        return data[name]["fp"]

    def get(self, name: str) -> str | None:
        """INTERNAL ONLY — resolve a value for use (never for an API response)."""
        d = self._load().get(name)
        if not d:
            return None
        nonce = base64.b64decode(d["nonce"])
        ct = base64.b64decode(d["ct"])
        return self._aes.decrypt(nonce, ct, name.encode("utf-8")).decode("utf-8")

    def delete(self, name: str) -> bool:
        data = self._load()
        if name in data:
            del data[name]
            self._save(data)
            return True
        return False

    def status(self) -> dict[str, dict]:
        """Per-name metadata only — fingerprint + updated, never the value."""
        return {k: {"fp": v["fp"], "updated": v.get("updated")} for k, v in self._load().items()}

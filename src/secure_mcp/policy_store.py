"""Central browser-policy authority: per-group policy documents + Ed25519
signing. Authored by the admin console (PAP), served signed by the edge PDP.

The signed-envelope format matches the browser plugin's existing verifier
(base64 canonical-JSON payload + raw-Ed25519 signature), so the extension can
verify policy with a GPO-distributed public key. Secrets never live here — only
non-sensitive policy settings.
"""

from __future__ import annotations

import base64
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_GROUP_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# Policy settings the admin may author (mirrors the plugin's managed schema).
# bool keys and string-array keys; anything else is rejected.
_BOOL_KEYS = {
    "ProtectionEnabled", "UrlFilteringEnabled", "BlockMaliciousUrls",
    "BlockPhishingUrls", "BlockSuspiciousUrls", "AllowUserBypass",
}
_LIST_KEYS = {"UrlAllowlist", "UrlBlocklist", "AllowlistDomains"}
ALLOWED_POLICY_KEYS = _BOOL_KEYS | _LIST_KEYS


class PolicyValidationError(ValueError):
    pass


def _canonical_bytes(doc: dict[str, Any]) -> bytes:
    # Deterministic JSON: keys sorted at every depth, compact separators. The
    # signature is computed over exactly these bytes; the client verifies the
    # decoded payload (not the convenience `document` copy).
    return json.dumps(doc, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _validate_settings(settings: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(settings, dict):
        raise PolicyValidationError("settings must be an object")
    out: dict[str, Any] = {}
    for k, v in settings.items():
        if k not in ALLOWED_POLICY_KEYS:
            raise PolicyValidationError(f"unknown policy key: {k}")
        if k in _BOOL_KEYS:
            if not isinstance(v, bool):
                raise PolicyValidationError(f"{k} must be boolean")
        else:  # list keys
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise PolicyValidationError(f"{k} must be a string array")
            v = [x.strip() for x in v if x.strip()][:1000]
        out[k] = v
    return out


def _atomic_write(path: Path, data: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class PolicyStore:
    """Authoring (set/get policy docs) needs no key. Signing lazily loads/creates
    the keypair — so the admin console can author policy without ever holding the
    private key; only the edge (which signs) materializes it."""

    def __init__(self, policy_dir: Path, keys_dir: Path) -> None:
        self._dir = Path(policy_dir)
        self._keys = Path(keys_dir)
        self._priv_cached: Ed25519PrivateKey | None = None

    # ---- keypair (lazy) ----
    def _priv(self) -> Ed25519PrivateKey:
        if self._priv_cached is not None:
            return self._priv_cached
        priv_path = self._keys / "policy_ed25519.pem"
        if priv_path.is_file():
            self._priv_cached = serialization.load_pem_private_key(
                priv_path.read_bytes(), password=None)  # type: ignore[assignment]
            return self._priv_cached
        self._keys.mkdir(parents=True, exist_ok=True)
        priv = Ed25519PrivateKey.generate()
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        fd = os.open(str(priv_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        self._priv_cached = priv
        return priv

    def public_key_b64(self) -> str:
        raw = self._priv().public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode("ascii")

    # ---- documents ----
    def _path(self, group: str) -> Path:
        if not _GROUP_RE.match(group):
            raise PolicyValidationError("group must match [A-Za-z0-9._-]{1,64}")
        base = self._dir.resolve()
        p = (base / f"{group}.json").resolve()
        if p.parent != base:
            raise PolicyValidationError("group path escapes policy dir")
        return p

    def list_groups(self) -> list[str]:
        if not self._dir.is_dir():
            return []
        return sorted(p.stem for p in self._dir.glob("*.json"))

    def get_document(self, group: str) -> dict[str, Any] | None:
        p = self._path(group)
        if not p.is_file():
            return None
        return json.loads(p.read_text(encoding="utf-8"))

    def set_settings(self, group: str, settings: dict[str, Any], *, now_iso: str) -> dict[str, Any]:
        clean = _validate_settings(settings)
        existing = self.get_document(group)
        version = int(existing["version"]) + 1 if existing else 1
        doc = {"version": version, "issuedAt": now_iso, "tenantId": group, "settings": clean}
        _atomic_write(self._path(group), json.dumps(doc, indent=2) + "\n")
        return doc

    # ---- signing ----
    def sign(self, doc: dict[str, Any]) -> dict[str, Any]:
        canonical = _canonical_bytes(doc)
        sig = self._priv().sign(canonical)
        return {
            "payload": base64.b64encode(canonical).decode("ascii"),
            "signature": base64.b64encode(sig).decode("ascii"),
            "alg": "ed25519",
            "document": doc,
        }


def verify_envelope(envelope: dict[str, Any], public_key_b64: str) -> bool:
    """Verify a signed envelope against a raw-base64 Ed25519 public key.
    Verifies the *payload* bytes (the signed content), not the document copy."""
    if envelope.get("alg") != "ed25519":
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        payload = base64.b64decode(envelope["payload"])
        sig = base64.b64decode(envelope["signature"])
        pub.verify(sig, payload)
        return True
    except Exception:
        return False

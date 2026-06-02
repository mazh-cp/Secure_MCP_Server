from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from ..config import ConfigError


def _require(name: str) -> str:
    val = os.environ.get(name)
    if not val or val.startswith("__"):
        raise ConfigError(f"Missing or placeholder env var: {name}")
    return val


def _https_or_raise(url: str, name: str) -> str:
    if not url.startswith("https://"):
        raise ConfigError(f"{name} must use https:// (TLS required)")
    return url


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in {"localhost", "ip6-localhost"}


def _load_hmac_key() -> bytes | None:
    raw = os.environ.get("SECURE_MCP_AUDIT_HMAC_KEY")
    if not raw or raw.startswith("__"):
        return None
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return raw.encode("utf-8")


@dataclass(frozen=True)
class EdgeConfig:
    enrollment_secret: str
    bind_host: str
    bind_port: int
    tls_cert: str | None
    tls_key: str | None
    threatcloud_base_url: str
    threatcloud_api_key: str
    audit_log_path: Path
    audit_hmac_key: bytes | None
    rate_limit_per_minute: int
    daily_quota: int
    token_ttl_sec: int
    allowed_groups: tuple[str, ...]
    block_suspicious: bool
    policy_dir: Path
    keys_dir: Path

    @property
    def tls_enabled(self) -> bool:
        return bool(self.tls_cert and self.tls_key)


def load_edge_config() -> EdgeConfig:
    """Edge (internet-facing PDP) config. The enrollment secret and ThreatCloud
    key MUST be injected from the secrets manager. Binding to a non-loopback
    interface without TLS is refused — terminate TLS here or at a reverse proxy
    (then bind loopback). Phase 1 is indicator-only: no file/AI content paths."""
    bind_host = os.environ.get("SECURE_MCP_EDGE_HOST", "127.0.0.1")
    tls_cert = os.environ.get("SECURE_MCP_EDGE_TLS_CERT") or None
    tls_key = os.environ.get("SECURE_MCP_EDGE_TLS_KEY") or None
    if not _is_loopback(bind_host) and not (tls_cert and tls_key):
        raise ConfigError(
            f"refusing to bind edge API to non-loopback host '{bind_host}' without "
            "TLS — set SECURE_MCP_EDGE_TLS_CERT/KEY or terminate TLS at a proxy and "
            "bind 127.0.0.1"
        )

    audit_default = str(Path(_require("SECURE_MCP_AUDIT_LOG_PATH")).parent / "edge-audit.jsonl")
    return EdgeConfig(
        enrollment_secret=_require("SECURE_MCP_EDGE_ENROLLMENT_SECRET"),
        bind_host=bind_host,
        bind_port=int(os.environ.get("SECURE_MCP_EDGE_PORT", "8770")),
        tls_cert=tls_cert,
        tls_key=tls_key,
        threatcloud_base_url=_https_or_raise(
            os.environ.get("CHECKPOINT_TC_BASE_URL", "https://rep.checkpoint.com"),
            "CHECKPOINT_TC_BASE_URL"),
        threatcloud_api_key=_require("CHECKPOINT_TC_API_KEY"),
        audit_log_path=Path(os.environ.get("SECURE_MCP_EDGE_AUDIT_LOG", audit_default)),
        audit_hmac_key=_load_hmac_key(),
        rate_limit_per_minute=int(os.environ.get("SECURE_MCP_EDGE_RATE_LIMIT_PER_MIN", "120")),
        daily_quota=int(os.environ.get("SECURE_MCP_EDGE_DAILY_QUOTA", "0")),
        token_ttl_sec=int(os.environ.get("SECURE_MCP_EDGE_TOKEN_TTL", "3600")),
        allowed_groups=tuple(
            g.strip() for g in os.environ.get("SECURE_MCP_EDGE_GROUPS", "").split(",")
            if g.strip()
        ),
        block_suspicious=os.environ.get("SECURE_MCP_EDGE_BLOCK_SUSPICIOUS", "").lower()
        in {"1", "true", "yes"},
        policy_dir=Path(os.environ.get("SECURE_MCP_EDGE_POLICY_DIR", "/etc/secure-mcp/policies")),
        keys_dir=Path(os.environ.get("SECURE_MCP_EDGE_KEYS_DIR", "/etc/secure-mcp/keys")),
    )

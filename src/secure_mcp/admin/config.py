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


@dataclass(frozen=True)
class AdminConfig:
    admin_token: str
    bind_host: str
    bind_port: int
    tls_cert: str | None
    tls_key: str | None
    audit_log_path: Path
    admin_audit_log_path: Path
    audit_hmac_key: bytes | None
    identity_dir: Path
    op_config_file: Path
    te_base_url: str
    tc_base_url: str
    lakera_base_url: str
    session_ttl_sec: int
    # Restart feature is opt-in: empty allowlist = disabled. Defaults keep
    # existing AdminConfig constructions (tests) valid.
    managed_units: tuple[str, ...] = ()
    restart_use_sudo: bool = False
    policy_dir: Path = Path("/etc/secure-mcp/policies")
    keys_dir: Path = Path("/etc/secure-mcp/keys")

    @property
    def tls_enabled(self) -> bool:
        return bool(self.tls_cert and self.tls_key)


def _load_hmac_key() -> bytes | None:
    raw = os.environ.get("SECURE_MCP_AUDIT_HMAC_KEY")
    if not raw or raw.startswith("__"):
        return None
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return raw.encode("utf-8")


def load_admin_config() -> AdminConfig:
    """Admin console config. The admin token MUST be injected from the secrets
    manager (never hardcoded). Binds to loopback by default; binding to a
    non-loopback interface without TLS is refused (fails closed)."""
    bind_host = os.environ.get("SECURE_MCP_ADMIN_HOST", "127.0.0.1")
    tls_cert = os.environ.get("SECURE_MCP_ADMIN_TLS_CERT") or None
    tls_key = os.environ.get("SECURE_MCP_ADMIN_TLS_KEY") or None

    if not _is_loopback(bind_host) and not (tls_cert and tls_key):
        raise ConfigError(
            f"refusing to bind admin console to non-loopback host '{bind_host}' "
            "without TLS — set SECURE_MCP_ADMIN_TLS_CERT/KEY or bind to 127.0.0.1"
        )

    audit_log_path = Path(_require("SECURE_MCP_AUDIT_LOG_PATH"))
    # Admin actions get their OWN hash-chained log: two processes appending to
    # one chained file would break verification.
    admin_audit = os.environ.get(
        "SECURE_MCP_ADMIN_AUDIT_LOG",
        str(audit_log_path.parent / "admin-audit.jsonl"),
    )

    return AdminConfig(
        admin_token=_require("SECURE_MCP_ADMIN_TOKEN"),
        bind_host=bind_host,
        bind_port=int(os.environ.get("SECURE_MCP_ADMIN_PORT", "8765")),
        tls_cert=tls_cert,
        tls_key=tls_key,
        audit_log_path=audit_log_path,
        admin_audit_log_path=Path(admin_audit),
        audit_hmac_key=_load_hmac_key(),
        identity_dir=Path(_require("SECURE_MCP_IDENTITY_DIR")),
        op_config_file=Path(os.environ.get("SECURE_MCP_CONFIG_FILE",
                                           "/etc/secure-mcp/config.json")),
        te_base_url=_https_or_raise(
            os.environ.get("CHECKPOINT_TE_BASE_URL", "https://te.checkpoint.com"),
            "CHECKPOINT_TE_BASE_URL"),
        tc_base_url=_https_or_raise(
            os.environ.get("CHECKPOINT_TC_BASE_URL", "https://rep.checkpoint.com"),
            "CHECKPOINT_TC_BASE_URL"),
        lakera_base_url=_https_or_raise(
            os.environ.get("LAKERA_GUARD_BASE_URL", "https://api.lakera.ai"),
            "LAKERA_GUARD_BASE_URL"),
        session_ttl_sec=int(os.environ.get("SECURE_MCP_ADMIN_SESSION_TTL", "1800")),
        managed_units=tuple(
            u.strip() for u in os.environ.get("SECURE_MCP_MANAGED_UNITS", "").split(",")
            if u.strip()
        ),
        restart_use_sudo=os.environ.get("SECURE_MCP_RESTART_USE_SUDO", "").lower()
        in {"1", "true", "yes"},
        policy_dir=Path(os.environ.get("SECURE_MCP_EDGE_POLICY_DIR", "/etc/secure-mcp/policies")),
        keys_dir=Path(os.environ.get("SECURE_MCP_EDGE_KEYS_DIR", "/etc/secure-mcp/keys")),
    )

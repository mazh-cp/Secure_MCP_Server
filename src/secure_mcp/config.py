from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Identity:
    caller_id: str
    allowed_tools: frozenset[str]


@dataclass(frozen=True)
class Settings:
    identity: Identity
    checkpoint_te_base_url: str
    checkpoint_te_api_key: str
    lakera_guard_base_url: str
    lakera_guard_api_key: str
    audit_log_path: Path
    upload_dir: Path
    max_upload_bytes: int
    rate_limit_per_minute: int
    # Fields below carry defaults so test fixtures and older deployments that
    # don't set them still construct a valid Settings.
    dlp_mode: str = "redact"
    audit_hmac_key: bytes | None = None
    daily_quota: int = 0
    threatcloud_base_url: str = "https://rep.checkpoint.com"
    threatcloud_api_key: str = ""


def _require_env(name: str) -> str:
    val = os.environ.get(name)
    # Reject empty values and the placeholder sentinel from .env.example so a
    # mis-deployed unit fails closed instead of forwarding requests with a
    # bogus key.
    if not val or val.startswith("__"):
        raise ConfigError(f"Missing or placeholder env var: {name}")
    return val


def _require_https(url: str, name: str) -> str:
    if not url.startswith("https://"):
        raise ConfigError(f"{name} must use https:// (TLS required)")
    return url


def _load_identity(path_str: str) -> Identity:
    path = Path(path_str)
    if not path.is_file():
        raise ConfigError(f"Identity file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    try:
        caller = str(data["caller_id"])
        tools = frozenset(str(t) for t in data["allowed_tools"])
    except (KeyError, TypeError) as e:
        raise ConfigError(f"Malformed identity file: {e}") from e
    if not caller or not tools:
        raise ConfigError("Identity file must define caller_id and non-empty allowed_tools")
    return Identity(caller_id=caller, allowed_tools=tools)


def _load_hmac_key() -> bytes | None:
    raw = os.environ.get("SECURE_MCP_AUDIT_HMAC_KEY")
    if not raw or raw.startswith("__"):
        return None
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return raw.encode("utf-8")


def _load_dlp_mode() -> str:
    mode = os.environ.get("SECURE_MCP_DLP_MODE", "redact").lower()
    if mode not in {"block", "redact", "flag"}:
        raise ConfigError(f"SECURE_MCP_DLP_MODE must be block|redact|flag, got '{mode}'")
    return mode


def load_settings() -> Settings:
    """Load settings from environment. Real keys MUST be injected by the
    secrets manager (Vault / KMS) into env at process start — never hardcoded."""
    identity = _load_identity(_require_env("SECURE_MCP_IDENTITY_FILE"))
    # ThreatCloud key is optional: only required if a threat_intel/url_category/
    # anti_phishing scope is granted. Validated at adapter use, not here, so a
    # TE-only or ai_guard-only deployment doesn't need it.
    tc_key = os.environ.get("CHECKPOINT_TC_API_KEY", "")
    return Settings(
        identity=identity,
        checkpoint_te_base_url=_require_https(
            os.environ.get("CHECKPOINT_TE_BASE_URL", "https://te.checkpoint.com"),
            "CHECKPOINT_TE_BASE_URL",
        ),
        checkpoint_te_api_key=_require_env("CHECKPOINT_TE_API_KEY"),
        lakera_guard_base_url=_require_https(
            os.environ.get("LAKERA_GUARD_BASE_URL", "https://api.lakera.ai"),
            "LAKERA_GUARD_BASE_URL",
        ),
        lakera_guard_api_key=_require_env("LAKERA_GUARD_API_KEY"),
        audit_log_path=Path(_require_env("SECURE_MCP_AUDIT_LOG_PATH")),
        upload_dir=Path(_require_env("SECURE_MCP_UPLOAD_DIR")),
        max_upload_bytes=int(os.environ.get("SECURE_MCP_MAX_UPLOAD_BYTES", "33554432")),
        rate_limit_per_minute=int(os.environ.get("SECURE_MCP_RATE_LIMIT_PER_MIN", "60")),
        dlp_mode=_load_dlp_mode(),
        audit_hmac_key=_load_hmac_key(),
        daily_quota=int(os.environ.get("SECURE_MCP_DAILY_QUOTA", "0")),
        threatcloud_base_url=_require_https(
            os.environ.get("CHECKPOINT_TC_BASE_URL", "https://rep.checkpoint.com"),
            "CHECKPOINT_TC_BASE_URL",
        ),
        threatcloud_api_key=tc_key,
    )

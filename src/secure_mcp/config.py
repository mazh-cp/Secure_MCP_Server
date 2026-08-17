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


def _load_dlp_mode(override: str | None) -> str:
    mode = (override or os.environ.get("SECURE_MCP_DLP_MODE", "redact")).lower()
    if mode not in {"block", "redact", "flag"}:
        raise ConfigError(f"DLP mode must be block|redact|flag, got '{mode}'")
    return mode


def _load_op_overrides() -> dict:
    """Operational config written by the admin console (SECURE_MCP_CONFIG_FILE).
    When present, these values take precedence over env for the operational
    knobs (dlp_mode, daily_quota, rate_limit_per_minute). Secrets are never
    sourced from this file — only from env/Vault."""
    path = os.environ.get("SECURE_MCP_CONFIG_FILE")
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (ValueError, OSError) as e:
        raise ConfigError(f"invalid SECURE_MCP_CONFIG_FILE: {e}") from e
    allowed = {"dlp_mode", "daily_quota", "rate_limit_per_minute"}
    return {k: v for k, v in data.items() if k in allowed}


def _load_keystore():
    """Optional encrypted keystore (local provisioning). None when no master key
    is configured — then secrets come from env/Vault only."""
    from .keystore import SecretKeystore, load_master_key
    mk = load_master_key()
    if not mk:
        return None
    path = os.environ.get("SECURE_MCP_KEYSTORE_PATH", "/etc/secure-mcp/secrets.enc")
    return SecretKeystore(Path(path), mk)


def _resolve_secret(name: str, env_name: str, ks) -> str | None:
    """Precedence: env var (Vault-injected) > encrypted keystore."""
    val = os.environ.get(env_name)
    if val and not val.startswith("__"):
        return val
    if ks is not None:
        return ks.get(name)
    return None


def _require_secret(name: str, env_name: str, ks) -> str:
    v = _resolve_secret(name, env_name, ks)
    if not v:
        raise ConfigError(f"secret '{name}' not found in env ({env_name}) or keystore")
    return v


# Scopes that need broker upstream keys. Guard-only identities (mcp_proxy alone)
# skip TE/Lakera so Cursor can run secure-mcp-guard without dual TE exposure.
_TE_SCOPES = frozenset({"threat_emulation", "file_sandboxing"})
_LAKERA_SCOPES = frozenset({"ai_guard"})


def load_settings() -> Settings:
    """Load settings from environment, with an optional encrypted keystore
    fallback for upstream API keys. Keys are never hardcoded — they come from
    the secrets manager (env/Vault) or the AES-256-GCM keystore."""
    identity = _load_identity(_require_env("SECURE_MCP_IDENTITY_FILE"))
    ks = _load_keystore()
    granted = identity.allowed_tools
    # ThreatCloud key is optional: only required if a threat_intel/url_category/
    # anti_phishing scope is granted (checked in build_server).
    tc_key = _resolve_secret("checkpoint_tc", "CHECKPOINT_TC_API_KEY", ks) or ""
    te_key = (
        _require_secret("checkpoint_te", "CHECKPOINT_TE_API_KEY", ks)
        if granted & _TE_SCOPES
        else (_resolve_secret("checkpoint_te", "CHECKPOINT_TE_API_KEY", ks) or "")
    )
    lakera_key = (
        _require_secret("lakera_guard", "LAKERA_GUARD_API_KEY", ks)
        if granted & _LAKERA_SCOPES
        else (_resolve_secret("lakera_guard", "LAKERA_GUARD_API_KEY", ks) or "")
    )
    op = _load_op_overrides()
    return Settings(
        identity=identity,
        checkpoint_te_base_url=_require_https(
            os.environ.get("CHECKPOINT_TE_BASE_URL", "https://te.checkpoint.com"),
            "CHECKPOINT_TE_BASE_URL",
        ),
        checkpoint_te_api_key=te_key,
        lakera_guard_base_url=_require_https(
            os.environ.get("LAKERA_GUARD_BASE_URL", "https://api.lakera.ai"),
            "LAKERA_GUARD_BASE_URL",
        ),
        lakera_guard_api_key=lakera_key,
        audit_log_path=Path(_require_env("SECURE_MCP_AUDIT_LOG_PATH")),
        upload_dir=Path(_require_env("SECURE_MCP_UPLOAD_DIR")),
        max_upload_bytes=int(os.environ.get("SECURE_MCP_MAX_UPLOAD_BYTES", "33554432")),
        rate_limit_per_minute=int(op.get("rate_limit_per_minute",
                                  os.environ.get("SECURE_MCP_RATE_LIMIT_PER_MIN", "60"))),
        dlp_mode=_load_dlp_mode(op.get("dlp_mode")),
        audit_hmac_key=_load_hmac_key(),
        daily_quota=int(op.get("daily_quota",
                        os.environ.get("SECURE_MCP_DAILY_QUOTA", "0"))),
        threatcloud_base_url=_require_https(
            os.environ.get("CHECKPOINT_TC_BASE_URL", "https://rep.checkpoint.com"),
            "CHECKPOINT_TC_BASE_URL",
        ),
        threatcloud_api_key=tc_key,
    )

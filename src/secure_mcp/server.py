from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .adapters.checkpoint_te import CheckpointTEClient
from .adapters.lakera_guard import LakeraGuardClient
from .adapters.threatcloud import ThreatCloudClient
from .audit import AuditLogger
from .config import ConfigError, Settings, load_settings
from .context import ToolContext
from .dlp import DLPScanner
from .logger import get_logger
from .quota import DailyQuota
from .rate_limit import ScopedRateLimiter
from .tools import (
    ai_guard,
    anti_phishing,
    file_sandboxing,
    threat_emulation,
    threat_intel,
    url_category,
)

# Scopes that require a ThreatCloud client + key.
_THREATCLOUD_SCOPES = frozenset({"threat_intel", "url_category", "anti_phishing"})


def build_server() -> FastMCP:
    settings = load_settings()
    log = get_logger()
    granted = settings.identity.allowed_tools
    log.info(
        "starting secure-mcp",
        extra={
            "caller_id": settings.identity.caller_id,
            "scopes": sorted(granted),
            "dlp_mode": settings.dlp_mode,
            "audit_tamper_evident": settings.audit_hmac_key is not None,
            "daily_quota": settings.daily_quota,
            "rate_limit_per_min": settings.rate_limit_per_minute,
        },
    )
    if settings.audit_hmac_key is None:
        log.warning("audit log running without HMAC key — chain integrity is "
                    "best-effort; set SECURE_MCP_AUDIT_HMAC_KEY for tamper evidence")

    ctx = ToolContext(
        settings=settings,
        audit=AuditLogger(settings.audit_log_path, settings.identity.caller_id,
                          hmac_key=settings.audit_hmac_key),
        rate=ScopedRateLimiter(per_minute=settings.rate_limit_per_minute),
        quota=DailyQuota(daily_limit=settings.daily_quota),
        dlp=DLPScanner(mode=settings.dlp_mode),
    )

    te = CheckpointTEClient(settings.checkpoint_te_base_url, settings.checkpoint_te_api_key)
    lakera = LakeraGuardClient(settings.lakera_guard_base_url, settings.lakera_guard_api_key)

    mcp = FastMCP("secure-broker")
    threat_emulation.register(mcp, ctx, te)
    file_sandboxing.register(mcp, ctx, te)
    ai_guard.register(mcp, ctx, lakera)

    # Coverage tools only wire up if their scope is granted — keeps the
    # ThreatCloud key requirement off TE-only / ai_guard-only deployments.
    if granted & _THREATCLOUD_SCOPES:
        if not settings.threatcloud_api_key:
            raise ConfigError(
                "a threat_intel/url_category/anti_phishing scope is granted but "
                "CHECKPOINT_TC_API_KEY is not set"
            )
        tc = ThreatCloudClient(settings.threatcloud_base_url, settings.threatcloud_api_key)
        if "threat_intel" in granted:
            threat_intel.register(mcp, ctx, tc)
        if "url_category" in granted:
            url_category.register(mcp, ctx, tc)
        if "anti_phishing" in granted:
            anti_phishing.register(mcp, ctx, tc)

    log.info("registered tools", extra={"scopes": sorted(granted)})
    return mcp


def main() -> None:
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()

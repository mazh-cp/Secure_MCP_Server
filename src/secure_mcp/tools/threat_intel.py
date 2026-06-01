from __future__ import annotations

from typing import Any

from ..adapters.threatcloud import ThreatCloudClient
from ..context import ToolContext
from ..validation import validate_domain, validate_hash, validate_ip, validate_url


SCOPE = "threat_intel"


def register(mcp: Any, ctx: ToolContext, tc: ThreatCloudClient) -> None:
    @mcp.tool()
    def lookup_ip(ip: str) -> dict[str, Any]:
        """ThreatCloud reputation for an IP address."""
        try:
            ctx.preflight(SCOPE)
            clean = validate_ip(ip)
            result = tc.lookup_ip(clean)
        except Exception as e:
            ctx.audit.record(tool=SCOPE, action="lookup_ip", result="error",
                             details={"error_type": type(e).__name__})
            raise
        ctx.audit.record(tool=SCOPE, action="lookup_ip", result="ok", details={"ip": clean})
        return result

    @mcp.tool()
    def lookup_domain(domain: str) -> dict[str, Any]:
        """ThreatCloud reputation for a domain."""
        try:
            ctx.preflight(SCOPE)
            clean = validate_domain(domain)
            result = tc.lookup_domain(clean)
        except Exception as e:
            ctx.audit.record(tool=SCOPE, action="lookup_domain", result="error",
                             details={"error_type": type(e).__name__})
            raise
        ctx.audit.record(tool=SCOPE, action="lookup_domain", result="ok", details={"domain": clean})
        return result

    @mcp.tool()
    def lookup_url(url: str) -> dict[str, Any]:
        """ThreatCloud reputation for a URL."""
        try:
            ctx.preflight(SCOPE)
            clean = validate_url(url)
            result = tc.lookup_url(clean)
        except Exception as e:
            ctx.audit.record(tool=SCOPE, action="lookup_url", result="error",
                             details={"error_type": type(e).__name__})
            raise
        ctx.audit.record(tool=SCOPE, action="lookup_url", result="ok", details={"url": clean})
        return result

    @mcp.tool()
    def lookup_hash(file_hash: str) -> dict[str, Any]:
        """ThreatCloud reputation for a file hash (md5/sha1/sha256)."""
        try:
            ctx.preflight(SCOPE)
            clean = validate_hash(file_hash)
            result = tc.lookup_hash(clean)
        except Exception as e:
            ctx.audit.record(tool=SCOPE, action="lookup_hash", result="error",
                             details={"error_type": type(e).__name__})
            raise
        ctx.audit.record(tool=SCOPE, action="lookup_hash", result="ok", details={"hash": clean})
        return result

from __future__ import annotations

from typing import Any

from ..adapters.threatcloud import ThreatCloudClient
from ..context import ToolContext
from ..validation import validate_url


SCOPE = "url_category"


def register(mcp: Any, ctx: ToolContext, tc: ThreatCloudClient) -> None:
    @mcp.tool()
    def categorize_url(url: str) -> dict[str, Any]:
        """Return the URL Filtering category and risk class for a URL —
        lightweight allow/warn/block decision without full emulation."""
        try:
            ctx.preflight(SCOPE)
            clean = validate_url(url)
            result = tc.categorize_url(clean)
        except Exception as e:
            ctx.audit.record(tool=SCOPE, action="categorize_url", result="error",
                             details={"error_type": type(e).__name__})
            raise
        ctx.audit.record(tool=SCOPE, action="categorize_url", result="ok", details={"url": clean})
        return result

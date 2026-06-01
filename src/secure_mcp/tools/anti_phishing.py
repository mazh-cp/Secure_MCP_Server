from __future__ import annotations

from typing import Any

from ..adapters.threatcloud import ThreatCloudClient
from ..context import ToolContext
from ..validation import validate_url


SCOPE = "anti_phishing"


def register(mcp: Any, ctx: ToolContext, tc: ThreatCloudClient) -> None:
    @mcp.tool()
    def score_url(url: str) -> dict[str, Any]:
        """Zero-Phishing ML score for a URL. URL only — to keep page content
        within the trust boundary, render-time HTML scoring is intentionally
        not exposed here (that would be a separate egress decision)."""
        try:
            ctx.preflight(SCOPE)
            clean = validate_url(url)
            result = tc.score_url(clean)
        except Exception as e:
            ctx.audit.record(tool=SCOPE, action="score_url", result="error",
                             details={"error_type": type(e).__name__})
            raise
        ctx.audit.record(tool=SCOPE, action="score_url", result="ok", details={"url": clean})
        return result

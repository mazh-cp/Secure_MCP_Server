from __future__ import annotations

from typing import Any

from ..adapters.lakera_guard import LakeraGuardClient
from ..context import ToolContext
from ..dlp import DLPFinding
from ..validation import validate_text


SCOPE = "ai_guard"


def _findings_payload(findings: list[DLPFinding]) -> list[dict[str, Any]]:
    return [{"type": f.type, "count": f.count} for f in findings]


def register(mcp: Any, ctx: ToolContext, lakera: LakeraGuardClient) -> None:
    @mcp.tool()
    def screen_prompt(text: str) -> dict[str, Any]:
        """Screen an LLM prompt for injection / jailbreak attempts.

        DLP runs first on the broker: secrets/PII are redacted (or the call is
        blocked) BEFORE any text crosses the boundary to Lakera. Text-only —
        never pass files, telemetry, or threat intel."""
        try:
            ctx.preflight(SCOPE)
            clean = validate_text(text)
            guarded, findings = ctx.dlp.apply(clean)
            result = lakera.screen_prompt(guarded)
        except Exception as e:
            ctx.audit.record(tool=SCOPE, action="screen_prompt", result="error",
                             details={"error_type": type(e).__name__})
            raise
        ctx.audit.record(tool=SCOPE, action="screen_prompt", result="ok",
                         details={"text_len": len(guarded), "dlp": _findings_payload(findings)})
        return result

    @mcp.tool()
    def screen_output(text: str) -> dict[str, Any]:
        """Screen an LLM output for PII, moderation issues, and data-leak signals."""
        try:
            ctx.preflight(SCOPE)
            clean = validate_text(text)
            guarded, findings = ctx.dlp.apply(clean)
            result = lakera.screen_output(guarded)
        except Exception as e:
            ctx.audit.record(tool=SCOPE, action="screen_output", result="error",
                             details={"error_type": type(e).__name__})
            raise
        ctx.audit.record(tool=SCOPE, action="screen_output", result="ok",
                         details={"text_len": len(guarded), "dlp": _findings_payload(findings)})
        return result

    @mcp.tool()
    def screen_payload(text: str, policy_id: str) -> dict[str, Any]:
        """Screen text against a named Lakera Guard policy."""
        try:
            ctx.preflight(SCOPE)
            clean = validate_text(text)
            if not isinstance(policy_id, str) or not policy_id or len(policy_id) > 64:
                raise ValueError("invalid policy_id")
            guarded, findings = ctx.dlp.apply(clean)
            result = lakera.screen_payload(guarded, policy_id)
        except Exception as e:
            ctx.audit.record(tool=SCOPE, action="screen_payload", result="error",
                             details={"error_type": type(e).__name__})
            raise
        ctx.audit.record(tool=SCOPE, action="screen_payload", result="ok",
                         details={"text_len": len(guarded), "policy_id": policy_id,
                                  "dlp": _findings_payload(findings)})
        return result

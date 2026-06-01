from __future__ import annotations

from typing import Any

from ..adapters.checkpoint_te import CheckpointTEClient
from ..context import ToolContext
from ..validation import validate_sha256, validate_upload_path, validate_url


SCOPE = "threat_emulation"


def register(mcp: Any, ctx: ToolContext, te: CheckpointTEClient) -> None:
    @mcp.tool()
    def emulate_file(file_ref: str, features: list[str] | None = None) -> dict[str, Any]:
        """Detonate a file in Check Point's Threat Emulation cloud sandbox."""
        try:
            ctx.preflight(SCOPE)
            path = validate_upload_path(
                file_ref, base_dir=ctx.settings.upload_dir, max_bytes=ctx.settings.max_upload_bytes,
            )
            feats = [str(f) for f in (features or [])]
            result = te.emulate_file(str(path), feats)
        except Exception as e:
            ctx.audit.record(tool=SCOPE, action="emulate_file", result="error",
                             details={"error_type": type(e).__name__})
            raise
        ctx.audit.record(tool=SCOPE, action="emulate_file", result="ok",
                         details={"file_ref": file_ref, "features": feats})
        return result

    @mcp.tool()
    def query_verdict(sha256: str) -> dict[str, Any]:
        """Look up a cached TE verdict by file sha256."""
        try:
            ctx.preflight(SCOPE)
            digest = validate_sha256(sha256)
            result = te.query_verdict(digest)
        except Exception as e:
            ctx.audit.record(tool=SCOPE, action="query_verdict", result="error",
                             details={"error_type": type(e).__name__})
            raise
        ctx.audit.record(tool=SCOPE, action="query_verdict", result="ok",
                         details={"sha256": digest})
        return result

    @mcp.tool()
    def emulate_url(url: str) -> dict[str, Any]:
        """Detonate a URL in Check Point's Threat Emulation cloud sandbox."""
        try:
            ctx.preflight(SCOPE)
            clean = validate_url(url)
            result = te.emulate_url(clean)
        except Exception as e:
            ctx.audit.record(tool=SCOPE, action="emulate_url", result="error",
                             details={"error_type": type(e).__name__})
            raise
        ctx.audit.record(tool=SCOPE, action="emulate_url", result="ok",
                         details={"url": clean})
        return result

from __future__ import annotations

from typing import Any

from ..adapters.checkpoint_te import CheckpointTEClient
from ..context import ToolContext
from ..validation import validate_upload_path


SCOPE = "file_sandboxing"


def register(mcp: Any, ctx: ToolContext, te: CheckpointTEClient) -> None:
    @mcp.tool()
    def submit_file(file_ref: str, te_options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Submit a file for deep sandbox detonation across configured OS images."""
        try:
            ctx.preflight(SCOPE)
            path = validate_upload_path(
                file_ref, base_dir=ctx.settings.upload_dir, max_bytes=ctx.settings.max_upload_bytes,
            )
            opts = te_options or {}
            result = te.emulate_file(str(path), list(opts.get("features", [])))
        except Exception as e:
            ctx.audit.record(tool=SCOPE, action="submit_file", result="error",
                             details={"error_type": type(e).__name__})
            raise
        ctx.audit.record(tool=SCOPE, action="submit_file", result="ok",
                         details={"file_ref": file_ref})
        return result

    @mcp.tool()
    def extract_threats(file_ref: str) -> dict[str, Any]:
        """Threat extraction (CDR) — submit a file for sanitization."""
        try:
            ctx.preflight(SCOPE)
            path = validate_upload_path(
                file_ref, base_dir=ctx.settings.upload_dir, max_bytes=ctx.settings.max_upload_bytes,
            )
            result = te.extract_threats(str(path))
        except Exception as e:
            ctx.audit.record(tool=SCOPE, action="extract_threats", result="error",
                             details={"error_type": type(e).__name__})
            raise
        ctx.audit.record(tool=SCOPE, action="extract_threats", result="ok",
                         details={"file_ref": file_ref})
        return result

    @mcp.tool()
    def get_report(job_id: str) -> dict[str, Any]:
        """Fetch the full forensic report for a submitted sandbox job."""
        try:
            ctx.preflight(SCOPE)
            if not isinstance(job_id, str) or not job_id or len(job_id) > 128:
                raise ValueError("invalid job_id")
            result = te.get_report(job_id)
        except Exception as e:
            ctx.audit.record(tool=SCOPE, action="get_report", result="error",
                             details={"error_type": type(e).__name__})
            raise
        ctx.audit.record(tool=SCOPE, action="get_report", result="ok",
                         details={"job_id": job_id})
        return result

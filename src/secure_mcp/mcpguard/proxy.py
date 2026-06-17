"""Policy-enforcing MCP gateway.

Turns the broker into a control plane in FRONT of arbitrary upstream MCP servers:
every tool call from any client (Claude, Cursor, in-browser agents, ...) passes
through the same gate as our own tools —

    authorize(scope) → quota → rate → DLP on outbound args → forward →
    injection + DLP screen on response → tamper-evident audit

and every advertised tool descriptor is screened for poisoning at registration.
No browser-bound competitor sits at this layer.

The Forwarder is injectable: tests pass a fake; production wires it to a real
MCP client transport (stdio/HTTP). The gate logic — the differentiator — is
fully exercised regardless.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from ..context import ToolContext
from ..dlp import DLPFinding, sanitize as dlp_sanitize
from .injection import RISK_MALICIOUS, screen_tool_descriptor, screen_tool_response

SCOPE = "mcp_proxy"


class GuardBlocked(RuntimeError):
    pass


class Forwarder(Protocol):
    def list_tools(self, server: str) -> list[dict[str, Any]]: ...
    def call(self, server: str, tool: str, args: dict[str, Any]) -> Any: ...


def _redact_args(obj: Any) -> tuple[Any, list[DLPFinding]]:
    """Recursively redact secrets in string leaves of the outbound arguments,
    preserving structure. Returns (redacted, findings)."""
    findings: list[DLPFinding] = []

    def rec(x: Any) -> Any:
        if isinstance(x, str):
            clean, f = dlp_sanitize(x)
            findings.extend(f)
            return clean
        if isinstance(x, dict):
            return {k: rec(v) for k, v in x.items()}
        if isinstance(x, list):
            return [rec(v) for v in x]
        return x

    return rec(obj), findings


class MCPGuard:
    def __init__(self, ctx: ToolContext, forwarder: Forwarder, *,
                 block_risks: tuple[str, ...] = (RISK_MALICIOUS,)) -> None:
        self._ctx = ctx
        self._fwd = forwarder
        self._block = set(block_risks)

    def list_tools(self, server: str) -> list[dict[str, Any]]:
        """Enumerate an upstream's tools, screening each descriptor for poisoning.
        Poisoned descriptors are flagged not-allowed (and audited)."""
        out: list[dict[str, Any]] = []
        for t in self._fwd.list_tools(server):
            name = str(t.get("name", ""))
            verdict = screen_tool_descriptor(name, str(t.get("description", "")), t.get("inputSchema"))
            allowed = verdict["risk"] not in self._block
            self._ctx.audit.record(
                tool="mcp_guard", action="register_tool",
                result="ok" if allowed else "blocked",
                details={"server": server, "tool": name, "risk": verdict["risk"],
                         "signals": verdict["signals"]})
            out.append({"name": name, "description": t.get("description"),
                        "risk": verdict["risk"], "allowed": allowed})
        return out

    def call(self, server: str, tool: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            self._ctx.preflight(SCOPE)
            redacted, arg_findings = _redact_args(args or {})
            mode = self._ctx.dlp.mode
            if arg_findings and mode == "block":
                raise GuardBlocked("outbound arguments contain secrets (DLP block mode)")
            args_to_send = redacted if (arg_findings and mode == "redact") else (args or {})
            resp = self._fwd.call(server, tool, args_to_send)
            resp_text = resp if isinstance(resp, str) else json.dumps(resp, ensure_ascii=False, default=str)
            screen = screen_tool_response(resp_text)
        except Exception as e:
            self._ctx.audit.record(tool="mcp_guard", action="call", result="error",
                                   details={"server": server, "tool": tool,
                                            "error_type": type(e).__name__})
            raise
        blocked = screen["risk"] in self._block
        self._ctx.audit.record(
            tool="mcp_guard", action="call", result="blocked" if blocked else "ok",
            details={"server": server, "tool": tool, "response_risk": screen["risk"],
                     "response_signals": screen["signals"], "response_dlp": screen["dlp"],
                     "args_dlp": [{"type": f.type, "count": f.count} for f in arg_findings]})
        if blocked:
            raise GuardBlocked(
                f"response from {server}.{tool} blocked: {screen['risk']} "
                f"({', '.join(screen['signals']) or 'dlp'})")
        return {"result": resp, "screen": screen,
                "args_redacted": bool(arg_findings and mode == "redact")}

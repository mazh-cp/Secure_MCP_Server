from __future__ import annotations

import json
import os
import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit import AuditLogger
from ..auth import require_scope
from ..config import load_settings
from ..context import ToolContext
from ..dlp import DLPScanner
from ..logger import get_logger
from ..quota import DailyQuota
from ..rate_limit import ScopedRateLimiter
from .forwarder import MCPForwarder
from .injection import screen_tool_descriptor, screen_tool_response
from .proxy import SCOPE, MCPGuard

_log = get_logger("secure_mcp.guard")

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_env_value(value: str) -> str:
    """Expand ${VAR} placeholders from the process environment."""
    def repl(m: re.Match[str]) -> str:
        return os.environ.get(m.group(1), "")
    return _ENV_REF.sub(repl, value)


def _prepare_registry(data: dict) -> dict:
    """Expand env placeholders and merge stdio env with the parent environment
    so upstream @chkp/* processes inherit PATH/HOME while receiving API keys."""
    out: dict[str, Any] = {}
    for name, spec in data.items():
        if not isinstance(spec, dict):
            continue
        entry = dict(spec)
        if "env" in entry and isinstance(entry["env"], dict):
            expanded = {k: _expand_env_value(str(v)) for k, v in entry["env"].items()}
            entry["env"] = {**os.environ, **expanded}
        if "headers" in entry and isinstance(entry["headers"], dict):
            entry["headers"] = {k: _expand_env_value(str(v)) for k, v in entry["headers"].items()}
        out[name] = entry
    return out


def _load_registry() -> dict | None:
    """Upstream MCP servers the guard may proxy. JSON file at
    SECURE_MCP_GUARD_REGISTRY: { "<name>": {"command": "...", "args": [...]} }."""
    path = os.environ.get("SECURE_MCP_GUARD_REGISTRY")
    if not path or not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or not data:
        return None
    return _prepare_registry(data)


class _UnwiredForwarder:
    """Transport boundary. Wire this to a real MCP client (stdio/HTTP) to enable
    transparent proxying of registered upstream servers. Until then, the two
    screening tools work standalone (no upstream needed)."""

    def __init__(self, registry: tuple[str, ...]) -> None:
        self._registry = registry

    def _check(self, server: str) -> None:
        if self._registry and server not in self._registry:
            raise ValueError(f"server '{server}' is not in SECURE_MCP_GUARD_UPSTREAMS")
        raise NotImplementedError(
            f"MCP forwarder not wired for '{server}' — see docs/MCP-GUARD.md. "
            "The guard gate and screening are active; only the upstream transport is pending.")

    def list_tools(self, server: str) -> list[dict[str, Any]]:
        self._check(server)
        return []

    def call(self, server: str, tool: str, args: dict[str, Any]) -> Any:
        self._check(server)
        return None


def register_guard_tools(mcp: Any, ctx: ToolContext, guard: MCPGuard) -> None:
    @mcp.tool()
    def screen_tool(name: str, description: str, schema: dict[str, Any] | None = None) -> dict[str, Any]:
        """Screen an MCP tool's descriptor (name/description/schema) for
        prompt-injection / tool-poisoning BEFORE an agent is allowed to trust it."""
        require_scope(ctx.settings, SCOPE)
        ctx.rate.check(SCOPE)
        v = screen_tool_descriptor(name, description, schema)
        ctx.audit.record(tool="mcp_guard", action="screen_tool", result="ok",
                         details={"name": name, "risk": v["risk"], "signals": v["signals"]})
        return v

    @mcp.tool()
    def screen_response(text: str) -> dict[str, Any]:
        """Screen a tool/agent response for injected instructions and leaked secrets."""
        require_scope(ctx.settings, SCOPE)
        ctx.rate.check(SCOPE)
        v = screen_tool_response(text)
        ctx.audit.record(tool="mcp_guard", action="screen_response", result="ok",
                         details={"risk": v["risk"], "signals": v["signals"], "dlp": v["dlp"]})
        return v

    @mcp.tool()
    def guard_list_tools(server: str) -> list[dict[str, Any]]:
        """List a registered upstream MCP server's tools, screening each descriptor."""
        return guard.list_tools(server)

    @mcp.tool()
    def guard_call(server: str, tool: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        """Call a tool on a registered upstream MCP server through the full policy
        gate (authz, quota, rate, outbound-arg DLP, response injection+DLP screen, audit)."""
        return guard.call(server, tool, args)


def build_guard_server(forwarder: Any = None) -> FastMCP:
    settings = load_settings()
    audit = AuditLogger(settings.audit_log_path, settings.identity.caller_id,
                        hmac_key=settings.audit_hmac_key)
    ctx = ToolContext(
        settings=settings,
        audit=audit,
        rate=ScopedRateLimiter(per_minute=settings.rate_limit_per_minute),
        quota=DailyQuota(daily_limit=settings.daily_quota),
        dlp=DLPScanner(mode=settings.dlp_mode),
    )
    if forwarder is None:
        registry = _load_registry()
        if registry:
            forwarder = MCPForwarder(registry)
            upstreams = list(registry)
        else:
            legacy = tuple(s.strip() for s in os.environ.get("SECURE_MCP_GUARD_UPSTREAMS", "").split(",") if s.strip())
            forwarder = _UnwiredForwarder(legacy)
            upstreams = "none-wired"
    else:
        upstreams = "injected"
    guard = MCPGuard(ctx, forwarder)
    _log.info("starting secure-mcp-guard", extra={"caller_id": settings.identity.caller_id,
                                                   "upstreams": upstreams,
                                                   "dlp_mode": settings.dlp_mode})
    mcp = FastMCP("secure-mcp-guard")
    register_guard_tools(mcp, ctx, guard)
    return mcp


def main() -> None:
    build_guard_server().run(transport="stdio")


if __name__ == "__main__":
    main()

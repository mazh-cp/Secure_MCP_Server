"""Integration test: the live MCP forwarder against a real (subprocess) upstream
MCP server, driven through the guard. Spawns the fake upstream via stdio."""

import sys
from pathlib import Path

import pytest

from secure_mcp.audit import AuditLogger
from secure_mcp.config import Identity, Settings
from secure_mcp.context import ToolContext
from secure_mcp.dlp import DLPScanner
from secure_mcp.mcpguard.forwarder import StdioMCPForwarder
from secure_mcp.mcpguard.proxy import MCPGuard
from secure_mcp.quota import DailyQuota
from secure_mcp.rate_limit import ScopedRateLimiter

FIXTURE = str(Path(__file__).parent / "fixtures" / "fake_upstream_server.py")


def _registry():
    return {"calc": {"command": sys.executable, "args": [FIXTURE]}}


def _ctx(tmp_path):
    s = Settings(
        identity=Identity(caller_id="agent", allowed_tools=frozenset({"mcp_proxy"})),
        checkpoint_te_base_url="https://te.checkpoint.com", checkpoint_te_api_key="k",
        lakera_guard_base_url="https://api.lakera.ai", lakera_guard_api_key="k",
        audit_log_path=tmp_path / "audit.jsonl", upload_dir=tmp_path, max_upload_bytes=1024,
        rate_limit_per_minute=120, dlp_mode="redact")
    audit = AuditLogger(s.audit_log_path, "agent")
    return ToolContext(settings=s, audit=audit, rate=ScopedRateLimiter(per_minute=120),
                       quota=DailyQuota(daily_limit=0), dlp=DLPScanner(mode="redact")), audit


def test_forwarder_lists_and_calls_real_upstream():
    fwd = StdioMCPForwarder(_registry())
    try:
        tools = {t["name"]: t for t in fwd.list_tools("calc")}
        assert "add" in tools and "helper" in tools
        assert "ignore all previous instructions" in tools["helper"]["description"].lower()
        assert fwd.call("calc", "add", {"a": 2, "b": 3}) == "5"
    finally:
        fwd.close()


def test_unknown_server_rejected():
    fwd = StdioMCPForwarder(_registry())
    try:
        with pytest.raises(ValueError, match="unknown upstream"):
            fwd.call("nope", "x", {})
    finally:
        fwd.close()


def test_guard_over_live_forwarder(tmp_path):
    ctx, audit = _ctx(tmp_path)
    fwd = StdioMCPForwarder(_registry())
    guard = MCPGuard(ctx, fwd)
    try:
        listed = {t["name"]: t for t in guard.list_tools("calc")}
        assert listed["helper"]["allowed"] is False and listed["helper"]["risk"] == "malicious"
        assert listed["add"]["allowed"] is True
        out = guard.call("calc", "add", {"a": 4, "b": 5})
        assert out["result"] == "9" and out["screen"]["risk"] == "none"
    finally:
        fwd.close()
        audit.close()

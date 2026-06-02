import asyncio
import json
from pathlib import Path

import pytest

from secure_mcp.config import ConfigError
from secure_mcp.server import build_server


@pytest.fixture(autouse=True)
def _no_real_dns(monkeypatch):
    """build_server() constructs real SecureHTTPClients, which resolve the
    upstream hosts via getaddrinfo. Stub it to a public IP so these tests are
    hermetic (no network, no DNS flakiness)."""
    import secure_mcp.http_client as hc
    monkeypatch.setattr(hc.socket, "getaddrinfo",
                        lambda host, port, *a, **k: [(0, 0, 0, "", ("93.184.216.34", port or 0))])


def _env(monkeypatch, tmp_path: Path, scopes: list[str], **extra):
    identity = tmp_path / "identity.json"
    identity.write_text(json.dumps({"caller_id": "t", "allowed_tools": scopes}))
    upload = tmp_path / "uploads"
    upload.mkdir(exist_ok=True)
    monkeypatch.setenv("SECURE_MCP_IDENTITY_FILE", str(identity))
    monkeypatch.setenv("CHECKPOINT_TE_API_KEY", "dummy")
    monkeypatch.setenv("LAKERA_GUARD_API_KEY", "dummy")
    monkeypatch.setenv("SECURE_MCP_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SECURE_MCP_UPLOAD_DIR", str(upload))
    monkeypatch.delenv("CHECKPOINT_TC_API_KEY", raising=False)
    monkeypatch.delenv("SECURE_MCP_AUDIT_HMAC_KEY", raising=False)
    for k, v in extra.items():
        monkeypatch.setenv(k, v)


def _tool_names(srv) -> set[str]:
    return {t.name for t in asyncio.run(srv.list_tools())}


def test_te_only_deployment_does_not_require_tc_key(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path, ["threat_emulation"])
    srv = build_server()
    names = _tool_names(srv)
    assert "query_verdict" in names
    assert "lookup_ip" not in names  # coverage tools not wired


def test_threatcloud_scope_without_key_fails_closed(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path, ["threat_intel"])  # no CHECKPOINT_TC_API_KEY
    with pytest.raises(ConfigError, match="CHECKPOINT_TC_API_KEY"):
        build_server()


def test_threatcloud_scope_with_key_registers_coverage(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path, ["threat_intel", "url_category"],
         CHECKPOINT_TC_API_KEY="dummy")
    names = _tool_names(build_server())
    assert {"lookup_ip", "lookup_domain", "lookup_url", "lookup_hash", "categorize_url"} <= names
    assert "score_url" not in names  # anti_phishing scope not granted


def test_invalid_dlp_mode_fails_closed(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path, ["ai_guard"], SECURE_MCP_DLP_MODE="nonsense")
    with pytest.raises(ConfigError, match="DLP mode"):
        build_server()

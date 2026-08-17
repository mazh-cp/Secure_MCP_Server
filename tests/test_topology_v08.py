"""Tests for guard registry env expansion and guard-only settings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secure_mcp.config import ConfigError, load_settings
from secure_mcp.mcpguard.server import _expand_env_value, _prepare_registry


def test_expand_env_value(monkeypatch):
    monkeypatch.setenv("FOO", "bar")
    assert _expand_env_value("pre-${FOO}-post") == "pre-bar-post"
    assert _expand_env_value("missing-${NO_SUCH_VAR}-x") == "missing--x"


def test_prepare_registry_merges_env(monkeypatch):
    monkeypatch.setenv("MGMT_KEY", "secret-value")
    monkeypatch.setenv("PATH", "/usr/bin")
    reg = _prepare_registry({
        "chkp-management": {
            "command": "npx",
            "args": ["-y", "@chkp/quantum-management-mcp"],
            "env": {"API_KEY": "${MGMT_KEY}", "TELEMETRY_DISABLED": "true"},
        }
    })
    env = reg["chkp-management"]["env"]
    assert env["API_KEY"] == "secret-value"
    assert env["TELEMETRY_DISABLED"] == "true"
    assert env["PATH"] == "/usr/bin"  # parent env preserved


def test_guard_only_identity_skips_te_lakera_keys(monkeypatch, tmp_path: Path):
    identity = tmp_path / "id.json"
    identity.write_text(json.dumps({"caller_id": "g", "allowed_tools": ["mcp_proxy"]}))
    upload = tmp_path / "up"
    upload.mkdir()
    monkeypatch.setenv("SECURE_MCP_IDENTITY_FILE", str(identity))
    monkeypatch.setenv("SECURE_MCP_AUDIT_LOG_PATH", str(tmp_path / "a.jsonl"))
    monkeypatch.setenv("SECURE_MCP_UPLOAD_DIR", str(upload))
    monkeypatch.delenv("CHECKPOINT_TE_API_KEY", raising=False)
    monkeypatch.delenv("LAKERA_GUARD_API_KEY", raising=False)
    s = load_settings()
    assert s.checkpoint_te_api_key == ""
    assert s.lakera_guard_api_key == ""


def test_broker_identity_still_requires_te_key(monkeypatch, tmp_path: Path):
    identity = tmp_path / "id.json"
    identity.write_text(json.dumps({
        "caller_id": "b", "allowed_tools": ["threat_emulation"],
    }))
    upload = tmp_path / "up"
    upload.mkdir()
    monkeypatch.setenv("SECURE_MCP_IDENTITY_FILE", str(identity))
    monkeypatch.setenv("SECURE_MCP_AUDIT_LOG_PATH", str(tmp_path / "a.jsonl"))
    monkeypatch.setenv("SECURE_MCP_UPLOAD_DIR", str(upload))
    monkeypatch.delenv("CHECKPOINT_TE_API_KEY", raising=False)
    monkeypatch.setenv("LAKERA_GUARD_API_KEY", "unused")
    with pytest.raises(ConfigError, match="checkpoint_te"):
        load_settings()

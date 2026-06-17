import json

import pytest

from secure_mcp.config import ConfigError, load_settings
from secure_mcp.keystore import SecretKeystore

MK = bytes(range(32))
NOW = "2026-01-01T00:00:00+00:00"


def _base_env(monkeypatch, tmp_path):
    identity = tmp_path / "id.json"
    identity.write_text(json.dumps({"caller_id": "c", "allowed_tools": ["ai_guard"]}))
    up = tmp_path / "up"; up.mkdir(exist_ok=True)
    monkeypatch.setenv("SECURE_MCP_IDENTITY_FILE", str(identity))
    monkeypatch.setenv("SECURE_MCP_AUDIT_LOG_PATH", str(tmp_path / "a.jsonl"))
    monkeypatch.setenv("SECURE_MCP_UPLOAD_DIR", str(up))
    for k in ("CHECKPOINT_TE_API_KEY", "LAKERA_GUARD_API_KEY", "CHECKPOINT_TC_API_KEY",
              "SECURE_MCP_KEYSTORE_MASTER_KEY", "SECURE_MCP_CONFIG_FILE"):
        monkeypatch.delenv(k, raising=False)


def _provision_keystore(tmp_path, monkeypatch):
    ks_path = tmp_path / "secrets.enc"
    ks = SecretKeystore(ks_path, MK)
    ks.set("checkpoint_te", "te-from-keystore", now_iso=NOW)
    ks.set("lakera_guard", "lk-from-keystore", now_iso=NOW)
    monkeypatch.setenv("SECURE_MCP_KEYSTORE_MASTER_KEY", MK.hex())
    monkeypatch.setenv("SECURE_MCP_KEYSTORE_PATH", str(ks_path))
    return ks


def test_keystore_supplies_upstream_keys(monkeypatch, tmp_path):
    _base_env(monkeypatch, tmp_path)
    _provision_keystore(tmp_path, monkeypatch)
    s = load_settings()
    assert s.checkpoint_te_api_key == "te-from-keystore"
    assert s.lakera_guard_api_key == "lk-from-keystore"


def test_env_takes_precedence_over_keystore(monkeypatch, tmp_path):
    _base_env(monkeypatch, tmp_path)
    _provision_keystore(tmp_path, monkeypatch)
    monkeypatch.setenv("CHECKPOINT_TE_API_KEY", "te-from-env")
    s = load_settings()
    assert s.checkpoint_te_api_key == "te-from-env"          # env wins
    assert s.lakera_guard_api_key == "lk-from-keystore"      # falls back to keystore


def test_missing_everywhere_fails_closed(monkeypatch, tmp_path):
    _base_env(monkeypatch, tmp_path)  # no env keys, no keystore
    with pytest.raises(ConfigError):
        load_settings()

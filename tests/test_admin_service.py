import json
from pathlib import Path

import pytest

from secure_mcp.admin.config import AdminConfig
from secure_mcp.admin.service import AdminService, AdminValidationError
from secure_mcp.audit import AuditLogger

KEY = b"admin-test-hmac-key"


def _cfg(tmp_path: Path, hmac_key=KEY) -> AdminConfig:
    idir = tmp_path / "identities"
    idir.mkdir(exist_ok=True)
    return AdminConfig(
        admin_token="tok",
        bind_host="127.0.0.1",
        bind_port=8765,
        tls_cert=None,
        tls_key=None,
        audit_log_path=tmp_path / "audit.jsonl",
        admin_audit_log_path=tmp_path / "admin-audit.jsonl",
        audit_hmac_key=hmac_key,
        identity_dir=idir,
        op_config_file=tmp_path / "config.json",
        te_base_url="https://te.checkpoint.com",
        tc_base_url="https://rep.checkpoint.com",
        lakera_base_url="https://api.lakera.ai",
        session_ttl_sec=1800,
        policy_dir=tmp_path / "policies",
        keys_dir=tmp_path / "keys",
    )


def test_upsert_and_list_identity(tmp_path):
    svc = AdminService(_cfg(tmp_path))
    svc.upsert_identity("soc-desktop", ["ai_guard", "threat_intel"])
    items = svc.list_identities()
    assert len(items) == 1
    assert items[0]["caller_id"] == "soc-desktop"
    assert items[0]["allowed_tools"] == ["ai_guard", "threat_intel"]
    assert items[0]["valid"] is True
    # File is consumable by the MCP server's identity loader.
    on_disk = json.loads((tmp_path / "identities" / "soc-desktop.json").read_text())
    assert on_disk == {"caller_id": "soc-desktop", "allowed_tools": ["ai_guard", "threat_intel"]}
    svc.close()


def test_upsert_rejects_unknown_scope(tmp_path):
    svc = AdminService(_cfg(tmp_path))
    with pytest.raises(AdminValidationError, match="unknown scopes"):
        svc.upsert_identity("c1", ["ai_guard", "not_a_scope"])
    assert svc.list_identities() == []
    svc.close()


def test_upsert_rejects_path_traversal_caller(tmp_path):
    svc = AdminService(_cfg(tmp_path))
    with pytest.raises(AdminValidationError):
        svc.upsert_identity("../evil", ["ai_guard"])
    with pytest.raises(AdminValidationError):
        svc.upsert_identity("a/b", ["ai_guard"])
    svc.close()


def test_upsert_rejects_empty_scopes(tmp_path):
    svc = AdminService(_cfg(tmp_path))
    with pytest.raises(AdminValidationError):
        svc.upsert_identity("c1", [])
    svc.close()


def test_delete_identity(tmp_path):
    svc = AdminService(_cfg(tmp_path))
    svc.upsert_identity("c1", ["ai_guard"])
    assert svc.delete_identity("c1") is True
    assert svc.delete_identity("c1") is False  # already gone
    assert svc.list_identities() == []
    svc.close()


def test_op_config_roundtrip_and_validation(tmp_path):
    svc = AdminService(_cfg(tmp_path))
    assert svc.get_op_config() == {"dlp_mode": "redact", "daily_quota": 0,
                                   "rate_limit_per_minute": 60}
    svc.set_op_config(dlp_mode="block", daily_quota=5000)
    cfg = svc.get_op_config()
    assert cfg["dlp_mode"] == "block"
    assert cfg["daily_quota"] == 5000
    assert cfg["rate_limit_per_minute"] == 60  # unchanged
    with pytest.raises(AdminValidationError):
        svc.set_op_config(dlp_mode="nope")
    with pytest.raises(AdminValidationError):
        svc.set_op_config(daily_quota=-1)
    with pytest.raises(AdminValidationError):
        svc.set_op_config(rate_limit_per_minute=0)
    svc.close()


def test_admin_actions_are_audited_and_chain_verifies(tmp_path):
    cfg = _cfg(tmp_path)
    svc = AdminService(cfg)
    svc.upsert_identity("c1", ["ai_guard"])
    svc.set_op_config(dlp_mode="redact")
    svc.delete_identity("c1")
    svc.close()
    from secure_mcp.audit import verify_chain
    ok, err = verify_chain(cfg.admin_audit_log_path, KEY)
    assert ok, err
    actions = [json.loads(l)["action"]
               for l in cfg.admin_audit_log_path.read_text().splitlines()]
    assert actions == ["upsert_identity", "set_op_config", "delete_identity"]


def test_audit_summary_counts_and_verifies(tmp_path):
    cfg = _cfg(tmp_path)
    a = AuditLogger(cfg.audit_log_path, "caller-1", hmac_key=KEY)
    a.record(tool="ai_guard", action="screen_prompt", result="ok",
             details={"dlp": [{"type": "aws_access_key_id", "count": 2}]})
    a.record(tool="threat_emulation", action="query_verdict", result="error",
             details={"error_type": "ValidationError"})
    a.close()
    svc = AdminService(cfg)
    s = svc.audit_summary()
    assert s["exists"] and s["verified"] is True
    assert s["total"] == 2
    assert s["by_result"] == {"ok": 1, "error": 1}
    assert s["by_error"] == {"ValidationError": 1}
    assert s["dlp_findings"] == 2
    svc.close()


def test_audit_summary_flags_tampering(tmp_path):
    cfg = _cfg(tmp_path)
    a = AuditLogger(cfg.audit_log_path, "caller-1", hmac_key=KEY)
    a.record(tool="ai_guard", action="screen_prompt", result="ok")
    a.record(tool="ai_guard", action="screen_prompt", result="ok")
    a.close()
    lines = cfg.audit_log_path.read_text().splitlines()
    bad = json.loads(lines[0]); bad["result"] = "error"
    lines[0] = json.dumps(bad, separators=(",", ":"))
    cfg.audit_log_path.write_text("\n".join(lines) + "\n")
    svc = AdminService(cfg)
    assert svc.audit_summary()["verified"] is False
    svc.close()


def test_browser_policy_author_list_and_version(tmp_path):
    from secure_mcp.policy_store import PolicyValidationError
    svc = AdminService(_cfg(tmp_path))
    d1 = svc.set_browser_policy("sales", {"BlockPhishingUrls": True})
    assert d1["version"] == 1 and d1["settings"]["BlockPhishingUrls"] is True
    d2 = svc.set_browser_policy("sales", {"BlockPhishingUrls": True, "BlockMaliciousUrls": True})
    assert d2["version"] == 2
    listed = svc.list_browser_policies()
    assert listed == [{"group": "sales", "version": 2, "issuedAt": d2["issuedAt"],
                       "settings": {"BlockPhishingUrls": True, "BlockMaliciousUrls": True}}]
    with pytest.raises(PolicyValidationError):
        svc.set_browser_policy("sales", {"BogusKey": True})
    svc.close()


def test_guidance_flags_least_privilege_and_hmac(tmp_path, monkeypatch):
    svc = AdminService(_cfg(tmp_path, hmac_key=None))
    svc.upsert_identity("god", sorted(["threat_emulation", "file_sandboxing",
                                       "ai_guard", "threat_intel", "url_category",
                                       "anti_phishing"]))
    monkeypatch.setattr(svc, "upstream_health", lambda: [])  # stay offline
    tips = svc.guidance()
    titles = " ".join(t["title"] for t in tips)
    assert "no HMAC key" in titles
    assert "ALL scopes" in titles
    svc.close()

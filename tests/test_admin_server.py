import threading
from pathlib import Path

import httpx
import pytest

from secure_mcp.admin.config import AdminConfig
from secure_mcp.admin.server import build_httpd
from secure_mcp.admin.service import AdminService

TOKEN = "console-admin-token"


def _cfg(tmp_path: Path, managed_units=()) -> AdminConfig:
    idir = tmp_path / "identities"
    idir.mkdir(exist_ok=True)
    return AdminConfig(
        admin_token=TOKEN, bind_host="127.0.0.1", bind_port=0,
        tls_cert=None, tls_key=None,
        audit_log_path=tmp_path / "audit.jsonl",
        admin_audit_log_path=tmp_path / "admin-audit.jsonl",
        audit_hmac_key=b"k", identity_dir=idir,
        op_config_file=tmp_path / "config.json",
        te_base_url="https://te.checkpoint.com",
        tc_base_url="https://rep.checkpoint.com",
        lakera_base_url="https://api.lakera.ai",
        session_ttl_sec=1800,
        managed_units=managed_units,
        policy_dir=tmp_path / "policies",
        keys_dir=tmp_path / "keys",
    )


@pytest.fixture()
def server(tmp_path):
    cfg = _cfg(tmp_path)
    svc = AdminService(cfg)
    svc.upstream_health = lambda: []  # keep tests offline
    httpd = build_httpd(cfg, svc)
    port = httpd.socket.getsockname()[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    try:
        yield base
    finally:
        httpd.shutdown()
        svc.close()


def _login(base) -> str:
    r = httpx.post(f"{base}/api/login", json={"token": TOKEN})
    assert r.status_code == 200
    return r.json()["session"]


def test_console_html_served_with_security_headers(server):
    r = httpx.get(f"{server}/")
    assert r.status_code == 200
    assert "Management Console" in r.text
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_api_requires_auth(server):
    r = httpx.get(f"{server}/api/overview")
    assert r.status_code == 401


def test_login_rejects_wrong_token(server):
    r = httpx.post(f"{server}/api/login", json={"token": "nope"})
    assert r.status_code == 401


def test_login_then_overview(server):
    s = _login(server)
    r = httpx.get(f"{server}/api/overview", headers={"Authorization": f"Bearer {s}"})
    assert r.status_code == 200
    body = r.json()
    assert "audit" in body and "op_config" in body and "guidance" in body


def test_identity_crud_via_api(server):
    s = _login(server)
    h = {"Authorization": f"Bearer {s}"}
    # create
    r = httpx.put(f"{server}/api/identities", headers=h,
                  json={"caller_id": "svc-a", "allowed_tools": ["ai_guard"]})
    assert r.status_code == 200
    # list
    r = httpx.get(f"{server}/api/identities", headers=h)
    assert any(i["caller_id"] == "svc-a" for i in r.json()["identities"])
    # invalid scope rejected
    r = httpx.put(f"{server}/api/identities", headers=h,
                  json={"caller_id": "svc-b", "allowed_tools": ["bogus"]})
    assert r.status_code == 400
    # delete
    r = httpx.request("DELETE", f"{server}/api/identities/svc-a", headers=h)
    assert r.status_code == 200 and r.json()["deleted"] is True


def test_config_update_via_api(server):
    s = _login(server)
    h = {"Authorization": f"Bearer {s}"}
    r = httpx.put(f"{server}/api/config", headers=h,
                  json={"dlp_mode": "block", "daily_quota": 1000})
    assert r.status_code == 200 and r.json()["dlp_mode"] == "block"
    r = httpx.put(f"{server}/api/config", headers=h, json={"dlp_mode": "bad"})
    assert r.status_code == 400


@pytest.fixture()
def server_with_units(tmp_path):
    cfg = _cfg(tmp_path, managed_units=("secure-mcp@soc.service",))
    calls = []

    def runner(args):
        calls.append(args)
        return (0, "ActiveState=active\nSubState=running\n", "")

    svc = AdminService(cfg, restart_runner=runner)
    svc.upstream_health = lambda: []
    httpd = build_httpd(cfg, svc)
    port = httpd.socket.getsockname()[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}", calls
    finally:
        httpd.shutdown()
        svc.close()


def test_restart_status_and_action(server_with_units):
    base, calls = server_with_units
    s = _login(base)
    h = {"Authorization": f"Bearer {s}"}
    r = httpx.get(f"{base}/api/restart", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is True
    assert body["units"][0]["unit"] == "secure-mcp@soc.service"
    # valid restart
    r = httpx.post(f"{base}/api/restart", headers=h, json={"unit": "secure-mcp@soc.service"})
    assert r.status_code == 200 and r.json()["ok"] is True
    assert ["systemctl", "restart", "secure-mcp@soc.service"] in calls
    # unit not in allowlist -> 400, never executed
    r = httpx.post(f"{base}/api/restart", headers=h, json={"unit": "secure-mcp@evil.service"})
    assert r.status_code == 400
    assert not any("evil" in " ".join(c) for c in calls)


def test_restart_disabled_when_no_units(server):
    s = _login(server)
    r = httpx.get(f"{server}/api/restart", headers={"Authorization": f"Bearer {s}"})
    assert r.status_code == 200 and r.json()["enabled"] is False


def test_browser_policy_via_api(server):
    h = {"Authorization": f"Bearer {_login(server)}"}
    r = httpx.put(f"{server}/api/policies", headers=h,
                  json={"group": "sales", "settings": {"BlockMaliciousUrls": True}})
    assert r.status_code == 200 and r.json()["version"] == 1
    r = httpx.get(f"{server}/api/policies", headers=h)
    assert any(p["group"] == "sales" for p in r.json()["policies"])
    r = httpx.get(f"{server}/api/policies/sales", headers=h)
    assert r.json()["settings"]["BlockMaliciousUrls"] is True
    # invalid policy key → 400
    r = httpx.put(f"{server}/api/policies", headers=h,
                  json={"group": "sales", "settings": {"Nope": True}})
    assert r.status_code == 400


def test_restart_all_via_api(server_with_units):
    base, calls = server_with_units
    h = {"Authorization": f"Bearer {_login(base)}"}
    r = httpx.post(f"{base}/api/restart-all", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is True
    assert body["results"][0]["ok"] is True
    assert ["systemctl", "restart", "secure-mcp@soc.service"] in calls


def test_restart_all_requires_auth(server_with_units):
    base, _ = server_with_units
    assert httpx.post(f"{base}/api/restart-all").status_code == 401


def test_session_for_wrong_token_rejected(server):
    # A session minted for a different admin token must not be accepted.
    from secure_mcp.admin.auth import mint_session
    forged = mint_session("some-other-token", ttl_sec=600)
    r = httpx.get(f"{server}/api/overview", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401

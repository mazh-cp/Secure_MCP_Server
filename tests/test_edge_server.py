import threading
from pathlib import Path

import httpx
import pytest

from secure_mcp.adapters.threatcloud import ThreatCloudClient
from secure_mcp.edge.config import EdgeConfig
from secure_mcp.edge.server import build_edge_httpd

SECRET = "edge-enroll-secret"


def _cfg(tmp_path: Path, groups=()) -> EdgeConfig:
    return EdgeConfig(
        enrollment_secret=SECRET, bind_host="127.0.0.1", bind_port=0,
        tls_cert=None, tls_key=None,
        threatcloud_base_url="https://rep.checkpoint.com", threatcloud_api_key="tc",
        audit_log_path=tmp_path / "edge-audit.jsonl", audit_hmac_key=b"k",
        rate_limit_per_minute=120, daily_quota=0, token_ttl_sec=3600,
        allowed_groups=groups, block_suspicious=False,
        policy_dir=tmp_path / "policies", keys_dir=tmp_path / "keys",
    )


def _tc(handler) -> ThreatCloudClient:
    return ThreatCloudClient(base_url="https://rep.checkpoint.com", api_key="tc",
                             _transport=httpx.MockTransport(handler))


@pytest.fixture()
def server(tmp_path):
    # ThreatCloud returns malicious for evil.example, benign otherwise.
    def handler(request: httpx.Request) -> httpx.Response:
        import json
        body = json.loads(request.content)
        res = "malicious" if "evil" in body.get("resource", "") else "benign"
        return httpx.Response(200, json={"classification": res})

    cfg = _cfg(tmp_path)
    httpd = build_edge_httpd(cfg, tc=_tc(handler))
    port = httpd.socket.getsockname()[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        yield base
    finally:
        httpd.shutdown()
        httpd.audit.close()


def _enroll(base, group="sales") -> str:
    r = httpx.post(f"{base}/edge/v1/enroll",
                   json={"enrollment_secret": SECRET, "group": group, "device_id": "d1"})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def test_healthz(server):
    assert httpx.get(f"{server}/edge/v1/healthz").json()["ok"] is True


def test_enroll_rejects_wrong_secret(server):
    r = httpx.post(f"{server}/edge/v1/enroll", json={"enrollment_secret": "no", "group": "g"})
    assert r.status_code == 401


def test_verdict_requires_auth(server):
    r = httpx.post(f"{server}/edge/v1/url/verdict", json={"url": "https://x.example"})
    assert r.status_code == 401


def test_verdict_blocks_malicious_allows_benign(server):
    h = {"Authorization": f"Bearer {_enroll(server)}"}
    r = httpx.post(f"{server}/edge/v1/url/verdict", headers=h,
                   json={"url": "https://evil.example/login"})
    assert r.status_code == 200 and r.json()["action"] == "block"
    r = httpx.post(f"{server}/edge/v1/url/verdict", headers=h,
                   json={"url": "https://good.example/"})
    assert r.status_code == 200 and r.json()["action"] == "allow"


def test_verdict_rejects_bad_url(server):
    h = {"Authorization": f"Bearer {_enroll(server)}"}
    r = httpx.post(f"{server}/edge/v1/url/verdict", headers=h, json={"url": "not-a-url"})
    assert r.status_code == 400
    # SSRF: internal IP must be rejected by validate_url
    r = httpx.post(f"{server}/edge/v1/url/verdict", headers=h, json={"url": "http://10.0.0.1/"})
    assert r.status_code == 400


def test_audit_records_host_not_full_url(tmp_path):
    import json as _json

    def handler(request):
        return httpx.Response(200, json={"classification": "benign"})

    cfg = _cfg(tmp_path)
    httpd = build_edge_httpd(cfg, tc=_tc(handler))
    port = httpd.socket.getsockname()[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        h = {"Authorization": f"Bearer {_enroll(base)}"}
        httpx.post(f"{base}/edge/v1/url/verdict", headers=h,
                   json={"url": "https://private.example/secret-path?token=abc"})
    finally:
        httpd.shutdown()
        httpd.audit.close()
    text = cfg.audit_log_path.read_text()
    assert "private.example" in text          # host is recorded
    assert "secret-path" not in text          # full path/query is NOT
    assert "token=abc" not in text


def test_pubkey_served(server):
    r = httpx.get(f"{server}/edge/v1/pubkey")
    assert r.status_code == 200 and r.json()["alg"] == "ed25519"
    assert len(r.json()["publicKey"]) > 0


def test_policy_requires_auth(server):
    assert httpx.get(f"{server}/edge/v1/policy").status_code == 401


def test_policy_404_then_signed_envelope(tmp_path):
    cfg = _cfg(tmp_path)
    httpd = build_edge_httpd(cfg, tc=_tc(lambda r: httpx.Response(200, json={})))
    port = httpd.socket.getsockname()[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        h = {"Authorization": f"Bearer {_enroll(base, group='sales')}"}
        # No policy authored yet → 404.
        assert httpx.get(f"{base}/edge/v1/policy", headers=h).status_code == 404
        # Author one for the group; it should now verify against the pubkey.
        httpd.policy.set_settings("sales", {"BlockPhishingUrls": True}, now_iso="2026-06-01T00:00:00+00:00")
        r = httpx.get(f"{base}/edge/v1/policy", headers=h)
        assert r.status_code == 200
        env = r.json()
        from secure_mcp.policy_store import verify_envelope
        assert verify_envelope(env, httpd.policy.public_key_b64()) is True
        assert env["document"]["settings"]["BlockPhishingUrls"] is True
        # ETag → 304 on re-fetch.
        etag = r.headers["ETag"]
        r2 = httpx.get(f"{base}/edge/v1/policy", headers={**h, "If-None-Match": etag})
        assert r2.status_code == 304
    finally:
        httpd.shutdown()
        httpd.audit.close()


def test_events_ingested_to_audit(tmp_path):
    cfg = _cfg(tmp_path)
    httpd = build_edge_httpd(cfg, tc=_tc(lambda r: httpx.Response(200, json={})))
    port = httpd.socket.getsockname()[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        h = {"Authorization": f"Bearer {_enroll(base)}"}
        r = httpx.post(f"{base}/edge/v1/events", headers=h,
                       json={"events": [{"classification": "Malicious", "host": "evil.example"}]})
        assert r.status_code == 202 and r.json()["accepted"] == 1
        # Unauthenticated → 401.
        assert httpx.post(f"{base}/edge/v1/events", json={"events": []}).status_code == 401
    finally:
        httpd.shutdown()
        httpd.audit.close()
    assert "telemetry" in cfg.audit_log_path.read_text()


def test_enroll_group_allowlist(tmp_path):
    cfg = _cfg(tmp_path, groups=("sales",))
    httpd = build_edge_httpd(cfg, tc=_tc(lambda r: httpx.Response(200, json={})))
    port = httpd.socket.getsockname()[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        ok = httpx.post(f"{base}/edge/v1/enroll",
                        json={"enrollment_secret": SECRET, "group": "sales"})
        assert ok.status_code == 200
        bad = httpx.post(f"{base}/edge/v1/enroll",
                         json={"enrollment_secret": SECRET, "group": "intruders"})
        assert bad.status_code == 403
    finally:
        httpd.shutdown()
        httpd.audit.close()

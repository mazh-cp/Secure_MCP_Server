#!/usr/bin/env python3
"""Interactive local instance — run the admin console + edge PDP on loopback for
manual / browser / plugin validation.

DEV ONLY: generates ephemeral secrets at launch (printed below), uses a mock
ThreatCloud so it runs offline, and a throwaway temp workspace. Nothing is
persisted; restart for a clean slate. Never use these secrets in production.

    .venv/bin/python scripts/run_local.py
"""

from __future__ import annotations

import json
import secrets
import tempfile
import threading
from pathlib import Path

import httpx

from secure_mcp.adapters.threatcloud import ThreatCloudClient
from secure_mcp.admin.config import AdminConfig
from secure_mcp.admin.server import build_httpd
from secure_mcp.admin.service import AdminService
from secure_mcp.edge.config import EdgeConfig
from secure_mcp.edge.server import build_edge_httpd

ADMIN_PORT = 8765
EDGE_PORT = 8770


def _tc_mock() -> ThreatCloudClient:
    def handler(req: httpx.Request) -> httpx.Response:
        res = json.loads(req.content).get("resource", "")
        cls = ("malicious" if "evil" in res or "malware" in res
               else "phishing" if "phish" in res else "benign")
        return httpx.Response(200, json={"classification": cls})
    return ThreatCloudClient("https://rep.checkpoint.com", "tc",
                             _transport=httpx.MockTransport(handler))


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="secure-mcp-dev-"))
    (tmp / "identities").mkdir()
    hmac_key = secrets.token_bytes(32)
    enroll = secrets.token_hex(16)
    admin_token = secrets.token_hex(16)
    master_key = secrets.token_bytes(32)
    pol_dir, keys_dir = tmp / "policies", tmp / "keys"
    group = "demo"

    edge_cfg = EdgeConfig(
        enrollment_secret=enroll, bind_host="127.0.0.1", bind_port=EDGE_PORT, tls_cert=None, tls_key=None,
        threatcloud_base_url="https://rep.checkpoint.com", threatcloud_api_key="tc",
        audit_log_path=tmp / "edge-audit.jsonl", audit_hmac_key=hmac_key,
        rate_limit_per_minute=120, daily_quota=0, token_ttl_sec=3600,
        allowed_groups=(group,), block_suspicious=False, policy_dir=pol_dir, keys_dir=keys_dir)
    admin_cfg = AdminConfig(
        admin_token=admin_token, bind_host="127.0.0.1", bind_port=ADMIN_PORT, tls_cert=None, tls_key=None,
        audit_log_path=tmp / "audit.jsonl", admin_audit_log_path=tmp / "admin-audit.jsonl",
        audit_hmac_key=hmac_key, identity_dir=tmp / "identities", op_config_file=tmp / "config.json",
        te_base_url="https://te.checkpoint.com", tc_base_url="https://rep.checkpoint.com",
        lakera_base_url="https://api.lakera.ai", session_ttl_sec=1800,
        policy_dir=pol_dir, keys_dir=keys_dir,
        keystore_path=tmp / "secrets.enc", keystore_master_key=master_key)

    edge = build_edge_httpd(edge_cfg, tc=_tc_mock())
    svc = AdminService(admin_cfg)
    svc.upstream_health = lambda: [  # friendly mock so the Health tab is populated offline
        {"name": "threat_emulation", "url": edge_cfg.threatcloud_base_url, "reachable": True, "status": 200},
        {"name": "threatcloud", "url": edge_cfg.threatcloud_base_url, "reachable": True, "status": 200},
        {"name": "lakera_guard", "url": admin_cfg.lakera_base_url, "reachable": True, "status": 200}]
    # Seed one group policy so the console + edge have something to show.
    svc.set_browser_policy(group, {"BlockMaliciousUrls": True, "BlockPhishingUrls": True})
    admin = build_httpd(admin_cfg, svc)
    pubkey = svc._policy.public_key_b64()  # noqa: SLF001 - dev launcher only

    threading.Thread(target=edge.serve_forever, daemon=True).start()
    threading.Thread(target=admin.serve_forever, daemon=True).start()

    bar = "=" * 64
    print(f"\n{bar}\n  secure-mcp — LOCAL DEV INSTANCE (ephemeral secrets, mock ThreatCloud)\n{bar}")
    print(f"  Admin console : http://127.0.0.1:{ADMIN_PORT}")
    print(f"      admin token : {admin_token}")
    print(f"  Edge PDP      : http://127.0.0.1:{EDGE_PORT}")
    print(f"      enrollment secret : {enroll}")
    print(f"      group             : {group}")
    print(f"      policy pubkey     : {pubkey}")
    print(f"{bar}")
    print("  Try the edge (enroll → verdict):")
    print(f"    TOK=$(curl -s localhost:{EDGE_PORT}/edge/v1/enroll -d "
          f"'{{\"enrollment_secret\":\"{enroll}\",\"group\":\"{group}\",\"device_id\":\"d1\"}}' | jq -r .token)")
    print(f"    curl -s localhost:{EDGE_PORT}/edge/v1/url/verdict -H \"Authorization: Bearer $TOK\" "
          f"-d '{{\"url\":\"https://evil.example/x\"}}'   # → block")
    print(f"  Plugin managed policy: EdgePdpUrl=http://127.0.0.1:{EDGE_PORT}, "
          f"EdgeGroup={group}, EdgeEnrollmentSecret=<above>, EdgePolicyPublicKey=<above>")
    print(f"{bar}\n  Ctrl-C to stop.\n", flush=True)

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nstopping…")
    finally:
        edge.shutdown(); admin.shutdown()
        edge.audit.close(); svc.close()


if __name__ == "__main__":
    main()

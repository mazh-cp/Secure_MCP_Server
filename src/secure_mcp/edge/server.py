from __future__ import annotations

import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import httpx

from ..adapters.threatcloud import ThreatCloudClient, ThreatCloudError
from ..admin.auth import LoginThrottle
from ..audit import AuditLogger
from ..logger import get_logger
from ..policy_store import PolicyStore
from ..quota import DailyQuota, QuotaExceeded
from ..rate_limit import RateLimitExceeded, ScopedRateLimiter
from ..validation import ValidationError, validate_url
from .auth import check_enrollment_secret, mint_device_token, verify_device_token
from .config import EdgeConfig, load_edge_config
from .verdict import UrlPolicy, classify_response, decide

_log = get_logger("secure_mcp.edge")

# JSON-only API → maximally strict headers.
_HEADERS = {
    "Content-Security-Policy": "default-src 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _host_of(url: str) -> str:
    try:
        return urlparse(url).hostname or "?"
    except ValueError:
        return "?"


class _Handler(BaseHTTPRequestHandler):
    server_version = "secure-mcp-edge"

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for k, v in _HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_raw(self) -> bytes:
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n <= 0 or n > 64 * 1024:
            return b""
        return self.rfile.read(n)

    def _read_json(self) -> dict:
        # Parses the body already drained in do_POST (see note there).
        try:
            data = json.loads(self._raw or b"{}")
            return data if isinstance(data, dict) else {}
        except ValueError:
            return {}

    def _claims(self) -> dict | None:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        return verify_device_token(auth[7:], self.server.cfg.enrollment_secret)

    def log_message(self, fmt: str, *args) -> None:
        _log.info("edge request", extra={"client": self.client_address[0],
                                         "request": fmt % args})

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/edge/v1/healthz":
            return self._json(200, {"ok": True})
        if path == "/edge/v1/pubkey":
            # Public key is public — clients also receive it via GPO (TOFU avoided).
            return self._json(200, {"publicKey": self.server.policy.public_key_b64(),
                                    "alg": "ed25519"})
        if path == "/edge/v1/policy":
            return self._policy()
        self._json(404, {"error": "not found"})

    def _policy(self) -> None:
        claims = self._claims()
        if claims is None:
            return self._json(401, {"error": "authentication required"})
        group = str(claims.get("grp", ""))
        doc = self.server.policy.get_document(group)
        if doc is None:
            return self._json(404, {"error": "no policy for group"})
        etag = f'W/"{doc.get("version")}"'
        if self.headers.get("If-None-Match") == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            for k, v in _HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            return
        envelope = self.server.policy.sign(doc)
        self.server.audit.record(tool="edge", action="policy_pull", result="ok",
                                 details={"group": group, "version": doc.get("version")})
        body = json.dumps(envelope).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("ETag", etag)
        for k, v in _HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        # Always drain the request body up front, so error/auth-fail paths that
        # respond early don't leave an unread body and reset the connection.
        self._raw = self._read_raw()
        try:
            if path == "/edge/v1/enroll":
                return self._enroll()
            if path == "/edge/v1/url/verdict":
                return self._url_verdict()
            if path == "/edge/v1/events":
                return self._events()
            self._json(404, {"error": "not found"})
        except ValidationError as e:
            self._json(400, {"error": str(e)})
        except (RateLimitExceeded, QuotaExceeded) as e:
            self._json(429, {"error": str(e)})
        except ThreatCloudError:
            # Upstream down — the PEP fails open locally on non-200.
            self._json(502, {"error": "verdict service unavailable"})
        except BrokenPipeError:
            pass
        except Exception:  # noqa: BLE001
            _log.warning("edge handler error", extra={"path": path})
            self._json(500, {"error": "internal error"})

    def _enroll(self) -> None:
        cfg: EdgeConfig = self.server.cfg
        throttle: LoginThrottle = self.server.throttle
        client = self.client_address[0]
        if throttle.is_locked(client):
            return self._json(429, {"error": "too many attempts, locked out"})
        body = self._read_json()
        secret = str(body.get("enrollment_secret", ""))
        group = str(body.get("group", "")).strip()
        device_id = str(body.get("device_id", "")).strip() or "unknown"
        if not secret or not check_enrollment_secret(secret, cfg.enrollment_secret):
            throttle.record_failure(client)
            return self._json(401, {"error": "invalid enrollment secret"})
        if not group or len(group) > 64:
            return self._json(400, {"error": "group required (<=64 chars)"})
        if cfg.allowed_groups and group not in cfg.allowed_groups:
            return self._json(403, {"error": "group not permitted"})
        throttle.reset(client)
        token = mint_device_token(cfg.enrollment_secret, group=group,
                                  device_id=device_id[:128], ttl_sec=cfg.token_ttl_sec)
        self.server.audit.record(tool="edge", action="enroll", result="ok",
                                 details={"group": group, "device": device_id[:128]})
        self._json(200, {"token": token, "expires_in": cfg.token_ttl_sec, "group": group})

    def _url_verdict(self) -> None:
        cfg: EdgeConfig = self.server.cfg
        claims = self._claims()
        if claims is None:
            return self._json(401, {"error": "authentication required"})
        group = str(claims.get("grp", "?"))
        try:
            self.server.quota.check()
            self.server.rate.check(group)
            url = validate_url(str(self._read_json().get("url", "")))
            resp = self.server.tc.lookup_url(url)
        except Exception as e:
            # Audit failures with host only (never the full URL/path).
            self.server.audit.record(tool="edge", action="url_verdict", result="error",
                                     details={"group": group, "error_type": type(e).__name__})
            raise
        classification = classify_response(resp)
        verdict = decide(classification, self.server.url_policy)
        # Privacy: audit records the host + decision, NOT the full URL/path.
        self.server.audit.record(tool="edge", action="url_verdict", result="ok",
                                 details={"group": group, "host": _host_of(url),
                                          "action": verdict["action"],
                                          "classification": classification})
        self._json(200, verdict)

    def _events(self) -> None:
        claims = self._claims()
        if claims is None:
            return self._json(401, {"error": "authentication required"})
        group = str(claims.get("grp", "?"))
        events = self._read_json().get("events", [])
        if not isinstance(events, list):
            return self._json(400, {"error": "events must be an array"})
        # Ingest into the tamper-evident audit log (the authorized telemetry sink).
        # Capped per request; per-event size capped to avoid log abuse.
        for ev in events[:100]:
            if isinstance(ev, dict):
                trimmed = {k: ev[k] for k in list(ev)[:20]}
                self.server.audit.record(tool="edge", action="telemetry", result="ok",
                                         details={"group": group, "event": trimmed})
        self._json(202, {"accepted": min(len(events), 100)})


def build_edge_httpd(cfg: EdgeConfig, tc: ThreatCloudClient | None = None) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((cfg.bind_host, cfg.bind_port), _Handler)
    httpd.cfg = cfg
    httpd.tc = tc or ThreatCloudClient(cfg.threatcloud_base_url, cfg.threatcloud_api_key)
    httpd.audit = AuditLogger(cfg.audit_log_path, "edge-pdp", hmac_key=cfg.audit_hmac_key)
    httpd.rate = ScopedRateLimiter(per_minute=cfg.rate_limit_per_minute)
    httpd.quota = DailyQuota(daily_limit=cfg.daily_quota)
    httpd.throttle = LoginThrottle()
    httpd.url_policy = UrlPolicy(block_suspicious=cfg.block_suspicious)
    httpd.policy = PolicyStore(cfg.policy_dir, cfg.keys_dir)
    if cfg.tls_enabled:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=cfg.tls_cert, keyfile=cfg.tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd


def main() -> None:
    cfg = load_edge_config()
    httpd = build_edge_httpd(cfg)
    scheme = "https" if cfg.tls_enabled else "http"
    _log.info("edge PDP listening", extra={
        "url": f"{scheme}://{cfg.bind_host}:{cfg.bind_port}",
        "tls": cfg.tls_enabled, "groups": list(cfg.allowed_groups) or "any"})
    if not cfg.tls_enabled:
        _log.warning("edge PDP without TLS — bind loopback behind a TLS-terminating proxy")
    try:
        httpd.serve_forever()
    finally:
        httpd.audit.close()


if __name__ == "__main__":
    main()

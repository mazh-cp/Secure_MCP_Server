from __future__ import annotations

import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

from ..logger import get_logger
from .auth import LoginThrottle, check_admin_token, mint_session, verify_session
from ..policy_store import PolicyValidationError
from .config import AdminConfig, load_admin_config
from .restart import RestartError
from .service import AdminService, AdminValidationError
from .views import render_console_html

_log = get_logger("secure_mcp.admin")

_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "connect-src 'self'; img-src data:; base-uri 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class _Handler(BaseHTTPRequestHandler):
    server_version = "secure-mcp-admin"

    # --- helpers ---
    def _headers(self, status: int, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for k, v in _SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self._headers(status, "application/json")
        self.wfile.write(body)

    def _html(self, status: int, html: str) -> None:
        self._headers(status, "text/html; charset=utf-8")
        self.wfile.write(html.encode("utf-8"))

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > 1_000_000:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
        except ValueError:
            return {}

    def _authed(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        return verify_session(auth[7:], self.server.cfg.admin_token)

    def log_message(self, fmt: str, *args) -> None:
        # Route to structured logger; never log request bodies (may carry token).
        # NB: avoid reserved LogRecord keys (msg/args/name) in `extra`.
        _log.info("admin request", extra={"client": self.client_address[0],
                                          "request": fmt % args})

    # --- verb dispatch ---
    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        try:
            path = urlparse(self.path).path
            if method == "GET" and path == "/":
                return self._html(200, render_console_html())
            if path == "/favicon.ico":
                return self._headers(204, "image/x-icon")

            if method == "POST" and path == "/api/login":
                return self._login()

            # Every other /api route requires a valid session.
            if path.startswith("/api/"):
                if not self._authed():
                    return self._json(401, {"error": "authentication required"})
                return self._api(method, path)

            self._json(404, {"error": "not found"})
        except (AdminValidationError, RestartError, PolicyValidationError) as e:
            self._json(400, {"error": str(e)})
        except BrokenPipeError:
            pass
        except Exception:  # noqa: BLE001
            _log.warning("admin handler error", extra={"path": self.path})
            self._json(500, {"error": "internal error"})

    def _login(self) -> None:
        cfg: AdminConfig = self.server.cfg
        throttle: LoginThrottle = self.server.throttle
        client = self.client_address[0]
        if throttle.is_locked(client):
            return self._json(429, {"error": "too many attempts, locked out"})
        token = str(self._read_json().get("token", ""))
        if not token or not check_admin_token(token, cfg.admin_token):
            throttle.record_failure(client)
            return self._json(401, {"error": "invalid admin token"})
        throttle.reset(client)
        session = mint_session(cfg.admin_token, ttl_sec=cfg.session_ttl_sec)
        self._json(200, {"session": session})

    def _api(self, method: str, path: str) -> None:
        svc: AdminService = self.server.svc
        if path == "/api/overview" and method == "GET":
            return self._json(200, svc.overview())
        if path == "/api/audit" and method == "GET":
            return self._json(200, svc.audit_summary())
        if path == "/api/health" and method == "GET":
            return self._json(200, {"upstreams": svc.upstream_health()})
        if path == "/api/restart":
            if method == "GET":
                return self._json(200, svc.restart_status())
            if method == "POST":
                unit = str(self._read_json().get("unit", ""))
                return self._json(200, svc.restart_unit(unit))
        if path == "/api/restart-all" and method == "POST":
            return self._json(200, svc.restart_all())
        if path == "/api/config":
            if method == "GET":
                return self._json(200, svc.get_op_config())
            if method == "PUT":
                b = self._read_json()
                return self._json(200, svc.set_op_config(
                    dlp_mode=b.get("dlp_mode"),
                    daily_quota=b.get("daily_quota"),
                    rate_limit_per_minute=b.get("rate_limit_per_minute")))
        if path == "/api/identities":
            if method == "GET":
                return self._json(200, {"identities": svc.list_identities()})
            if method == "PUT":
                b = self._read_json()
                return self._json(200, svc.upsert_identity(
                    str(b.get("caller_id", "")), b.get("allowed_tools", [])))
        if path.startswith("/api/identities/") and method == "DELETE":
            cid = unquote(path[len("/api/identities/"):])
            return self._json(200, {"deleted": svc.delete_identity(cid)})
        if path == "/api/policies":
            if method == "GET":
                return self._json(200, {"policies": svc.list_browser_policies()})
            if method == "PUT":
                b = self._read_json()
                return self._json(200, svc.set_browser_policy(
                    str(b.get("group", "")), b.get("settings", {})))
        if path.startswith("/api/policies/") and method == "GET":
            group = unquote(path[len("/api/policies/"):])
            return self._json(200, svc.get_browser_policy(group))
        self._json(404, {"error": "not found"})


def build_httpd(cfg: AdminConfig, svc: AdminService) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((cfg.bind_host, cfg.bind_port), _Handler)
    httpd.cfg = cfg
    httpd.svc = svc
    httpd.throttle = LoginThrottle()
    if cfg.tls_enabled:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=cfg.tls_cert, keyfile=cfg.tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd


def main() -> None:
    cfg = load_admin_config()
    svc = AdminService(cfg)
    httpd = build_httpd(cfg, svc)
    scheme = "https" if cfg.tls_enabled else "http"
    _log.info("admin console listening", extra={
        "url": f"{scheme}://{cfg.bind_host}:{cfg.bind_port}",
        "tls": cfg.tls_enabled, "identity_dir": str(cfg.identity_dir)})
    if not cfg.tls_enabled:
        _log.warning("admin console running without TLS — loopback only; "
                     "set SECURE_MCP_ADMIN_TLS_CERT/KEY for remote access")
    try:
        httpd.serve_forever()
    finally:
        svc.close()


if __name__ == "__main__":
    main()

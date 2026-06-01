from unittest.mock import patch

import httpx
import pytest

from secure_mcp.circuit_breaker import CircuitBreaker, CircuitOpenError
from secure_mcp.http_client import SecureHTTPClient


def _stub_getaddrinfo_to(ip: str):
    def fn(host, port, *args, **kwargs):
        return [(0, 0, 0, "", (ip, port or 0))]
    return fn


def test_rejects_http_base_url():
    with pytest.raises(ValueError, match="https://"):
        SecureHTTPClient(base_url="http://example.com", auth_header={})


def test_rejects_private_resolved_host():
    with patch("secure_mcp.http_client.socket.getaddrinfo", _stub_getaddrinfo_to("10.0.0.1")):
        with pytest.raises(httpx.ConnectError, match="non-public"):
            SecureHTTPClient(base_url="https://internal.example", auth_header={"x": "y"})


def test_rejects_loopback_resolved_host():
    with patch("secure_mcp.http_client.socket.getaddrinfo", _stub_getaddrinfo_to("127.0.0.1")):
        with pytest.raises(httpx.ConnectError, match="non-public"):
            SecureHTTPClient(base_url="https://localish.example", auth_header={"x": "y"})


def test_auth_header_passed_to_upstream():
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("authorization", "")
        return httpx.Response(200, json={"ok": True})

    client = SecureHTTPClient(
        base_url="https://public.example",
        auth_header={"Authorization": "Bearer test-token"},
        _transport=httpx.MockTransport(handler),
    )
    resp = client.request("GET", "/v1/probe")
    assert resp.status_code == 200
    assert captured["auth"] == "Bearer test-token"
    client.close()


def test_does_not_follow_redirects():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/"})

    client = SecureHTTPClient(
        base_url="https://public.example",
        auth_header={"Authorization": "x"},
        _transport=httpx.MockTransport(handler),
    )
    resp = client.request("GET", "/x")
    assert resp.status_code == 302
    client.close()


def test_circuit_opens_after_repeated_upstream_failures():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)  # always failing upstream

    # threshold=2 so we don't pay tenacity's full retry/backoff many times.
    client = SecureHTTPClient(
        base_url="https://public.example",
        auth_header={"Authorization": "x"},
        breaker=CircuitBreaker(failure_threshold=2, cooldown_sec=60),
        _transport=httpx.MockTransport(handler),
    )
    for _ in range(2):
        with pytest.raises(httpx.HTTPStatusError):
            client.request("GET", "/x")
    # Breaker now open: fails fast without hitting the transport.
    with pytest.raises(CircuitOpenError):
        client.request("GET", "/x")
    client.close()

from __future__ import annotations

import ipaddress
import socket
from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from .circuit_breaker import CircuitBreaker


_DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=5.0)


def _assert_public_host(host: str) -> None:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise httpx.ConnectError(f"dns resolution failed for {host}: {e}") from e
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise httpx.ConnectError(f"host {host} resolves to non-public address {ip}")


class SecureHTTPClient:
    """httpx wrapper: TLS verify on, no redirects, timeouts, SSRF guard,
    retries, and a per-upstream circuit breaker."""

    def __init__(
        self,
        base_url: str,
        *,
        auth_header: dict[str, str],
        breaker: CircuitBreaker | None = None,
        _transport: httpx.BaseTransport | None = None,
    ) -> None:
        """_transport is a test-only seam for httpx.MockTransport injection.
        When set, the DNS-time SSRF guard is skipped because the transport
        short-circuits real network I/O. Production callers MUST leave it None."""
        if not base_url.startswith("https://"):
            raise ValueError("base_url must be https://")
        self._base_url = base_url.rstrip("/")
        # verify=True is httpx's default; we set it explicitly so any future
        # edit that tries to disable TLS verification stands out in review.
        self._client = httpx.Client(
            base_url=self._base_url,
            timeout=_DEFAULT_TIMEOUT,
            verify=True,
            headers=auth_header,
            follow_redirects=False,
            transport=_transport,
        )
        self._breaker = breaker or CircuitBreaker()
        if _transport is None:
            host = httpx.URL(self._base_url).host
            if host:
                _assert_public_host(host)

    @retry(
        retry=retry_if_exception_type((httpx.TransportError, httpx.HTTPStatusError)),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=8.0),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def _do_request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        resp = self._client.request(method, path, **kwargs)
        if resp.status_code >= 500:
            resp.raise_for_status()
        return resp

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        # Breaker wraps the whole retried call: one logical request == one
        # success/failure signal, so transient retries don't trip it early.
        self._breaker.before()
        try:
            resp = self._do_request(method, path, **kwargs)
        except Exception:
            self._breaker.record_failure()
            raise
        self._breaker.record_success()
        return resp

    def close(self) -> None:
        self._client.close()

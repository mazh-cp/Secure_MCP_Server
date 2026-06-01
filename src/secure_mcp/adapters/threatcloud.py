"""Check Point ThreatCloud adapter — indicator reputation & categorization.

Backs the threat_intel / url_category / anti_phishing tool groups. These send
*indicators only* (IP, domain, URL, file hash) to Check Point's own ThreatCloud
— data stays within the Check Point boundary, consistent with the org data-
handling policy. No customer files or free-form text are sent here.

The endpoint paths and response shapes match the publicly documented
ThreatCloud reputation pattern. Confirm them against the reputation/IOC API
tied to your subscription before production — class constants make that a
one-line change per path.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..http_client import SecureHTTPClient
from ..logger import get_logger

_log = get_logger("secure_mcp.threatcloud")

REPUTATION_PATH = "/rep/v1/lookup"        # ip / domain / url / hash reputation
CATEGORIZE_PATH = "/urlf/v1/categorize"   # URL filtering category
PHISHING_PATH = "/zphish/v1/score"        # zero-phishing URL score


class ThreatCloudError(RuntimeError):
    pass


class ThreatCloudClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        _transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._http = SecureHTTPClient(
            base_url=base_url,
            auth_header={"Authorization": api_key},
            _transport=_transport,
        )

    def _lookup(self, *, resource: str, indicator: str) -> dict[str, Any]:
        payload = {"resource_type": resource, "resource": indicator}
        resp = self._http.request("POST", REPUTATION_PATH, json=payload)
        if resp.status_code >= 400:
            _log.warning("threatcloud lookup non-2xx",
                         extra={"status": resp.status_code, "resource_type": resource})
            raise ThreatCloudError(f"ThreatCloud lookup failed: HTTP {resp.status_code}")
        return resp.json()

    def lookup_ip(self, ip: str) -> dict[str, Any]:
        return self._lookup(resource="ip", indicator=ip)

    def lookup_domain(self, domain: str) -> dict[str, Any]:
        return self._lookup(resource="domain", indicator=domain)

    def lookup_url(self, url: str) -> dict[str, Any]:
        return self._lookup(resource="url", indicator=url)

    def lookup_hash(self, digest: str) -> dict[str, Any]:
        return self._lookup(resource="hash", indicator=digest)

    def categorize_url(self, url: str) -> dict[str, Any]:
        resp = self._http.request("POST", CATEGORIZE_PATH, json={"url": url})
        if resp.status_code >= 400:
            _log.warning("threatcloud categorize non-2xx", extra={"status": resp.status_code})
            raise ThreatCloudError(f"ThreatCloud categorize failed: HTTP {resp.status_code}")
        return resp.json()

    def score_url(self, url: str) -> dict[str, Any]:
        resp = self._http.request("POST", PHISHING_PATH, json={"url": url})
        if resp.status_code >= 400:
            _log.warning("threatcloud phishing non-2xx", extra={"status": resp.status_code})
            raise ThreatCloudError(f"ThreatCloud phishing score failed: HTTP {resp.status_code}")
        return resp.json()

    def close(self) -> None:
        self._http.close()

"""Check Point Threat Emulation (cloud) adapter.

Endpoint paths and the wrapped-response shape below match the publicly
documented Check Point Threat Prevention API. Confirm the paths, payload
fields, and verdict shape against the API doc tied to your TE subscription
before turning the service on in production — Check Point has shipped
multiple API versions over time.

Customer files and telemetry stay within Check Point infrastructure; do NOT
add code that routes any of this data to non-approved destinations.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from ..http_client import SecureHTTPClient
from ..logger import get_logger

_log = get_logger("secure_mcp.te")

# Override these via subclass or monkeypatch if your subscription documents
# different paths. Kept as constants so search-and-replace is straightforward.
QUERY_PATH = "/tecloud/api/v1/file/query"
UPLOAD_PATH = "/tecloud/api/v1/file/upload"
DOWNLOAD_PATH = "/tecloud/api/v1/file/download"
URL_QUERY_PATH = "/tecloud/api/v1/url/query"
REPORT_PATH = "/tecloud/api/v1/report"


class CheckpointTEError(RuntimeError):
    pass


class CheckpointTEClient:
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

    @staticmethod
    def _first_item(body: dict[str, Any]) -> dict[str, Any]:
        """TE Cloud wraps batch results in {"response": [...]}; this helper
        unwraps a single-item request. Returns the raw body if the wrapper
        shape is absent so callers can inspect unexpected responses."""
        items = body.get("response")
        if isinstance(items, list) and items:
            return items[0]
        return body

    def query_verdict(self, sha256: str) -> dict[str, Any]:
        payload = {"request": [{"sha256": sha256, "features": ["te"]}]}
        resp = self._http.request("POST", QUERY_PATH, json=payload)
        if resp.status_code >= 400:
            _log.warning("te query_verdict non-2xx", extra={"status": resp.status_code})
            raise CheckpointTEError(f"TE query failed: HTTP {resp.status_code}")
        return self._first_item(resp.json())

    def emulate_url(self, url: str) -> dict[str, Any]:
        payload = {"request": [{"url": url, "features": ["te"]}]}
        resp = self._http.request("POST", URL_QUERY_PATH, json=payload)
        if resp.status_code >= 400:
            _log.warning("te emulate_url non-2xx", extra={"status": resp.status_code})
            raise CheckpointTEError(f"TE URL emulation failed: HTTP {resp.status_code}")
        return self._first_item(resp.json())

    def emulate_file(self, file_path: str, features: list[str]) -> dict[str, Any]:
        path = Path(file_path)
        metadata = {
            "request": [{
                "file_name": path.name,
                "features": features or ["te"],
            }]
        }
        with path.open("rb") as fh:
            resp = self._http.request(
                "POST",
                UPLOAD_PATH,
                files={
                    "request": (None, json.dumps(metadata), "application/json"),
                    "file": (path.name, fh, "application/octet-stream"),
                },
            )
        if resp.status_code >= 400:
            _log.warning("te emulate_file non-2xx", extra={"status": resp.status_code})
            raise CheckpointTEError(f"TE upload failed: HTTP {resp.status_code}")
        return self._first_item(resp.json())

    def extract_threats(self, file_path: str) -> dict[str, Any]:
        """Submit a file with the threat-extraction (CDR) feature enabled. The
        cleaned-file *download* is a separate /file/download round-trip not
        included here — wire it as a follow-up tool once you've confirmed the
        size limits and storage policy for sanitized files."""
        return self.emulate_file(file_path, features=["extraction"])

    def get_report(self, job_id: str) -> dict[str, Any]:
        resp = self._http.request("GET", f"{REPORT_PATH}/{job_id}")
        if resp.status_code >= 400:
            _log.warning("te get_report non-2xx", extra={"status": resp.status_code})
            raise CheckpointTEError(f"TE report fetch failed: HTTP {resp.status_code}")
        return resp.json()

    def close(self) -> None:
        self._http.close()

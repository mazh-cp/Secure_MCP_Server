"""Lakera Guard adapter — TEXT-ONLY by design.

Do NOT pass customer files, telemetry, or Check Point threat-intel artifacts
to this external service. Egress scope is LLM prompt/response text only.

The endpoint path and request body match the publicly documented Lakera Guard
v2 API (messages-array shape). Confirm against your Lakera plan's docs before
production — Lakera has shipped multiple API versions and self-hosted variants.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..http_client import SecureHTTPClient
from ..logger import get_logger
from ..validation import validate_text

_log = get_logger("secure_mcp.lakera")

GUARD_PATH = "/v2/guard"


class LakeraGuardError(RuntimeError):
    pass


class LakeraGuardClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        _transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._http = SecureHTTPClient(
            base_url=base_url,
            auth_header={"Authorization": f"Bearer {api_key}"},
            _transport=_transport,
        )

    def _post_guard(self, body: dict[str, Any]) -> dict[str, Any]:
        resp = self._http.request("POST", GUARD_PATH, json=body)
        if resp.status_code >= 400:
            _log.warning("lakera guard non-2xx", extra={"status": resp.status_code})
            raise LakeraGuardError(f"Lakera Guard failed: HTTP {resp.status_code}")
        return resp.json()

    def screen_prompt(self, text: str) -> dict[str, Any]:
        validate_text(text)
        return self._post_guard({"messages": [{"role": "user", "content": text}]})

    def screen_output(self, text: str) -> dict[str, Any]:
        validate_text(text)
        return self._post_guard({"messages": [{"role": "assistant", "content": text}]})

    def screen_payload(self, text: str, policy_id: str) -> dict[str, Any]:
        """Screen text against a named Lakera policy/project.

        Confirm against your Lakera docs whether project routing is done via
        a body field (project_id), a request header (X-Project-Id), or the
        URL (/v2/projects/{id}/guard). This implementation uses the body-field
        form — adjust if your plan differs."""
        validate_text(text)
        if not isinstance(policy_id, str) or not policy_id:
            raise ValueError("policy_id required")
        return self._post_guard({
            "messages": [{"role": "user", "content": text}],
            "project_id": policy_id,
        })

    def close(self) -> None:
        self._http.close()

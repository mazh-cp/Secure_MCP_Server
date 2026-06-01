import json

import httpx
import pytest

from secure_mcp.adapters.threatcloud import (
    CATEGORIZE_PATH,
    PHISHING_PATH,
    REPUTATION_PATH,
    ThreatCloudClient,
    ThreatCloudError,
)


def _client(handler) -> ThreatCloudClient:
    return ThreatCloudClient(
        base_url="https://rep.checkpoint.com",
        api_key="tc-test-key",
        _transport=httpx.MockTransport(handler),
    )


def test_lookup_ip_sends_resource_payload():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"reputation": "malicious", "confidence": 88})

    c = _client(handler)
    out = c.lookup_ip("1.2.3.4")
    assert captured["path"] == REPUTATION_PATH
    assert captured["auth"] == "tc-test-key"
    assert captured["body"] == {"resource_type": "ip", "resource": "1.2.3.4"}
    assert out["reputation"] == "malicious"
    c.close()


def test_lookup_hash_and_domain_resource_types():
    seen: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content)["resource_type"])
        return httpx.Response(200, json={"ok": True})

    c = _client(handler)
    c.lookup_domain("evil.example")
    c.lookup_hash("a" * 64)
    assert seen == ["domain", "hash"]
    c.close()


def test_categorize_url_hits_categorize_path():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"category": "Phishing", "risk": "high"})

    c = _client(handler)
    out = c.categorize_url("https://evil.example/login")
    assert captured["path"] == CATEGORIZE_PATH
    assert captured["body"]["url"] == "https://evil.example/login"
    assert out["category"] == "Phishing"
    c.close()


def test_score_url_hits_phishing_path():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        return httpx.Response(200, json={"phishing_score": 0.97})

    c = _client(handler)
    out = c.score_url("https://evil.example")
    assert captured["path"] == PHISHING_PATH
    assert out["phishing_score"] == 0.97
    c.close()


def test_non_2xx_raises_typed_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": "rate limited"})

    c = _client(handler)
    with pytest.raises(ThreatCloudError, match="HTTP 429"):
        c.lookup_ip("1.2.3.4")
    c.close()

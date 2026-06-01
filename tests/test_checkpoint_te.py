import json
from pathlib import Path

import httpx
import pytest

from secure_mcp.adapters.checkpoint_te import (
    CheckpointTEClient,
    CheckpointTEError,
    QUERY_PATH,
    UPLOAD_PATH,
    URL_QUERY_PATH,
)


def _client(handler) -> CheckpointTEClient:
    return CheckpointTEClient(
        base_url="https://te.checkpoint.com",
        api_key="test-api-key",
        _transport=httpx.MockTransport(handler),
    )


def test_query_verdict_sends_sha256_and_unwraps_response():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "response": [{
                "sha256": "a" * 64,
                "status": {"code": 1001, "label": "FOUND"},
                "te": {"combined_verdict": "benign", "trust": 100},
            }]
        })

    c = _client(handler)
    out = c.query_verdict("a" * 64)
    assert captured["path"] == QUERY_PATH
    assert captured["auth"] == "test-api-key"  # raw key, not Bearer-prefixed
    assert captured["body"] == {"request": [{"sha256": "a" * 64, "features": ["te"]}]}
    assert out["te"]["combined_verdict"] == "benign"
    c.close()


def test_emulate_url_sends_url_payload():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"response": [{"url": "https://x.example", "verdict": "benign"}]})

    c = _client(handler)
    c.emulate_url("https://x.example")
    assert captured["path"] == URL_QUERY_PATH
    assert captured["body"]["request"][0]["url"] == "https://x.example"
    c.close()


def test_emulate_file_uses_multipart(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc123")
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["ctype"] = request.headers.get("content-type", "")
        captured["body"] = request.content
        return httpx.Response(200, json={"response": [{"sha256": "deadbeef", "status": {"code": 1003}}]})

    c = _client(handler)
    out = c.emulate_file(str(sample), features=["te", "extraction"])
    assert captured["path"] == UPLOAD_PATH
    assert captured["ctype"].startswith("multipart/form-data")
    assert b"sample.bin" in captured["body"]
    assert b"abc123" in captured["body"]
    assert b'"features": ["te", "extraction"]' in captured["body"]
    assert out["sha256"] == "deadbeef"
    c.close()


def test_extract_threats_sets_extraction_feature(tmp_path: Path):
    sample = tmp_path / "sample.pdf"
    sample.write_bytes(b"pdfbytes")
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content
        return httpx.Response(200, json={"response": [{"status": {"code": 1003}}]})

    c = _client(handler)
    c.extract_threats(str(sample))
    assert b'"features": ["extraction"]' in captured["body"]
    c.close()


def test_non_2xx_raises_typed_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": "forbidden"})

    c = _client(handler)
    with pytest.raises(CheckpointTEError, match="HTTP 403"):
        c.query_verdict("a" * 64)
    c.close()


def test_unwrap_falls_through_on_unexpected_shape():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})

    c = _client(handler)
    out = c.query_verdict("a" * 64)
    assert out == {"unexpected": "shape"}
    c.close()

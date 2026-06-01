from pathlib import Path

import pytest

from secure_mcp.validation import (
    ValidationError,
    validate_sha256,
    validate_text,
    validate_upload_path,
    validate_url,
)


def test_sha256_accepts_hex64():
    digest = "a" * 64
    assert validate_sha256(digest) == digest


def test_sha256_rejects_short():
    with pytest.raises(ValidationError):
        validate_sha256("deadbeef")


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/x",
    "http://10.0.0.5/x",
    "http://192.168.1.1/x",
    "http://[::1]/x",
])
def test_url_blocks_ssrf_literals(url):
    with pytest.raises(ValidationError):
        validate_url(url)


def test_url_blocks_non_http_scheme():
    with pytest.raises(ValidationError):
        validate_url("file:///etc/passwd")


def test_url_accepts_https_public():
    assert validate_url("https://example.com/path") == "https://example.com/path"


def test_text_rejects_oversize():
    with pytest.raises(ValidationError):
        validate_text("x" * 200_001, max_chars=200_000)


def test_upload_path_rejects_traversal(tmp_path: Path):
    with pytest.raises(ValidationError):
        validate_upload_path("../etc/passwd", base_dir=tmp_path, max_bytes=1024)


def test_upload_path_rejects_absolute(tmp_path: Path):
    with pytest.raises(ValidationError):
        validate_upload_path("/etc/passwd", base_dir=tmp_path, max_bytes=1024)


def test_upload_path_accepts_in_bounds(tmp_path: Path):
    f = tmp_path / "ok.bin"
    f.write_bytes(b"hello")
    out = validate_upload_path("ok.bin", base_dir=tmp_path, max_bytes=1024)
    assert out == f.resolve()

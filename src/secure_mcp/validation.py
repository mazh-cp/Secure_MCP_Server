from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_ALLOWED_URL_SCHEMES = frozenset({"http", "https"})


class ValidationError(ValueError):
    pass


def validate_sha256(value: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.match(value):
        raise ValidationError("expected hex sha256 (64 chars)")
    return value.lower()


def validate_hash(value: str) -> str:
    """Accept md5 / sha1 / sha256 hex digests (32/40/64 chars)."""
    if not isinstance(value, str) or not _HASH_RE.match(value):
        raise ValidationError("expected md5/sha1/sha256 hex digest")
    return value.lower()


def validate_ip(value: str) -> str:
    if not isinstance(value, str):
        raise ValidationError("ip must be a string")
    try:
        ipaddress.ip_address(value)
    except ValueError as e:
        raise ValidationError(f"invalid IP address: {e}") from e
    return value


def validate_domain(value: str) -> str:
    if not isinstance(value, str) or len(value) > 253 or not _DOMAIN_RE.match(value):
        raise ValidationError("invalid domain name")
    return value.lower()


def validate_url(value: str) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValidationError("url must be a string under 2048 chars")
    parsed = urlparse(value)
    if parsed.scheme not in _ALLOWED_URL_SCHEMES:
        raise ValidationError(f"url scheme '{parsed.scheme}' not allowed")
    host = parsed.hostname
    if not host:
        raise ValidationError("url missing host")
    # Literal-IP SSRF guard. Hostname resolution is re-checked at request time
    # in http_client._assert_public_host to defeat DNS-rebinding tricks.
    ip: ipaddress._BaseAddress | None = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass  # hostname, not a literal IP — DNS-time check happens later
    if ip is not None and (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    ):
        raise ValidationError("url targets a non-public IP range")
    return value


def validate_text(value: str, *, max_chars: int = 100_000) -> str:
    if not isinstance(value, str):
        raise ValidationError("text must be a string")
    if len(value) > max_chars:
        raise ValidationError(f"text exceeds {max_chars} chars")
    return value


def validate_upload_path(value: str, *, base_dir: Path, max_bytes: int) -> Path:
    if not isinstance(value, str) or not value:
        raise ValidationError("file_ref must be a non-empty string")
    if value.startswith(("/", "\\")) or ".." in Path(value).parts:
        raise ValidationError("file_ref must be relative with no parent refs")
    base = base_dir.resolve(strict=True)
    candidate = (base / value).resolve()
    if base != candidate and base not in candidate.parents:
        raise ValidationError("file_ref escapes upload directory")
    if not candidate.is_file():
        raise ValidationError("file_ref does not point to a regular file")
    size = candidate.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ValidationError(f"file size {size} outside [1, {max_bytes}]")
    return candidate

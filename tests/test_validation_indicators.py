import pytest

from secure_mcp.validation import (
    ValidationError,
    validate_domain,
    validate_hash,
    validate_ip,
)


@pytest.mark.parametrize("ip", ["8.8.8.8", "192.0.2.1", "2001:db8::1"])
def test_valid_ips(ip):
    assert validate_ip(ip) == ip


@pytest.mark.parametrize("bad", ["not-an-ip", "999.999.999.999", "", "1.2.3"])
def test_invalid_ips(bad):
    with pytest.raises(ValidationError):
        validate_ip(bad)


@pytest.mark.parametrize("d", ["example.com", "sub.evil.example", "a.co"])
def test_valid_domains(d):
    assert validate_domain(d) == d


@pytest.mark.parametrize("bad", ["no-tld", "-bad.com", "bad-.com", "a..b.com", ""])
def test_invalid_domains(bad):
    with pytest.raises(ValidationError):
        validate_domain(bad)


def test_hash_accepts_md5_sha1_sha256():
    assert validate_hash("d" * 32) == "d" * 32
    assert validate_hash("e" * 40) == "e" * 40
    assert validate_hash("F" * 64) == "f" * 64


@pytest.mark.parametrize("bad", ["xyz", "a" * 31, "a" * 50])
def test_hash_rejects_bad(bad):
    with pytest.raises(ValidationError):
        validate_hash(bad)

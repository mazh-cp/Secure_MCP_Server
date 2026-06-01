import pytest

from secure_mcp.dlp import DLPScanner, DLPViolation, sanitize, scan


def test_detects_aws_access_key():
    findings = scan("my key is AKIAIOSFODNN7EXAMPLE here")
    assert any(f.type == "aws_access_key_id" for f in findings)


def test_detects_jwt_and_private_key():
    text = "token eyJhbGciOiJIUzI1Ni, key -----BEGIN RSA PRIVATE KEY-----"
    types = {f.type for f in scan(text + " eyJabc.eyJdef.sigZ")}
    assert "private_key" in types
    assert "jwt" in types


def test_detects_luhn_valid_card_only():
    valid = "card 4111 1111 1111 1111 end"      # passes Luhn
    invalid = "num 1234 5678 9012 3456 end"      # fails Luhn
    assert any(f.type == "credit_card" for f in scan(valid))
    assert not any(f.type == "credit_card" for f in scan(invalid))


def test_detects_ssn():
    assert any(f.type == "us_ssn" for f in scan("ssn 123-45-6789"))
    # invalid area numbers should not match
    assert not any(f.type == "us_ssn" for f in scan("000-12-3456"))


def test_clean_text_has_no_findings():
    assert scan("the quick brown fox jumps over the lazy dog") == []


def test_sanitize_redacts_and_preserves_surrounding_text():
    text = "key AKIAIOSFODNN7EXAMPLE done"
    out, findings = sanitize(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "[REDACTED:aws_access_key_id]" in out
    assert out.startswith("key ") and out.endswith(" done")
    assert findings[0].type == "aws_access_key_id"


def test_scanner_block_mode_raises():
    s = DLPScanner(mode="block")
    with pytest.raises(DLPViolation):
        s.apply("leak AKIAIOSFODNN7EXAMPLE")


def test_scanner_redact_mode_sanitizes():
    s = DLPScanner(mode="redact")
    out, findings = s.apply("leak AKIAIOSFODNN7EXAMPLE")
    assert "AKIA" not in out
    assert findings


def test_scanner_flag_mode_passes_through():
    s = DLPScanner(mode="flag")
    out, findings = s.apply("leak AKIAIOSFODNN7EXAMPLE")
    assert out == "leak AKIAIOSFODNN7EXAMPLE"
    assert findings


def test_scanner_clean_text_unchanged():
    s = DLPScanner(mode="redact")
    out, findings = s.apply("nothing sensitive here")
    assert out == "nothing sensitive here"
    assert findings == []


def test_invalid_mode_rejected():
    with pytest.raises(ValueError):
        DLPScanner(mode="nonsense")


def test_findings_never_contain_values():
    # The whole point: a finding is type + count, never the secret itself.
    findings = scan("AKIAIOSFODNN7EXAMPLE and 123-45-6789")
    for f in findings:
        assert "AKIA" not in f.type
        assert isinstance(f.count, int)

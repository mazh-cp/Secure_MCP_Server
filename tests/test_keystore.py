import os

import pytest

from secure_mcp.keystore import KeystoreError, SecretKeystore, fingerprint

KEY = bytes(range(32))
NOW = "2026-06-01T00:00:00+00:00"


def _ks(tmp_path):
    return SecretKeystore(tmp_path / "secrets.enc", KEY)


def test_set_get_roundtrip(tmp_path):
    ks = _ks(tmp_path)
    ks.set("checkpoint_te", "super-secret-key", now_iso=NOW)
    assert ks.get("checkpoint_te") == "super-secret-key"


def test_encrypted_at_rest_no_plaintext(tmp_path):
    ks = _ks(tmp_path)
    ks.set("lakera_guard", "lk-PLAINTEXT-VALUE", now_iso=NOW)
    raw = (tmp_path / "secrets.enc").read_bytes()
    assert b"lk-PLAINTEXT-VALUE" not in raw  # value never on disk in clear


def test_status_exposes_only_fingerprint(tmp_path):
    ks = _ks(tmp_path)
    ks.set("checkpoint_te", "abc123", now_iso=NOW)
    st = ks.status()["checkpoint_te"]
    assert st["fp"] == fingerprint("abc123")
    assert "abc123" not in str(st)  # no value in status


def test_file_mode_owner_only(tmp_path):
    ks = _ks(tmp_path)
    ks.set("x", "y", now_iso=NOW)
    assert (os.stat(tmp_path / "secrets.enc").st_mode & 0o777) == 0o600


def test_delete(tmp_path):
    ks = _ks(tmp_path)
    ks.set("x", "y", now_iso=NOW)
    assert ks.delete("x") is True
    assert ks.get("x") is None
    assert ks.delete("x") is False


def test_aad_binding_prevents_swap(tmp_path):
    import base64
    import json
    ks = _ks(tmp_path)
    ks.set("a", "secret-a", now_iso=NOW)
    ks.set("b", "secret-b", now_iso=NOW)
    data = json.loads((tmp_path / "secrets.enc").read_text())
    # Swap a's ciphertext under b's name → AAD mismatch → decrypt fails.
    data["b"] = data["a"]
    (tmp_path / "secrets.enc").write_text(json.dumps(data))
    with pytest.raises(Exception):
        ks.get("b")


def test_rejects_wrong_master_key_length(tmp_path):
    with pytest.raises(KeystoreError):
        SecretKeystore(tmp_path / "s.enc", b"too-short")


def test_wrong_master_key_cannot_decrypt(tmp_path):
    SecretKeystore(tmp_path / "s.enc", KEY).set("x", "v", now_iso=NOW)
    other = SecretKeystore(tmp_path / "s.enc", bytes([1]) * 32)
    with pytest.raises(Exception):
        other.get("x")

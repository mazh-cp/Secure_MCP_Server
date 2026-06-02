import base64
import json

import pytest

from secure_mcp.policy_store import PolicyStore, PolicyValidationError, verify_envelope

NOW = "2026-06-01T00:00:00+00:00"


def _store(tmp_path):
    return PolicyStore(tmp_path / "policies", tmp_path / "keys")


def test_set_and_get_with_version_increment(tmp_path):
    s = _store(tmp_path)
    d1 = s.set_settings("sales", {"BlockMaliciousUrls": True}, now_iso=NOW)
    assert d1["version"] == 1 and d1["tenantId"] == "sales"
    d2 = s.set_settings("sales", {"BlockMaliciousUrls": True, "BlockPhishingUrls": True}, now_iso=NOW)
    assert d2["version"] == 2
    assert s.get_document("sales")["version"] == 2


def test_rejects_unknown_key_and_bad_types(tmp_path):
    s = _store(tmp_path)
    with pytest.raises(PolicyValidationError):
        s.set_settings("g", {"NotAKey": True}, now_iso=NOW)
    with pytest.raises(PolicyValidationError):
        s.set_settings("g", {"BlockMaliciousUrls": "yes"}, now_iso=NOW)
    with pytest.raises(PolicyValidationError):
        s.set_settings("g", {"UrlBlocklist": [1, 2]}, now_iso=NOW)


def test_rejects_group_traversal(tmp_path):
    s = _store(tmp_path)
    with pytest.raises(PolicyValidationError):
        s.set_settings("../evil", {"ProtectionEnabled": True}, now_iso=NOW)


def test_sign_and_verify_roundtrip(tmp_path):
    s = _store(tmp_path)
    doc = s.set_settings("sales", {"BlockPhishingUrls": True, "UrlBlocklist": ["bad.example"]}, now_iso=NOW)
    env = s.sign(doc)
    assert env["alg"] == "ed25519"
    assert verify_envelope(env, s.public_key_b64()) is True
    # The payload decodes back to the signed document.
    assert json.loads(base64.b64decode(env["payload"]))["settings"]["BlockPhishingUrls"] is True


def test_tampered_payload_fails_verify(tmp_path):
    s = _store(tmp_path)
    env = s.sign(s.set_settings("g", {"ProtectionEnabled": True}, now_iso=NOW))
    bad = dict(env)
    forged = {"version": 99, "issuedAt": NOW, "tenantId": "g", "settings": {"ProtectionEnabled": False}}
    bad["payload"] = base64.b64encode(json.dumps(forged).encode()).decode()
    assert verify_envelope(bad, s.public_key_b64()) is False


def test_wrong_key_fails_verify(tmp_path):
    s = _store(tmp_path)
    env = s.sign(s.set_settings("g", {"ProtectionEnabled": True}, now_iso=NOW))
    other = PolicyStore(tmp_path / "p2", tmp_path / "k2")
    assert verify_envelope(env, other.public_key_b64()) is False


def test_keypair_persists_across_instances(tmp_path):
    s1 = _store(tmp_path)
    pub1 = s1.public_key_b64()
    s2 = _store(tmp_path)  # same dirs → same key loaded
    assert s2.public_key_b64() == pub1


def test_list_groups(tmp_path):
    s = _store(tmp_path)
    s.set_settings("sales", {"ProtectionEnabled": True}, now_iso=NOW)
    s.set_settings("eng", {"ProtectionEnabled": True}, now_iso=NOW)
    assert s.list_groups() == ["eng", "sales"]
